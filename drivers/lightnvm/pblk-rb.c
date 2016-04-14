/*
 * Copyright (C) 2016 CNEX Labs
 * Initial release: Javier Gonzalez <jg@lightnvm.io>
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License version
 * 2 as published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; see the file COPYING.  If not, write to
 * the Free Software Foundation, 675 Mass Ave, Cambridge, MA 02139,
 * USA.
 *
 */

#include <linux/circ_buf.h>
#include "pblk.h"

/**
 * pblk_rb_init -- initialize ring buffer
 * @rb: ring buffer
 * @rb_entry_base: pointer to entry buffer base
 * @rb_data_base: pointer to data buffer base
 * @grace_area_sz: size of the grace area between head and tail
 * @power_size: size of ring buffer in power of two
 * @power_seg_sz: size of the segments being stored in power of two (e.g.,4KB)
 *
 * Initialize ring buffer. The data and metadata buffers must be previously
 * allocated and their size must be a power of two
 * (Documentation/circular-buffers.txt)
 */
int pblk_rb_init(struct pblk_rb *rb, struct pblk_rb_entry *rb_entry_base,
			void *rb_data_base, unsigned long grace_area_sz,
			unsigned int power_size, unsigned int power_seg_sz)
{
	struct pblk_rb_entry *entry;
	unsigned int i;

	rb->entries = rb_entry_base;
	rb->data = rb_data_base;
	rb->seg_size = (1 << power_seg_sz);
	rb->nentries = (1 << power_size);
	rb->grace_area = grace_area_sz;
	rb->mem = rb->subm = rb->sync = 0;
	rb->sync_point = RB_EMPTY_ENTRY;

	rb->data_size = rb->nentries * rb->seg_size;
	if (rb->data_size & (rb->data_size - 1)) {
		pr_debug("lnvm: write buffer size forced to be power of 2\n");
		rb->data_size++;
	}

	spin_lock_init(&rb->w_lock);
	spin_lock_init(&rb->s_lock);
	spin_lock_init(&rb->sy_lock);

	for (i = 0; i < rb->nentries; i++) {
		entry = &rb->entries[i];
		entry->data = rb->data + (i * rb->seg_size);
	}

	return 0;
}

/* Copy data to ring buffer. It handles wrap around */
static void memcpy_torb(struct pblk_rb *rb, void *buf, void *data,
								unsigned size)
{
	unsigned s1, s2;

	if (buf + size >= rb->data + rb->data_size) {
		/* Wrap around case */
		s1 = (unsigned)(rb->data + rb->data_size - buf);
		s2 = size - s1;
		memcpy(buf, data, s1);
		memcpy(rb->data, data + s1, s2);
	} else {
		memcpy(buf, data, size);
	}
}

/* Copy data from ring buffer. It handles wrap around */
static void memcpy_fromrb(struct pblk_rb *rb, void *buf, void *data,
								unsigned size)
{
	unsigned s1, s2;

	if (buf + size >= rb->data + rb->data_size) {
		/* Wrap around case */
		s1 = (unsigned)(rb->data + rb->data_size - buf);
		s2 = size - s1;
		memcpy(buf, data, s1);
		memcpy(buf + s1, rb->data, s2);
	} else {
		memcpy(buf, data, size);
	}
}

static void memcpy_wctx(struct pblk_w_ctx *to, struct pblk_w_ctx *from)
{
	to->bio = from->bio;
	to->lba = from->lba;
	to->flags = from->flags;
}

#define pblk_rb_ring_count(head, tail, size) CIRC_CNT(head, tail, size)
#define pblk_rb_ring_space(rb, head, tail, size) \
	(CIRC_SPACE(head, tail, size) - rb->grace_area)

/* Available space is calculated with respect to the back pointer signaling
 * synchronized entries to the media.
 */
unsigned long pblk_rb_space(struct pblk_rb *rb)
{
	unsigned long mem = READ_ONCE(rb->mem);
	unsigned long sync = READ_ONCE(rb->sync);

	return pblk_rb_ring_space(rb, mem, sync, rb->nentries);
}

unsigned long pblk_rb_count(struct pblk_rb *rb)
{
	unsigned long mem = READ_ONCE(rb->mem);
	unsigned long subm = READ_ONCE(rb->subm);

	return pblk_rb_ring_count(mem, subm, rb->nentries);
}

/**
 * Returns how many entries are on the write buffer at the time of call and
 * takes the submission lock. The lock is only taken if there are any entries on
 * the buffer. This guarantees that at least the returned amount of entries
 * will be on the buffer when reading from it.
 */
unsigned long pblk_rb_count_init(struct pblk_rb *rb)
{
	unsigned long mem = READ_ONCE(rb->mem);
	unsigned long subm = READ_ONCE(rb->subm);
	unsigned long ret;

	spin_lock(&rb->s_lock);

	ret = pblk_rb_ring_count(mem, subm, rb->nentries);
	if (!ret)
		spin_unlock(&rb->s_lock);
	return ret;
}

/**
 * Unlocks submission path
 * @rb: ring buffer
 */
void pblk_rb_read_commit(struct pblk_rb *rb, unsigned int nentries)
{
	unsigned long subm;

	lockdep_assert_held(&rb->s_lock);

	subm = READ_ONCE(rb->subm);
	smp_store_release(&rb->subm, (subm + nentries) & (rb->nentries - 1));
	spin_unlock(&rb->s_lock);
}

void pblk_rb_read_rollback(struct pblk_rb *rb)
{
	unsigned long subm;

	lockdep_assert_held(&rb->s_lock);

	subm = READ_ONCE(rb->subm);
	smp_store_release(&rb->subm, subm);
	spin_unlock(&rb->s_lock);
}

/**
 * pblk_rb_write - write to ring buffer
 * @rb: ring buffer
 * @data: buffer with data to be copied. Must be at least of @nentries *
 * rb->seg_size bytes
 * @w_ctx_list: list of write contexts to be stored on each buffer entry
 * @pos: (out) base position in the buffer for the current write
 *
 * Write @nentries to ring buffer from @data buffer if there is enough space.
 * Typically, 4KB data chunks coming from a bio will be copied to the ring
 * buffer, thus the write will fail if not all incoming data can be copied.
 *
 * Return: 0 on success, -ENOMEM on failure
 */
int pblk_rb_write_entry(struct pblk_rb *rb, void *data, struct pblk_w_ctx w_ctx,
							unsigned int pos)
{
	struct pblk_rb_entry *entry;
	unsigned long size = rb->seg_size;
	unsigned long sync;
	unsigned int ring_pos = (pos & (rb->nentries - 1));
	int ret = 0;

	lockdep_assert_held(&rb->w_lock);

	sync = ACCESS_ONCE(rb->sync);

	if (pblk_rb_ring_space(rb, ring_pos, sync, rb->nentries) < 1) {
		ret = -ENOMEM;
		goto out;
	}

	entry = &rb->entries[ring_pos];
	memcpy_torb(rb, entry->data, data, size);
	memcpy_wctx(&entry->w_ctx, &w_ctx);

out:
	return ret;
}

unsigned long pblk_rb_write_init(struct pblk_rb *rb)
{
	/* Serialize writers */
	spin_lock(&rb->w_lock);

	return READ_ONCE(rb->mem);
}

void pblk_rb_write_commit(struct pblk_rb *rb, unsigned int nentries)
{
	unsigned long mem;

	lockdep_assert_held(&rb->w_lock);

	mem = READ_ONCE(rb->mem);
	smp_store_release(&rb->mem, (mem + nentries) & (rb->nentries - 1));
	spin_unlock(&rb->w_lock);
}

void pblk_rb_write_rollback(struct pblk_rb *rb)
{
	unsigned long mem;

	lockdep_assert_held(&rb->w_lock);

	mem = READ_ONCE(rb->mem);
	smp_store_release(&rb->mem, mem);
	spin_unlock(&rb->w_lock);
}

/**
 * pblk_rb_read - read from ring buffer
 * @rb: ring buffer
 * @buf: buffer to which data is copied. Must be of at least @size bytes long
 * @w_ctx_list: write context associated with the read entries - filled while
 * entries are being read
 * @nentries: number of entries to be read from the buffer
 *
 * Read from ring buffer and copy the data in buf. This allows the submit
 * pointer of the ring buffer (tail) to advance, since data is copied to a
 * different buffer.  It is required that the submission lock (consumer) has
 * been taken
 *
 * In order to avoid this memory copy, pblk_rb_get_ref can be used. In this case,
 * only a reference to the data is given, bu the caller is responsible from
 * notifying the ring buffer that data has been persisted and that it is safe to
 * advance the submit pointer.
 *
 * XXX: Read one entry at a time using the position pointers to locate the right
 * entry. Optimize this in the future to read all at once and then copy metadata
 * in a per entry basis
 */
unsigned int pblk_rb_read(struct pblk_rb *rb, void *buf,
					struct pblk_ctx *ctx,
					unsigned int nentries)
{
	struct pblk *pblk = container_of(rb, struct pblk, rwb);
	struct pblk_rb_entry *entry;
	struct pblk_compl_ctx *c_ctx = ctx->c_ctx;
	struct pblk_w_ctx *w_ctx_list = ctx->w_ctx;
	struct pblk_l2p_upd_ctx *upt_ctx;
	/* unsigned long size = nentries * rb->seg_size; */
	unsigned long mem, subm;
	unsigned int read = 0;
	unsigned int i;

	lockdep_assert_held(&rb->s_lock);

	mem = smp_load_acquire(&rb->mem);
	subm = READ_ONCE(rb->subm);

	if (pblk_rb_ring_count(mem, subm, rb->nentries) < nentries)
		goto out;

	/* entry = &rb->entries[subm]; */
	/* memcpy_fromrb(rb, buf, entry->data, size); */

	c_ctx->sentry = subm;
	c_ctx->nentries = nentries;

	/* XXX: Read one entry at a time for now */
	for (i = 0; i < nentries; i++) {
		entry = &rb->entries[subm];
		memcpy_fromrb(rb, buf + (i * rb->seg_size), entry->data,
								rb->seg_size);
		memcpy_wctx(&w_ctx_list[i], &entry->w_ctx);
		subm = (subm + 1) & (rb->nentries - 1);

		upt_ctx = &w_ctx_list[i].upt_ctx;
		/* If the address cannot be locked on the l2p table, return a no
		 * read. The caller is responsible for rolling back the read
		 * requests
		 */
		if (pblk_lock_laddr(pblk, entry->w_ctx.lba, 1, upt_ctx))
			goto out;
	}

	read = nentries;

out:
	return read;
}

/* Read available entries on rb, and lock entries on the l2p table that
 * are on its way to be persisted to the media. This guarantees
 * consistency between the write buffer and the l2p table.
 */
unsigned int pblk_rb_read_to_bio(struct pblk_rb *rb, struct bio *bio,
					struct pblk_ctx *ctx,
					unsigned int nentries)
{
	struct pblk *pblk = container_of(rb, struct pblk, rwb);
	struct request_queue *q = pblk->dev->q;
	struct pblk_rb_entry *entry;
	struct pblk_compl_ctx *c_ctx = ctx->c_ctx;
	struct pblk_w_ctx *w_ctx_list = ctx->w_ctx;
	struct pblk_l2p_upd_ctx *upt_ctx;
	struct page *page;
	/* unsigned long size = nentries * rb->seg_size; */
	unsigned long mem, subm;
	unsigned long count;
	unsigned int pad = 0, read = 0, to_read = nentries;
	unsigned int i;
	int ret;

	lockdep_assert_held(&rb->s_lock);

	mem = smp_load_acquire(&rb->mem);
	subm = READ_ONCE(rb->subm);

	if ((count = pblk_rb_ring_count(mem, subm, rb->nentries)) < nentries) {
		pad = nentries - count;
		to_read = count;
	}

	/* entry = &rb->entries[subm]; */
	/* memcpy_fromrb(rb, buf, entry->data, size); */

	c_ctx->sentry = subm;
	c_ctx->nentries = to_read;

	/* XXX: Read one entry at a time for now */
	for (i = 0; i < to_read; i++) {
		entry = &rb->entries[subm];

		page = vmalloc_to_page(entry->data);
		if (!page) {
			pr_err("pblk: could not allocate write bio page\n");
			goto out;
		}

		ret = bio_add_pc_page(q, bio, page, rb->seg_size, 0);
		if (ret != rb->seg_size) {
			pr_err("pblk: could not ad page to write bio\n");
			goto out;
		}

		memcpy_wctx(&w_ctx_list[i], &entry->w_ctx);
		upt_ctx = &w_ctx_list[i].upt_ctx;
		subm = (subm + 1) & (rb->nentries - 1);

		/* If the address cannot be locked on the l2p table, return a no
		 * read. The caller is responsible for rolling back the read
		 * requests
		 */
		if (pblk_lock_laddr(pblk, entry->w_ctx.lba, 1, upt_ctx))
			goto out;
	}

	for (i = to_read; i < nentries; i++) {
		w_ctx_list[i].lba = ADDR_PADDED;
		w_ctx_list[i].flags = 0;
		w_ctx_list[i].bio = NULL;
	}

	read = to_read;

#ifdef CONFIG_NVM_DEBUG
	atomic_add(pad, &pblk->padded_writes);
#endif

out:
	return read;
}

unsigned int pblk_rb_copy_entry_to_bio(struct pblk_rb *rb, struct bio *bio,
								u64 pos)
{
	struct pblk_rb_entry *entry;
	struct bio_vec bv;
	struct page *page;
	void *kaddr;

	entry = &rb->entries[pos];

	bv = bio_iter_iovec(bio, bio->bi_iter);
	page = bv.bv_page;
	kaddr = kmap_atomic(page);
	memcpy_fromrb(rb, kaddr + bv.bv_offset, entry->data, rb->seg_size);
	kunmap_atomic(kaddr);

	return 1;
}

unsigned long pblk_rb_sync_init(struct pblk_rb *rb, unsigned long *flags)
{
	spin_lock_irqsave(&rb->sy_lock, *flags);

	return rb->sync;
}

unsigned long pblk_rb_sync_advance(struct pblk_rb *rb, unsigned int nentries)
{
	unsigned long sync;

	lockdep_assert_held(&rb->sy_lock);

	sync = (rb->sync + nentries) & (rb->nentries -1 );
	smp_store_release(&rb->sync, sync);

	return sync;
}

void pblk_rb_sync_end(struct pblk_rb *rb, unsigned long flags)
{
	lockdep_assert_held(&rb->sy_lock);

	spin_unlock_irqrestore(&rb->sy_lock, flags);
}

int pblk_rb_sync_point_set(struct pblk_rb *rb, struct bio *bio)
{
	struct pblk_rb_entry *entry;
	unsigned long mem, subm, sync_point;
	int ret = NVM_IO_OK;

	spin_lock(&rb->s_lock);

	mem = smp_load_acquire(&rb->mem);
	sync_point = smp_load_acquire(&rb->sync_point);
	subm = READ_ONCE(rb->subm);

	if (mem == subm) {
		ret = NVM_IO_DONE;
		goto out;
	}

	sync_point = (mem == 0) ? (rb->nentries - 1) : (mem - 1);
	entry = &rb->entries[sync_point];

	if (entry->w_ctx.bio) {
		pr_err("pblk: Duplicated sync point:%lu\n", sync_point);
		BUG_ON(1);
		//TODO: Deal with this case
	}

	entry->w_ctx.bio = bio;
	smp_store_release(&rb->sync_point, sync_point);

out:
	spin_unlock(&rb->s_lock);
	return ret;
}

void pblk_rb_sync_point_reset(struct pblk_rb *rb)
{
	smp_store_release(&rb->sync_point, ADDR_EMPTY);
}

unsigned long pblk_rb_sync_point_count(struct pblk_rb *rb)
{
	unsigned long subm, sync_point, count;

	sync_point = smp_load_acquire(&rb->sync_point);
	if (sync_point == ADDR_EMPTY)
		return 0;

	subm = READ_ONCE(rb->subm);

	/* The sync point itself counts as a sector to sync */
	count = pblk_rb_ring_count(sync_point, subm, rb->nentries) + 1;

	return count;
}

#ifdef CONFIG_NVM_DEBUG
void pblk_rb_print_debug(struct pblk_rb *rb)
{
	if (rb->sync_point != ADDR_EMPTY)
		pr_info("pblk_rb: %lu\t%lu\t%lu\tsync:y(%lu)\n",
			rb->mem, rb->subm, rb->sync, rb->sync_point);
	else
		pr_info("pblk_rb: %lu\t%lu\t%lu\tsync:n\n",
			rb->mem, rb->subm, rb->sync);
}
#endif

/*
 * TODO: Implement this part when we do not do a copy from buffer when sending
 * an internal bio to the device
 */
#if 0
unsigned pblk_rb_get_ref(struct pblk_rb *rb, void *ptr, unsigned nentries)
{
	struct pblk_rb_entry *entry;
	struct void *data;
	unsigned long size = nentries * rb->seg_size;
	unsigned mem, subm;
	unsigned read = 0;

	lockdep_assert_held(&rb->s_lock);

	mem = smp_load_acquire(&rb->mem);
	subm = rb->subm;

	if (pblk_rb_ring_count(mem, subm, rb->nentries) < nentries)
		return -ENOMEM;

	/*
	 * XXX: For now copy the data on the buffer to a new buffer, which is
	 * then used to form the bio to be sent out to the device. In the
	 * future, we want to give a reference to the buffer and only move the
	 * pointer when the data has been persisted to the media.
	 *
	 * As with the producer, We assume for now that we store 4KB at the
	 * time, i.e., one entry
	 */
	entry = rb->entries[subm];
	memcpy_fromrb(rb, ptr, entry->data, size);
	read = nentries;

	smp_store_release(&rb->subm, (subm + nentries) & (rb->nentries - 1));

	spin_unlock(&rb->s_lock);
}

unsigned pblk_rb_get_ref_lock(struct pblk_rb *rb, void *ptr, unsigned nentries)
{
	/* Serialize readers*/
	spin_lock(&rb->s_lock);
	return pblk_rb_get_ref(rb, ptr, nentries);
}
#endif

/* TODO: Implement this part when we need to roll back in multipage */
#if 0
static void pblk_rb_commit_read(struct pblk_rb *rb)
{

}

static void pblk_rb_commit_write(struct pblk_rb *rb)
{
	/*
	 * We must ensure ordering with regards to previously committed data
	 * before we update the current write pointer. This write barrier is
	 * paired with the rad barrier at pblk_rb_count()
	 */
	wmb();
	ACCESS_ONCE(*rb->mem)
}

#endif

