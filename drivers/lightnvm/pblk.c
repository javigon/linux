/*
 * Copyright (C) 2015 IT University of Copenhagen (rrpc.c)
 * Copyright (C) 2016 CNEX Labs
 * Initial release: Matias Bjorling <m@bjorling.me>
 * Write buffering: Javier Gonzalez <jg@lightnvm.io>
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
 * Implementation of a physical block-device target for Open-channel SSDs.
 *
 * Derived from rrpc.c
 */

#include "pblk.h"

static struct kmem_cache *pblk_gcb_cache, *pblk_rq_cache, *pblk_rrq_cache,
			*pblk_buf_rrq_cache, *pblk_wb_cache, *pblk_block_cache;
static DECLARE_RWSEM(pblk_lock);

static int pblk_submit_io(struct pblk *pblk, struct bio *bio,
				struct pblk_rq *rqd, unsigned long flags);

#define pblk_for_each_lun(pblk, rlun, i) \
		for ((i) = 0, rlun = &(pblk)->luns[0]; \
			(i) < (pblk)->nr_luns; (i)++, rlun = &(pblk)->luns[(i)])

static void pblk_page_invalidate(struct pblk *pblk, struct pblk_addr *a)
{
	struct pblk_block *rblk = a->rblk;
	unsigned int pg_offset;

	lockdep_assert_held(&pblk->rev_lock);

	if (a->addr == ADDR_EMPTY || !rblk)
		return;

	spin_lock(&rblk->lock);

	div_u64_rem(a->addr, pblk->dev->pgs_per_blk, &pg_offset);
	WARN_ON(test_and_set_bit(pg_offset, rblk->invalid_pages));
	rblk->nr_invalid_pages++;

	spin_unlock(&rblk->lock);

	pblk->rev_trans_map[a->addr - pblk->poffset].addr = ADDR_EMPTY;
}

static void pblk_invalidate_range(struct pblk *pblk, sector_t slba,
								unsigned len)
{
	sector_t i;

	spin_lock(&pblk->rev_lock);
	for (i = slba; i < slba + len; i++) {
		struct pblk_addr *gp = &pblk->trans_map[i];

		pblk_page_invalidate(pblk, gp);
		gp->rblk = NULL;
	}
	spin_unlock(&pblk->rev_lock);
}

static void pblk_free_rrqd(struct kref *ref)
{
	struct pblk_rq *rrqd = container_of(ref, struct pblk_rq, refs);
	struct pblk *pblk = rrqd->pblk;

	mempool_free(rrqd, pblk->rrq_pool);
}

static void pblk_release_and_free_rrqd(struct kref *ref)
{
	struct pblk_rq *rrqd = container_of(ref, struct pblk_rq, refs);
	struct pblk *pblk = rrqd->pblk;

	pblk_unlock_rq(pblk, rrqd);
	mempool_free(rrqd, pblk->rrq_pool);
}

static struct pblk_rq *pblk_inflight_laddr_acquire(struct pblk *pblk,
					sector_t laddr, unsigned int pages)
{
	struct pblk_rq *rrqd;
	struct pblk_inflight_rq *inf;

	rrqd = mempool_alloc(pblk->rrq_pool, GFP_ATOMIC);
	if (!rrqd)
		return ERR_PTR(-ENOMEM);
	rrqd->pblk = pblk;
	kref_init(&rrqd->refs);

	inf = pblk_get_inflight_rq(rrqd);
	if (pblk_lock_laddr(pblk, laddr, pages, inf)) {
		mempool_free(rrqd, pblk->rrq_pool);
		return NULL;
	}

	return rrqd;
}

static void pblk_inflight_laddr_release(struct pblk *pblk, struct pblk_rq *rrqd)
{
	kref_put(&rrqd->refs, pblk_release_and_free_rrqd);
}

static void pblk_discard(struct pblk *pblk, struct bio *bio)
{
	sector_t slba = bio->bi_iter.bi_sector / NR_PHY_IN_LOG;
	sector_t len = bio->bi_iter.bi_size / PBLK_EXPOSED_PAGE_SIZE;
	struct pblk_rq *rrqd;

	do {
		rrqd = pblk_inflight_laddr_acquire(pblk, slba, len);
		schedule();
	} while (!rrqd);

	if (IS_ERR(rrqd)) {
		pr_err("pblk: unable to acquire inflight IO\n");
		bio_io_error(bio);
		return;
	}

	pblk_invalidate_range(pblk, slba, len);
	pblk_inflight_laddr_release(pblk, rrqd);
}

static int block_is_full(struct pblk *pblk, struct pblk_block *rblk)
{
	return (rblk->next_page == pblk->dev->pgs_per_blk);
}

static u64 block_to_addr(struct pblk *pblk, struct pblk_block *rblk)
{
	struct nvm_block *blk = rblk->parent;

	return blk->id * pblk->dev->pgs_per_blk;
}

static struct ppa_addr linear_to_generic_addr(struct nvm_dev *dev,
							struct ppa_addr r)
{
	struct ppa_addr l;
	int secs, pgs, blks, luns;
	sector_t ppa = r.ppa;

	l.ppa = 0;

	div_u64_rem(ppa, dev->sec_per_pg, &secs);
	l.g.sec = secs;

	sector_div(ppa, dev->sec_per_pg);
	div_u64_rem(ppa, dev->sec_per_blk, &pgs);
	l.g.pg = pgs;

	sector_div(ppa, dev->pgs_per_blk);
	div_u64_rem(ppa, dev->blks_per_lun, &blks);
	l.g.blk = blks;

	sector_div(ppa, dev->blks_per_lun);
	div_u64_rem(ppa, dev->luns_per_chnl, &luns);
	l.g.lun = luns;

	sector_div(ppa, dev->luns_per_chnl);
	l.g.ch = ppa;

	return l;
}

static struct ppa_addr pblk_ppa_to_gaddr(struct nvm_dev *dev, u64 addr)
{
	struct ppa_addr paddr;

	paddr.ppa = addr;
	return linear_to_generic_addr(dev, paddr);
}

/* requires lun->lock taken */
static void pblk_set_lun_cur(struct pblk_lun *rlun, struct pblk_block *rblk)
{
	struct pblk *pblk = rlun->pblk;

	if (rlun->cur) {
		spin_lock(&rlun->cur->lock);
		WARN_ON(!block_is_full(pblk, rlun->cur));
		spin_unlock(&rlun->cur->lock);
	}
	rlun->cur = rblk;
}

static void pblk_free_w_buffer(struct pblk *pblk, struct pblk_block *rblk)
{
try:
	spin_lock(&rblk->w_buf.s_lock);
	if (atomic_read(&rblk->w_buf.refs) > 0) {
		spin_unlock(&rblk->w_buf.s_lock);
		schedule();
		goto try;
	}

	mempool_free(rblk->w_buf.entries, pblk->block_pool);
	rblk->w_buf.entries = NULL;
	spin_unlock(&rblk->w_buf.s_lock);

	/* TODO: Reuse the same buffers if the block size is the same */
	mempool_free(rblk->w_buf.data, pblk->write_buf_pool);
	kfree(rblk->w_buf.sync_bitmap);

	rblk->w_buf.mem = NULL;
	rblk->w_buf.subm = NULL;
	rblk->w_buf.sync_bitmap = NULL;
	rblk->w_buf.data = NULL;
	rblk->w_buf.nentries = 0;
	rblk->w_buf.cur_mem = 0;
	rblk->w_buf.cur_subm = 0;
}

static void pblk_put_blk(struct pblk *pblk, struct pblk_block *rblk)
{
	struct pblk_lun *rlun = rblk->rlun;
	struct nvm_lun *lun = rlun->parent;
	struct pblk_w_buf *buf = &rblk->w_buf;

try:
	spin_lock(&buf->w_lock);
	/* Flush inflight I/Os */
	if (!bitmap_full(buf->sync_bitmap, buf->cur_mem)) {
		spin_unlock(&buf->w_lock);
		schedule();
		goto try;
	}
	spin_unlock(&buf->w_lock);

	if (rblk->w_buf.entries)
		pblk_free_w_buffer(pblk, rblk);

	spin_lock(&lun->lock);
	nvm_put_blk_unlocked(pblk->dev, rblk->parent);
	list_del(&rblk->list);
	spin_unlock(&lun->lock);
}

static void pblk_put_blks(struct pblk *pblk)
{
	struct pblk_lun *rlun;
	int i;

	for (i = 0; i < pblk->nr_luns; i++) {
		rlun = &pblk->luns[i];
		if (rlun->cur)
			pblk_put_blk(pblk, rlun->cur);
		if (rlun->gc_cur)
			pblk_put_blk(pblk, rlun->gc_cur);
	}
}

static struct pblk_block *pblk_get_blk(struct pblk *pblk, struct pblk_lun *rlun,
							unsigned long flags)
{
	struct nvm_dev *dev = pblk->dev;
	struct nvm_lun *lun = rlun->parent;
	struct nvm_block *blk;
	struct pblk_block *rblk;
	struct buf_entry *entries;
	unsigned long *sync_bitmap;
	void *data;
	int nentries = dev->pgs_per_blk * dev->sec_per_pg;

	data = mempool_alloc(pblk->write_buf_pool, GFP_ATOMIC);
	if (!data) {
		pr_err("nvm: pblk: cannot allocate write buffer for block\n");
		return NULL;
	}

	entries = mempool_alloc(pblk->block_pool, GFP_ATOMIC);
	if (!entries) {
		pr_err("nvm: pblk: cannot allocate write buffer for block\n");
		mempool_free(data, pblk->write_buf_pool);
		return NULL;
	}

	/* TODO: Mempool? */
	sync_bitmap = kmalloc(BITS_TO_LONGS(nentries) *
					sizeof(unsigned long), GFP_ATOMIC);
	if (!sync_bitmap) {
		mempool_free(data, pblk->write_buf_pool);
		mempool_free(entries, pblk->block_pool);
		return NULL;
	}

	bitmap_zero(sync_bitmap, nentries);

	spin_lock(&lun->lock);
	blk = nvm_get_blk_unlocked(pblk->dev, rlun->parent, flags);
	if (!blk) {
		pr_err("nvm: pblk: cannot get new block from media manager\n");
		spin_unlock(&lun->lock);
		return NULL;
	}

	rblk = pblk_get_rblk(rlun, blk->id);

	blk->priv = rblk;
	bitmap_zero(rblk->invalid_pages, dev->pgs_per_blk);
	rblk->next_page = 0;
	rblk->nr_invalid_pages = 0;

	rblk->w_buf.data = data;
	rblk->w_buf.entries = entries;
	rblk->w_buf.sync_bitmap = sync_bitmap;

	rblk->w_buf.entries->data  = rblk->w_buf.data;
	rblk->w_buf.mem = rblk->w_buf.entries;
	rblk->w_buf.subm = rblk->w_buf.entries;
	rblk->w_buf.nentries = nentries;
	rblk->w_buf.cur_mem = 0;
	rblk->w_buf.cur_subm = 0;

	atomic_set(&rblk->w_buf.refs, 0);

	spin_lock_init(&rblk->w_buf.w_lock);
	spin_lock_init(&rblk->w_buf.s_lock);

	list_add_tail(&rblk->list, &rlun->open_list);
	spin_unlock(&lun->lock);

	return rblk;
}

static struct pblk_lun *get_next_lun(struct pblk *pblk)
{
	int next = atomic_inc_return(&pblk->next_lun);

	return &pblk->luns[next % pblk->nr_luns];
}

static void pblk_gc_kick(struct pblk *pblk)
{
	struct pblk_lun *rlun;
	unsigned int i;

	for (i = 0; i < pblk->nr_luns; i++) {
		rlun = &pblk->luns[i];
		queue_work(pblk->krqd_wq, &rlun->ws_gc);
	}
}

static void pblk_writer_kick(struct pblk *pblk)
{
	struct pblk_lun *rlun;
	unsigned int i;

	for (i = 0; i < pblk->nr_luns; i++) {
		rlun = &pblk->luns[i];
		queue_work(pblk->kw_wq, &rlun->ws_writer);
	}
}

/*
 * timed GC every interval.
 */
static void pblk_gc_timer(unsigned long data)
{
	struct pblk *pblk = (struct pblk *)data;

	pblk_gc_kick(pblk);
	mod_timer(&pblk->gc_timer, jiffies + msecs_to_jiffies(10));
}

static void pblk_end_sync_bio(struct bio *bio)
{
	struct completion *waiting = bio->bi_private;

	if (bio->bi_error)
		pr_err("nvm: gc request failed (%u).\n", bio->bi_error);

	complete(waiting);
}

/*
 * pblk_move_valid_pages -- migrate live data off the block
 * @pblk: the 'pblk' structure
 * @block: the block from which to migrate live pages
 *
 * Description:
 *   GC algorithms may call this function to migrate remaining live
 *   pages off the block prior to erasing it. This function blocks
 *   further execution until the operation is complete.
 */
static int pblk_move_valid_pages(struct pblk *pblk, struct pblk_block *rblk)
{
	struct request_queue *q = pblk->dev->q;
	struct pblk_rev_addr *rev;
	struct pblk_rq *rrqd;
	struct bio *bio;
	struct page *page;
	int slot;
	int nr_pgs_per_blk = pblk->dev->pgs_per_blk;
	u64 phys_addr;
	DECLARE_COMPLETION_ONSTACK(wait);

	if (bitmap_full(rblk->invalid_pages, nr_pgs_per_blk))
		return 0;

	bio = bio_alloc(GFP_NOIO, 1);
	if (!bio) {
		pr_err("nvm: could not alloc bio to gc\n");
		return -ENOMEM;
	}

	page = mempool_alloc(pblk->page_pool, GFP_NOIO);
	if (!page) {
		bio_put(bio);
		return -ENOMEM;
	}

	while ((slot = find_first_zero_bit(rblk->invalid_pages,
					nr_pgs_per_blk)) < nr_pgs_per_blk) {

		/* Lock laddr */
		phys_addr = (rblk->parent->id * nr_pgs_per_blk) + slot;

try:
		spin_lock(&pblk->rev_lock);
		/* Get logical address from physical to logical table */
		rev = &pblk->rev_trans_map[phys_addr - pblk->poffset];
		/* already updated by previous regular write */
		if (rev->addr == ADDR_EMPTY) {
			spin_unlock(&pblk->rev_lock);
			continue;
		}

		rrqd = pblk_inflight_laddr_acquire(pblk, rev->addr, 1);
		if (IS_ERR_OR_NULL(rrqd)) {
			spin_unlock(&pblk->rev_lock);
			schedule();
			goto try;
		}

		spin_unlock(&pblk->rev_lock);

		/* Perform read to do GC */
		bio->bi_iter.bi_sector = pblk_get_sector(rev->addr);
		bio->bi_rw = READ;
		bio->bi_private = &wait;
		bio->bi_end_io = pblk_end_sync_bio;

		/* TODO: may fail when EXP_PG_SIZE > PAGE_SIZE */
		bio_add_pc_page(q, bio, page, PBLK_EXPOSED_PAGE_SIZE, 0);

		if (pblk_submit_io(pblk, bio, rrqd, NVM_IOTYPE_GC)) {
			pr_err("pblk: gc read failed.\n");
			pblk_inflight_laddr_release(pblk, rrqd);
			goto finished;
		}
		wait_for_completion_io(&wait);
		if (bio->bi_error) {
			pblk_inflight_laddr_release(pblk, rrqd);
			goto finished;
		}

		bio_reset(bio);
		reinit_completion(&wait);

		bio->bi_iter.bi_sector = pblk_get_sector(rev->addr);
		bio->bi_rw = WRITE;
		bio->bi_private = &wait;
		bio->bi_end_io = pblk_end_sync_bio;

		bio_add_pc_page(q, bio, page, PBLK_EXPOSED_PAGE_SIZE, 0);

		/* turn the command around and write the data back to a new
		 * address
		 */
		if (pblk_submit_io(pblk, bio, rrqd, NVM_IOTYPE_GC)
							!= NVM_IO_DONE) {
			/* If the I/O fails, the write make_rq routines will
			 * unlock the laddr and clean rrqd
			 */
			pr_err("pblk: gc write failed.\n");
			goto finished;
		}
		bio_endio(bio);
		wait_for_completion_io(&wait);

		/* pblk_inflight_laddr_release(pblk, rrqd); */
		if (bio->bi_error)
			goto finished;

		bio_reset(bio);
	}

finished:
	mempool_free(page, pblk->page_pool);
	bio_put(bio);

	if (!bitmap_full(rblk->invalid_pages, nr_pgs_per_blk)) {
		pr_err("nvm: failed to garbage collect block\n");
		return -EIO;
	}

	return 0;
}

static void pblk_block_gc(struct work_struct *work)
{
	struct pblk_block_gc *gcb = container_of(work, struct pblk_block_gc,
									ws_gc);
	struct pblk *pblk = gcb->pblk;
	struct pblk_block *rblk = gcb->rblk;
	struct nvm_dev *dev = pblk->dev;
	struct nvm_lun *lun = rblk->parent->lun;
	struct pblk_lun *rlun = &pblk->luns[lun->id - pblk->lun_offset];

	mempool_free(gcb, pblk->gcb_pool);
	pr_debug("nvm: block '%lu' being reclaimed\n", rblk->parent->id);

	if (pblk_move_valid_pages(pblk, rblk))
		goto put_back;

	if (nvm_erase_blk(dev, rblk->parent))
		goto put_back;

	pblk_put_blk(pblk, rblk);

	return;

put_back:
	spin_lock(&rlun->lock);
	list_add_tail(&rblk->prio, &rlun->prio_list);
	spin_unlock(&rlun->lock);
}

/* the block with highest number of invalid pages, will be in the beginning
 * of the list
 */
static struct pblk_block *rblock_max_invalid(struct pblk_block *ra,
							struct pblk_block *rb)
{
	if (ra->nr_invalid_pages == rb->nr_invalid_pages)
		return ra;

	return (ra->nr_invalid_pages < rb->nr_invalid_pages) ? rb : ra;
}

/* linearly find the block with highest number of invalid pages
 * requires lun->lock
 */
static struct pblk_block *block_prio_find_max(struct pblk_lun *rlun)
{
	struct list_head *prio_list = &rlun->prio_list;
	struct pblk_block *rblock, *max;

	BUG_ON(list_empty(prio_list));

	max = list_first_entry(prio_list, struct pblk_block, prio);
	list_for_each_entry(rblock, prio_list, prio)
		max = rblock_max_invalid(max, rblock);

	return max;
}

static void pblk_lun_gc(struct work_struct *work)
{
	struct pblk_lun *rlun = container_of(work, struct pblk_lun, ws_gc);
	struct pblk *pblk = rlun->pblk;
	struct nvm_lun *lun = rlun->parent;
	struct pblk_block_gc *gcb;
	unsigned int nr_blocks_need;

	nr_blocks_need = pblk->dev->blks_per_lun / GC_LIMIT_INVERSE;

	if (nr_blocks_need < pblk->nr_luns)
		nr_blocks_need = pblk->nr_luns;

	spin_lock(&rlun->lock);
	while (nr_blocks_need > lun->nr_free_blocks &&
					!list_empty(&rlun->prio_list)) {
		struct pblk_block *rblock = block_prio_find_max(rlun);
		struct nvm_block *block = rblock->parent;

		if (!rblock->nr_invalid_pages)
			break;

		gcb = mempool_alloc(pblk->gcb_pool, GFP_ATOMIC);
		if (!gcb)
			break;

		list_del_init(&rblock->prio);

		BUG_ON(!block_is_full(pblk, rblock));

		pr_debug("pblk: selected block '%lu' for GC\n", block->id);

		gcb->pblk = pblk;
		gcb->rblk = rblock;
		INIT_WORK(&gcb->ws_gc, pblk_block_gc);

		queue_work(pblk->kgc_wq, &gcb->ws_gc);

		nr_blocks_need--;
	}
	spin_unlock(&rlun->lock);

	/* TODO: Hint that request queue can be started again */
}

static void pblk_gc_queue(struct work_struct *work)
{
	struct pblk_block_gc *gcb = container_of(work, struct pblk_block_gc,
									ws_gc);
	struct pblk *pblk = gcb->pblk;
	struct pblk_block *rblk = gcb->rblk;
	struct nvm_lun *lun = rblk->parent->lun;
	struct nvm_block *blk = rblk->parent;
	struct pblk_lun *rlun = &pblk->luns[lun->id - pblk->lun_offset];

	spin_lock(&rlun->lock);
	list_add_tail(&rblk->prio, &rlun->prio_list);
	spin_unlock(&rlun->lock);

	spin_lock(&lun->lock);
	lun->nr_open_blocks--;
	lun->nr_closed_blocks++;
	blk->state &= ~NVM_BLK_ST_OPEN;
	blk->state |= NVM_BLK_ST_CLOSED;
	list_move_tail(&rblk->list, &rlun->closed_list);
	spin_unlock(&lun->lock);

	pblk_free_w_buffer(pblk, rblk);

	mempool_free(gcb, pblk->gcb_pool);
	pr_debug("nvm: block '%lu' is full, allow GC (sched)\n",
							rblk->parent->id);
}

static const struct block_device_operations pblk_fops = {
	.owner		= THIS_MODULE,
};

static struct pblk_lun *pblk_get_lun_rr(struct pblk *pblk, int is_gc)
{
	unsigned int i;
	struct pblk_lun *rlun, *max_free;

	if (!is_gc)
		return get_next_lun(pblk);

	/* during GC, we don't care about RR, instead we want to make
	 * sure that we maintain evenness between the block luns.
	 */
	max_free = &pblk->luns[0];
	/* prevent GC-ing lun from devouring pages of a lun with
	 * little free blocks. We don't take the lock as we only need an
	 * estimate.
	 */
	pblk_for_each_lun(pblk, rlun, i) {
		if (rlun->parent->nr_free_blocks >
					max_free->parent->nr_free_blocks)
			max_free = rlun;
	}

	return max_free;
}

static struct pblk_addr *pblk_update_map(struct pblk *pblk, sector_t laddr,
					struct pblk_block *rblk, u64 paddr)
{
	struct pblk_addr *gp;
	struct pblk_rev_addr *rev;

	BUG_ON(laddr >= pblk->nr_sects);

	gp = &pblk->trans_map[laddr];
	spin_lock(&pblk->rev_lock);
	if (gp->rblk)
		pblk_page_invalidate(pblk, gp);

	gp->addr = paddr;
	gp->rblk = rblk;

	rev = &pblk->rev_trans_map[gp->addr - pblk->poffset];
	rev->addr = laddr;
	spin_unlock(&pblk->rev_lock);

	return gp;
}

static u64 pblk_alloc_addr(struct pblk *pblk, struct pblk_block *rblk)
{
	u64 addr = ADDR_EMPTY;

	spin_lock(&rblk->lock);
	if (block_is_full(pblk, rblk))
		goto out;

	addr = block_to_addr(pblk, rblk) + rblk->next_page;

	rblk->next_page++;
out:
	spin_unlock(&rblk->lock);
	return addr;
}

/* Simple round-robin Logical to physical address translation.
 *
 * Retrieve the mapping using the active append point. Then update the ap for
 * the next write to the disk.
 *
 * Returns pblk_addr with the physical address and block. Remember to return to
 * pblk->addr_cache when request is finished.
 */
static struct pblk_addr *pblk_map_page(struct pblk *pblk, sector_t laddr,
								int is_gc)
{
	struct pblk_lun *rlun;
	struct pblk_block *rblk;
	struct nvm_lun *lun;
	u64 paddr;

	rlun = pblk_get_lun_rr(pblk, is_gc);
	lun = rlun->parent;

	if (!is_gc && lun->nr_free_blocks < pblk->nr_luns * 4)
		return NULL;

	spin_lock(&rlun->lock);

	rblk = rlun->cur;
retry:
	paddr = pblk_alloc_addr(pblk, rblk);

	if (paddr == ADDR_EMPTY) {
		rblk = pblk_get_blk(pblk, rlun, 0);
		if (rblk) {
			pblk_set_lun_cur(rlun, rblk);
			goto retry;
		}

		if (is_gc) {
			/* retry from emergency gc block */
			paddr = pblk_alloc_addr(pblk, rlun->gc_cur);
			if (paddr == ADDR_EMPTY) {
				rblk = pblk_get_blk(pblk, rlun, 1);
				if (!rblk) {
					pr_err("pblk: no more blocks");
					goto err;
				}

				rlun->gc_cur = rblk;
				paddr = pblk_alloc_addr(pblk, rlun->gc_cur);
			}
			rblk = rlun->gc_cur;
		}
	}

	spin_unlock(&rlun->lock);
	return pblk_update_map(pblk, laddr, rblk, paddr);
err:
	spin_unlock(&rlun->lock);
	return NULL;
}

static void pblk_run_gc(struct pblk *pblk, struct pblk_block *rblk)
{
	struct pblk_block_gc *gcb;

	gcb = mempool_alloc(pblk->gcb_pool, GFP_ATOMIC);
	if (!gcb) {
		pr_err("pblk: unable to queue block for gc.");
		return;
	}

	gcb->pblk = pblk;
	gcb->rblk = rblk;

	INIT_WORK(&gcb->ws_gc, pblk_gc_queue);
	queue_work(pblk->kgc_wq, &gcb->ws_gc);
}

static void pblk_sync_buffer(struct pblk *pblk, struct pblk_addr *p)
{
	struct pblk_block *rblk;
	struct pblk_w_buf *buf;
	struct nvm_lun *lun;
	unsigned long bppa;

	rblk = p->rblk;
	buf = &rblk->w_buf;
	lun = rblk->parent->lun;

	bppa = pblk->dev->sec_per_blk * rblk->parent->id;

	WARN_ON(test_and_set_bit((p->addr - bppa), buf->sync_bitmap));

#ifdef CONFIG_NVM_DEBUG
		atomic_dec(&pblk->inflight_writes);
		atomic_inc(&pblk->sync_writes);
#endif

	if (unlikely(bitmap_full(buf->sync_bitmap, buf->nentries))) {
		/* Write buffer out-of-bounds */
		WARN_ON((buf->cur_mem != buf->nentries) &&
					(buf->cur_mem != buf->cur_subm));

		pblk_run_gc(pblk, rblk);
	}
}

static void pblk_end_io_write(struct pblk *pblk, struct nvm_rq *rqd,
							uint8_t nr_pages)
{
	struct pblk_buf_rq *brrqd = nvm_rq_to_pdu(rqd);
	struct pblk_rq *rrqd;
	int i;

	for (i = 0; i < nr_pages; i++) {
		rrqd = brrqd[i].rrqd;
		pblk_sync_buffer(pblk, brrqd[i].addr);
		kref_put(&rrqd->refs, pblk_release_and_free_rrqd);
	}

	mempool_free(brrqd, pblk->m_rrq_pool);
	pblk_writer_kick(pblk);
}

static void pblk_end_io_read(struct pblk *pblk, struct nvm_rq *rqd,
							uint8_t nr_pages)
{
	struct pblk_rq *rrqd = nvm_rq_to_pdu(rqd);

	if (rqd->flags & NVM_IOTYPE_GC)
		return;

	pblk_unlock_rq(pblk, rrqd);
	mempool_free(rrqd, pblk->rrq_pool);
#ifdef CONFIG_NVM_DEBUG
	atomic_sub(nr_pages, &pblk->inflight_reads);
#endif
}

static void pblk_end_io(struct nvm_rq *rqd)
{
	struct pblk *pblk = container_of(rqd->ins, struct pblk, instance);
	uint8_t nr_pages = rqd->nr_pages;

	if (bio_data_dir(rqd->bio) == WRITE) {
		pblk_end_io_write(pblk, rqd, nr_pages);
	} else {
		if (rqd->flags & NVM_IOTYPE_SYNC)
			return;
		pblk_end_io_read(pblk, rqd, nr_pages);
	}

	bio_put(rqd->bio);

	if (nr_pages > 1)
		nvm_dev_dma_free(pblk->dev, rqd->ppa_list, rqd->dma_ppa_list);
	if (rqd->metadata)
		nvm_dev_dma_free(pblk->dev, rqd->metadata, rqd->dma_metadata);

	mempool_free(rqd, pblk->rq_pool);
}

/*
 * Copy data from current bio to block write buffer. This if necessary
 * to guarantee durability if a flash block becomes bad before all pages
 * are written. This buffer is also used to write at the right page
 * granurality
 */
static int pblk_write_to_buffer(struct pblk *pblk, struct bio *bio,
				struct pblk_rq *rrqd, struct pblk_addr *addr,
				struct pblk_w_buf *w_buf,
				unsigned long flags)
{
	struct nvm_dev *dev = pblk->dev;
	unsigned int bio_len = bio_cur_bytes(bio);

	if (bio_len != PBLK_EXPOSED_PAGE_SIZE)
		return NVM_IO_ERR;

	spin_lock(&w_buf->w_lock);

	WARN_ON(w_buf->cur_mem == w_buf->nentries);

	w_buf->mem->rrqd = rrqd;
	w_buf->mem->addr = addr;
	w_buf->mem->flags = flags;

	memcpy(w_buf->mem->data, bio_data(bio), bio_len);

	w_buf->cur_mem++;
	if (likely(w_buf->cur_mem < w_buf->nentries)) {
		w_buf->mem++;
		w_buf->mem->data =
				w_buf->data + (w_buf->cur_mem * dev->sec_size);
	}

	spin_unlock(&w_buf->w_lock);

	return 0;
}

static int pblk_write_ppalist_rq(struct pblk *pblk, struct bio *bio,
			struct pblk_rq *rrqd, unsigned long flags, int nr_pages)
{
	struct pblk_w_buf *w_buf;
	struct pblk_addr *p;
	struct pblk_lun *rlun;
	sector_t laddr = pblk_get_laddr(bio);
	int is_gc = flags & NVM_IOTYPE_GC;
	int err;
	int i;

	if (!is_gc && pblk_lock_rq(pblk, bio, rrqd)) {
		kref_put(&rrqd->refs, pblk_free_rrqd);
		return NVM_IO_REQUEUE;
	}

	for (i = 0; i < nr_pages; i++) {
		kref_get(&rrqd->refs);

		/* We assume that mapping occurs at 4KB granularity */
		p = pblk_map_page(pblk, laddr + i, is_gc);
		if (!p) {
			BUG_ON(is_gc);
			kref_put(&rrqd->refs, pblk_release_and_free_rrqd);
			pblk_gc_kick(pblk);
			return NVM_IO_REQUEUE;
		}

		w_buf = &p->rblk->w_buf;
		rlun = p->rblk->rlun;

		rrqd->addr = p;

#ifdef CONFIG_NVM_DEBUG
		atomic_inc(&pblk->inflight_writes);
		atomic_inc(&pblk->req_writes);
#endif

		err = pblk_write_to_buffer(pblk, bio, rrqd, p, w_buf, flags);
		if (err) {
			pr_err("pblk: could not write to write buffer\n");
			return err;
		}

		bio_advance(bio, PBLK_EXPOSED_PAGE_SIZE);

		queue_work(pblk->kw_wq, &rlun->ws_writer);
	}

	if (kref_put(&rrqd->refs, pblk_release_and_free_rrqd)) {
		pr_err("pblk: request reference counter dailed\n");
		return NVM_IO_ERR;
	}

	return NVM_IO_DONE;
}

static int pblk_write_rq(struct pblk *pblk, struct bio *bio,
				struct pblk_rq *rrqd, unsigned long flags)
{
	struct pblk_w_buf *w_buf;
	struct pblk_addr *p;
	struct pblk_lun *rlun;
	int is_gc = flags & NVM_IOTYPE_GC;
	int err;
	sector_t laddr = pblk_get_laddr(bio);

	if (!is_gc && pblk_lock_rq(pblk, bio, rrqd)) {
		mempool_free(rrqd, pblk->rrq_pool);
		return NVM_IO_REQUEUE;
	}

	p = pblk_map_page(pblk, laddr, is_gc);
	if (!p) {
		BUG_ON(is_gc);
		kref_put(&rrqd->refs, pblk_release_and_free_rrqd);
		pblk_gc_kick(pblk);
		return NVM_IO_REQUEUE;
	}

	w_buf = &p->rblk->w_buf;
	rlun = p->rblk->rlun;

	rrqd->addr = p;

#ifdef CONFIG_NVM_DEBUG
	atomic_inc(&pblk->inflight_writes);
	atomic_inc(&pblk->req_writes);
#endif

	err = pblk_write_to_buffer(pblk, bio, rrqd, p, w_buf, flags);
	if (err) {
		pr_err("pblk: could not write to write buffer\n");
		return err;
	}

	queue_work(pblk->kw_wq, &rlun->ws_writer);
	return NVM_IO_DONE;
}

static int pblk_buffer_write(struct pblk *pblk, struct bio *bio,
				struct pblk_rq *rrqd, unsigned long flags)
{
	uint8_t nr_pages = pblk_get_pages(bio);

	rrqd->nr_pages = nr_pages;

	if (nr_pages > 1)
		return pblk_write_ppalist_rq(pblk, bio, rrqd, flags, nr_pages);
	else
		return pblk_write_rq(pblk, bio, rrqd, flags);
}

static int pblk_read_ppalist_rq(struct pblk *pblk, struct bio *bio,
			struct nvm_rq *rqd, struct pblk_buf_rq *brrqd,
			unsigned long flags, int nr_pages)
{
	struct pblk_rq *rrqd = nvm_rq_to_pdu(rqd);
	struct pblk_addr *gp;
	sector_t laddr = pblk_get_laddr(bio);
	int is_gc = flags & NVM_IOTYPE_GC;
	int i;

	if (!is_gc && pblk_lock_rq(pblk, bio, rrqd)) {
		nvm_dev_dma_free(pblk->dev, rqd->ppa_list, rqd->dma_ppa_list);
		return NVM_IO_REQUEUE;
	}

	for (i = 0; i < nr_pages; i++) {
		/* We assume that mapping occurs at 4KB granularity */
		BUG_ON(!(laddr + i >= 0 && laddr + i < pblk->nr_sects));
		gp = &pblk->trans_map[laddr + i];

		if (gp->rblk) {
			rqd->ppa_list[i] = pblk_ppa_to_gaddr(pblk->dev,
								gp->addr);
		} else {
			BUG_ON(is_gc);
			pblk_unlock_rq(pblk, rrqd);
			nvm_dev_dma_free(pblk->dev, rqd->ppa_list,
							rqd->dma_ppa_list);
			return NVM_IO_DONE;
		}

		brrqd[i].addr = gp;

#ifdef CONFIG_NVM_DEBUG
		atomic_inc(&pblk->inflight_reads);
#endif
	}

	rqd->opcode = NVM_OP_HBREAD;

	return NVM_IO_OK;
}

static int pblk_read_rq(struct pblk *pblk, struct bio *bio, struct nvm_rq *rqd,
							unsigned long flags)
{
	struct pblk_rq *rrqd = nvm_rq_to_pdu(rqd);
	int is_gc = flags & NVM_IOTYPE_GC;
	sector_t laddr = pblk_get_laddr(bio);
	struct pblk_addr *gp;

	if (!is_gc && pblk_lock_rq(pblk, bio, rrqd))
		return NVM_IO_REQUEUE;

	BUG_ON(!(laddr >= 0 && laddr < pblk->nr_sects));
	gp = &pblk->trans_map[laddr];

	if (gp->rblk) {
		rqd->ppa_addr = pblk_ppa_to_gaddr(pblk->dev, gp->addr);
	} else {
		BUG_ON(is_gc);
		pblk_unlock_rq(pblk, rrqd);
		return NVM_IO_DONE;
	}

	rqd->opcode = NVM_OP_HBREAD;
	rrqd->addr = gp;

#ifdef CONFIG_NVM_DEBUG
		atomic_inc(&pblk->inflight_reads);
#endif

	return NVM_IO_OK;
}

static int pblk_read_w_buf_entry(struct bio *bio, struct pblk_block *rblk,
					struct bvec_iter iter, int entry)
{
	struct buf_entry *read_entry;
	struct bio_vec bv;
	struct page *page;
	void *kaddr;
	void *data;
	int read = 0;

	lockdep_assert_held(&rblk->w_buf.s_lock);

	spin_lock(&rblk->w_buf.w_lock);
	if (entry >= rblk->w_buf.cur_mem) {
		spin_unlock(&rblk->w_buf.w_lock);
		goto out;
	}
	spin_unlock(&rblk->w_buf.w_lock);

	read_entry = &rblk->w_buf.entries[entry];
	data = read_entry->data;

	bv = bio_iter_iovec(bio, iter);
	page = bv.bv_page;
	kaddr = kmap_atomic(page);
	memcpy(kaddr + bv.bv_offset, data, PBLK_EXPOSED_PAGE_SIZE);
	kunmap_atomic(kaddr);
	read++;

out:
	return read;
}

static int pblk_read_from_w_buf(struct pblk *pblk, struct nvm_rq *rqd,
			struct pblk_buf_rq *brrqd, unsigned long *read_bitmap)
{
	struct nvm_dev *dev = pblk->dev;
	struct pblk_rq *rrqd = nvm_rq_to_pdu(rqd);
	struct pblk_addr *addr;
	struct bio *bio = rqd->bio;
	struct bvec_iter iter = bio->bi_iter;
	struct pblk_block *rblk;
	unsigned long blk_id;
	int nr_pages = rqd->nr_pages;
	int left = nr_pages;
	int read = 0;
	int entry;
	int i;

	if (nr_pages != bio->bi_vcnt)
		goto out;

	if (nr_pages == 1) {
		rblk = rrqd->addr->rblk;

		/* If the write buffer exists, the block is open in memory */
		spin_lock(&rblk->w_buf.s_lock);
		atomic_inc(&rblk->w_buf.refs);
		if (rblk->w_buf.entries) {
			blk_id = rblk->parent->id;
			entry = rrqd->addr->addr -
				(blk_id * dev->sec_per_pg * dev->pgs_per_blk);

			read = pblk_read_w_buf_entry(bio, rblk, iter, entry);

			left -= read;
			WARN_ON(test_and_set_bit(0, read_bitmap));
		}
		bio_advance_iter(bio, &iter, PBLK_EXPOSED_PAGE_SIZE);

		atomic_dec(&rblk->w_buf.refs);
		spin_unlock(&rblk->w_buf.s_lock);

		goto out;
	}

	/* Iterate through all pages and copy those that are found in the write
	 * buffer. We will complete the holes (if any) with a intermediate bio
	 * later on
	 */
	for (i = 0; i < nr_pages; i++) {
		addr = brrqd[i].addr;
		rblk = addr->rblk;

		/* If the write buffer exists, the block is open in memory */
		spin_lock(&rblk->w_buf.s_lock);
		atomic_inc(&rblk->w_buf.refs);
		if (rblk->w_buf.entries) {
			blk_id = rblk->parent->id;
			entry = addr->addr - (blk_id * dev->sec_per_pg *
							dev->pgs_per_blk);

			read = pblk_read_w_buf_entry(bio, rblk, iter, entry);

			left -= read;
			WARN_ON(test_and_set_bit(i, read_bitmap));
		}
		bio_advance_iter(bio, &iter, PBLK_EXPOSED_PAGE_SIZE);

		atomic_dec(&rblk->w_buf.refs);
		spin_unlock(&rblk->w_buf.s_lock);
	}

out:
	return left;
}

static int pblk_submit_read_io(struct pblk *pblk, struct bio *bio,
				struct nvm_rq *rqd, unsigned long flags)
{
	struct pblk_rq *rrqd = nvm_rq_to_pdu(rqd);
	int err;

	err = nvm_submit_io(pblk->dev, rqd);
	if (err) {
		pr_err("pblk: I/O submission failed: %d\n", err);
		bio_put(bio);
		if (!(flags & NVM_IOTYPE_GC)) {
			pblk_unlock_rq(pblk, rrqd);
			if (rqd->nr_pages > 1)
				nvm_dev_dma_free(pblk->dev,
			rqd->ppa_list, rqd->dma_ppa_list);
		}
		return NVM_IO_ERR;
	}

	return NVM_IO_OK;
}

static int pblk_fill_partial_read_bio(struct pblk *pblk, struct bio *bio,
				unsigned long *read_bitmap, struct nvm_rq *rqd,
				struct pblk_buf_rq *brrqd, uint8_t nr_pages)
{
	struct bio *new_bio;
	struct page *page;
	struct bio_vec src_bv, dst_bv;
	void *src_p, *dst_p;
	int nr_holes = nr_pages - bitmap_weight(read_bitmap, nr_pages);
	int hole;
	int i = 0;
	int ret;
	DECLARE_COMPLETION_ONSTACK(wait);

	new_bio = bio_alloc(GFP_KERNEL, nr_holes);
	if (!new_bio) {
		pr_err("nvm: pblk: could not alloc read bio\n");
		return NVM_IO_ERR;
	}

	hole = find_first_zero_bit(read_bitmap, nr_pages);
	do {
		page = mempool_alloc(pblk->page_pool, GFP_KERNEL);
		if (!page) {
			bio_put(new_bio);
			pr_err("nvm: pblk: could not alloc read page\n");
			goto err;
		}

		ret = bio_add_page(new_bio, page, PBLK_EXPOSED_PAGE_SIZE, 0);
		if (ret != PBLK_EXPOSED_PAGE_SIZE) {
			pr_err("nvm: pblk: could not add page to bio\n");
			mempool_free(page, pblk->page_pool);
			goto err;
		}

		rqd->ppa_list[i] = pblk_ppa_to_gaddr(pblk->dev,
							brrqd[hole].addr->addr);

		i++;
		hole = find_next_zero_bit(read_bitmap, nr_pages, hole + 1);
	} while (hole != nr_pages);

	if (nr_holes != new_bio->bi_vcnt) {
		pr_err("pblk: malformed bio\n");
		goto err;
	}

	new_bio->bi_iter.bi_sector = bio->bi_iter.bi_sector;
	new_bio->bi_rw = READ;
	new_bio->bi_private = &wait;
	new_bio->bi_end_io = pblk_end_sync_bio;

	rqd->flags |= NVM_IOTYPE_SYNC;
	rqd->bio = new_bio;
	rqd->nr_pages = nr_holes;

	pblk_submit_read_io(pblk, new_bio, rqd, rqd->flags);
	wait_for_completion_io(&wait);

	if (new_bio->bi_error)
		goto err;

	/* Fill the holes in the original bio */
	i = 0;
	hole = find_first_zero_bit(read_bitmap, nr_pages);
	do {
		src_bv = new_bio->bi_io_vec[i];
		dst_bv = bio->bi_io_vec[hole];

		src_p = kmap_atomic(src_bv.bv_page);
		dst_p = kmap_atomic(dst_bv.bv_page);

		memcpy(dst_p + dst_bv.bv_offset,
			src_p + src_bv.bv_offset,
			PBLK_EXPOSED_PAGE_SIZE);

		kunmap_atomic(src_p);
		kunmap_atomic(dst_p);

		mempool_free(&src_bv.bv_page, pblk->page_pool);

		i++;
		hole = find_next_zero_bit(read_bitmap, nr_pages, hole + 1);
	} while (hole != nr_pages);

	bio_put(new_bio);

	/* Complete the original bio and associated request */
	rqd->flags &= ~NVM_IOTYPE_SYNC;
	rqd->bio = bio;
	rqd->nr_pages = nr_pages;

	bio_endio(bio);
	pblk_end_io(rqd);
	mempool_free(brrqd, pblk->m_rrq_pool);
	return NVM_IO_OK;

err:
	/* Free allocated pages in new bio */
	for (i = 0; i < new_bio->bi_vcnt; i++) {
		src_bv = new_bio->bi_io_vec[i];
		mempool_free(&src_bv.bv_page, pblk->page_pool);
	}
	bio_endio(new_bio);
	mempool_free(brrqd, pblk->m_rrq_pool);
	return NVM_IO_ERR;
}

static int pblk_submit_read(struct pblk *pblk, struct bio *bio,
				struct pblk_rq *rrqd, unsigned long flags)
{
	struct nvm_rq *rqd;
	struct pblk_buf_rq *brrqd = NULL;
	unsigned long read_bitmap; /* Max 64 ppas per request */
	uint8_t left;
	uint8_t nr_pages = pblk_get_pages(bio);
	int err;

	bitmap_zero(&read_bitmap, nr_pages);

	rqd = mempool_alloc(pblk->rq_pool, GFP_KERNEL);
	if (!rqd) {
		pr_err_ratelimited("pblk: not able to queue bio.");
		bio_io_error(bio);
		return NVM_IO_ERR;
	}
	rqd->metadata = NULL;
	rqd->priv = rrqd;

	if (nr_pages > 1) {
		rqd->ppa_list = nvm_dev_dma_alloc(pblk->dev, GFP_KERNEL,
						&rqd->dma_ppa_list);
		if (!rqd->ppa_list) {
			pr_err("pblk: not able to allocate ppa list\n");
			mempool_free(rqd, pblk->rq_pool);
			mempool_free(rrqd, pblk->rrq_pool);
			return NVM_IO_ERR;
		}

		brrqd = mempool_alloc(pblk->m_rrq_pool, GFP_KERNEL);
		if (!brrqd) {
			pr_err_ratelimited("pblk: not able to queue bio.");
			bio_io_error(bio);
			return NVM_IO_ERR;
		}

		err = pblk_read_ppalist_rq(pblk, bio, rqd, brrqd, flags,
								nr_pages);
		if (err) {
			mempool_free(brrqd, pblk->m_rrq_pool);
			mempool_free(rqd, pblk->rq_pool);
			mempool_free(rrqd, pblk->rrq_pool);
			return err;
		}
	} else {
		err = pblk_read_rq(pblk, bio, rqd, flags);
		if (err) {
			mempool_free(rrqd, pblk->rrq_pool);
			mempool_free(rqd, pblk->rq_pool);
			return err;
		}
	}

	bio_get(bio);
	rqd->bio = bio;
	rqd->ins = &pblk->instance;
	rqd->nr_pages = rrqd->nr_pages = nr_pages;
	rqd->flags = flags;

	left = pblk_read_from_w_buf(pblk, rqd, brrqd, &read_bitmap);
	if (left == 0) {
		bio_endio(bio);
		pblk_end_io(rqd);
		if (brrqd)
			mempool_free(brrqd, pblk->m_rrq_pool);
		return NVM_IO_OK;
	} else if (left < 0) {
		if (brrqd)
			mempool_free(brrqd, pblk->m_rrq_pool);
		return NVM_IO_ERR;
	}

	if (bitmap_empty(&read_bitmap, nr_pages)) {
		if (brrqd)
			mempool_free(brrqd, pblk->m_rrq_pool);
		return pblk_submit_read_io(pblk, bio, rqd, flags);
	}

	/* The read bio could not be completely read from the write buffer. This
	 * case only occurs when several pages are sent in a single bio
	 */
	return pblk_fill_partial_read_bio(pblk, bio, &read_bitmap, rqd, brrqd,
								nr_pages);
}

static int pblk_submit_io(struct pblk *pblk, struct bio *bio,
				struct pblk_rq *rrqd, unsigned long flags)
{
	int bio_size = bio_sectors(bio) << 9;

	if (bio_size < pblk->dev->sec_size)
		return NVM_IO_ERR;
	else if (bio_size > pblk->dev->max_rq_size)
		return NVM_IO_ERR;

	if (bio_rw(bio) == READ)
		return pblk_submit_read(pblk, bio, rrqd, flags);

	return pblk_buffer_write(pblk, bio, rrqd, flags);
}

static blk_qc_t pblk_make_rq(struct request_queue *q, struct bio *bio)
{
	struct pblk *pblk = q->queuedata;
	struct pblk_rq *rrqd;
	int err;

	if (bio->bi_rw & REQ_DISCARD) {
		pblk_discard(pblk, bio);
		return BLK_QC_T_NONE;
	}

	rrqd = mempool_alloc(pblk->rrq_pool, GFP_KERNEL);
	if (!rrqd) {
		pr_err_ratelimited("pblk: not able to allocate rrqd.");
		bio_io_error(bio);
		return BLK_QC_T_NONE;
	}
	rrqd->pblk = pblk;
	kref_init(&rrqd->refs);

	err = pblk_submit_io(pblk, bio, rrqd, NVM_IOTYPE_NONE);
	switch (err) {
	case NVM_IO_OK:
		return BLK_QC_T_NONE;
	case NVM_IO_ERR:
		bio_io_error(bio);
		break;
	case NVM_IO_DONE:
		bio_endio(bio);
		break;
	case NVM_IO_REQUEUE:
		spin_lock(&pblk->bio_lock);
		bio_list_add(&pblk->requeue_bios, bio);
		spin_unlock(&pblk->bio_lock);
		queue_work(pblk->kgc_wq, &pblk->ws_requeue);
		break;
	}

	return BLK_QC_T_NONE;
}

static int pblk_alloc_page_in_bio(struct pblk *pblk, struct bio *bio,
								void *data)
{
	struct page *page;
	int err;

	if (PAGE_SIZE != PBLK_EXPOSED_PAGE_SIZE)
		return -1;

	page = virt_to_page(data);
	if (!page) {
		pr_err("nvm: pblk: could not alloc page\n");
		return -1;
	}

	err = bio_add_page(bio, page, PBLK_EXPOSED_PAGE_SIZE, 0);
	if (err != PBLK_EXPOSED_PAGE_SIZE) {
		pr_err("nvm: pblk: could not add page to bio\n");
		return -1;
	}

	return 0;
}

static void pblk_submit_write(struct work_struct *work)
{
	struct pblk_lun *rlun = container_of(work, struct pblk_lun, ws_writer);
	struct pblk *pblk = rlun->pblk;
	struct nvm_dev *dev = pblk->dev;
	struct pblk_addr *addr;
	struct pblk_rq *rrqd;
	struct pblk_buf_rq *brrqd;
	void *data;
	struct nvm_rq *rqd;
	struct pblk_block *rblk, *trblk;
	struct bio *bio;
	int pgs_to_sync, pgs_avail;
	int sync = NVM_SYNC_HARD;
	int err;
	int i;

	/* Note that OS pages are typically mapped to flash page sectors, which
	 * are 4K; a flash page might be formed of several sectors. Also,
	 * controllers typically program flash pages across multiple planes.
	 * This is the flash programing granurality, and the reason behind the
	 * sync strategy performed in this write thread.
	 */
try:
	list_for_each_entry_safe(rblk, trblk, &rlun->open_list, list) {
		if (!spin_trylock(&rblk->w_buf.w_lock))
			continue;

		/* If the write thread has already submitted all I/Os in the
		 * write buffer for this block ignore that the block is in the
		 * open list; it is on its way to the closed list. This enables
		 * us to avoid taking a lock on the list.
		 */
		if (unlikely(rblk->w_buf.cur_subm == rblk->w_buf.nentries)) {
			spin_unlock(&rblk->w_buf.w_lock);
			schedule();
			goto try;
		}
		pgs_avail = rblk->w_buf.cur_mem - rblk->w_buf.cur_subm;

		switch (sync) {
		case NVM_SYNC_SOFT:
			pgs_to_sync = (pgs_avail >= pblk->max_write_pgs) ?
					pblk->max_write_pgs : 0;
			break;
		case NVM_SYNC_HARD:
			if (pgs_avail >= pblk->max_write_pgs)
				pgs_to_sync = pblk->max_write_pgs;
			else if (pgs_avail >= pblk->min_write_pgs)
				pgs_to_sync = pblk->min_write_pgs *
					(pgs_avail / pblk->min_write_pgs);
			else
				pgs_to_sync = pgs_avail; /* TODO: ADD PADDING */
			break;
		case NVM_SYNC_OPORT:
			if (pgs_avail >= pblk->max_write_pgs)
				pgs_to_sync = pblk->max_write_pgs;
			else if (pgs_avail >= pblk->min_write_pgs)
				pgs_to_sync = pblk->min_write_pgs *
					(pgs_avail / pblk->min_write_pgs);
			else
				pgs_to_sync = 0;
		}

		if (pgs_to_sync == 0) {
			spin_unlock(&rblk->w_buf.w_lock);
			continue;
		}

		bio = bio_alloc(GFP_ATOMIC, pgs_to_sync);
		if (!bio) {
			pr_err("nvm: pblk: could not alloc write bio\n");
			goto out1;
		}

		rqd = mempool_alloc(pblk->rq_pool, GFP_ATOMIC);
		if (!rqd) {
			pr_err_ratelimited("pblk: not able to create w req.");
			goto out2;
		}
		rqd->metadata = NULL;

		brrqd = mempool_alloc(pblk->m_rrq_pool, GFP_ATOMIC);
		if (!brrqd) {
			pr_err_ratelimited("pblk: not able to create w rea.");
			goto out3;
		}

		bio->bi_iter.bi_sector = 0; /* artificial bio */
		bio->bi_rw = WRITE;

		rqd->opcode = NVM_OP_HBWRITE;
		rqd->bio = bio;
		rqd->ins = &pblk->instance;
		rqd->nr_pages = pgs_to_sync;
		rqd->priv = brrqd;

		if (pgs_to_sync == 1) {
			rrqd = rblk->w_buf.subm->rrqd;
			addr = rblk->w_buf.subm->addr;
			rqd->flags = rblk->w_buf.subm->flags;
			data = rblk->w_buf.subm->data;

			err = pblk_alloc_page_in_bio(pblk, bio, data);
			if (err) {
				pr_err("pblk: cannot allocate page in bio\n");
				goto out4;
			}

			/* TODO: This address can be skipped */
			if (addr->addr == ADDR_EMPTY)
				pr_err_ratelimited("pblk: submitting empty rq");

			rqd->ppa_addr = pblk_ppa_to_gaddr(dev, addr->addr);

			brrqd[0].rrqd = rrqd;
			brrqd[0].addr = addr;

			rblk->w_buf.subm++;
			rblk->w_buf.cur_subm++;

			goto submit_io;
		}

		/* This bio will contain several pppas */
		rqd->ppa_list = nvm_dev_dma_alloc(pblk->dev, GFP_ATOMIC,
							&rqd->dma_ppa_list);
		if (!rqd->ppa_list) {
			pr_err("pblk: not able to allocate ppa list\n");
			goto out4;
		}

		for (i = 0; i < pgs_to_sync; i++) {
			rrqd = rblk->w_buf.subm->rrqd;
			addr = rblk->w_buf.subm->addr;
			rqd->flags = rblk->w_buf.subm->flags;
			data = rblk->w_buf.subm->data;

			err = pblk_alloc_page_in_bio(pblk, bio, data);
			if (err) {
				pr_err("pblk: cannot allocate page in bio\n");
				goto out5;
			}

			/* TODO: This address can be skipped */
			if (addr->addr == ADDR_EMPTY)
				pr_err_ratelimited("pblk: submitting empty rq");

			rqd->ppa_list[i] = pblk_ppa_to_gaddr(dev, addr->addr);

			brrqd[i].rrqd = rrqd;
			brrqd[i].addr = addr;

			rblk->w_buf.subm++;
			rblk->w_buf.cur_subm++;
		}

submit_io:
		WARN_ON(rblk->w_buf.cur_subm > rblk->w_buf.nentries);

		spin_unlock(&rblk->w_buf.w_lock);

		err = nvm_submit_io(dev, rqd);
		if (err) {
			pr_err("pblk: I/O submission failed: %d\n", err);
			mempool_free(rqd, pblk->rq_pool);
			bio_put(bio);
		}
#ifdef CONFIG_NVM_DEBUG
		atomic_add(pgs_to_sync, &pblk->sub_writes);
#endif
	}

	return;

out5:
	nvm_dev_dma_free(pblk->dev, rqd->ppa_list, rqd->dma_ppa_list);
out4:
	mempool_free(brrqd, pblk->m_rrq_pool);
out3:
	mempool_free(rqd, pblk->rq_pool);
out2:
	bio_put(bio);
out1:
	spin_unlock(&rblk->w_buf.w_lock);
}

static void pblk_requeue(struct work_struct *work)
{
	struct pblk *pblk = container_of(work, struct pblk, ws_requeue);
	struct bio_list bios;
	struct bio *bio;

	bio_list_init(&bios);

	spin_lock(&pblk->bio_lock);
	bio_list_merge(&bios, &pblk->requeue_bios);
	bio_list_init(&pblk->requeue_bios);
	spin_unlock(&pblk->bio_lock);

	while ((bio = bio_list_pop(&bios)))
		pblk_make_rq(pblk->disk->queue, bio);
}

static void pblk_gc_free(struct pblk *pblk)
{
	if (pblk->krqd_wq)
		destroy_workqueue(pblk->krqd_wq);

	if (pblk->kgc_wq)
		destroy_workqueue(pblk->kgc_wq);
}

static int pblk_gc_init(struct pblk *pblk)
{
	pblk->krqd_wq = alloc_workqueue("pblk-lun", WQ_MEM_RECLAIM | WQ_UNBOUND,
								pblk->nr_luns);
	if (!pblk->krqd_wq)
		return -ENOMEM;

	pblk->kgc_wq = alloc_workqueue("pblk-bg", WQ_MEM_RECLAIM, 1);
	if (!pblk->kgc_wq)
		return -ENOMEM;

	setup_timer(&pblk->gc_timer, pblk_gc_timer, (unsigned long)pblk);

	return 0;
}

static void pblk_map_free(struct pblk *pblk)
{
	vfree(pblk->rev_trans_map);
	vfree(pblk->trans_map);
}

static int pblk_map_init(struct pblk *pblk)
{
	struct nvm_dev *dev = pblk->dev;
	sector_t i;
	u64 slba;

	slba = pblk->soffset >> (ilog2(dev->sec_size) - 9);

	pblk->trans_map = vzalloc(sizeof(struct pblk_addr) * pblk->nr_sects);
	if (!pblk->trans_map)
		return -ENOMEM;

	pblk->rev_trans_map = vmalloc(sizeof(struct pblk_rev_addr)
							* pblk->nr_sects);
	if (!pblk->rev_trans_map)
		return -ENOMEM;

	for (i = 0; i < pblk->nr_sects; i++) {
		struct pblk_addr *p = &pblk->trans_map[i];
		struct pblk_rev_addr *r = &pblk->rev_trans_map[i];

		p->addr = ADDR_EMPTY;
		r->addr = ADDR_EMPTY;
	}

	return 0;
}

/* Minimum pages needed within a lun */
#define PAGE_POOL_SIZE 16
#define ADDR_POOL_SIZE 64

static int pblk_core_init(struct pblk *pblk)
{
	struct nvm_dev *dev = pblk->dev;

	down_write(&pblk_lock);
	if (!pblk_gcb_cache) {
		pblk_gcb_cache = kmem_cache_create("pblk_gcb",
				sizeof(struct pblk_block_gc), 0, 0, NULL);
		if (!pblk_gcb_cache) {
			up_write(&pblk_lock);
			return -ENOMEM;
		}

		pblk_r_rq_cache = kmem_cache_create("pblk_r_rq",
					sizeof(struct nvm_rq), 0, 0, NULL);
		if (!pblk_rq_cache) {
			kmem_cache_destroy(pblk_gcb_cache);
			up_write(&pblk_lock);
			return -ENOMEM;
		}

		pblk_w_rq_cache = kmem_cache_create("pblk_w_rq",
			sizeof(struct nvm_rq) +
			(pblk->max_write_pgs * sizeof(struct pblk_buf_rq)),
			0, 0, NULL);
		if (!pblk_w_rq_cache) {
			kmem_cache_destroy(pblk_r_rq_cache);
			kmem_cache_destroy(pblk_gcb_cache);
			kmem_cache_destroy(pblk_rq_cache);
			up_write(&pblk_lock);
			return -ENOMEM;
		}

		pblk_buf_rrq_cache = kmem_cache_create("pblk_m_rrq",
			pblk->max_write_pgs * sizeof(struct pblk_buf_rq),
			0, 0, NULL);
		if (!pblk_buf_rrq_cache) {
			kmem_cache_destroy(pblk_gcb_cache);
			kmem_cache_destroy(pblk_rq_cache);
			kmem_cache_destroy(pblk_rrq_cache);
			up_write(&pblk_lock);
			return -ENOMEM;
		}
	}

	/* we assume that sec->sec_size is the same as the page size exposed by
	 * pblk (4KB). We need extra logic otherwise
	 */
	if (!pblk_block_cache) {
		/* Write buffer: Allocate all buffer (for all block) at once. We
		 * avoid having to allocate a memory from the pool for each IO
		 * at the cost pre-allocating memory for the whole block when a
		 * new block is allocated from the media manager.
		 */
		pblk_wb_cache = kmem_cache_create("nvm_wb",
			dev->pgs_per_blk * dev->sec_per_pg * dev->sec_size,
			0, 0, NULL);
		if (!pblk_wb_cache) {
			kmem_cache_destroy(pblk_gcb_cache);
			kmem_cache_destroy(pblk_rq_cache);
			kmem_cache_destroy(pblk_rrq_cache);
			kmem_cache_destroy(pblk_buf_rrq_cache);
			up_write(&pblk_lock);
			return -ENOMEM;
		}

		/* Write buffer entries */
		pblk_block_cache = kmem_cache_create("nvm_entry",
			dev->pgs_per_blk * dev->sec_per_pg *
			sizeof(struct buf_entry),
			0, 0, NULL);
		if (!pblk_block_cache) {
			kmem_cache_destroy(pblk_gcb_cache);
			kmem_cache_destroy(pblk_rq_cache);
			kmem_cache_destroy(pblk_rrq_cache);
			kmem_cache_destroy(pblk_buf_rrq_cache);
			kmem_cache_destroy(pblk_wb_cache);
			up_write(&pblk_lock);
			return -ENOMEM;
		}
	}
	up_write(&pblk_lock);

	pblk->page_pool = mempool_create_page_pool(PAGE_POOL_SIZE, 0);
	if (!pblk->page_pool)
		return -ENOMEM;

	pblk->gcb_pool = mempool_create_slab_pool(pblk->dev->nr_luns,
								pblk_gcb_cache);
	if (!pblk->gcb_pool)
		return -ENOMEM;

	pblk->rq_pool = mempool_create_slab_pool(64, pblk_rq_cache);
	if (!pblk->rq_pool)
		return -ENOMEM;

	pblk->rrq_pool = mempool_create_slab_pool(64, pblk_rrq_cache);
	if (!pblk->rrq_pool)
		return -ENOMEM;

	pblk->m_rrq_pool = mempool_create_slab_pool(64, pblk_buf_rrq_cache);
	if (!pblk->m_rrq_pool)
		return -ENOMEM;

	pblk->block_pool = mempool_create_slab_pool(8, pblk_block_cache);
	if (!pblk->block_pool)
		return -ENOMEM;

	pblk->write_buf_pool = mempool_create_slab_pool(8, pblk_wb_cache);
	if (!pblk->write_buf_pool)
		return -ENOMEM;

	spin_lock_init(&pblk->inflights.lock);
	INIT_LIST_HEAD(&pblk->inflights.reqs);

	pblk->kw_wq = alloc_workqueue("pblk-writer",
				WQ_MEM_RECLAIM | WQ_UNBOUND, pblk->nr_luns);
	if (!pblk->kw_wq)
		return -ENOMEM;

	return 0;
}

static void pblk_core_free(struct pblk *pblk)
{
	if (pblk->kw_wq)
		destroy_workqueue(pblk->kw_wq);

	mempool_destroy(pblk->page_pool);
	mempool_destroy(pblk->gcb_pool);
	mempool_destroy(pblk->m_rrq_pool);
	mempool_destroy(pblk->rrq_pool);
	mempool_destroy(pblk->rq_pool);
	mempool_destroy(pblk->block_pool);
	mempool_destroy(pblk->write_buf_pool);
}

static void pblk_luns_free(struct pblk *pblk)
{
	struct nvm_dev *dev = pblk->dev;
	struct nvm_lun *lun;
	struct pblk_lun *rlun;
	int i;

	if (!pblk->luns)
		return;

	for (i = 0; i < pblk->nr_luns; i++) {
		rlun = &pblk->luns[i];
		lun = rlun->parent;
		if (!lun)
			break;
		dev->mt->release_lun(dev, lun->id);
		vfree(rlun->blocks);
	}

	kfree(pblk->luns);
}

static int pblk_luns_init(struct pblk *pblk, int lun_begin, int lun_end)
{
	struct nvm_dev *dev = pblk->dev;
	struct pblk_lun *rlun;
	int i, j, ret = -EINVAL;

	if (dev->pgs_per_blk > MAX_INVALID_PAGES_STORAGE * BITS_PER_LONG) {
		pr_err("pblk: number of pages per block too high.");
		return -EINVAL;
	}

	spin_lock_init(&pblk->rev_lock);

	pblk->luns = kcalloc(pblk->nr_luns, sizeof(struct pblk_lun),
								GFP_KERNEL);
	if (!pblk->luns)
		return -ENOMEM;

	pblk->min_write_pgs = dev->sec_per_pl * (dev->sec_size / PAGE_SIZE);
	/* assume max_phys_sect % dev->min_write_pgs == 0 */
	pblk->max_write_pgs = dev->ops->max_phys_sect;

	/* 1:1 mapping */
	for (i = 0; i < pblk->nr_luns; i++) {
		int lunid = lun_begin + i;
		struct nvm_lun *lun;

		if (dev->mt->reserve_lun(dev, lunid)) {
			pr_err("pblk: lun %u is already allocated\n", lunid);
			goto err;
		}

		lun = dev->mt->get_lun(dev, lunid);
		if (!lun)
			goto err;

		rlun = &pblk->luns[i];
		rlun->parent = lun;
		rlun->blocks = vzalloc(sizeof(struct pblk_block) *
						pblk->dev->blks_per_lun);
		if (!rlun->blocks) {
			ret = -ENOMEM;
			goto err;
		}

		for (j = 0; j < pblk->dev->blks_per_lun; j++) {
			struct pblk_block *rblk = &rlun->blocks[j];
			struct nvm_block *blk = &lun->blocks[j];

			rblk->parent = blk;
			rblk->rlun = rlun;
			INIT_LIST_HEAD(&rblk->prio);
			spin_lock_init(&rblk->lock);
		}

		rlun->pblk = pblk;
		INIT_LIST_HEAD(&rlun->prio_list);
		INIT_LIST_HEAD(&rlun->open_list);
		INIT_LIST_HEAD(&rlun->closed_list);

		INIT_WORK(&rlun->ws_writer, pblk_submit_write);
		INIT_WORK(&rlun->ws_gc, pblk_lun_gc);
		spin_lock_init(&rlun->lock);

		pblk->total_blocks += dev->blks_per_lun;
		pblk->nr_sects += dev->sec_per_lun;

	}

	return 0;
err:
	return ret;
}

/* returns 0 on success and stores the beginning address in *begin */
static int pblk_area_init(struct pblk *pblk, sector_t *begin)
{
	struct nvm_dev *dev = pblk->dev;
	struct nvmm_type *mt = dev->mt;
	sector_t size = pblk->nr_sects * dev->sec_size;

	size >>= 9;

	return mt->get_area(dev, begin, size);
}

static void pblk_area_free(struct pblk *pblk)
{
	struct nvm_dev *dev = pblk->dev;
	struct nvmm_type *mt = dev->mt;

	mt->put_area(dev, pblk->soffset);
}

static void pblk_free(struct pblk *pblk)
{
	pblk_gc_free(pblk);
	pblk_map_free(pblk);
	pblk_core_free(pblk);
	pblk_luns_free(pblk);
	pblk_area_free(pblk);

	kfree(pblk);
}

static void pblk_exit(void *private)
{
	struct pblk *pblk = private;

	del_timer(&pblk->gc_timer);

	flush_workqueue(pblk->krqd_wq);
	flush_workqueue(pblk->kgc_wq);
	/* flush_workqueue(pblk->kw_wq); */ /* TODO: Implement flush + padding*/

	pblk_free(pblk);
}

static sector_t pblk_capacity(void *private)
{
	struct pblk *pblk = private;
	struct nvm_dev *dev = pblk->dev;
	sector_t reserved, provisioned;

	/* cur, gc, and two emergency blocks for each lun */
	reserved = pblk->nr_luns * dev->max_pages_per_blk * 4;
	provisioned = pblk->nr_sects - reserved;

	if (reserved > pblk->nr_sects) {
		pr_err("pblk: not enough space available to expose storage.\n");
		return 0;
	}

	sector_div(provisioned, 10);
	return provisioned * 9 * NR_PHY_IN_LOG;
}

/*
 * Looks up the logical address from reverse trans map and check if its valid by
 * comparing the logical to physical address with the physical address.
 * Returns 0 on free, otherwise 1 if in use
 */
static void pblk_block_map_update(struct pblk *pblk, struct pblk_block *rblk)
{
	struct nvm_dev *dev = pblk->dev;
	int offset;
	struct pblk_addr *laddr;
	u64 paddr, pladdr;

	for (offset = 0; offset < dev->pgs_per_blk; offset++) {
		paddr = block_to_addr(pblk, rblk) + offset;

		pladdr = pblk->rev_trans_map[paddr].addr;
		if (pladdr == ADDR_EMPTY)
			continue;

		laddr = &pblk->trans_map[pladdr];

		if (paddr == laddr->addr) {
			laddr->rblk = rblk;
		} else {
			set_bit(offset, rblk->invalid_pages);
			rblk->nr_invalid_pages++;
		}
	}
}

static int pblk_blocks_init(struct pblk *pblk)
{
	struct pblk_lun *rlun;
	struct pblk_block *rblk;
	int lun_iter, blk_iter;

	for (lun_iter = 0; lun_iter < pblk->nr_luns; lun_iter++) {
		rlun = &pblk->luns[lun_iter];

		for (blk_iter = 0; blk_iter < pblk->dev->blks_per_lun;
								blk_iter++) {
			rblk = &rlun->blocks[blk_iter];
			pblk_block_map_update(pblk, rblk);
		}
	}

	return 0;
}

static int pblk_luns_configure(struct pblk *pblk)
{
	struct pblk_lun *rlun;
	struct pblk_block *rblk;
	int i;

	for (i = 0; i < pblk->nr_luns; i++) {
		rlun = &pblk->luns[i];

		rblk = pblk_get_blk(pblk, rlun, 0);
		if (!rblk)
			goto err;

		pblk_set_lun_cur(rlun, rblk);

		/* Emergency gc block */
		rblk = pblk_get_blk(pblk, rlun, 1);
		if (!rblk)
			goto err;
		rlun->gc_cur = rblk;
	}

	return 0;
err:
	pblk_put_blks(pblk);
	return -EINVAL;
}

static struct nvm_tgt_type tt_pblk;

static void *pblk_init(struct nvm_dev *dev, struct gendisk *tdisk,
						int lun_begin, int lun_end)
{
	struct request_queue *bqueue = dev->q;
	struct request_queue *tqueue = tdisk->queue;
	struct pblk *pblk;
	sector_t soffset;
	int ret;

	if (dev->identity.dom & NVM_RSP_L2P) {
		pr_err("nvm: pblk: device has device-side translation table. Target not supported. (%x)\n",
							dev->identity.dom);
		return ERR_PTR(-EINVAL);
	}

	pblk = kzalloc(sizeof(struct pblk), GFP_KERNEL);
	if (!pblk)
		return ERR_PTR(-ENOMEM);

	pblk->instance.tt = &tt_pblk;
	pblk->dev = dev;
	pblk->disk = tdisk;

	bio_list_init(&pblk->requeue_bios);
	spin_lock_init(&pblk->bio_lock);
	INIT_WORK(&pblk->ws_requeue, pblk_requeue);

	pblk->nr_luns = lun_end - lun_begin + 1;

	/* simple round-robin strategy */
	atomic_set(&pblk->next_lun, -1);

#ifdef CONFIG_NVM_DEBUG
	atomic_set(&pblk->inflight_writes, 0);
	atomic_set(&pblk->req_writes, 0);
	atomic_set(&pblk->sub_writes, 0);
	atomic_set(&pblk->sync_writes, 0);
	atomic_set(&pblk->inflight_reads, 0);
#endif

	ret = pblk_area_init(pblk, &soffset);
	if (ret < 0) {
		pr_err("nvm: pblk: could not initialize area\n");
		return ERR_PTR(ret);
	}
	pblk->soffset = soffset;

	ret = pblk_luns_init(pblk, lun_begin, lun_end);
	if (ret) {
		pr_err("nvm: pblk: could not initialize luns\n");
		goto err;
	}

	pblk->poffset = dev->sec_per_lun * lun_begin;
	pblk->lun_offset = lun_begin;

	ret = pblk_core_init(pblk);
	if (ret) {
		pr_err("nvm: pblk: could not initialize core\n");
		goto err;
	}

	ret = pblk_map_init(pblk);
	if (ret) {
		pr_err("nvm: pblk: could not initialize maps\n");
		goto err;
	}

	ret = pblk_blocks_init(pblk);
	if (ret) {
		pr_err("nvm: pblk: could not initialize state for blocks\n");
		goto err;
	}

	ret = pblk_luns_configure(pblk);
	if (ret) {
		pr_err("nvm: pblk: not enough blocks available in LUNs.\n");
		goto err;
	}

	ret = pblk_gc_init(pblk);
	if (ret) {
		pr_err("nvm: pblk: could not initialize gc\n");
		goto err;
	}

	/* inherit the size from the underlying device */
	blk_queue_logical_block_size(tqueue, queue_physical_block_size(bqueue));
	blk_queue_max_hw_sectors(tqueue, queue_max_hw_sectors(bqueue));

	pr_info("nvm: pblk initialized with %u luns and %llu pages.\n",
			pblk->nr_luns, (unsigned long long)pblk->nr_sects);

	mod_timer(&pblk->gc_timer, jiffies + msecs_to_jiffies(10));

	return pblk;
err:
	pblk_free(pblk);
	return ERR_PTR(ret);
}

/* physical block device target */
static struct nvm_tgt_type tt_pblk = {
	.name		= "pblk",
	.version	= {1, 0, 0},

	.make_rq	= pblk_make_rq,
	.capacity	= pblk_capacity,
	.end_io		= pblk_end_io,

	.init		= pblk_init,
	.exit		= pblk_exit,
};

static int __init pblk_module_init(void)
{
	return nvm_register_target(&tt_pblk);
}

static void pblk_module_exit(void)
{
	nvm_unregister_target(&tt_pblk);
}

module_init(pblk_module_init);
module_exit(pblk_module_exit);
MODULE_AUTHOR("Matias Bjorling <m@bjorling.me>");
MODULE_AUTHOR("Javier Gonzalez <jg@lightnvm.io>");
MODULE_LICENSE("GPL v2");
MODULE_DESCRIPTION("Physical Block-Device Target for Open-Channel SSDs");
