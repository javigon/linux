/*
 * Copyright (C) 2015 IT University of Copenhagen
 * Initial release: Matias Bjorling <m@bjorling.me>
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
 * Implementation of a Round-robin page-based Hybrid FTL for Open-channel SSDs.
 */

#include "rrpc.h"

static struct kmem_cache *rrpc_gcb_cache, *rrpc_rq_cache, *rrpc_rrq_cache,
							*rrpc_block_cache;
static DECLARE_RWSEM(rrpc_lock);

static int rrpc_submit_io(struct rrpc *rrpc, struct bio *bio,
				struct rrpc_rq *rrqd, unsigned long flags);

#define rrpc_for_each_lun(rrpc, rlun, i) \
		for ((i) = 0, rlun = &(rrpc)->luns[0]; \
			(i) < (rrpc)->nr_luns; (i)++, rlun = &(rrpc)->luns[(i)])

static void rrpc_page_invalidate(struct rrpc *rrpc, struct rrpc_addr *a)
{
	struct rrpc_block *rblk = a->rblk;
	unsigned int pg_offset;

	lockdep_assert_held(&rrpc->rev_lock);

	if (a->addr == ADDR_EMPTY || !rblk)
		return;

	spin_lock(&rblk->lock);

	div_u64_rem(a->addr, rrpc->dev->pgs_per_blk, &pg_offset);
	WARN_ON(test_and_set_bit(pg_offset, rblk->invalid_pages));
	rblk->nr_invalid_pages++;

	spin_unlock(&rblk->lock);

	rrpc->rev_trans_map[a->addr - rrpc->poffset].addr = ADDR_EMPTY;
}

static void rrpc_invalidate_range(struct rrpc *rrpc, sector_t slba,
								unsigned len)
{
	sector_t i;

	spin_lock(&rrpc->rev_lock);
	for (i = slba; i < slba + len; i++) {
		struct rrpc_addr *gp = &rrpc->trans_map[i];

		rrpc_page_invalidate(rrpc, gp);
		gp->rblk = NULL;
	}
	spin_unlock(&rrpc->rev_lock);
}

static struct nvm_rq *rrpc_inflight_laddr_acquire(struct rrpc *rrpc,
					sector_t laddr, unsigned int pages)
{
	struct nvm_rq *rqd;
	struct rrpc_inflight_rq *inf;

	rqd = mempool_alloc(rrpc->rq_pool, GFP_ATOMIC);
	if (!rqd)
		return ERR_PTR(-ENOMEM);

	inf = rrpc_get_inflight_rq((struct rrpc_rq*)rqd->priv);
	if (rrpc_lock_laddr(rrpc, laddr, pages, inf)) {
		mempool_free(rqd, rrpc->rq_pool);
		return NULL;
	}

	return rqd;
}

static void rrpc_inflight_laddr_release(struct rrpc *rrpc, struct nvm_rq *rqd)
{
	struct rrpc_inflight_rq *inf =
				rrpc_get_inflight_rq((struct rrpc_rq*)rqd->priv);

	rrpc_unlock_laddr(rrpc, inf);

	mempool_free(rqd, rrpc->rq_pool);
}

static void rrpc_discard(struct rrpc *rrpc, struct bio *bio)
{
	sector_t slba = bio->bi_iter.bi_sector / NR_PHY_IN_LOG;
	sector_t len = bio->bi_iter.bi_size / RRPC_EXPOSED_PAGE_SIZE;
	struct nvm_rq *rqd;

	do {
		rqd = rrpc_inflight_laddr_acquire(rrpc, slba, len);
		schedule();
	} while (!rqd);

	if (IS_ERR(rqd)) {
		pr_err("rrpc: unable to acquire inflight IO\n");
		bio_io_error(bio);
		return;
	}

	rrpc_invalidate_range(rrpc, slba, len);
	rrpc_inflight_laddr_release(rrpc, rqd);
}

static int block_is_full(struct rrpc *rrpc, struct rrpc_block *rblk)
{
	return (rblk->next_page == rrpc->dev->pgs_per_blk);
}

static u64 block_to_addr(struct rrpc *rrpc, struct rrpc_block *rblk)
{
	struct nvm_block *blk = rblk->parent;

	return blk->id * rrpc->dev->pgs_per_blk;
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

static struct ppa_addr rrpc_ppa_to_gaddr(struct nvm_dev *dev, u64 addr)
{
	struct ppa_addr paddr;

	paddr.ppa = addr;
	return linear_to_generic_addr(dev, paddr);
}

/* requires lun->lock taken */
static void rrpc_set_lun_cur(struct rrpc_lun *rlun, struct rrpc_block *rblk)
{
	struct rrpc *rrpc = rlun->rrpc;

	BUG_ON(!rblk);

	if (rlun->cur) {
		spin_lock(&rlun->cur->lock);
		WARN_ON(!block_is_full(rrpc, rlun->cur));
		spin_unlock(&rlun->cur->lock);
	}
	rlun->cur = rblk;
}

static void rrpc_free_w_buffer(struct rrpc *rrpc, struct rrpc_block *rblk)
{
	printk("Freeing buffer for block:%lu\n", rblk->parent->id);
	mempool_free(rblk->w_buffer.entries, rrpc->block_pool);
	rblk->w_buffer.entries = NULL;
	rblk->w_buffer.mem = NULL;
	rblk->w_buffer.sync = NULL;
	rblk->w_buffer.nentries = 0;
	rblk->w_buffer.cur_mem = 0;
	rblk->w_buffer.cur_sync = 0;
}

static void rrpc_put_blk(struct rrpc *rrpc, struct rrpc_block *rblk)
{
	if (rblk->w_buffer.entries)
		rrpc_free_w_buffer(rrpc, rblk);
	nvm_put_blk(rrpc->dev, rblk->parent);
}

static void rrpc_put_blks(struct rrpc *rrpc)
{
	struct rrpc_lun *rlun;
	int i;

	for (i = 0; i < rrpc->nr_luns; i++) {
		rlun = &rrpc->luns[i];
		if (rlun->cur)
			rrpc_put_blk(rrpc, rlun->cur);
		if (rlun->gc_cur)
			rrpc_put_blk(rrpc, rlun->gc_cur);
	}
}

static struct rrpc_block *rrpc_get_blk(struct rrpc *rrpc, struct rrpc_lun *rlun,
							unsigned long flags)
{
	struct nvm_dev *dev = rrpc->dev;
	struct nvm_block *blk;
	struct rrpc_block *rblk;

	blk = nvm_get_blk(dev, &rlun->open_list, rlun->parent, flags);
	if (!blk)
		return NULL;

	rblk = &rlun->blocks[blk->id];
	blk->priv = rblk;

	bitmap_zero(rblk->invalid_pages, dev->pgs_per_blk);
	rblk->next_page = 0;
	rblk->nr_invalid_pages = 0;
	atomic_set(&rblk->data_cmnt_size, 0);

	/* Set up block write buffer */
	printk("Setting up write buffer for blk:%lu, data_size:%d, sec_per_blk:%d\n",
			rblk->parent->id,
			dev->sec_size,
			dev->pgs_per_blk * dev->sec_per_pg);
	rblk->w_buffer.entries = mempool_alloc(rrpc->block_pool, GFP_ATOMIC);
	if (!rblk->w_buffer.entries) {
		pr_err("nvm: rrpc: cannot allocate write buffer for block\n");
		rrpc_put_blk(rrpc, rblk);
		return NULL;
	}

	rblk->w_buffer.mem = rblk->w_buffer.entries;
	rblk->w_buffer.sync = rblk->w_buffer.entries;
	rblk->w_buffer.nentries = dev->pgs_per_blk * dev->sec_per_pg;
	rblk->w_buffer.cur_mem = 0;
	rblk->w_buffer.cur_sync = 0;

	return rblk;
}

static struct rrpc_lun *get_next_lun(struct rrpc *rrpc)
{
	int next = atomic_inc_return(&rrpc->next_lun);

	return &rrpc->luns[next % rrpc->nr_luns];
}

static void rrpc_gc_kick(struct rrpc *rrpc)
{
	struct rrpc_lun *rlun;
	unsigned int i;

	for (i = 0; i < rrpc->nr_luns; i++) {
		rlun = &rrpc->luns[i];
		queue_work(rrpc->krqd_wq, &rlun->ws_gc);
	}
}

/*
 * timed GC every interval.
 */
static void rrpc_gc_timer(unsigned long data)
{
	struct rrpc *rrpc = (struct rrpc *)data;

	rrpc_gc_kick(rrpc);
	mod_timer(&rrpc->gc_timer, jiffies + msecs_to_jiffies(10));
}

static void rrpc_end_sync_bio(struct bio *bio)
{
	struct completion *waiting = bio->bi_private;

	if (bio->bi_error)
		pr_err("nvm: gc request failed (%u).\n", bio->bi_error);

	complete(waiting);
}

/*
 * rrpc_move_valid_pages -- migrate live data off the block
 * @rrpc: the 'rrpc' structure
 * @block: the block from which to migrate live pages
 *
 * Description:
 *   GC algorithms may call this function to migrate remaining live
 *   pages off the block prior to erasing it. This function blocks
 *   further execution until the operation is complete.
 */
static int rrpc_move_valid_pages(struct rrpc *rrpc, struct rrpc_block *rblk)
{
	struct request_queue *q = rrpc->dev->q;
	struct rrpc_rev_addr *rev;
	struct nvm_rq *rqd;
	struct rrpc_rq *rrqd;
	struct bio *bio;
	struct page *page;
	int slot;
	int nr_pgs_per_blk = rrpc->dev->pgs_per_blk;
	u64 phys_addr;
	DECLARE_COMPLETION_ONSTACK(wait);

	if (bitmap_full(rblk->invalid_pages, nr_pgs_per_blk))
		return 0;

	bio = bio_alloc(GFP_NOIO, 1);
	if (!bio) {
		pr_err("nvm: could not alloc bio to gc\n");
		return -ENOMEM;
	}

	page = mempool_alloc(rrpc->page_pool, GFP_NOIO);
	if (!page)
		return -ENOMEM;

	while ((slot = find_first_zero_bit(rblk->invalid_pages,
					    nr_pgs_per_blk)) < nr_pgs_per_blk) {

		/* Lock laddr */
		phys_addr = (rblk->parent->id * nr_pgs_per_blk) + slot;

try:
		spin_lock(&rrpc->rev_lock);
		/* Get logical address from physical to logical table */
		rev = &rrpc->rev_trans_map[phys_addr - rrpc->poffset];
		/* already updated by previous regular write */
		if (rev->addr == ADDR_EMPTY) {
			spin_unlock(&rrpc->rev_lock);
			continue;
		}

		rqd = rrpc_inflight_laddr_acquire(rrpc, rev->addr, 1);
		if (IS_ERR_OR_NULL(rqd)) {
			spin_unlock(&rrpc->rev_lock);
			schedule();
			goto try;
		}
		rrqd = (struct rrpc_rq*)rqd->priv;

		spin_unlock(&rrpc->rev_lock);

		/* Perform read to do GC */
		bio->bi_iter.bi_sector = rrpc_get_sector(rev->addr);
		bio->bi_rw = READ;
		bio->bi_private = &wait;
		bio->bi_end_io = rrpc_end_sync_bio;

		/* TODO: may fail when EXP_PG_SIZE > PAGE_SIZE */
		bio_add_pc_page(q, bio, page, RRPC_EXPOSED_PAGE_SIZE, 0);

		if (rrpc_submit_io(rrpc, bio, rrqd, NVM_IOTYPE_GC)) {
			pr_err("rrpc: gc read failed.\n");
			rrpc_inflight_laddr_release(rrpc, rqd);
			goto finished;
		}
		wait_for_completion_io(&wait);

		bio_reset(bio);
		reinit_completion(&wait);

		bio->bi_iter.bi_sector = rrpc_get_sector(rev->addr);
		bio->bi_rw = WRITE;
		bio->bi_private = &wait;
		bio->bi_end_io = rrpc_end_sync_bio;

		bio_add_pc_page(q, bio, page, RRPC_EXPOSED_PAGE_SIZE, 0);

		/* turn the command around and write the data back to a new
		 * address
		 */
		if (rrpc_submit_io(rrpc, bio, rrqd, NVM_IOTYPE_GC)) {
			pr_err("rrpc: gc write failed.\n");
			rrpc_inflight_laddr_release(rrpc, rqd);
			goto finished;
		}
		wait_for_completion_io(&wait);

		rrpc_inflight_laddr_release(rrpc, rqd);

		bio_reset(bio);
	}

finished:
	mempool_free(page, rrpc->page_pool);
	bio_put(bio);

	if (!bitmap_full(rblk->invalid_pages, nr_pgs_per_blk)) {
		pr_err("nvm: failed to garbage collect block\n");
		return -EIO;
	}

	return 0;
}

static void rrpc_block_gc(struct work_struct *work)
{
	struct rrpc_block_gc *gcb = container_of(work, struct rrpc_block_gc,
									ws_gc);
	struct rrpc *rrpc = gcb->rrpc;
	struct rrpc_block *rblk = gcb->rblk;
	struct nvm_dev *dev = rrpc->dev;

	pr_debug("nvm: block '%lu' being reclaimed\n", rblk->parent->id);

	if (rrpc_move_valid_pages(rrpc, rblk))
		goto done;

	nvm_erase_blk(dev, rblk->parent);
	rrpc_put_blk(rrpc, rblk);
done:
	mempool_free(gcb, rrpc->gcb_pool);
}

/* the block with highest number of invalid pages, will be in the beginning
 * of the list
 */
static struct rrpc_block *rblock_max_invalid(struct rrpc_block *ra,
							struct rrpc_block *rb)
{
	if (ra->nr_invalid_pages == rb->nr_invalid_pages)
		return ra;

	return (ra->nr_invalid_pages < rb->nr_invalid_pages) ? rb : ra;
}

/* linearly find the block with highest number of invalid pages
 * requires lun->lock
 */
static struct rrpc_block *block_prio_find_max(struct rrpc_lun *rlun)
{
	struct list_head *prio_list = &rlun->prio_list;
	struct rrpc_block *rblock, *max;

	BUG_ON(list_empty(prio_list));

	max = list_first_entry(prio_list, struct rrpc_block, prio);
	list_for_each_entry(rblock, prio_list, prio)
		max = rblock_max_invalid(max, rblock);

	return max;
}

static void rrpc_lun_gc(struct work_struct *work)
{
	struct rrpc_lun *rlun = container_of(work, struct rrpc_lun, ws_gc);
	struct rrpc *rrpc = rlun->rrpc;
	struct nvm_lun *lun = rlun->parent;
	struct rrpc_block_gc *gcb;
	unsigned int nr_blocks_need;

	nr_blocks_need = rrpc->dev->blks_per_lun / GC_LIMIT_INVERSE;

	if (nr_blocks_need < rrpc->nr_luns)
		nr_blocks_need = rrpc->nr_luns;

	spin_lock(&lun->lock);
	while (nr_blocks_need > lun->nr_free_blocks &&
					!list_empty(&rlun->prio_list)) {
		struct rrpc_block *rblock = block_prio_find_max(rlun);
		struct nvm_block *block = rblock->parent;

		if (!rblock->nr_invalid_pages)
			break;

		list_del_init(&rblock->prio);

		BUG_ON(!block_is_full(rrpc, rblock));

		pr_debug("rrpc: selected block '%lu' for GC\n", block->id);

		gcb = mempool_alloc(rrpc->gcb_pool, GFP_ATOMIC);
		if (!gcb)
			break;

		gcb->rrpc = rrpc;
		gcb->rblk = rblock;
		INIT_WORK(&gcb->ws_gc, rrpc_block_gc);

		queue_work(rrpc->kgc_wq, &gcb->ws_gc);

		nr_blocks_need--;
	}
	spin_unlock(&lun->lock);

	/* TODO: Hint that request queue can be started again */
}

static void rrpc_gc_queue(struct work_struct *work)
{
	struct rrpc_block_gc *gcb = container_of(work, struct rrpc_block_gc,
									ws_gc);
	struct rrpc *rrpc = gcb->rrpc;
	struct rrpc_block *rblk = gcb->rblk;
	struct nvm_lun *lun = rblk->parent->lun;
	struct rrpc_lun *rlun = &rrpc->luns[lun->id - rrpc->lun_offset];

	spin_lock(&rlun->lock);
	list_add_tail(&rblk->prio, &rlun->prio_list);
	spin_unlock(&rlun->lock);

	mempool_free(gcb, rrpc->gcb_pool);
	pr_debug("nvm: block '%lu' is full, allow GC (sched)\n",
							rblk->parent->id);
}

static const struct block_device_operations rrpc_fops = {
	.owner		= THIS_MODULE,
};

static struct rrpc_lun *rrpc_get_lun_rr(struct rrpc *rrpc, int is_gc)
{
	unsigned int i;
	struct rrpc_lun *rlun, *max_free;

	if (!is_gc)
		return get_next_lun(rrpc);

	/* during GC, we don't care about RR, instead we want to make
	 * sure that we maintain evenness between the block luns.
	 */
	max_free = &rrpc->luns[0];
	/* prevent GC-ing lun from devouring pages of a lun with
	 * little free blocks. We don't take the lock as we only need an
	 * estimate.
	 */
	rrpc_for_each_lun(rrpc, rlun, i) {
		if (rlun->parent->nr_free_blocks >
					max_free->parent->nr_free_blocks)
			max_free = rlun;
	}

	return max_free;
}

static struct rrpc_addr *rrpc_update_map(struct rrpc *rrpc, sector_t laddr,
					struct rrpc_block *rblk, u64 paddr)
{
	struct rrpc_addr *gp;
	struct rrpc_rev_addr *rev;

	BUG_ON(laddr >= rrpc->nr_pages);

	gp = &rrpc->trans_map[laddr];
	spin_lock(&rrpc->rev_lock);
	if (gp->rblk)
		rrpc_page_invalidate(rrpc, gp);

	gp->addr = paddr;
	gp->rblk = rblk;

	rev = &rrpc->rev_trans_map[gp->addr - rrpc->poffset];
	rev->addr = laddr;
	spin_unlock(&rrpc->rev_lock);

	return gp;
}

static u64 rrpc_alloc_addr(struct rrpc *rrpc, struct rrpc_block *rblk)
{
	u64 addr = ADDR_EMPTY;

	spin_lock(&rblk->lock);
	if (block_is_full(rrpc, rblk))
		goto out;

	addr = block_to_addr(rrpc, rblk) + rblk->next_page;

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
 * Returns rrpc_addr with the physical address and block. Remember to return to
 * rrpc->addr_cache when request is finished.
 */
static struct rrpc_addr *rrpc_map_page(struct rrpc *rrpc, sector_t laddr,
								int is_gc)
{
	struct rrpc_lun *rlun;
	struct rrpc_block *rblk;
	struct nvm_lun *lun;
	u64 paddr;

	rlun = rrpc_get_lun_rr(rrpc, is_gc);
	lun = rlun->parent;

	if (!is_gc && lun->nr_free_blocks < rrpc->nr_luns * 4)
		return NULL;

	spin_lock(&rlun->lock);

	rblk = rlun->cur;
retry:
	paddr = rrpc_alloc_addr(rrpc, rblk);

	if (paddr == ADDR_EMPTY) {
		rblk = rrpc_get_blk(rrpc, rlun, 0);
		if (rblk) {
			rrpc_set_lun_cur(rlun, rblk);
			goto retry;
		}

		if (is_gc) {
			/* retry from emergency gc block */
			paddr = rrpc_alloc_addr(rrpc, rlun->gc_cur);
			if (paddr == ADDR_EMPTY) {
				rblk = rrpc_get_blk(rrpc, rlun, 1);
				if (!rblk) {
					pr_err("rrpc: no more blocks");
					goto err;
				}

				rlun->gc_cur = rblk;
				paddr = rrpc_alloc_addr(rrpc, rlun->gc_cur);
			}
			rblk = rlun->gc_cur;
		}
	}

	spin_unlock(&rlun->lock);
	return rrpc_update_map(rrpc, laddr, rblk, paddr);
err:
	spin_unlock(&rlun->lock);
	return NULL;
}

static void rrpc_run_gc(struct rrpc *rrpc, struct rrpc_block *rblk)
{
	struct rrpc_block_gc *gcb;

	gcb = mempool_alloc(rrpc->gcb_pool, GFP_ATOMIC);
	if (!gcb) {
		pr_err("rrpc: unable to queue block for gc.");
		return;
	}

	gcb->rrpc = rrpc;
	gcb->rblk = rblk;

	INIT_WORK(&gcb->ws_gc, rrpc_gc_queue);
	queue_work(rrpc->kgc_wq, &gcb->ws_gc);
}

static void rrpc_end_io_write(struct rrpc *rrpc, struct rrpc_rq *rrqd,
						sector_t laddr, uint8_t npages)
{
	struct rrpc_addr *p;
	struct rrpc_block *rblk;
	struct rrpc_w_buffer *buf;
	struct nvm_lun *lun;
	int cmnt_size, i;

	printk("Endio: npages:%d\n", npages);
	for (i = 0; i < npages; i++) {
		p = &rrpc->trans_map[laddr + i];
		rblk = p->rblk;
		buf = &rblk->w_buffer;
		lun = rblk->parent->lun;

		cmnt_size = atomic_inc_return(&rblk->data_cmnt_size);
		printk("end_io_write (laddr:%lu, addr:%llu)- cmnt: %d\n",
				laddr, p->addr,
				atomic_read(&rblk->data_cmnt_size));
		if (unlikely(cmnt_size == rrpc->dev->pgs_per_blk)) {
			struct nvm_block *blk = rblk->parent;
			struct rrpc_lun *rlun = rblk->rlun;
			BUG_ON((buf->cur_mem != buf->cur_sync) &&
					(buf->cur_mem != buf->nentries));

			spin_lock(&lun->lock);
			/* clear_bit(NVM_BLOCK_STATE_OPEN, blk->type); //JAVIER: CHECK! */
			lun->nr_open_blocks--;
			lun->nr_closed_blocks++;
			blk->type |= NVM_BLOCK_STATE_CLOSED;
			list_move_tail(&blk->list, &rlun->closed_list);
			spin_unlock(&lun->lock);

			rrpc_free_w_buffer(rrpc, rblk);
			rrpc_run_gc(rrpc, rblk);
		}
	}
}

static int rrpc_end_io(struct nvm_rq *rqd, int error)
{
	struct rrpc *rrpc = container_of(rqd->ins, struct rrpc, instance);
	struct rrpc_rq *rrqd = nvm_rq_to_pdu(rqd);
	uint8_t npages = rqd->nr_pages;
	sector_t laddr = rrpc_get_laddr(rqd->bio) - npages;

	printk("end io - laddr:%lu, npages:%d\n", laddr, npages);

	if (bio_data_dir(rqd->bio) == WRITE)
		rrpc_end_io_write(rrpc, rrqd, laddr, npages);

	if (rrqd->flags & NVM_IOTYPE_GC)
		return 0;

	rrpc_unlock_rq(rrpc, rrqd, npages);
	bio_put(rqd->bio);

	if ((npages > 1) && (rqd->ppa_list))
		nvm_dev_dma_free(rrpc->dev, rqd->ppa_list, rqd->dma_ppa_list);
	/* if (rqd->metadata) */
		/* nvm_dev_dma_free(rrpc->dev, rqd->metadata, rqd->dma_metadata); */

	mempool_free(rrqd, rrpc->rrq_pool);
	mempool_free(rqd, rrpc->rq_pool);

	return 0;
}

static int rrpc_read_ppalist_rq(struct rrpc *rrpc, struct bio *bio,
			struct nvm_rq *rqd, unsigned long flags, int npages)
{
	struct rrpc_rq *rrqd = nvm_rq_to_pdu(rqd);
	struct rrpc_inflight_rq *r = rrpc_get_inflight_rq(rrqd);
	struct rrpc_addr *gp;
	sector_t laddr = rrpc_get_laddr(bio);
	int is_gc = flags & NVM_IOTYPE_GC;
	int i;

	if (!is_gc && rrpc_lock_rq(rrpc, bio, rrqd)) {
		nvm_dev_dma_free(rrpc->dev, rqd->ppa_list, rqd->dma_ppa_list);
		return NVM_IO_REQUEUE;
	}

	for (i = 0; i < npages; i++) {
		/* We assume that mapping occurs at 4KB granularity */
		BUG_ON(!(laddr + i >= 0 && laddr + i < rrpc->nr_pages));
		gp = &rrpc->trans_map[laddr + i];

		if (gp->rblk) {
			rqd->ppa_list[i] = rrpc_ppa_to_gaddr(rrpc->dev,
								gp->addr);
		} else {
			printk("FALSE READ(m): laddr:%lu\n", laddr);
			BUG_ON(is_gc);
			rrpc_unlock_laddr(rrpc, r);
			nvm_dev_dma_free(rrpc->dev, rqd->ppa_list,
							rqd->dma_ppa_list);
			return NVM_IO_DONE;
		}

		printk("READ(m):laddr:%lu,addr:%llu\n", laddr + i, gp->addr);
	}

	rqd->opcode = NVM_OP_HBREAD;

	return NVM_IO_OK;
}

static int rrpc_read_rq(struct rrpc *rrpc, struct bio *bio, struct nvm_rq *rqd,
							unsigned long flags)
{
	struct rrpc_rq *rrqd = nvm_rq_to_pdu(rqd);
	int is_gc = flags & NVM_IOTYPE_GC;
	sector_t laddr = rrpc_get_laddr(bio);
	struct rrpc_addr *gp;

	if (!is_gc && rrpc_lock_rq(rrpc, bio, rrqd))
		return NVM_IO_REQUEUE;

	BUG_ON(!(laddr >= 0 && laddr < rrpc->nr_pages));
	gp = &rrpc->trans_map[laddr];

	if (gp->rblk) {
		rqd->ppa_addr = rrpc_ppa_to_gaddr(rrpc->dev, gp->addr);
	} else {
		printk("FALSE READ: laddr:%lu\n", laddr);
		BUG_ON(is_gc);
		rrpc_unlock_rq(rrpc, rrqd, 1);
		return NVM_IO_DONE;
	}

	rqd->opcode = NVM_OP_HBREAD;
	rrqd->addr = gp;

	printk("READ(1):laddr:%lu,addr:%llu\n", laddr, gp->addr);

	return NVM_IO_OK;
}

static int rrpc_write_ppalist_rq(struct rrpc *rrpc, struct bio *bio,
			struct rrpc_rq *rrqd, unsigned long flags, int npages)
{
	struct rrpc_inflight_rq *r = rrpc_get_inflight_rq(rrqd);
	struct rrpc_addr *p;
	struct rrpc_w_buffer *w_buffer;
	sector_t laddr = rrpc_get_laddr(bio);
	void *ppa_data;
	int is_gc = flags & NVM_IOTYPE_GC;
	int i;

	if (!is_gc && rrpc_lock_rq(rrpc, bio, rrqd)) {
		//JAVIER: THIS WILL GO
		/* nvm_dev_dma_free(rrpc->dev, rqd->ppa_list, rqd->dma_ppa_list); */
		return NVM_IO_REQUEUE;
	}

	for (i = 0; i < npages; i++) {
		unsigned int bio_len;
		/* We assume that mapping occurs at 4KB granularity */
		p = rrpc_map_page(rrpc, laddr + i, is_gc);
		if (!p) {
			BUG_ON(is_gc);
			rrpc_unlock_laddr(rrpc, r);
			//JAVIER: THIS WILL GO
			/* nvm_dev_dma_free(rrpc->dev, rqd->ppa_list, */
							/* rqd->dma_ppa_list); */
			rrpc_gc_kick(rrpc);
			return NVM_IO_REQUEUE;
		}

		bio_len = bio_cur_bytes(bio);
		w_buffer = &p->rblk->w_buffer;

		BUG_ON(w_buffer->cur_mem + 1 > w_buffer->nentries);
		BUG_ON(bio_len != RRPC_EXPOSED_PAGE_SIZE);

		rrqd->flags = flags;
		rrqd->addr = p;
		w_buffer->mem->rrqd = rrqd;

		ppa_data = w_buffer->mem->rrqd + 1;
		memcpy(ppa_data, bio_data(bio), bio_len);
		w_buffer->mem++;
		w_buffer->cur_mem++;

		//JAVIER: THIS WILL GO
		/* rqd->ppa_list[i] = rrpc_ppa_to_gaddr(rrpc->dev, p->addr); */

		printk("multipage. blk:%lu, cur_mem:%d, bio_size:%d\n",
				p->rblk->parent->id, w_buffer->cur_mem,
				bio_len);

		// JAVIER: Check that this acks bio as it advances
		bio_advance(bio, 4096);
	}

	return NVM_IO_OK;
}

static int rrpc_write_rq(struct rrpc *rrpc, struct bio *bio,
				struct rrpc_rq *rrqd, unsigned long flags)
{
	struct rrpc_addr *p;
	struct rrpc_w_buffer *w_buffer;
	void *ppa_data;
	unsigned int bio_len = bio_cur_bytes(bio);
	int is_gc = flags & NVM_IOTYPE_GC;
	sector_t laddr = rrpc_get_laddr(bio);

	if (!is_gc && rrpc_lock_rq(rrpc, bio, rrqd))
		return NVM_IO_REQUEUE;

	p = rrpc_map_page(rrpc, laddr, is_gc);
	if (!p) {
		BUG_ON(is_gc);
		rrpc_unlock_rq(rrpc, rrqd, 1);
		rrpc_gc_kick(rrpc);
		return NVM_IO_REQUEUE;
	}

	/*
	 * Copy data from current bio to block write buffer. This if necessary
	 * to guarantee durability if a flash block becomes bad before all pages
	 * are written. This buffer is also used to write at the right page
	 * granurality*/
	w_buffer = &p->rblk->w_buffer;

	BUG_ON(w_buffer->cur_mem + 1 > w_buffer->nentries);
	BUG_ON(bio_len != RRPC_EXPOSED_PAGE_SIZE);

	rrqd->flags = flags;
	rrqd->addr = p;
	rrqd->laddr = laddr;
	w_buffer->mem->rrqd = rrqd;

	//JAVIER: THIS IS THE MEMORY ERROR YOU ARE HUNTING!
	/* ppa_data = w_buffer->mem->rrqd + 1; */
	/* memcpy(ppa_data, bio_data(bio), bio_len); */
	w_buffer->mem++;
	w_buffer->cur_mem++;

	printk("WRITE_RQ(1):laddr:%lu,addr:%llu, bio_sec:%lu\n", laddr, p->addr, bio->bi_iter.bi_sector);
	// JAVIER: This will go
	/* rqd->ppa_addr = rrpc_ppa_to_gaddr(rrpc->dev, p->addr); */
	/* rqd->opcode = NVM_OP_HBWRITE; */

	return NVM_IO_OK;
}

static int rrpc_submit_io(struct rrpc *rrpc, struct bio *bio,
				struct rrpc_rq *rrqd, unsigned long flags)
{
	int err;
	uint8_t npages = rrpc_get_pages(bio);
	int bio_size = bio_sectors(bio) << 9;

	if (bio_size < rrpc->dev->sec_size)
		return NVM_IO_ERR;
	else if (bio_size > rrpc->dev->max_rq_size)
		return NVM_IO_ERR;

	if (bio_rw(bio) == READ) {
		struct nvm_rq *rqd;

		rqd = mempool_alloc(rrpc->rq_pool, GFP_ATOMIC);
		if (!rqd) {
			pr_err_ratelimited("rrpc: not able to queue bio.");
			bio_io_error(bio);
			return BLK_QC_T_NONE;
		}
		rqd->priv = rrqd;

		if (npages > 1) {
			rqd->ppa_list = nvm_dev_dma_alloc(rrpc->dev, GFP_ATOMIC,
							&rqd->dma_ppa_list);
			if (!rqd->ppa_list) {
				pr_err("rrpc: not able to allocate ppa list\n");
				return NVM_IO_ERR;
			}

			err = rrpc_read_ppalist_rq(rrpc, bio, rqd, flags, npages);
			if (err)
				return err;
		} else {
			err = rrpc_read_rq(rrpc, bio, rqd, flags);
			if (err)
				return err;
		}

		printk("READ\n");
		bio_get(bio);
		rqd->bio = bio;
		rqd->ins = &rrpc->instance;
		rqd->nr_pages = npages;
		rrqd->flags = flags;

		err = nvm_submit_io(rrpc->dev, rqd);
		if (err) {
			pr_err("rrpc: I/O submission failed: %d\n", err);
			bio_put(bio);
			return NVM_IO_ERR;
		}

		return NVM_IO_OK;
	}

	printk("WRITE\n");
	/* WRITE path */
	if (npages > 1) {
		err = rrpc_write_ppalist_rq(rrpc, bio, rrqd, flags, npages);
		if (err)
			return err;
	} else {
		err = rrpc_write_rq(rrpc, bio, rrqd, flags);
		if (err)
			return err;
	}

	queue_work(rrpc->kw_wq, &rrpc->ws_writer);
	return NVM_IO_DONE;
}

static blk_qc_t rrpc_make_rq(struct request_queue *q, struct bio *bio)
{
	struct rrpc *rrpc = q->queuedata;
	struct rrpc_rq *rrqd;
	int err;

	if (bio->bi_rw & REQ_DISCARD) {
		rrpc_discard(rrpc, bio);
		return BLK_QC_T_NONE;
	}

	rrqd = mempool_alloc(rrpc->rrq_pool, GFP_ATOMIC);
	if (!rrqd) {
		pr_err_ratelimited("rrpc: not able to queue bio.");
		bio_io_error(bio);
		return BLK_QC_T_NONE;
	}
	memset(rrqd, 0, sizeof(struct rrpc_rq));

	err = rrpc_submit_io(rrpc, bio, rrqd, NVM_IOTYPE_NONE);
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
		spin_lock(&rrpc->bio_lock);
		bio_list_add(&rrpc->requeue_bios, bio);
		spin_unlock(&rrpc->bio_lock);
		queue_work(rrpc->kgc_wq, &rrpc->ws_requeue);
		break;
	}

	return BLK_QC_T_NONE;
}

/*
 * TODO:: JAVIER:: Create a job per lun */
static void rrpc_submit_write(struct work_struct *work)
{
	struct rrpc *rrpc = container_of(work, struct rrpc, ws_writer);
	struct request_queue *q = rrpc->dev->q;
	struct rrpc_lun *rlun;
	struct rrpc_rq *rrqd;
	void *data;
	struct nvm_rq *rqd;
	struct nvm_block *blk;
	struct rrpc_block *rblk;
	struct bio *bio;
	struct page *page;
	struct bio_list bios;
	unsigned page_offset;
	/* int full_mem_pgs; */
	int pgs_to_sync;
	int err;
	int i, j;

	bio_list_init(&bios);

	for (i = 0; i < rrpc->nr_luns; i++) {
		rlun = &rrpc->luns[i];

		list_for_each_entry(blk, &rlun->open_list, list) {
			/* full_mem_pgs =  */
				/* (blk->cur_mem - blk->cur_sync) / dev->sec_size; */
			/* pgs_to_sync = (full_mem_pgs > dev->max_rq_size) ? */
						/* dev->max_rq_size : full_mem_pgs; */
			rblk = (struct rrpc_block*)blk->priv;

			pgs_to_sync =
				rblk->w_buffer.cur_mem - rblk->w_buffer.cur_sync;

			printk("Write IO: blk:%lu, pgs_to_sync:%d, s:%d,m:%d\n",
					blk->id, pgs_to_sync,
					rblk->w_buffer.cur_sync,
					rblk->w_buffer.cur_mem);

			for (j = 0; j < pgs_to_sync; j++) {
				rrqd = rblk->w_buffer.sync->rrqd;
				data = rrqd + 1;

				rqd = mempool_alloc(rrpc->rq_pool, GFP_NOIO);
				if (!rqd) {
					pr_err_ratelimited("rrpc: not able to queue bio.");
					return;
				}

				bio = bio_alloc(GFP_NOIO, 1);
				if (!bio) {
					pr_err("nvm: rrpc: could not alloc write bio\n");
					return;
				}

				/* page = mempool_alloc(rrpc->page_pool, GFP_NOIO); */
				/* if (!page) { */
					/* pr_err("nvm: rrpc: could not alloc page\n"); */
					/* return; */
				/* } */

				//JAVIER: This page is bad formed
				page = virt_to_page(data);
				page_offset = offset_in_page(data);

				bio->bi_iter.bi_sector = rrpc_get_sector(rrqd->laddr);
				bio->bi_rw = WRITE;
				bio_add_pc_page(q, bio, page, RRPC_EXPOSED_PAGE_SIZE, 0);

				bio_get(bio);

				// JAVIER: For now we only send 4KB at a time
				rqd->ppa_addr = rrpc_ppa_to_gaddr(rrpc->dev, rrqd->addr->addr);
				rqd->opcode = NVM_OP_HBWRITE;
				rqd->bio = bio;
				rqd->ins = &rrpc->instance;
				rqd->nr_pages = 1;
				rqd->flags = rrqd->flags;
				rqd->priv = rrqd;

				printk("rqd addr:%llu(%llu), sec:%lu\n",
						rrqd->addr->addr,
						rqd->ppa_addr.ppa,
						rqd->bio->bi_iter.bi_sector);
				printk("cmnt:%d\n", atomic_read(&rblk->data_cmnt_size));

				err = nvm_submit_io(rrpc->dev, rqd);
				if (err) {
					pr_err("rrpc: I/O submission failed: %d\n", err);
					bio_put(bio);
					return;
				}

				rblk->w_buffer.cur_sync++;
				rblk->w_buffer.sync++;
			}

			/* YOU ARE HERE!! BE SURE THAT YOU WORK WITH 4KB SECTORS! */
			/* if (pgs_to_sync == dev->max_rq_size) { */
				/* for (j = 0; j < pgs_to_sync) */
			/* } */
		}
	}
}

static void rrpc_requeue(struct work_struct *work)
{
	struct rrpc *rrpc = container_of(work, struct rrpc, ws_requeue);
	struct bio_list bios;
	struct bio *bio;

	bio_list_init(&bios);

	spin_lock(&rrpc->bio_lock);
	bio_list_merge(&bios, &rrpc->requeue_bios);
	bio_list_init(&rrpc->requeue_bios);
	spin_unlock(&rrpc->bio_lock);

	while ((bio = bio_list_pop(&bios)))
		rrpc_make_rq(rrpc->disk->queue, bio);
}

static void rrpc_gc_free(struct rrpc *rrpc)
{
	struct rrpc_lun *rlun;
	int i;

	if (rrpc->krqd_wq)
		destroy_workqueue(rrpc->krqd_wq);

	if (rrpc->kgc_wq)
		destroy_workqueue(rrpc->kgc_wq);

	if (!rrpc->luns)
		return;

	for (i = 0; i < rrpc->nr_luns; i++) {
		rlun = &rrpc->luns[i];

		if (!rlun->blocks)
			break;
		vfree(rlun->blocks);
	}
}

static int rrpc_gc_init(struct rrpc *rrpc)
{
	rrpc->krqd_wq = alloc_workqueue("rrpc-lun", WQ_MEM_RECLAIM | WQ_UNBOUND,
								rrpc->nr_luns);
	if (!rrpc->krqd_wq)
		return -ENOMEM;

	rrpc->kgc_wq = alloc_workqueue("rrpc-bg", WQ_MEM_RECLAIM, 1);
	if (!rrpc->kgc_wq)
		return -ENOMEM;

	setup_timer(&rrpc->gc_timer, rrpc_gc_timer, (unsigned long)rrpc);

	return 0;
}

static void rrpc_map_free(struct rrpc *rrpc)
{
	vfree(rrpc->rev_trans_map);
	vfree(rrpc->trans_map);
}

static int rrpc_l2p_update(u64 slba, u32 nlb, __le64 *entries, void *private)
{
	struct rrpc *rrpc = (struct rrpc *)private;
	struct nvm_dev *dev = rrpc->dev;
	struct rrpc_addr *addr = rrpc->trans_map + slba;
	struct rrpc_rev_addr *raddr = rrpc->rev_trans_map;
	sector_t max_pages = dev->total_pages * (dev->sec_size >> 9);
	u64 elba = slba + nlb;
	u64 i;

	if (unlikely(elba > dev->total_pages)) {
		pr_err("nvm: L2P data from device is out of bounds!\n");
		return -EINVAL;
	}

	for (i = 0; i < nlb; i++) {
		u64 pba = le64_to_cpu(entries[i]);
		/* LNVM treats address-spaces as silos, LBA and PBA are
		 * equally large and zero-indexed.
		 */
		if (unlikely(pba >= max_pages && pba != U64_MAX)) {
			pr_err("nvm: L2P data entry is out of bounds!\n");
			return -EINVAL;
		}

		/* Address zero is a special one. The first page on a disk is
		 * protected. As it often holds internal device boot
		 * information.
		 */
		if (!pba)
			continue;

		addr[i].addr = pba;
		raddr[pba].addr = slba + i;
	}

	return 0;
}

static int rrpc_map_init(struct rrpc *rrpc)
{
	struct nvm_dev *dev = rrpc->dev;
	sector_t i;
	int ret;

	rrpc->trans_map = vzalloc(sizeof(struct rrpc_addr) * rrpc->nr_pages);
	if (!rrpc->trans_map)
		return -ENOMEM;

	rrpc->rev_trans_map = vmalloc(sizeof(struct rrpc_rev_addr)
							* rrpc->nr_pages);
	if (!rrpc->rev_trans_map)
		return -ENOMEM;

	for (i = 0; i < rrpc->nr_pages; i++) {
		struct rrpc_addr *p = &rrpc->trans_map[i];
		struct rrpc_rev_addr *r = &rrpc->rev_trans_map[i];

		p->addr = ADDR_EMPTY;
		r->addr = ADDR_EMPTY;
	}

	if (!dev->ops->get_l2p_tbl)
		return 0;

	/* Bring up the mapping table from device */
	ret = dev->ops->get_l2p_tbl(dev, 0, dev->total_pages,
							rrpc_l2p_update, rrpc);
	if (ret) {
		pr_err("nvm: rrpc: could not read L2P table.\n");
		return -EINVAL;
	}

	return 0;
}


/* Minimum pages needed within a lun */
#define PAGE_POOL_SIZE 16
#define ADDR_POOL_SIZE 64

static int rrpc_core_init(struct rrpc *rrpc)
{
	struct nvm_dev *dev = rrpc->dev;

	down_write(&rrpc_lock);
	if (!rrpc_gcb_cache) {
		rrpc_gcb_cache = kmem_cache_create("rrpc_gcb",
				sizeof(struct rrpc_block_gc), 0, 0, NULL);
		if (!rrpc_gcb_cache) {
			up_write(&rrpc_lock);
			return -ENOMEM;
		}
	}

	rrpc_rq_cache = kmem_cache_create("nvm_rq",
					sizeof(struct nvm_rq), 0, 0, NULL);
	if (!rrpc_rq_cache) {
		kmem_cache_destroy(rrpc_gcb_cache);
		up_write(&rrpc_lock);
		return -ENOMEM;
	}

	rrpc_rrq_cache = kmem_cache_create("rrpc_rrq",
					sizeof(struct rrpc_rq), 0, 0, NULL);
	if (!rrpc_rrq_cache) {
		kmem_cache_destroy(rrpc_gcb_cache);
		kmem_cache_destroy(rrpc_rq_cache);
		up_write(&rrpc_lock);
		return -ENOMEM;
	}

	/*
	 * we assume that sec->sec_size is the same as the page size exposed by
	 * rrpc (4KB). We need extra logic otherwise
	 */
	BUG_ON(dev->sec_size != RRPC_EXPOSED_PAGE_SIZE);
	if (!rrpc_block_cache) {
		rrpc_block_cache = kmem_cache_create("nvm_block",
			dev->pgs_per_blk * dev->sec_per_pg *
			(sizeof(struct rrpc_rq) + dev->sec_size),
			0, 0, NULL);
		if (!rrpc_block_cache) {
			kmem_cache_destroy(rrpc_gcb_cache);
			kmem_cache_destroy(rrpc_rq_cache);
			kmem_cache_destroy(rrpc_rrq_cache);
			up_write(&rrpc_lock);
			return -ENOMEM;
		}
	}
	up_write(&rrpc_lock);

	rrpc->page_pool = mempool_create_page_pool(PAGE_POOL_SIZE, 0);
	if (!rrpc->page_pool)
		return -ENOMEM;

	rrpc->gcb_pool = mempool_create_slab_pool(rrpc->dev->nr_luns,
								rrpc_gcb_cache);
	if (!rrpc->gcb_pool)
		return -ENOMEM;

	rrpc->rq_pool = mempool_create_slab_pool(64, rrpc_rq_cache);
	if (!rrpc->rq_pool)
		return -ENOMEM;

	rrpc->rrq_pool = mempool_create_slab_pool(64, rrpc_rrq_cache);
	if (!rrpc->rrq_pool)
		return -ENOMEM;

	rrpc->block_pool = mempool_create_slab_pool(64, rrpc_block_cache);
	if (!rrpc->block_pool)
		return -ENOMEM;

	spin_lock_init(&rrpc->inflights.lock);
	INIT_LIST_HEAD(&rrpc->inflights.reqs);

	return 0;
}

static void rrpc_core_free(struct rrpc *rrpc)
{
	mempool_destroy(rrpc->page_pool);
	mempool_destroy(rrpc->gcb_pool);
	mempool_destroy(rrpc->rrq_pool);
	mempool_destroy(rrpc->rq_pool);
	mempool_destroy(rrpc->block_pool);

	if (rrpc->kw_wq)
		destroy_workqueue(rrpc->kw_wq);
}

static void rrpc_luns_free(struct rrpc *rrpc)
{
	kfree(rrpc->luns);
}

static int rrpc_luns_init(struct rrpc *rrpc, int lun_begin, int lun_end)
{
	struct nvm_dev *dev = rrpc->dev;
	struct rrpc_lun *rlun;
	struct rrpc_flash_pg *flash_pg;
	int i, j;

	spin_lock_init(&rrpc->rev_lock);

	rrpc->luns = kcalloc(rrpc->nr_luns, sizeof(struct rrpc_lun),
								GFP_KERNEL);
	if (!rrpc->luns)
		return -ENOMEM;

	/* 1:1 mapping */
	for (i = 0; i < rrpc->nr_luns; i++) {
		struct nvm_lun *lun = dev->mt->get_lun(dev, lun_begin + i);

		if (dev->pgs_per_blk >
				MAX_INVALID_PAGES_STORAGE * BITS_PER_LONG) {
			pr_err("rrpc: number of pages per block too high.");
			goto err;
		}

		rlun = &rrpc->luns[i];
		rlun->rrpc = rrpc;
		rlun->parent = lun;
		INIT_LIST_HEAD(&rlun->prio_list);
		INIT_LIST_HEAD(&rlun->open_list);
		INIT_LIST_HEAD(&rlun->closed_list);

		INIT_WORK(&rlun->ws_gc, rrpc_lun_gc);
		spin_lock_init(&rlun->lock);

		flash_pg = &rlun->flash_pg;
		flash_pg->sec_size = dev->sec_size;
		flash_pg->page_size = flash_pg->sec_size * dev->sec_per_pg;
		flash_pg->pln_pg_size = flash_pg->page_size * dev->nr_planes;

		rrpc->total_blocks += dev->blks_per_lun;
		rrpc->nr_pages += dev->sec_per_lun;

		rlun->blocks = vzalloc(sizeof(struct rrpc_block) *
						rrpc->dev->blks_per_lun);
		if (!rlun->blocks)
			goto err;

		for (j = 0; j < rrpc->dev->blks_per_lun; j++) {
			struct rrpc_block *rblk = &rlun->blocks[j];
			struct nvm_block *blk = &lun->blocks[j];

			rblk->parent = blk;
			rblk->rlun = rlun;
			INIT_LIST_HEAD(&rblk->prio);
			spin_lock_init(&rblk->lock);
		}
	}

	return 0;
err:
	return -ENOMEM;
}

static void rrpc_free(struct rrpc *rrpc)
{
	rrpc_gc_free(rrpc);
	rrpc_map_free(rrpc);
	rrpc_core_free(rrpc);
	rrpc_luns_free(rrpc);

	kfree(rrpc);
}

static void rrpc_exit(void *private)
{
	struct rrpc *rrpc = private;

	del_timer(&rrpc->gc_timer);

	flush_workqueue(rrpc->kw_wq);
	flush_workqueue(rrpc->krqd_wq);
	flush_workqueue(rrpc->kgc_wq);

	rrpc_free(rrpc);
}

static sector_t rrpc_capacity(void *private)
{
	struct rrpc *rrpc = private;
	struct nvm_dev *dev = rrpc->dev;
	sector_t reserved, provisioned;

	/* cur, gc, and two emergency blocks for each lun */
	reserved = rrpc->nr_luns * dev->max_pages_per_blk * 4;
	provisioned = rrpc->nr_pages - reserved;

	if (reserved > rrpc->nr_pages) {
		pr_err("rrpc: not enough space available to expose storage.\n");
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
static void rrpc_block_map_update(struct rrpc *rrpc, struct rrpc_block *rblk)
{
	struct nvm_dev *dev = rrpc->dev;
	int offset;
	struct rrpc_addr *laddr;
	u64 paddr, pladdr;

	for (offset = 0; offset < dev->pgs_per_blk; offset++) {
		paddr = block_to_addr(rrpc, rblk) + offset;

		pladdr = rrpc->rev_trans_map[paddr].addr;
		if (pladdr == ADDR_EMPTY)
			continue;

		laddr = &rrpc->trans_map[pladdr];

		if (paddr == laddr->addr) {
			laddr->rblk = rblk;
		} else {
			set_bit(offset, rblk->invalid_pages);
			rblk->nr_invalid_pages++;
		}
	}
}

static int rrpc_blocks_init(struct rrpc *rrpc)
{
	struct rrpc_lun *rlun;
	struct rrpc_block *rblk;
	int lun_iter, blk_iter;

	for (lun_iter = 0; lun_iter < rrpc->nr_luns; lun_iter++) {
		rlun = &rrpc->luns[lun_iter];

		for (blk_iter = 0; blk_iter < rrpc->dev->blks_per_lun;
								blk_iter++) {
			rblk = &rlun->blocks[blk_iter];
			rrpc_block_map_update(rrpc, rblk);
		}
	}

	return 0;
}

static int rrpc_luns_configure(struct rrpc *rrpc)
{
	struct rrpc_lun *rlun;
	struct rrpc_block *rblk;
	int i;

	for (i = 0; i < rrpc->nr_luns; i++) {
		rlun = &rrpc->luns[i];

		rblk = rrpc_get_blk(rrpc, rlun, 0);
		if (!rblk)
			goto err;

		rrpc_set_lun_cur(rlun, rblk);

		/* Emergency gc block */
		rblk = rrpc_get_blk(rrpc, rlun, 1);
		if (!rblk)
			goto err;
		rlun->gc_cur = rblk;
	}

	return 0;
err:
	rrpc_put_blks(rrpc);
	return -EINVAL;
}

static struct nvm_tgt_type tt_rrpc;

static void *rrpc_init(struct nvm_dev *dev, struct gendisk *tdisk,
						int lun_begin, int lun_end)
{
	struct request_queue *bqueue = dev->q;
	struct request_queue *tqueue = tdisk->queue;
	struct rrpc *rrpc;
	int ret;

	if (!(dev->identity.dom & NVM_RSP_L2P)) {
		pr_err("nvm: rrpc: device does not support l2p (%x)\n",
							dev->identity.dom);
		return ERR_PTR(-EINVAL);
	}

	rrpc = kzalloc(sizeof(struct rrpc), GFP_KERNEL);
	if (!rrpc)
		return ERR_PTR(-ENOMEM);

	rrpc->instance.tt = &tt_rrpc;
	rrpc->dev = dev;
	rrpc->disk = tdisk;

	bio_list_init(&rrpc->requeue_bios);
	spin_lock_init(&rrpc->bio_lock);
	INIT_WORK(&rrpc->ws_requeue, rrpc_requeue);

	INIT_WORK(&rrpc->ws_writer, rrpc_submit_write);
	rrpc->kw_wq = alloc_workqueue("rrpc-writer",
					WQ_MEM_RECLAIM, 1);
	if (!rrpc->kw_wq)
		return ERR_PTR(-ENOMEM);

	rrpc->nr_luns = lun_end - lun_begin + 1;

	/* simple round-robin strategy */
	atomic_set(&rrpc->next_lun, -1);

	ret = rrpc_luns_init(rrpc, lun_begin, lun_end);
	if (ret) {
		pr_err("nvm: rrpc: could not initialize luns\n");
		goto err;
	}

	rrpc->poffset = dev->sec_per_lun * lun_begin;
	rrpc->lun_offset = lun_begin;

	ret = rrpc_core_init(rrpc);
	if (ret) {
		pr_err("nvm: rrpc: could not initialize core\n");
		goto err;
	}

	ret = rrpc_map_init(rrpc);
	if (ret) {
		pr_err("nvm: rrpc: could not initialize maps\n");
		goto err;
	}

	ret = rrpc_blocks_init(rrpc);
	if (ret) {
		pr_err("nvm: rrpc: could not initialize state for blocks\n");
		goto err;
	}

	ret = rrpc_luns_configure(rrpc);
	if (ret) {
		pr_err("nvm: rrpc: not enough blocks available in LUNs.\n");
		goto err;
	}

	ret = rrpc_gc_init(rrpc);
	if (ret) {
		pr_err("nvm: rrpc: could not initialize gc\n");
		goto err;
	}

	/* inherit the size from the underlying device */
	blk_queue_logical_block_size(tqueue, queue_physical_block_size(bqueue));
	blk_queue_max_hw_sectors(tqueue, queue_max_hw_sectors(bqueue));

	pr_info("nvm: rrpc initialized with %u luns and %llu pages.\n",
			rrpc->nr_luns, (unsigned long long)rrpc->nr_pages);

	mod_timer(&rrpc->gc_timer, jiffies + msecs_to_jiffies(10));

	return rrpc;
err:
	rrpc_free(rrpc);
	return ERR_PTR(ret);
}

/* round robin, page-based FTL, and cost-based GC */
static struct nvm_tgt_type tt_rrpc = {
	.name		= "rrpc",
	.version	= {1, 0, 0},

	.make_rq	= rrpc_make_rq,
	.capacity	= rrpc_capacity,
	.end_io		= rrpc_end_io,

	.init		= rrpc_init,
	.exit		= rrpc_exit,
};

static int __init rrpc_module_init(void)
{
	return nvm_register_target(&tt_rrpc);
}

static void rrpc_module_exit(void)
{
	nvm_unregister_target(&tt_rrpc);
}

module_init(rrpc_module_init);
module_exit(rrpc_module_exit);
MODULE_LICENSE("GPL v2");
MODULE_DESCRIPTION("Block-Device Target for Open-Channel SSDs");
