/*
 * Copyright (C) 2015 IT University of Copenhagen (rrpc.c)
 * Copyright (C) 2016 CNEX Labs
 * Initial release: Javier Gonzalez <jg@lightnvm.io>
 *                  Matias Bjorling <m@bjorling.me>
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

static struct kmem_cache *pblk_blk_ws_cache, *pblk_rec_cache, *pblk_r_rq_cache,
							*pblk_w_rq_cache;
static DECLARE_RWSEM(pblk_lock);

static const struct block_device_operations pblk_fops = {
	.owner		= THIS_MODULE,
};

#ifdef CONFIG_NVM_DEBUG
static inline u64 pblk_current_pg(struct pblk *pblk, struct pblk_block *rblk)
{
	int next_free_page;

	spin_lock(&rblk->lock);
	next_free_page = find_first_zero_bit(rblk->sector_bitmap,
							pblk->nr_blk_dsecs);
	spin_unlock(&rblk->lock);

	return next_free_page;
}
#endif

static int pblk_submit_io_checks(struct pblk *pblk, struct bio *bio)
{
	int bio_size = bio_sectors(bio) << 9;
	int is_flush = (bio->bi_rw & (REQ_FLUSH | REQ_FUA));

	if ((bio_size < pblk->dev->sec_size) && (!is_flush))
		return 1;

	if (bio_size > pblk->dev->max_rq_size)
		return 1;

	return 0;
}

static int pblk_submit_io(struct pblk *pblk, struct bio *bio,
			  unsigned long flags)
{
	if (pblk_submit_io_checks(pblk, bio))
		return NVM_IO_ERR;

	if (bio_rw(bio) == READ)
		return pblk_submit_read(pblk, bio, flags);

	return pblk_buffer_write(pblk, bio, flags);
}

static blk_qc_t pblk_make_rq(struct request_queue *q, struct bio *bio)
{
	struct pblk *pblk = q->queuedata;
	int err;

	if (bio->bi_rw & REQ_DISCARD) {
		pblk_discard(pblk, bio);
		if (!(bio->bi_rw & (REQ_FLUSH | REQ_FUA)))
			return BLK_QC_T_NONE;
	}

	err = pblk_submit_io(pblk, bio, PBLK_IOTYPE_NONE);
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

static void pblk_map_free(struct pblk *pblk)
{
	vfree(pblk->trans_map);
}

static int pblk_map_init(struct pblk *pblk)
{
	struct nvm_dev *dev = pblk->dev;
	sector_t i;
	u64 slba;

	slba = pblk->soffset >> (ilog2(dev->sec_size) - 9);

	pblk->trans_map = vzalloc(sizeof(struct pblk_addr) * pblk->nr_secs);
	if (!pblk->trans_map)
		return -ENOMEM;

	for (i = 0; i < pblk->nr_secs; i++) {
		struct pblk_addr *p = &pblk->trans_map[i];

		p->rblk = NULL;
		ppa_set_empty(&p->ppa);
	}

	return 0;
}

static void pblk_rwb_free(struct pblk *pblk)
{
	vfree(pblk_rb_data_ref(&pblk->rwb));
	vfree(pblk_rb_entries_ref(&pblk->rwb));
}

static int pblk_rgcb_init(struct pblk *pblk)
{
	struct nvm_dev *dev = pblk->dev;
	struct pblk_rb_entry *entries;
	void *data_buffer;
	unsigned long nr_entries, data_size;
	unsigned int power_size, power_seg_sz, grace_area_sz;

	/* Allocate one block for emergency GC */
	nr_entries = pblk_rb_calculate_size(dev->sec_per_blk);
	data_size = nr_entries * dev->sec_size;

	data_buffer = vzalloc(data_size);
	if (!data_buffer)
		return -ENOMEM;

	entries = vzalloc(nr_entries * sizeof(struct pblk_rb_entry));
	if (!entries) {
		vfree(data_buffer);
		return -ENOMEM;
	}

	/* Assume no grace area for now - only support for SLC and MLC */
	grace_area_sz = 0;
	power_size = get_count_order(nr_entries);
	power_seg_sz = get_count_order(dev->sec_size);

	pblk_rb_init(&pblk->rgcb, entries, data_buffer, grace_area_sz,
					power_size, power_seg_sz, PBLK_RB_GC);

	return 0;
}

static int pblk_rwb_init(struct pblk *pblk)
{
	struct nvm_dev *dev = pblk->dev;
	struct pblk_rb_entry *entries;
	void *data_buffer;
	unsigned long nr_entries, data_size;
	unsigned int power_size, power_seg_sz, grace_area_sz;

	/*
	 * pblk write buffer characteristics:
	 *  - It must be able to hold one entire flash block from each device
	 *  LUN configured in the target.
	 *  - It must respect a grace area corresponding to the actual memory
	 *  constrains so that the memory is correctly programmed. For example,
	 *  in TLC NAND memories there should be space enough so that each block
	 *  present in the buffer can hold the upper, middle, and lower page so
	 *  that the NAND can be correctly programmed.
	 *  - It is not necessary that a whole flash block is maintained in
	 *  memory before the last sector of the block is persisted in the NAND.
	 *  If a block becomes bad while it is being programmed, already written
	 *  pages can be read, as long as the write constrains are being met,
	 *  e.g., programming the three mentioned pages in TLC memories.
	 *  - Each entry of the buffer holds a pointer to the actual data on
	 *  that entry and a pointer to metadata associated to the entry.
	 */
	nr_entries = pblk_rb_calculate_size(pblk->nr_luns * dev->sec_per_blk);
	data_size = nr_entries * dev->sec_size;

	data_buffer = vzalloc(data_size);
	if (!data_buffer)
		return -ENOMEM;

	entries = vzalloc(nr_entries * sizeof(struct pblk_rb_entry));
	if (!entries) {
		vfree(data_buffer);
		return -ENOMEM;
	}

	/* Assume no grace area for now - only support for SLC and MLC */
	grace_area_sz = 0;
	power_size = get_count_order(nr_entries);
	power_seg_sz = get_count_order(dev->sec_size);

	pblk_rb_init(&pblk->rwb, entries, data_buffer, grace_area_sz,
				power_size, power_seg_sz, PBLK_RB_GENERAL);

	return 0;
}

/* Minimum pages needed within a lun */
#define PAGE_POOL_SIZE 16
#define ADDR_POOL_SIZE 64

static int pblk_core_init(struct pblk *pblk)
{
	down_write(&pblk_lock);
	if (!pblk_blk_ws_cache) {
		pblk_blk_ws_cache = kmem_cache_create("pblk_blk_ws",
				sizeof(struct pblk_block_ws), 0, 0, NULL);
		if (!pblk_blk_ws_cache) {
			up_write(&pblk_lock);
			return -ENOMEM;
		}

		pblk_rec_cache = kmem_cache_create("pblk_rec",
				sizeof(struct pblk_rec_ctx), 0, 0, NULL);
		if (!pblk_rec_cache) {
			kmem_cache_destroy(pblk_blk_ws_cache);
			up_write(&pblk_lock);
			return -ENOMEM;
		}

		pblk_r_rq_cache = kmem_cache_create("pblk_r_rq", pblk_r_rq_size,
				0, 0, NULL);
		if (!pblk_r_rq_cache) {
			kmem_cache_destroy(pblk_blk_ws_cache);
			kmem_cache_destroy(pblk_rec_cache);
			up_write(&pblk_lock);
			return -ENOMEM;
		}

		pblk_w_rq_cache = kmem_cache_create("pblk_w_rq", pblk_w_rq_size,
				0, 0, NULL);
		if (!pblk_w_rq_cache) {
			kmem_cache_destroy(pblk_blk_ws_cache);
			kmem_cache_destroy(pblk_rec_cache);
			kmem_cache_destroy(pblk_r_rq_cache);
			up_write(&pblk_lock);
			return -ENOMEM;
		}
	}
	up_write(&pblk_lock);

	pblk->page_pool = mempool_create_page_pool(PAGE_POOL_SIZE, 0);
	if (!pblk->page_pool)
		return -ENOMEM;

	pblk->blk_ws_pool = mempool_create_slab_pool(pblk->dev->nr_luns,
							pblk_blk_ws_cache);
	if (!pblk->blk_ws_pool)
		goto free_page_pool;

	pblk->rec_pool = mempool_create_slab_pool(pblk->dev->nr_luns,
							pblk_rec_cache);
	if (!pblk->rec_pool)
		goto free_blk_ws_pool;

	pblk->r_rq_pool = mempool_create_slab_pool(64, pblk_r_rq_cache);
	if (!pblk->r_rq_pool)
		goto free_rec_pool;

	pblk->w_rq_pool = mempool_create_slab_pool(16, pblk_w_rq_cache);
	if (!pblk->w_rq_pool)
		goto free_r_rq_pool;

	pblk->kw_wq = alloc_workqueue("pblk-writer",
				WQ_MEM_RECLAIM | WQ_UNBOUND, pblk->nr_luns);
	if (!pblk->kw_wq)
		goto free_w_rq_pool;

	/* Init write buffer */
	if (pblk_rwb_init(pblk))
		goto free_kw_wq;

	/* Init emergency GC buffer */
	if (pblk_rgcb_init(pblk))
		goto free_rwb;


	pblk->gc_limit = pblk->nr_luns * 4;
	INIT_LIST_HEAD(&pblk->compl_list);

	return 0;

free_rwb:
	pblk_rwb_free(pblk);
free_kw_wq:
	destroy_workqueue(pblk->kw_wq);
free_w_rq_pool:
	mempool_destroy(pblk->w_rq_pool);
free_r_rq_pool:
	mempool_destroy(pblk->r_rq_pool);
free_rec_pool:
	mempool_destroy(pblk->rec_pool);
free_blk_ws_pool:
	mempool_destroy(pblk->blk_ws_pool);
free_page_pool:
	mempool_destroy(pblk->page_pool);
	return -ENOMEM;
}

static void pblk_core_free(struct pblk *pblk)
{
	if (pblk->kw_wq)
		destroy_workqueue(pblk->kw_wq);

	mempool_destroy(pblk->page_pool);
	mempool_destroy(pblk->blk_ws_pool);
	mempool_destroy(pblk->rec_pool);
	mempool_destroy(pblk->r_rq_pool);
	mempool_destroy(pblk->w_rq_pool);
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
	kfree(pblk->ch_list);
}

static int pblk_luns_init(struct pblk *pblk, int lun_begin, int lun_end)
{
	struct nvm_dev *dev = pblk->dev;
	struct pblk_lun *rlun;
	int i, j, mod, ret = -EINVAL;

	pblk->nr_blk_dsecs = dev->sec_per_blk - dev->sec_per_pl;
	pblk->min_write_pgs = dev->sec_per_pl * (dev->sec_size / PAGE_SIZE);
	/* assume max_phys_sect % dev->min_write_pgs == 0 */
	pblk->max_write_pgs = dev->ops->max_phys_sect;

	if (pblk->max_write_pgs > PBLK_MAX_REQ_ADDRS) {
		pr_err("pblk: cannot support device max_phys_sect\n");
		return -EINVAL;
	}

	div_u64_rem(dev->sec_per_blk, pblk->min_write_pgs, &mod);
	if (mod) {
		pr_err("pblk: bad configuration of sectors/pages\n");
		return -EINVAL;
	}

	pblk->luns = kcalloc(pblk->nr_luns, sizeof(struct pblk_lun),
								GFP_KERNEL);
	if (!pblk->luns)
		return -ENOMEM;

	pblk->ch_list = kcalloc(dev->nr_chnls, sizeof(struct pblk_ch),
								GFP_KERNEL);
	if (!pblk->ch_list)
		return -ENOMEM;

	for (i = 0; i < dev->nr_chnls; i++)
		sema_init(&pblk->ch_list[i].ch_sm, PBLK_MAX_CH_INFLIGHT_IOS);

	/* 1:1 mapping */
	for (i = 0; i < pblk->nr_luns; i++) {
		/* Align lun list to the channel each lun belongs to */
		int ch =  ((lun_begin + i) % dev->nr_chnls);
		int lun_raw =  ((lun_begin + i) / dev->nr_chnls);
		int lunid =  lun_raw + ch * dev->luns_per_chnl;
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

		rlun->ch = ch;

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
		INIT_LIST_HEAD(&rlun->bb_list);

		rlun->nr_bad_blocks = 0;

		INIT_WORK(&rlun->ws_gc, pblk_lun_gc);

		spin_lock_init(&rlun->lock);
		spin_lock_init(&rlun->lock_lists);

		pblk->total_blocks += dev->blks_per_lun;
		pblk->nr_secs += dev->sec_per_lun;

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
	sector_t size = pblk->nr_secs * dev->sec_size;

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
	pblk_map_free(pblk);
	pblk_core_free(pblk);
	pblk_luns_free(pblk);
	pblk_area_free(pblk);

	kfree(pblk);
}

static void pblk_tear_down(struct pblk *pblk)
{
	pblk_flush_writer(pblk);
	pblk_pad_open_blks(pblk);
	pblk_rb_sync_l2p(&pblk->rwb);
	pblk_rwb_free(pblk);

	if (pblk_rb_tear_down_check(&pblk->rwb)) {
		pr_err("pblk: write buffer error on tear down\n");
		return;
	}

	/* TODO: Stop GC before freeing blocks */
	pblk_free_blks(pblk);

	pr_debug("pblk: consistent tear down\n");

	/* TODO: Save FTL snapshot for fast recovery */
}

static void pblk_exit(void *private)
{
	struct pblk *pblk = private;

	down_write(&pblk_lock);
	flush_workqueue(pblk->krqd_wq);
	pblk_tear_down(pblk);
	pblk_gc_exit(pblk);
	pblk_free(pblk);
	up_write(&pblk_lock);
}

static sector_t pblk_capacity(void *private)
{
	struct pblk *pblk = private;
	struct nvm_dev *dev = pblk->dev;
	sector_t reserved, provisioned;

	/* cur, gc, and two emergency blocks for each lun */
	reserved = pblk->nr_luns * dev->sec_per_blk * 4;
	provisioned = pblk->nr_secs - reserved;

	if (reserved > pblk->nr_secs) {
		pr_err("pblk: not enough space available to expose storage.\n");
		return 0;
	}

	sector_div(provisioned, 10);
	return provisioned * 9 * NR_PHY_IN_LOG;
}

static int pblk_blocks_init(struct pblk *pblk)
{
	struct pblk_lun *rlun;
	struct pblk_block *rblk;
	int lun, blk;
	int ret = 0;

	/* TODO: Try to recover from l2p snapshot. Only perform scanning in
	 * case of failure
	 */

#ifdef CONFIG_NVM_PBLK_NO_RECOV
	return 0;
#endif

	for (lun = 0; lun < pblk->nr_luns; lun++) {
		rlun = &pblk->luns[lun];
		for (blk = 0; blk < pblk->dev->blks_per_lun; blk++) {
			rblk = &rlun->blocks[blk];
			ret = pblk_recov_scan_blk(pblk, rblk);
			if (ret) {
				pr_err("nvm: pblk: could not recover l2p\n");
				goto out;
			}
		}
	}

out:
	return ret;
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

		pblk_set_lun_cur(rlun, rblk, 0);

		/* Emergency gc block */
		rblk = pblk_get_blk(pblk, rlun, 1);
		if (!rblk)
			goto err;
		rlun->gc_cur = rblk;
	}

	return 0;
err:
	while (--i >= 0) {
		rlun = &pblk->luns[i];

		if (rlun->cur)
			pblk_put_blk(pblk, rlun->cur);
		if (rlun->gc_cur)
			pblk_put_blk(pblk, rlun->gc_cur);
	}
	return -EINVAL;
}

#ifdef CONFIG_NVM_DEBUG
static ssize_t pblk_sysfs_stats(struct pblk *pblk, char *buf)
{
	ssize_t offset;

	offset = scnprintf(buf, PAGE_SIZE,
			"%u\t%u\t%u\t%u\t%u\t%u\t%u\t%u\t%u\t%u\t%u\t%u\n",
			atomic_read(&pblk->inflight_writes),
			atomic_read(&pblk->inflight_reads),
			atomic_read(&pblk->req_writes),
			atomic_read(&pblk->nr_flush),
			atomic_read(&pblk->padded_writes),
			atomic_read(&pblk->sub_writes),
			atomic_read(&pblk->sync_writes),
			atomic_read(&pblk->compl_writes),
			atomic_read(&pblk->recov_writes),
			atomic_read(&pblk->recov_gc_writes),
			atomic_read(&pblk->requeued_writes),
			atomic_read(&pblk->sync_reads));

	return offset;
}

static ssize_t pblk_sysfs_open_blks(struct pblk *pblk, char *buf)
{
	struct pblk_lun *rlun;
	struct pblk_block *rblk;
	int i;
	ssize_t sz = 0;

	pblk_for_each_lun(pblk, rlun, i) {
		sz += sprintf(buf + sz, "LUN:%d\n", rlun->parent->id);

		spin_lock(&rlun->lock_lists);
		list_for_each_entry(rblk, &rlun->open_list, list) {
			spin_lock(&rblk->lock);
			sz += sprintf(buf + sz,
				"open:\tblk:%lu\t%u\t%u\t%u\t%u\t%u\t%u\n",
				rblk->parent->id,
				pblk->dev->sec_per_blk,
				pblk->nr_blk_dsecs,
				bitmap_weight(rblk->sector_bitmap,
							pblk->dev->sec_per_blk),
				bitmap_weight(rblk->sync_bitmap,
							pblk->dev->sec_per_blk),
				bitmap_weight(rblk->invalid_bitmap,
							pblk->dev->sec_per_blk),
				rblk->nr_invalid_secs);
			spin_unlock(&rblk->lock);
		}
		spin_unlock(&rlun->lock_lists);
	}

	return sz;
}

static ssize_t pblk_sysfs_bad_blks(struct pblk *pblk, char *buf)
{
	struct pblk_lun *rlun;
	struct pblk_block *rblk;
	int i;
	ssize_t sz = 0;

	pblk_for_each_lun(pblk, rlun, i) {
		sz += sprintf(buf + sz, "LUN:%d\n", rlun->parent->id);

		spin_lock(&rlun->lock_lists);
		list_for_each_entry(rblk, &rlun->bb_list, list) {
			spin_lock(&rblk->lock);
			sz += sprintf(buf + sz,
				"bad:\tblk:%lu\t%u\n",
				rblk->parent->id,
				bitmap_weight(rblk->sector_bitmap,
						pblk->dev->sec_per_blk));
			spin_unlock(&rblk->lock);
		}
		spin_unlock(&rlun->lock_lists);
	}

	return sz;
}

static ssize_t pblk_sysfs_write_buffer(struct pblk *pblk, char *buf)
{
	return pblk_rb_sysfs(&pblk->rwb, buf);
}

static ssize_t pblk_sysfs_backpointer(struct pblk *pblk, char *buf)
{
	struct pblk_ctx *c;
	struct pblk_compl_ctx *c_ctx;
	int i = 0;
	ssize_t sz = 0;

	list_for_each_entry(c, &pblk->compl_list, list) {
		c_ctx = c->c_ctx;
		sz += sprintf(buf + sz, "Entry:%d\t%u\t%u\t%u\n",
			i,
			c_ctx->sentry,
			c_ctx->nr_valid,
			c_ctx->nr_padded);
	}

	return sz;
}

#else
static ssize_t pblk_sysfs_stats(struct pblk *pblk, char *buf)
{
	return 0;
}

static ssize_t pblk_sysfs_open_blks(struct pblk *pblk, char *buf)
{
	return 0;
}

static ssize_t pblk_sysfs_bad_blks(struct pblk *pblk, char *buf)
{
	return 0;
}

static ssize_t pblk_sysfs_write_buffer(struct pblk *pblk, char *buf)
{
	return 0;
}

static ssize_t pblk_sysfs_backpointer(struct pblk *pblk, char *buf)
{
	return 0;
}
#endif

static struct attribute sys_stats_attr = {
	.name = "stats",
	.mode = S_IRUGO
};

static struct attribute sys_open_blocks_attr = {
	.name = "open",
	.mode = S_IRUGO
};

static struct attribute sys_bad_blocks_attr = {
	.name = "bad",
	.mode = S_IRUGO
};

static struct attribute sys_rb_attr = {
	.name = "write_buffer",
	.mode = S_IRUGO
};

static struct attribute sys_backpointer_attr = {
	.name = "backpointer",
	.mode = S_IRUGO
};

static struct attribute *pblk_attrs[] = {
	&sys_stats_attr,
	&sys_open_blocks_attr,
	&sys_bad_blocks_attr,
	&sys_rb_attr,
	&sys_backpointer_attr,
	NULL,
};

static const struct attribute_group pblk_attr_group = {
	.attrs		= pblk_attrs,
};

static ssize_t pblk_sysfs_show(struct nvm_target *t, struct attribute *attr,
			       char *buf)
{
	struct pblk *pblk = t->disk->private_data;

	if (strcmp(attr->name, "stats") == 0)
		return pblk_sysfs_stats(pblk, buf);
	if (strcmp(attr->name, "open") == 0)
		return pblk_sysfs_open_blks(pblk, buf);
	if (strcmp(attr->name, "bad") == 0)
		return pblk_sysfs_bad_blks(pblk, buf);
	if (strcmp(attr->name, "write_buffer") == 0)
		return pblk_sysfs_write_buffer(pblk, buf);
	if (strcmp(attr->name, "backpointer") == 0)
		return pblk_sysfs_backpointer(pblk, buf);

	return 0;
}

static void pblk_sysfs_init(struct nvm_target *t)
{
	if (sysfs_create_group(&t->kobj, &pblk_attr_group))
		pr_warn("%s: failed to create sysfs group\n",
			t->disk->disk_name);
}

static void pblk_sysfs_exit(struct nvm_target *t)
{
	sysfs_remove_group(&t->kobj, &pblk_attr_group);
}

static void *pblk_init(struct nvm_dev *dev, struct gendisk *tdisk,
		       int lun_begin, int lun_end);

/* physical block device target */
static struct nvm_tgt_type tt_pblk = {
	.name		= "pblk",
	.version	= {1, 0, 0},

	.make_rq	= pblk_make_rq,
	.capacity	= pblk_capacity,
	.end_io		= pblk_end_io,

	.init		= pblk_init,
	.exit		= pblk_exit,

	.sysfs_init	= pblk_sysfs_init,
	.sysfs_exit	= pblk_sysfs_exit,
	.sysfs_show	= pblk_sysfs_show,
};

static void *pblk_init(struct nvm_dev *dev, struct gendisk *tdisk,
		       int lun_begin, int lun_end)
{
	struct request_queue *bqueue = dev->q;
	struct request_queue *tqueue = tdisk->queue;
	struct pblk *pblk;
	sector_t soffset;
	int ret;

	/* XXX: Workaround due to FW bug */
#if 0
	if (dev->identity.dom & NVM_RSP_L2P) {
		pr_err("nvm: pblk: device has device-side translation table. "
						" Target not supported. (%x)\n",
							dev->identity.dom);
		return ERR_PTR(-EINVAL);
	}
#endif

	pblk = kzalloc(sizeof(struct pblk), GFP_KERNEL);
	if (!pblk)
		return ERR_PTR(-ENOMEM);

	pblk->instance.tt = &tt_pblk;
	pblk->dev = dev;
	pblk->disk = tdisk;

	bio_list_init(&pblk->requeue_bios);
	spin_lock_init(&pblk->bio_lock);
	spin_lock_init(&pblk->trans_lock);
	INIT_WORK(&pblk->ws_requeue, pblk_requeue);

	pblk->nr_luns = lun_end - lun_begin + 1;

	/* simple round-robin strategy */
	atomic_set(&pblk->next_lun, -1);

#ifdef CONFIG_NVM_DEBUG
	atomic_set(&pblk->inflight_writes, 0);
	atomic_set(&pblk->padded_writes, 0);
	atomic_set(&pblk->nr_flush, 0);
	atomic_set(&pblk->req_writes, 0);
	atomic_set(&pblk->sub_writes, 0);
	atomic_set(&pblk->sync_writes, 0);
	atomic_set(&pblk->compl_writes, 0);
	atomic_set(&pblk->inflight_reads, 0);
	atomic_set(&pblk->sync_reads, 0);
	atomic_set(&pblk->recov_writes, 0);
	atomic_set(&pblk->recov_gc_writes, 0);
	atomic_set(&pblk->requeued_writes, 0);
#endif

	ret = pblk_area_init(pblk, &soffset);
	if (ret < 0) {
		pr_err("pblk: could not initialize area\n");
		return ERR_PTR(ret);
	}
	pblk->soffset = soffset;

	ret = pblk_luns_init(pblk, lun_begin, lun_end);
	if (ret) {
		pr_err("pblk: could not initialize luns\n");
		goto err;
	}

	pblk->poffset = dev->sec_per_lun * lun_begin;
	pblk->lun_offset = lun_begin;

	ret = pblk_core_init(pblk);
	if (ret) {
		pr_err("pblk: could not initialize core\n");
		goto err;
	}

	ret = pblk_map_init(pblk);
	if (ret) {
		pr_err("pblk: could not initialize maps\n");
		goto err;
	}

	ret = pblk_blocks_init(pblk);
	if (ret) {
		pr_err("pblk: could not initialize state for blocks\n");
		goto err;
	}

	ret = pblk_luns_configure(pblk);
	if (ret) {
		pr_err("pblk: not enough blocks available in LUNs.\n");
		goto err;
	}

	ret = pblk_gc_init(pblk);
	if (ret) {
		pr_err("pblk: could not initialize gc\n");
		goto err;
	}

	/* inherit the size from the underlying device */
	blk_queue_logical_block_size(tqueue, queue_physical_block_size(bqueue));
	blk_queue_max_hw_sectors(tqueue, queue_max_hw_sectors(bqueue));

	/* Signal the block layer that flush is supported */
	blk_queue_flush(tqueue, REQ_FLUSH | REQ_FUA);

	pr_info("pblk initialized with %u luns and %llu pages.\n",
			pblk->nr_luns, (unsigned long long)pblk->nr_secs);

	mod_timer(&pblk->gc_timer, jiffies + msecs_to_jiffies(10));

	return pblk;
err:
	pblk_free(pblk);
	return ERR_PTR(ret);
}

static int __init pblk_module_init(void)
{
	return nvm_register_tgt_type(&tt_pblk);
}

static void pblk_module_exit(void)
{
	nvm_unregister_tgt_type(&tt_pblk);
}

module_init(pblk_module_init);
module_exit(pblk_module_exit);
MODULE_AUTHOR("Javier Gonzalez <jg@lightnvm.io>");
MODULE_AUTHOR("Matias Bjorling <m@bjorling.me>");
MODULE_LICENSE("GPL v2");
MODULE_DESCRIPTION("Physical Block-Device Target for Open-Channel SSDs");
