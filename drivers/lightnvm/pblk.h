/*
 * Copyright (C) 2015 IT University of Copenhagen (rrpc.h)
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
 * Implementation of a Physical Block-device target for Open-channel SSDs.
 *
 * Derived from rrpc.h
 */

#ifndef PBLK_H_
#define PBLK_H_

#include <linux/blkdev.h>
#include <linux/blk-mq.h>
#include <linux/bio.h>
#include <linux/module.h>
#include <linux/kthread.h>
#include <linux/vmalloc.h>

#include <linux/lightnvm.h>

/* Run only GC if less than 1/X blocks are free */
#define GC_LIMIT_INVERSE 10
#define GC_TIME_SECS 100

#define PBLK_SECTOR (512)
#define PBLK_EXPOSED_PAGE_SIZE (4096)

#define NR_PHY_IN_LOG (PBLK_EXPOSED_PAGE_SIZE / PBLK_SECTOR)

struct pblk_inflight {
	struct list_head reqs;
	spinlock_t lock;
};

struct pblk_inflight_rq {
	struct list_head list;
	sector_t l_start;
	sector_t l_end;
};

struct pblk_rq {
	struct pblk *pblk;
	struct pblk_addr *addr;
	struct pblk_inflight_rq inflight_rq;
	int nr_pages;

	struct kref refs;
};

struct pblk_buf_rq {
	struct pblk_addr *addr;
	struct pblk_rq *rrqd;
};

/* Sync strategies from write buffer to media */
enum {
	NVM_SYNC_SOFT	= 0x0,		/* Only submit at max_write_pgs
					 * supported by the device. Typically 64
					 * pages (256k).
					 */
	NVM_SYNC_HARD	= 0x1,		/* Submit the whole buffer. Add padding
					 * if necessary to respect the device's
					 * min_write_pgs.
					 */
	NVM_SYNC_OPORT	= 0x2,		/* Submit what we can, always respecting
					 * the device's min_write_pgs.
					 */
};

struct buf_entry {
	struct pblk_rq *rrqd;
	void *data;
	struct pblk_addr *addr;
	unsigned long flags;
};

struct pblk_w_buf {
	struct buf_entry *entries;	/* Entries */
	struct buf_entry *mem;		/* Points to the next writable entry */
	struct buf_entry *subm;		/* Points to the last submitted entry */
	int cur_mem;			/* Current memory entry. Follows mem */
	int cur_subm;			/* Entries have been submitted to dev */
	int nentries;			/* Number of entries in write buffer */

	void *data;			/* Actual data */
	unsigned long *sync_bitmap;	/* Bitmap representing physical
					 * addresses that have been synced to
					 * the media
					 */

	atomic_t refs;

	spinlock_t w_lock;
	spinlock_t s_lock;
};

struct pblk_block {
	struct nvm_block *parent;
	struct pblk_lun *rlun;
	struct list_head prio;
	struct list_head list;
	struct pblk_w_buf w_buf;

#define MAX_INVALID_PAGES_STORAGE 8
	/* Bitmap for invalid page entries */
	unsigned long invalid_pages[MAX_INVALID_PAGES_STORAGE];
	/* points to the next writable page within a block */
	unsigned int next_page;
	/* number of pages that are invalid, wrt host page size */
	unsigned int nr_invalid_pages;

	spinlock_t lock;
};

struct pblk_lun {
	struct pblk *pblk;
	struct nvm_lun *parent;
	struct pblk_block *cur, *gc_cur;
	struct pblk_block *blocks;	/* Reference to block allocation */

	struct list_head prio_list;	/* Blocks that may be GC'ed */
	struct list_head open_list;	/* In-use open blocks. These are blocks
					 * that can be both written to and read
					 * from
					 */
	struct list_head closed_list;	/* In-use closed blocks. These are
					 * blocks that can _only_ be read from
					 */

	struct work_struct ws_gc;
	struct work_struct ws_writer;

	spinlock_t lock;
};

struct pblk {
	/* instance must be kept in top to resolve pblk in unprep */
	struct nvm_tgt_instance instance;

	struct nvm_dev *dev;
	struct gendisk *disk;

	sector_t soffset; /* logical sector offset */
	u64 poffset; /* physical page offset */
	int lun_offset;

	int nr_luns;
	struct pblk_lun *luns;

	/* calculated values */
	unsigned long long nr_sects;
	unsigned long total_blocks;

	int min_write_pgs; /* minimum amount of pages required by controller */
	int max_write_pgs; /* maximum amount of pages supported by controller */

	/* Write strategy variables. Move these into each for structure for each
	 * strategy
	 */
	atomic_t next_lun; /* Whenever a page is written, this is updated
			    * to point to the next write lun
			    */

#ifdef CONFIG_NVM_DEBUG
	atomic_t inflight_writes;
	atomic_t req_writes;
	atomic_t sub_writes;
	atomic_t sync_writes;
	atomic_t inflight_reads;
#endif

	spinlock_t bio_lock;
	struct bio_list requeue_bios;
	struct work_struct ws_requeue;

	/* Simple translation map of logical addresses to physical addresses.
	 * The logical addresses is known by the host system, while the physical
	 * addresses are used when writing to the disk block device.
	 */
	struct pblk_addr *trans_map;
	/* also store a reverse map for garbage collection */
	struct pblk_rev_addr *rev_trans_map;
	spinlock_t rev_lock;

	struct pblk_inflight inflights;

	mempool_t *page_pool;
	mempool_t *gcb_pool;
	mempool_t *rq_pool;
	mempool_t *rrq_pool;
	mempool_t *flush_pool;

	struct timer_list gc_timer;
	struct workqueue_struct *krqd_wq;
	struct workqueue_struct *kgc_wq;
	struct workqueue_struct *kw_wq;
};

struct pblk_block_gc {
	struct pblk *pblk;
	struct pblk_block *rblk;
	struct work_struct ws_gc;
};

/* Logical to physical mapping */
struct pblk_addr {
	u64 addr;
	struct pblk_block *rblk;
};

/* Physical to logical mapping */
struct pblk_rev_addr {
	u64 addr;
};

static inline struct pblk_block *pblk_get_rblk(struct pblk_lun *rlun,
								int blk_id)
{
	struct pblk *pblk = rlun->pblk;
	int blk_pos = blk_id % pblk->dev->blks_per_lun;

	return &rlun->blocks[blk_pos];
}

static inline sector_t pblk_get_laddr(struct bio *bio)
{
	return bio->bi_iter.bi_sector / NR_PHY_IN_LOG;
}

static inline unsigned int pblk_get_pages(struct bio *bio)
{
	return  bio->bi_iter.bi_size / PBLK_EXPOSED_PAGE_SIZE;
}

static inline sector_t pblk_get_sector(sector_t laddr)
{
	return laddr * NR_PHY_IN_LOG;
}

static inline int request_intersects(struct pblk_inflight_rq *r,
				sector_t laddr_start, sector_t laddr_end)
{
	return (laddr_end >= r->l_start) && (laddr_start <= r->l_end);
}

static int __pblk_lock_laddr(struct pblk *pblk, sector_t laddr,
				unsigned pages, struct pblk_inflight_rq *r)
{
	sector_t laddr_end = laddr + pages - 1;
	struct pblk_inflight_rq *rtmp;

	WARN_ON(irqs_disabled());

	spin_lock_irq(&pblk->inflights.lock);
	list_for_each_entry(rtmp, &pblk->inflights.reqs, list) {
		if (unlikely(request_intersects(rtmp, laddr, laddr_end))) {
			/* existing, overlapping request, come back later */
			spin_unlock_irq(&pblk->inflights.lock);
			return 1;
		}
	}

	r->l_start = laddr;
	r->l_end = laddr_end;

	list_add_tail(&r->list, &pblk->inflights.reqs);
	spin_unlock_irq(&pblk->inflights.lock);
	return 0;
}

static inline int pblk_lock_laddr(struct pblk *pblk, sector_t laddr,
				unsigned pages,
				struct pblk_inflight_rq *r)
{
	BUG_ON((laddr + pages) > pblk->nr_sects);

	return __pblk_lock_laddr(pblk, laddr, pages, r);
}

static inline struct pblk_inflight_rq
				*pblk_get_inflight_rq(struct pblk_rq *rrqd)
{
	return &rrqd->inflight_rq;
}

static inline int pblk_lock_rq(struct pblk *pblk, struct bio *bio,
							struct pblk_rq *rrqd)
{
	sector_t laddr = pblk_get_laddr(bio);
	unsigned int pages = pblk_get_pages(bio);
	struct pblk_inflight_rq *r = pblk_get_inflight_rq(rrqd);

	return pblk_lock_laddr(pblk, laddr, pages, r);
}

static inline void pblk_unlock_laddr(struct pblk *pblk,
						struct pblk_inflight_rq *r)
{
	unsigned long flags;

	spin_lock_irqsave(&pblk->inflights.lock, flags);
	list_del_init(&r->list);
	spin_unlock_irqrestore(&pblk->inflights.lock, flags);
}

static inline void pblk_unlock_rq(struct pblk *pblk, struct pblk_rq *rrqd)
{
	struct pblk_inflight_rq *r = pblk_get_inflight_rq(rrqd);
	uint8_t nr_pages = rrqd->nr_pages;

	BUG_ON((r->l_start + nr_pages) > pblk->nr_sects);

	pblk_unlock_laddr(pblk, r);
}

#endif /* PBLK_H_ */
