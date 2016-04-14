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

/* Sync strategies from write buffer to media */
enum {
	NVM_SYNC_SOFT	= 0x0,		/* Only submit at max_write_pgs
					 * supported by the device, typically 64
					 * pages (256k). This option ignores
					 * sync I/Os from the upper layers
					 * (e.g., REQ_FLUSH, REQ_FUA).
					 */
	NVM_SYNC_HARD	= 0x1,		/* Submit the whole buffer. Add padding
					 * if necessary to respect the device's
					 * min_write_pgs. Respect sync I/Os.
					 */
	NVM_SYNC_OPORT	= 0x2,		/* Submit what we can, always respecting
					 * the device's min_write_pgs and sync
					 * I/Os.
					 */
};

struct pblk_l2p_lock {
	struct list_head lock_list;
	spinlock_t lock;
};

struct pblk_l2p_upd_ctx {
	struct list_head list;
	sector_t l_start;
	sector_t l_end;
};

/* Logical to physical mapping */
struct pblk_addr {
	struct ppa_addr ppa;		/* cacheline OR physical address */
	struct pblk_block *rblk;	/* reference to pblk block for lookup */
};

/* Completion context */
struct pblk_compl_ctx {
	unsigned int sentry;
	unsigned int nentries;
};

/* Write context */
struct pblk_w_ctx {
	struct bio *bio;		/* Original bio - used for completing in
					 * REQ_FUA, REQ_FLUSH case
					 */
	struct pblk_l2p_upd_ctx upt_ctx;/* Update context for l2p table */
	sector_t lba;			/* Logic addr. associated with entry */
	struct pblk_addr ppa;		/* Physic addr. associated with entry */
	int flags;			/* Write context flags */
};

struct pblk_ctx {
	struct list_head list;
	struct pblk *pblk;
	struct pblk_compl_ctx *c_ctx;
	struct pblk_w_ctx *w_ctx;
};

struct pblk_rb_entry {
	void *data;			/* Pointer to data on this entry */
	struct pblk_w_ctx w_ctx;	/* Context for this entry */
};

#define RB_EMPTY_ENTRY (~0ULL)

struct pblk_rb {
	struct pblk_rb_entry *entries;	/* Ring buffer entries */
	unsigned long mem;		/* Write offset - points to next
					 * writable entry in memory
					 */
	unsigned long subm;		/* Read offset - points to last entry
					 * that has been submitted to the media
					 * to be persisted
					 */
	unsigned long sync;		/* Synced - backpointer that signals
					 * the last submitted entry that has
					 * been successfully persisted to media
					 */
	unsigned long sync_point;	/* Sync point - last entry that must be
					 * flushed to the media. Used with
					 * REQ_FLUSH and REQ_FUA
					 */
	unsigned long nentries;		/* Number of entries in write buffer -
					   must be a power of two */
	unsigned long grace_area;	/* Space in buffer that must be
					 * respected between head and tail. This
					 * space is memory-specific.
					 */
	unsigned long data_size;	/* Data buffer size in bytes - must be a
					 * power of two.
					 */
	unsigned int seg_size;		/* Size of the data segments being
					 * stored on each entry. Typically this
					 * will be 4KB */

	void *data;			/* Data buffer*/

	spinlock_t w_lock;		/* Write lock */
	spinlock_t s_lock;		/* Submit lock */
	spinlock_t sy_lock;		/* Sync lock */
};

struct pblk_block {
	struct nvm_block *parent;
	struct pblk_lun *rlun;
	struct list_head prio;
	struct list_head list;

	unsigned long *sync_bitmap;	/* Bitmap representing physical
					 * addresses that have been synced to
					 * the media
					 */

#define MAX_INVALID_PAGES_STORAGE 64
	/* Bitmap for invalid page entries */
	unsigned long invalid_pages[MAX_INVALID_PAGES_STORAGE];
	/* Bitmap for free (0) / used pages (1) in the block */
	unsigned long *pages;
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

	spinlock_t lock_lists;
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

	struct pblk_rb rwb;

	int min_write_pgs; /* minimum amount of pages required by controller */
	int max_write_pgs; /* maximum amount of pages supported by controller */

	/* Write strategy variables. Move these into each for structure for each
	 * strategy
	 */
	atomic_t next_lun; /* Whenever a page is written, this is updated
			    * to point to the next write lun
			    */

#ifdef CONFIG_NVM_DEBUG
	/* All debug counters apply to 4kb sector I/Os */
	atomic_t inflight_writes;	/* Sectors not synced to media */
	atomic_t padded_writes;		/* Sectors padded due to flush/fua */
	atomic_t req_writes;		/* Sectors stored on write buffer */
	atomic_t sub_writes;		/* Sectors submitted from buffer */
	atomic_t sync_writes;		/* Sectors synced to media */
	atomic_t compl_writes;		/* Sectors completed in write bio */
	atomic_t inflight_reads;	/* Inflight sector read requests */
	atomic_t sync_reads;		/* Completed sector read requests */
#endif

	spinlock_t bio_lock;
	struct bio_list requeue_bios;
	struct work_struct ws_requeue;
	struct work_struct ws_writer;

	/* Simple translation map of logical addresses to physical addresses.
	 * The logical addresses is known by the host system, while the physical
	 * addresses are used when writing to the disk block device.
	 */
	struct pblk_addr *trans_map;
	struct pblk_l2p_lock l2p_locks;

	struct list_head compl_list;

	mempool_t *page_pool;
	mempool_t *gcb_pool;
	mempool_t *r_rq_pool;
	mempool_t *w_rq_pool;

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

/* pblk ring buffer operations */
int pblk_rb_init(struct pblk_rb *rb, struct pblk_rb_entry *rb_entry_base,
			void *rb_data_base, unsigned long grace_area_sz,
			unsigned int power_size, unsigned int power_seg_sz);
int pblk_rb_write_entry(struct pblk_rb *rb, void *data, struct pblk_w_ctx w_ctx,
							unsigned int pos);
unsigned long pblk_rb_write_init(struct pblk_rb *rb);
void pblk_rb_write_commit(struct pblk_rb *rb, unsigned int nentries);
void pblk_rb_write_rollback(struct pblk_rb *rb);
unsigned long pblk_rb_count_init(struct pblk_rb *rb);
unsigned int pblk_rb_read(struct pblk_rb *rb, void *buf,
					struct pblk_ctx *ctx,
					unsigned int nentries);
unsigned int pblk_rb_read_to_bio(struct pblk_rb *rb, struct bio *bio,
					struct pblk_ctx *ctx,
					unsigned int nentries);
void pblk_rb_read_commit(struct pblk_rb *rb, unsigned int entries);
void pblk_rb_read_rollback(struct pblk_rb *rb);
unsigned int pblk_rb_copy_entry_to_bio(struct pblk_rb *rb, struct bio *bio,
								u64 pos);
unsigned long pblk_rb_sync_init(struct pblk_rb *rb, unsigned long *flags);
unsigned long pblk_rb_sync_advance(struct pblk_rb *rb, unsigned int nentries);
void pblk_rb_sync_end(struct pblk_rb *rb, unsigned long flags);
int pblk_rb_sync_point_set(struct pblk_rb *rb, struct bio *bio);
unsigned long pblk_rb_sync_point_count(struct pblk_rb *rb);
void pblk_rb_sync_point_reset(struct pblk_rb *rb);

// unsigned pblk_rb_get_ref(struct pblk_rb *rb, void *ptr, unsigned nentries);
// unsigned pblk_rb_get_ref_lock(struct pblk_rb *rb, void *ptr, unsigned nentries);
// void pblk_rb_commit(struct pblk_rb *rb, int rw);

unsigned long pblk_rb_space(struct pblk_rb *rb);
unsigned long pblk_rb_count(struct pblk_rb *rb);

#ifdef CONFIG_NVM_DEBUG
void pblk_rb_print_debug(struct pblk_rb *rb);
#endif

static inline struct pblk_ctx *pblk_set_ctx(struct pblk *pblk,
							struct nvm_rq *rqd)
{
	struct pblk_ctx *c;

	c = nvm_rq_to_pdu(rqd);
	c->pblk = pblk;
	c->c_ctx = (struct pblk_compl_ctx*)(c + 1);
	c->w_ctx = (struct pblk_w_ctx*)(c->c_ctx + 1);

	return c;
}

static inline void pblk_memcpy_addr(struct pblk_addr *to,
							struct pblk_addr *from)
{
	to->ppa = from->ppa;
	to->rblk = from->rblk;
}

/* Calculate the page offset of within a block from a generic address */
static inline unsigned int pblk_gaddr_to_pg_offset(struct nvm_dev *dev,
							struct ppa_addr p)
{
	/* FIXME: The calculation is correct, but the variable naming is
	 * misleading. Change this.
	 */
	return (unsigned int) (p.g.pg * dev->sec_per_pl) +
				(p.g.pl * dev->sec_per_pg ) + p.g.sec;
}

static inline struct ppa_addr pblk_cacheline_to_ppa(u64 addr)
{
	struct ppa_addr gp;

	//TODO: Check that last bit is not set
	gp.c.line = (u64)addr;
	gp.c.is_cached = 1;

	return gp;
}

static inline struct pblk_block *pblk_get_rblk(struct pblk_lun *rlun,
								int blk_id)
{
	struct pblk *pblk = rlun->pblk;
	int lun_blk = blk_id % pblk->dev->blks_per_lun;

	return &rlun->blocks[lun_blk];
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

static inline int request_intersects(struct pblk_l2p_upd_ctx *r,
				sector_t laddr_start, sector_t laddr_end)
{
	return (laddr_end >= r->l_start) && (laddr_start <= r->l_end);
}

static int __pblk_lock_laddr(struct pblk *pblk, sector_t laddr,
				unsigned pages, struct pblk_l2p_upd_ctx *r)
{
	sector_t laddr_end = laddr + pages - 1;
	struct pblk_l2p_upd_ctx *rtmp;

	spin_lock(&pblk->l2p_locks.lock);
	list_for_each_entry(rtmp, &pblk->l2p_locks.lock_list, list) {
		if (unlikely(request_intersects(rtmp, laddr, laddr_end))) {
			/* existing, overlapping request, come back later */
			spin_unlock(&pblk->l2p_locks.lock);
			return 1;
		}
	}

	r->l_start = laddr;
	r->l_end = laddr_end;

	list_add_tail(&r->list, &pblk->l2p_locks.lock_list);
	spin_unlock(&pblk->l2p_locks.lock);
	return 0;
}

static inline int pblk_lock_laddr(struct pblk *pblk, sector_t laddr,
				unsigned pages,
				struct pblk_l2p_upd_ctx *r)
{
	BUG_ON((laddr + pages) > pblk->nr_sects);

	return __pblk_lock_laddr(pblk, laddr, pages, r);
}

static inline int pblk_lock_rq(struct pblk *pblk, struct bio *bio,
					struct pblk_l2p_upd_ctx *l2p_ctx)
{
	sector_t laddr = pblk_get_laddr(bio);
	unsigned int pages = pblk_get_pages(bio);

	return pblk_lock_laddr(pblk, laddr, pages, l2p_ctx);
}

static inline void pblk_unlock_laddr(struct pblk *pblk,
						struct pblk_l2p_upd_ctx *r)
{
	spin_lock(&pblk->l2p_locks.lock);
	list_del_init(&r->list);
	spin_unlock(&pblk->l2p_locks.lock);
}

static inline void pblk_unlock_rq(struct pblk *pblk, struct bio *bio,
					struct pblk_l2p_upd_ctx *l2p_ctx)
{
	unsigned int nr_pages = pblk_get_pages(bio);

	BUG_ON((l2p_ctx->l_start + nr_pages) > pblk->nr_sects);

	pblk_unlock_laddr(pblk, l2p_ctx);
}

#endif /* PBLK_H_ */
