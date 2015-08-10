#ifndef _NBA_H_
#define _NBA_H_

#include <linux/blkdev.h>
#include <linux/blk-mq.h>
#include <linux/bio.h>
#include <linux/module.h>
#include <linux/kthread.h>
#include <linux/vmalloc.h>

#include <linux/lightnvm.h>
#include "nba_debug.h"

struct nba_lun;

struct nba {
	struct nvm_tgt_instance instance;

	unsigned long nr_pages;
	unsigned long total_blocks;
	unsigned long nr_luns;

	struct nba_lun *luns;

	mempool_t *rq_pool;

	struct nvm_dev *dev;
	struct gendisk *disk;
};


struct nba_lun {
	struct nba *nba;

	struct nvm_lun	*parent;
	struct nvm_block	*blocks;

	unsigned long nr_blocks;
};

struct nba_block {
	unsigned long lun;

	sector_t phys_addr;

	unsigned long id;

	void *internals;
};

struct nba_channel {
	unsigned long int lun_idx;
	unsigned short int chnl_idx;

	unsigned int gran_write;
	unsigned int gran_read;
	unsigned int gran_erase;
};

/* TODO: Define commands with meaningful ids */
#define NVM_BLOCK_PUT		21525
#define NVM_BLOCK_GET_NEXT	21526
#define NVM_BLOCK_GET_BY_ADDR	21531
#define NVM_BLOCK_GET_BY_ID	21532
#define NVM_LUNS_NR_GET		21527
#define NVM_BLOCKS_NR_GET	21528
#define NVM_BLOCK_ERASE		21529
#define NVM_PAGES_NR_GET	21530
#define NVM_PAGE_SIZE_GET	21533
#define NVM_CHANNELS_NR_GET	21534

#define NVM_DEVSECTSIZE_GET	21535
#define NVM_DEVMAXSECT_GET	21536

#endif
