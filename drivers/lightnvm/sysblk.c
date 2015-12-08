/*
 * Copyright (C) 2015 Matias Bjorling. All rights reserved.
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

#include <linux/lightnvm.h>

#define MAX_SYSBLKS 3	/* remember to update mapping scheme on change */
#define MAX_BLKS_PR_SYSBLK 2 /* 2 blks with 256 pages and 3000 erases
			      * enables ~1.5M updates per sysblk unit */

struct sysblk_scan {
	int nr_rows;
	int nr_ppas;
	/* A row is a collection of flash blocks for a system block. */
	int row;
	struct ppa_addr ppas[MAX_SYSBLKS * MAX_BLKS_PR_SYSBLK];/* all sysblks */
};

static inline int scan_ppa_idx(struct sysblk_scan *s, int row, int blkid)
{
	return (row * s->nr_rows) + blkid;
}

static int nvm_setup_sysblks(struct nvm_dev *dev, struct ppa_addr *sysblk_ppa)
{
	int nr_rows = min_t(int, MAX_SYSBLKS, dev->nr_chnls);
	int i;

	for (i = 0; i < nr_rows; i++)
		sysblk_ppa[i].ppa = 0;

	/* if possible, place sysblk at first channel, middle channel and last
	 * channel of the device. If not, create only one or two sys blocks */
	switch (dev->nr_chnls) {
		case 2:
			sysblk_ppa[1].g.ch = 1;
			/* fall-through */
		case 1:
			sysblk_ppa[0].g.ch = 0;
			break;
		default:
			sysblk_ppa[0].g.ch = 0;
			sysblk_ppa[1].g.ch = dev->nr_chnls / 2;
			sysblk_ppa[2].g.ch = dev->nr_chnls - 1;
			break;
	}

	return nr_rows;
}

static int sysblk_get_host_blks(struct ppa_addr ppa, int nr_blks, u8 *blks,
								void *private)
{
	struct sysblk_scan *s = private;
	int i, nr_sysblk = 0;

	for (i = 0; i < nr_blks; i++) {
		if (blks[i] != NVM_BLK_T_HOST)
			continue;

		if (s->nr_ppas == MAX_BLKS_PR_SYSBLK * MAX_SYSBLKS) {
			pr_err("nvm: too many host blks\n");
			return -EINVAL;
		}

		ppa.g.blk = i;

		s->ppas[scan_ppa_idx(s, s->row, nr_sysblk)].ppa = ppa.ppa;
		s->nr_ppas++;
		nr_sysblk++;
	}

	return 0;
}

static int nvm_get_all_sysblks(struct nvm_dev *dev, struct ppa_addr *ppas,
				int nr_ppas, struct sysblk_scan *s)
{
	struct ppa_addr dev_ppa;
	int i, ret;

	s->nr_ppas = 0;
	s->nr_rows = nr_ppas;

	for (i = 0; i < nr_ppas; i++) {
		dev_ppa = generic_to_dev_addr(dev, ppas[i]);
		s->row = i;

		ret = dev->ops->get_bb_tbl(dev, dev_ppa, dev->blks_per_lun,
						sysblk_get_host_blks, s);
		if (ret) {
			pr_err("nvm: failed bb tbl for ch%u lun%u\n",
								ppas[i].g.ch,
								ppas[i].g.blk);
			return ret;
		}
	}

	return ret;
}

/*
 * scans a block for latest sysblk.
 * Returns:
 *	0 - newer sysblk not found. PPA is updated to latest page.
 *	1 - newer sysblk found and stored in *cur. PPA is updated to
 *	    next valid page.
 *	<0- error.
 */
static int nvm_scan_block(struct nvm_dev *dev, struct ppa_addr *ppa,
							struct nvm_sysblk *sblk)
{
	struct nvm_sysblk *cur;
	int pg, cursz, ret, found = 0;

	/* the full buffer for a flash page is allocated. Only the first of it
	 * contains the system block information */
	cursz = dev->sec_size * dev->sec_per_pg * dev->nr_planes;
	cur = kmalloc(cursz, GFP_KERNEL);
	if (!cur)
		return -ENOMEM;

	/* perform linear scan through the block */
	for (pg = 0; pg < dev->pgs_per_blk; pg++) {
		ppa->g.pg = pg;

		ret = nvm_submit_ppa(dev, *ppa, NVM_OP_PREAD, cur, cursz);
		if (ret)
			break; /* if we can't read it, continue to the
				* next blk */

		if (strncmp(cur->header, "SYSBLOCK", 8) != 0)
			break; /* last valid page already iterated */

		if (cur->seqnr > sblk->seqnr)
			memcpy(sblk, cur, sizeof(struct nvm_sysblk));

		found = 1;
	}

	kfree(cur);

	return found;
}

int nvm_get_sysblock(struct nvm_dev *dev, struct nvm_sysblk *sblk)
{
	struct ppa_addr sysblk_ppa[MAX_SYSBLKS];
	struct sysblk_scan s;
	struct nvm_sysblk *cur;
	int i, j, rows, found;
	int ret = -ENOMEM;

	/* 1. get bad block list
	 * 2. filter on host-specific (type 3)
	 * 3. iterate through all and find the highest seq nr.
	 * 4. return superblock information
	 */

	if (!dev->ops->get_bb_tbl)
		return -EINVAL;

	rows = nvm_setup_sysblks(dev, sysblk_ppa);

	mutex_lock(&dev->mlock);
	ret = nvm_get_all_sysblks(dev, sysblk_ppa, rows, &s);
	if (ret)
		goto err_sysblk;

	cur = kzalloc(sizeof(struct nvm_sysblk), GFP_KERNEL);
	if (!cur)
		goto err_sysblk;

	/* find the latest block across all sysblocks */
	for (i = 0; i < MAX_SYSBLKS; i++) {
		for (j = 0; j < MAX_BLKS_PR_SYSBLK; j++) {
			struct ppa_addr ppa = s.ppas[scan_ppa_idx(&s, i, j)];

			ret = nvm_scan_block(dev, &ppa, cur);
			if (ret > 0)
				found = 1;
			else if (ret < 0)
				break;
		}
	}

	kfree(cur);
err_sysblk:
	mutex_unlock(&dev->mlock);

	if (found)
		return 0;
	return ret;
}

int nvm_update_sysblock(struct nvm_dev *dev, struct nvm_sysblk *new)
{
	/* 1. for each latest superblock on lun0, lun1/2, lunX
	 * 2. if room
	 *    a. write new flash page entry with the updated information
	 * 3. if no room
	 *    a. find next available block on lun (linear search)
	 *       if none, continue to next lun
	 *       if none at all, report error. also report that it wasn't
	 *       possible to write to all superblocks.
	 *    b. mark block type 3
	 *    c. write data to block.
	 */
	struct ppa_addr sysblk_ppa[MAX_SYSBLKS];
	struct sysblk_scan s;
	struct nvm_sysblk *cur;
	int i, j, found, rows;
	int ret = -ENOMEM;

	if (!dev->ops->get_bb_tbl)
		return -EINVAL;

	rows = nvm_setup_sysblks(dev, sysblk_ppa);

	mutex_lock(&dev->mlock);
	ret = nvm_get_all_sysblks(dev, sysblk_ppa, rows, &s);
	if (ret)
		goto err_sysblk;

	cur = kzalloc(sizeof(struct nvm_sysblk) * MAX_SYSBLKS, GFP_KERNEL);
	if (!cur)
		goto err_sysblk;

	/* Find the latest sysblk for each sysblk channel */
	for (i = 0; i < MAX_SYSBLKS; i++) {
		for (j = 0; j < MAX_BLKS_PR_SYSBLK; j++) {
			found = 0;
			ret = nvm_scan_block(dev,
						&s.ppas[scan_ppa_idx(&s, i, j)],
						&cur[i]);
			if (ret > 0)
				found = 1;
			else if (ret < 0)
			break;
		}
	}

	if (!found) {
		pr_err("nvm: no valid sysblks found to update\n");
		ret = -EINVAL;
		goto err_cur;
	}

	/* All sysblocks found. Check that they are all the same revision and
	 * same page in flash block */
/*	for (i = 1; i < s.nr_ppas; i++) {
		if (cur[0]->seqnr != cur[i]->seqnr ||
				s.ppas[0][0].g.pg != s.ppas[i][0].g.pg) {
			pr_err("nvm: sysblks not coherent.\n");
			ret = -EINVAL;
			goto err_cur;
		}
	}*/

	/* Check that there haven't been another update to the seqnr since we
	 * began */
/*	if ((new->seqnr - 1) != cur[i]->seqnr) {
		pr_err("nvm: seq is not sequential\n");
		ret = -EINVAL;
		goto err_cur;
	}*/

	/* prepare to write new sysblk.
	 * First case is that we can continue to write to the same sysblocks
	 * allocated.
	 * Second case is that the current sysblks have been fully written and
	 * new ones must be allocated.
	 */
	//if (sysblks.ppas[0].g.pg == dev->pgs_per_blk)
	//	nvm_allocate_new_sysblks(dev, sysblocks);

	//nvm_write_sysblk(dev, new, )
err_cur:
	kfree(cur);
err_sysblk:
	mutex_unlock(&dev->mlock);

	return ret;
}

static int sysblk_get_free_blks(struct ppa_addr ppa, int nr_blks, u8 *blks,
								void *private)
{
	struct sysblk_scan *s = private;
	int i, blkid = 0;

	for (i = 0; i < nr_blks; i++) {
		if (blks[i] == NVM_BLK_T_HOST) {
			pr_err("nvm: device already initialized\n");
			return -EEXIST;
		}

		if (blks[i] != NVM_BLK_T_FREE)
			continue;

		s->ppas[scan_ppa_idx(s, s->row, blkid)].g.blk = i;
		s->nr_ppas++;
		blkid++;

		if (blkid > MAX_BLKS_PR_SYSBLK - 1)
			return 0;
	}

	return -EINVAL;
}

static int nvm_mark_all_sysblks(struct nvm_dev *dev, struct ppa_addr *ppas,
								int nr_ppas)
{
	struct nvm_rq rqd;
	struct ppa_addr dev_ppa;
	struct sysblk_scan s;

	int i, ret;

	for (i = 0; i < nr_ppas; i++) {
		dev_ppa = generic_to_dev_addr(dev, ppas[i]);

		s.row = i;
		ret = dev->ops->get_bb_tbl(dev, dev_ppa, dev->blks_per_lun,
						sysblk_get_free_blks, &s);
		if (ret) {
			pr_err("nvm: sysblk failed bb tbl for ch%u lun%u\n",
								ppas[i].g.ch,
								ppas[i].g.blk);
			return -EINVAL;
		}
	}

	if (s.nr_ppas > dev->ops->max_phys_sect) {
		pr_err("nvm: unable to update all sysblocks atomically\n");
		return -EINVAL;
	}

	memset(&rqd, 0, sizeof(struct nvm_rq));

	/* FIXME: Make a ppa list to be sent off to the device */
	nvm_set_rqd_ppalist(dev, &rqd, s.ppas, s.nr_ppas);

	ret = dev->ops->set_bb_tbl(dev->q, &rqd, NVM_BLK_T_HOST);
	nvm_free_rqd_ppalist(dev, &rqd);
	if (ret) {
		pr_err("nvm: sysblk failed bb mark\n");
		return -EINVAL;
	}

	return 0;
}

int nvm_init_sysblock(struct nvm_dev *dev, struct nvm_sysblk *sblk)
{
	struct ppa_addr sysblk_ppa[MAX_SYSBLKS];
	struct sysblk_scan s;
	void *buf;
	int i, ret, bufsz;
	int rows;

	/* 1. get bad block list
	 * 2. select master block from lun0, lun1/2, lunX -> first available blk
	 *    a. write data to block
	 *    b. mark block type host-based device 
	 */

	if (!dev->ops->get_bb_tbl)
		return -EINVAL;

	bufsz = dev->sec_size * dev->sec_per_pg * dev->nr_planes;
	buf = kmalloc(bufsz, GFP_KERNEL);
	if (!buf)
		return -ENOMEM;
	memcpy(buf, sblk, sizeof(struct nvm_sysblk));

	rows = nvm_setup_sysblks(dev, sysblk_ppa);

	mutex_lock(&dev->mlock);

	/* premark all host system blocks */
	ret = nvm_mark_all_sysblks(dev, sysblk_ppa, rows);
	if (ret)
		goto err_mark;

	/* Write and verify */
	for (i = 0; i < rows; i++) {
		struct ppa_addr ppa;

		ppa.ppa = s.ppas[scan_ppa_idx(&s, i, 0)].ppa;
		ret = nvm_submit_ppa(dev, ppa, NVM_OP_PWRITE, buf, bufsz);
		if (ret) {
			pr_err("nvm: sysblk failed program [ch%u lun%u blk%u]\n",
								ppa.g.ch,
								ppa.g.lun,
								ppa.g.blk);
			break;
		}

		ret = nvm_submit_ppa(dev, ppa, NVM_OP_PREAD, buf, bufsz);
		if (ret) {
			pr_err("nvm: sysblk failed read [ch%u lun%u blk%u]\n",
								ppa.g.ch,
								ppa.g.lun,
								ppa.g.blk);
			break;
		}

		if (memcmp(buf, sblk, sizeof(struct nvm_sysblk))) {
			pr_err("nvm: sysblk failed verify [ch%u lun%u blk%u]\n",
								ppa.g.ch,
								ppa.g.lun,
								ppa.g.blk);
			break;
		}
	}

err_mark:
	mutex_unlock(&dev->mlock);
	kfree(buf);
	return ret;
}
