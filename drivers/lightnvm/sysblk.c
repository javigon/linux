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

#define MAX_HOST_BLKS 8
#define MAX_SYSBLKS 3 /* remember to update mapping scheme if changing */

struct sysblk_scan {
	int nr_ppas;
	struct ppa_addr ppas[MAX_HOST_BLKS];
};

static int sysblk_get_host_blks(struct ppa_addr ppa, int nr_blks, u8 *blks,
								void *private)
{
	struct sysblk_scan *sysblks = private;
	int i;

	for (i = 0; i < nr_blks; i++) {
		if (blks[i] != NVM_BLK_T_HOST)
			continue;

		if (sysblks->nr_ppas == MAX_HOST_BLKS) {
			pr_err("nvm: too many host blks\n");
			return -EINVAL;
		}
		ppa.g.blk = i;

		printk("found blk: %llu\n", ppa.ppa);

		sysblks->ppas[sysblks->nr_ppas].ppa = ppa.ppa;
		sysblks->nr_ppas++;
	}

	return 0;
}

static int nvm_find_all_sysblocks(struct nvm_dev *dev,
						struct sysblk_scan *sysblks)
{
	struct ppa_addr dev_ppa;
	int chnlid, lunid, ret = 0;

	sysblks->nr_ppas = 0;

	for (chnlid = 0; chnlid < dev->nr_chnls; chnlid++) {
		for (lunid = 0; lunid < dev->nr_luns; lunid++) {
			dev_ppa.ppa = 0;
			dev_ppa.g.ch = chnlid;
			dev_ppa.g.lun = lunid;

			dev_ppa = generic_to_dev_addr(dev, dev_ppa);

			ret = dev->ops->get_bb_tbl(dev, dev_ppa,
							dev->blks_per_lun,
							sysblk_get_host_blks,
							sysblks);
			if (ret) {
				dev_ppa = dev_to_generic_addr(dev, dev_ppa);

				pr_err("nvm: failed bb tbl for ch%u lun%u\n",
							dev_ppa.g.ch,
							dev_ppa.g.blk);
				return ret;
			}
		}
	}

	return ret;
}

int nvm_get_sysblock(struct nvm_dev *dev, struct nvm_sysblk *sblk)
{
	struct sysblk_scan sysblks;
	struct nvm_sysblk *sblkcur;
	int i, pg, sblksz, found;
	int ret = 0;
	void *sblkbuf;

	/* 1. get bad block list
	 * 2. filter on host-specific (type 3)
	 * 3. iterate through all and find the highest seq nr.
	 * 4. return superblock information
	 */

	if (!dev->ops->get_bb_tbl)
		return -EINVAL;

	ret = nvm_find_all_sysblocks(dev, &sysblks);
	if (ret)
		return ret;

	sblksz = dev->sec_size * dev->sec_per_pg * dev->nr_planes;
	sblkbuf = kzalloc(sblksz + sizeof(struct nvm_sysblk), GFP_KERNEL);
	if (!sblkbuf)
		return -ENOMEM;
	sblkcur = sblkbuf + sblksz;

	for (i = 0; i < sysblks.nr_ppas; i++) {
		struct ppa_addr ppa = sysblks.ppas[i];

		/* perform linear scan through the block */
		for (pg = 0; pg < dev->pgs_per_blk; pg++) {
			ppa.g.pg = pg;
			ret = nvm_submit_ppa(dev, ppa, NVM_OP_PREAD, sblkbuf,
									sblksz);
			if (ret) {
				break; /* if we can't read it, continue to the
					* next blk */
			}

			memcpy(sblkcur, sblkbuf, sizeof(struct nvm_sysblk));

			if (strcmp(sblkcur->header, "SYSBLOCK") != 0)
				break; /* last valid page already iterated */

			if (sblkcur->seqnr > sblk->seqnr)
				memcpy(sblk, sblkcur,
						sizeof(struct nvm_sysblk));

			printk("wooo\n");
			found = 1;
		}
	}

	if (found)
		return 0;
	return ret;
}

int nvm_update_sysblock(struct nvm_dev *dev, struct nvm_sysblk *sblk)
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
	return 0;
}

static int nvm_place_sysblks(struct nvm_dev *dev, struct ppa_addr *sysblk_ppa)
{
	int nr_sysblks = min_t(int, MAX_SYSBLKS, dev->nr_chnls);
	int i;

	for (i = 0; i < nr_sysblks; i++)
		sysblk_ppa[i].ppa = 0;

	/* if possible, place sysblk at first channel, middle channel and last
	 * channel of the device. If not, create only one or two sys blocks */
	switch (dev->nr_chnls) {
		case 2:
			sysblk_ppa[1].g.ch = 1;
			/* fallthrough */
		case 1:
			sysblk_ppa[0].g.ch = 0;
			break;
		default:
			sysblk_ppa[0].g.ch = 0;
			sysblk_ppa[1].g.ch = dev->nr_chnls / 2;
			sysblk_ppa[2].g.ch = dev->nr_chnls - 1;
			break;
	}

	return nr_sysblks;
}

static int sysblk_find_free_blk(struct ppa_addr ppa, int nr_blks, u8 *blks,
								void *private)
{
	struct ppa_addr *dst_addr = private;
	int i;

	for (i = 0; i < nr_blks; i++) {
		if (blks[i] == NVM_BLK_T_HOST) {
			pr_err("nvm: device already initialized\n");
			return -EEXIST;
		}

		if (blks[i] == NVM_BLK_T_FREE) {
			dst_addr->g.blk = i;
			return 0;
		}
	}

	return -EINVAL;
}

/* FIXME: make sure only one can run at a time */
int nvm_init_sysblock(struct nvm_dev *dev, struct nvm_sysblk *sblk)
{
	struct ppa_addr sysblk_ppa[MAX_SYSBLKS];
	struct nvm_rq rqd;
	void *sblkbuf;
	int i, ret, sblksz;
	int nr_sysblks;
	int success = 0;

	/* 1. get bad block list
	 * 2. select master block from lun0, lun1/2, lunX -> first available blk
	 *    a. write data to block
	 *    b. mark block type host-based device 
	 */

	if (!dev->ops->get_bb_tbl)
		return -EINVAL;

	sblksz = dev->sec_size * dev->sec_per_pg * dev->nr_planes;
	sblkbuf = kzalloc(sblksz, GFP_KERNEL);
	if (!sblkbuf)
		return -ENOMEM;
	memcpy(sblkbuf, sblk, sizeof(struct nvm_sysblk));

	nr_sysblks = nvm_place_sysblks(dev, sysblk_ppa);

	for (i = 0; i < nr_sysblks; i++) {
		struct ppa_addr dev_ppa;

		dev_ppa = generic_to_dev_addr(dev, sysblk_ppa[i]);

		ret = dev->ops->get_bb_tbl(dev, dev_ppa, dev->blks_per_lun,
					sysblk_find_free_blk, &sysblk_ppa[i]);
		if (ret) {
			pr_err("nvm: sysblk failed bb tbl for ch%u lun%u\n",
						sysblk_ppa[i].g.ch,
						sysblk_ppa[i].g.blk);
			break;
		}

		/* set up erase */
		ret = nvm_erase_ppa(dev, sysblk_ppa[i]);
		if (ret) {
			pr_err("nvm: sysblk failed erase [ch%u lun%u blk%u]\n",
						sysblk_ppa[i].g.ch,
						sysblk_ppa[i].g.lun,
						sysblk_ppa[i].g.blk);
			break;
		}

		/* write system block */
		ret = nvm_submit_ppa(dev, sysblk_ppa[i], NVM_OP_PWRITE, sblkbuf,
									sblksz);
		if (ret) {
			pr_err("nvm: sysblk failed program [ch%u lun%u blk%u]\n",
						sysblk_ppa[i].g.ch,
						sysblk_ppa[i].g.lun,
						sysblk_ppa[i].g.blk);
			break;
		}

		/* verify system block */
		ret = nvm_submit_ppa(dev, sysblk_ppa[i], NVM_OP_PREAD,
							sblkbuf, sblksz);
		if (ret) {
			pr_err("nvm: sysblk failed read [ch%u lun%u blk%u]\n",
						sysblk_ppa[i].g.ch,
						sysblk_ppa[i].g.lun,
						sysblk_ppa[i].g.blk);
			break;
		}

		if (memcmp(sblkbuf, sblk, sizeof(struct nvm_sysblk))) {
			pr_err("nvm: sysblk failed read [ch%u lun%u blk%u]\n",
						sysblk_ppa[i].g.ch,
						sysblk_ppa[i].g.lun,
						sysblk_ppa[i].g.blk);
			break;
		}

		success++;
	}

	/* make sure all blocks are marked as system blocks as an atomic
	 * operation. Else the device can be left in a state where it has to be
	 * manually recovered to proceed. */
	if (success == nr_sysblks) {
		memset(&rqd, 0, sizeof(struct nvm_rq));

		nvm_set_rqd_ppalist(dev, &rqd, sysblk_ppa, nr_sysblks);

		ret = dev->ops->set_bb_tbl(dev->q, &rqd, NVM_BLK_T_HOST);
		nvm_free_rqd_ppalist(dev, &rqd);
		if (ret) {
			pr_err("nvm: sysblk failed bb mark for ch%u lun 0\n",
						sysblk_ppa[i].g.ch);
		}
	}

	kfree(sblkbuf);
	return ret;
}
