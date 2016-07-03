/*
 * Copyright: Matias Bjorling <mb@bjorling.me>
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
 */

#ifndef GENNVM_H_
#define GENNVM_H_

#include <linux/module.h>
#include <linux/vmalloc.h>

#include <linux/lightnvm.h>

struct gen_lun {
	struct nvm_lun vlun;

	/* A LUN can either be managed by the media manager if it is shared
	 * among several used through the generic get/put block interface or
	 * exclusively owned by a target. In this case, the target manages
	 * the LUN. gen_lun always maintains a reference to the LUN management.
	 *
	 * Exclusive access is managed by the dev->lun_map bitmask. 0:
	 * non-exclusive, 1: exclusive.
	 */
	struct nvm_lun_mgmt *mgmt;
	struct nvm_target *tgt;
};

struct gen_dev {
	struct nvm_dev *dev;

	int nr_luns;
	struct gen_lun *luns;
	struct list_head area_list;

	struct mutex lock;
	struct list_head targets;
};

struct gen_area {
	struct list_head list;
	sector_t begin;
	sector_t end;	/* end is excluded */
};

#define gen_for_each_lun(bm, lun, i) \
		for ((i) = 0, lun = &(bm)->luns[0]; \
			(i) < (bm)->nr_luns; (i)++, lun = &(bm)->luns[(i)])

#endif /* GENNVM_H_ */
