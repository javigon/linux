/*
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
 * pblk-rl.c - pblk's rate limiter for user I/O
 */

#include "pblk.h"

static inline bool __pblk_rl_rate_user_rb(struct pblk *pblk, int nr_entries)
{
	struct pblk_prov *rl = &pblk->rl;

	spin_lock(&rl->lock);
	if (rl->rb_user_cnt + nr_entries > rl->rb_user_max) {
		spin_unlock(&rl->lock);
		return false;
	}

	rl->rb_user_cnt += nr_entries;
	spin_unlock(&rl->lock);

	return true;
}

void pblk_rl_user_in(struct pblk *pblk, int nr_entries)
{
	DEFINE_WAIT(wait);

	if (__pblk_rl_rate_user_rb(pblk, nr_entries))
		return;

	do {
		prepare_to_wait_exclusive(&pblk->wait, &wait,
						TASK_UNINTERRUPTIBLE);

		if (__pblk_rl_rate_user_rb(pblk, nr_entries))
			break;

		io_schedule();
	} while (1);

	finish_wait(&pblk->wait, &wait);
}

void pblk_rl_user_out(struct pblk *pblk, int nr_entries)
{
	struct pblk_prov *rl = &pblk->rl;

	spin_lock(&rl->lock);
	rl->rb_user_cnt -= nr_entries;
	WARN_ON(rl->rb_user_cnt < 0);
	spin_unlock(&rl->lock);

	/* Kick user I/O rate limiter queue if waiting */
	if (waitqueue_active(&pblk->wait))
		wake_up_all(&pblk->wait);
}

/*
 * We check for (i) the number of free blocks in the current LUN and (ii) the
 * total number of free blocks in the pblk instance. This is to even out the
 * number of free blocks on each LUN when GC kicks in.
 *
 * Only the total number of free blocks is used to configure the rate limiter.
 */
static void pblk_rl_update_rates(struct pblk *pblk, struct pblk_lun *rlun)
{
	struct pblk_prov *rl = &pblk->rl;
	unsigned long rwb_size = pblk_rb_nr_entries(&pblk->rwb);
	int should_start_gc = 0, should_stop_gc = 0;
	unsigned int high = 1 << rl->high_pw;
	unsigned int low = 1 << rl->low_pw;

#ifdef CONFIG_NVM_DEBUG
	lockdep_assert_held(&rl->lock);
#endif

	if (rlun->nr_free_blocks > rl->high_lun)
		should_stop_gc = 1;
	else if (rlun->nr_free_blocks < rl->low_lun)
		should_start_gc = 1;

	if (rl->free_blocks >= high) {
		rl->rb_user_max = rwb_size;
		should_stop_gc = 1;
	} else if (rl->free_blocks > low && rl->free_blocks < high) {
		int shift = rl->high_pw - rl->rb_windows_pw;
		int user_windows = rl->free_blocks >> shift;

		rl->rb_user_max = user_windows << PBLK_MAX_REQ_ADDRS_PW;
		should_start_gc = 1;
	} else {
		rl->rb_user_max = 0;
		should_start_gc = 1;
	}

	if (should_start_gc)
		pblk_gc_should_start(pblk);
	else if (should_stop_gc)
		pblk_gc_should_stop(pblk);
}

void pblk_rl_free_blks_inc(struct pblk *pblk, struct pblk_lun *rlun)
{
#ifdef CONFIG_NVM_DEBUG
	lockdep_assert_held(&rlun->lock);
#endif

	rlun->nr_free_blocks++;

	spin_lock(&pblk->rl.lock);
	pblk->rl.free_blocks++;
	pblk_rl_update_rates(pblk, rlun);
	spin_unlock(&pblk->rl.lock);
}

void pblk_rl_free_blks_dec(struct pblk *pblk, struct pblk_lun *rlun)
{
#ifdef CONFIG_NVM_DEBUG
	lockdep_assert_held(&rlun->lock);
#endif

	rlun->nr_free_blocks--;

	spin_lock(&pblk->rl.lock);
	pblk->rl.free_blocks--;
	pblk_rl_update_rates(pblk, rlun);
	spin_unlock(&pblk->rl.lock);
}

int pblk_rl_gc_thrs(struct pblk *pblk)
{
	return pblk->rl.high_lun + 1;
}

int pblk_rl_sysfs_rate_show(struct pblk *pblk)
{
	return pblk->rl.rb_user_max;
}

int pblk_rl_sysfs_rate_store(struct pblk *pblk, int value)
{
	pblk->rl.rb_user_max = value;

	return 0;
}

/* TODO: Update values correctly on power up recovery */
void pblk_rl_init(struct pblk *pblk)
{
	struct nvm_tgt_dev *dev = pblk->dev;
	struct nvm_geo *geo = &dev->geo;
	struct pblk_prov *rl = &pblk->rl;
	unsigned int rb_windows;

	rl->free_blocks = pblk_nr_free_blks(pblk);

	rl->high_pw = get_count_order(rl->total_blocks / PBLK_USER_HIGH_THRS);
	rl->low_pw = get_count_order(rl->total_blocks / PBLK_USER_LOW_THRS);
	rl->high_lun = geo->blks_per_lun / PBLK_USER_HIGH_THRS;
	rl->low_lun = geo->blks_per_lun / PBLK_USER_LOW_THRS;
	if (rl->low_lun < 3)
		rl->low_lun = 3;

	/* This will always be a power-of-2 */
	rb_windows = pblk_rb_nr_entries(&pblk->rwb) / PBLK_MAX_REQ_ADDRS;
	rl->rb_windows_pw = get_count_order(rb_windows);

	/* To start with, all buffer is available to user I/O writers */
	rl->rb_user_max = pblk_rb_nr_entries(&pblk->rwb);
	rl->rb_user_cnt = 0;

	spin_lock_init(&rl->lock);
}

