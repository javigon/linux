#include <linux/blkdev.h>
#include <linux/blk-mq.h>
#include <linux/bio.h>
#include <linux/module.h>
#include <linux/kthread.h>
#include <linux/compat.h>
#include <linux/vmalloc.h>

#include <linux/lightnvm.h>

#include "nba.h"

/*
 * TODO: move .ioctl to .unlocked_ioctl and implement locking within the module
 */

static DEFINE_SPINLOCK(dev_list_lock);

static int nba_check_device(struct block_device *bdev)
{
	struct nba *nb;
	int ret = 0;

	/* TODO: kref?*/
	spin_lock(&dev_list_lock);
	nb = bdev->bd_disk->private_data;
	if (!nb)
		ret = -ENXIO;
	spin_unlock(&dev_list_lock);

	return ret;
}

static int nba_block_put(struct nba *nba, struct nba_block __user *u_nba_b)
{
	struct nba_block nba_block;
	struct nvm_block *block;

	if (copy_from_user(&nba_block, u_nba_b, sizeof(nba_block)))
		return -EFAULT;

	block = nba_block.internals;
	nvm_put_blk(nba->dev, block);

	return 0;
}

/* Get next block from LIGHTNVM's BM free block list */
static int nba_block_get_next(struct nba *nba, struct nba_block __user *u_nba_b)
{
	struct nba_block nba_block;
	struct nba_lun *nba_lun;
	struct nvm_block *block;

	if (copy_from_user(&nba_block, u_nba_b, sizeof(nba_block)))
		return -EFAULT;

	if (nba_block.lun >= nba->nr_luns)
		return -EINVAL;

	nba_lun = &nba->luns[nba_block.lun];

	block = nvm_get_blk(nba->dev, nba_lun->parent, 0);

	nba_block.id = block->id;
	nba_block.internals = block;

	if (copy_to_user(u_nba_b, &nba_block, sizeof(nba_block)))
		return -EFAULT;

	return 0;
}

static int nba_block_get_by_id(struct nba *nba, struct nba_block __user *u_nba_b)
{
	struct nba_block nba_block;
	struct nba_lun *nba_lun;
	struct nvm_block *block;
	struct nvm_lun *lun;

	if (copy_from_user(&nba_block, u_nba_b, sizeof(nba_block)))
		return -EFAULT;

	if (nba_block.lun >= nba->nr_luns)
		return -EINVAL;

	nba_lun = &nba->luns[nba_block.lun];
	if (nba_block.id >= nba_lun->nr_blocks)
		return -EINVAL;

	lun = nba_lun->parent;
	block = &nba_lun->blocks[nba_block.id];

	nba_block.phys_addr = lun->nr_pages_per_blk * nba_block.id;
	nba_block.internals = block;

	if (copy_to_user(u_nba_b, &nba_block, sizeof(nba_block)))
		return -EFAULT;

	return 0;
}

static int nba_block_get_by_addr(struct nba *nba,
					struct nba_block __user *u_nba_b)
{
	struct nba_block nba_block;
	struct nba_lun *nba_lun;
	struct nvm_block *block;
	struct nvm_lun *lun;
	unsigned long block_nr;

	if (copy_from_user(&nba_block, u_nba_b, sizeof(nba_block)))
		return -EFAULT;

	if (nba_block.lun >= nba->nr_luns)
		return -EINVAL;

	nba_lun = &nba->luns[nba_block.lun];
	lun = nba_lun->parent;

	block_nr = nba_block.phys_addr / lun->nr_pages_per_blk;
	if (block_nr >= nba_lun->nr_blocks)
		return -EINVAL;

	block = &nba_lun->blocks[block_nr];

	nba_block.id = block->id;
	nba_block.internals = block;

	if (copy_to_user(u_nba_b, &nba_block, sizeof(nba_block)))
		return -EFAULT;

	return 0;
}

static int nba_block_erase(struct nba *nba, struct nba_block __user *u_nba_b)
{
	struct nba_block nba_block;
	struct nvm_block *block;

	if (copy_from_user(&nba_block, u_nba_b, sizeof(nba_block)))
		return -EFAULT;

	block = nba_block.internals;
	nvm_erase_blk(nba->dev, block);
	nvm_put_blk(nba->dev, block);

	return 0;
}

static int nba_nluns_get(struct nba *nba, struct nba_block __user *u_nba_b)
{
	if (copy_to_user(u_nba_b, &nba->nr_luns, sizeof(nba->nr_luns)))
			return -EFAULT;

	return 0;
}

static int nba_nblocks_in_lun(struct nba *nba, struct nba_block __user *u_nba_b)
{
	unsigned long lun_id, nblocks;

	if (copy_from_user(&lun_id, u_nba_b, sizeof(lun_id)))
		return -EFAULT;

	if(lun_id >= nba->nr_luns)
		return -EINVAL;

	nblocks = nba->luns[lun_id].nr_blocks;

	if (copy_to_user(u_nba_b, &nblocks, sizeof(nblocks)))
		return -EFAULT;

	return 0;
}

static int nba_pages_per_block(struct nba *nba, struct nba_block __user *u_nba_b)
{
	struct nba_lun *nba_lun;
	struct nvm_lun *lun;
	unsigned long lun_id;

	if (copy_from_user(&lun_id, u_nba_b, sizeof(lun_id)))
		return -EFAULT;

	if(lun_id >= nba->nr_luns)
		return -EINVAL;

	nba_lun = &nba->luns[lun_id];
	lun = nba_lun->parent;

	if (copy_to_user(u_nba_b, &lun->nr_pages_per_blk,
						sizeof(lun->nr_pages_per_blk)))
		return -EFAULT;

	return 0;
}

static int nba_nchannels(struct nba *nba, struct nba_block __user *u_nba_b)
{
	struct nba_lun *nba_lun;
	struct nvm_dev *dev;
	unsigned long lun_id;

	if (copy_from_user(&lun_id, u_nba_b, sizeof(lun_id)))
		return -EFAULT;

	if(lun_id >= nba->nr_luns)
		return -EINVAL;

	nba_lun = &nba->luns[lun_id];
	dev = nba_lun->parent->dev;

	if (copy_to_user(u_nba_b, &dev->identity.nchannels,
						sizeof(dev->identity.nchannels)))
		return -EFAULT;

	return 0;
}

static int nba_page_size(struct nba *nba, struct nba_block __user *u_nba_b)
{
	struct nba_channel nba_channel;
	struct nba_lun *nba_lun;
	struct nvm_id_chnl *channel;
	struct nvm_dev *dev;

	if (copy_from_user(&nba_channel, u_nba_b, sizeof(nba_channel)))
		return -EFAULT;

	if(nba_channel.lun_idx >= nba->nr_luns)
		return -EINVAL;

	nba_lun = &nba->luns[nba_channel.lun_idx];

	dev = nba_lun->parent->dev;
	if(nba_channel.chnl_idx >= dev->identity.nchannels)
		return -EINVAL;

	channel = &dev->identity.chnls[nba_channel.chnl_idx];

	nba_channel.gran_write = channel->gran_write;
	nba_channel.gran_read = channel->gran_read;
	nba_channel.gran_erase = channel->gran_erase;

	if (copy_to_user(u_nba_b, &nba_channel, sizeof(nba_channel)))
		return -EFAULT;

	return 0;
}

static int nba_compat_put_uint(unsigned long arg, unsigned int val)
{
	return put_user(val, (compat_int_t __user *)compat_ptr(arg));
}

static int nba_ioctl(struct block_device *bdev, fmode_t mode, unsigned int cmd,
							unsigned long arg)
{
	struct nba *nba = bdev->bd_disk->private_data;

	switch(cmd) {
	case NVM_BLOCK_PUT:
		return nba_block_put(nba, (void __user*)arg);
	case NVM_BLOCK_GET_NEXT:
		return nba_block_get_next(nba, (void __user*)arg);
	case NVM_BLOCK_GET_BY_ID:
		return nba_block_get_by_id(nba, (void __user*)arg);
	case NVM_BLOCK_GET_BY_ADDR:
		return nba_block_get_by_addr(nba, (void __user*)arg);
	case NVM_BLOCK_ERASE:
		return nba_block_erase(nba, (void __user*)arg);
	case NVM_LUNS_NR_GET:
		return nba_nluns_get(nba, (void __user*)arg);
	case NVM_BLOCKS_NR_GET:
		return nba_nblocks_in_lun(nba, (void __user*)arg);
	case NVM_PAGES_NR_GET:
		return nba_pages_per_block(nba, (void __user*)arg);
	case NVM_CHANNELS_NR_GET:
		return nba_nchannels(nba, (void __user*)arg);
	case NVM_PAGE_SIZE_GET:
		return nba_page_size(nba, (void __user*)arg);
	case NVM_DEVSECTSIZE_GET:
		return nba_compat_put_uint(arg, nvm_dev_sector_size(nba->dev));
	case NVM_DEVMAXSECT_GET:
		return nba_compat_put_uint(arg, nvm_dev_max_sectors(nba->dev));
	default:
		return -ENOTTY;
	}
}

static int nba_open(struct block_device *bdev, fmode_t mode)
{
	return nba_check_device(bdev);
}

static void nba_release(struct gendisk *disk, fmode_t mode)
{
}

const struct block_device_operations nba_fops = {
	.owner		= THIS_MODULE,
	.ioctl		= nba_ioctl,
	.open		= nba_open,
	.release	= nba_release,
};
