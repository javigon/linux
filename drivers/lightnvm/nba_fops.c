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

static int nba_ioctl(struct block_device *bdev, fmode_t mode, unsigned int cmd,
                     unsigned long arg)
{
	struct nba		*api;

	struct nvm_block    *block;
	struct nvm_dev      *process_dev;
	struct nvm_lun	*lun;
	struct nvm_id_chnl  *process_chnl;

	struct nba_lun      *nba_lun;
	struct nba_block    *nba_block;
	struct nba_channel	*process_nba_channel;


	unsigned long temp_long;

	if(bdev == NULL ||
	    bdev->bd_disk == NULL ||
	    bdev->bd_disk->private_data == NULL) {
		NBA_PRINT("device is not lightnvm device");
		return -EINVAL;
	}

	if(arg == 0) {
		return -EINVAL;
	}

	api = (struct nba *)bdev->bd_disk->private_data;

	switch(cmd) {
	//puts a block to storage
	//input is a nba_block
	case NVMBLOCKPUT: {
		nba_block = (struct nba_block*)arg;
		block = nba_block->internals;

		nvm_put_blk(api->dev, block);
	}
	return 0;

	//erases a block arg is a nba_block
	case NVMBLOCKERASE: {
		nba_block = (struct nba_block *)arg;
		block = (struct nvm_block *)nba_block->internals;

		nvm_erase_blk(api->dev, block);
		nvm_put_blk(api->dev, block);
	}
	return 0;

	//gets a block from a specified id on array
	//input is a nba_block
	case NVMBLOCKGETBYID: {
		nba_block = (struct nba_block *)arg;

		if(nba_block->lun >= api->nr_luns) {
			NBA_PRINT("out of bounds");
			return -EINVAL;
		}

		nba_lun = &api->luns[nba_block->lun];

		lun = nba_lun->parent;

		if(nba_block->id >= nba_lun->nr_blocks) {
			NBA_PRINT("out of bounds");
			return -EINVAL;
		}

		block = &nba_lun->blocks[nba_block->id];

		nba_block->phys_addr = lun->nr_pages_per_blk * nba_block->id;
		nba_block->internals = block;
	}
	return 0;

	//gets a block from a specified address on flash
	//input is a nba_block
	case NVMBLOCKGETBYADDR: {
		nba_block = (struct nba_block *)arg;

		if(nba_block->lun >= api->nr_luns) {
			NBA_PRINT("out of bounds");
			return -EINVAL;
		}

		nba_lun = &api->luns[nba_block->lun];

		lun = nba_lun->parent;

		temp_long = nba_block->phys_addr / lun->nr_pages_per_blk;

		if(temp_long >= nba_lun->nr_blocks) {
			NBA_PRINT("out of bounds");
			return -EINVAL;
		}

		block = &nba_lun->blocks[temp_long];

		nba_block->id = block->id;
		nba_block->internals = block;
	}
	return 0;

	//gets the next free block from lightnvm's list
	case NVMBLOCKRRGET: {
		nba_block = (struct nba_block *)arg;

		if(nba_block->lun >= api->nr_luns) {
			NBA_PRINT("out of bounds");
			return -EINVAL;
		}

		nba_lun = &api->luns[nba_block->lun];

		block = nvm_get_blk(api->dev, nba_lun->parent, 0);

		nba_block->id = block->id;
		nba_block->internals = block;
	}
	return 0;

	//returns number of luns in API
	case NVMLUNSNRGET: {
		(*(unsigned long *)arg) = api->nr_luns;
	}
	return 0;

	//returns number of blocks in lun index *arg
	case NVMBLOCKSNRGET: {
		temp_long = *(unsigned long *)arg;

		if(temp_long >= api->nr_luns) {
			NBA_PRINT("out of bounds");
			return -EINVAL;
		}

		(*(unsigned long *)arg) = api->luns[temp_long].nr_blocks;
	}
	return 0;

	//returns nr of pages for block
	//arg is lun index
	case NVMPAGESNRGET: {
		temp_long = *(unsigned long *)arg;

		if(temp_long >= api->nr_luns) {
			NBA_PRINT("out of bounds");
			return -EINVAL;
		}

		nba_lun = &api->luns[temp_long];

		lun = nba_lun->parent;

		(*(unsigned long *)arg) = lun->nr_pages_per_blk;
	}
	return 0;

	//returns nr of channels for lun
	//arg is lun index
	case NVMCHANNELSNRGET: {
		temp_long = *(unsigned long *)arg;

		if(temp_long >= api->nr_luns) {
			NBA_PRINT("out of bounds");
			return -EINVAL;
		}

		nba_lun = &api->luns[temp_long];

		process_dev = nba_lun->parent->dev;

		(*(unsigned long *)arg) = process_dev->identity.nchannels;
	}
	return 0;

	//gets the page size
	//arg is a long (lun index)
	case NVMPAGESIZEGET: {
		process_nba_channel = (struct nba_channel *)arg;

		if(process_nba_channel->lun_idx >= api->nr_luns) {
			NBA_PRINT("out of bounds");
			return -EINVAL;
		}

		nba_lun = &api->luns[process_nba_channel->lun_idx];

		process_dev = nba_lun->parent->dev;

		if(process_nba_channel->chnl_idx >= process_dev->identity.nchannels) {
			NBA_PRINT("out of bounds");
			return -EINVAL;
		}

		process_chnl = &process_dev->identity.chnls[process_nba_channel->chnl_idx];

		process_nba_channel->gran_write = process_chnl->gran_write;
		process_nba_channel->gran_read = process_chnl->gran_read;
		process_nba_channel->gran_erase = process_chnl->gran_erase;
	}
	return 0;

	default: {
		NBA_PRINT("unknown command");
	}
	return -EINVAL;
	}
}

static int nba_compat_ioctl(struct block_device *bdev, fmode_t mode,
                            unsigned int cmd, unsigned long arg)
{
	return 0;
}

static int nba_open(struct block_device *bdev, fmode_t mode)
{
	return nba_check_device(bdev);
}

static void nba_release(struct gendisk *disk, fmode_t mode)
{
	return;
}

const struct block_device_operations nba_fops = {
	.owner		= THIS_MODULE,
	.ioctl		= nba_ioctl,
	.compat_ioctl	= nba_compat_ioctl,
	.open		= nba_open,
	.release	= nba_release,
};
