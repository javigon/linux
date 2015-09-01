#include "nba.h"

static struct kmem_cache *nba_rq_cache;
static DECLARE_RWSEM(nba_lock);
extern const struct block_device_operations nba_fops;

static inline sector_t nba_get_laddr(struct bio *bio)
{
	return bio->bi_iter.bi_sector / NR_PHY_IN_LOG;
}

static int nba_setup_rq(struct nba *nba, struct bio *bio, struct nvm_rq *rqd,
							uint8_t npages)
{
	sector_t laddr = nba_get_laddr(bio);
	int i;

	if (npages > 1) {
		rqd->ppa_list = nvm_alloc_ppalist(nba->dev, GFP_KERNEL,
							&rqd->dma_ppa_list);
		if (!rqd->ppa_list) {
			pr_err("nba: not able to allocate ppa list\n");
			return NVM_IO_ERR;
		}

		for (i = 0; i < npages; i++) {
			BUG_ON(!(laddr + i >= 0 && laddr + i < nba->nr_pages));
			rqd->ppa_list[i] = laddr + i;
		}

		return NVM_IO_OK;
	}

	/* Logic address == physic address */
	rqd->ppa = laddr;

	return NVM_IO_OK;
}

static int nba_submit_io(struct nba *nba, struct bio *bio, struct nvm_rq *rqd)
{
	int err;
	uint8_t npages = nba_get_pages(bio);

	err = nba_setup_rq(nba, bio, rqd, npages);
	if (err)
		return err;

	bio_get(bio);
	rqd->bio = bio;
	rqd->ins = &nba->instance;
	rqd->npages = npages;

	err = nvm_submit_io(nba->dev, rqd);
	if (err) {
		pr_err("rrpc: IO submission failed: %d\n", err);
		return NVM_IO_ERR;
	}

	return NVM_IO_OK;
}

static void nba_make_rq(struct request_queue *q, struct bio *bio)
{
	struct nba *nba;
	struct nvm_rq *rqd;

	if (bio->bi_rw & REQ_DISCARD)
		return;

	nba = q->queuedata;

	rqd = mempool_alloc(nba->rq_pool, GFP_KERNEL);
	if (!rqd) {
		pr_err_ratelimited("nba: not able to queue bio.");
		bio_io_error(bio);
		return;
	}

	switch (nba_submit_io(nba, bio, rqd)) {
	case NVM_IO_OK:
		return;
	case NVM_IO_ERR:
		if (rqd->ppa_list)
			nvm_free_ppalist(nba->dev, rqd->ppa_list,
							rqd->dma_ppa_list);
		bio_io_error(bio);
		break;
	default:
		break;
	}

	mempool_free(rqd, nba->rq_pool);
}

static void nba_end_io(struct nvm_rq *rqd, int error)
{
	struct nba *nba = container_of(rqd->ins, struct nba, instance);
	uint8_t npages = rqd->npages;

	bio_put(rqd->bio);

	if (npages > 1)
		nvm_free_ppalist(nba->dev, rqd->ppa_list, rqd->dma_ppa_list);

	mempool_free(rqd, nba->rq_pool);
}

static sector_t nba_capacity(void *private)
{
	struct nba *nba = private;

	return nba->nr_real_pages * NR_PHY_IN_LOG;
}

static void nba_core_free(struct nba *nba)
{
	if (nba->rq_pool)
		mempool_destroy(nba->rq_pool);
}

static void nba_luns_free(struct nba *nba)
{
	if(nba->luns)
		kfree(nba->luns);
}

static void nba_free(struct nba *nba)
{
	if(nba) {
		nba_core_free(nba);
		nba_luns_free(nba);
		kfree(nba);
	}
}

static int nba_luns_init(struct nba *nba, int lun_begin, int lun_end)
{
	struct nvm_dev *dev = nba->dev;
	struct nvm_lun *luns;
	struct nvm_lun *lun;
	struct nvm_block *block;

	struct nba_lun *rlun;

	unsigned long j;
	unsigned long i;
	int ret = 0;

	luns = dev->bm->get_luns(dev, lun_begin, lun_end);
	if (!luns) {
		return -EINVAL;
	}

	nba->luns = kcalloc(nba->nr_luns, sizeof(struct nba_lun), GFP_KERNEL);
	if(!nba->luns) {
		return -ENOMEM;
	}

	for(i = 0; i < nba->nr_luns; ++i) {
		lun = &luns[i];

		rlun = &nba->luns[i];

		rlun->nba = nba;

		rlun->parent = lun;

		rlun->nr_blocks = lun->nr_available_blocks;
		rlun->nr_free_blocks = lun->nr_available_blocks;

		nba->total_blocks += lun->nr_available_blocks;
		nba->nr_pages += lun->nr_available_blocks * lun->nr_pages_per_blk;
		nba->nr_real_pages += lun->nr_blocks * lun->nr_pages_per_blk;

		//FIXME: This allocation is a momentary fix until we fix the
		//block id issue
		rlun->blocks = vzalloc(sizeof(struct nvm_block) *
								lun->nr_blocks);
		if(!rlun->blocks) {
			ret = -ENOMEM;
			goto out;
		}

		for(j = 0; j < rlun->nr_free_blocks; ++j) {
			block = &rlun->blocks[j];

			/* FIXME */
			/* spin_lock_init(&block->lock); */
			INIT_LIST_HEAD(&block->list);

			/* FIXME */
			/* bitmap_zero(block->invalid_pages, lun->nr_pages_per_blk); */
			/* block->next_page = 0; */
			/* block->nr_invalid_pages = 0; */
			/* atomic_set(&block->data_cmnt_size, 0); */
		}
	}

out:
	return ret;
}

static int nba_core_init(struct nba *nba)
{
	down_write(&nba_lock);
	nba_rq_cache = kmem_cache_create("nba_rq", sizeof(struct nvm_rq), 0, 0,
									NULL);
	if (!nba_rq_cache) {
		up_write(&nba_lock);
		return -ENOMEM;
	}
	up_write(&nba_lock);

	nba->rq_pool = mempool_create_slab_pool(64, nba_rq_cache);
	if (!nba->rq_pool)
		return -ENOMEM;

	return 0;
}

static struct nvm_tgt_type tt_nba;

static void *nba_init(struct nvm_dev *dev, struct gendisk *tdisk, int lun_begin,
								int lun_end)
{
	struct request_queue *bqueue = dev->q;
	struct request_queue *tqueue = tdisk->queue;
	struct nba *nba;
	int ret;

	nba = kzalloc(sizeof(struct nba), GFP_KERNEL);
	if (!nba) {
		ret = -ENOMEM;
		goto err;
	}

	nba->instance.tt = &tt_nba;
	nba->dev = dev;
	nba->disk = tdisk;

	nba->luns = NULL;
	nba->nr_luns = lun_end - lun_begin + 1;
	nba->total_blocks = 0;
	nba->nr_pages = 0;

	ret = nba_luns_init(nba, lun_begin, lun_end);
	if(ret) {
		pr_err("nvm: nba: could not initialize luns\n");
		goto clean;
	}

	ret = nba_core_init(nba);
	if (ret) {
		pr_err("nvm: nba: could not initialize core\n");
		goto clean;
	}

	tdisk->fops = &nba_fops;

	/* inherit the size from the underlying device */
	blk_queue_logical_block_size(tqueue, queue_physical_block_size(bqueue));
	blk_queue_max_hw_sectors(tqueue, queue_max_hw_sectors(bqueue));

	pr_info("nvm: nba initialized nba %lu luns, %lu blocks and %lu pages",
				nba->nr_luns, nba->total_blocks, nba->nr_pages);

	return nba;
clean:
	nba_free(nba);
err:
	return ERR_PTR(ret);
}

static void nba_exit(void *private)
{
	struct nba *nba = private;

	nba_free(nba);
}

static struct nvm_tgt_type tt_nba = {
	.name		= "nba",

	.make_rq	= nba_make_rq,
	.capacity	= nba_capacity,
	.end_io	    	= nba_end_io,

	.init		= nba_init,
	.exit		= nba_exit,
};

static int __init nba_module_init (void)
{
	return nvm_register_target(&tt_nba);
}

static void nba_module_exit (void)
{
	nvm_unregister_target(&tt_nba);
}

module_init(nba_module_init);
module_exit(nba_module_exit);
MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("Block nba for IO");
