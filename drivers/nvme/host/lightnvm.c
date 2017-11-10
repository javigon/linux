/*
 * nvme-lightnvm.c - LightNVM NVMe device
 *
 * Copyright (C) 2014-2015 IT University of Copenhagen
 * Initial release: Matias Bjorling <mb@lightnvm.io>
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

#include "nvme.h"

#include <linux/nvme.h>
#include <linux/bitops.h>
#include <linux/lightnvm.h>
#include <linux/vmalloc.h>
#include <linux/sched/sysctl.h>
#include <uapi/linux/lightnvm.h>

enum nvme_nvm_admin_opcode {
	nvme_nvm_admin_identity		= 0xe2,
	nvme_nvm_admin_get_bb_tbl	= 0xf2,
	nvme_nvm_admin_set_bb_tbl	= 0xf1,
};

enum nvme_nvm_log_page {
	NVME_NVM_LOG_REPORT_CHUNK	= 0xCA,
};

struct nvme_nvm_ph_rw {
	__u8			opcode;
	__u8			flags;
	__u16			command_id;
	__le32			nsid;
	__u64			rsvd2;
	__le64			metadata;
	__le64			prp1;
	__le64			prp2;
	__le64			spba;
	__le16			length;
	__le16			control;
	__le32			dsmgmt;
	__le64			resv;
};

struct nvme_nvm_identity {
	__u8			opcode;
	__u8			flags;
	__u16			command_id;
	__le32			nsid;
	__u64			rsvd[2];
	__le64			prp1;
	__le64			prp2;
	__le32			chnl_off;
	__u32			rsvd11[5];
};

struct nvme_nvm_getbbtbl {
	__u8			opcode;
	__u8			flags;
	__u16			command_id;
	__le32			nsid;
	__u64			rsvd[2];
	__le64			prp1;
	__le64			prp2;
	__le64			spba;
	__u32			rsvd4[4];
};

struct nvme_nvm_setbbtbl {
	__u8			opcode;
	__u8			flags;
	__u16			command_id;
	__le32			nsid;
	__le64			rsvd[2];
	__le64			prp1;
	__le64			prp2;
	__le64			spba;
	__le16			nlb;
	__u8			value;
	__u8			rsvd3;
	__u32			rsvd4[3];
};

struct nvme_nvm_erase_blk {
	__u8			opcode;
	__u8			flags;
	__u16			command_id;
	__le32			nsid;
	__u64			rsvd[2];
	__le64			prp1;
	__le64			prp2;
	__le64			spba;
	__le16			length;
	__le16			control;
	__le32			dsmgmt;
	__le64			resv;
};

struct nvme_nvm_command {
	union {
		struct nvme_common_command common;
		struct nvme_nvm_identity identity;
		struct nvme_nvm_ph_rw ph_rw;
		struct nvme_nvm_getbbtbl get_bb;
		struct nvme_nvm_setbbtbl set_bb;
		struct nvme_nvm_erase_blk erase;
	};
};

#define NVME_NVM_LP_MLC_PAIRS 886
struct nvme_nvm_lp_mlc {
	__le16			num_pairs;
	__u8			pairs[NVME_NVM_LP_MLC_PAIRS];
};

struct nvme_nvm_lp_tbl {
	__u8			id[8];
	struct nvme_nvm_lp_mlc	mlc;
};

struct nvme_nvm_id_group {
	__u8			mtype;
	__u8			fmtype;
	__le16			res16;
	__u8			num_ch;
	__u8			num_lun;
	__u8			num_pln;
	__u8			rsvd1;
	__le16			num_chk;
	__le16			num_pg;
	__le16			fpg_sz;
	__le16			csecs;
	__le16			sos;
	__le16			rsvd2;
	__le32			trdt;
	__le32			trdm;
	__le32			tprt;
	__le32			tprm;
	__le32			tbet;
	__le32			tbem;
	__le32			mpos;
	__le32			mccap;
	__le16			cpar;
	__u8			reserved[10];
	struct nvme_nvm_lp_tbl lptbl;
} __packed;

struct nvme_nvm_geo_20 {
	__le16			num_ch;
	__le16			num_lun;
	__le32			num_chnks;
	__le32			clba;
	__le32			csecs;
	__le32			sos;
	__u8			resv[44];
};

struct nvme_nvm_wrt_20 {
	__le32			ws_min;
	__le32			ws_opt;
	__le32			mw_cunits;
	__u8			resv[52];
};

struct nvme_nvm_perf_20 {
	__le32			trdt;
	__le32			trdm;
	__le32			tprt;
	__le32			tprm;
	__le32			tbet;
	__le32			tbem;
	__u8			resv[40];
};

struct nvme_nvm_addr_format_20 {
	__u8			ch_len;
	__u8			lun_len;
	__u8			chk_len;
	__u8			sec_len;
	__u8			res[4];
} __packed;

struct nvme_nvm_addr_format_12 {
	__u8			ch_offset;
	__u8			ch_len;
	__u8			lun_offset;
	__u8			lun_len;
	__u8			pln_offset;
	__u8			pln_len;
	__u8			blk_offset;
	__u8			blk_len;
	__u8			pg_offset;
	__u8			pg_len;
	__u8			sec_offset;
	__u8			sec_len;
	__u8			res[4];
} __packed;

struct nvme_nvm_id_20 {
	__u8			major_ver_id;
	__u8			minor_ver_id;
	__u8			resv[6];
	struct nvme_nvm_addr_format_20 lbaf;
	__le32			mccap;
	__u8			resv2[44];
	struct nvme_nvm_geo_20	geo;
	struct nvme_nvm_wrt_20	wrt;
	struct nvme_nvm_perf_20	perf;
} __packed;

struct nvme_nvm_id_12 {
	__u8			ver_id;
	__u8			vmnt;
	__u8			cgrps;
	__u8			res;
	__le32			cap;
	__le32			dom;
	struct nvme_nvm_addr_format_12 ppaf;
	__u8			resv[228];
	struct nvme_nvm_id_group groups[4];
} __packed;

/* Generic identification structure */
struct nvme_nvm_id {
	__u8			ver_id;
	__u8			resv[4095];
} __packed;

struct nvme_nvm_bb_tbl {
	__u8	tblid[4];
	__le16	verid;
	__le16	revid;
	__le32	rvsd1;
	__le32	tblks;
	__le32	tfact;
	__le32	tgrown;
	__le32	tdresv;
	__le32	thresv;
	__le32	rsvd2[8];
	__u8	blk[0];
};

/*
 * Check we didn't inadvertently grow the command struct
 */
static inline void _nvme_nvm_check_size(void)
{
	BUILD_BUG_ON(sizeof(struct nvme_nvm_identity) != 64);
	BUILD_BUG_ON(sizeof(struct nvme_nvm_ph_rw) != 64);
	BUILD_BUG_ON(sizeof(struct nvme_nvm_getbbtbl) != 64);
	BUILD_BUG_ON(sizeof(struct nvme_nvm_setbbtbl) != 64);
	BUILD_BUG_ON(sizeof(struct nvme_nvm_erase_blk) != 64);
	BUILD_BUG_ON(sizeof(struct nvme_nvm_id_group) != 960);
	BUILD_BUG_ON(sizeof(struct nvme_nvm_addr_format_12) != 16);
	BUILD_BUG_ON(sizeof(struct nvme_nvm_id) != NVME_IDENTIFY_DATA_SIZE);
	BUILD_BUG_ON(sizeof(struct nvme_nvm_bb_tbl) != 64);
}

static void nvme_nvm_set_addr_12(struct nvm_addr_format_12 *dst,
				 struct nvme_nvm_addr_format_12 *src)
{
	dst->ch_len = src->ch_len;
	dst->lun_len = src->lun_len;
	dst->blk_len = src->blk_len;
	dst->pg_len = src->pg_len;
	dst->pln_len = src->pln_len;
	dst->sec_len = src->sec_len;

	dst->ch_offset = src->ch_offset;
	dst->lun_offset = src->lun_offset;
	dst->blk_offset = src->blk_offset;
	dst->pg_offset = src->pg_offset;
	dst->pln_offset = src->pln_offset;
	dst->sec_offset = src->sec_offset;

	dst->ch_mask = ((1ULL << dst->ch_len) - 1) << dst->ch_offset;
	dst->lun_mask = ((1ULL << dst->lun_len) - 1) << dst->lun_offset;
	dst->blk_mask = ((1ULL << dst->blk_len) - 1) << dst->blk_offset;
	dst->pg_mask = ((1ULL << dst->pg_len) - 1) << dst->pg_offset;
	dst->pln_mask = ((1ULL << dst->pln_len) - 1) << dst->pln_offset;
	dst->sec_mask = ((1ULL << dst->sec_len) - 1) << dst->sec_offset;
}

static int nvme_nvm_identity_12(struct nvme_nvm_id *gen_id,
				struct nvm_dev_geo *dev_geo)
{
	struct nvme_nvm_id_12 *id = (struct nvme_nvm_id_12 *)gen_id;
	struct nvme_nvm_id_group *src;
	int sec_per_pg, sec_per_pl, pg_per_blk;

	if (id->cgrps != 1)
		return -EINVAL;

	nvme_nvm_set_addr_12((struct nvm_addr_format_12 *)&dev_geo->addrf,
								&id->ppaf);

	src = &id->groups[0];

	if (src->mtype != 0) {
		pr_err("nvm: memory type not supported\n");
		return -EINVAL;
	}

	/* 1.2 spec. only reports a single version id - unfold */
	dev_geo->major_ver_id = 1;
	dev_geo->minor_ver_id = 2;

	dev_geo->num_ch = src->num_ch;
	dev_geo->num_lun = src->num_lun;
	dev_geo->num_chk = le16_to_cpu(src->num_chk);
	dev_geo->csecs = le16_to_cpu(src->csecs);
	dev_geo->sos = le16_to_cpu(src->sos);

	pg_per_blk = le16_to_cpu(src->num_pg);
	sec_per_pg = le16_to_cpu(src->fpg_sz) / dev_geo->csecs;
	sec_per_pl = sec_per_pg * src->num_pln;
	dev_geo->clba = sec_per_pl * pg_per_blk;

	dev_geo->ws_opt = dev_geo->ws_min = sec_per_pg;
	dev_geo->ws_seq = NVM_IO_SNGL_ACCESS;
	dev_geo->ws_per_chk = pg_per_blk;

	dev_geo->mccap = le32_to_cpu(src->mccap);

	dev_geo->trdt = le32_to_cpu(src->trdt);
	dev_geo->trdm = le32_to_cpu(src->trdm);
	dev_geo->tprt = le32_to_cpu(src->tprt);
	dev_geo->tprm = le32_to_cpu(src->tprm);
	dev_geo->tbet = le32_to_cpu(src->tbet);
	dev_geo->tbem = le32_to_cpu(src->tbem);

	/* 1.2 compatibility */
	dev_geo->vmnt = id->vmnt;
	dev_geo->cap = le32_to_cpu(id->cap);
	dev_geo->dom = le32_to_cpu(id->dom);

	dev_geo->mtype = src->mtype;
	dev_geo->fmtype = src->fmtype;

	dev_geo->cpar = le16_to_cpu(src->cpar);
	dev_geo->mpos = le32_to_cpu(src->mpos);

	if (dev_geo->mpos & 0x020202) {
		dev_geo->ws_seq = NVM_IO_DUAL_ACCESS;
		dev_geo->ws_opt <<= 1;
	} else if (dev_geo->mpos & 0x040404) {
		dev_geo->ws_seq = NVM_IO_QUAD_ACCESS;
		dev_geo->ws_opt <<= 2;
	}

	dev_geo->num_pln = src->num_pln;
	dev_geo->num_pg = le16_to_cpu(src->num_pg);
	dev_geo->fpg_sz = le16_to_cpu(src->fpg_sz);

	return 0;
}

static void nvme_nvm_set_addr_20(struct nvm_addr_format *dst,
				 struct nvme_nvm_addr_format_20 *src)
{
	dst->ch_len = src->ch_len;
	dst->lun_len = src->lun_len;
	dst->chk_len = src->chk_len;
	dst->sec_len = src->sec_len;

	dst->sec_offset = 0;
	dst->chk_offset = dst->sec_len;
	dst->lun_offset = dst->chk_offset + dst->chk_len;
	dst->ch_offset = dst->lun_offset + dst->lun_len;

	dst->ch_mask = ((1ULL << dst->ch_len) - 1) << dst->ch_offset;
	dst->lun_mask = ((1ULL << dst->lun_len) - 1) << dst->lun_offset;
	dst->chk_mask = ((1ULL << dst->chk_len) - 1) << dst->chk_offset;
	dst->sec_mask = ((1ULL << dst->sec_len) - 1) << dst->sec_offset;
}

static int nvme_nvm_identity_20(struct nvme_nvm_id *gen_id,
				struct nvm_dev_geo *dev_geo)
{
	struct nvme_nvm_id_20 *id = (struct nvme_nvm_id_20 *)gen_id;

	dev_geo->major_ver_id = id->major_ver_id;
	dev_geo->minor_ver_id = id->minor_ver_id;

	if (!(dev_geo->major_ver_id == 2 && dev_geo->minor_ver_id == 0)) {
		pr_err("nvm: OCSSD version not supported (v%d.%d)\n",
				dev_geo->major_ver_id, dev_geo->minor_ver_id);
		return -EINVAL;
	}

	nvme_nvm_set_addr_20(&dev_geo->addrf, &id->lbaf);

	dev_geo->num_ch = le16_to_cpu(id->geo.num_ch);
	dev_geo->num_lun = le16_to_cpu(id->geo.num_lun);
	dev_geo->num_chk = le32_to_cpu(id->geo.num_chnks);
	dev_geo->clba = le32_to_cpu(id->geo.clba);
	dev_geo->csecs = le32_to_cpu(id->geo.csecs);
	dev_geo->sos = le32_to_cpu(id->geo.sos);

	dev_geo->ws_min = le32_to_cpu(id->wrt.ws_min);
	dev_geo->ws_opt = le32_to_cpu(id->wrt.ws_opt);
	dev_geo->ws_seq = NVM_IO_SNGL_ACCESS;
	dev_geo->ws_per_chk = dev_geo->clba / dev_geo->ws_min;

	dev_geo->mccap = le32_to_cpu(id->mccap);

	dev_geo->trdt = le32_to_cpu(id->perf.trdt);
	dev_geo->trdm = le32_to_cpu(id->perf.trdm);
	dev_geo->tprt = le32_to_cpu(id->perf.tprt);
	dev_geo->tprm = le32_to_cpu(id->perf.tprm);
	dev_geo->tbet = le32_to_cpu(id->perf.tbet);
	dev_geo->tbem = le32_to_cpu(id->perf.tbem);

	return 0;
}

static int nvme_nvm_identity(struct nvm_dev *nvmdev)
{
	struct nvme_ns *ns = nvmdev->q->queuedata;
	struct nvme_nvm_id *nvme_nvm_id;
	struct nvme_nvm_command c = {};
	int ret;

	c.identity.opcode = nvme_nvm_admin_identity;
	c.identity.nsid = cpu_to_le32(ns->head->ns_id);
	c.identity.chnl_off = 0;

	nvme_nvm_id = kmalloc(sizeof(struct nvme_nvm_id), GFP_KERNEL);
	if (!nvme_nvm_id)
		return -ENOMEM;

	ret = nvme_submit_sync_cmd(ns->ctrl->admin_q, (struct nvme_command *)&c,
				nvme_nvm_id, sizeof(struct nvme_nvm_id));
	if (ret) {
		ret = -EIO;
		goto out;
	}

	switch (nvme_nvm_id->ver_id) {
	case 1:
		ret = nvme_nvm_identity_12(nvme_nvm_id, &nvmdev->dev_geo);
		break;
	case 2:
		ret = nvme_nvm_identity_20(nvme_nvm_id, &nvmdev->dev_geo);
		break;
	default:
		dev_err(ns->ctrl->device,
				"OCSSD revision not supported (%d)\n",
				nvme_nvm_id->ver_id);
		ret = -EINVAL;
		break;
	}

out:
	kfree(nvme_nvm_id);
	return ret;
}

static int nvme_nvm_get_bb_tbl(struct nvm_dev *nvmdev, struct ppa_addr ppa,
								u8 *blks)
{
	struct request_queue *q = nvmdev->q;
	struct nvm_geo *geo = &nvmdev->geo;
	struct nvme_ns *ns = q->queuedata;
	struct nvme_ctrl *ctrl = ns->ctrl;
	struct nvme_nvm_command c = {};
	struct nvme_nvm_bb_tbl *bb_tbl;
	int nr_blks = geo->nr_chks * geo->plane_mode;
	int tblsz = sizeof(struct nvme_nvm_bb_tbl) + nr_blks;
	int ret = 0;

	c.get_bb.opcode = nvme_nvm_admin_get_bb_tbl;
	c.get_bb.nsid = cpu_to_le32(ns->head->ns_id);
	c.get_bb.spba = cpu_to_le64(ppa.ppa);

	bb_tbl = kzalloc(tblsz, GFP_KERNEL);
	if (!bb_tbl)
		return -ENOMEM;

	ret = nvme_submit_sync_cmd(ctrl->admin_q, (struct nvme_command *)&c,
								bb_tbl, tblsz);
	if (ret) {
		dev_err(ctrl->device, "get bad block table failed (%d)\n", ret);
		ret = -EIO;
		goto out;
	}

	if (bb_tbl->tblid[0] != 'B' || bb_tbl->tblid[1] != 'B' ||
		bb_tbl->tblid[2] != 'L' || bb_tbl->tblid[3] != 'T') {
		dev_err(ctrl->device, "bbt format mismatch\n");
		ret = -EINVAL;
		goto out;
	}

	if (le16_to_cpu(bb_tbl->verid) != 1) {
		ret = -EINVAL;
		dev_err(ctrl->device, "bbt version not supported\n");
		goto out;
	}

	if (le32_to_cpu(bb_tbl->tblks) != nr_blks) {
		ret = -EINVAL;
		dev_err(ctrl->device,
				"bbt unsuspected blocks returned (%u!=%u)",
				le32_to_cpu(bb_tbl->tblks), nr_blks);
		goto out;
	}

	memcpy(blks, bb_tbl->blk, geo->nr_chks * geo->plane_mode);
out:
	kfree(bb_tbl);
	return ret;
}

static int nvme_nvm_set_bb_tbl(struct nvm_dev *nvmdev, struct ppa_addr *ppas,
							int nr_ppas, int type)
{
	struct nvme_ns *ns = nvmdev->q->queuedata;
	struct nvme_nvm_command c = {};
	int ret = 0;

	c.set_bb.opcode = nvme_nvm_admin_set_bb_tbl;
	c.set_bb.nsid = cpu_to_le32(ns->head->ns_id);
	c.set_bb.spba = cpu_to_le64(ppas->ppa);
	c.set_bb.nlb = cpu_to_le16(nr_ppas - 1);
	c.set_bb.value = type;

	ret = nvme_submit_sync_cmd(ns->ctrl->admin_q, (struct nvme_command *)&c,
								NULL, 0);
	if (ret)
		dev_err(ns->ctrl->device, "set bad block table failed (%d)\n",
									ret);
	return ret;
}

static int nvme_nvm_get_chunk_log_page(struct nvm_dev *nvmdev,
				       struct nvm_chunk_log_page *log,
				       unsigned long off,
				       unsigned long total_len)
{
	struct nvme_ns *ns = nvmdev->q->queuedata;
	struct nvme_command c = { };
	unsigned long offset = off, left = total_len;
	unsigned long len, len_dwords;
	void *buf = log;
	int ret;

	/* The offset needs to be dword-aligned */
	if (offset & 0x3)
		return -EINVAL;

	do {
		/* Send 256KB at a time */
		len = (1 << 18) > left ? left : (1 << 18);
		len_dwords = (len >> 2) - 1;

		c.get_log_page.opcode = nvme_admin_get_log_page;
		c.get_log_page.nsid = cpu_to_le32(ns->head->ns_id);
		c.get_log_page.lid = NVME_NVM_LOG_REPORT_CHUNK;
		c.get_log_page.lpol = cpu_to_le32(offset & 0xffffffff);
		c.get_log_page.lpou = cpu_to_le32(offset >> 32);
		c.get_log_page.numdl = cpu_to_le16(len_dwords & 0xffff);
		c.get_log_page.numdu = cpu_to_le16(len_dwords >> 16);

		ret = nvme_submit_sync_cmd(ns->ctrl->admin_q, &c, buf, len);
		if (ret) {
			dev_err(ns->ctrl->device,
				"get chunk log page failed (%d)\n", ret);
			break;
		}

		buf += len;
		offset += len;
		left -= len;
	} while (left);

	return ret;
}

static inline void nvme_nvm_rqtocmd(struct nvm_rq *rqd, struct nvme_ns *ns,
				    struct nvme_nvm_command *c)
{
	c->ph_rw.opcode = rqd->opcode;
	c->ph_rw.nsid = cpu_to_le32(ns->head->ns_id);
	c->ph_rw.spba = cpu_to_le64(rqd->ppa_addr.ppa);
	c->ph_rw.metadata = cpu_to_le64(rqd->dma_meta_list);
	c->ph_rw.control = cpu_to_le16(rqd->flags);
	c->ph_rw.length = cpu_to_le16(rqd->nr_ppas - 1);
}

static void nvme_nvm_end_io(struct request *rq, blk_status_t status)
{
	struct nvm_rq *rqd = rq->end_io_data;

	rqd->ppa_status = le64_to_cpu(nvme_req(rq)->result.u64);
	rqd->error = nvme_req(rq)->status;
	nvm_end_io(rqd);

	kfree(nvme_req(rq)->cmd);
	blk_mq_free_request(rq);
}

static struct request *nvme_nvm_alloc_request(struct request_queue *q,
					      struct nvm_rq *rqd,
					      struct nvme_nvm_command *cmd)
{
	struct nvme_ns *ns = q->queuedata;
	struct request *rq;

	nvme_nvm_rqtocmd(rqd, ns, cmd);

	rq = nvme_alloc_request(q, (struct nvme_command *)cmd, 0, NVME_QID_ANY);
	if (IS_ERR(rq))
		return rq;

	rq->cmd_flags &= ~REQ_FAILFAST_DRIVER;

	if (rqd->bio) {
		blk_init_request_from_bio(rq, rqd->bio);
	} else {
		rq->ioprio = IOPRIO_PRIO_VALUE(IOPRIO_CLASS_BE, IOPRIO_NORM);
		rq->__data_len = 0;
	}

	return rq;
}

static int nvme_nvm_submit_io(struct nvm_dev *dev, struct nvm_rq *rqd)
{
	struct request_queue *q = dev->q;
	struct nvme_nvm_command *cmd;
	struct request *rq;

	cmd = kzalloc(sizeof(struct nvme_nvm_command), GFP_KERNEL);
	if (!cmd)
		return -ENOMEM;

	rq = nvme_nvm_alloc_request(q, rqd, cmd);
	if (IS_ERR(rq)) {
		kfree(cmd);
		return PTR_ERR(rq);
	}

	rq->end_io_data = rqd;

	blk_execute_rq_nowait(q, NULL, rq, 0, nvme_nvm_end_io);

	return 0;
}

static int nvme_nvm_submit_io_sync(struct nvm_dev *dev, struct nvm_rq *rqd)
{
	struct request_queue *q = dev->q;
	struct request *rq;
	struct nvme_nvm_command cmd;
	int ret = 0;

	memset(&cmd, 0, sizeof(struct nvme_nvm_command));

	rq = nvme_nvm_alloc_request(q, rqd, &cmd);
	if (IS_ERR(rq))
		return PTR_ERR(rq);

	/* I/Os can fail and the error is signaled through rqd. Callers must
	 * handle the error accordingly.
	 */
	blk_execute_rq(q, NULL, rq, 0);
	if (nvme_req(rq)->flags & NVME_REQ_CANCELLED)
		ret = -EINTR;

	rqd->ppa_status = le64_to_cpu(nvme_req(rq)->result.u64);
	rqd->error = nvme_req(rq)->status;

	blk_mq_free_request(rq);

	return ret;
}

static void *nvme_nvm_create_dma_pool(struct nvm_dev *nvmdev, char *name)
{
	struct nvme_ns *ns = nvmdev->q->queuedata;

	return dma_pool_create(name, ns->ctrl->dev, PAGE_SIZE, PAGE_SIZE, 0);
}

static void nvme_nvm_destroy_dma_pool(void *pool)
{
	struct dma_pool *dma_pool = pool;

	dma_pool_destroy(dma_pool);
}

static void *nvme_nvm_dev_dma_alloc(struct nvm_dev *dev, void *pool,
				    gfp_t mem_flags, dma_addr_t *dma_handler)
{
	return dma_pool_alloc(pool, mem_flags, dma_handler);
}

static void nvme_nvm_dev_dma_free(void *pool, void *addr,
							dma_addr_t dma_handler)
{
	dma_pool_free(pool, addr, dma_handler);
}

static struct nvm_dev_ops nvme_nvm_dev_ops = {
	.identity		= nvme_nvm_identity,

	.get_bb_tbl		= nvme_nvm_get_bb_tbl,
	.set_bb_tbl		= nvme_nvm_set_bb_tbl,

	.get_chunk_log_page	= nvme_nvm_get_chunk_log_page,

	.submit_io		= nvme_nvm_submit_io,
	.submit_io_sync		= nvme_nvm_submit_io_sync,

	.create_dma_pool	= nvme_nvm_create_dma_pool,
	.destroy_dma_pool	= nvme_nvm_destroy_dma_pool,
	.dev_dma_alloc		= nvme_nvm_dev_dma_alloc,
	.dev_dma_free		= nvme_nvm_dev_dma_free,

	.max_phys_sect		= 64,
};

static int nvme_nvm_submit_user_cmd(struct request_queue *q,
				struct nvme_ns *ns,
				struct nvme_nvm_command *vcmd,
				void __user *ubuf, unsigned int bufflen,
				void __user *meta_buf, unsigned int meta_len,
				void __user *ppa_buf, unsigned int ppa_len,
				u32 *result, u64 *status, unsigned int timeout)
{
	bool write = nvme_is_write((struct nvme_command *)vcmd);
	struct nvm_dev *dev = ns->ndev;
	struct gendisk *disk = ns->disk;
	struct request *rq;
	struct bio *bio = NULL;
	__le64 *ppa_list = NULL;
	dma_addr_t ppa_dma;
	__le64 *metadata = NULL;
	dma_addr_t metadata_dma;
	DECLARE_COMPLETION_ONSTACK(wait);
	int ret = 0;

	rq = nvme_alloc_request(q, (struct nvme_command *)vcmd, 0,
			NVME_QID_ANY);
	if (IS_ERR(rq)) {
		ret = -ENOMEM;
		goto err_cmd;
	}

	rq->timeout = timeout ? timeout : ADMIN_TIMEOUT;

	if (ppa_buf && ppa_len) {
		ppa_list = dma_pool_alloc(dev->dma_pool, GFP_KERNEL, &ppa_dma);
		if (!ppa_list) {
			ret = -ENOMEM;
			goto err_rq;
		}
		if (copy_from_user(ppa_list, (void __user *)ppa_buf,
						sizeof(u64) * (ppa_len + 1))) {
			ret = -EFAULT;
			goto err_ppa;
		}
		vcmd->ph_rw.spba = cpu_to_le64(ppa_dma);
	} else {
		vcmd->ph_rw.spba = cpu_to_le64((uintptr_t)ppa_buf);
	}

	if (ubuf && bufflen) {
		ret = blk_rq_map_user(q, rq, NULL, ubuf, bufflen, GFP_KERNEL);
		if (ret)
			goto err_ppa;
		bio = rq->bio;

		if (meta_buf && meta_len) {
			metadata = dma_pool_alloc(dev->dma_pool, GFP_KERNEL,
								&metadata_dma);
			if (!metadata) {
				ret = -ENOMEM;
				goto err_map;
			}

			if (write) {
				if (copy_from_user(metadata,
						(void __user *)meta_buf,
						meta_len)) {
					ret = -EFAULT;
					goto err_meta;
				}
			}
			vcmd->ph_rw.metadata = cpu_to_le64(metadata_dma);
		}

		bio->bi_disk = disk;
	}

	blk_execute_rq(q, NULL, rq, 0);

	if (nvme_req(rq)->flags & NVME_REQ_CANCELLED)
		ret = -EINTR;
	else if (nvme_req(rq)->status & 0x7ff)
		ret = -EIO;
	if (result)
		*result = nvme_req(rq)->status & 0x7ff;
	if (status)
		*status = le64_to_cpu(nvme_req(rq)->result.u64);

	if (metadata && !ret && !write) {
		if (copy_to_user(meta_buf, (void *)metadata, meta_len))
			ret = -EFAULT;
	}
err_meta:
	if (meta_buf && meta_len)
		dma_pool_free(dev->dma_pool, metadata, metadata_dma);
err_map:
	if (bio)
		blk_rq_unmap_user(bio);
err_ppa:
	if (ppa_buf && ppa_len)
		dma_pool_free(dev->dma_pool, ppa_list, ppa_dma);
err_rq:
	blk_mq_free_request(rq);
err_cmd:
	return ret;
}

static int nvme_nvm_submit_vio(struct nvme_ns *ns,
					struct nvm_user_vio __user *uvio)
{
	struct nvm_user_vio vio;
	struct nvme_nvm_command c;
	unsigned int length;
	int ret;

	if (copy_from_user(&vio, uvio, sizeof(vio)))
		return -EFAULT;
	if (vio.flags)
		return -EINVAL;

	memset(&c, 0, sizeof(c));
	c.ph_rw.opcode = vio.opcode;
	c.ph_rw.nsid = cpu_to_le32(ns->head->ns_id);
	c.ph_rw.control = cpu_to_le16(vio.control);
	c.ph_rw.length = cpu_to_le16(vio.nppas);

	length = (vio.nppas + 1) << ns->lba_shift;

	ret = nvme_nvm_submit_user_cmd(ns->queue, ns, &c,
			(void __user *)(uintptr_t)vio.addr, length,
			(void __user *)(uintptr_t)vio.metadata,
							vio.metadata_len,
			(void __user *)(uintptr_t)vio.ppa_list, vio.nppas,
			&vio.result, &vio.status, 0);

	if (ret && copy_to_user(uvio, &vio, sizeof(vio)))
		return -EFAULT;

	return ret;
}

static int nvme_nvm_user_vcmd(struct nvme_ns *ns, int admin,
					struct nvm_passthru_vio __user *uvcmd)
{
	struct nvm_passthru_vio vcmd;
	struct nvme_nvm_command c;
	struct request_queue *q;
	unsigned int timeout = 0;
	int ret;

	if (copy_from_user(&vcmd, uvcmd, sizeof(vcmd)))
		return -EFAULT;
	if ((vcmd.opcode != 0xF2) && (!capable(CAP_SYS_ADMIN)))
		return -EACCES;
	if (vcmd.flags)
		return -EINVAL;

	memset(&c, 0, sizeof(c));
	c.common.opcode = vcmd.opcode;
	c.common.nsid = cpu_to_le32(ns->head->ns_id);
	c.common.cdw2[0] = cpu_to_le32(vcmd.cdw2);
	c.common.cdw2[1] = cpu_to_le32(vcmd.cdw3);
	/* cdw11-12 */
	c.ph_rw.length = cpu_to_le16(vcmd.nppas);
	c.ph_rw.control  = cpu_to_le16(vcmd.control);
	c.common.cdw10[3] = cpu_to_le32(vcmd.cdw13);
	c.common.cdw10[4] = cpu_to_le32(vcmd.cdw14);
	c.common.cdw10[5] = cpu_to_le32(vcmd.cdw15);

	if (vcmd.timeout_ms)
		timeout = msecs_to_jiffies(vcmd.timeout_ms);

	q = admin ? ns->ctrl->admin_q : ns->queue;

	ret = nvme_nvm_submit_user_cmd(q, ns,
			(struct nvme_nvm_command *)&c,
			(void __user *)(uintptr_t)vcmd.addr, vcmd.data_len,
			(void __user *)(uintptr_t)vcmd.metadata,
							vcmd.metadata_len,
			(void __user *)(uintptr_t)vcmd.ppa_list, vcmd.nppas,
			&vcmd.result, &vcmd.status, timeout);

	if (ret && copy_to_user(uvcmd, &vcmd, sizeof(vcmd)))
		return -EFAULT;

	return ret;
}

int nvme_nvm_ioctl(struct nvme_ns *ns, unsigned int cmd, unsigned long arg)
{
	switch (cmd) {
	case NVME_NVM_IOCTL_ADMIN_VIO:
		return nvme_nvm_user_vcmd(ns, 1, (void __user *)arg);
	case NVME_NVM_IOCTL_IO_VIO:
		return nvme_nvm_user_vcmd(ns, 0, (void __user *)arg);
	case NVME_NVM_IOCTL_SUBMIT_VIO:
		return nvme_nvm_submit_vio(ns, (void __user *)arg);
	default:
		return -ENOTTY;
	}
}

int nvme_nvm_register(struct nvme_ns *ns, char *disk_name, int node)
{
	struct request_queue *q = ns->queue;
	struct nvm_dev *dev;

	_nvme_nvm_check_size();

	dev = nvm_alloc_dev(node);
	if (!dev)
		return -ENOMEM;

	dev->q = q;
	memcpy(dev->name, disk_name, DISK_NAME_LEN);
	dev->ops = &nvme_nvm_dev_ops;
	dev->private_data = ns;
	ns->ndev = dev;

	return nvm_register(dev);
}

void nvme_nvm_unregister(struct nvme_ns *ns)
{
	nvm_unregister(ns->ndev);
}

static ssize_t nvm_dev_attr_show_ppaf(struct nvm_addr_format_12 *ppaf,
					 char *page)
{
	return scnprintf(page, PAGE_SIZE,
		"0x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x\n",
				ppaf->ch_offset, ppaf->ch_len,
				ppaf->lun_offset, ppaf->lun_len,
				ppaf->pln_offset, ppaf->pln_len,
				ppaf->blk_offset, ppaf->blk_len,
				ppaf->pg_offset, ppaf->pg_len,
				ppaf->sec_offset, ppaf->sec_len);
}

static ssize_t nvm_dev_attr_show_lbaf(struct nvm_addr_format *lbaf,
					 char *page)
{
	return scnprintf(page, PAGE_SIZE,
		"0x%02x%02x%02x%02x%02x%02x%02x%02x\n",
				lbaf->ch_offset, lbaf->ch_len,
				lbaf->lun_offset, lbaf->lun_len,
				lbaf->chk_offset, lbaf->chk_len,
				lbaf->sec_offset, lbaf->sec_len);
}

static ssize_t nvm_dev_attr_show(struct device *dev,
				 struct device_attribute *dattr, char *page)
{
	struct nvme_ns *ns = nvme_get_ns_from_dev(dev);
	struct nvm_dev *ndev = ns->ndev;
	struct nvm_dev_geo *dev_geo = &ndev->dev_geo;
	struct attribute *attr;

	if (!ndev)
		return 0;

	attr = &dattr->attr;

	if (strcmp(attr->name, "version") == 0) {
		return scnprintf(page, PAGE_SIZE, "%u.%u\n",
						dev_geo->major_ver_id,
						dev_geo->minor_ver_id);
	} else if (strcmp(attr->name, "ppa_format") == 0) {
		if (dev_geo->major_ver_id == 1)
			return nvm_dev_attr_show_ppaf((void *)&dev_geo->addrf,
									page);
		else
			return nvm_dev_attr_show_lbaf((void *)&dev_geo->addrf,
									page);
	} else if (strcmp(attr->name, "num_channels") == 0) {
		return scnprintf(page, PAGE_SIZE, "%u\n", dev_geo->num_ch);
	} else if (strcmp(attr->name, "num_luns") == 0) {
		return scnprintf(page, PAGE_SIZE, "%u\n", dev_geo->num_lun);
	} else if (strcmp(attr->name, "num_blocks") == 0) {	/* u16 */
		return scnprintf(page, PAGE_SIZE, "%u\n", dev_geo->num_chk);
	} else if (strcmp(attr->name, "hw_sector_size") == 0) {
		return scnprintf(page, PAGE_SIZE, "%u\n", dev_geo->csecs);
	} else if (strcmp(attr->name, "oob_sector_size") == 0) {/* u32 */
		return scnprintf(page, PAGE_SIZE, "%u\n", dev_geo->sos);
	} else if (strcmp(attr->name, "read_typ") == 0) {
		return scnprintf(page, PAGE_SIZE, "%u\n", dev_geo->trdt);
	} else if (strcmp(attr->name, "read_max") == 0) {
		return scnprintf(page, PAGE_SIZE, "%u\n", dev_geo->trdm);
	} else if (strcmp(attr->name, "prog_typ") == 0) {
		return scnprintf(page, PAGE_SIZE, "%u\n", dev_geo->tprt);
	} else if (strcmp(attr->name, "prog_max") == 0) {
		return scnprintf(page, PAGE_SIZE, "%u\n", dev_geo->tprm);
	} else if (strcmp(attr->name, "erase_typ") == 0) {
		return scnprintf(page, PAGE_SIZE, "%u\n", dev_geo->tbet);
	} else if (strcmp(attr->name, "erase_max") == 0) {
		return scnprintf(page, PAGE_SIZE, "%u\n", dev_geo->tbem);
	} else if (strcmp(attr->name, "media_capabilities") == 0) {
		return scnprintf(page, PAGE_SIZE, "0x%08x\n", dev_geo->mccap);
	} else if (strcmp(attr->name, "max_phys_secs") == 0) {
		return scnprintf(page, PAGE_SIZE, "%u\n",
						ndev->ops->max_phys_sect);
	/* 1.2 compatibility */
	} else if (strcmp(attr->name, "media_manager") == 0) {
		return scnprintf(page, PAGE_SIZE, "%s\n", "gennvm");
	} else if (strcmp(attr->name, "vendor_opcode") == 0) {
		return scnprintf(page, PAGE_SIZE, "%u\n", dev_geo->vmnt);
	} else if (strcmp(attr->name, "capabilities") == 0) {
		return scnprintf(page, PAGE_SIZE, "%u\n", dev_geo->cap);
	} else if (strcmp(attr->name, "device_mode") == 0) {
		return scnprintf(page, PAGE_SIZE, "%u\n", dev_geo->dom);
	} else if (strcmp(attr->name, "media_type") == 0) {	/* u8 */
		return scnprintf(page, PAGE_SIZE, "%u\n", dev_geo->mtype);
	} else if (strcmp(attr->name, "flash_media_type") == 0) {
		return scnprintf(page, PAGE_SIZE, "%u\n", dev_geo->fmtype);
	} else if (strcmp(attr->name, "multiplane_modes") == 0) {
		return scnprintf(page, PAGE_SIZE, "0x%08x\n", dev_geo->mpos);
	} else if (strcmp(attr->name, "num_planes") == 0) {
		return scnprintf(page, PAGE_SIZE, "%u\n", dev_geo->num_pln);
	} else if (strcmp(attr->name, "num_pages") == 0) {
		return scnprintf(page, PAGE_SIZE, "%u\n", dev_geo->num_pg);
	} else if (strcmp(attr->name, "page_size") == 0) {
		return scnprintf(page, PAGE_SIZE, "%u\n", dev_geo->fpg_sz);
	} else {
		return scnprintf(page,
				 PAGE_SIZE,
				 "Unhandled attr(%s) in `nvm_dev_attr_show`\n",
				 attr->name);
	}
}

#define NVM_DEV_ATTR_RO(_name)						\
	DEVICE_ATTR(_name, S_IRUGO, nvm_dev_attr_show, NULL)

static NVM_DEV_ATTR_RO(version);
static NVM_DEV_ATTR_RO(ppa_format);

static NVM_DEV_ATTR_RO(num_channels);
static NVM_DEV_ATTR_RO(num_luns);
static NVM_DEV_ATTR_RO(num_blocks);
static NVM_DEV_ATTR_RO(hw_sector_size);
static NVM_DEV_ATTR_RO(oob_sector_size);
static NVM_DEV_ATTR_RO(read_typ);
static NVM_DEV_ATTR_RO(read_max);
static NVM_DEV_ATTR_RO(prog_typ);
static NVM_DEV_ATTR_RO(prog_max);
static NVM_DEV_ATTR_RO(erase_typ);
static NVM_DEV_ATTR_RO(erase_max);
static NVM_DEV_ATTR_RO(media_capabilities);
static NVM_DEV_ATTR_RO(max_phys_secs);

/* 1.2 compatibility */
static NVM_DEV_ATTR_RO(media_manager);
static NVM_DEV_ATTR_RO(vendor_opcode);
static NVM_DEV_ATTR_RO(capabilities);
static NVM_DEV_ATTR_RO(device_mode);
static NVM_DEV_ATTR_RO(media_type);
static NVM_DEV_ATTR_RO(flash_media_type);
static NVM_DEV_ATTR_RO(multiplane_modes);
static NVM_DEV_ATTR_RO(num_planes);
static NVM_DEV_ATTR_RO(num_pages);
static NVM_DEV_ATTR_RO(page_size);

static struct attribute *nvm_dev_attrs_20[] = {
	&dev_attr_version.attr,
	&dev_attr_ppa_format.attr,

	&dev_attr_num_channels.attr,
	&dev_attr_num_luns.attr,
	&dev_attr_num_blocks.attr,
	&dev_attr_hw_sector_size.attr,
	&dev_attr_oob_sector_size.attr,
	&dev_attr_read_typ.attr,
	&dev_attr_read_max.attr,
	&dev_attr_prog_typ.attr,
	&dev_attr_prog_max.attr,
	&dev_attr_erase_typ.attr,
	&dev_attr_erase_max.attr,
	&dev_attr_media_capabilities.attr,
	&dev_attr_max_phys_secs.attr,

	NULL,
};

static struct attribute *nvm_dev_attrs_12[] = {
	&dev_attr_version.attr,
	&dev_attr_ppa_format.attr,

	&dev_attr_num_channels.attr,
	&dev_attr_num_luns.attr,
	&dev_attr_num_blocks.attr,
	&dev_attr_hw_sector_size.attr,
	&dev_attr_oob_sector_size.attr,
	&dev_attr_read_typ.attr,
	&dev_attr_read_max.attr,
	&dev_attr_prog_typ.attr,
	&dev_attr_prog_max.attr,
	&dev_attr_erase_typ.attr,
	&dev_attr_erase_max.attr,
	&dev_attr_media_capabilities.attr,
	&dev_attr_max_phys_secs.attr,

	/* 1.2 compatibility */
	&dev_attr_media_manager.attr,
	&dev_attr_vendor_opcode.attr,
	&dev_attr_capabilities.attr,
	&dev_attr_device_mode.attr,
	&dev_attr_media_type.attr,
	&dev_attr_flash_media_type.attr,
	&dev_attr_multiplane_modes.attr,
	&dev_attr_num_planes.attr,
	&dev_attr_num_pages.attr,
	&dev_attr_page_size.attr,

	NULL,
};

static const struct attribute_group nvm_dev_attr_group_12 = {
	.name		= "lightnvm",
	.attrs		= nvm_dev_attrs_12,
};

static const struct attribute_group nvm_dev_attr_group_20 = {
	.name		= "lightnvm",
	.attrs		= nvm_dev_attrs_20,
};

int nvme_nvm_register_sysfs(struct nvme_ns *ns)
{
	struct nvm_dev *ndev = ns->ndev;
	struct nvm_dev_geo *dev_geo = &ndev->dev_geo;

	if (dev_geo->major_ver_id == 1)
		return sysfs_create_group(&disk_to_dev(ns->disk)->kobj,
							&nvm_dev_attr_group_12);
	else if (dev_geo->major_ver_id == 2)
		return sysfs_create_group(&disk_to_dev(ns->disk)->kobj,
							&nvm_dev_attr_group_20);
	else
		return -EINVAL;
}

void nvme_nvm_unregister_sysfs(struct nvme_ns *ns)
{
	struct nvm_dev *ndev = ns->ndev;
	struct nvm_dev_geo *dev_geo = &ndev->dev_geo;

	if (dev_geo->major_ver_id == 1)
		return sysfs_remove_group(&disk_to_dev(ns->disk)->kobj,
							&nvm_dev_attr_group_12);
	else if (dev_geo->major_ver_id == 2)
		return sysfs_remove_group(&disk_to_dev(ns->disk)->kobj,
							&nvm_dev_attr_group_20);
}
