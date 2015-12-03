/*
 * sun4i-ss-dma.c - hardware cryptographic accelerator for Allwinner A20 SoC
 *
 * Copyright (C) 2013-2015 Corentin LABBE <clabbe.montjoie@gmail.com>
 *
 * Core file which registers crypto algorithms supported by the SS.
 *
 * You could find a link for the datasheet in Documentation/arm/sunxi/README
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 */
#include <linux/clk.h>
#include <linux/crypto.h>
#include <linux/io.h>
#include <linux/module.h>
#include <linux/of.h>
#include <linux/platform_device.h>
#include <crypto/scatterwalk.h>
#include <linux/scatterlist.h>
#include <linux/interrupt.h>
#include <linux/delay.h>

#include "sun4i-ss.h"

void sun4i_ss_dma_callback(void *data)
{
	struct sun4i_ss_ctx *ss = (struct sun4i_ss_ctx *)data;

	/*dev_info(ss->dev, "%s\n", __func__);*/

	ss->dma_success = 1;
	complete(&ss->complete);
}

int sun4i_ss_dma_init(struct sun4i_ss_ctx *ss)
{
	struct dma_slave_config dma_conf_rx;
	struct dma_slave_config dma_conf_tx;
	int err;

	dev_info(ss->dev, "%s\n", __func__);

	ss->chan_rx = dma_request_slave_channel(ss->dev, "tx");
	if (!ss->chan_rx) {
		dev_err(ss->dev, "Could not acquire RX DMA channel.\n");
		return -EBUSY;
	}
	ss->chan_tx = dma_request_slave_channel(ss->dev, "rx");
	if (!ss->chan_tx) {
		dev_err(ss->dev, "Could not acquire TX DMA channel.\n");
		return -EBUSY;
	}

	dma_conf_rx.direction = DMA_MEM_TO_DEV;
	dma_conf_rx.dst_addr = ss->phys_base + SS_RXFIFO;
	dma_conf_rx.dst_addr_width = DMA_SLAVE_BUSWIDTH_4_BYTES;
	dma_conf_rx.dst_maxburst = 1;
	dma_conf_rx.src_addr_width = DMA_SLAVE_BUSWIDTH_4_BYTES;
	dma_conf_rx.src_maxburst = 1;
	/*dma_conf_rx.device_fc = false;*/

	err = dmaengine_slave_config(ss->chan_rx, &dma_conf_rx);
	if (err) {
		dev_err(ss->dev, "dmaengine_slave_config error for rx");
		return err;
	}

	dma_conf_tx.direction = DMA_DEV_TO_MEM;
	dma_conf_tx.dst_addr_width = DMA_SLAVE_BUSWIDTH_4_BYTES;
	dma_conf_tx.dst_maxburst = 1;
	dma_conf_tx.src_addr = ss->phys_base + SS_TXFIFO;
	dma_conf_tx.src_addr_width = DMA_SLAVE_BUSWIDTH_4_BYTES;
	dma_conf_tx.src_maxburst = 1;

	err = dmaengine_slave_config(ss->chan_tx, &dma_conf_tx);
	if (err) {
		dev_err(ss->dev, "dmaengine_slave_config error for tx");
		return err;
	}

	init_completion(&ss->complete);

	dev_info(ss->dev, "%s end\n", __func__);

	return 0;
}

/* do DMA need SS to be setuped */
int sun4i_ss_dma(struct ablkcipher_request *areq)
{
	struct crypto_ablkcipher *tfm = crypto_ablkcipher_reqtfm(areq);
	struct sun4i_tfm_ctx *op = crypto_ablkcipher_ctx(tfm);
	struct sun4i_ss_ctx *ss = op->ss;
	int nr_sgrx, nr_sgtx, trig_rx, trig_tx;
	dma_cookie_t cookie;
	int err = 0;
	struct dma_async_tx_descriptor *desc_rx;
	struct dma_async_tx_descriptor *desc_tx;
	u32 fcsr, icsr, v;

	writel(SS_ICSR_DRQ_ENABLE, ss->base + SS_ICSR);

	/*
	 * The datasheet is blurry about what is trigger.
	 * Setting any value other than 0 give DMA timeout.
	 * By playing with xxxMAGIC from sun4i dmaengine, non-zero values could
	 * be used, but 
	 */
	trig_rx = 0x0;
	trig_tx = 0x0;
	v = (trig_tx | (trig_rx << 8));
	writel(v, ss->base + SS_FCSR);

	if (!ss->chan_rx || !ss->chan_tx) {
		dev_err(ss->dev, "DMA is not enabled\n");
		err = -EFAULT;
		goto dma_end;
	}

	if (areq->src == areq->dst) {
		nr_sgrx = dma_map_sg(ss->dev, areq->src, sg_nents(areq->src),
				     DMA_BIDIRECTIONAL);
		if (nr_sgrx == 0) {
			dev_err(ss->dev, "Invalid sg count\n");
			err = -EINVAL;
			goto dma_end;
		}
		nr_sgtx = nr_sgrx;

		desc_rx = dmaengine_prep_slave_sg(ss->chan_rx, areq->src,
						  nr_sgrx,
						  DMA_MEM_TO_DEV,
						  DMA_PREP_INTERRUPT);

		if (!desc_rx) {
			dev_err(ss->dev, "dmaengine_prep_slave_sg error for rx\n");
			err = -EINVAL;
			goto dma_end;
		}

		desc_tx = dmaengine_prep_slave_sg(ss->chan_tx, areq->dst,
						  nr_sgrx,
						  DMA_DEV_TO_MEM,
						  DMA_PREP_INTERRUPT);

		if (!desc_tx) {
			dev_err(ss->dev, "dmaengine_prep_slave_sg error for tx\n");
			err = -EINVAL;
			goto dma_end;
		}
	} else {
		nr_sgrx = dma_map_sg(ss->chan_rx->device->dev,
				     areq->src, sg_nents(areq->src),
				     DMA_TO_DEVICE);
		if (nr_sgrx <= 0) {
			dev_err(ss->dev, "Invalid sg count\n");
			err = -EINVAL;
			goto dma_end;
		}

		desc_rx = dmaengine_prep_slave_sg(ss->chan_rx, areq->src,
						  nr_sgrx,
						  DMA_MEM_TO_DEV,
						  DMA_PREP_INTERRUPT);

		if (!desc_rx) {
			dev_err(ss->dev, "dmaengine_prep_slave_sg error for rx\n");
			err = -EINVAL;
			goto dma_end;
		}

		nr_sgtx = dma_map_sg(ss->chan_tx->device->dev,
				     areq->dst, sg_nents(areq->dst),
				     DMA_FROM_DEVICE);
		if (nr_sgtx <= 0) {
			dev_err(ss->dev, "Invalid sg_count\n");
			err = -EINVAL;
			goto dma_end;
		}

		desc_tx = dmaengine_prep_slave_sg(ss->chan_tx, areq->dst,
						  nr_sgtx,
						  DMA_DEV_TO_MEM,
						  DMA_PREP_INTERRUPT);

		if (!desc_tx) {
			dev_err(ss->dev, "dmaengine_prep_slave_sg error for tx\n");
			err = -EINVAL;
			goto dma_end;
		}
	}
	desc_tx->callback = sun4i_ss_dma_callback;
	desc_tx->callback_param = ss;
	ss->dma_success = 0;

	cookie = dmaengine_submit(desc_rx);
	dma_async_issue_pending(ss->chan_rx);

	cookie = dmaengine_submit(desc_tx);
	dma_async_issue_pending(ss->chan_tx);

	wait_for_completion_interruptible_timeout(&ss->complete, msecs_to_jiffies(5000));

	if (ss->dma_success == 1) {
		dev_dbg(ss->dev, "DMA is finish\n");
	} else {
		fcsr = readl(ss->base + SS_FCSR);
		icsr = readl(ss->base + SS_ICSR);
		dev_err(ss->dev, "DMA timeout trig rx=%x tx=%x F=%02x I=%02x rr=%d rt=%d sg=%u/%u len=%u\n",
			trig_rx, trig_tx, fcsr, icsr,
			SS_RXFIFO_SPACES(fcsr),
			SS_TXFIFO_SPACES(fcsr), nr_sgrx, nr_sgtx, areq->nbytes);
		err = -EFAULT;
	}

	dmaengine_terminate_all(ss->chan_rx);
	dmaengine_terminate_all(ss->chan_tx);

	if (areq->src == areq->dst) {
		dma_unmap_sg(ss->chan_rx->device->dev, areq->src,
			     nr_sgrx, DMA_BIDIRECTIONAL);
	} else {
		dma_unmap_sg(ss->chan_rx->device->dev, areq->src, nr_sgrx,
			     DMA_TO_DEVICE);
		dma_unmap_sg(ss->chan_tx->device->dev, areq->dst, nr_sgtx,
			     DMA_FROM_DEVICE);
	}
dma_end:
	writel(0, ss->base + SS_ICSR);
	writel(0, ss->base + SS_CTL);
	return err;
}
