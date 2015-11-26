/*
 * sun4i-ss-async.c - hardware cryptographic accelerator for Allwinner A20 SoC
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

int sun4i_ss_async_hash(struct crypto_engine *engine, struct ahash_request *areq)
{
	int err;

	err = sun4i_hash(areq);
	crypto_finalize_hash_request(engine, areq, err);
	return err;
}

int sun4i_ss_async_cipher(struct crypto_engine *engine, struct ablkcipher_request *areq)
{
	int err;

	err = sun4i_ss_cipher_poll(areq);
	crypto_finalize_cipher_request(engine, areq, err);
	return err;
}
