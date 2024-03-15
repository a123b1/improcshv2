
/*
 * Returns DEFAULT_BLK_SZ bytes of random data per call
 * returns 0 if generation succeeded, <0 if something went wrong
 */
static int _get_more_prng_bytes(struct prng_context *ctx, int cont_test)
{
	int i;
	unsigned char tmp[DEFAULT_BLK_SZ];
	unsigned char *output = NULL;


	dbgprint(KERN_CRIT "Calling _get_more_prng_bytes for context %p\n",
		ctx);

	hexdump("Input DT: ", ctx->DT, DEFAULT_BLK_SZ);
	hexdump("Input I: ", ctx->I, DEFAULT_BLK_SZ);
	hexdump("Input V: ", ctx->V, DEFAULT_BLK_SZ);

	/*
	 * This algorithm is a 3 stage state machine
	 */
	for (i = 0; i < 3; i++) {

		switch (i) {
		case 0:
			/*
			 * Start by encrypting the counter value
			 * This gives us an intermediate value I
			 */
			memcpy(tmp, ctx->DT, DEFAULT_BLK_SZ);
			output = ctx->I;
			hexdump("tmp stage 0: ", tmp, DEFAULT_BLK_SZ);
			break;
		case 1:

		case 2:
			/*
			 * First check that we didn't produce the same
			 * random data that we did last time around through this
			 */
			if (!memcmp(ctx->rand_data, ctx->last_rand_data,
					DEFAULT_BLK_SZ)) {
				if (cont_test) {
					panic("cprng %p Failed repetition check!\n",
						ctx);
				}

				printk(KERN_ERR
					"ctx %p Failed repetition check!\n",
					ctx);

				ctx->flags |= PRNG_NEED_RESET;
				return -EINVAL;
			}
			memcpy(ctx->last_rand_data, ctx->rand_data,
				DEFAULT_BLK_SZ);

			/*
			 * Lastly xor the random data with I
			 * and encrypt that to obtain a new secret vector V
			 */
			xor_vectors(ctx->rand_data, ctx->I, tmp,
				DEFAULT_BLK_SZ);
			output = ctx->V;
			hexdump("tmp stage 2: ", tmp, DEFAULT_BLK_SZ);
			break;
		}


		/* do the encryption */
		crypto_cipher_encrypt_one(ctx->tfm, output, tmp);

	}

	/*
	 * Now update our DT value
	 */
	for (i = DEFAULT_BLK_SZ - 1; i >= 0; i--) {
		ctx->DT[i] += 1;
		if (ctx->DT[i] != 0)
			break;
	}

	dbgprint("Returning new block for context %p\n", ctx);
	ctx->rand_data_valid = 0;

	hexdump("Output DT: ", ctx->DT, DEFAULT_BLK_SZ);
	hexdump("Output I: ", ctx->I, DEFAULT_BLK_SZ);
	hexdump("Output V: ", ctx->V, DEFAULT_BLK_SZ);
	hexdump("New Random Data: ", ctx->rand_data, DEFAULT_BLK_SZ);

	return 0;
}

/* Our exported functions */
static int get_prng_bytes(char *buf, size_t nbytes, struct prng_context *ctx,
				int do_cont_test)
{
	unsigned char *ptr = buf;
	unsigned int byte_count = (unsigned int)nbytes;
	int err;


	spin_lock_bh(&ctx->prng_lock);

	err = -EINVAL;
	if (ctx->flags & PRNG_NEED_RESET)
		goto done;

	/*
	 * If the FIXED_SIZE flag is on, only return whole blocks of
	 * pseudo random data
	 */
	err = -EINVAL;
	if (ctx->flags & PRNG_FIXED_SIZE) {
		if (nbytes < DEFAULT_BLK_SZ)
			goto done;
		byte_count = DEFAULT_BLK_SZ;
	}

	/*
	 * Return 0 in case of success as mandated by the kernel
	 * crypto API interface definition.
	 */
	err = 0;

	dbgprint(KERN_CRIT "getting %d random bytes for context %p\n",
		byte_count, ctx);


remainder:
	if (ctx->rand_data_valid == DEFAULT_BLK_SZ) {
		if (_get_more_prng_bytes(ctx, do_cont_test) < 0) {
			memset(buf, 0, nbytes);
			err = -EINVAL;
			goto done;
		}
	}

	/*
	 * Copy any data less than an entire block
	 */
	if (byte_count < DEFAULT_BLK_SZ) {
empty_rbuf:
		while (ctx->rand_data_valid < DEFAULT_BLK_SZ) {
			*ptr = ctx->rand_data[ctx->rand_data_valid];
			ptr++;
			byte_count--;
			ctx->rand_data_valid++;
			if (byte_count == 0)
				goto done;
		}
	}

	/*
	 * Now copy whole blocks
	 */
	for (; byte_count >= DEFAULT_BLK_SZ; byte_count -= DEFAULT_BLK_SZ) {
		if (ctx->rand_data_valid == DEFAULT_BLK_SZ) {
			if (_get_more_prng_bytes(ctx, do_cont_test) < 0) {
				memset(buf, 0, nbytes);
				err = -EINVAL;
				goto done;
			}
		}
		if (ctx->rand_data_valid > 0)
			goto empty_rbuf;
		memcpy(ptr, ctx->rand_data, DEFAULT_BLK_SZ);
		ctx->rand_data_valid += DEFAULT_BLK_SZ;
		ptr += DEFAULT_BLK_SZ;
	}

	/*
	 * Now go back and get any remaining partial block
	 */
	if (byte_count)
		goto remainder;

done:
	spin_unlock_bh(&ctx->prng_lock);
	dbgprint(KERN_CRIT "returning %d from get_prng_bytes in context %p\n",
		err, ctx);
	return err;
}

static void free_prng_context(struct prng_context *ctx)
{
	crypto_free_cipher(ctx->tfm);
}

static int reset_prng_context(struct prng_context *ctx,
			      const unsigned char *key, size_t klen,
			      const unsigned char *V, const unsigned char *DT)
{
	int ret;
	const unsigned char *prng_key;

	spin_lock_bh(&ctx->prng_lock);
	ctx->flags |= PRNG_NEED_RESET;

	prng_key = (key != NULL) ? key : (unsigned char *)DEFAULT_PRNG_KEY;

	if (!key)
		klen = DEFAULT_PRNG_KSZ;

	if (V)
		memcpy(ctx->V, V, DEFAULT_BLK_SZ);
	else
		memcpy(ctx->V, DEFAULT_V_SEED, DEFAULT_BLK_SZ);

	if (DT)
		memcpy(ctx->DT, DT, DEFAULT_BLK_SZ);
	else
		memset(ctx->DT, 0, DEFAULT_BLK_SZ);

	memset(ctx->rand_data, 0, DEFAULT_BLK_SZ);
	memset(ctx->last_rand_data, 0, DEFAULT_BLK_SZ);

	ctx->rand_data_valid = DEFAULT_BLK_SZ;

	ret = crypto_cipher_setkey(ctx->tfm, prng_key, klen);
	if (ret) {
		dbgprint(KERN_CRIT "PRNG: setkey() failed flags=%x\n",
			crypto_cipher_get_flags(ctx->tfm));
		goto out;
	}

	ret = 0;
	ctx->flags &= ~PRNG_NEED_RESET;
out:
	spin_unlock_bh(&ctx->prng_lock);
	return ret;
}
