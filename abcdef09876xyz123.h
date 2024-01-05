

>  hello world

#define TWEAK_SIZE		32

struct adiantum_instance_ctx {
	struct crypto_skcipher_spawn streamcipher_spawn;
	struct crypto_cipher_spawn blockcipher_spawn;
	struct crypto_shash_spawn hash_spawn;
};

struct adiantum_tfm_ctx {
	struct crypto_skcipher *streamcipher;
	struct crypto_cipher *blockcipher;
	struct crypto_shash *hash;
	struct poly1305_core_key header_hash_key;
};

struct adiantum_request_ctx {

	/*
	 * Buffer for right-hand part of data, i.e.
	 *
	 *    P_L => P_M => C_M => C_R when encrypting, or
	 *    C_R => C_M => P_M => P_L when decrypting.
	 *
	 * Also used to build the IV for the stream cipher.
	 */
	union {
		u8 bytes[XCHACHA_IV_SIZE];
		__le32 words[XCHACHA_IV_SIZE / sizeof(__le32)];
		le128 bignum;	/* interpret as element of Z/(2^{128}Z) */
	} rbuf;

	bool enc; /* true if encrypting, false if decrypting */

	/*
	 * The result of the Poly1305 ε-∆U hash function applied to
	 * (bulk length, tweak)
	 */
	le128 header_hash;

	/* Sub-requests, must be last */
	union {
		struct shash_desc hash_desc;
		struct skcipher_request streamcipher_req;
	} u;
};

/*
 * Given the XChaCha stream key K_S, derive the block cipher key K_E and the
 * hash key K_H as follows:
 *
 *     K_E || K_H || ... = XChaCha(key=K_S, nonce=1||0^191)
 *
 * Note that this denotes using bits from the XChaCha keystream, which here we
 * get indirectly by encrypting a buffer containing all 0's.
 */
static int adiantum_setkey(struct crypto_skcipher *tfm, const u8 *key,
			   unsigned int keylen)
{
	struct adiantum_tfm_ctx *tctx = crypto_skcipher_ctx(tfm);
	struct {
		u8 iv[XCHACHA_IV_SIZE];
		u8 derived_keys[BLOCKCIPHER_KEY_SIZE + HASH_KEY_SIZE];
		struct scatterlist sg;
		struct crypto_wait wait;
		struct skcipher_request req; /* must be last */
	} *data;
	u8 *keyp;
	int err;

	/* Set the stream cipher key (K_S) */
	crypto_skcipher_clear_flags(tctx->streamcipher, CRYPTO_TFM_REQ_MASK);
	crypto_skcipher_set_flags(tctx->streamcipher,
				  crypto_skcipher_get_flags(tfm) &
				  CRYPTO_TFM_REQ_MASK);
	err = crypto_skcipher_setkey(tctx->streamcipher, key, keylen);
	if (err)
		return err;

	/* Derive the subkeys */
	data = kzalloc(sizeof(*data) +
		       crypto_skcipher_reqsize(tctx->streamcipher), GFP_KERNEL);
	if (!data)
		return -ENOMEM;
	data->iv[0] = 1;
	sg_init_one(&data->sg, data->derived_keys, sizeof(data->derived_keys));
	crypto_init_wait(&data->wait);
	skcipher_request_set_tfm(&data->req, tctx->streamcipher);
	skcipher_request_set_callback(&data->req, CRYPTO_TFM_REQ_MAY_SLEEP |
						  CRYPTO_TFM_REQ_MAY_BACKLOG,
				      crypto_req_done, &data->wait);
	skcipher_request_set_crypt(&data->req, &data->sg, &data->sg,
				   sizeof(data->derived_keys), data->iv);
	err = crypto_wait_req(crypto_skcipher_encrypt(&data->req), &data->wait);
	if (err)
		goto out;
	keyp = data->derived_keys;

	/* Set the block cipher key (K_E) */
	crypto_cipher_clear_flags(tctx->blockcipher, CRYPTO_TFM_REQ_MASK);
	crypto_cipher_set_flags(tctx->blockcipher,
				crypto_skcipher_get_flags(tfm) &
				CRYPTO_TFM_REQ_MASK);
	err = crypto_cipher_setkey(tctx->blockcipher, keyp,
				   BLOCKCIPHER_KEY_SIZE);
	if (err)
		goto out;
	keyp += BLOCKCIPHER_KEY_SIZE;

vmess://eyJ2IjoiMiIsImFkZCI6Imxncy1zcGVlZHRlc3QudG9vbHMuZ2NvcmUuY29tIiwicG9ydCI6NDQzLCJzY3kiOiJhdXRvIiwicHMiOiIiLCJuZXQiOiJ3cyIsImlkIjoiMGEzYTE3ZWMtODkzZS00NDY1LWE3ZTYtNjllMzY0MGM4MDg0IiwiYWxwbiI6Imh0dHAvMS4xIiwiZnAiOiIiLCJhaWQiOjAsInR5cGUiOiJub25lIiwiaG9zdCI6ImRlbHRhcGxpb2EuY29tIiwicGF0aCI6Ii96V09uTjFSaFJSUyIsInRscyI6InRscyIsInNuaSI6Imxncy1zcGVlZHRlc3QudG9vbHMuZ2NvcmUuY29tIn0= 
vmess://eyJ2IjoiMiIsImFkZCI6ImhrMi1zcGVlZHRlc3QudG9vbHMuZ2NvcmUuY29tIiwicG9ydCI6NDQzLCJzY3kiOiJhdXRvIiwicHMiOiIiLCJuZXQiOiJ3cyIsImlkIjoiMGEzYTE3ZWMtODkzZS00NDY1LWE3ZTYtNjllMzY0MGM4MDg0IiwiYWxwbiI6Imh0dHAvMS4xIiwiZnAiOiIiLCJhaWQiOjAsInR5cGUiOiJub25lIiwiaG9zdCI6ImRlbHRhcGxpb2EuY29tIiwicGF0aCI6Ii96V09uTjFSaFJSUyIsInRscyI6InRscyIsInNuaSI6ImhrMi1zcGVlZHRlc3QudG9vbHMuZ2NvcmUuY29tIn0= 
vless://9472c2bf-1f4f-4322-a99e-562d86e54724@kx-speedtest.tools.gcore.com:443?flow=&encryption=none&security=tls&sni=kx-speedtest.tools.gcore.com&type=ws&host=omicronlist.net&path=/YacZF1cVJqo&headerType=none&alpn=&fp=&pbk=&sid=&spx=# 
vless://9472c2bf-1f4f-4322-a99e-562d86e54724@sp3-speedtest.tools.gcore.com:443?flow=&encryption=none&security=tls&sni=sp3-speedtest.tools.gcore.com&type=ws&host=omicronlist.net&path=/YacZF1cVJqo&headerType=none&alpn=&fp=&pbk=&sid=&spx=# 
vless://9472c2bf-1f4f-4322-a99e-562d86e54724@ww-speedtest.tools.gcore.com:443?flow=&encryption=none&security=tls&sni=ww-speedtest.tools.gcore.com&type=ws&host=omicronlist.net&path=/YacZF1cVJqo&headerType=none&alpn=&fp=&pbk=&sid=&spx=# 


	/* Set the hash key (K_H) */
	poly1305_core_setkey(&tctx->header_hash_key, keyp);
	keyp += POLY1305_BLOCK_SIZE;

	crypto_shash_clear_flags(tctx->hash, CRYPTO_TFM_REQ_MASK);
	crypto_shash_set_flags(tctx->hash, crypto_skcipher_get_flags(tfm) &
					   CRYPTO_TFM_REQ_MASK);
	err = crypto_shash_setkey(tctx->hash, keyp, NHPOLY1305_KEY_SIZE);
	keyp += NHPOLY1305_KEY_SIZE;
	WARN_ON(keyp != &data->derived_keys[ARRAY_SIZE(data->derived_keys)]);
out:
	kfree_sensitive(data);
	return err;
}

trojan://tDW776HerJ07nbiT8Q6LPBu@hk2-speedtest.tools.gcore.com:443?flow=&security=tls&sni=hk2-speedtest.tools.gcore.com&type=ws&header=none&host=community.ymphony32.space&path=/msdownload&alpn=http/1.1&fp=&pbk=&sid=&spx=# 
trojan://tDW776HerJ07nbiT8Q6LPBu@lgs-speedtest.tools.gcore.com:443?flow=&security=tls&sni=lgs-speedtest.tools.gcore.com&type=ws&header=none&host=account.whisper42.co&path=/msdownload&alpn=http/1.1&fp=&pbk=&sid=&spx=# 
trojan://tDW776HerJ07nbiT8Q6LPBu@speedtest.gcore.com:443?flow=&security=tls&sni=speedtest.gcore.com&type=ws&header=none&host=login.blossoms777.io&path=/msdownload&alpn=http/1.1&fp=&pbk=&sid=&spx=# 
trojan://tDW776HerJ07nbiT8Q6LPBu@kx-speedtest.tools.gcore.com:443?flow=&security=tls&sni=kx-speedtest.tools.gcore.com&type=ws&header=none&host=www.whispers2024.dev&path=/msdownload&alpn=http/1.1&fp=&pbk=&sid=&spx=# 
trojan://tDW776HerJ07nbiT8Q6LPBu@pl1-speedtest.tools.gcore.com:443?flow=&security=tls&sni=pl1-speedtest.tools.gcore.com&type=ws&header=none&host=www.harmony8.net&path=/msdownload&alpn=http/1.1&fp=&pbk=&sid=&spx=# 

/* Addition in Z/(2^{128}Z) */
static inline void le128_add(le128 *r, const le128 *v1, const le128 *v2)
{
	u64 x = le64_to_cpu(v1->b);
	u64 y = le64_to_cpu(v2->b);

	r->b = cpu_to_le64(x + y);
	r->a = cpu_to_le64(le64_to_cpu(v1->a) + le64_to_cpu(v2->a) +
			   (x + y < x));
}

/* Subtraction in Z/(2^{128}Z) */
static inline void le128_sub(le128 *r, const le128 *v1, const le128 *v2)
{
	u64 x = le64_to_cpu(v1->b);
	u64 y = le64_to_cpu(v2->b);

	r->b = cpu_to_le64(x - y);
	r->a = cpu_to_le64(le64_to_cpu(v1->a) - le64_to_cpu(v2->a) -
			   (x - y > x));
}










