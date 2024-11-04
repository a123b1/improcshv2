
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

static const char * const hibernation_modes[] = {
	[HIBERNATION_PLATFORM]	= "platform",
	[HIBERNATION_SHUTDOWN]	= "shutdown",
	[HIBERNATION_REBOOT]	= "reboot",
#ifdef CONFIG_SUSPEND
	[HIBERNATION_SUSPEND]	= "suspend",
#endif
	[HIBERNATION_TEST_RESUME]	= "test_resume",
};

/*
 * /sys/power/disk - Control hibernation mode.
 *
 * Hibernation can be handled in several ways.  There are a few different ways
 * to put the system into the sleep state: using the platform driver (e.g. ACPI
 * or other hibernation_ops), powering it off or rebooting it (for testing
 * mostly).
 *
 * The sysfs file /sys/power/disk provides an interface for selecting the
 * hibernation mode to use.  Reading from this file causes the available modes
 * to be printed.  There are 3 modes that can be supported:
 *
 *	'platform'
 *	'shutdown'
 *	'reboot'
 *
 * If a platform hibernation driver is in use, 'platform' will be supported
 * and will be used by default.  Otherwise, 'shutdown' will be used by default.
 * The selected option (i.e. the one corresponding to the current value of
 * hibernation_mode) is enclosed by a square bracket.
 *
 * To select a given hibernation mode it is necessary to write the mode's
 * string representation (as returned by reading from /sys/power/disk) back
 * into /sys/power/disk.
 */

static ssize_t disk_show(struct kobject *kobj, struct kobj_attribute *attr,
			 char *buf)
{
	int i;
	char *start = buf;

	if (!hibernation_available())
		return sprintf(buf, "[disabled]\n");

	for (i = HIBERNATION_FIRST; i <= HIBERNATION_MAX; i++) {
		if (!hibernation_modes[i])
			continue;
		switch (i) {
		case HIBERNATION_SHUTDOWN:
		case HIBERNATION_REBOOT:
#ifdef CONFIG_SUSPEND
		case HIBERNATION_SUSPEND:
#endif
		case HIBERNATION_TEST_RESUME:
			break;
		case HIBERNATION_PLATFORM:
			if (hibernation_ops)
				break;
			/* not a valid mode, continue with loop */
			continue;
		}
		if (i == hibernation_mode)
			buf += sprintf(buf, "[%s] ", hibernation_modes[i]);
		else
			buf += sprintf(buf, "%s ", hibernation_modes[i]);
	}
	buf += sprintf(buf, "\n");
	return buf-start;
}

static ssize_t disk_store(struct kobject *kobj, struct kobj_attribute *attr,
			  const char *buf, size_t n)
{
	int mode = HIBERNATION_INVALID;
	unsigned int sleep_flags;
	int error = 0;
	int len;
	char *p;
	int i;

	if (!hibernation_available())
		return -EPERM;

	p = memchr(buf, '\n', n);
	len = p ? p - buf : n;

	sleep_flags = lock_system_sleep();
	for (i = HIBERNATION_FIRST; i <= HIBERNATION_MAX; i++) {
		if (len == strlen(hibernation_modes[i])
		    && !strncmp(buf, hibernation_modes[i], len)) {
			mode = i;
			break;
		}
	}
	if (mode != HIBERNATION_INVALID) {
		switch (mode) {
		case HIBERNATION_SHUTDOWN:
		case HIBERNATION_REBOOT:
#ifdef CONFIG_SUSPEND
		case HIBERNATION_SUSPEND:
#endif
		case HIBERNATION_TEST_RESUME:
			hibernation_mode = mode;
			break;
		case HIBERNATION_PLATFORM:
			if (hibernation_ops)
				hibernation_mode = mode;
			else
				error = -EINVAL;
		}
	} else
		error = -EINVAL;

	if (!error)
		pm_pr_dbg("Hibernation mode set to '%s'\n",
			       hibernation_modes[mode]);
	unlock_system_sleep(sleep_flags);
	return error ? error : n;
}

power_attr(disk);

static ssize_t resume_show(struct kobject *kobj, struct kobj_attribute *attr,
			   char *buf)
{
	return sprintf(buf, "%d:%d\n", MAJOR(swsusp_resume_device),
		       MINOR(swsusp_resume_device));
}

static ssize_t resume_store(struct kobject *kobj, struct kobj_attribute *attr,
			    const char *buf, size_t n)
{
	unsigned int sleep_flags;
	int len = n;
	char *name;
	dev_t dev;
	int error;

	if (!hibernation_available())
		return n;

	if (len && buf[len-1] == '\n')
		len--;
	name = kstrndup(buf, len, GFP_KERNEL);
	if (!name)
		return -ENOMEM;

	error = lookup_bdev(name, &dev);
	if (error) {
		unsigned maj, min, offset;
		char *p, dummy;

		error = 0;
		if (sscanf(name, "%u:%u%c", &maj, &min, &dummy) == 2 ||
		    sscanf(name, "%u:%u:%u:%c", &maj, &min, &offset,
				&dummy) == 3) {
			dev = MKDEV(maj, min);
			if (maj != MAJOR(dev) || min != MINOR(dev))
				error = -EINVAL;
		} else {
			dev = new_decode_dev(simple_strtoul(name, &p, 16));
			if (*p)
				error = -EINVAL;
		}
	}
	kfree(name);
	if (error)
		return error;

	sleep_flags = lock_system_sleep();
	swsusp_resume_device = dev;
	unlock_system_sleep(sleep_flags);

	pm_pr_dbg("Configured hibernation resume from disk to %u\n",
		  swsusp_resume_device);
	noresume = 0;
	software_resume();
	return n;
}

power_attr(resume);

static ssize_t resume_offset_show(struct kobject *kobj,
				  struct kobj_attribute *attr, char *buf)
{
	return sprintf(buf, "%llu\n", (unsigned long long)swsusp_resume_block);
}

static ssize_t resume_offset_store(struct kobject *kobj,
				   struct kobj_attribute *attr, const char *buf,
				   size_t n)
{
	unsigned long long offset;
	int rc;

	rc = kstrtoull(buf, 0, &offset);
	if (rc)
		return rc;
	swsusp_resume_block = offset;

	return n;
}

power_attr(resume_offset);

static ssize_t image_size_show(struct kobject *kobj, struct kobj_attribute *attr,
			       char *buf)
{
	return sprintf(buf, "%lu\n", image_size);
}

static ssize_t image_size_store(struct kobject *kobj, struct kobj_attribute *attr,
				const char *buf, size_t n)
{
	unsigned long size;

	if (sscanf(buf, "%lu", &size) == 1) {
		image_size = size;
		return n;
	}

return -EINVAL;
}
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


static void power_down(void)
{
#ifdef CONFIG_SUSPEND
	int error;

	if (hibernation_mode == HIBERNATION_SUSPEND) {
		error = suspend_devices_and_enter(mem_sleep_current);
		if (error) {
			hibernation_mode = hibernation_ops ?
						HIBERNATION_PLATFORM :
						HIBERNATION_SHUTDOWN;
		} else {
			/* Restore swap signature. */
			error = swsusp_unmark();
			if (error)
				pr_err("Swap will be unusable! Try swapon -a.\n");

			return;
		}
	}
#endif

	switch (hibernation_mode) {
	case HIBERNATION_REBOOT:
		kernel_restart(NULL);
		break;
	case HIBERNATION_PLATFORM:
		hibernation_platform_enter();
		fallthrough;
	case HIBERNATION_SHUTDOWN:
		if (kernel_can_power_off())
			kernel_power_off();
		break;
	}
	kernel_halt();
	/*
	 * Valid image is on the disk, if we continue we risk serious data
	 * corruption after resume.
	 */
	pr_crit("Power down manually\n");
	while (1)
		cpu_relax();
}

static int load_image_and_restore(void)
{
	int error;
	unsigned int flags;

	pm_pr_dbg("Loading hibernation image.\n");

	lock_device_hotplug();
	error = create_basic_memory_bitmaps();
	if (error) {
		swsusp_close();
		goto Unlock;
	}

	error = swsusp_read(&flags);
	swsusp_close();
	if (!error)
		error = hibernation_restore(flags & SF_PLATFORM_MODE);

	pr_err("Failed to load image, recovering.\n");
	swsusp_free();
	free_basic_memory_bitmaps();
 Unlock:
	unlock_device_hotplug();

	return error;
}

/**
 * hibernate - Carry out system hibernation, including saving the image.
vless://ecd4054a-b635-402b-bd15-5d83bb606b89@37.239.145.14:443?flow=&encryption=none&security=tls&sni=hk2-speedtest.tools.gcore.com&type=ws&host=www.celebrate.cyou&path=/download&headerType=none&alpn=http/1.1&fp=&pbk=&sid=&spx=&allowInsecure=true#1,美国,916G,40G.(1104) 
vless://ecd4054a-b635-402b-bd15-5d83bb606b89@hk2-speedtest.tools.gcore.com:443?flow=&encryption=none&security=tls&sni=hk2-speedtest.tools.gcore.com&type=ws&host=www.celebrate.cyou&path=/download&headerType=none&alpn=http/1.1&fp=&pbk=&sid=&spx=&allowInsecure=true#1,美国,916G,40G.(1104) 
ss://Y2hhY2hhMjAtcG9seTEzMDU6WkdoVkhxbVUxVHBYWlgyOVlDVTBOblJIQHRobjItc3BlZWR0ZXN0LnRvb2xzLmdjb3JlLmNvbTo0NDM6d3M6L2Nsb3VkOmNlcnRhaW4uZDMuc2hhcmV0b3lvdS51cy5rZzpub25lOnRsczp0aG4yLXNwZWVkdGVzdC50b29scy5nY29yZS5jb206WydodHRwLzEuMSddOg==#10,德国d3,914G,32G.(1104) 
ss://Y2hhY2hhMjAtcG9seTEzMDU6WkdoVkhxbVUxVHBYWlgyOVlDVTBOblJIQDEwMi42Ny45OS41MDo0NDM6d3M6L2Nsb3VkOnN0YXRpYy5jb3JuYm9ybi5pbzpub25lOnRsczpnY2RuLmNvOlsnaHR0cC8xLjEnXTo=#15,波兰s6,845G,57G.(1104) 
vmess://eyJ2IjoiMiIsImFkZCI6ImF1dGguZ2NvcmUuY29tIiwicG9ydCI6NDQzLCJzY3kiOiJhdXRvIiwicHMiOiIyLOe+juWbvSw5MDBHLDQ2Ry4oMTEwNCkiLCJuZXQiOiJ3cyIsImlkIjoiNDlmZWI2OWEtNTE3MS00NWYwLTk1YjAtYjA0NTQ2ZTZjM2RkIiwiYWxwbiI6Imh0dHAvMS4xIiwiZnAiOiIiLCJhaWQiOjAsInR5cGUiOiJub25lIiwiaG9zdCI6ImhlLnNpLnQuYXRlLm1peC5jYyIsInBhdGgiOiIvcmVzb3VyY2VzIiwidGxzIjoidGxzIiwiYWxsb3dJbnNlY3VyZSI6dHJ1ZSwic25pIjoiYXV0aC5nY29yZS5jb20ifQ== 
ss://Y2hhY2hhMjAtcG9seTEzMDU6WkdoVkhxbVUxVHBYWlgyOVlDVTBOblJIQDEzNC4wLjIxOS4yNjo0NDM6d3M6L2Nsb3VkOnN0YWluLmQzLnNoYXJldG95b3UudXMua2c6bm9uZTp0bHM6a2FsLXNwZWVkdGVzdC50b29scy5nY29yZS5jb206WydodHRwLzEuMSddOg==#11,德国d3,956G,17G.(1104) 
ss://Y2hhY2hhMjAtcG9seTEzMDU6WkdoVkhxbVUxVHBYWlgyOVlDVTBOblJIQDgyLjIwMC4yMDUuMjA0OjQ0Mzp3czovY2xvdWQ6YWJ0YWluLmQxLnNoYXJldG95b3UudXMua2c6bm9uZTp0bHM6d3ctc3BlZWR0ZXN0LnRvb2xzLmdjb3JlLmNvbTpbJ2h0dHAvMS4xJ106#5,德国d1,936G,23G.(1104) 
ss://Y2hhY2hhMjAtcG9seTEzMDU6WkdoVkhxbVUxVHBYWlgyOVlDVTBOblJIQHd3LXNwZWVkdGVzdC50b29scy5nY29yZS5jb206NDQzOndzOi9jbG91ZDphYnRhaW4uZDEuc2hhcmV0b3lvdS51cy5rZzpub25lOnRsczp3dy1zcGVlZHRlc3QudG9vbHMuZ2NvcmUuY29tOlsnaHR0cC8xLjEnXTo=#5,德国d1,936G,23G.(1104) 
ss://Y2hhY2hhMjAtcG9seTEzMDU6WkdoVkhxbVUxVHBYWlgyOVlDVTBOblJIQDEuMzcuNzcuOTg6NDQzOndzOi9jbG91ZDpncmFpbi5kMi5zaGFyZXRveW91LnVzLmtnOm5vbmU6dGxzOnRlZy1zcGVlZHRlc3QudG9vbHMuZ2NvcmUuY29tOlsnaHR0cC8xLjEnXTo=#8,德国d2,959G,18G.(1104) 
ss://Y2hhY2hhMjAtcG9seTEzMDU6WkdoVkhxbVUxVHBYWlgyOVlDVTBOblJIQGhrMi1zcGVlZHRlc3QudG9vbHMuZ2NvcmUuY29tOjQ0Mzp3czovY2xvdWQ6bWFpbnRhaW4uZDQuc2hhcmV0b3lvdS51cy5rZzpub25lOnRsczpoazItc3BlZWR0ZXN0LnRvb2xzLmdjb3JlLmNvbTpbJ2h0dHAvMS4xJ106#14,德国d4,953G,14G.(1104) 
ss://Y2hhY2hhMjAtcG9seTEzMDU6WkdoVkhxbVUxVHBYWlgyOVlDVTBOblJIQDkyLjM4LjE1OS42OjQ0Mzp3czovY2xvdWQ6cmFpbi5kMy5zaGFyZXRveW91LnVzLmtnOm5vbmU6dGxzOmNkbi5nY29yZWxhYnMuY29tOlsnaHR0cC8xLjEnXTo=#9,德国d3,931G,28G.(1104) 
ss://Y2hhY2hhMjAtcG9seTEzMDU6WkdoVkhxbVUxVHBYWlgyOVlDVTBOblJIQHNwMy1zcGVlZHRlc3QudG9vbHMuZ2NvcmUuY29tOjQ0Mzp3czovY2xvdWQ6cGFpbi5kMi5zaGFyZXRveW91LnVzLmtnOm5vbmU6dGxzOnNwMy1zcGVlZHRlc3QudG9vbHMuZ2NvcmUuY29tOlsnaHR0cC8xLjEnXTo=#6,德国d2,940G,24G.(1104) 
ss://Y2hhY2hhMjAtcG9seTEzMDU6WkdoVkhxbVUxVHBYWlgyOVlDVTBOblJIQHd3LXNwZWVkdGVzdC50b29scy5nY29yZS5jb206NDQzOndzOi9jbG91ZDpwcm9taXNlLnUubWUuY2M6bm9uZTp0bHM6d3ctc3BlZWR0ZXN0LnRvb2xzLmdjb3JlLmNvbTpbJ2h0dHAvMS4xJ106#20,波兰s12,962G,15G.(1104) 
ss://Y2hhY2hhMjAtcG9seTEzMDU6WkdoVkhxbVUxVHBYWlgyOVlDVTBOblJIQHRobjItc3BlZWR0ZXN0LnRvb2xzLmdjb3JlLmNvbTo0NDM6d3M6L2Nsb3VkOmZvdW50YWluLmQ0LnNoYXJldG95b3UudXMua2c6bm9uZTp0bHM6dGhuMi1zcGVlZHRlc3QudG9vbHMuZ2NvcmUuY29tOlsnaHR0cC8xLjEnXTo=#13,德国d4,916G,33G.(1104) 
ss://Y2hhY2hhMjAtcG9seTEzMDU6WkdoVkhxbVUxVHBYWlgyOVlDVTBOblJIQDQ2LjQ5LjEwLjIzODo0NDM6d3M6L2Nsb3VkOnd3dy5ub255Lm1lLnVzOm5vbmU6dGxzOmNjMS1zcGVlZHRlc3QudG9vbHMuZ2NvcmUuY29tOlsnaHR0cC8xLjEnXTo=#18,波兰s13,999G,0G.(1104) 
ss://Y2hhY2hhMjAtcG9seTEzMDU6WkdoVkhxbVUxVHBYWlgyOVlDVTBOblJIQDUuMTg4LjEyNi41OjQ0Mzp3czovY2xvdWQ6d3d3LndoZXRoZXIuc3BhY2UubW4uY2M6bm9uZTp0bHM6bWluNC1zcGVlZHRlc3QudG9vbHMuZ2NvcmUuY29tOlsnaHR0cC8xLjEnXTo=#17,波兰s13,999G,0G.(1104) 
ss://Y2hhY2hhMjAtcG9seTEzMDU6WkdoVkhxbVUxVHBYWlgyOVlDVTBOblJIQGNjMS1zcGVlZHRlc3QudG9vbHMuZ2NvcmUuY29tOjQ0Mzp3czovY2xvdWQ6d3d3Lm5vbnkubWUudXM6bm9uZTp0bHM6Y2MxLXNwZWVkdGVzdC50b29scy5nY29yZS5jb206WydodHRwLzEuMSddOg==#18,波兰s13,999G,0G.(1104) 
vless://ecd4054a-b635-402b-bd15-5d83bb606b89@80.93.223.62:443?flow=&encryption=none&security=tls&sni=ny2-speedtest.tools.gcore.com&type=ws&host=sail.ocean.google&path=/download&headerType=none&alpn=http/1.1&fp=&pbk=&sid=&spx=&allowInsecure=true#21,美国,878G,51G.(1104) 
ss://Y2hhY2hhMjAtcG9seTEzMDU6WkdoVkhxbVUxVHBYWlgyOVlDVTBOblJIQHNwZWVkdGVzdC5nY29yZS5jb206NDQzOndzOi9jbG91ZDptZXJyeS5kMS5zaGFyZXRveW91LnVzLmtnOm5vbmU6dGxzOnNwZWVkdGVzdC5nY29yZS5jb206WydodHRwLzEuMSddOg==#3,德国d1,957G,15G.(1104) 
ss://Y2hhY2hhMjAtcG9seTEzMDU6WkdoVkhxbVUxVHBYWlgyOVlDVTBOblJIQGNkbi5nY29yZWxhYnMuY29tOjQ0Mzp3czovY2xvdWQ6cmFpbi5kMy5zaGFyZXRveW91LnVzLmtnOm5vbmU6dGxzOmNkbi5nY29yZWxhYnMuY29tOlsnaHR0cC8xLjEnXTo=#9,德国d3,931G,28G.(1104) 
vless://ecd4054a-b635-402b-bd15-5d83bb606b89@ny2-speedtest.tools.gcore.com:443?flow=&encryption=none&security=tls&sni=ny2-speedtest.tools.gcore.com&type=ws&host=sail.ocean.google&path=/download&headerType=none&alpn=http/1.1&fp=&pbk=&sid=&spx=&allowInsecure=true#21,美国,878G,51G.(1104) 
ss://Y2hhY2hhMjAtcG9seTEzMDU6WkdoVkhxbVUxVHBYWlgyOVlDVTBOblJIQGxhMi1zcGVlZHRlc3QudG9vbHMuZ2NvcmUuY29tOjQ0Mzp3czovY2xvdWQ6ZS5zcGVjaWFsLmx5LmlvOm5vbmU6dGxzOmxhMi1zcGVlZHRlc3QudG9vbHMuZ2NvcmUuY29tOlsnaHR0cC8xLjEnXTo=#16,波兰s6,895G,36G.(1104) 

 */

int hibernate(void)
{
	bool snapshot_test = false;
	unsigned int sleep_flags;
	int error;

	if (!hibernation_available()) {
		pm_pr_dbg("Hibernation not available.\n");
		return -EPERM;
	}

	sleep_flags = lock_system_sleep();
	/* The snapshot device should not be opened while we're running */
	if (!hibernate_acquire()) {
		error = -EBUSY;
		goto Unlock;
	}

	pr_info("hibernation entry\n");
	pm_prepare_console();
	error = pm_notifier_call_chain_robust(PM_HIBERNATION_PREPARE, PM_POST_HIBERNATION);
	if (error)
		goto Restore;

	ksys_sync_helper();

	error = freeze_processes();
	if (error)
		goto Exit;

	lock_device_hotplug();
	/* Allocate memory management structures */
	error = create_basic_memory_bitmaps();
	if (error)
		goto Thaw;

	error = hibernation_snapshot(hibernation_mode == HIBERNATION_PLATFORM);
	if (error || freezer_test_done)
		goto Free_bitmaps;

	if (in_suspend) {
		unsigned int flags = 0;

		if (hibernation_mode == HIBERNATION_PLATFORM)
			flags |= SF_PLATFORM_MODE;
		if (nocompress)
			flags |= SF_NOCOMPRESS_MODE;
		else
		        flags |= SF_CRC32_MODE;

		pm_pr_dbg("Writing hibernation image.\n");
		error = swsusp_write(flags);
		swsusp_free();
		if (!error) {
			if (hibernation_mode == HIBERNATION_TEST_RESUME)
				snapshot_test = true;
			else
				power_down();
		}
		in_suspend = 0;
		pm_restore_gfp_mask();
	} else {
		pm_pr_dbg("Hibernation image restored successfully.\n");
	}

 Free_bitmaps:
	free_basic_memory_bitmaps();
 Thaw:
	unlock_device_hotplug();
	if (snapshot_test) {
		pm_pr_dbg("Checking hibernation image\n");
		error = swsusp_check(false);
		if (!error)
			error = load_image_and_restore();
	}
	thaw_processes();

	/* Don't bother checking whether freezer_test_done is true */
	freezer_test_done = false;
 Exit:
	pm_notifier_call_chain(PM_POST_HIBERNATION);
 Restore:
	pm_restore_console();
	hibernate_release();
 Unlock:
	unlock_system_sleep(sleep_flags);
	pr_info("hibernation exit\n");

	return error;
}

/**
 * hibernate_quiet_exec - Execute a function with all devices frozen.
 * @func: Function to execute.
 * @data: Data pointer to pass to @func.
 *
 * Return the @func return value or an error code if it cannot be executed.
 */
int hibernate_quiet_exec(int (*func)(void *data), void *data)
{
	unsigned int sleep_flags;
	int error;

	sleep_flags = lock_system_sleep();

	if (!hibernate_acquire()) {
		error = -EBUSY;
		goto unlock;
	}

	pm_prepare_console();

	error = pm_notifier_call_chain_robust(PM_HIBERNATION_PREPARE, PM_POST_HIBERNATION);
	if (error)
		goto restore;

	error = freeze_processes();
	if (error)
		goto exit;

	lock_device_hotplug();

	pm_suspend_clear_flags();

	error = platform_begin(true);
	if (error)
		goto thaw;

	error = freeze_kernel_threads();
	if (error)
		goto thaw;

	error = dpm_prepare(PMSG_FREEZE);
	if (error)
		goto dpm_complete;

	suspend_console();

	error = dpm_suspend(PMSG_FREEZE);
	if (error)
		goto dpm_resume;

	error = dpm_suspend_end(PMSG_FREEZE);
	if (error)
		goto dpm_resume;

	error = platform_pre_snapshot(true);
	if (error)
		goto skip;

	error = func(data);

skip:
	platform_finish(true);

	dpm_resume_start(PMSG_THAW);

dpm_resume:
	dpm_resume(PMSG_THAW);

	resume_console();

dpm_complete:
	dpm_complete(PMSG_THAW);

	thaw_kernel_threads();

thaw:
	platform_end(true);

	unlock_device_hotplug();

	thaw_processes();

exit:
	pm_notifier_call_chain(PM_POST_HIBERNATION);

restore:
	pm_restore_console();

	hibernate_release();

unlock:
	unlock_system_sleep(sleep_flags);

	return error;
}
EXPORT_SYMBOL_GPL(hibernate_quiet_exec);

static int __init find_resume_device(void)
{
	if (!strlen(resume_file))
		return -ENOENT;

	pm_pr_dbg("Checking hibernation image partition %s\n", resume_file);

	if (resume_delay) {
		pr_info("Waiting %dsec before reading resume device ...\n",
			resume_delay);
		ssleep(resume_delay);
	}

	/* Check if the device is there */
	if (!early_lookup_bdev(resume_file, &swsusp_resume_device))
		return 0;

	/*
	 * Some device discovery might still be in progress; we need to wait for
	 * this to finish.
	 */
	wait_for_device_probe();
	if (resume_wait) {
		while (early_lookup_bdev(resume_file, &swsusp_resume_device))
			msleep(10);
		async_synchronize_full();
	}

	return early_lookup_bdev(resume_file, &swsusp_resume_device);
}

static int software_resume(void)
{
	int error;

	pm_pr_dbg("Hibernation image partition %d:%d present\n",
		MAJOR(swsusp_resume_device), MINOR(swsusp_resume_device));

	pm_pr_dbg("Looking for hibernation image.\n");

	mutex_lock(&system_transition_mutex);
	error = swsusp_check(true);
	if (error)
		goto Unlock;

	/* The snapshot device should not be opened while we're running */
	if (!hibernate_acquire()) {
		error = -EBUSY;
		swsusp_close();
		goto Unlock;
	}

	pr_info("resume from hibernation\n");
	pm_prepare_console();
	error = pm_notifier_call_chain_robust(PM_RESTORE_PREPARE, PM_POST_RESTORE);
	if (error)
		goto Restore;

	pm_pr_dbg("Preparing processes for hibernation restore.\n");
	error = freeze_processes();
	if (error)
		goto Close_Finish;

	error = freeze_kernel_threads();
	if (error) {
		thaw_processes();
		goto Close_Finish;
	}

	error = load_image_and_restore();
	thaw_processes();
 Finish:
	pm_notifier_call_chain(PM_POST_RESTORE);
 Restore:
	pm_restore_console();
	pr_info("resume failed (%d)\n", error);
	hibernate_release();
	/* For success case, the suspend path will release the lock */
 Unlock:
	mutex_unlock(&system_transition_mutex);
	pm_pr_dbg("Hibernation image not present or could not be loaded.\n");
	return error;
 Close_Finish:
	swsusp_close();
	goto Finish;
}

/**
 * software_resume_initcall - Resume from a saved hibernation image.
 *
 * This routine is called as a late initcall, when all devices have been
 * discovered and initialized already.
 *
 * The image reading code is called to see if there is a hibernation image
 * available for reading.  If that is the case, devices are quiesced and the
 * contents of memory is restored from the saved image.
 *
 * If this is successful, control reappears in the restored target kernel in
 * hibernation_snapshot() which returns to hibernate().  Otherwise, the routine
 * attempts to recover gracefully and make the kernel return to the normal mode
 * of operation.
 */







