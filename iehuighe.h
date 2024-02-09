
#include <linux/oid_registry.h>
#include <crypto/pkcs7.h>
#include "x509_parser.h"

#define kenter(FMT, ...) \
	pr_devel("==> %s("FMT")\n", __func__, ##__VA_ARGS__)
#define kleave(FMT, ...) \
	pr_devel("<== %s()"FMT"\n", __func__, ##__VA_ARGS__)

struct pkcs7_signed_info {
	struct pkcs7_signed_info *next;
	struct x509_certificate *signer; /* Signing certificate (in msg->certs) */
	unsigned	index;
	bool		unsupported_crypto;	/* T if not usable due to missing crypto */
	bool		blacklisted;

	/* Message digest - the digest of the Content Data (or NULL) */
	const void	*msgdigest;
	unsigned	msgdigest_len;

	/* A
	unsigned long	aa_set;
#define	sinfo_has_content_type		0
#define	sinfo_has_signing_time		1
#define	sinfo_has_message_digest	2
#define sinfo_has_smime_caps		3
#define	sinfo_has_ms_opus_info		4
#define	sinfo_has_ms_statement_type	5
	time64_t	signing_time;

	/* Message signature.
	 *
	 * This contains the generated digest of _either_ the Content Data or
	 * the Authenticated Attributes [RFC2315 9.3].  If the latter, one of
	 * the attributes containuthenticated Attribute data (or NULL) */
	unsigned	authattrs_len;
	const void	*authattrs;s the digest of the Content Data within it.
	 *
	 * This also contains the issuing cert serial number and issuer's name
	 * [PKCS#7 or CMS ver 1] or issuing cert's SKID [CMS ver 3].
	 */
	struct public_key_signature *sig;
};
