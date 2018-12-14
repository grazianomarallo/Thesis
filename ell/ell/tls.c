/*
 *  Embedded Linux library
 *
 *  Copyright (C) 2015  Intel Corporation. All rights reserved.
 *
 *  This library is free software; you can redistribute it and/or
 *  modify it under the terms of the GNU Lesser General Public
 *  License as published by the Free Software Foundation; either
 *  version 2.1 of the License, or (at your option) any later version.
 *
 *  This library is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 *  Lesser General Public License for more details.
 *
 *  You should have received a copy of the GNU Lesser General Public
 *  License along with this library; if not, write to the Free Software
 *  Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA  02110-1301  USA
 */

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#define _GNU_SOURCE
#include <time.h>
#include <stdlib.h>
#include <errno.h>
#include <stdio.h>

#include "util.h"
#include "private.h"
#include "tls.h"
#include "checksum.h"
#include "cipher.h"
#include "random.h"
#include "queue.h"
#include "pem.h"
#include "cert.h"
#include "cert-private.h"
#include "tls-private.h"
#include "key.h"
#include "asn1-private.h"

bool tls10_prf(const void *secret, size_t secret_len,
		const char *label,
		const void *seed, size_t seed_len,
		uint8_t *out, size_t out_len)
{
	uint8_t p_hash2[out_len];
	uint8_t l_s1 = (secret_len + 1) / 2;
	unsigned int i;

	/*
	 * RFC2246 section 5:
	 * S1 and S2 are the two halves of the secret, and each is the same
	 * length.  S1 is taken from the first half of the secret, S2 from the
	 * second half.  Their length is created by rounding up the length of
	 * the overall secret, divided by two; thus, if the original secret is
	 * an odd number of bytes long, the last byte of S1 will be the same as
	 * the first byte of S2.
	 */

	if (!tls12_prf(L_CHECKSUM_MD5, 16,
			secret, l_s1,
			label, seed, seed_len,
			out, out_len))
		return false;

	if (secret_len > 0)
		secret += secret_len - l_s1;

	if (!tls12_prf(L_CHECKSUM_SHA1, 20,
			secret, l_s1,
			label, seed, seed_len,
			p_hash2, out_len))
		return false;

	for (i = 0; i < out_len; i++)
		out[i] ^= p_hash2[i];

	return true;
}

bool tls12_prf(enum l_checksum_type type, size_t hash_len,
		const void *secret, size_t secret_len,
		const char *label,
		const void *seed, size_t seed_len,
		uint8_t *out, size_t out_len)
{
	struct l_checksum *hmac = l_checksum_new_hmac(type, secret, secret_len);
	size_t a_len, chunk_len, prfseed_len = strlen(label) + seed_len;
	uint8_t a[128], prfseed[prfseed_len];

	if (!hmac)
		return false;

	/* Generate the hash seed or A(0) as label + seed */
	memcpy(prfseed, label, strlen(label));
	memcpy(prfseed + strlen(label), seed, seed_len);

	memcpy(a, prfseed, prfseed_len);
	a_len = prfseed_len;

	while (out_len) {
		/* Generate A(i) */
		l_checksum_reset(hmac);
		l_checksum_update(hmac, a, a_len);
		l_checksum_get_digest(hmac, a, hash_len);
		a_len = hash_len;

		/* Append seed & generate output */
		memcpy(a + a_len, prfseed, prfseed_len);
		l_checksum_reset(hmac);
		l_checksum_update(hmac, a, a_len + prfseed_len);

		chunk_len = out_len < hash_len ? out_len : hash_len;
		l_checksum_get_digest(hmac, out, chunk_len);
		out += chunk_len;
		out_len -= chunk_len;
	}

	l_checksum_free(hmac);
	return true;
}

static bool tls_prf_get_bytes(struct l_tls *tls,
				const void *secret, size_t secret_len,
				const char *label,
				const void *seed, size_t seed_len,
				uint8_t *buf, size_t len)
{
	if (tls->negotiated_version >= TLS_V12)
		return tls12_prf(tls->prf_hmac->l_id, tls->prf_hmac->length,
					secret, secret_len, label,
					seed, seed_len, buf, len);
	else
		return tls10_prf(secret, secret_len, label, seed, seed_len,
					buf, len);
}

LIB_EXPORT bool l_tls_prf_get_bytes(struct l_tls *tls, bool use_master_secret,
				const char *label, uint8_t *buf, size_t len)
{
	uint8_t seed[64];
	bool r;

	if (unlikely(!tls || !tls->prf_hmac))
		return false;

	memcpy(seed +  0, tls->pending.client_random, 32);
	memcpy(seed + 32, tls->pending.server_random, 32);

	if (use_master_secret)
		r = tls_prf_get_bytes(tls, tls->pending.master_secret, 48,
					label, seed, 64, buf, len);
	else
		r = tls_prf_get_bytes(tls, "", 0, label, seed, 64, buf, len);

	memset(seed, 0, 64);

	return r;
}

static void tls_write_random(uint8_t *buf)
{
	l_put_be32(time(NULL), buf);

	l_getrandom(buf + 4, 28);
}

static void tls_drop_handshake_hash(struct l_tls *tls,
					enum handshake_hash_type hash)
{
	if (tls->handshake_hash[hash]) {
		l_checksum_free(tls->handshake_hash[hash]);

		tls->handshake_hash[hash] = NULL;
	}
}

static void tls_reset_handshake(struct l_tls *tls)
{
	enum handshake_hash_type hash;

	memset(tls->pending.key_block, 0, sizeof(tls->pending.key_block));

	l_cert_free(tls->peer_cert);
	l_key_free(tls->peer_pubkey);

	tls->peer_cert = NULL;
	tls->peer_pubkey = NULL;
	tls->peer_pubkey_size = 0;

	for (hash = 0; hash < __HANDSHAKE_HASH_COUNT; hash++)
		tls_drop_handshake_hash(tls, hash);

	TLS_SET_STATE(TLS_HANDSHAKE_WAIT_HELLO);
	tls->cert_requested = 0;
	tls->cert_sent = 0;
}

static void tls_cleanup_handshake(struct l_tls *tls)
{
	memset(tls->pending.client_random, 0, 32);
	memset(tls->pending.server_random, 0, 32);
	memset(tls->pending.master_secret, 0, 48);
}

static bool tls_change_cipher_spec(struct l_tls *tls, bool txrx,
					const char **error)
{
	struct tls_bulk_encryption_algorithm *enc;
	struct tls_mac_algorithm *mac;
	int key_offset;
	static char error_buf[200];

	if (tls->cipher_type[txrx] == TLS_CIPHER_AEAD) {
		if (tls->aead_cipher[txrx]) {
			l_aead_cipher_free(tls->aead_cipher[txrx]);
			tls->aead_cipher[txrx] = NULL;
		}
	} else {
		if (tls->cipher[txrx]) {
			l_cipher_free(tls->cipher[txrx]);
			tls->cipher[txrx] = NULL;
		}
	}

	tls->cipher_type[txrx] = TLS_CIPHER_STREAM;

	if (tls->mac[txrx]) {
		l_checksum_free(tls->mac[txrx]);
		tls->mac[txrx] = NULL;
	}

	tls->mac_length[txrx] = 0;
	tls->block_length[txrx] = 0;
	tls->record_iv_length[txrx] = 0;

	if (tls->fixed_iv_length[txrx]) {
		memset(tls->fixed_iv[txrx], 0, tls->fixed_iv_length[txrx]);
		tls->fixed_iv_length[txrx] = 0;
	}

	tls->auth_tag_length[txrx] = 0;
	tls->seq_num[txrx] = 0;

	tls->cipher_suite[txrx] = tls->pending.cipher_suite;
	if (!tls->cipher_suite[txrx])
		return true;

	key_offset = 0;

	if (tls->cipher_suite[txrx]->mac) {
		mac = tls->cipher_suite[txrx]->mac;

		/* Server write / client read is 2nd in the key block */
		if ((tls->server && txrx) || (!tls->server && !txrx))
			key_offset += mac->mac_length;

		tls->mac[txrx] = l_checksum_new_hmac(mac->hmac_type,
						tls->pending.key_block +
						key_offset, mac->mac_length);

		/* Wipe out the now unneeded part of the key block */
		memset(tls->pending.key_block + key_offset, 0, mac->mac_length);

		if (!tls->mac[txrx]) {
			if (error) {
				*error = error_buf;
				snprintf(error_buf, sizeof(error_buf),
						"Can't create %s's %s HMAC",
						tls->cipher_suite[txrx]->name,
						txrx ? "Tx" : "Rx");
			}

			return false;
		}

		tls->mac_length[txrx] = mac->mac_length;

		key_offset = 2 * mac->mac_length;
	}

	if (tls->cipher_suite[txrx]->encryption) {
		void *cipher;

		enc = tls->cipher_suite[txrx]->encryption;

		/* Server write / client read is 4th in the key block */
		if ((tls->server && txrx) || (!tls->server && !txrx))
			key_offset += enc->key_length;

		if (enc->cipher_type == TLS_CIPHER_AEAD) {
			cipher = l_aead_cipher_new(enc->l_aead_id,
						tls->pending.key_block +
						key_offset, enc->key_length,
						enc->auth_tag_length);
			tls->aead_cipher[txrx] = cipher;
		} else {
			cipher = l_cipher_new(enc->l_id,
						tls->pending.key_block +
						key_offset, enc->key_length);
			tls->cipher[txrx] = cipher;
		}

		/* Wipe out the now unneeded part of the key block */
		memset(tls->pending.key_block + key_offset, 0, enc->key_length);

		if (!cipher) {
			if (error) {
				*error = error_buf;
				snprintf(error_buf, sizeof(error_buf),
						"Can't create %s's %s cipher",
						tls->cipher_suite[txrx]->name,
						txrx ? "Tx" : "Rx");
			}

			return false;
		}

		tls->cipher_type[txrx] = enc->cipher_type;
		tls->record_iv_length[txrx] = enc->iv_length -
			enc->fixed_iv_length;
		tls->block_length[txrx] = enc->block_length;
		tls->auth_tag_length[txrx] = enc->auth_tag_length;

		if ((tls->server && txrx) || (!tls->server && !txrx))
			key_offset += enc->key_length;
		else
			key_offset += 2 * enc->key_length;
	}

	if (tls->negotiated_version <= TLS_V10 &&
			tls->cipher_suite[txrx]->encryption &&
			tls->cipher_suite[txrx]->encryption->cipher_type ==
			TLS_CIPHER_BLOCK) {
		enc = tls->cipher_suite[txrx]->encryption;

		/* Server write / client read is 6th in the key block */
		if ((tls->server && txrx) || (!tls->server && !txrx))
			key_offset += enc->iv_length;

		l_cipher_set_iv(tls->cipher[txrx], tls->pending.key_block +
				key_offset, enc->iv_length);

		/* Wipe out the now unneeded part of the key block */
		memset(tls->pending.key_block + key_offset, 0, enc->iv_length);
	} else if (tls->cipher_suite[txrx]->encryption &&
			tls->cipher_suite[txrx]->encryption->fixed_iv_length) {
		enc = tls->cipher_suite[txrx]->encryption;

		/* Server write / client read is 6th in the key block */
		if ((tls->server && txrx) || (!tls->server && !txrx))
			key_offset += enc->fixed_iv_length;

		tls->fixed_iv_length[txrx] = enc->fixed_iv_length;
		memcpy(tls->fixed_iv[txrx], tls->pending.key_block + key_offset,
			enc->fixed_iv_length);

		/* Wipe out the now unneeded part of the key block */
		memset(tls->pending.key_block + key_offset, 0,
			enc->fixed_iv_length);
	}

	return true;
}

static void tls_reset_cipher_spec(struct l_tls *tls, bool txrx)
{
	/* Reset everything to the TLS_NULL_WITH_NULL_NULL state */

	tls->pending.cipher_suite = NULL;

	tls_change_cipher_spec(tls, txrx, NULL);
}

static bool tls_send_rsa_client_key_xchg(struct l_tls *tls);
static void tls_handle_rsa_client_key_xchg(struct l_tls *tls,
						const uint8_t *buf, size_t len);

static ssize_t tls_rsa_sign(struct l_tls *tls, uint8_t *out, size_t len,
				tls_get_hash_t get_hash);
static bool tls_rsa_verify(struct l_tls *tls, const uint8_t *in, size_t len,
				tls_get_hash_t get_hash);

static bool tls_rsa_validate_cert_key(struct l_cert *cert)
{
	return l_cert_get_pubkey_type(cert) == L_CERT_KEY_RSA;
}

static struct tls_key_exchange_algorithm tls_rsa = {
	.id = 1, /* RSA_sign */
	.certificate_check = true,
	.validate_cert_key_type = tls_rsa_validate_cert_key,
	.send_client_key_exchange = tls_send_rsa_client_key_xchg,
	.handle_client_key_exchange = tls_handle_rsa_client_key_xchg,
	.sign = tls_rsa_sign,
	.verify = tls_rsa_verify,
};

static struct tls_bulk_encryption_algorithm tls_rc4 = {
	.cipher_type = TLS_CIPHER_STREAM,
	.l_id = L_CIPHER_ARC4,
	.key_length = 16,
}, tls_aes128 = {
	.cipher_type = TLS_CIPHER_BLOCK,
	.l_id = L_CIPHER_AES_CBC,
	.key_length = 16,
	.iv_length = 16,
	.block_length = 16,
}, tls_aes256 = {
	.cipher_type = TLS_CIPHER_BLOCK,
	.l_id = L_CIPHER_AES_CBC,
	.key_length = 32,
	.iv_length = 16,
	.block_length = 16,
}, tls_3des_ede = {
	.cipher_type = TLS_CIPHER_BLOCK,
	.l_id = L_CIPHER_DES3_EDE_CBC,
	.key_length = 24,
	.iv_length = 8,
	.block_length = 8,
}, tls_aes128_gcm = {
	.cipher_type = TLS_CIPHER_AEAD,
	.l_aead_id = L_AEAD_CIPHER_AES_GCM,
	.key_length = 16,
	.iv_length = 12,
	.fixed_iv_length = 4,
	.auth_tag_length = 16,
}, tls_aes256_gcm = {
	.cipher_type = TLS_CIPHER_AEAD,
	.l_aead_id = L_AEAD_CIPHER_AES_GCM,
	.key_length = 32,
	.iv_length = 12,
	.fixed_iv_length = 4,
	.auth_tag_length = 16,
};

static struct tls_mac_algorithm tls_md5 = {
	.id = 1,
	.hmac_type = L_CHECKSUM_MD5,
	.mac_length = 16,
}, tls_sha = {
	.id = 2,
	.hmac_type = L_CHECKSUM_SHA1,
	.mac_length = 20,
}, tls_sha256 = {
	.id = 4,
	.hmac_type = L_CHECKSUM_SHA256,
	.mac_length = 32,
};

static struct tls_cipher_suite tls_cipher_suite_pref[] = {
	{
		.id = { 0x00, 0x35 },
		.name = "TLS_RSA_WITH_AES_256_CBC_SHA",
		.verify_data_length = 12,
		.encryption = &tls_aes256,
		.mac = &tls_sha,
		.key_xchg = &tls_rsa,
	},
	{
		.id = { 0x00, 0x2f },
		.name = "TLS_RSA_WITH_AES_128_CBC_SHA",
		.verify_data_length = 12,
		.encryption = &tls_aes128,
		.mac = &tls_sha,
		.key_xchg = &tls_rsa,
	},
	{
		.id = { 0x00, 0x3d },
		.name = "TLS_RSA_WITH_AES_256_CBC_SHA256",
		.verify_data_length = 12,
		.encryption = &tls_aes256,
		.mac = &tls_sha256,
		.key_xchg = &tls_rsa,
	},
	{
		.id = { 0x00, 0x3c },
		.name = "TLS_RSA_WITH_AES_128_CBC_SHA256",
		.verify_data_length = 12,
		.encryption = &tls_aes128,
		.mac = &tls_sha256,
		.key_xchg = &tls_rsa,
	},
	{
		.id = { 0x00, 0x9d },
		.name = "TLS_RSA_WITH_AES_256_GCM_SHA384",
		.verify_data_length = 12,
		.encryption = &tls_aes256_gcm,
		.prf_hmac = L_CHECKSUM_SHA384,
		.key_xchg = &tls_rsa,
	},
	{
		.id = { 0x00, 0x9c },
		.name = "TLS_RSA_WITH_AES_128_GCM_SHA256",
		.verify_data_length = 12,
		.encryption = &tls_aes128_gcm,
		.key_xchg = &tls_rsa,
	},
	{
		.id = { 0x00, 0x0a },
		.name = "TLS_RSA_WITH_3DES_EDE_CBC_SHA",
		.verify_data_length = 12,
		.encryption = &tls_3des_ede,
		.mac = &tls_sha,
		.key_xchg = &tls_rsa,
	},
	{
		.id = { 0x00, 0x05 },
		.name = "TLS_RSA_WITH_RC4_128_SHA",
		.verify_data_length = 12,
		.encryption = &tls_rc4,
		.mac = &tls_sha,
		.key_xchg = &tls_rsa,
	},
	{
		.id = { 0x00, 0x04 },
		.name = "TLS_RSA_WITH_RC4_128_MD5",
		.verify_data_length = 12,
		.encryption = &tls_rc4,
		.mac = &tls_md5,
		.key_xchg = &tls_rsa,
	},
};

static bool tls_cipher_suite_is_compatible(struct l_tls *tls,
					const struct tls_cipher_suite *suite,
					const char **error)
{
	static char error_buf[200];
	struct l_cert *leaf;

	if (suite->encryption &&
			suite->encryption->cipher_type == TLS_CIPHER_AEAD) {
		if (tls->negotiated_version &&
				tls->negotiated_version < TLS_V12) {
			if (error) {
				*error = error_buf;
				snprintf(error_buf, sizeof(error_buf),
						"Cipher suite %s uses an AEAD "
						"cipher but TLS < 1.2 was "
						"negotiated", suite->name);
			}

			return false;
		}

		if (!l_aead_cipher_is_supported(suite->encryption->l_aead_id)) {
			if (error) {
				*error = error_buf;
				snprintf(error_buf, sizeof(error_buf),
						"Cipher suite %s's AEAD cipher "
						"algorithm not supported by "
						"the kernel", suite->name);
			}

			return false;
		}
	} else if (suite->encryption) { /* Block or stream cipher */
		if (!l_cipher_is_supported(suite->encryption->l_id)) {
			if (error) {
				*error = error_buf;
				snprintf(error_buf, sizeof(error_buf),
						"Cipher suite %s's block/stream"
						" cipher algorithm not "
						"supported by the kernel",
						suite->name);
			}

			return false;
		}
	}

	if (suite->mac &&
			!l_checksum_is_supported(suite->mac->hmac_type, true)) {
		if (error) {
			*error = error_buf;
			snprintf(error_buf, sizeof(error_buf),
					"Cipher suite %s's HMAC algorithm not "
					"supported by the kernel", suite->name);
		}

		return false;
	}

	if ((tls->negotiated_version && tls->negotiated_version < TLS_V12 &&
			(!l_checksum_is_supported(L_CHECKSUM_MD5, true) ||
			 !l_checksum_is_supported(L_CHECKSUM_SHA1, true))) ||
			(tls->negotiated_version >= TLS_V12 &&
			 !l_checksum_is_supported(
					suite->prf_hmac != L_CHECKSUM_NONE ?
					suite->prf_hmac : L_CHECKSUM_SHA256,
					true))) {
		if (error) {
			*error = error_buf;
			snprintf(error_buf, sizeof(error_buf),
					"Cipher suite %s's PRF algorithm not "
					"supported by the kernel", suite->name);
		}

		return false;
	}

	leaf = l_certchain_get_leaf(tls->cert);
	if (leaf && !suite->key_xchg->validate_cert_key_type(leaf)) {
		if (error) {
			*error = error_buf;
			snprintf(error_buf, sizeof(error_buf),
					"Local certificate has key type "
					"incompatible with cipher suite %s's "
					"key xchg mechanism", suite->name);
		}

		return false;
	}

	return true;
}

static struct tls_cipher_suite *tls_find_cipher_suite(const uint8_t *id)
{
	int i;

	for (i = 0; i < (int) L_ARRAY_SIZE(tls_cipher_suite_pref); i++)
		if (tls_cipher_suite_pref[i].id[0] == id[0] &&
				tls_cipher_suite_pref[i].id[1] == id[1])
			return &tls_cipher_suite_pref[i];

	return NULL;
}

static struct tls_compression_method tls_compression_pref[] = {
	{
		0,
		"CompressionMethod.null",
	},
};

static struct tls_compression_method *tls_find_compression_method(
							const uint8_t id)
{
	int i;

	for (i = 0; i < (int) L_ARRAY_SIZE(tls_compression_pref); i++)
		if (tls_compression_pref[i].id == id)
			return &tls_compression_pref[i];

	return NULL;
}

static const struct tls_hash_algorithm tls_handshake_hash_data[] = {
	[HANDSHAKE_HASH_SHA384]	= { 5, L_CHECKSUM_SHA384, 48, "SHA384" },
	[HANDSHAKE_HASH_SHA256]	= { 4, L_CHECKSUM_SHA256, 32, "SHA256" },
	[HANDSHAKE_HASH_MD5]	= { 1, L_CHECKSUM_MD5, 16, "MD5" },
	[HANDSHAKE_HASH_SHA1]	= { 2, L_CHECKSUM_SHA1, 20, "SHA1" },
};

static bool tls_init_handshake_hash(struct l_tls *tls)
{
	enum handshake_hash_type hash;

	for (hash = 0; hash < __HANDSHAKE_HASH_COUNT; hash++) {
		if (tls->handshake_hash[hash]) {
			TLS_DEBUG("Handshake hash %s already exists",
					tls_handshake_hash_data[hash].name);
			goto err;
		}

		tls->handshake_hash[hash] = l_checksum_new(
					tls_handshake_hash_data[hash].l_id);

		if (!tls->handshake_hash[hash]) {
			TLS_DEBUG("Can't create %s hash",
					tls_handshake_hash_data[hash].name);
			goto err;
		}
	}

	return true;
err:
	for (hash = 0; hash < __HANDSHAKE_HASH_COUNT; hash++)
		tls_drop_handshake_hash(tls, hash);

	return false;
}

static const struct tls_hash_algorithm *tls_set_prf_hmac(struct l_tls *tls)
{
	enum handshake_hash_type hash;

	if (tls->pending.cipher_suite->prf_hmac == L_CHECKSUM_NONE) {
		tls->prf_hmac = &tls_handshake_hash_data[HANDSHAKE_HASH_SHA256];
		return tls->prf_hmac;
	}

	for (hash = 0; hash < __HANDSHAKE_HASH_COUNT; hash++)
		if (tls_handshake_hash_data[hash].l_id ==
				tls->pending.cipher_suite->prf_hmac) {
			tls->prf_hmac = &tls_handshake_hash_data[hash];
			return tls->prf_hmac;
		}

	return NULL;
}

enum tls_handshake_type {
	TLS_HELLO_REQUEST	= 0,
	TLS_CLIENT_HELLO	= 1,
	TLS_SERVER_HELLO	= 2,
	TLS_CERTIFICATE		= 11,
	TLS_SERVER_KEY_EXCHANGE	= 12,
	TLS_CERTIFICATE_REQUEST	= 13,
	TLS_SERVER_HELLO_DONE	= 14,
	TLS_CERTIFICATE_VERIFY	= 15,
	TLS_CLIENT_KEY_EXCHANGE	= 16,
	TLS_FINISHED		= 20,
};

#define SWITCH_ENUM_TO_STR(val) \
	case (val):		\
		return L_STRINGIFY(val);

static const char *tls_handshake_type_to_str(enum tls_handshake_type type)
{
	static char buf[100];

	switch (type) {
	SWITCH_ENUM_TO_STR(TLS_HELLO_REQUEST)
	SWITCH_ENUM_TO_STR(TLS_CLIENT_HELLO)
	SWITCH_ENUM_TO_STR(TLS_SERVER_HELLO)
	SWITCH_ENUM_TO_STR(TLS_CERTIFICATE)
	SWITCH_ENUM_TO_STR(TLS_SERVER_KEY_EXCHANGE)
	SWITCH_ENUM_TO_STR(TLS_CERTIFICATE_REQUEST)
	SWITCH_ENUM_TO_STR(TLS_SERVER_HELLO_DONE)
	SWITCH_ENUM_TO_STR(TLS_CERTIFICATE_VERIFY)
	SWITCH_ENUM_TO_STR(TLS_CLIENT_KEY_EXCHANGE)
	SWITCH_ENUM_TO_STR(TLS_FINISHED)
	}

	snprintf(buf, sizeof(buf), "tls_handshake_type(%i)", type);
	return buf;
}

static const uint8_t pkcs1_digest_info_md5_start[] = {
	0x30, 0x20, 0x30, 0x0c, 0x06, 0x08, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d,
	0x02, 0x05, 0x05, 0x00, 0x04, 0x10,
};
static const uint8_t pkcs1_digest_info_sha1_start[] = {
	0x30, 0x21, 0x30, 0x09, 0x06, 0x05, 0x2b, 0x0e, 0x03, 0x02, 0x1a, 0x05,
	0x00, 0x04, 0x14,
};
static const uint8_t pkcs1_digest_info_sha256_start[] = {
	0x30, 0x31, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03,
	0x04, 0x02, 0x01, 0x05, 0x00, 0x04, 0x20,
};
static const uint8_t pkcs1_digest_info_sha384_start[] = {
	0x30, 0x41, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03,
	0x04, 0x02, 0x02, 0x05, 0x00, 0x04, 0x30,
};
static const uint8_t pkcs1_digest_info_sha512_start[] = {
	0x30, 0x51, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03,
	0x04, 0x02, 0x03, 0x05, 0x00, 0x04, 0x40,
};

static void pkcs1_write_digest_info(enum l_checksum_type type,
					uint8_t *out, size_t *out_len,
					const uint8_t *hash, size_t hash_len)
{
	switch (type) {
	case L_CHECKSUM_MD5:
		memcpy(out, pkcs1_digest_info_md5_start,
				sizeof(pkcs1_digest_info_md5_start));
		*out_len = sizeof(pkcs1_digest_info_md5_start);
		break;
	case L_CHECKSUM_SHA1:
		memcpy(out, pkcs1_digest_info_sha1_start,
				sizeof(pkcs1_digest_info_sha1_start));
		*out_len = sizeof(pkcs1_digest_info_sha1_start);
		break;
	case L_CHECKSUM_SHA256:
		memcpy(out, pkcs1_digest_info_sha256_start,
				sizeof(pkcs1_digest_info_sha256_start));
		*out_len = sizeof(pkcs1_digest_info_sha256_start);
		break;
	case L_CHECKSUM_SHA384:
		memcpy(out, pkcs1_digest_info_sha384_start,
				sizeof(pkcs1_digest_info_sha384_start));
		*out_len = sizeof(pkcs1_digest_info_sha384_start);
		break;
	case L_CHECKSUM_SHA512:
		memcpy(out, pkcs1_digest_info_sha512_start,
				sizeof(pkcs1_digest_info_sha512_start));
		*out_len = sizeof(pkcs1_digest_info_sha512_start);
		break;
	default:
		abort();
	}

	memcpy(out + *out_len, hash, hash_len);
	*out_len += hash_len;
}

static void tls_send_alert(struct l_tls *tls, bool fatal,
				enum l_tls_alert_desc alert_desc)
{
	uint8_t buf[2];

	TLS_DEBUG("Sending a %s Alert: %s", fatal ? "Fatal" : "Warning",
			l_tls_alert_to_str(alert_desc));

	buf[0] = fatal ? 2 : 1;
	buf[1] = alert_desc;

	tls_tx_record(tls, TLS_CT_ALERT, buf, 2);
}

/*
 * Callers make sure this is about the last function before returning
 * from the stack frames up to the exported library call so that the
 * user-supplied disconnected callback here is free to use l_tls_free
 * for example.
 */
void tls_disconnect(struct l_tls *tls, enum l_tls_alert_desc desc,
			enum l_tls_alert_desc local_desc)
{
	tls_send_alert(tls, true, desc);

	tls_reset_handshake(tls);
	tls_cleanup_handshake(tls);

	tls_reset_cipher_spec(tls, 0);
	tls_reset_cipher_spec(tls, 1);

	tls->negotiated_version = 0;
	tls->ready = false;

	tls->disconnected(local_desc ?: desc, local_desc && !desc,
				tls->user_data);
}

#define TLS_HANDSHAKE_HEADER_SIZE	4

static void tls_tx_handshake(struct l_tls *tls, int type, uint8_t *buf,
				size_t length)
{
	int i;

	TLS_DEBUG("Sending a %s of %zi bytes",
			tls_handshake_type_to_str(type),
			length - TLS_HANDSHAKE_HEADER_SIZE);

	/* Fill in the handshake header */

	buf[0] = type;
	buf[1] = (length - TLS_HANDSHAKE_HEADER_SIZE) >> 16;
	buf[2] = (length - TLS_HANDSHAKE_HEADER_SIZE) >>  8;
	buf[3] = (length - TLS_HANDSHAKE_HEADER_SIZE) >>  0;

	for (i = 0; i < __HANDSHAKE_HASH_COUNT; i++)
		if (tls->handshake_hash[i])
			l_checksum_update(tls->handshake_hash[i], buf, length);

	tls_tx_record(tls, TLS_CT_HANDSHAKE, buf, length);
}

static bool tls_send_client_hello(struct l_tls *tls)
{
	uint8_t buf[128 + L_ARRAY_SIZE(tls_compression_pref) +
			2 * L_ARRAY_SIZE(tls_cipher_suite_pref)];
	uint8_t *ptr = buf + TLS_HANDSHAKE_HEADER_SIZE;
	uint8_t *len_ptr;
	int i;

	/* Fill in the Client Hello body */

	*ptr++ = (uint8_t) (TLS_VERSION >> 8);
	*ptr++ = (uint8_t) (TLS_VERSION >> 0);

	tls_write_random(tls->pending.client_random);
	memcpy(ptr, tls->pending.client_random, 32);
	ptr += 32;

	*ptr++ = 0; /* No SessionID */

	/*
	 * FIXME: We do need to filter the cipher suites by key exchange
	 * mechanism compatibility with the certificate but we don't normally
	 * have the certificate at this point because we're called from
	 * l_tls_new.  We also don't know the TLS version that's going to
	 * be negotiated yet.
	 */
	len_ptr = ptr;
	ptr += 2;

	for (i = 0; i < (int) L_ARRAY_SIZE(tls_cipher_suite_pref); i++) {
		if (!tls_cipher_suite_is_compatible(tls,
						&tls_cipher_suite_pref[i],
						NULL))
			continue;

		*ptr++ = tls_cipher_suite_pref[i].id[0];
		*ptr++ = tls_cipher_suite_pref[i].id[1];
	}

	if (ptr == len_ptr + 2) {
		TLS_DEBUG("No compatible cipher suites, check kernel config");
		return false;
	}

	l_put_be16((ptr - len_ptr - 2), len_ptr);
	*ptr++ = L_ARRAY_SIZE(tls_compression_pref);

	for (i = 0; i < (int) L_ARRAY_SIZE(tls_compression_pref); i++)
		*ptr++ = tls_compression_pref[i].id;

	tls_tx_handshake(tls, TLS_CLIENT_HELLO, buf, ptr - buf);
	return true;
}

static void tls_send_server_hello(struct l_tls *tls)
{
	uint8_t buf[128];
	uint8_t *ptr = buf + TLS_HANDSHAKE_HEADER_SIZE;

	/* Fill in the Server Hello body */

	*ptr++ = tls->negotiated_version >> 8;
	*ptr++ = tls->negotiated_version >> 0;

	tls_write_random(tls->pending.server_random);
	memcpy(ptr, tls->pending.server_random, 32);
	ptr += 32;

	*ptr++ = 0; /* Sessions are not cached */

	*ptr++ = tls->pending.cipher_suite->id[0];
	*ptr++ = tls->pending.cipher_suite->id[1];

	*ptr++ = tls->pending.compression_method->id;

	tls_tx_handshake(tls, TLS_SERVER_HELLO, buf, ptr - buf);
}

static bool tls_cert_list_add_size(struct l_cert *cert, void *user_data)
{
	size_t *total = user_data;
	size_t der_len;

	l_cert_get_der_data(cert, &der_len);
	*total += 3 + der_len;

	return false;
}

static bool tls_cert_list_append(struct l_cert *cert, void *user_data)
{
	uint8_t **ptr = user_data;
	const uint8_t *der;
	size_t der_len;

	der = l_cert_get_der_data(cert, &der_len);
	*(*ptr)++ = der_len >> 16;
	*(*ptr)++ = der_len >>  8;
	*(*ptr)++ = der_len >>  0;
	memcpy(*ptr, der, der_len);
	*ptr += der_len;

	return false;
}

static bool tls_send_certificate(struct l_tls *tls)
{
	uint8_t *buf, *ptr;
	size_t total;
	struct l_cert *leaf;

	if (tls->server && !tls->cert) {
		TLS_DISCONNECT(TLS_ALERT_INTERNAL_ERROR, TLS_ALERT_BAD_CERT,
				"Certificate needed in server mode");
		return false;
	}

	if (tls->cert && !l_certchain_find(tls->cert, tls->ca_certs)) {
		TLS_DISCONNECT(TLS_ALERT_INTERNAL_ERROR, TLS_ALERT_UNKNOWN_CA,
				"Can't find certificate chain to local "
				"CA cert");
		return false;
	}

	/* TODO: might want check this earlier and exclude the cipher suite */
	leaf = l_certchain_get_leaf(tls->cert);
	if (leaf && !tls->pending.cipher_suite->key_xchg->
			validate_cert_key_type(leaf)) {
		TLS_DISCONNECT(TLS_ALERT_INTERNAL_ERROR, TLS_ALERT_CERT_UNKNOWN,
				"Local certificate has key type incompatible "
				"with pending cipher suite %s",
				tls->pending.cipher_suite->name);

		return false;
	}

	/*
	 * TODO: check that the certificate is compatible with hash and
	 * signature algorithms lists supplied to us in the Client Hello
	 * extensions (if we're a server) or in the Certificate Request
	 * (if we act as a 1.2+ client).
	 *
	 *  - for the hash and signature_algorithms list, check all
	 *    certs in the cert chain.
	 *
	 *  - also if !cipher_suite->key_xchg->key_exchange_msg, check that the
	 *    end entity certificate's key type matches and is usable with some
	 *    hash/signature pair.
	 *
	 *  - on client check if any of the supplied DNs (if any) match
	 *    anything in our cert chain.
	 */

	total = 0;
	l_certchain_foreach_from_leaf(tls->cert, tls_cert_list_add_size, &total);

	buf = l_malloc(128 + total);
	ptr = buf + TLS_HANDSHAKE_HEADER_SIZE;

	/* Fill in the Certificate body */

	*ptr++ = total >> 16;
	*ptr++ = total >>  8;
	*ptr++ = total >>  0;
	l_certchain_foreach_from_leaf(tls->cert, tls_cert_list_append, &ptr);

	tls_tx_handshake(tls, TLS_CERTIFICATE, buf, ptr - buf);

	l_free(buf);

	if (tls->cert)
		tls->cert_sent = true;

	return true;
}

static uint8_t tls_cert_type_pref[] = {
	1, /* RSA_sign */
};

struct tls_signature_hash_algorithms {
	uint8_t hash_id;
	uint8_t signature_id;
};

static struct tls_signature_hash_algorithms tls_signature_hash_pref[] = {
	{ 6, 1 }, /* SHA512 + RSA */
	{ 5, 1 }, /* SHA384 + RSA */
	{ 4, 1 }, /* SHA256 + RSA */
	{ 2, 1 }, /* SHA1 + RSA */
	{ 1, 1 }, /* MD5 + RSA */
};

static bool tls_send_certificate_request(struct l_tls *tls)
{
	uint8_t *buf, *ptr, *dn_ptr, *signature_hash_ptr;
	const struct l_queue_entry *entry;
	unsigned int i;
	size_t dn_total = 0;

	for (entry = l_queue_get_entries(tls->ca_certs); entry;
			entry = entry->next) {
		struct l_cert *ca_cert = entry->data;
		size_t dn_size;

		if (l_cert_get_dn(ca_cert, &dn_size))
			dn_total += 10 + dn_size;
	}

	buf = l_malloc(128 + L_ARRAY_SIZE(tls_cert_type_pref) +
			2 * L_ARRAY_SIZE(tls_signature_hash_pref) +
			dn_total);
	ptr = buf + TLS_HANDSHAKE_HEADER_SIZE;

	/* Fill in the Certificate Request body */

	*ptr++ = L_ARRAY_SIZE(tls_cert_type_pref);
	for (i = 0; i < L_ARRAY_SIZE(tls_cert_type_pref); i++)
		*ptr++ = tls_cert_type_pref[i];

	/*
	 * This only makes sense as a variable-length field, assume there's
	 * a typo in RFC5246 7.4.4 here.
	 *
	 * TODO: we support the full list of hash algorithms when used
	 * in the client certificate chain but we can only verify the
	 * Certificate Verify signature when the hash algorithm matches
	 * one of HANDSHAKE_HASH_*.  The values we include here will
	 * affect both of these steps so revisit which set we're passing
	 * here.
	 */
	if (tls->negotiated_version >= TLS_V12) {
		signature_hash_ptr = ptr;
		ptr += 2;

		for (i = 0; i < L_ARRAY_SIZE(tls_signature_hash_pref); i++) {
			*ptr++ = tls_signature_hash_pref[i].hash_id;
			*ptr++ = tls_signature_hash_pref[i].signature_id;
		}

		l_put_be16(ptr - (signature_hash_ptr + 2), signature_hash_ptr);
	}

	dn_ptr = ptr;
	ptr += 2;			/* Leave space for the total DN size */

	for (entry = l_queue_get_entries(tls->ca_certs); entry;
			entry = entry->next) {
		struct l_cert *ca_cert = entry->data;
		size_t dn_size;
		const uint8_t *dn = l_cert_get_dn(ca_cert, &dn_size);
		uint8_t *cur_dn_ptr = ptr;

		if (!dn)
			continue;

		ptr += 2;		/* Leave space for current DN size */
		*ptr++ = ASN1_ID_SEQUENCE;	/* DER outer SEQUENCE tag */
		asn1_write_definite_length(&ptr, dn_size); /* length */
		memcpy(ptr, dn, dn_size);	/* value */
		ptr += dn_size;
		l_put_be16(ptr - cur_dn_ptr - 2, cur_dn_ptr);
	}

	l_put_be16(ptr - dn_ptr - 2, dn_ptr);	/* DistinguishedNames size */

	tls_tx_handshake(tls, TLS_CERTIFICATE_REQUEST, buf, ptr - buf);

	l_free(buf);

	return true;
}

static void tls_send_server_hello_done(struct l_tls *tls)
{
	uint8_t buf[32];

	/* No body */

	tls_tx_handshake(tls, TLS_SERVER_HELLO_DONE, buf,
				TLS_HANDSHAKE_HEADER_SIZE);
}

static void tls_generate_master_secret(struct l_tls *tls,
					const uint8_t *pre_master_secret,
					int pre_master_secret_len)
{
	uint8_t seed[64];
	int key_block_size;

	memcpy(seed +  0, tls->pending.client_random, 32);
	memcpy(seed + 32, tls->pending.server_random, 32);

	tls_prf_get_bytes(tls, pre_master_secret, pre_master_secret_len,
				"master secret", seed, 64,
				tls->pending.master_secret, 48);

	/* Directly generate the key block while we're at it */
	key_block_size = 0;

	if (tls->pending.cipher_suite->encryption)
		key_block_size += 2 *
			tls->pending.cipher_suite->encryption->key_length;

	if (tls->pending.cipher_suite->mac)
		key_block_size += 2 *
			tls->pending.cipher_suite->mac->mac_length;

	if (tls->pending.cipher_suite->encryption &&
			tls->negotiated_version <= TLS_V10 &&
			tls->pending.cipher_suite->encryption->cipher_type ==
			TLS_CIPHER_BLOCK)
		key_block_size += 2 *
			tls->pending.cipher_suite->encryption->iv_length;

	if (tls->pending.cipher_suite->encryption)
		key_block_size += 2 * tls->pending.cipher_suite->encryption->
			fixed_iv_length;

	/* Reverse order from the master secret seed */
	memcpy(seed +  0, tls->pending.server_random, 32);
	memcpy(seed + 32, tls->pending.client_random, 32);

	tls_prf_get_bytes(tls, tls->pending.master_secret, 48,
				"key expansion", seed, 64,
				tls->pending.key_block, key_block_size);

	memset(seed, 0, 64);
}

static bool tls_send_rsa_client_key_xchg(struct l_tls *tls)
{
	uint8_t buf[1024 + 32];
	uint8_t *ptr = buf + TLS_HANDSHAKE_HEADER_SIZE;
	uint8_t pre_master_secret[48];
	ssize_t bytes_encrypted;

	if (!tls->peer_pubkey) {
		TLS_DISCONNECT(TLS_ALERT_INTERNAL_ERROR, 0,
				"Peer public key not received");

		return false;
	}

	pre_master_secret[0] = (uint8_t) (TLS_VERSION >> 8);
	pre_master_secret[1] = (uint8_t) (TLS_VERSION >> 0);
	l_getrandom(pre_master_secret + 2, 46);

	if (tls->peer_pubkey_size + 32 > (int) sizeof(buf)) {
		TLS_DISCONNECT(TLS_ALERT_INTERNAL_ERROR, 0,
				"Peer public key too big: %zi",
				tls->peer_pubkey_size);

		return false;
	}

	l_put_be16(tls->peer_pubkey_size, ptr);
	bytes_encrypted = l_key_encrypt(tls->peer_pubkey,
					L_KEY_RSA_PKCS1_V1_5, L_CHECKSUM_NONE,
					pre_master_secret, ptr + 2, 48,
					tls->peer_pubkey_size);
	ptr += tls->peer_pubkey_size + 2;

	if (bytes_encrypted != (ssize_t) tls->peer_pubkey_size) {
		TLS_DISCONNECT(TLS_ALERT_INTERNAL_ERROR, 0,
				"Encrypting PreMasterSecret failed: %s",
				strerror(-bytes_encrypted));

		return false;
	}

	tls_tx_handshake(tls, TLS_CLIENT_KEY_EXCHANGE, buf, ptr - buf);

	tls_generate_master_secret(tls, pre_master_secret, 48);
	memset(pre_master_secret, 0, 48);

	return true;
}

static ssize_t tls_rsa_sign(struct l_tls *tls, uint8_t *out, size_t len,
				tls_get_hash_t get_hash)
{
	ssize_t result;
	const struct tls_hash_algorithm *hash_type;
	uint8_t hash[HANDSHAKE_HASH_MAX_SIZE];
	uint8_t sign_input[HANDSHAKE_HASH_MAX_SIZE * 2 + 32];
	size_t sign_input_len;
	bool prepend_hash_type = false;
	size_t expected_bytes;

	if (!tls->priv_key || !tls->priv_key_size) {
		TLS_DISCONNECT(TLS_ALERT_INTERNAL_ERROR, TLS_ALERT_BAD_CERT,
				"No private key loaded");

		return -ENOKEY;
	}

	expected_bytes = tls->priv_key_size + 2;

	if (tls->negotiated_version >= TLS_V12) {
		hash_type = &tls_handshake_hash_data[tls->signature_hash];
		get_hash(tls, hash_type->tls_id, hash, NULL, NULL);

		pkcs1_write_digest_info(hash_type->l_id,
					sign_input, &sign_input_len,
					hash, hash_type->length);

		prepend_hash_type = true;
		expected_bytes += 2;
	} else {
		get_hash(tls, 1, sign_input + 0, NULL, NULL);	/* MD5 */
		get_hash(tls, 2, sign_input + 16, NULL, NULL);	/* SHA1 */
		sign_input_len = 36;
	}

	result = -EMSGSIZE;

	if (len >= expected_bytes) {
		if (prepend_hash_type) {
			*out++ = hash_type->tls_id;
			*out++ = 1;	/* RSA_sign */
		}

		l_put_be16(tls->priv_key_size, out);
		result = l_key_sign(tls->priv_key, L_KEY_RSA_PKCS1_V1_5,
					L_CHECKSUM_NONE, sign_input, out + 2,
					sign_input_len, tls->priv_key_size);

		if (result == (ssize_t) tls->priv_key_size)
			result = expected_bytes;
	}

	if (result < 0)
		TLS_DISCONNECT(TLS_ALERT_INTERNAL_ERROR, 0,
				"Signing the hash failed: %s",
				strerror(-result));

	return result;
}

static bool tls_rsa_verify(struct l_tls *tls, const uint8_t *in, size_t len,
				tls_get_hash_t get_hash)
{
	uint8_t hash[HANDSHAKE_HASH_MAX_SIZE];
	size_t hash_len;
	enum l_checksum_type hash_type;
	uint8_t expected[HANDSHAKE_HASH_MAX_SIZE * 2 + 32];
	size_t expected_len;
	unsigned int offset;
	bool success;

	/* 2 bytes for SignatureAndHashAlgorithm if version >= 1.2 */
	offset = 2;
	if (tls->negotiated_version < TLS_V12)
		offset = 0;

	if (len < offset + 2 ||
			(size_t) l_get_be16(in + offset) + offset + 2 != len) {
		TLS_DISCONNECT(TLS_ALERT_DECODE_ERROR, 0, "Signature msg too "
				"short (%zi) or signature length doesn't match",
				len);

		return false;
	}

	/* Only the default hash type supported */
	if (len != offset + 2 + tls->peer_pubkey_size) {
		TLS_DISCONNECT(TLS_ALERT_DECODE_ERROR, 0,
				"Signature length %zi not equal %zi", len,
				offset + 2 + tls->peer_pubkey_size);

		return false;
	}

	if (tls->negotiated_version >= TLS_V12) {
		/* Only RSA supported */
		if (in[1] != 1 /* RSA_sign */) {
			TLS_DISCONNECT(TLS_ALERT_DECRYPT_ERROR, 0,
					"Unknown signature algorithm %i",
					in[1]);

			return false;
		}

		if (!get_hash(tls, in[0], hash, &hash_len, &hash_type)) {
			TLS_DISCONNECT(TLS_ALERT_DECRYPT_ERROR, 0,
					"Unknown hash type %i", in[0]);

			return false;
		}

		/*
		 * TODO: According to 4.7 we need to support at least two forms
		 * of the signed content in the verification:
		 *  - DigestInfo with NULL AlgorithmIdentifier.parameters,
		 *  - DigestInfo with empty AlgorithmIdentifier.parameters.
		 *
		 * Additionally PKCS#1 now says BER is used in place of DER for
		 * DigestInfo encoding which adds more ambiguity in the
		 * encoding.
		 */
		pkcs1_write_digest_info(hash_type, expected, &expected_len,
					hash, hash_len);
	} else {
		get_hash(tls, 1, expected + 0, NULL, NULL);	/* MD5 */
		get_hash(tls, 2, expected + 16, NULL, NULL);	/* SHA1 */
		expected_len = 36;

		/*
		 * Within the RSA padding for signatures PKCS#1 1.5 allows
		 * the block format to be either 0 or 1, while PKCS#1 2.0
		 * mandates block type 1 making the signatures unambiguous.
		 * The l_asymmetric_cipher_verify implementation only
		 * accepts block type 1.
		 * TODO: TLS 1.0 doesn't specify that block type must be 1
		 * like TLS 1.2 does meaning that both PKCS#1 1.5 types are
		 * probably allowed.
		 */
	}

	success = l_key_verify(tls->peer_pubkey, L_KEY_RSA_PKCS1_V1_5,
				L_CHECKSUM_NONE, expected, in + 4,
				expected_len, tls->peer_pubkey_size);

	if (!success)
		TLS_DISCONNECT(TLS_ALERT_DECRYPT_ERROR, 0,
				"Peer signature verification failed");
	else
		TLS_DEBUG("Peer signature verified");

	return success;
}

static void tls_get_handshake_hash(struct l_tls *tls,
					enum handshake_hash_type type,
					uint8_t *out)
{
	struct l_checksum *hash = l_checksum_clone(tls->handshake_hash[type]);

	if (!hash)
		return;

	l_checksum_get_digest(hash, out, tls_handshake_hash_data[type].length);

	l_checksum_free(hash);
}

static bool tls_get_handshake_hash_by_id(struct l_tls *tls, uint8_t hash_id,
					uint8_t *out, size_t *len,
					enum l_checksum_type *type)
{
	enum handshake_hash_type hash;

	for (hash = 0; hash < __HANDSHAKE_HASH_COUNT; hash++)
		if (tls_handshake_hash_data[hash].tls_id == hash_id &&
				tls->handshake_hash[hash]) {
			tls_get_handshake_hash(tls, hash, out);

			if (len)
				*len = tls_handshake_hash_data[hash].length;

			if (type)
				*type = tls_handshake_hash_data[hash].l_id;

			return true;
		}

	return false;
}

static bool tls_send_certificate_verify(struct l_tls *tls)
{
	uint8_t buf[2048];
	int i;
	ssize_t sign_len;

	/* Fill in the Certificate Verify body */

	sign_len = tls->pending.cipher_suite->key_xchg->sign(tls,
					buf + TLS_HANDSHAKE_HEADER_SIZE,
					2048 - TLS_HANDSHAKE_HEADER_SIZE,
					tls_get_handshake_hash_by_id);

	if (sign_len < 0)
		return false;

	/* Stop maintaining handshake message hashes other than the PRF hash */
	if (tls->negotiated_version >= TLS_V12)
		for (i = 0; i < __HANDSHAKE_HASH_COUNT; i++)
			if (&tls_handshake_hash_data[i] != tls->prf_hmac)
				tls_drop_handshake_hash(tls, i);

	tls_tx_handshake(tls, TLS_CERTIFICATE_VERIFY, buf,
				sign_len + TLS_HANDSHAKE_HEADER_SIZE);

	return true;
}

static void tls_send_change_cipher_spec(struct l_tls *tls)
{
	uint8_t buf = 1;

	tls_tx_record(tls, TLS_CT_CHANGE_CIPHER_SPEC, &buf, 1);
}

static void tls_send_finished(struct l_tls *tls)
{
	uint8_t buf[512];
	uint8_t *ptr = buf + TLS_HANDSHAKE_HEADER_SIZE;
	uint8_t seed[HANDSHAKE_HASH_MAX_SIZE * 2];
	size_t seed_len;

	if (tls->negotiated_version >= TLS_V12) {
		/* Same hash type as that used for the PRF (usually SHA256) */
		enum handshake_hash_type hash;

		for (hash = 0; hash < __HANDSHAKE_HASH_COUNT; hash++)
			if (&tls_handshake_hash_data[hash] == tls->prf_hmac)
				break;

		tls_get_handshake_hash(tls, hash, seed);
		seed_len = tls_handshake_hash_data[hash].length;
	} else {
		tls_get_handshake_hash(tls, HANDSHAKE_HASH_MD5, seed + 0);
		tls_get_handshake_hash(tls, HANDSHAKE_HASH_SHA1, seed + 16);
		seed_len = 36;
	}

	tls_prf_get_bytes(tls, tls->pending.master_secret, 48,
				tls->server ? "server finished" :
				"client finished",
				seed, seed_len,
				ptr, tls->cipher_suite[1]->verify_data_length);
	ptr += tls->cipher_suite[1]->verify_data_length;

	tls_tx_handshake(tls, TLS_FINISHED, buf, ptr - buf);
}

static bool tls_verify_finished(struct l_tls *tls, const uint8_t *received,
				size_t len)
{
	uint8_t expected[tls->cipher_suite[0]->verify_data_length];
	uint8_t *seed;
	size_t seed_len;

	if (len != (size_t) tls->cipher_suite[0]->verify_data_length) {
		TLS_DISCONNECT(TLS_ALERT_DECODE_ERROR, 0,
				"TLS_FINISHED length not %i",
				tls->cipher_suite[0]->verify_data_length);

		return false;
	}

	if (tls->negotiated_version >= TLS_V12) {
		enum handshake_hash_type hash;

		for (hash = 0; hash < __HANDSHAKE_HASH_COUNT; hash++)
			if (&tls_handshake_hash_data[hash] == tls->prf_hmac)
				break;

		seed = tls->prev_digest[hash];
		seed_len = tls_handshake_hash_data[hash].length;
	} else {
		seed = alloca(36);
		memcpy(seed + 0, tls->prev_digest[HANDSHAKE_HASH_MD5], 16);
		memcpy(seed + 16, tls->prev_digest[HANDSHAKE_HASH_SHA1], 20);
		seed_len = 36;
	}

	tls_prf_get_bytes(tls, tls->pending.master_secret, 48,
				tls->server ? "client finished" :
				"server finished",
				seed, seed_len,
				expected,
				tls->cipher_suite[0]->verify_data_length);

	if (memcmp(received, expected, len)) {
		TLS_DISCONNECT(TLS_ALERT_DECRYPT_ERROR, 0,
				"TLS_FINISHED contents don't match");

		return false;
	}

	return true;
}

static void tls_handle_client_hello(struct l_tls *tls,
					const uint8_t *buf, size_t len)
{
	uint16_t cipher_suites_size;
	uint8_t session_id_size, compression_methods_size;
	const uint8_t *cipher_suites;
	const uint8_t *compression_methods;
	int i;

	/* Do we have enough for ProtocolVersion + Random + SessionID size? */
	if (len < 2 + 32 + 1)
		goto decode_error;

	memcpy(tls->pending.client_random, buf + 2, 32);
	session_id_size = buf[34];
	len -= 35;

	/*
	 * Do we have enough to hold the actual session ID + 2 byte field for
	 * cipher_suite len + minimum of a single cipher suite identifier
	 */
	if (len < (size_t) session_id_size + 4)
		goto decode_error;

	len -= session_id_size + 2;

	cipher_suites_size = l_get_be16(buf + 35 + session_id_size);
	cipher_suites = buf + 37 + session_id_size;

	/*
	 * Check that size is not odd, more than 0 and we have enough
	 * data in the packet for cipher_suites_size + 2 bytes for
	 * compression_methods_size + a single compression method
	 */
	if (len < (size_t) cipher_suites_size + 2 ||
			(cipher_suites_size & 1) || cipher_suites_size == 0)
		goto decode_error;

	len -= cipher_suites_size + 1;

	compression_methods_size = cipher_suites[cipher_suites_size];
	compression_methods = cipher_suites + cipher_suites_size + 1;

	if (len < (size_t) compression_methods_size ||
			compression_methods_size == 0)
		goto decode_error;

	len -= compression_methods_size;

	if (len) {
		uint16_t extensions_size;

		if (len < 2 || len > 2 + 65535)
			goto decode_error;

		extensions_size = l_get_be16(compression_methods +
						compression_methods_size);
		len -= 2;

		if (len != extensions_size)
			goto decode_error;

		/* TODO: validate each extension in the vector, 7.4.1.4 */
		/* TODO: check for duplicates? */
	}

	/*
	 * Note: if the client is supplying a SessionID we know it is false
	 * because our server implementation never generates any SessionIDs
	 * yet so either the client is attempting something strange or was
	 * trying to connect somewhere else.  We might want to throw an error.
	 */

	/*
	 * TODO: Obligatory in 1.2: check for signature_algorithms extension,
	 * store the list of algorithms for later checking in
	 * tls_send_certificate on both server and client sides.  If not
	 * present assume only SHA1+RSA (7.4.1.4.1).
	 */

	/* Save client_version for Premaster Secret verification */
	tls->client_version = l_get_be16(buf);

	if (tls->client_version < TLS_MIN_VERSION) {
		TLS_DISCONNECT(TLS_ALERT_PROTOCOL_VERSION, 0,
				"Client version too low: %02x",
				tls->client_version);
		return;
	}

	tls->negotiated_version = TLS_VERSION < tls->client_version ?
		TLS_VERSION : tls->client_version;

	/* Stop maintaining handshake message hashes other than MD1 and SHA. */
	if (tls->negotiated_version < TLS_V12)
		for (i = 0; i < __HANDSHAKE_HASH_COUNT; i++)
			if (i != HANDSHAKE_HASH_SHA1 && i != HANDSHAKE_HASH_MD5)
				tls_drop_handshake_hash(tls, i);

	TLS_DEBUG("Negotiated TLS 1.%i", (tls->negotiated_version & 0xff) - 1);

	/* Select a cipher suite according to client's preference list */
	while (cipher_suites_size) {
		struct tls_cipher_suite *suite =
			tls_find_cipher_suite(cipher_suites);

		if (suite && tls_cipher_suite_is_compatible(tls, suite, NULL)) {
			tls->pending.cipher_suite = suite;
			break;
		}

		cipher_suites += 2;
		cipher_suites_size -= 2;
	}

	if (!cipher_suites_size) {
		TLS_DISCONNECT(TLS_ALERT_HANDSHAKE_FAIL, 0,
				"No common cipher suites matching negotiated "
				"TLS version and our certificate's key type");
		return;
	}

	if (!tls_set_prf_hmac(tls)) {
		TLS_DISCONNECT(TLS_ALERT_INTERNAL_ERROR, 0,
				"Error selecting the PRF HMAC");
		return;
	}

	TLS_DEBUG("Negotiated %s", tls->pending.cipher_suite->name);

	/* Select a compression method */

	/* CompressionMethod.null must be present in the vector */
	if (!memchr(compression_methods, 0, compression_methods_size)) {
		TLS_DISCONNECT(TLS_ALERT_HANDSHAKE_FAIL, 0,
				"No common compression methods");
		return;
	}

	while (compression_methods_size) {
		tls->pending.compression_method =
			tls_find_compression_method(*compression_methods);

		if (tls->pending.compression_method)
			break;

		compression_methods++;
		compression_methods_size--;
	}

	TLS_DEBUG("Negotiated %s", tls->pending.compression_method->name);

	tls_send_server_hello(tls);

	if (tls->pending.cipher_suite->key_xchg->certificate_check && tls->cert)
		if (!tls_send_certificate(tls))
			return;

	/* TODO: don't bother if configured to not authenticate client */
	if (tls->pending.cipher_suite->key_xchg->certificate_check &&
			tls->ca_certs)
		if (!tls_send_certificate_request(tls))
			return;

	tls_send_server_hello_done(tls);

	if (tls->pending.cipher_suite->key_xchg->certificate_check &&
			tls->ca_certs)
		TLS_SET_STATE(TLS_HANDSHAKE_WAIT_CERTIFICATE);
	else
		TLS_SET_STATE(TLS_HANDSHAKE_WAIT_KEY_EXCHANGE);

	return;

decode_error:
	TLS_DISCONNECT(TLS_ALERT_DECODE_ERROR, 0,
			"ClientHello decode error");
}

static void tls_handle_server_hello(struct l_tls *tls,
					const uint8_t *buf, size_t len)
{
	uint8_t session_id_size, cipher_suite_id[2], compression_method_id;
	const char *error;
	int i;

	/* Do we have enough for ProtocolVersion + Random + SessionID len ? */
	if (len < 2 + 32 + 1)
		goto decode_error;

	memcpy(tls->pending.server_random, buf + 2, 32);
	session_id_size = buf[34];
	len -= 35;

	/* Do we have enough for SessionID + CipherSuite ID + Compression ID */
	if (len < (size_t) session_id_size + 2 + 1)
		goto decode_error;

	cipher_suite_id[0] = buf[35 + session_id_size + 0];
	cipher_suite_id[1] = buf[35 + session_id_size + 1];
	compression_method_id = buf[35 + session_id_size + 2];
	len -= session_id_size + 2 + 1;

	if (len != 0) { /* We know we haven't solicited any extensions */
		TLS_DISCONNECT(TLS_ALERT_UNSUPPORTED_EXTENSION, 0,
				"ServerHello contains extensions");
		return;
	}

	tls->negotiated_version = l_get_be16(buf);

	if (tls->negotiated_version < TLS_MIN_VERSION ||
			tls->negotiated_version > TLS_VERSION) {
		TLS_DISCONNECT(tls->negotiated_version < TLS_MIN_VERSION ?
				TLS_ALERT_PROTOCOL_VERSION :
				TLS_ALERT_ILLEGAL_PARAM, 0,
				"Unsupported version %02x",
				tls->negotiated_version);
		return;
	}

	/* Stop maintaining handshake message hashes other than MD1 and SHA. */
	if (tls->negotiated_version < TLS_V12)
		for (i = 0; i < __HANDSHAKE_HASH_COUNT; i++)
			if (i != HANDSHAKE_HASH_SHA1 && i != HANDSHAKE_HASH_MD5)
				tls_drop_handshake_hash(tls, i);

	TLS_DEBUG("Negotiated TLS 1.%i", (tls->negotiated_version & 0xff) - 1);

	/* Set the new cipher suite and compression method structs */
	tls->pending.cipher_suite = tls_find_cipher_suite(cipher_suite_id);
	if (!tls->pending.cipher_suite) {
		TLS_DISCONNECT(TLS_ALERT_HANDSHAKE_FAIL, 0,
				"Unknown cipher suite %04x",
				l_get_be16(cipher_suite_id));
		return;
	}

	if (!tls_cipher_suite_is_compatible(tls, tls->pending.cipher_suite,
						&error)) {
		TLS_DISCONNECT(TLS_ALERT_HANDSHAKE_FAIL, 0,
				"Selected cipher suite not compatible: %s",
				error);
		return;
	}

	if (!tls_set_prf_hmac(tls)) {
		TLS_DISCONNECT(TLS_ALERT_INTERNAL_ERROR, 0,
				"Error selecting the PRF HMAC");
		return;
	}

	TLS_DEBUG("Negotiated %s", tls->pending.cipher_suite->name);

	tls->pending.compression_method =
		tls_find_compression_method(compression_method_id);
	if (!tls->pending.compression_method) {
		TLS_DISCONNECT(TLS_ALERT_HANDSHAKE_FAIL, 0,
				"Unknown compression method %i",
				compression_method_id);
		return;
	}

	TLS_DEBUG("Negotiated %s", tls->pending.compression_method->name);

	if (tls->pending.cipher_suite->key_xchg->certificate_check)
		TLS_SET_STATE(TLS_HANDSHAKE_WAIT_CERTIFICATE);
	else
		TLS_SET_STATE(TLS_HANDSHAKE_WAIT_KEY_EXCHANGE);

	return;

decode_error:
	TLS_DISCONNECT(TLS_ALERT_DECODE_ERROR, 0,
			"ServerHello decode error");
}

static void tls_handle_certificate(struct l_tls *tls,
					const uint8_t *buf, size_t len)
{
	size_t total;
	struct l_certchain *certchain = NULL;
	struct l_cert *leaf;
	size_t der_len;
	const uint8_t *der;
	bool dummy;

	if (len < 3)
		goto decode_error;

	/* Length checks */
	total = *buf++ << 16;
	total |= *buf++ << 8;
	total |= *buf++ << 0;
	if (total + 3 != len)
		goto decode_error;

	if (tls_parse_certificate_list(buf, total, &certchain) < 0) {
		TLS_DISCONNECT(TLS_ALERT_DECODE_ERROR, 0,
				"Error decoding peer certificate chain");

		goto done;
	}

	/*
	 * "Note that a client MAY send no certificates if it does not have any
	 * appropriate certificate to send in response to the server's
	 * authentication request." -- for now we unconditionally accept
	 * an empty certificate chain from the client.  Later on we need to
	 * make this configurable, if we don't want to authenticate the
	 * client then also don't bother sending a Certificate Request.
	 */
	if (!certchain) {
		if (!tls->server) {
			TLS_DISCONNECT(TLS_ALERT_HANDSHAKE_FAIL, 0,
					"Server sent no certificate chain");

			goto done;
		}

		TLS_SET_STATE(TLS_HANDSHAKE_WAIT_KEY_EXCHANGE);

		goto done;
	}

	/*
	 * Validate the certificate chain's consistency and validate it
	 * against our CAs if we have any.
	 */
	if (!l_certchain_verify(certchain, tls->ca_certs)) {
		TLS_DISCONNECT(TLS_ALERT_BAD_CERT, 0,
				"Peer certchain verification failed "
				"consistency check%s", tls->ca_certs ?
				" or against local CA certs" : "");

		goto done;
	}

	/*
	 * RFC5246 7.4.2:
	 * "The end entity certificate's public key (and associated
	 * restrictions) MUST be compatible with the selected key exchange
	 * algorithm."
	 */
	leaf = l_certchain_get_leaf(certchain);
	if (!tls->pending.cipher_suite->key_xchg->
			validate_cert_key_type(leaf)) {
		TLS_DISCONNECT(TLS_ALERT_UNSUPPORTED_CERT, 0,
				"Peer certificate key type incompatible with "
				"pending cipher suite %s",
				tls->pending.cipher_suite->name);

		goto done;
	}

	/* Save the end-entity certificate and free the chain */
	der = l_cert_get_der_data(leaf, &der_len);
	tls->peer_cert = l_cert_new_from_der(der, der_len);

	tls->peer_pubkey = l_cert_get_pubkey(tls->peer_cert);
	if (!tls->peer_pubkey) {
		TLS_DISCONNECT(TLS_ALERT_UNSUPPORTED_CERT, 0,
				"Error loading peer public key to kernel");

		goto done;
	}

	if (!l_key_get_info(tls->peer_pubkey, L_KEY_RSA_PKCS1_V1_5,
					L_CHECKSUM_NONE, &tls->peer_pubkey_size,
					&dummy)) {
		TLS_DISCONNECT(TLS_ALERT_INTERNAL_ERROR, 0,
				"Can't l_key_get_info for peer public key");

		goto done;
	}

	tls->peer_pubkey_size /= 8;

	if (tls->server)
		TLS_SET_STATE(TLS_HANDSHAKE_WAIT_KEY_EXCHANGE);
	else
		TLS_SET_STATE(TLS_HANDSHAKE_WAIT_HELLO_DONE);

	goto done;

decode_error:
	TLS_DISCONNECT(TLS_ALERT_DECODE_ERROR, 0,
			"TLS_CERTIFICATE decode error");

done:
	l_certchain_free(certchain);
}

static void tls_handle_certificate_request(struct l_tls *tls,
						const uint8_t *buf, size_t len)
{
	int cert_type_len, signature_hash_len, dn_len, i;
	enum handshake_hash_type first_supported, hash;
	const uint8_t *signature_hash_data;
	uint8_t hash_id;

	tls->cert_requested = 1;

	cert_type_len = *buf++;
	if (len < (size_t) 1 + cert_type_len + 2)
		goto decode_error;

	/* Skip certificate_types */
	buf += cert_type_len;
	len -= 1 + cert_type_len;

	/*
	 * TODO: parse and save certificate_types,
	 * supported_signature_algorithms and certificate_authorities
	 * lists for use in tls_send_certificate.
	 */

	if (tls->negotiated_version >= TLS_V12) {
		/*
		 * This only makes sense as a variable-length field, assume
		 * there's a typo in RFC5246 7.4.4 here.
		 */
		signature_hash_len = l_get_be16(buf);
		signature_hash_data = buf + 2;

		if (len < (size_t) 2 + signature_hash_len + 2 ||
				(signature_hash_len & 1))
			goto decode_error;

		len -= 2 + signature_hash_len;
		buf += 2 + signature_hash_len;

		/*
		 * In 1.2 SHA256 is the default because that is most likely
		 * to be supported in all the scenarios and optimal because
		 * SHA256 is required independently for the Finished hash
		 * meaning that we'll just need one hash type instead of
		 * two.  If not available fall back to the first common
		 * hash algorithm.
		 */
		first_supported = -1;

		for (i = 0; i < signature_hash_len; i += 2) {
			hash_id = signature_hash_data[i + 0];

			/* Ignore hash types for signatures other than ours */
			if (signature_hash_data[i + 1] != tls_rsa.id)
				continue;

			if (hash_id == tls_handshake_hash_data[
						HANDSHAKE_HASH_SHA256].tls_id)
				break;

			if ((int) first_supported != -1)
				continue;

			for (hash = 0; hash < __HANDSHAKE_HASH_COUNT; hash++)
				if (hash_id == tls_handshake_hash_data[hash].
						tls_id &&
						tls->handshake_hash[hash]) {
					first_supported = hash;
					break;
				}
		}

		if (i < signature_hash_len)
			tls->signature_hash = HANDSHAKE_HASH_SHA256;
		else if ((int) first_supported != -1)
			tls->signature_hash = first_supported;
		else {
			TLS_DISCONNECT(TLS_ALERT_UNSUPPORTED_CERT, 0,
					"No supported signature hash type");

			return;
		}

		/*
		 * We can now safely stop maintaining handshake message
		 * hashes other than the PRF hash and the one selected for
		 * signing.
		 */
		for (hash = 0; hash < __HANDSHAKE_HASH_COUNT; hash++)
			if (&tls_handshake_hash_data[hash] != tls->prf_hmac &&
					hash != tls->signature_hash)
				tls_drop_handshake_hash(tls, hash);
	}

	dn_len = l_get_be16(buf);
	if ((size_t) 2 + dn_len != len)
		goto decode_error;

	return;

decode_error:
	TLS_DISCONNECT(TLS_ALERT_DECODE_ERROR, 0,
			"CertificateRequest decode error");
}

static void tls_handle_server_hello_done(struct l_tls *tls,
						const uint8_t *buf, size_t len)
{
	const char *error;

	if (len) {
		TLS_DISCONNECT(TLS_ALERT_DECODE_ERROR, 0,
				"ServerHello not empty");
		return;
	}

	if (tls->cert_requested)
		if (!tls_send_certificate(tls))
			return;

	if (!tls->pending.cipher_suite->key_xchg->send_client_key_exchange(tls))
		return;

	if (tls->cert_sent)
		if (!tls_send_certificate_verify(tls))
			return;

	tls_send_change_cipher_spec(tls);

	if (!tls_change_cipher_spec(tls, 1, &error)) {
		TLS_DISCONNECT(TLS_ALERT_INTERNAL_ERROR, 0,
				"change_cipher_spec: %s", error);
		return;
	}

	tls_send_finished(tls);

	TLS_SET_STATE(TLS_HANDSHAKE_WAIT_CHANGE_CIPHER_SPEC);
}

static void tls_handle_rsa_client_key_xchg(struct l_tls *tls,
						const uint8_t *buf, size_t len)
{
	uint8_t pre_master_secret[48], random_secret[46];
	ssize_t bytes_decrypted;

	if (!tls->priv_key || !tls->priv_key_size) {
		TLS_DISCONNECT(TLS_ALERT_INTERNAL_ERROR, TLS_ALERT_BAD_CERT,
				"No private key");

		return;
	}

	if (len != tls->priv_key_size + 2) {
		TLS_DISCONNECT(TLS_ALERT_DECODE_ERROR, 0,
				"ClientKeyExchange len %zi not %zi", len,
				tls->priv_key_size + 2);

		return;
	}

	len = l_get_be16(buf);

	if (len != tls->priv_key_size) {
		TLS_DISCONNECT(TLS_ALERT_DECODE_ERROR, 0,
				"EncryptedPreMasterSecret len %zi not %zi",
				len, tls->priv_key_size);

		return;
	}

	bytes_decrypted = l_key_decrypt(tls->priv_key, L_KEY_RSA_PKCS1_V1_5,
					L_CHECKSUM_NONE, buf + 2,
					pre_master_secret, tls->priv_key_size,
					48);

	/*
	 * Assume correct premaster secret client version which according
	 * to the TLS1.2 spec is unlikely in client implementations SSLv3
	 * and prior.  Spec suggests either not supporting them or adding
	 * a configurable override for <= SSLv3 clients.  For now we have
	 * no need to support them.
	 *
	 * On any decode error randomise the Pre Master Secret as per the
	 * countermeasures in 7.4.7.1 and don't generate any alerts.
	 */
	l_getrandom(random_secret, 46);

	pre_master_secret[0] = tls->client_version >> 8;
	pre_master_secret[1] = tls->client_version >> 0;

	if (bytes_decrypted != 48) {
		memcpy(pre_master_secret + 2, random_secret, 46);

		TLS_DEBUG("Error decrypting PreMasterSecret: %s",
				strerror(-bytes_decrypted));
	}

	tls_generate_master_secret(tls, pre_master_secret, 48);
	memset(pre_master_secret, 0, 48);
	memset(random_secret, 0, 46);
}

static bool tls_get_prev_digest_by_id(struct l_tls *tls, uint8_t hash_id,
					uint8_t *out, size_t *out_len,
					enum l_checksum_type *type)
{
	enum handshake_hash_type hash;
	size_t len;

	for (hash = 0; hash < __HANDSHAKE_HASH_COUNT; hash++)
		if (tls_handshake_hash_data[hash].tls_id == hash_id &&
				tls->handshake_hash[hash]) {
			len = tls_handshake_hash_data[hash].length;
			memcpy(out, tls->prev_digest[hash], len);

			if (out_len)
				*out_len = len;

			if (type)
				*type = tls_handshake_hash_data[hash].l_id;

			return len;
		}

	return 0;
}

static void tls_handle_certificate_verify(struct l_tls *tls,
						const uint8_t *buf, size_t len)
{
	int i;

	if (!tls->pending.cipher_suite->key_xchg->verify(tls, buf, len,
						tls_get_prev_digest_by_id))
		return;

	/* Stop maintaining handshake message hashes other than the PRF hash */
	if (tls->negotiated_version >= TLS_V12)
		for (i = 0; i < __HANDSHAKE_HASH_COUNT; i++)
			if (&tls_handshake_hash_data[i] != tls->prf_hmac)
				tls_drop_handshake_hash(tls, i);

	/*
	 * The client's certificate is now verified based on the following
	 * logic:
	 *   - If we received an (expected) Certificate Verify, we must have
	 *     sent a Certificate Request.
	 *   - If we sent a Certificate Request that's because
	 *     tls->ca_certs is non-NULL.
	 *   - If tls->ca_certs is non-NULL then tls_handle_certificate
	 *     will have checked the whole certificate chain to be valid and
	 *     additionally trusted by our CAs if known.
	 *   - Additionally cipher_suite->key_xchg->verify has just confirmed
	 *     that the peer owns the end-entity certificate because it was
	 *     able to sign the contents of the handshake messages and that
	 *     signature could be verified with the public key from that
	 *     certificate.
	 */
	tls->peer_authenticated = true;

	TLS_SET_STATE(TLS_HANDSHAKE_WAIT_CHANGE_CIPHER_SPEC);
}

static const struct asn1_oid dn_organization_name_oid =
	{ 3, { 0x55, 0x04, 0x0a } };
static const struct asn1_oid dn_common_name_oid =
	{ 3, { 0x55, 0x04, 0x03 } };

static char *tls_get_peer_identity_str(struct l_cert *cert)
{
	const uint8_t *dn, *end;
	size_t dn_size;
	const uint8_t *printable_str = NULL;
	size_t printable_str_len;

	if (!cert)
		return NULL;

	dn = l_cert_get_dn(cert, &dn_size);
	if (!dn)
		return NULL;

	end = dn + dn_size;
	while (dn < end) {
		const uint8_t *set, *seq, *oid, *name;
		uint8_t tag;
		size_t len, oid_len, name_len;

		set = asn1_der_find_elem(dn, end - dn, 0, &tag, &len);
		if (!set || tag != ASN1_ID_SET)
			return NULL;

		dn = set + len;

		seq = asn1_der_find_elem(set, len, 0, &tag, &len);
		if (!seq || tag != ASN1_ID_SEQUENCE)
			return NULL;

		oid = asn1_der_find_elem(seq, len, 0, &tag, &oid_len);
		if (!oid || tag != ASN1_ID_OID)
			return NULL;

		name = asn1_der_find_elem(seq, len, 1, &tag, &name_len);
		if (!oid || (tag != ASN1_ID_PRINTABLESTRING &&
					tag != ASN1_ID_UTF8STRING))
			continue;

		/* organizationName takes priority, commonName is second */
		if (asn1_oid_eq(&dn_organization_name_oid, oid_len, oid) ||
				(!printable_str &&
				 asn1_oid_eq(&dn_common_name_oid,
						oid_len, oid))) {
			printable_str = name;
			printable_str_len = name_len;
		}
	}

	if (printable_str)
		return l_strndup((char *) printable_str, printable_str_len);
	else
		return NULL;
}

static void tls_finished(struct l_tls *tls)
{
	char *peer_identity = NULL;

	if (tls->peer_authenticated) {
		peer_identity = tls_get_peer_identity_str(tls->peer_cert);
		if (!peer_identity)
			TLS_DEBUG("tls_get_peer_identity_str failed");
	}

	/* Free up the resources used in the handshake */
	tls_reset_handshake(tls);

	TLS_SET_STATE(TLS_HANDSHAKE_DONE);
	tls->ready = true;

	tls->ready_handle(peer_identity, tls->user_data);
	l_free(peer_identity);

	tls_cleanup_handshake(tls);
}

static void tls_handle_handshake(struct l_tls *tls, int type,
					const uint8_t *buf, size_t len)
{
	TLS_DEBUG("Handling a %s of %zi bytes",
			tls_handshake_type_to_str(type), len);

	switch (type) {
	case TLS_HELLO_REQUEST:
		if (tls->server) {
			TLS_DISCONNECT(TLS_ALERT_UNEXPECTED_MESSAGE, 0,
					"Message invalid in server mode");
			break;
		}

		if (len != 0) {
			TLS_DISCONNECT(TLS_ALERT_DECODE_ERROR, 0,
					"HelloRequest not empty");
			break;
		}

		/*
		 * May be sent by the server at any time but "SHOULD be ignored
		 * by the client if it arrives in the middle of a handshake"
		 * and "MAY be ignored by the client if it does not wish to
		 * renegotiate a session".
		 */

		break;

	case TLS_CLIENT_HELLO:
		if (!tls->server) {
			TLS_DISCONNECT(TLS_ALERT_UNEXPECTED_MESSAGE, 0,
					"Message invalid in client mode");
			break;
		}

		if (tls->state != TLS_HANDSHAKE_WAIT_HELLO &&
				tls->state != TLS_HANDSHAKE_DONE) {
			TLS_DISCONNECT(TLS_ALERT_UNEXPECTED_MESSAGE, 0,
					"Message invalid in state %s",
					tls_handshake_state_to_str(tls->state));
			break;
		}

		tls_handle_client_hello(tls, buf, len);

		break;

	case TLS_SERVER_HELLO:
		if (tls->server) {
			TLS_DISCONNECT(TLS_ALERT_UNEXPECTED_MESSAGE, 0,
					"Message invalid in server mode");
			break;
		}

		if (tls->state != TLS_HANDSHAKE_WAIT_HELLO) {
			TLS_DISCONNECT(TLS_ALERT_UNEXPECTED_MESSAGE, 0,
					"Message invalid in state %s",
					tls_handshake_state_to_str(tls->state));
			break;
		}

		tls_handle_server_hello(tls, buf, len);

		break;

	case TLS_CERTIFICATE:
		if (tls->state != TLS_HANDSHAKE_WAIT_CERTIFICATE) {
			TLS_DISCONNECT(TLS_ALERT_UNEXPECTED_MESSAGE, 0,
					"Message invalid in state %s",
					tls_handshake_state_to_str(tls->state));
			break;
		}

		tls_handle_certificate(tls, buf, len);

		break;

	case TLS_CERTIFICATE_REQUEST:
		/*
		 * Server sends this optionally so in the WAIT_HELLO_DONE
		 * state we accept either this or a Server Hello Done (below).
		 */
		if (tls->state != TLS_HANDSHAKE_WAIT_HELLO_DONE ||
				tls->cert_requested ||
				!tls->pending.cipher_suite->key_xchg->
				certificate_check) {
			TLS_DISCONNECT(TLS_ALERT_UNEXPECTED_MESSAGE, 0,
					"Message invalid in current state "
					"or certificate check not supported "
					"in pending cipher suite");
			break;
		}

		tls_handle_certificate_request(tls, buf, len);

		break;

	case TLS_SERVER_HELLO_DONE:
		if (tls->state != TLS_HANDSHAKE_WAIT_HELLO_DONE) {
			TLS_DISCONNECT(TLS_ALERT_UNEXPECTED_MESSAGE, 0,
					"Message invalid in state %s",
					tls_handshake_state_to_str(tls->state));
			break;
		}

		tls_handle_server_hello_done(tls, buf, len);

		break;

	case TLS_CERTIFICATE_VERIFY:
		if (tls->state != TLS_HANDSHAKE_WAIT_CERTIFICATE_VERIFY) {
			TLS_DISCONNECT(TLS_ALERT_UNEXPECTED_MESSAGE, 0,
					"Message invalid in state %s",
					tls_handshake_state_to_str(tls->state));
			break;
		}

		tls_handle_certificate_verify(tls, buf, len);

		break;

	case TLS_CLIENT_KEY_EXCHANGE:
		if (!tls->server) {
			TLS_DISCONNECT(TLS_ALERT_UNEXPECTED_MESSAGE, 0,
					"Message invalid in client mode");
			break;
		}

		if (tls->state != TLS_HANDSHAKE_WAIT_KEY_EXCHANGE) {
			TLS_DISCONNECT(TLS_ALERT_UNEXPECTED_MESSAGE, 0,
					"Message invalid in state %s",
					tls_handshake_state_to_str(tls->state));
			break;
		}

		tls->pending.cipher_suite->key_xchg->handle_client_key_exchange(
								tls, buf, len);

		/*
		 * If we accepted a client Certificate message with a
		 * certificate that has signing capability (TODO: check
		 * usage bitmask), Certiifcate Verify is received next.  It
		 * sounds as if this is mandatory for the client although
		 * this isn't 100% clear.
		 */
		if (tls->peer_pubkey)
			TLS_SET_STATE(TLS_HANDSHAKE_WAIT_CERTIFICATE_VERIFY);
		else
			TLS_SET_STATE(TLS_HANDSHAKE_WAIT_CHANGE_CIPHER_SPEC);

		break;

	case TLS_FINISHED:
		if (tls->state != TLS_HANDSHAKE_WAIT_FINISHED) {
			TLS_DISCONNECT(TLS_ALERT_UNEXPECTED_MESSAGE, 0,
					"Message invalid in state %s",
					tls_handshake_state_to_str(tls->state));
			break;
		}

		if (!tls_verify_finished(tls, buf, len))
			break;

		if (tls->server) {
			const char *error;

			tls_send_change_cipher_spec(tls);
			if (!tls_change_cipher_spec(tls, 1, &error)) {
				TLS_DISCONNECT(TLS_ALERT_INTERNAL_ERROR, 0,
						"change_cipher_spec: %s",
						error);
				break;
			}
			tls_send_finished(tls);
		}

		/*
		 * On the client, the server's certificate is only now
		 * verified, based on the following logic:
		 *  - tls->ca_certs is non-NULL so tls_handle_certificate
		 *    (always called on the client) must have veritifed the
		 *    server's certificate chain to be valid and additionally
		 *    trusted by our CA.
		 *  - the correct receival of this Finished message confirms
		 *    that the peer owns the end-entity certificate because
		 *    it was able to decrypt the master secret which we had
		 *    encrypted with the public key from that certificate, and
		 *    the posession of the master secret in turn is verified
		 *    by both the successful decryption and the MAC of this
		 *    message (either should be enough).
		 */
		if (!tls->server && tls->cipher_suite[0]->key_xchg->
				certificate_check && tls->ca_certs)
			tls->peer_authenticated = true;

		tls_finished(tls);

		break;

	default:
		TLS_DISCONNECT(TLS_ALERT_UNEXPECTED_MESSAGE, 0,
				"Invalid message");
	}
}

LIB_EXPORT struct l_tls *l_tls_new(bool server,
				l_tls_write_cb_t app_data_handler,
				l_tls_write_cb_t tx_handler,
				l_tls_ready_cb_t ready_handler,
				l_tls_disconnect_cb_t disconnect_handler,
				void *user_data)
{
	struct l_tls *tls;

	if (!l_key_is_supported(L_KEY_FEATURE_CRYPTO))
		return NULL;

	tls = l_new(struct l_tls, 1);
	tls->server = server;
	tls->rx = app_data_handler;
	tls->tx = tx_handler;
	tls->ready_handle = ready_handler;
	tls->disconnected = disconnect_handler;
	tls->user_data = user_data;

	tls->signature_hash = HANDSHAKE_HASH_SHA256;

	/* If we're the client, start the handshake right away */
	if (!tls->server) {
		if (!tls_init_handshake_hash(tls) ||
				!tls_send_client_hello(tls)) {
			l_free(tls);

			return NULL;
		}
	}

	TLS_SET_STATE(TLS_HANDSHAKE_WAIT_HELLO);

	return tls;
}

LIB_EXPORT void l_tls_free(struct l_tls *tls)
{
	enum handshake_hash_type hash;

	if (unlikely(!tls))
		return;

	l_tls_set_cacert(tls, NULL);
	l_tls_set_auth_data(tls, NULL, NULL, NULL);

	tls_reset_handshake(tls);
	tls_cleanup_handshake(tls);

	tls_reset_cipher_spec(tls, 0);
	tls_reset_cipher_spec(tls, 1);

	if (tls->record_buf)
		l_free(tls->record_buf);

	if (tls->message_buf)
		l_free(tls->message_buf);

	for (hash = 0; hash < __HANDSHAKE_HASH_COUNT; hash++)
		tls_drop_handshake_hash(tls, hash);

	if (tls->debug_destroy)
		tls->debug_destroy(tls->debug_data);

	l_free(tls);
}

LIB_EXPORT void l_tls_write(struct l_tls *tls, const uint8_t *data, size_t len)
{
	if (unlikely(!tls->ready)) {
		return;
	}

	tls_tx_record(tls, TLS_CT_APPLICATION_DATA, data, len);
}

bool tls_handle_message(struct l_tls *tls, const uint8_t *message,
			int len, enum tls_content_type type, uint16_t version)
{
	enum handshake_hash_type hash;
	const char *error;

	switch (type) {
	case TLS_CT_CHANGE_CIPHER_SPEC:
		if (len != 1 || message[0] != 0x01) {
			TLS_DISCONNECT(TLS_ALERT_DECODE_ERROR, 0,
					"ChangeCipherSpec msg decode error");

			return false;
		}

		if (tls->state != TLS_HANDSHAKE_WAIT_CHANGE_CIPHER_SPEC) {
			TLS_DISCONNECT(TLS_ALERT_UNEXPECTED_MESSAGE, 0,
					"ChangeCipherSpec invalid in state %s",
					tls_handshake_state_to_str(tls->state));

			return false;
		}

		if (!tls_change_cipher_spec(tls, 0, &error)) {
			TLS_DISCONNECT(TLS_ALERT_INTERNAL_ERROR, 0,
					"change_cipher_spec: %s", error);

			return false;
		}

		TLS_SET_STATE(TLS_HANDSHAKE_WAIT_FINISHED);

		return true;

	case TLS_CT_ALERT:
		/* Verify AlertLevel */
		if (message[0] != 0x01 && message[0] != 0x02) {
			TLS_DISCONNECT(TLS_ALERT_DECODE_ERROR, 0,
					"Received bad AlertLevel %i",
					message[0]);

			return false;
		}

		/*
		 * On a fatal alert we are obligated to respond with a
		 * fatal alert and disconnect but also not complain if
		 * the connection has been torn down by the peer before
		 * we were able to send our alert.  However on a non-fatal
		 * alert (warning) we're also allowed to panic and send
		 * a fatal alert, then disconnect, so we do that
		 * regardless of the alert level.
		 */
		TLS_DISCONNECT(TLS_ALERT_CLOSE_NOTIFY, message[1],
				"Peer sent a %s Alert: %s",
				message[0] == 0x02 ? "Fatal" : "Warning",
				l_tls_alert_to_str(message[1]));

		return false;

	case TLS_CT_HANDSHAKE:
		/* Start hashing the handshake contents on first message */
		if (tls->server && message[0] == TLS_CLIENT_HELLO &&
				(tls->state == TLS_HANDSHAKE_WAIT_HELLO ||
				 tls->state != TLS_HANDSHAKE_DONE))
			if (!tls_init_handshake_hash(tls))
				return false;

		/*
		 * Corner case: When handling a Certificate Verify or a
		 * Finished message we need access to the messages hash from
		 * before this message was transmitted on the Tx side so we
		 * can verify it matches the hash the sender included in the
		 * message.  We save it here for that purpose.  Everywhere
		 * else we need to update the hash before handling the new
		 * message because 1. we may need the new hash to build our
		 * own Certificate Verify or Finished messages, and 2. we
		 * update the message hash with newly transmitted messages
		 * inside tls_tx_handshake which may be called as part of
		 * handling incoming message, and if we didn't call
		 * l_checksum_update before, the calls would end up being
		 * out of order.
		 */
		if (message[0] == TLS_CERTIFICATE_VERIFY ||
				message[0] == TLS_FINISHED)
			for (hash = 0; hash < __HANDSHAKE_HASH_COUNT; hash++) {
				if (!tls->handshake_hash[hash])
					continue;

				tls_get_handshake_hash(tls, hash,
							tls->prev_digest[hash]);
			}

		/*
		 * RFC 5246, Section 7.4.1.1:
		 * This message MUST NOT be included in the message hashes
		 * that are maintained throughout the handshake and used in
		 * the Finished messages and the certificate verify message.
		 */
		if (message[0] != TLS_HELLO_REQUEST)
			for (hash = 0; hash < __HANDSHAKE_HASH_COUNT; hash++) {
				if (!tls->handshake_hash[hash])
					continue;

				l_checksum_update(tls->handshake_hash[hash],
							message, len);
			}

		tls_handle_handshake(tls, message[0],
					message + TLS_HANDSHAKE_HEADER_SIZE,
					len - TLS_HANDSHAKE_HEADER_SIZE);

		return true;

	case TLS_CT_APPLICATION_DATA:
		if (!tls->ready) {
			TLS_DISCONNECT(TLS_ALERT_UNEXPECTED_MESSAGE, 0,
					"Application data message before "
					"handshake finished");

			return false;
		}

		if (!len)
			return true;

		tls->rx(message, len, tls->user_data);

		return true;
	}

	return false;
}

LIB_EXPORT void l_tls_close(struct l_tls *tls)
{
	TLS_DISCONNECT(TLS_ALERT_CLOSE_NOTIFY, 0, "Closing session");
}

LIB_EXPORT bool l_tls_set_cacert(struct l_tls *tls, const char *ca_cert_path)
{
	TLS_DEBUG("ca-cert-path=%s", ca_cert_path);

	if (tls->ca_certs) {
		l_queue_destroy(tls->ca_certs,
				(l_queue_destroy_func_t) l_cert_free);
		tls->ca_certs = NULL;
	}

	if (ca_cert_path) {
		if (!l_key_is_supported(L_KEY_FEATURE_RESTRICT)) {
			TLS_DEBUG("keyctl restrict support missing, "
					"check kernel configuration");
			return false;
		}

		tls->ca_certs = l_pem_load_certificate_list(ca_cert_path);
		if (!tls->ca_certs) {
			TLS_DEBUG("Error loading %s", ca_cert_path);
			return false;
		}
	}

	return true;
}

LIB_EXPORT bool l_tls_set_auth_data(struct l_tls *tls, const char *cert_path,
					const char *priv_key_path,
					const char *priv_key_passphrase)
{
	TLS_DEBUG("cert-path=%s priv-key-path=%s priv-key-passphrase=%p",
			cert_path, priv_key_path, priv_key_passphrase);

	if (tls->cert) {
		l_certchain_free(tls->cert);
		tls->cert = NULL;
	}

	if (tls->priv_key) {
		l_key_free(tls->priv_key);
		tls->priv_key = NULL;
		tls->priv_key_size = 0;
	}

	if (cert_path) {
		tls->cert = l_pem_load_certificate_chain(cert_path);
		if (!tls->cert) {
			TLS_DEBUG("Error loading %s", cert_path);
			return false;
		}
	}

	if (priv_key_path) {
		bool is_public = true;

		tls->priv_key = l_pem_load_private_key(priv_key_path,
							priv_key_passphrase,
							NULL);
		if (!tls->priv_key) {
			TLS_DEBUG("Error loading %s", priv_key_path);
			return false;
		}

		if (!l_key_get_info(tls->priv_key, L_KEY_RSA_PKCS1_V1_5,
					L_CHECKSUM_NONE, &tls->priv_key_size,
					&is_public) || is_public) {
			TLS_DEBUG("Not a private key or l_key_get_info failed");
			l_key_free(tls->priv_key);
			tls->priv_key = NULL;
			tls->priv_key_size = 0;
			return false;
		}

		tls->priv_key_size /= 8;
	}

	return true;
}

LIB_EXPORT const char *l_tls_alert_to_str(enum l_tls_alert_desc desc)
{
	switch (desc) {
	case TLS_ALERT_CLOSE_NOTIFY:
		return "close_notify";
	case TLS_ALERT_UNEXPECTED_MESSAGE:
		return "unexpected_message";
	case TLS_ALERT_BAD_RECORD_MAC:
		return "bad_record_mac";
	case TLS_ALERT_DECRYPT_FAIL_RESERVED:
		return "decryption_failure_RESERVED";
	case TLS_ALERT_RECORD_OVERFLOW:
		return "record_overflow";
	case TLS_ALERT_DECOMPRESS_FAIL:
		return "decompression_failure";
	case TLS_ALERT_HANDSHAKE_FAIL:
		return "handshake_failure";
	case TLS_ALERT_NO_CERT_RESERVED:
		return "no_certificate_RESERVED";
	case TLS_ALERT_BAD_CERT:
		return "bad_certificate";
	case TLS_ALERT_UNSUPPORTED_CERT:
		return "unsupported_certificate";
	case TLS_ALERT_CERT_REVOKED:
		return "certificate_revoked";
	case TLS_ALERT_CERT_EXPIRED:
		return "certificate_expired";
	case TLS_ALERT_CERT_UNKNOWN:
		return "certificate_unknown";
	case TLS_ALERT_ILLEGAL_PARAM:
		return "illegal_parameter";
	case TLS_ALERT_UNKNOWN_CA:
		return "unknown_ca";
	case TLS_ALERT_ACCESS_DENIED:
		return "access_denied";
	case TLS_ALERT_DECODE_ERROR:
		return "decode_error";
	case TLS_ALERT_DECRYPT_ERROR:
		return "decrypt_error";
	case TLS_ALERT_EXPORT_RES_RESERVED:
		return "export_restriction_RESERVED";
	case TLS_ALERT_PROTOCOL_VERSION:
		return "protocol_version";
	case TLS_ALERT_INSUFFICIENT_SECURITY:
		return "insufficient_security";
	case TLS_ALERT_INTERNAL_ERROR:
		return "internal_error";
	case TLS_ALERT_USER_CANCELED:
		return "user_canceled";
	case TLS_ALERT_NO_RENEGOTIATION:
		return "no_renegotiation";
	case TLS_ALERT_UNSUPPORTED_EXTENSION:
		return "unsupported_extension";
	}

	return NULL;
}

const char *tls_handshake_state_to_str(enum tls_handshake_state state)
{
	static char buf[100];

	switch (state) {
	SWITCH_ENUM_TO_STR(TLS_HANDSHAKE_WAIT_HELLO)
	SWITCH_ENUM_TO_STR(TLS_HANDSHAKE_WAIT_CERTIFICATE)
	SWITCH_ENUM_TO_STR(TLS_HANDSHAKE_WAIT_KEY_EXCHANGE)
	SWITCH_ENUM_TO_STR(TLS_HANDSHAKE_WAIT_HELLO_DONE)
	SWITCH_ENUM_TO_STR(TLS_HANDSHAKE_WAIT_CERTIFICATE_VERIFY)
	SWITCH_ENUM_TO_STR(TLS_HANDSHAKE_WAIT_CHANGE_CIPHER_SPEC)
	SWITCH_ENUM_TO_STR(TLS_HANDSHAKE_WAIT_FINISHED)
	SWITCH_ENUM_TO_STR(TLS_HANDSHAKE_DONE)
	}

	snprintf(buf, sizeof(buf), "tls_handshake_state(%i)", state);
	return buf;
}

struct l_cert *tls_cert_load_file(const char *filename)
{
	uint8_t *der;
	size_t len;
	struct l_cert *cert;

	der = l_pem_load_certificate(filename, &len);
	if (!der)
		return NULL;

	cert = l_cert_new_from_der(der, len);
	l_free(der);
	return cert;
}

int tls_parse_certificate_list(const void *data, size_t len,
				struct l_certchain **out_certchain)
{
	const uint8_t *buf = data;
	struct l_certchain *chain = NULL;

	while (len) {
		struct l_cert *cert;
		size_t cert_len;

		if (len < 3)
			goto decode_error;

		cert_len = *buf++ << 16;
		cert_len |= *buf++ << 8;
		cert_len |= *buf++ << 0;

		if (cert_len + 3 > len)
			goto decode_error;

		cert = l_cert_new_from_der(buf, cert_len);
		if (!cert)
			goto decode_error;

		if (!chain) {
			chain = certchain_new_from_leaf(cert);
			if (!chain)
				goto decode_error;
		} else
			certchain_link_issuer(chain, cert);

		buf += cert_len;
		len -= cert_len + 3;
	}

	if (out_certchain)
		*out_certchain = chain;
	else
		l_certchain_free(chain);

	return 0;

decode_error:
	l_certchain_free(chain);
	return -EBADMSG;
}

LIB_EXPORT bool l_tls_set_debug(struct l_tls *tls, l_tls_debug_cb_t function,
				void *user_data, l_tls_destroy_cb_t destroy)
{
	if (unlikely(!tls))
		return false;

	if (tls->debug_destroy)
		tls->debug_destroy(tls->debug_data);

	tls->debug_handler = function;
	tls->debug_destroy = destroy;
	tls->debug_data = user_data;

	return true;
}
