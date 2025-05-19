/*====================================================================
 *  generic_wrappers.h
 *
 *  Prototypes for the generic dispatch helpers defined in
 *  generic_wrappers.c  (or whatever you called your source file).
 *
 *  This header intentionally does NOT redeclare the underlying BearSSL
 *  primitives like cbc_encrypt(), gcm_encrypt(), br_sha256_update(), …
 *===================================================================*/
#ifndef GENERIC_WRAPPERS_H
#define GENERIC_WRAPPERS_H

#include <stddef.h>
#include <stdint.h>
#include "inner.h"   /* BearSSL internal structs (br_sslrec_*, br_hash_*, …) */

/*--------------------------------------------------------------------
 *  Record-layer helpers
 *------------------------------------------------------------------*/
void generic_max_plaintext(void *fn_ptr,
        const br_sslrec_out_class * const *ctx,
        size_t *start, size_t *end);

void generic_clear_encrypt(void *fn_ptr,
        const br_sslrec_out_class **ctx,
        int record_type, unsigned version,
        void *plaintext, size_t *len);

void generic_enc_init(void *fn_ptr,
        const br_block_cbcenc_class **ctx,
        const void *key, size_t key_len);

void g_br_block_run(void *fn_ptr,
        const br_block_cbcenc_class **ctx,
        const void *iv, void *data, size_t len);

unsigned char *generic_encrypt(void *fn_ptr,
        const br_sslrec_out_class **ctx,
        int record_type, unsigned version,
        void *plaintext, size_t *len);

unsigned char *generic_decrypt(void *fn_ptr,
        const br_sslrec_in_class **ctx,
        int record_type, unsigned version,
        void *ciphertext, size_t *len);

/*--------------------------------------------------------------------
 *  AEAD / Poly1305 / ChaCha helpers
 *------------------------------------------------------------------*/
void generic_ipoly(void *fn_ptr,
        const void *key, const void *iv,
        void *data, size_t len,
        const void *aad, size_t aad_len,
        void *tag, br_chacha20_run ichacha,
        int encrypt);

uint32_t generic_chacha(void *fn_ptr,
        const void *key, const void *iv, uint32_t cc,
        void *data, size_t len);

void generic_ghash(void *fn_ptr,
        void *y, const void *h,
        const void *data, size_t len);

/*--------------------------------------------------------------------
 *  CTR-CBC helpers
 *------------------------------------------------------------------*/
void g_br_block_init(void *fn_ptr,
        const br_block_cbcenc_class * const *ctx,
        const void *key, size_t key_len);

void g_br_block_encrypt(void *fn_ptr,
        const br_block_ctrcbc_class * const *ctx,
        void *ctr, void *cbcmac,
        void *data, size_t len);

void g_br_block_decrypt(void *fn_ptr,
        const br_block_ctrcbc_class * const *ctx,
        void *ctr, void *cbcmac,
        void *data, size_t len);

void g_br_block_ctr(void *fn_ptr,
        const br_block_ctrcbc_class * const *ctx,
        void *ctr, void *data, size_t len);

void g_br_block_mac(void *fn_ptr,
        const br_block_cbcenc_class * const *ctx,
        void *cbcmac, const void *data, size_t len);

/*--------------------------------------------------------------------
 *  Hashing helpers
 *------------------------------------------------------------------*/
void generic_hash_init(void *fn_ptr,
        const br_hash_class **ctx);

void generic_hash_update(void *fn_ptr,
        const br_hash_class * const *ctx,
        const void *data, size_t len);

void generic_hash_out(void *fn_ptr,
        const br_hash_class * const *ctx,
        void *dst);

uint64_t generic_hash_state(void *fn_ptr,
        const br_hash_class * const *ctx,
        void *out);

void generic_hash_set_state(void *fn_ptr,
        const br_hash_class * const *ctx,
        void *stb, uint64_t count);

/*--------------------------------------------------------------------
 *  Miscellaneous math / signature helpers
 *------------------------------------------------------------------*/
uint32_t generic_muladd(void *fn_ptr,
        unsigned char *A, const unsigned char *B, size_t len,
        const unsigned char *x, size_t xlen,
        const unsigned char *y, size_t ylen,
        int curve);

uint32_t generic_irsa(void *fn_ptr,
        const br_ec_impl *impl,
        const void *hash, size_t hash_len,
        const br_ec_public_key *pk,
        const void *sig, size_t sig_len);


// Needed for ssl_engine.c
extern void in_ccm_init(br_sslrec_ccm_context *cc,
	const br_block_ctrcbc_class *bc_impl,
	const void *key, size_t key_len,
	const void *iv, size_t tag_len);

extern void out_ccm_init(br_sslrec_ccm_context *cc,
	const br_block_ctrcbc_class *bc_impl,
	const void *key, size_t key_len,
	const void *iv, size_t tag_len);

extern void in_gcm_init(br_sslrec_gcm_context *cc,
	const br_block_ctr_class *bc_impl,
	const void *key, size_t key_len,
	const void *iv, size_t tag_len);

extern void out_gcm_init(br_sslrec_gcm_context *cc,
	const br_block_ctr_class *bc_impl,
	const void *key, size_t key_len,
	const void *iv, size_t tag_len);

extern void in_cbc_init(br_sslrec_in_cbc_context *cc,
	const br_block_cbcdec_class *bc_impl,
	const void *bc_key, size_t bc_key_len,
	const br_hash_class *dig_impl,
	const void *mac_key, size_t mac_key_len, size_t mac_out_len,
	const void *iv);

extern void out_cbc_init(br_sslrec_out_cbc_context *cc,
	const br_block_cbcenc_class *bc_impl,
	const void *bc_key, size_t bc_key_len,
	const br_hash_class *dig_impl,
	const void *mac_key, size_t mac_key_len, size_t mac_out_len,
	const void *iv);

extern void
in_chapol_init(br_sslrec_chapol_context *cc,
	br_chacha20_run ichacha, br_poly1305_run ipoly,
	const void *key, const void *iv);

extern void
out_chapol_init(br_sslrec_chapol_context *cc,
	br_chacha20_run ichacha, br_poly1305_run ipoly,
	const void *key, const void *iv);

#endif /* GENERIC_WRAPPERS_H */