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
#include <stdlib.h>
#include <stdio.h>
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

int generic_check_length(void *fn_pointer, const br_sslrec_in_class **ctx, size_t len);

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

void g_start_chain(void *fn_pointer, const br_x509_class **ctx,
		const char *server_name);

void g_start_cert(void *fn_pointer, const br_x509_class **ctx,
		uint32_t cert_type);

void g_append(void *fn_pointer, const br_x509_class **ctx,
		const void *data, size_t len);

void g_end_cert(void *fn_pointer, const br_x509_class **ctx);

unsigned g_end_chain(void *fn_pointer, const br_x509_class **ctx);

void g_prng_update(void *fn_pointer, const br_prng_class **ctx,
		const void *seed, size_t seed_len);

void br_hash_dn_init(void *fn_pointer, const br_hash_class *const *ctx);

void br_hash_dn_update(void *fn_pointer, const br_hash_class *const *ctx,
        const void *data, size_t len);

void br_hash_dn_out(void *fn_pointer, const br_hash_class *const *ctx,
        void *dst);

uint32_t g_iecdsa(void *fn_pointer, const br_ec_impl *impl,
	const void *hash, size_t hash_len,
	const br_ec_public_key *pk, const void *sig, size_t sig_len);

uint32_t g_irsa(void *fn_pointer, const br_ec_impl *impl,
	const void *hash, size_t hash_len,
	const br_ec_public_key *pk, const void *sig, size_t sig_len);

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

uint32_t g_br_block_ctr_run(void *fn_pointer,
        const br_block_ctr_class *const *ctx,
        const void *iv, uint32_t cc,
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

void generic_hs_run(void *fn_pointer, void *cc);

void g_prf(void *fn_pointer, void *dst, size_t len,
	const void *secret, size_t secret_len, const char *label,
	size_t seed_num, const br_tls_prf_seed_chunk *seed);

int g_read(void* fn_pointer, void *read_context,
		unsigned char *data, size_t len);

int g_write(void* fn_pointer, void *write_context,
		unsigned char *data, size_t len);

void g_choose(void *fn_pointer, const br_ssl_client_certificate_class **pctx,
		const br_ssl_client_context *cc, uint32_t auth_types,
		br_ssl_client_certificate *choices);

uint32_t g_do_keyx(void *fn_pointer, const br_ssl_client_certificate_class **pctx,
		unsigned char *data, size_t *len);

const unsigned char *g_order(void *fn_pointer, int curve, size_t *len);

size_t g_do_sign(void *fn_pointer, const br_ssl_client_certificate_class **pctx,
		int hash_id, size_t hv_len, unsigned char *data, size_t len);

void g_append_name(void *fn_pointer, const br_ssl_client_certificate_class **pctx,
		const unsigned char *data, size_t len);

void g_start_name_list(void *fn_pointer, const br_ssl_client_certificate_class **pctx);

void g_end_name_list(void *fn_pointer, const br_ssl_client_certificate_class **pctx);

void g_start_name(void *fn_pointer, const br_ssl_client_certificate_class **pctx, size_t len);

void g_end_name(void *fn_pointer, const br_ssl_client_certificate_class **pctx);

void g_generator(void *fn_pointer, int curve, size_t *len);

uint32_t g_mul(void *fn_pointer, unsigned char *G, size_t Glen,
		const unsigned char *x, size_t xlen, int curve);

size_t g_mulgen(void *fn_pointer, unsigned char *R,
		const unsigned char *x, size_t xlen, int curve);

size_t g_xoff(void *fn_pointer, int curve, size_t *len);

uint32_t g_irsavrfy(void *fn_pointer, const unsigned char *x, size_t xlen,
	const unsigned char *hash_oid, size_t hash_len,
	const br_rsa_public_key *pk, unsigned char *hash_out);

const br_x509_pkey *g_get_pkey(void *fn_pointer,
		const br_x509_class *const *ctx, unsigned *usages);

// Needed for ssl_engine.c
extern void in_ccm_init(br_sslrec_ccm_context *cc,
	const br_block_ctrcbc_class *bc_impl,
	const void *key, size_t key_len,
	const void *iv, size_t tag_len);

extern void out_ccm_init(br_sslrec_ccm_context *cc,
	const br_block_ctrcbc_class *bc_impl,
	const void *key, size_t key_len,
	const void *iv, size_t tag_len);

extern void
in_gcm_init(br_sslrec_gcm_context *cc,
	const br_block_ctr_class *bc_impl,
	const void *key, size_t key_len,
	br_ghash gh_impl,
	const void *iv);

extern void
out_gcm_init(br_sslrec_gcm_context *cc,
	const br_block_ctr_class *bc_impl,
	const void *key, size_t key_len,
	br_ghash gh_impl,
	const void *iv);

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



// Needed for ec_all_m31.c
extern const unsigned char *
ec_c_25519_m31_api_generator(int curve, size_t *len);

extern const unsigned char *
ec_c_25519_m31_api_order(int curve, size_t *len);

extern size_t
ec_c_25519_m31_api_xoff(int curve, size_t *len);

extern uint32_t
ec_c_25519_m31_api_mul(unsigned char *G, size_t Glen,
	const unsigned char *kb, size_t kblen, int curve);

extern size_t
ec_c_25519_m31_api_mulgen(unsigned char *R,
	const unsigned char *x, size_t xlen, int curve);

extern uint32_t
ec_c_25519_m31_api_muladd(unsigned char *A, const unsigned char *B, size_t len,
	const unsigned char *x, size_t xlen,
	const unsigned char *y, size_t ylen, int curve);

extern size_t
ec_p_256_m31_api_mulgen(unsigned char *R,
	const unsigned char *x, size_t xlen, int curve);

extern const unsigned char *
ec_p_256_m31_api_generator(int curve, size_t *len);

extern uint32_t
ec_p_256_m31_api_muladd(unsigned char *A, const unsigned char *B, size_t len,
	const unsigned char *x, size_t xlen,
	const unsigned char *y, size_t ylen, int curve);

extern uint32_t
ec_p_256_m31_api_mul(unsigned char *G, size_t Glen,
	const unsigned char *x, size_t xlen, int curve);

extern uint32_t
ec_prime_i31_api_muladd(unsigned char *A, const unsigned char *B, size_t len,
	const unsigned char *x, size_t xlen,
	const unsigned char *y, size_t ylen, int curve);

extern const unsigned char *
ec_p_256_m31_api_order(int curve, size_t *len);

extern size_t
ec_p_256_m31_api_xoff(int curve, size_t *len);


extern const unsigned char *
ec_prime_i31_api_generator(int curve, size_t *len);

extern uint32_t
ec_prime_i31_api_mul(unsigned char *G, size_t Glen,
	const unsigned char *x, size_t xlen, int curve);

extern size_t
ec_prime_i31_api_mulgen(unsigned char *R,
	const unsigned char *x, size_t xlen, int curve);

extern const unsigned char *
ec_prime_i31_api_generator(int curve, size_t *len);

extern const unsigned char *
ec_prime_i31_api_order(int curve, size_t *len);

extern size_t
ec_prime_i31_api_xoff(int curve, size_t *len);

extern const unsigned char *
ec_p_256_m31_api_generator(int curve, size_t *len);

extern const unsigned char *
ec_all_m31_api_order(int curve, size_t *len);

extern const unsigned char *
ec_all_m31_api_generator(int curve, size_t *len);

uint32_t
ec_all_m31_api_mul(unsigned char *G, size_t Glen,
	const unsigned char *kb, size_t kblen, int curve);

uint32_t
ec_all_m31_api_muladd(unsigned char *A, const unsigned char *B, size_t len,
	const unsigned char *x, size_t xlen,
	const unsigned char *y, size_t ylen, int curve);
	
size_t
ec_all_m31_api_mulgen(unsigned char *R,
	const unsigned char *x, size_t xlen, int curve);

extern size_t
ec_all_m31_api_xoff(int curve, size_t *len);

extern int
sock_read(void *ctx, unsigned char *buf, size_t len);

extern int
sock_write(void *ctx, const unsigned char *buf, size_t len);

extern void xm_start_chain(const br_x509_class **ctx, const char *server_name);

extern void xm_start_cert(const br_x509_class **ctx, uint32_t length);

extern void xm_append(const br_x509_class **ctx, const unsigned char *buf, size_t len);

extern const br_x509_pkey *
xm_get_pkey(const br_x509_class *const *ctx, unsigned *usages);

extern void xm_end_cert(const br_x509_class **ctx);

extern unsigned xm_end_chain(const br_x509_class **ctx);
#endif /* GENERIC_WRAPPERS_H */