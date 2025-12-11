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
#include "../../ct-verif.h"

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

int g_time(void *fn_pointer, void *tctx,
	uint32_t not_before_days, uint32_t not_before_seconds,
	uint32_t not_after_days, uint32_t not_after_seconds);

unsigned char *g_irsapub(void *fn_pointer,
	unsigned char *x, size_t xlen,
	const br_rsa_public_key *pk);

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

extern uint32_t
ec_all_m31_api_mul(unsigned char *G, size_t Glen,
	const unsigned char *kb, size_t kblen, int curve);

extern uint32_t
ec_all_m31_api_muladd(unsigned char *A, const unsigned char *B, size_t len,
	const unsigned char *x, size_t xlen,
	const unsigned char *y, size_t ylen, int curve);

extern size_t
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

extern uint32_t
br_rsa_i31_public(unsigned char *x, size_t xlen,
	const br_rsa_public_key *pk);

extern void
clear_max_plaintext(const br_sslrec_out_clear_context *cc,
	size_t *start, size_t *end);

extern void
cbc_max_plaintext(const br_sslrec_out_cbc_context *cc,
	size_t *start, size_t *end);

extern void
gcm_max_plaintext(const br_sslrec_gcm_context *cc,
	size_t *start, size_t *end);

extern void
ccm_max_plaintext(const br_sslrec_ccm_context *cc,
	size_t *start, size_t *end);

extern void
chapol_max_plaintext(const br_sslrec_chapol_context *cc,
	size_t *start, size_t *end);

extern unsigned char *
clear_encrypt(br_sslrec_out_clear_context *cc,
	int record_type, unsigned version, void *data, size_t *data_len);

extern unsigned char *
cbc_encrypt(br_sslrec_out_cbc_context *cc,
	int record_type, unsigned version, void *data, size_t *data_len);

extern unsigned char *
gcm_encrypt(br_sslrec_gcm_context *cc,
	int record_type, unsigned version, void *data, size_t *data_len);

extern unsigned char *
ccm_encrypt(br_sslrec_ccm_context *cc,
	int record_type, unsigned version, void *data, size_t *data_len);

extern unsigned char *
chapol_encrypt(br_sslrec_chapol_context *cc,
	int record_type, unsigned version, void *data, size_t *data_len);

extern unsigned char *
cbc_decrypt(br_sslrec_in_cbc_context *cc,
	int record_type, unsigned version, void *data, size_t *data_len);

extern unsigned char *
gcm_decrypt(br_sslrec_gcm_context *cc,
	int record_type, unsigned version, void *data, size_t *data_len);

extern unsigned char *
ccm_decrypt(br_sslrec_ccm_context *cc,
	int record_type, unsigned version, void *data, size_t *data_len);

extern unsigned char *
chapol_decrypt(br_sslrec_chapol_context *cc,
	int record_type, unsigned version, void *data, size_t *data_len);

extern int cbc_check_length(const br_sslrec_in_cbc_context *cc, size_t rlen);
extern int gcm_check_length(const br_sslrec_gcm_context *cc, size_t rlen);
extern int ccm_check_length(const br_sslrec_ccm_context *cc, size_t rlen);
extern int chapol_check_length(const br_sslrec_chapol_context *cc, size_t rlen);


extern void br_poly1305_ctmul_run(const void *key, const void *iv,
	void *data, size_t len, const void *aad, size_t aad_len,
	void *tag, br_chacha20_run ichacha, int encrypt);

extern uint32_t
ec_c_25519_i15_api_muladd(unsigned char *A, const unsigned char *B, size_t len,
	const unsigned char *x, size_t xlen,
	const unsigned char *y, size_t ylen, int curve);

extern uint32_t
ec_c_25519_i31_api_muladd(unsigned char *A, const unsigned char *B, size_t len,
	const unsigned char *x, size_t xlen,
	const unsigned char *y, size_t ylen, int curve);

extern uint32_t
ec_c_25519_m15_api_muladd(unsigned char *A, const unsigned char *B, size_t len,
	const unsigned char *x, size_t xlen,
	const unsigned char *y, size_t ylen, int curve);

extern uint32_t
ec_c_25519_m31_api_muladd(unsigned char *A, const unsigned char *B, size_t len,
	const unsigned char *x, size_t xlen,
	const unsigned char *y, size_t ylen, int curve);

extern uint32_t
br_ecdsa_i31_vrfy_asn1(const br_ec_impl *impl,
	const void *hash, size_t hash_len,
	const br_ec_public_key *pk, const void *sig, size_t sig_len);

extern int
sock_read(void *ctx, unsigned char *buf, size_t len);

extern int
sock_write(void *ctx, const unsigned char *buf, size_t len);

#ifndef TEST
inline __attribute__((always_inline))
int g_memcmp(const void *str1, const void *str2, size_t n)
{
    const unsigned char *s1 = (const unsigned char *)str1;
	const unsigned char *s2 = (const unsigned char *)str2;

	while (n--) {
		if (*s1 != *s2) {
			int result;
			if (*s1 < *s2) {
				result = -1;
			} else {
				result = 1;
			}
			return result;
		}
		s1++;
		s2++;
	}
	return 0;
}

inline __attribute__((always_inline))
size_t g_strlen(const char *str) {
  size_t count = 0;
  while (str[count])
    count++;
  return count;
}

inline __attribute__((always_inline))
void *g_memmove(void *dest, const void *src, size_t n)
{
    unsigned char       *d = (unsigned char *)dest;
    const unsigned char *s = (const unsigned char *)src;

    /* Trivial cases: nothing to do. */
    if (d == s || n == 0)
        return dest;

    /*
     * Decide copy direction:
     *   – If destination starts before source, they either don’t overlap
     *     or overlap with dest in the *front* part → copy **forward**.
     *   – Otherwise destination is after source → copy **backward**.
     *
     *  Copying in the correct direction prevents the source byte
     *  from being overwritten before we read it.
     */ // n = 64
    if (d < s) {
        /* ---------- forward copy ---------- */
        for (size_t i = 0; i < n; ++i)
            d[i] = s[i];
    } else { // TODO: unreachable code
        /* ---------- backward copy ---------- */
        /* Start from the last byte and move toward the first. */ // n = 64
        for (size_t i = n; i > 0; i--)
    		d[i-1] = s[i-1];
    }

    return dest;
}
#else

inline __attribute__((always_inline))
size_t g_strlen(const char *str) {
  return strlen(str);
}

inline __attribute__((always_inline))
int g_memcmp(const void *str1, const void *str2, size_t n) {
  return memcmp(str1, str2, n);
}

inline __attribute__((always_inline))
void *g_memmove(void *dest, const void *src, size_t n)
{
    return memmove(dest, src, n);
}

#endif /* __SMACK__ */

#endif /* GENERIC_WRAPPERS_H */