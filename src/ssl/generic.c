#include "inner.h"

extern void
clear_max_plaintext(const br_sslrec_out_clear_context *cc,
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

extern int
cbc_check_length(const br_sslrec_in_cbc_context *cc, size_t rlen);
extern int gcm_check_length(const br_sslrec_in_class **ctx, size_t len);
extern int ccm_check_length(const br_sslrec_in_class **ctx, size_t len);
extern int chapol_check_length(const br_sslrec_in_class **ctx, size_t len);


void br_poly1305_ctmul_run(const void *key, const void *iv,
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

void generic_max_plaintext(void *fn_pointer, const br_sslrec_out_class *const *ctx, size_t *start, size_t *end)
{
	if (fn_pointer == &clear_max_plaintext) {
		clear_max_plaintext(ctx, start, end);
	} else {
		abort();
	}
}

void generic_clear_encrypt(void *fn_pointer, const br_sslrec_out_class **ctx,
		int record_type, unsigned version,
		void *plaintext, size_t *len)
{
	if (fn_pointer == &clear_encrypt) {
		clear_encrypt(ctx, record_type, version, plaintext, len);
	} else {	
		abort();
	}
}

void generic_enc_init(void *fn_pointer, const br_block_cbcenc_class **ctx,
		const void *key, size_t key_len){
	if (fn_pointer == &br_aes_ct64_cbcenc_init) {
		br_aes_ct64_cbcenc_init(ctx, key, key_len);
	} else{
		abort();
	}
}

void g_br_block_run(void *fn_pointer, const br_block_cbcenc_class **ctx,
		const void *iv, void *data, size_t len){
	if (fn_pointer == &br_aes_ct64_cbcenc_run) {
		br_aes_ct64_cbcenc_run(ctx, iv, data, len);
	} else{
		abort();
	}
}

unsigned char *generic_encrypt(void *fn_pointer, const br_sslrec_out_class **ctx,
		int record_type, unsigned version,
		void *plaintext, size_t *len){
	if (fn_pointer == &clear_encrypt) {
		return clear_encrypt(ctx, record_type, version, plaintext, len);
	} else if (fn_pointer == &cbc_encrypt) {
		return cbc_encrypt(ctx, record_type, version, plaintext, len);
	} else if (fn_pointer == &gcm_encrypt) {
		return gcm_encrypt(ctx, record_type, version, plaintext, len);
	} else if (fn_pointer == &ccm_encrypt) {
		return ccm_encrypt(ctx, record_type, version, plaintext, len);
	} else if (fn_pointer == &chapol_encrypt) {
		return chapol_encrypt(ctx, record_type, version, plaintext, len);
	} else {
		abort();
	}
}

unsigned char *generic_decrypt(void *fn_pointer, const br_sslrec_in_class **ctx,
		int record_type, unsigned version,
		void *ciphertext, size_t *len){
	if (fn_pointer == &cbc_decrypt) {
		return cbc_decrypt(ctx, record_type, version, ciphertext, len);
	} else if (fn_pointer == &gcm_decrypt) {
		return gcm_decrypt(ctx, record_type, version, ciphertext, len);
	} else if (fn_pointer == &ccm_decrypt) {
		return ccm_decrypt(ctx, record_type, version, ciphertext, len);
	} else if (fn_pointer == &chapol_decrypt) {
		return chapol_decrypt(ctx, record_type, version, ciphertext, len);
	} else {
		abort();
	}
}

void generic_ipoly(void *fn_pointer, const void *key, const void *iv,
	void *data, size_t len, const void *aad, size_t aad_len,
	void *tag, br_chacha20_run ichacha, int encrypt){
	if (fn_pointer == &br_poly1305_ctmul_run) {
		return br_poly1305_ctmul_run(key, iv, data, len, aad, aad_len, tag, ichacha, encrypt);
	} else {
		abort();
	}
}

uint32_t generic_chacha(void *fn_pointer, const void *key,
	const void *iv, uint32_t cc, void *data, size_t len){
	if (fn_pointer == &br_chacha20_ct_run) {
		return br_chacha20_ct_run(key, iv, cc, data, len);
	} else {
		abort();
	}
}

void generic_ghash(void *fn_pointer, void *y, const void *h, const void *data, size_t len){
	if (fn_pointer == &br_ghash_ctmul) {
		return br_ghash_ctmul64(y, h, data, len);
	} else {
		abort();
	}
}

void g_br_block_init(void *fn_pointer, const br_block_cbcenc_class *const *ctx,
		const void *key, size_t key_len){
	if (fn_pointer == &br_aes_ct64_ctrcbc_init) {
		return br_aes_ct64_ctrcbc_init(ctx, key, key_len);
	} else {
		abort();
	}
}

void g_br_block_encrypt(void *fn_pointer, const br_block_ctrcbc_class *const *ctx,
		void *ctr, void *cbcmac, void *data, size_t len){
	if (fn_pointer == &br_aes_ct64_ctrcbc_encrypt) {
		return br_aes_ct64_ctrcbc_encrypt(ctx, ctr, cbcmac, data, len);
	} else {
		abort();
	}
}

void g_br_block_decrypt(void *fn_pointer, const br_block_ctrcbc_class *const *ctx,
		void *ctr, void *cbcmac, void *data, size_t len){
	if (fn_pointer == &br_aes_ct64_ctrcbc_decrypt) {
		return br_aes_ct64_ctrcbc_decrypt(ctx, ctr, cbcmac, data, len);
	} else {
		abort();
	}
}

void g_br_block_ctr(void *fn_pointer, const br_block_ctrcbc_class *const *ctx,
		void *ctr, void *data, size_t len){
	if (fn_pointer == &br_aes_ct64_ctrcbc_ctr) {
		return br_aes_ct64_ctrcbc_ctr(ctx, ctr, data, len);
	} else {
		abort();
	}
}

void g_br_block_mac(void *fn_pointer, const br_block_cbcenc_class *const *ctx,
		void *cbcmac, const void *data, size_t len){
	if (fn_pointer == &br_aes_ct64_ctrcbc_mac) {
		return br_aes_ct64_ctrcbc_mac(ctx, cbcmac, data, len);
	} else {
		abort();
	}
}

void generic_hash_init(void *fn_pointer, const br_hash_class **ctx){
	if (fn_pointer == &br_sha256_init) {
		br_sha256_init(ctx);
	} else if (fn_pointer == &br_sha384_init) {
		br_sha384_init(ctx);
	} else if (fn_pointer == &br_sha1_init) {
		br_sha1_init(ctx);
	} else if (fn_pointer == &br_md5_init) {
		br_md5_init(ctx);
	} else if (fn_pointer == &br_sha224_init) {
		br_sha224_init(ctx);
	} else if (fn_pointer == &br_sha512_init) {
		br_sha512_init(ctx);
	} else {
		abort();
	}
}

void generic_hash_update(void *fn_pointer, const br_hash_class *const *ctx, const void *data, size_t len){
	if (fn_pointer == &br_sha256_update) {
		br_sha256_update(ctx, data, len);
	} else if (fn_pointer == &br_sha384_update) {
		br_sha384_update(ctx, data, len);
	} else if (fn_pointer == &br_sha1_update) {
		br_sha1_update(ctx, data, len);
	} else if (fn_pointer == &br_md5_update) {
		br_md5_update(ctx, data, len);
	} else if (fn_pointer == &br_sha224_update) {
		br_sha224_update(ctx, data, len);
	} else if (fn_pointer == &br_sha512_update) {
		br_sha512_update(ctx, data, len);
	} else {
		abort();
	}
}

void generic_hash_out(void *fn_pointer, const br_hash_class *const *ctx, void *dst){
	if (fn_pointer == &br_sha256_out) {
		br_sha256_out(ctx, dst);
	} else if (fn_pointer == &br_sha384_out) {
		br_sha384_out(ctx, dst);
	} else if (fn_pointer == &br_sha1_out) {
		br_sha1_out(ctx, dst);
	} else if (fn_pointer == &br_md5_out) {
		br_md5_out(ctx, dst);
	} else if (fn_pointer == &br_sha224_out) {
		br_sha224_out(ctx, dst);
	} else if (fn_pointer == &br_sha512_out) {
		br_sha512_out(ctx, dst);
	} else {
		abort();
	}
}

uint64_t generic_hash_state(void *fn_pointer, const br_hash_class *const *ctx, void *out){
	if (fn_pointer == &br_sha256_state) {
		return br_sha256_state(ctx, out);
	} else if (fn_pointer == &br_sha384_state) {
		return br_sha384_state(ctx, out);
	} else if (fn_pointer == &br_sha1_state) {
		return br_sha1_state(ctx, out);
	} else if (fn_pointer == &br_md5_state) {
		return br_md5_state(ctx, out);
	} else if (fn_pointer == &br_sha224_state) {
		return br_sha224_state(ctx, out);
	} else if (fn_pointer == &br_sha512_state) {
		return br_sha512_state(ctx, out);
	} else {
		abort();
	}
}

void generic_hash_set_state(void *fn_pointer, const br_hash_class *const *ctx, void *stb, uint64_t count){
	if (fn_pointer == &br_sha256_set_state) {
		br_sha256_set_state(ctx, stb, count);
	} else if (fn_pointer == &br_sha384_set_state) {
		br_sha384_set_state(ctx, stb, count);
	} else if (fn_pointer == &br_sha1_set_state) {
		br_sha1_set_state(ctx, stb, count);
	} else if (fn_pointer == &br_md5_set_state) {
		br_md5_set_state(ctx, stb, count);
	} else if (fn_pointer == &br_sha224_set_state) {
		br_sha224_set_state(ctx, stb, count);
	} else if (fn_pointer == &br_sha512_set_state) {
		br_sha512_set_state(ctx, stb, count);
	} else {
		abort();
	}
}

int generic_check_length(void *fn_pointer, const br_sslrec_in_class **ctx, size_t len){
	 if (fn_pointer == &cbc_check_length) {
		return cbc_check_length(ctx, len);
	} else if (fn_pointer == &gcm_check_length) {
		return gcm_check_length(ctx, len);
	} else if (fn_pointer == &ccm_check_length) {
		return ccm_check_length(ctx, len);
	} else if (fn_pointer == &chapol_check_length) {
		return chapol_check_length(ctx, len);
	} else {
		abort();
	}
}

uint32_t generic_muladd(void *fn_pointer, unsigned char *A, const unsigned char *B, size_t len,
	const unsigned char *x, size_t xlen,
	const unsigned char *y, size_t ylen, int curve){
	if (fn_pointer == &ec_c_25519_i15_api_muladd) {
		return ec_c_25519_i15_api_muladd(A, B, len, x, xlen, y, ylen, curve);
	} else if (fn_pointer == &ec_c_25519_i31_api_muladd) {
		return ec_c_25519_i31_api_muladd(A, B, len, x, xlen, y, ylen, curve);
	} else if (fn_pointer == &ec_c_25519_m15_api_muladd) {
		return ec_c_25519_m15_api_muladd(A, B, len, x, xlen, y, ylen, curve);
	} else if (fn_pointer == &ec_c_25519_m31_api_muladd) {
		return ec_c_25519_m31_api_muladd(A, B, len, x, xlen, y, ylen, curve);
	} else {
		abort();
	}
}

uint32_t generic_irsa(void *fn_pointer, const br_ec_impl *impl,
	const void *hash, size_t hash_len,
	const br_ec_public_key *pk, const void *sig, size_t sig_len){
	if (fn_pointer == &br_ecdsa_i31_vrfy_asn1) {
		return br_ecdsa_i31_vrfy_asn1(impl, hash, hash_len, pk, sig, sig_len);
	} else {
		abort();
	}
}


void generic_hs_run(void *fn_pointer, void *cc){
	if (fn_pointer == &br_ssl_hs_client_run) {
		br_ssl_hs_client_run(cc);
	} else {
		abort();
	}
}
