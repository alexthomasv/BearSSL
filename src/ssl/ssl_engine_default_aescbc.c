/*
 * Copyright (c) 2017 Thomas Pornin <pornin@bolet.org>
 *
 * Permission is hereby granted, free of charge, to any person obtaining 
 * a copy of this software and associated documentation files (the
 * "Software"), to deal in the Software without restriction, including
 * without limitation the rights to use, copy, modify, merge, publish,
 * distribute, sublicense, and/or sell copies of the Software, and to
 * permit persons to whom the Software is furnished to do so, subject to
 * the following conditions:
 *
 * The above copyright notice and this permission notice shall be 
 * included in all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, 
 * EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
 * MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND 
 * NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS
 * BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN
 * ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
 * CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */

#include "inner.h"

#ifndef TEST 
static void
in_cbc_init(br_sslrec_in_cbc_context *cc,
	const br_block_cbcdec_class *bc_impl,
	const void *bc_key, size_t bc_key_len,
	const br_hash_class *dig_impl,
	const void *mac_key, size_t mac_key_len, size_t mac_out_len,
	const void *iv);

static void
out_cbc_init(br_sslrec_out_cbc_context *cc,
	const br_block_cbcenc_class *bc_impl,
	const void *bc_key, size_t bc_key_len,
	const br_hash_class *dig_impl,
	const void *mac_key, size_t mac_key_len, size_t mac_out_len,
	const void *iv);

static void
cbc_max_plaintext(const br_sslrec_out_cbc_context *cc,
	size_t *start, size_t *end);

static unsigned char *
cbc_encrypt(br_sslrec_out_cbc_context *cc,
	int record_type, unsigned version, void *data, size_t *data_len);

static int
cbc_check_length(const br_sslrec_in_cbc_context *cc, size_t rlen);

static unsigned char *
cbc_decrypt(br_sslrec_in_cbc_context *cc,
	int record_type, unsigned version, void *data, size_t *data_len);
#endif

/* see bearssl_ssl.h */
void
br_ssl_engine_set_default_aes_cbc(br_ssl_engine_context *cc)
{
#if BR_AES_X86NI || BR_POWER8
	const br_block_cbcenc_class *ienc;
	const br_block_cbcdec_class *idec;
#endif

	br_ssl_engine_set_cbc(cc,
		&br_sslrec_in_cbc_vtable,
		&br_sslrec_out_cbc_vtable);

#ifndef TEST 
	((br_sslrec_in_cbc_class *)cc->icbc_in)->init = in_cbc_init;
	br_sslrec_in_class *cbc_in = &((br_sslrec_in_cbc_class *) cc->icbc_in)->inner;
	cbc_in->check_length = cbc_check_length;
	cbc_in->decrypt = cbc_decrypt;

	((br_sslrec_out_cbc_class *)cc->icbc_out)->init = out_cbc_init;
	br_sslrec_out_class *cbc_out = &((br_sslrec_out_cbc_class *) cc->icbc_out)->inner;
	cbc_out->max_plaintext = cbc_max_plaintext;
	cbc_out->encrypt = cbc_encrypt;
#endif

#if BR_AES_X86NI
	ienc = br_aes_x86ni_cbcenc_get_vtable();
	idec = br_aes_x86ni_cbcdec_get_vtable();
	if (ienc != NULL && idec != NULL) {
		br_ssl_engine_set_aes_cbc(cc, ienc, idec);
		return;
	}
#endif
#if BR_POWER8
	ienc = br_aes_pwr8_cbcenc_get_vtable();
	idec = br_aes_pwr8_cbcdec_get_vtable();
	if (ienc != NULL && idec != NULL) {
		br_ssl_engine_set_aes_cbc(cc, ienc, idec);
		return;
	}
#endif
#if BR_64
	br_ssl_engine_set_aes_cbc(cc,
		&br_aes_ct64_cbcenc_vtable,
		&br_aes_ct64_cbcdec_vtable);
#else
	br_ssl_engine_set_aes_cbc(cc,
		&br_aes_ct_cbcenc_vtable,
		&br_aes_ct_cbcdec_vtable);
#endif
}
