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
br_ssl_engine_set_default_des_cbc(br_ssl_engine_context *cc)
{
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

	br_ssl_engine_set_des_cbc(cc,
		&br_des_ct_cbcenc_vtable,
		&br_des_ct_cbcdec_vtable);

#ifndef TEST 
	((br_block_cbcenc_class *)cc->ides_cbcenc)->init = br_des_ct_cbcenc_init;
	((br_block_cbcenc_class *)cc->ides_cbcenc)->run = br_des_ct_cbcenc_run;

	((br_block_cbcdec_class *)cc->ides_cbcdec)->init = br_des_ct_cbcdec_init;
	((br_block_cbcdec_class *)cc->ides_cbcdec)->run = br_des_ct_cbcdec_run;	
#endif
}
