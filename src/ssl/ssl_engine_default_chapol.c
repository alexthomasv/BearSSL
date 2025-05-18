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
static int
chapol_check_length(const br_sslrec_chapol_context *cc, size_t rlen);

static unsigned char *
chapol_decrypt(br_sslrec_chapol_context *cc,
	int record_type, unsigned version, void *data, size_t *data_len);

static void
in_chapol_init(br_sslrec_chapol_context *cc,
	br_chacha20_run ichacha, br_poly1305_run ipoly,
	const void *key, const void *iv);

static void
out_chapol_init(br_sslrec_chapol_context *cc,
	br_chacha20_run ichacha, br_poly1305_run ipoly,
	const void *key, const void *iv);

static unsigned char *
chapol_encrypt(br_sslrec_chapol_context *cc,
	int record_type, unsigned version, void *data, size_t *data_len);

static void
chapol_max_plaintext(const br_sslrec_chapol_context *cc,
	size_t *start, size_t *end);
#endif

/* see bearssl_ssl.h */
void
br_ssl_engine_set_default_chapol(br_ssl_engine_context *cc)
{
#if BR_INT128 || BR_UMUL128
	br_poly1305_run bp;
#endif
#if BR_SSE2
	br_chacha20_run bc;
#endif

	br_ssl_engine_set_chapol(cc,
		&br_sslrec_in_chapol_vtable,
		&br_sslrec_out_chapol_vtable);

#ifndef TEST 
	((br_sslrec_in_chapol_class *)cc->ichapol_in)->init = in_chapol_init;
	br_sslrec_in_class *cbc_in = &((br_sslrec_in_chapol_class *) cc->ichapol_in)->inner;
	cbc_in->check_length = chapol_check_length;
	cbc_in->decrypt = chapol_decrypt;

	((br_sslrec_out_chapol_class *)cc->ichapol_out)->init = out_chapol_init;
	br_sslrec_out_class *cbc_out = &((br_sslrec_out_chapol_class *) cc->ichapol_out)->inner;
	cbc_out->max_plaintext = chapol_max_plaintext;
	cbc_out->encrypt = chapol_encrypt;
#endif

#if BR_SSE2
	bc = br_chacha20_sse2_get();
	if (bc) {
		br_ssl_engine_set_chacha20(cc, bc);
	} else {
#endif
		br_ssl_engine_set_chacha20(cc, &br_chacha20_ct_run);
#if BR_SSE2
	}
#endif
#if BR_INT128 || BR_UMUL128
	bp = br_poly1305_ctmulq_get();
	if (bp) {
		br_ssl_engine_set_poly1305(cc, bp);
	} else {
#endif
#if BR_LOMUL
		br_ssl_engine_set_poly1305(cc, &br_poly1305_ctmul32_run);
#else
		br_ssl_engine_set_poly1305(cc, &br_poly1305_ctmul_run);
#endif
#if BR_INT128 || BR_UMUL128
	}
#endif
}
