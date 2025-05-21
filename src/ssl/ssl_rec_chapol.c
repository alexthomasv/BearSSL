/*
 * Copyright (c) 2016 Thomas Pornin <pornin@bolet.org>
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
#include "g_header.h"

static void
dump_chunk(const void *p, size_t len)
{
    const unsigned char *v = p;
    for (size_t i = 0; i < len; i += 16) {
        /* print offset */
        printf("  %04zx  ", i);

        /* hex part */
        for (size_t j = 0; j < 16; j++) {
            if (i + j < len)
                printf("%02x ", v[i + j]);
            else
                printf("   ");
        }

        /* ASCII part */
        printf(" ");
        for (size_t j = 0; j < 16 && i + j < len; j++) {
            unsigned char c = v[i + j];
            putchar((c >= 32 && c <= 126) ? c : '.');
        }
        putchar('\n');
    }
}

static void
gen_chapol_init(br_sslrec_chapol_context *cc,
	br_chacha20_run ichacha, br_poly1305_run ipoly,
	const void *key, const void *iv)
{
	cc->seq = 0;
	cc->ichacha = ichacha;
	cc->ipoly = ipoly;
	memcpy(cc->key, key, sizeof cc->key);
	memcpy(cc->iv, iv, sizeof cc->iv);
}

static void
gen_chapol_process(br_sslrec_chapol_context *cc,
	int record_type, unsigned version, void *data, size_t len,
	void *tag, int encrypt)
{
	unsigned char header[13];
	unsigned char nonce[12];
	uint64_t seq;
	size_t u;

	seq = cc->seq ++;
	br_enc64be(header, seq);
	header[8] = (unsigned char)record_type;
	br_enc16be(header + 9, version);
	br_enc16be(header + 11, len);
	memcpy(nonce, cc->iv, 12);
	for (u = 0; u < 8; u ++) {
		nonce[11 - u] ^= (unsigned char)seq;
		seq >>= 8;
	}
	generic_ipoly(cc->ipoly, cc->key, nonce, data, len, header, sizeof header,
		tag, cc->ichacha, encrypt);
	// cc->ipoly(cc->key, nonce, data, len, header, sizeof header,
		// tag, cc->ichacha, encrypt);
}

void
in_chapol_init(br_sslrec_chapol_context *cc,
	br_chacha20_run ichacha, br_poly1305_run ipoly,
	const void *key, const void *iv)
{
	cc->vtable.in = &br_sslrec_in_chapol_vtable;
	gen_chapol_init(cc, ichacha, ipoly, key, iv);
}

int
chapol_check_length(const br_sslrec_chapol_context *cc, size_t rlen)
{
	/*
	 * Overhead is just the authentication tag (16 bytes).
	 */
	(void)cc;
	return rlen >= 16 && rlen <= (16384 + 16);
}

unsigned char *
chapol_decrypt(br_sslrec_chapol_context *cc,
	int record_type, unsigned version, void *data, size_t *data_len)
{
	unsigned char *buf;
	size_t u, len;
	unsigned char tag[16];
	unsigned bad;

	dump_chunk(data, *data_len);

	buf = data;
	len = *data_len - 16;
	gen_chapol_process(cc, record_type, version, buf, len, tag, 0);
	bad = 0;
	for (u = 0; u < 16; u ++) {
		bad |= tag[u] ^ buf[len + u];
	}
	if (bad) {
		return NULL;
	}
	*data_len = len;
	dump_chunk(data, *data_len);
	return buf;
}

/* see bearssl_ssl.h */
const br_sslrec_in_chapol_class br_sslrec_in_chapol_vtable = {
	{
		sizeof(br_sslrec_chapol_context),
		(int (*)(const br_sslrec_in_class *const *, size_t))
			&chapol_check_length,
		(unsigned char *(*)(const br_sslrec_in_class **,
			int, unsigned, void *, size_t *))
			&chapol_decrypt
	},
	(void (*)(const br_sslrec_in_chapol_class **,
		br_chacha20_run, br_poly1305_run,
		const void *, const void *))
		&in_chapol_init
};

void
out_chapol_init(br_sslrec_chapol_context *cc,
	br_chacha20_run ichacha, br_poly1305_run ipoly,
	const void *key, const void *iv)
{
	cc->vtable.out = &br_sslrec_out_chapol_vtable;
	gen_chapol_init(cc, ichacha, ipoly, key, iv);
}

void
chapol_max_plaintext(const br_sslrec_chapol_context *cc,
	size_t *start, size_t *end)
{
	size_t len;

	(void)cc;
	len = *end - *start - 16;
	if (len > 16384) {
		len = 16384;
	}
	*end = *start + len;
}

unsigned char *
chapol_encrypt(br_sslrec_chapol_context *cc,
	int record_type, unsigned version, void *data, size_t *data_len)
{
	printf("chapol_encrypt\n");
	unsigned char *buf;
	size_t len;

	buf = data;
	len = *data_len;
	gen_chapol_process(cc, record_type, version, buf, len, buf + len, 1);
	buf -= 5;
	dump_chunk(buf, len);
	buf[0] = (unsigned char)record_type;
	br_enc16be(buf + 1, version);
	br_enc16be(buf + 3, len + 16);
	*data_len = len + 21;
	dump_chunk(data, *data_len);
	return buf;
}

/* see bearssl_ssl.h */
const br_sslrec_out_chapol_class br_sslrec_out_chapol_vtable = {
	{
		sizeof(br_sslrec_chapol_context),
		(void (*)(const br_sslrec_out_class *const *,
			size_t *, size_t *))
			&chapol_max_plaintext,
		(unsigned char *(*)(const br_sslrec_out_class **,
			int, unsigned, void *, size_t *))
			&chapol_encrypt
	},
	(void (*)(const br_sslrec_out_chapol_class **,
		br_chacha20_run, br_poly1305_run,
		const void *, const void *))
		&out_chapol_init
};
