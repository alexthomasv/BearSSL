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
#include "g_header.h"
#include <stdio.h>

const unsigned char *
ec_all_m31_api_generator(int curve, size_t *len)
{
	switch (curve) {
	case BR_EC_secp256r1:
#if BR_INT128 || BR_UMUL128
		return br_ec_p256_m64.generator(curve, len);
#else
		return ec_p_256_m31_api_generator(curve, len);
		// return br_ec_p256_m31.generator(curve, len);
#endif
	case BR_EC_curve25519:
#if BR_INT128 || BR_UMUL128
		return br_ec_c25519_m64.generator(curve, len);
#else
		return ec_c_25519_m31_api_generator(curve, len);
		// return br_ec_c25519_m31.generator(curve, len);
#endif
	default:
		return ec_prime_i31_api_generator(curve, len);
		// return br_ec_prime_i31.generator(curve, len);
	}
}

const unsigned char *
ec_all_m31_api_order(int curve, size_t *len)
{
	switch (curve) {
	case BR_EC_secp256r1:
#if BR_INT128 || BR_UMUL128
		return br_ec_p256_m64.order(curve, len);
#else
		return ec_p_256_m31_api_order(curve, len);
		// return br_ec_p256_m31.order(curve, len);
#endif
	case BR_EC_curve25519:
#if BR_INT128 || BR_UMUL128
		return br_ec_c25519_m64.order(curve, len);
#else
		return ec_c_25519_m31_api_order(curve, len);
		// return br_ec_c25519_m31.order(curve, len);
#endif
	default:
		return ec_prime_i31_api_order(curve, len);
		// return br_ec_prime_i31.order(curve, len);
	}
}

size_t
ec_all_m31_api_xoff(int curve, size_t *len)
{
	switch (curve) {
	case BR_EC_secp256r1:
#if BR_INT128 || BR_UMUL128
		return br_ec_p256_m64.xoff(curve, len);
#else
		return ec_p_256_m31_api_xoff(curve, len);
		// return br_ec_p256_m31.xoff(curve, len);
#endif
	case BR_EC_curve25519:
#if BR_INT128 || BR_UMUL128
		return br_ec_c25519_m64.xoff(curve, len);
#else
		return ec_c_25519_m31_api_xoff(curve, len);
		// return br_ec_c25519_m31.xoff(curve, len);
#endif
	default:
		return ec_prime_i31_api_xoff(curve, len);
		// return br_ec_prime_i31.xoff(curve, len);
	}
}

uint32_t
ec_all_m31_api_mul(unsigned char *G, size_t Glen,
	const unsigned char *kb, size_t kblen, int curve)
{
	switch (curve) {
	case BR_EC_secp256r1:
#if BR_INT128 || BR_UMUL128
		return br_ec_p256_m64.mul(G, Glen, kb, kblen, curve);
#else
		return ec_p_256_m31_api_mul(G, Glen, kb, kblen, curve);
		// return br_ec_p256_m31.mul(G, Glen, kb, kblen, curve);
#endif
	case BR_EC_curve25519:
#if BR_INT128 || BR_UMUL128
		return br_ec_c25519_m64.mul(G, Glen, kb, kblen, curve);
#else
		return ec_c_25519_m31_api_mul(G, Glen, kb, kblen, curve);
		// return br_ec_c25519_m31.mul(G, Glen, kb, kblen, curve);
#endif
	default:
		return ec_prime_i31_api_mul(G, Glen, kb, kblen, curve);
		// return br_ec_prime_i31.mul(G, Glen, kb, kblen, curve);
	}
}

size_t
ec_all_m31_api_mulgen(unsigned char *R,
	const unsigned char *x, size_t xlen, int curve)
{
	switch (curve) {
	case BR_EC_secp256r1:
#if BR_INT128 || BR_UMUL128
		return br_ec_p256_m64.mulgen(R, x, xlen, curve);
#else
		return ec_p_256_m31_api_mulgen(R, x, xlen, curve);
		// return br_ec_p256_m31.mulgen(R, x, xlen, curve);
#endif
	case BR_EC_curve25519:
#if BR_INT128 || BR_UMUL128
		return br_ec_c25519_m64.mulgen(R, x, xlen, curve);
#else
		return ec_c_25519_m31_api_mulgen(R, x, xlen, curve);
		// return br_ec_c25519_m31.mulgen(R, x, xlen, curve);
#endif
	default:
		return ec_prime_i31_api_mulgen(R, x, xlen, curve);
		// return br_ec_prime_i31.mulgen(R, x, xlen, curve);
	}
}

uint32_t
ec_all_m31_api_muladd(unsigned char *A, const unsigned char *B, size_t len,
	const unsigned char *x, size_t xlen,
	const unsigned char *y, size_t ylen, int curve)
{
	switch (curve) {
	case BR_EC_secp256r1:
#if BR_INT128 || BR_UMUL128
		return br_ec_p256_m64.muladd(A, B, len,
			x, xlen, y, ylen, curve);
#else
		return ec_p_256_m31_api_muladd(A, B, len,
			x, xlen, y, ylen, curve);
		// return br_ec_p256_m31.muladd(A, B, len,
		// 	x, xlen, y, ylen, curve);
#endif
	case BR_EC_curve25519:
#if BR_INT128 || BR_UMUL128
		return br_ec_c25519_m64.muladd(A, B, len,
			x, xlen, y, ylen, curve);
#else
		return ec_c_25519_m31_api_muladd(A, B, len,
			x, xlen, y, ylen, curve);
		// return br_ec_c25519_m31.muladd(A, B, len,
		// 	x, xlen, y, ylen, curve);
#endif
	default:
		return ec_prime_i31_api_muladd(A, B, len,
			x, xlen, y, ylen, curve);
		// return br_ec_prime_i31.muladd(A, B, len,
		// 	x, xlen, y, ylen, curve);
	}
}

/* see bearssl_ec.h */
const br_ec_impl br_ec_all_m31 = {
	(uint32_t)0x23800000,
	&ec_all_m31_api_generator,
	&ec_all_m31_api_order,
	&ec_all_m31_api_xoff,
	&ec_all_m31_api_mul,
	&ec_all_m31_api_mulgen,
	&ec_all_m31_api_muladd
};
