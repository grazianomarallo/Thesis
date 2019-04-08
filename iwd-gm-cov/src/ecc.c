/*
 * Copyright (c) 2013, Kenneth MacKay
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are
 * met:
 *  * Redistributions of source code must retain the above copyright
 *   notice, this list of conditions and the following disclaimer.
 *  * Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
 * A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
 * HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 * LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 * OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <fcntl.h>
#include <unistd.h>
#include <sys/types.h>
#include <string.h>

#include "src/ecc.h"

#define MAX_TRIES 16

typedef struct {
	uint64_t m_low;
	uint64_t m_high;
} uint128_t;

static uint64_t curve_p[NUM_ECC_DIGITS] = CURVE_P_32;
static uint64_t curve_b[NUM_ECC_DIGITS] = CURVE_B_32;

static void vli_clear(uint64_t *vli)
{
	int i;

	for (i = 0; i < NUM_ECC_DIGITS; i++)
		vli[i] = 0;
}

/* Returns true if vli == 0, false otherwise. */
static bool vli_is_zero(const uint64_t *vli)
{
	int i;

	for (i = 0; i < NUM_ECC_DIGITS; i++) {
		if (vli[i])
			return false;
	}

	return true;
}

/* Returns nonzero if bit bit of vli is set. */
static uint64_t vli_test_bit(const uint64_t *vli, unsigned int bit)
{
	return (vli[bit / 64] & ((uint64_t) 1 << (bit % 64)));
}

/* Counts the number of 64-bit "digits" in vli. */
static unsigned int vli_num_digits(const uint64_t *vli)
{
	int i;

	/* Search from the end until we find a non-zero digit.
	 * We do it in reverse because we expect that most digits will
	 * be nonzero.
	 */
	for (i = NUM_ECC_DIGITS - 1; i >= 0 && vli[i] == 0; i--);

	return (i + 1);
}

/* Counts the number of bits required for vli. */
unsigned int vli_num_bits(const uint64_t *vli)
{
	unsigned int i, num_digits;
	uint64_t digit;

	num_digits = vli_num_digits(vli);
	if (num_digits == 0)
		return 0;

	digit = vli[num_digits - 1];
	for (i = 0; digit; i++)
		digit >>= 1;

	return ((num_digits - 1) * 64 + i);
}

/* Sets dest = src. */
static void vli_set(uint64_t *dest, const uint64_t *src)
{
	int i;

	for (i = 0; i < NUM_ECC_DIGITS; i++)
		dest[i] = src[i];
}

/* Returns sign of left - right. */
int vli_cmp(const uint64_t *left, const uint64_t *right)
{
    int i;

    for (i = NUM_ECC_DIGITS - 1; i >= 0; i--) {
	if (left[i] > right[i])
		return 1;
	else if (left[i] < right[i])
		return -1;
    }

    return 0;
}

/* Constant-time comparison function - secure way to compare long integers */
/* Returns one if left == right, zero otherwise. */
static bool vli_equal(const uint64_t *left, const uint64_t *right)
{
	uint64_t diff = 0;
	int i;

	for (i = NUM_ECC_DIGITS - 1; i >= 0; --i)
		diff |= (left[i] ^ right[i]);

	return (diff == 0);
}

/* Computes result = in << c, returning carry. Can modify in place
 * (if result == in). 0 < shift < 64.
 */
static uint64_t vli_lshift(uint64_t *result, const uint64_t *in,
							unsigned int shift)
{
	uint64_t carry = 0;
	int i;

	for (i = 0; i < NUM_ECC_DIGITS; i++) {
		uint64_t temp = in[i];

		result[i] = (temp << shift) | carry;
		carry = temp >> (64 - shift);
	}

	return carry;
}

/* Computes vli = vli >> 1. */
static void vli_rshift1(uint64_t *vli)
{
	uint64_t *end = vli;
	uint64_t carry = 0;

	vli += NUM_ECC_DIGITS;

	while (vli-- > end) {
		uint64_t temp = *vli;
		*vli = (temp >> 1) | carry;
		carry = temp << 63;
	}
}

/* Computes result = left + right, returning carry. Can modify in place. */
static uint64_t vli_add(uint64_t *result, const uint64_t *left,
							const uint64_t *right)
{
	uint64_t carry = 0;
	int i;

	for (i = 0; i < NUM_ECC_DIGITS; i++) {
		uint64_t sum;

		sum = left[i] + right[i] + carry;
		if (sum != left[i])
			carry = (sum < left[i]);

		result[i] = sum;
	}

	return carry;
}

/* Computes result = left - right, returning borrow. Can modify in place. */
uint64_t vli_sub(uint64_t *result, const uint64_t *left,
							const uint64_t *right)
{
	uint64_t borrow = 0;
	int i;

	for (i = 0; i < NUM_ECC_DIGITS; i++) {
		uint64_t diff;

		diff = left[i] - right[i] - borrow;
		if (diff != left[i])
			borrow = (diff > left[i]);

		result[i] = diff;
	}

	return borrow;
}

static uint128_t mul_64_64(uint64_t left, uint64_t right)
{
	uint64_t a0 = left & 0xffffffffull;
	uint64_t a1 = left >> 32;
	uint64_t b0 = right & 0xffffffffull;
	uint64_t b1 = right >> 32;
	uint64_t m0 = a0 * b0;
	uint64_t m1 = a0 * b1;
	uint64_t m2 = a1 * b0;
	uint64_t m3 = a1 * b1;
	uint128_t result;

	m2 += (m0 >> 32);
	m2 += m1;

	/* Overflow */
	if (m2 < m1)
		m3 += 0x100000000ull;

	result.m_low = (m0 & 0xffffffffull) | (m2 << 32);
	result.m_high = m3 + (m2 >> 32);

	return result;
}

static uint128_t add_128_128(uint128_t a, uint128_t b)
{
	uint128_t result;

	result.m_low = a.m_low + b.m_low;
	result.m_high = a.m_high + b.m_high + (result.m_low < a.m_low);

	return result;
}

static void vli_mult(uint64_t *result, const uint64_t *left,
							const uint64_t *right)
{
	uint128_t r01 = { 0, 0 };
	uint64_t r2 = 0;
	unsigned int i, k;

	/* Compute each digit of result in sequence, maintaining the
	 * carries.
	 */
	for (k = 0; k < NUM_ECC_DIGITS * 2 - 1; k++) {
		unsigned int min;

		if (k < NUM_ECC_DIGITS)
			min = 0;
		else
			min = (k + 1) - NUM_ECC_DIGITS;

		for (i = min; i <= k && i < NUM_ECC_DIGITS; i++) {
			uint128_t product;

			product = mul_64_64(left[i], right[k - i]);

			r01 = add_128_128(r01, product);
			r2 += (r01.m_high < product.m_high);
		}

		result[k] = r01.m_low;
		r01.m_low = r01.m_high;
		r01.m_high = r2;
		r2 = 0;
	}

	result[NUM_ECC_DIGITS * 2 - 1] = r01.m_low;
}

static void vli_square(uint64_t *result, const uint64_t *left)
{
	uint128_t r01 = { 0, 0 };
	uint64_t r2 = 0;
	int i, k;

	for (k = 0; k < NUM_ECC_DIGITS * 2 - 1; k++) {
		unsigned int min;

		if (k < NUM_ECC_DIGITS)
			min = 0;
		else
			min = (k + 1) - NUM_ECC_DIGITS;

		for (i = min; i <= k && i <= k - i; i++) {
			uint128_t product;

			product = mul_64_64(left[i], left[k - i]);

			if (i < k - i) {
				r2 += product.m_high >> 63;
				product.m_high = (product.m_high << 1) |
							(product.m_low >> 63);
				product.m_low <<= 1;
			}

			r01 = add_128_128(r01, product);
			r2 += (r01.m_high < product.m_high);
		}

		result[k] = r01.m_low;
		r01.m_low = r01.m_high;
		r01.m_high = r2;
		r2 = 0;
	}

	result[NUM_ECC_DIGITS * 2 - 1] = r01.m_low;
}

/* Computes result = (left + right) % mod.
 * Assumes that left < mod and right < mod, result != mod.
 */
void vli_mod_add(uint64_t *result, const uint64_t *left,
				const uint64_t *right, const uint64_t *mod)
{
	uint64_t carry;

	carry = vli_add(result, left, right);

	/* result > mod (result = mod + remainder), so subtract mod to
	 * get remainder.
	 */
	if (carry || vli_cmp(result, mod) >= 0)
		vli_sub(result, result, mod);
}

/* Computes result = (left - right) % mod.
 * Assumes that left < mod and right < mod, result != mod.
 */
void vli_mod_sub(uint64_t *result, const uint64_t *left,
				const uint64_t *right, const uint64_t *mod)
{
	uint64_t borrow = vli_sub(result, left, right);

	/* In this case, p_result == -diff == (max int) - diff.
	 * Since -x % d == d - x, we can get the correct result from
	 * result + mod (with overflow).
	 */
	if (borrow)
		vli_add(result, result, mod);
}

/* Computes result = product % curve_p
   from http://www.nsa.gov/ia/_files/nist-routines.pdf */
static void vli_mmod_fast(uint64_t *result, const uint64_t *product)
{
	uint64_t tmp[NUM_ECC_DIGITS];
	int carry;

	/* t */
	vli_set(result, product);

	/* s1 */
	tmp[0] = 0;
	tmp[1] = product[5] & 0xffffffff00000000ull;
	tmp[2] = product[6];
	tmp[3] = product[7];
	carry = vli_lshift(tmp, tmp, 1);
	carry += vli_add(result, result, tmp);

	/* s2 */
	tmp[1] = product[6] << 32;
	tmp[2] = (product[6] >> 32) | (product[7] << 32);
	tmp[3] = product[7] >> 32;
	carry += vli_lshift(tmp, tmp, 1);
	carry += vli_add(result, result, tmp);

	/* s3 */
	tmp[0] = product[4];
	tmp[1] = product[5] & 0xffffffff;
	tmp[2] = 0;
	tmp[3] = product[7];
	carry += vli_add(result, result, tmp);

	/* s4 */
	tmp[0] = (product[4] >> 32) | (product[5] << 32);
	tmp[1] = (product[5] >> 32) | (product[6] & 0xffffffff00000000ull);
	tmp[2] = product[7];
	tmp[3] = (product[6] >> 32) | (product[4] << 32);
	carry += vli_add(result, result, tmp);

	/* d1 */
	tmp[0] = (product[5] >> 32) | (product[6] << 32);
	tmp[1] = (product[6] >> 32);
	tmp[2] = 0;
	tmp[3] = (product[4] & 0xffffffff) | (product[5] << 32);
	carry -= vli_sub(result, result, tmp);

	/* d2 */
	tmp[0] = product[6];
	tmp[1] = product[7];
	tmp[2] = 0;
	tmp[3] = (product[4] >> 32) | (product[5] & 0xffffffff00000000ull);
	carry -= vli_sub(result, result, tmp);

	/* d3 */
	tmp[0] = (product[6] >> 32) | (product[7] << 32);
	tmp[1] = (product[7] >> 32) | (product[4] << 32);
	tmp[2] = (product[4] >> 32) | (product[5] << 32);
	tmp[3] = (product[6] << 32);
	carry -= vli_sub(result, result, tmp);

	/* d4 */
	tmp[0] = product[7];
	tmp[1] = product[4] & 0xffffffff00000000ull;
	tmp[2] = product[5];
	tmp[3] = product[6] & 0xffffffff00000000ull;
	carry -= vli_sub(result, result, tmp);

	if (carry < 0) {
		do {
			carry += vli_add(result, result, curve_p);
		} while (carry < 0);
	} else {
		while (carry || vli_cmp(curve_p, result) != 1)
			carry -= vli_sub(result, result, curve_p);
	}
}

/* Computes result = (left * right) % curve_p. */
void vli_mod_mult_fast(uint64_t *result, const uint64_t *left,
							const uint64_t *right)
{
	uint64_t product[2 * NUM_ECC_DIGITS];

	vli_mult(product, left, right);
	vli_mmod_fast(result, product);
}

/* Computes result = left^2 % curve_p. */
static void vli_mod_square_fast(uint64_t *result, const uint64_t *left)
{
	uint64_t product[2 * NUM_ECC_DIGITS];

	vli_square(product, left);
	vli_mmod_fast(result, product);
}

#define EVEN(vli) (!(vli[0] & 1))
/* Computes result = (1 / p_input) % mod. All VLIs are the same size.
 * See "From Euclid's GCD to Montgomery Multiplication to the Great Divide"
 * https://labs.oracle.com/techrep/2001/smli_tr-2001-95.pdf
 */
void vli_mod_inv(uint64_t *result, const uint64_t *input,
							const uint64_t *mod)
{
	uint64_t a[NUM_ECC_DIGITS], b[NUM_ECC_DIGITS];
	uint64_t u[NUM_ECC_DIGITS], v[NUM_ECC_DIGITS];
	uint64_t carry;
	int cmp_result;

	if (vli_is_zero(input)) {
		vli_clear(result);
		return;
	}

	vli_set(a, input);
	vli_set(b, mod);
	vli_clear(u);
	u[0] = 1;
	vli_clear(v);

	while ((cmp_result = vli_cmp(a, b)) != 0) {
		carry = 0;

		if (EVEN(a)) {
			vli_rshift1(a);

			if (!EVEN(u))
				carry = vli_add(u, u, mod);

			vli_rshift1(u);
			if (carry)
				u[NUM_ECC_DIGITS - 1] |= 0x8000000000000000ull;
		} else if (EVEN(b)) {
			vli_rshift1(b);

			if (!EVEN(v))
				carry = vli_add(v, v, mod);

			vli_rshift1(v);
			if (carry)
				v[NUM_ECC_DIGITS - 1] |= 0x8000000000000000ull;
		} else if (cmp_result > 0) {
			vli_sub(a, a, b);
			vli_rshift1(a);

			if (vli_cmp(u, v) < 0)
				vli_add(u, u, mod);

			vli_sub(u, u, v);
			if (!EVEN(u))
				carry = vli_add(u, u, mod);

			vli_rshift1(u);
			if (carry)
				u[NUM_ECC_DIGITS - 1] |= 0x8000000000000000ull;
		} else {
			vli_sub(b, b, a);
			vli_rshift1(b);

			if (vli_cmp(v, u) < 0)
				vli_add(v, v, mod);

			vli_sub(v, v, u);
			if (!EVEN(v))
				carry = vli_add(v, v, mod);

			vli_rshift1(v);
			if (carry)
				v[NUM_ECC_DIGITS - 1] |= 0x8000000000000000ull;
		}
	}

	vli_set(result, u);
}

/* ------ Point operations ------ */

/* Returns true if p_point is the point at infinity, false otherwise. */
static bool ecc_point_is_zero(const struct ecc_point *point)
{
	return (vli_is_zero(point->x) && vli_is_zero(point->y));
}

/* Point multiplication algorithm using Montgomery's ladder with co-Z
 * coordinates. From http://eprint.iacr.org/2011/338.pdf
 */

/* Double in place */
static void ecc_point_double_jacobian(uint64_t *x1, uint64_t *y1, uint64_t *z1)
{
	/* t1 = x, t2 = y, t3 = z */
	uint64_t t4[NUM_ECC_DIGITS];
	uint64_t t5[NUM_ECC_DIGITS];

	if (vli_is_zero(z1))
		return;

	vli_mod_square_fast(t4, y1);   /* t4 = y1^2 */
	vli_mod_mult_fast(t5, x1, t4); /* t5 = x1*y1^2 = A */
	vli_mod_square_fast(t4, t4);   /* t4 = y1^4 */
	vli_mod_mult_fast(y1, y1, z1); /* t2 = y1*z1 = z3 */
	vli_mod_square_fast(z1, z1);   /* t3 = z1^2 */

	vli_mod_add(x1, x1, z1, curve_p); /* t1 = x1 + z1^2 */
	vli_mod_add(z1, z1, z1, curve_p); /* t3 = 2*z1^2 */
	vli_mod_sub(z1, x1, z1, curve_p); /* t3 = x1 - z1^2 */
	vli_mod_mult_fast(x1, x1, z1);    /* t1 = x1^2 - z1^4 */

	vli_mod_add(z1, x1, x1, curve_p); /* t3 = 2*(x1^2 - z1^4) */
	vli_mod_add(x1, x1, z1, curve_p); /* t1 = 3*(x1^2 - z1^4) */
	if (vli_test_bit(x1, 0)) {
		uint64_t carry = vli_add(x1, x1, curve_p);
		vli_rshift1(x1);
		x1[NUM_ECC_DIGITS - 1] |= carry << 63;
	} else {
		vli_rshift1(x1);
	}
	/* t1 = 3/2*(x1^2 - z1^4) = B */

	vli_mod_square_fast(z1, x1);      /* t3 = B^2 */
	vli_mod_sub(z1, z1, t5, curve_p); /* t3 = B^2 - A */
	vli_mod_sub(z1, z1, t5, curve_p); /* t3 = B^2 - 2A = x3 */
	vli_mod_sub(t5, t5, z1, curve_p); /* t5 = A - x3 */
	vli_mod_mult_fast(x1, x1, t5);    /* t1 = B * (A - x3) */
	vli_mod_sub(t4, x1, t4, curve_p); /* t4 = B * (A - x3) - y1^4 = y3 */

	vli_set(x1, z1);
	vli_set(z1, y1);
	vli_set(y1, t4);
}

/* Modify (x1, y1) => (x1 * z^2, y1 * z^3) */
static void apply_z(uint64_t *x1, uint64_t *y1, uint64_t *z)
{
	uint64_t t1[NUM_ECC_DIGITS];

	vli_mod_square_fast(t1, z);    /* z^2 */
	vli_mod_mult_fast(x1, x1, t1); /* x1 * z^2 */
	vli_mod_mult_fast(t1, t1, z);  /* z^3 */
	vli_mod_mult_fast(y1, y1, t1); /* y1 * z^3 */
}

/* P = (x1, y1) => 2P, (x2, y2) => P' */
static void xycz_initial_double(uint64_t *x1, uint64_t *y1, uint64_t *x2,
					uint64_t *y2, uint64_t *p_initial_z)
{
	uint64_t z[NUM_ECC_DIGITS];

	vli_set(x2, x1);
	vli_set(y2, y1);

	vli_clear(z);
	z[0] = 1;

	if (p_initial_z)
		vli_set(z, p_initial_z);

	apply_z(x1, y1, z);

	ecc_point_double_jacobian(x1, y1, z);

	apply_z(x2, y2, z);
}

/* Input P = (x1, y1, Z), Q = (x2, y2, Z)
 * Output P' = (x1', y1', Z3), P + Q = (x3, y3, Z3)
 * or P => P', Q => P + Q
 */
static void xycz_add(uint64_t *x1, uint64_t *y1, uint64_t *x2, uint64_t *y2)
{
	/* t1 = X1, t2 = Y1, t3 = X2, t4 = Y2 */
	uint64_t t5[NUM_ECC_DIGITS];

	vli_mod_sub(t5, x2, x1, curve_p); /* t5 = x2 - x1 */
	vli_mod_square_fast(t5, t5);      /* t5 = (x2 - x1)^2 = A */
	vli_mod_mult_fast(x1, x1, t5);    /* t1 = x1*A = B */
	vli_mod_mult_fast(x2, x2, t5);    /* t3 = x2*A = C */
	vli_mod_sub(y2, y2, y1, curve_p); /* t4 = y2 - y1 */
	vli_mod_square_fast(t5, y2);      /* t5 = (y2 - y1)^2 = D */

	vli_mod_sub(t5, t5, x1, curve_p); /* t5 = D - B */
	vli_mod_sub(t5, t5, x2, curve_p); /* t5 = D - B - C = x3 */
	vli_mod_sub(x2, x2, x1, curve_p); /* t3 = C - B */
	vli_mod_mult_fast(y1, y1, x2);    /* t2 = y1*(C - B) */
	vli_mod_sub(x2, x1, t5, curve_p); /* t3 = B - x3 */
	vli_mod_mult_fast(y2, y2, x2);    /* t4 = (y2 - y1)*(B - x3) */
	vli_mod_sub(y2, y2, y1, curve_p); /* t4 = y3 */

	vli_set(x2, t5);
}

/* Input P = (x1, y1, Z), Q = (x2, y2, Z)
 * Output P + Q = (x3, y3, Z3), P - Q = (x3', y3', Z3)
 * or P => P - Q, Q => P + Q
 */
static void xycz_add_c(uint64_t *x1, uint64_t *y1, uint64_t *x2, uint64_t *y2)
{
	/* t1 = X1, t2 = Y1, t3 = X2, t4 = Y2 */
	uint64_t t5[NUM_ECC_DIGITS];
	uint64_t t6[NUM_ECC_DIGITS];
	uint64_t t7[NUM_ECC_DIGITS];

	vli_mod_sub(t5, x2, x1, curve_p); /* t5 = x2 - x1 */
	vli_mod_square_fast(t5, t5);      /* t5 = (x2 - x1)^2 = A */
	vli_mod_mult_fast(x1, x1, t5);    /* t1 = x1*A = B */
	vli_mod_mult_fast(x2, x2, t5);    /* t3 = x2*A = C */
	vli_mod_add(t5, y2, y1, curve_p); /* t4 = y2 + y1 */
	vli_mod_sub(y2, y2, y1, curve_p); /* t4 = y2 - y1 */

	vli_mod_sub(t6, x2, x1, curve_p); /* t6 = C - B */
	vli_mod_mult_fast(y1, y1, t6);    /* t2 = y1 * (C - B) */
	vli_mod_add(t6, x1, x2, curve_p); /* t6 = B + C */
	vli_mod_square_fast(x2, y2);      /* t3 = (y2 - y1)^2 */
	vli_mod_sub(x2, x2, t6, curve_p); /* t3 = x3 */

	vli_mod_sub(t7, x1, x2, curve_p); /* t7 = B - x3 */
	vli_mod_mult_fast(y2, y2, t7);    /* t4 = (y2 - y1)*(B - x3) */
	vli_mod_sub(y2, y2, y1, curve_p); /* t4 = y3 */

	vli_mod_square_fast(t7, t5);      /* t7 = (y2 + y1)^2 = F */
	vli_mod_sub(t7, t7, t6, curve_p); /* t7 = x3' */
	vli_mod_sub(t6, t7, x1, curve_p); /* t6 = x3' - B */
	vli_mod_mult_fast(t6, t6, t5);    /* t6 = (y2 + y1)*(x3' - B) */
	vli_mod_sub(y1, t6, y1, curve_p); /* t2 = y3' */

	vli_set(x1, t7);
}

void ecc_point_mult(struct ecc_point *result,
				const struct ecc_point *point,
				uint64_t *scalar, uint64_t *initial_z,
				int num_bits)
{
	/* R0 and R1 */
	uint64_t rx[2][NUM_ECC_DIGITS];
	uint64_t ry[2][NUM_ECC_DIGITS];
	uint64_t z[NUM_ECC_DIGITS];
	int i, nb;

	vli_set(rx[1], point->x);
	vli_set(ry[1], point->y);

	xycz_initial_double(rx[1], ry[1], rx[0], ry[0], initial_z);

	for (i = num_bits - 2; i > 0; i--) {
		nb = !vli_test_bit(scalar, i);
		xycz_add_c(rx[1 - nb], ry[1 - nb], rx[nb], ry[nb]);
		xycz_add(rx[nb], ry[nb], rx[1 - nb], ry[1 - nb]);
	}

	nb = !vli_test_bit(scalar, 0);
	xycz_add_c(rx[1 - nb], ry[1 - nb], rx[nb], ry[nb]);

	/* Find final 1/Z value. */
	vli_mod_sub(z, rx[1], rx[0], curve_p); /* X1 - X0 */
	vli_mod_mult_fast(z, z, ry[1 - nb]); /* Yb * (X1 - X0) */
	vli_mod_mult_fast(z, z, point->x);   /* xP * Yb * (X1 - X0) */
	vli_mod_inv(z, z, curve_p);          /* 1 / (xP * Yb * (X1 - X0)) */
	vli_mod_mult_fast(z, z, point->y);   /* yP / (xP * Yb * (X1 - X0)) */
	vli_mod_mult_fast(z, z, rx[1 - nb]); /* Xb * yP / (xP * Yb * (X1 - X0)) */
	/* End 1/Z calculation */

	xycz_add(rx[nb], ry[nb], rx[1 - nb], ry[1 - nb]);

	apply_z(rx[0], ry[0], z);

	vli_set(result->x, rx[0]);
	vli_set(result->y, ry[0]);
}

bool ecc_valid_point(struct ecc_point *point)
{
	uint64_t tmp1[NUM_ECC_DIGITS];
	uint64_t tmp2[NUM_ECC_DIGITS];
	uint64_t _3[NUM_ECC_DIGITS] = { 3 };	/* -a = 3 */

	/* The point at infinity is invalid. */
	if (ecc_point_is_zero(point))
		return false;

	/* x and y must be smaller than p. */
	if (vli_cmp(curve_p, point->x) != 1 ||
			vli_cmp(curve_p, point->y) != 1)
		return false;

	/* Computes result = y^2. */
	vli_mod_square_fast(tmp1, point->y);

	/* Computes result = x^3 + ax + b. result must not overlap x. */
	vli_mod_square_fast(tmp2, point->x);		/* r = x^2 */
	vli_mod_sub(tmp2, tmp2, _3, curve_p);		/* r = x^2 - 3 */
	vli_mod_mult_fast(tmp2, tmp2, point->x);	/* r = x^3 - 3x */
	vli_mod_add(tmp2, tmp2, curve_b, curve_p);	/* r = x^3 - 3x + b */

	/* Make sure that y^2 == x^3 + ax + b */
	return vli_equal(tmp1, tmp2);
}

/*
 * These two byte conversion functions were modified to allow for conversion
 * to and from both BE and LE architectures.
 */

/* Big endian byte-array to native conversion */
void ecc_be2native(uint64_t bytes[NUM_ECC_DIGITS])
{
	int i;
	uint64_t tmp[NUM_ECC_DIGITS];

	for (i = 0; i < NUM_ECC_DIGITS; i++)
		tmp[NUM_ECC_DIGITS - 1 - i] = l_get_be64(&bytes[i]);

	memcpy(bytes, tmp, 32);
}

/* Native to big endian byte-array conversion */
void ecc_native2be(uint64_t native[NUM_ECC_DIGITS])
{
	int i;
	uint64_t tmp[NUM_ECC_DIGITS];

	for (i = 0; i < NUM_ECC_DIGITS; i++)
		l_put_be64(native[NUM_ECC_DIGITS - 1 - i], &tmp[i]);

	memcpy(native, tmp, 32);
}

/*
 * The code below was not in the original file and was added to support EAP-PWD.
 * The above ECC implementation did not include functionality for point
 * addition or the ability to solve for Y value given some X.
 */

/* (rx, ry) = (px, py) + (qx, qy) */
void ecc_point_add(struct ecc_point *ret, struct ecc_point *p,
		struct ecc_point *q)
{
	/*
	 * s = (py - qy)/(px - qx)
	 *
	 * rx = s^2 - px - qx
	 * ry = s(px - rx) - py
	 */
	uint64_t s[NUM_ECC_DIGITS];
	uint64_t kp1[NUM_ECC_DIGITS];
	uint64_t kp2[NUM_ECC_DIGITS];
	uint64_t resx[NUM_ECC_DIGITS];
	uint64_t resy[NUM_ECC_DIGITS];

	vli_clear(s);

	/* kp1 = py - qy */
	vli_mod_sub(kp1, q->y, p->y, curve_p);
	/* kp2 = px - qx */
	vli_mod_sub(kp2, q->x, p->x, curve_p);
	/* s = kp1/kp2 */
	vli_mod_inv(kp2, kp2, curve_p);
	vli_mod_mult_fast(s, kp1, kp2);
	/* rx = s^2 - px - qx */
	vli_mod_mult_fast(kp1, s, s);
	vli_mod_sub(kp1, kp1, p->x, curve_p);
	vli_mod_sub(resx, kp1, q->x, curve_p);
	/* ry = s(px - rx) - py */
	vli_mod_sub(kp1, p->x, resx, curve_p);
	vli_mod_mult_fast(kp1, s, kp1);
	vli_mod_sub(resy, kp1, p->y, curve_p);

	vli_set(ret->x, resx);
	vli_set(ret->y, resy);
}

/* result = (base ^ exp) % p */
void vli_mod_exp(uint64_t *result, uint64_t *base, uint64_t *exp,
		const uint64_t *mod)
{
	int i;
	int bit;
	uint64_t n[NUM_ECC_DIGITS];
	uint64_t r[NUM_ECC_DIGITS] = { 1 };

	vli_set(n, base);

	for (i = 0; i < NUM_ECC_DIGITS; i++) {
		for (bit = 0; bit < 64; bit++) {
			uint64_t tmp[NUM_ECC_DIGITS];

			if (exp[i] & (1ull << bit)) {
				vli_mod_mult_fast(tmp, r, n);
				memcpy(r, tmp, 32);
			}

			vli_mod_mult_fast(tmp, n, n);
			memcpy(n, tmp, 32);
		}
	}

	memcpy(result, r, 32);
}

bool ecc_compute_y(uint64_t *y, uint64_t *x)
{
	/*
	 * y = sqrt(x^3 + ax + b) (mod p)
	 *
	 * Since our prime p satisfies p = 3 (mod 4), we can say:
	 *
	 * y = (x^3 - 3x + b)^((p + 1) / 4)
	 *
	 * This avoids the need for a square root function.
	 */

	uint64_t sum[NUM_ECC_DIGITS] = { 0 };
	uint64_t expo[NUM_ECC_DIGITS] = { 0 };
	uint64_t one[NUM_ECC_DIGITS] = { 1ull };
	uint64_t check[NUM_ECC_DIGITS] = { 0 };
	uint64_t _3[NUM_ECC_DIGITS] = { 3ull }; /* -a = 3 */
	uint64_t tmp[NUM_ECC_DIGITS] = { 0 };

	vli_set(expo, curve_p);

	vli_mod_square_fast(sum, x);
	vli_mod_mult_fast(sum, sum, x); /* x^3 */
	vli_mod_mult_fast(tmp, _3, x);
	vli_mod_sub(sum, sum, tmp, curve_p); /* x^3 - ax */
	vli_mod_add(sum, sum, curve_b, curve_p); /* x^3 - ax + b */

	/* (p + 1) / 4  == (p >> 2) + 1 */
	vli_rshift1(expo);
	vli_rshift1(expo);
	vli_mod_add(expo, expo, one, curve_p);
	/* sum ^ ((p + 1) / 4) */
	vli_mod_exp(y, sum, expo, curve_p);

	/* square y to ensure we have a correct value */
	vli_mod_mult_fast(check, y, y);

	if (vli_cmp(check, sum) != 0)
		return false;

	return true;
}

void ecc_compute_y_sqr(uint64_t *y_sqr, uint64_t *x)
{
	uint64_t sum[NUM_ECC_DIGITS] = { 0 };
	uint64_t tmp[NUM_ECC_DIGITS] = { 0 };
	uint64_t _3[NUM_ECC_DIGITS] = { 3ull }; /* -a = 3 */

	vli_mod_square_fast(sum, x);
	vli_mod_mult_fast(sum, sum, x); /* x^3 */
	vli_mod_mult_fast(tmp, _3, x);
	vli_mod_sub(sum, sum, tmp, curve_p); /* x^3 - ax */
	vli_mod_add(sum, sum, curve_b, curve_p); /* x^3 - ax + b */

	memcpy(y_sqr, sum, 32);
}

int vli_legendre(uint64_t *val, const uint64_t *p)
{
	uint64_t tmp[NUM_ECC_DIGITS];
	uint64_t exp[NUM_ECC_DIGITS];
	uint64_t _1[NUM_ECC_DIGITS] = { 1ull };
	uint64_t _0[NUM_ECC_DIGITS] = { 0 };

	/* check that val ^ ((p - 1) / 2) == [1, 0 or -1] */

	vli_sub(exp, p, _1);
	vli_rshift1(exp);
	vli_mod_exp(tmp, val, exp, p);

	if (vli_cmp(tmp, _1) == 0)
		return 1;
	else if (vli_cmp(tmp, _0) == 0)
		return 0;
	else
		return -1;
}
