/*
 * randsaddr: randomize source address of outgoing sockets.
 *
 * randsaddr is copyrighted:
 * Copyright (C) 2022, 2023, 2024, 2026 Rys Andrey. All rights reserved.
 *
 * randsaddr is licensed to you under the terms of std. MIT/X11 license:
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
 * MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.
 * IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY
 * CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT,
 * TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE
 * SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
 */

#include "randsaddr.h"

static inline void reverse_bytes(TFNG_BYTE_TYPE *x, size_t xl)
{
	TFNG_BYTE_TYPE *e = x+xl-1;
	while (x < e) {
		*x ^= *e;
		*e ^= *x;
		*x ^= *e;
		x++; e--;
	}
}

static void add_block(TFNG_BYTE_TYPE *x, size_t xl, const TFNG_BYTE_TYPE *y, size_t yl)
{
	size_t cf = 0;
	TFNG_BYTE_TYPE t = 0;

	for (size_t z = 0; z < xl; z++) {
		t = x[z] + (z >= yl ? (TFNG_BYTE_TYPE)0 : y[z]) + cf;
		if (cf) cf = (x[z] >= t ? 1 : 0);
		else cf = (x[z] > t ? 1 : 0);
		x[z] = t;
	}
}

static void ras_bit_block(void *dst, const void *src, size_t sz, ras_bitop op)
{
	const size_t *sx = (const size_t *)src;
	const TFNG_BYTE_TYPE *usx = (const TFNG_BYTE_TYPE *)src;
	size_t *dx = (size_t *)dst;
	TFNG_BYTE_TYPE *udx = (TFNG_BYTE_TYPE *)dst;
	size_t sl = sz;

	if (op == RBO_AND) {
		for (sl = 0; sl < (sz / sizeof(size_t)); sl++) dx[sl] &= sx[sl];
		if (sz - (sl * sizeof(size_t))) for (sl *= sizeof(size_t); sl < sz; sl++) udx[sl] &= usx[sl];
	}
	else if (op == RBO_OR) {
		for (sl = 0; sl < (sz / sizeof(size_t)); sl++) dx[sl] |= sx[sl];
		if (sz - (sl * sizeof(size_t))) for (sl *= sizeof(size_t); sl < sz; sl++) udx[sl] |= usx[sl];
	}
	else if (op == RBO_XOR) {
		for (sl = 0; sl < (sz / sizeof(size_t)); sl++) dx[sl] ^= sx[sl];
		if (sz - (sl * sizeof(size_t))) for (sl *= sizeof(size_t); sl < sz; sl++) udx[sl] ^= usx[sl];
	}
	else if (op == RBO_ADD) {
		TFNG_BYTE_TYPE tmp[RAS_V6LEN];

		/*
		 * Well, this is VERY ugly.
		 *
		 * add_block() works as little-endian, e.g. first byte in input (MSB)
		 * considered as the LSB of the large number we operate on. Example:
		 * 80fee0ae + 0000024c = 80fee2fa must be properly calculated this way:
		 *
		 *	rev(80fee0ae) = aee0fe80
		 *	rev(0000024c) = 4c020000
		 *	add_block(aee0fe80, 4c020000) = fae2fe80
		 *	rev(fae2fe80) = 80fee2fa
		 *
		 * Since there must be IPv6 adder version, I cannot simply cast to uint32_t and bswap.
		 *
		 * I promise, one day I will write a big-endian version of arbitrary length word adder, but not now.
		 */
		reverse_bytes(udx, sz);
		memcpy(tmp, usx, sizeof(tmp) > sz ? sz : sizeof(tmp));
		reverse_bytes(tmp, sizeof(tmp) > sz ? sz : sizeof(tmp));
		add_block(udx, sz, tmp, sizeof(tmp));
		reverse_bytes(udx, sz);
	}
	else memmove(dst, src, sz);
}

void ras_xor_block(void *dst, const void *src, size_t sz)
{
	ras_bit_block(dst, src, sz, RBO_XOR);
}

void ras_and_block(void *dst, const void *src, size_t sz)
{
	ras_bit_block(dst, src, sz, RBO_AND);
}

void ras_or_block(void *dst, const void *src, size_t sz)
{
	ras_bit_block(dst, src, sz, RBO_OR);
}

void ras_add_block(void *dst, const void *src, size_t sz)
{
	ras_bit_block(dst, src, sz, RBO_ADD);
}

void ras_apply_addrmods(struct s_addr *sa, const struct s_addrmod *adm, size_t nadm)
{
	size_t x;

	for (x = 0; x < nadm; x++) {
		ras_atype at = adm[x].sa.atype;

		switch (adm[x].aop) {
			case RBO_NONE: break;
			case RBO_AND:
				if (at == RAT_IPV6) ras_and_block(sa->inet6, adm[x].sa.inet6, RAS_V6LEN);
				else if (at == RAT_IPV4) ras_and_block(sa->inet4, adm[x].sa.inet4, RAS_V4LEN);
				break;
			case RBO_OR:
				if (at == RAT_IPV6) ras_or_block(sa->inet6, adm[x].sa.inet6, RAS_V6LEN);
				else if (at == RAT_IPV4) ras_or_block(sa->inet4, adm[x].sa.inet4, RAS_V4LEN);
				break;
			case RBO_XOR:
				if (at == RAT_IPV6) ras_xor_block(sa->inet6, adm[x].sa.inet6, RAS_V6LEN);
				else if (at == RAT_IPV4) ras_xor_block(sa->inet4, adm[x].sa.inet4, RAS_V4LEN);
				break;
			case RBO_ADD:
				if (at == RAT_IPV6) ras_add_block(sa->inet6, adm[x].sa.inet6, RAS_V6LEN);
				else if (at == RAT_IPV4) ras_add_block(sa->inet4, adm[x].sa.inet4, RAS_V4LEN);
				break;
		}
	}
}
