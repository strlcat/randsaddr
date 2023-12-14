/*
 * randsaddr: randomize source address of outgoing sockets.
 *
 * randsaddr is copyrighted:
 * Copyright (C) 2022 Rys Andrey. All rights reserved.
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

ras_yesno ras_mkrandaddr6(void *d_addr, const void *s_addr, size_t prefix, ras_yesno want_full)
{
	uint8_t *ud_addr = (uint8_t *)d_addr;
	size_t x;
	uint8_t c;

	if (prefix < 0 || prefix > 128) return NO;
	memcpy(d_addr, s_addr, 16);
	if ((128-prefix)%8) {
		for (x = (prefix/8)+1; x < 16; x++) ud_addr[x] = ras_prng_getrandc(want_full);
		c = ras_prng_getrandc(want_full);
		for (x = 0; x < (128-prefix)%8; x++) {
			if (c & (1 << x)) ud_addr[prefix/8] |= (1 << x);
			else ud_addr[prefix/8] &= ~(1 << x);
		}
	}
	else {
		for (x = (prefix/8); x < 16; x++) ud_addr[x] = ras_prng_getrandc(want_full);
	}
	return YES;
}

void ras_mkeui64addr(void *d_addr, const void *s_addr)
{
	uint8_t *ud_addr = (uint8_t *)d_addr;

	memcpy(d_addr, s_addr, 16);
	ud_addr[11] = 0xff;
	ud_addr[12] = 0xfe;
	ras_amendeui64addr(d_addr, s_addr);
	if (ud_addr[8] & (1 << 0)) ud_addr[8] ^= 1 << 0;
}

ras_yesno ras_mkrandaddr4(void *d_addr, const void *s_addr, size_t prefix, ras_yesno want_full)
{
	uint8_t *ud_addr = (uint8_t *)d_addr;
	size_t x;
	uint8_t c;

	if (prefix < 0 || prefix > 32) return NO;
	memcpy(d_addr, s_addr, 4);
	if ((32-prefix)%8) {
		for (x = (prefix/8)+1; x < 4; x++) ud_addr[x] = ras_prng_getrandc(want_full);
		c = ras_prng_getrandc(want_full);
		for (x = 0; x < (32-prefix)%8; x++) {
			if (c & (1 << x)) ud_addr[prefix/8] |= (1 << x);
			else ud_addr[prefix/8] &= ~(1 << x);
		}
	}
	else {
		for (x = (prefix/8); x < 4; x++) ud_addr[x] = ras_prng_getrandc(want_full);
	}
	return YES;
}
