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

static inline void xor_block(void *dst, const void *src, size_t sz)
{
	const size_t *sx = (const size_t *)src;
	const TFNG_BYTE_TYPE *usx = (const TFNG_BYTE_TYPE *)src;
	size_t *dx = (size_t *)dst;
	TFNG_BYTE_TYPE *udx = (TFNG_BYTE_TYPE *)dst;
	size_t sl = sz;

	for (sl = 0; sl < (sz / sizeof(size_t)); sl++) dx[sl] ^= sx[sl];
	if (sz - (sl * sizeof(size_t))) for (sl *= sizeof(size_t); sl < sz; sl++) udx[sl] ^= usx[sl];
}

static ras_yesno do_prng_init(void)
{
	static ras_yesno initdone;
	size_t x;
	int fd;
	uint8_t key[TFNG_PRNG_KEY_SIZE], tmp[TFNG_PRNG_KEY_SIZE];

	if (initdone) return YES;

	memset(key, 0, sizeof(key));
	for (x = 0; randsaddr_config->randsources[x] && x < RAS_NRANDPATHS; x++) {
		fd = open(randsaddr_config->randsources[x], O_RDONLY);
		if (fd == -1) {
			if (x == 0 && randsaddr_config->randsources[1]) continue;
			return NO;
		}
		if (read(fd, tmp, sizeof(tmp)) < sizeof(tmp)) {
			close(fd);
			errno = ESPIPE;
			return NO;
		}
		xor_block(key, tmp, sizeof(key));
		close(fd);
	}
	tfng_prng_seedkey(key);

	initdone = YES;
	return YES;
}

void ras_prng_init(void)
{
	if (do_prng_init() != YES) {
		fprintf(stderr, "randsaddr: prng init failed: %s\n", strerror(errno));
		exit(errno);
	}
}

/*
 * @want_full: "I want byte full of bits, without zero nibbles!"
 */
uint8_t ras_prng_getrandc(ras_yesno want_full)
{
	uint8_t res;

_nx:	res = (uint8_t)tfng_prng_range(0, 0xff);
	if (want_full == NO) return res;
	else {
		if ((res >> 4 & 0xf) && (res & 0xf)) return res;
		else goto _nx;
	}
	return res;
}

size_t ras_prng_index(size_t from, size_t to)
{
	return (size_t)tfng_prng_range((TFNG_UNIT_TYPE)from, (TFNG_UNIT_TYPE)to);
}
