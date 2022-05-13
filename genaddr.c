#include <stdio.h>
#include <string.h>
#include <sys/time.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <libgen.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <stdint.h>
#include "randsaddr.h"

ras_yesno mkrandaddr6(void *d_addr, const void *s_addr, size_t prefix, ras_yesno want_full)
{
	uint8_t *ud_addr = (uint8_t *)d_addr;
	size_t x;
	uint8_t c;

	if (prefix < 0 || prefix > 128) return NO;
	memcpy(d_addr, s_addr, 16);
	if ((128-prefix)%8) {
		for (x = (prefix/8)+1; x < 16; x++) ud_addr[x] = prng_getrandc(want_full);
		c = prng_getrandc(want_full);
		for (x = 0; x < (128-prefix)%8; x++) {
			if (c & (1 << x)) ud_addr[prefix/8] |= (1 << x);
			else ud_addr[prefix/8] &= ~(1 << x);
		}
	}
	else {
		for (x = (prefix/8); x < 16; x++) ud_addr[x] = prng_getrandc(want_full);
	}
	return YES;
}

void mkeui64addr(void *d_addr, const void *s_addr)
{
	uint8_t *ud_addr = (uint8_t *)d_addr;

	memcpy(d_addr, s_addr, 16);
	ud_addr[11] = 0xff;
	ud_addr[12] = 0xfe;
	if (ud_addr[8] & (1 << 0)) ud_addr[8] ^= 1 << 0;
}

ras_yesno mkrandaddr4(void *d_addr, const void *s_addr, size_t prefix, ras_yesno want_full)
{
	uint8_t *ud_addr = (uint8_t *)d_addr;
	size_t x;
	uint8_t c;

	if (prefix < 0 || prefix > 32) return NO;
	memcpy(d_addr, s_addr, 4);
	if ((32-prefix)%8) {
		for (x = (prefix/8)+1; x < 4; x++) ud_addr[x] = prng_getrandc(want_full);
		c = prng_getrandc(want_full);
		for (x = 0; x < (32-prefix)%8; x++) {
			if (c & (1 << x)) ud_addr[prefix/8] |= (1 << x);
			else ud_addr[prefix/8] &= ~(1 << x);
		}
	}
	else {
		for (x = (prefix/8); x < 4; x++) ud_addr[x] = prng_getrandc(want_full);
	}
	return YES;
}
