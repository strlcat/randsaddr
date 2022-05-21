#include "randsaddr.h"

static ras_yesno do_prng_init(void)
{
	static ras_yesno initdone;
	uint8_t key[TFNG_PRNG_KEY_SIZE];
	int fd;

	if (initdone) return YES;

	fd = open("/dev/urandom", O_RDONLY);
	if (fd == -1) return NO;
	read(fd, key, sizeof(key));
	close(fd);

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
