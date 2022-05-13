#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <string.h>
#include <stdint.h>
#include <stdio.h>
#include <errno.h>
#include "randsaddr.h"

static int do_prng_init(void)
{
	static unsigned initdone;
	uint8_t key[TFNG_PRNG_KEY_SIZE];
	int fd;

	if (initdone) return 1;

	fd = open("/dev/urandom", O_RDONLY);
	if (fd == -1) return 0;
	read(fd, key, sizeof(key));
	close(fd);

	tfng_prng_seedkey(key);
	initdone = 1;
	return 1;
}

static void prng_init(void)
{
	if (!do_prng_init()) {
		fprintf(stderr, "prng init failed: %s\n", strerror(errno));
		exit(errno);
	}
}

/*
 * @want_full: "I want byte full of bits, without zero nibbles!"
 */
uint8_t prng_getrandc(ras_yesno want_full)
{
	uint8_t res;

	prng_init();
_nx:	res = (uint8_t)tfng_prng_range(0, 0xff);
	if (want_full == NO) return res;
	else {
		if ((res >> 4 & 0xf) && (res & 0xf)) return res;
		else goto _nx;
	}
	return res;
}

size_t prng_index(size_t from, size_t to)
{
	prng_init();
	return (size_t)tfng_prng_range((TFNG_UNIT_TYPE)from, (TFNG_UNIT_TYPE)to);
}
