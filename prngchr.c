#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <string.h>
#include <stdint.h>
#include <stdio.h>
#include <errno.h>
#include "randsaddr.h"

static int prng_init(void)
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

uint8_t prng_getrandc(void)
{
	uint8_t res;

	if (!prng_init()) {
		fprintf(stderr, "prng init failed: %s\n", strerror(errno));
		exit(errno);
	}

	res = (uint8_t)tfng_prng_range(0, 0xff);
	return res;
}
