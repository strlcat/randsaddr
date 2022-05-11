#include <string.h>
#include <sys/socket.h>
#include "randsaddr.h"

int addr_type(const char *addr)
{
	if (strchr(addr, '.') && !strchr(addr, ':')) return AF_INET;
	else if (strchr(addr, ':') && !strchr(addr, '.')) return AF_INET6;
	return 0;
}

#if 0
int compare_prefix(int af, const void *a, const void *b, size_t sz)
{
	const uint8_t *ua = (const uint8_t *)a;
	const uint8_t *ub = (const uint8_t *)b;
	size_t x, y, max;

	if (af == AF_INET) max = 32;
	else max = 128;

	if (sz > max) return 0;

	if ((max-sz)%8) {
		for (x = 0; x < (sz/8); x++) if (ua[x] != ub[x]) return 0;
		y = x;
		for (x = (max-sz)%8; x < 8; x++) {
			if ((ua[y] & (1 << x)) != (ub[y] & (1 << x))) return 0;
		}
	}
	else {
		for (x = 0; x < (sz/8); x++) if (ua[x] != ub[x]) return 0;
	}
	return 1;
}
#endif
