#include "randsaddr.h"

ras_atype ras_addr_type(const char *addr)
{
	if (strchr(addr, '.') && !strchr(addr, ':')) return RAT_IPV4;
	else if (strchr(addr, ':') && !strchr(addr, '.')) return RAT_IPV6;
	return RAT_NONE;
}

ras_yesno ras_compare_prefix(ras_atype af, const void *a, const void *b, size_t sz)
{
	const uint8_t *ua = (const uint8_t *)a;
	const uint8_t *ub = (const uint8_t *)b;
	size_t x, y, max;

	if (af == RAT_IPV4) max = 32;
	else if (af == RAT_IPV6) max = 128;
	else return NO;

	if (sz > max) return NO;

	if ((max-sz)%8) {
		for (x = 0; x < (sz/8); x++) if (ua[x] != ub[x]) return NO;
		y = x;
		for (x = (max-sz)%8; x < 8; x++) {
			if ((ua[y] & (1 << x)) != (ub[y] & (1 << x))) return NO;
		}
	}
	else {
		for (x = 0; x < (sz/8); x++) if (ua[x] != ub[x]) return NO;
	}
	return YES;
}
