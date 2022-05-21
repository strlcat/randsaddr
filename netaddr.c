#include "randsaddr.h"

ras_atype ras_addr_type(const char *addr)
{
	if (strchr(addr, '.') && !strchr(addr, ':')) return RAT_IPV4;
	else if (strchr(addr, ':') && !strchr(addr, '.')) return RAT_IPV6;
	return RAT_NONE;
}

ras_yesno ras_stobaddr(ras_atype type, void *baddr, const char *saddr)
{
	char stmp[RAS_ADDRLEN], *s;

	if (type == RAT_IPV6 && ras_addr_type(saddr) == RAT_IPV6) {
		if (ras_strlcpy(stmp, saddr, sizeof(stmp)) >= sizeof(stmp)) return NO;
		s = strchr(stmp, '/');
		if (s) *s = 0;

		ras_strxstr(&stmp[0], "[", "");
		ras_strxstr(&stmp[0], "]", "");

		if (inet_pton(AF_INET6, stmp, baddr) != 1) return NO;
		else return YES;
	}
	else if (type == RAT_IPV4 && ras_addr_type(saddr) == RAT_IPV4) {
		if (ras_strlcpy(stmp, saddr, sizeof(stmp)) >= sizeof(stmp)) return NO;
		s = strchr(stmp, '/');
		if (s) *s = 0;

		ras_strxstr(&stmp[0], "[", "");
		ras_strxstr(&stmp[0], "]", "");

		if (inet_pton(AF_INET, stmp, baddr) != 1) return NO;
		else return YES;
	}

	return NO;
}

size_t ras_saddr_prefix(const char *saddr)
{
	char stmp[RAS_ADDRLEN], *s, *d, *stoi;
	ras_atype atype;
	size_t res;

	if (ras_strlcpy(stmp, saddr, sizeof(stmp)) >= sizeof(stmp)) return NOSIZE;

	atype = ras_addr_type(saddr);
	if (atype != RAT_IPV4 && atype != RAT_IPV6) return NOSIZE;

	s = stmp;
	d = strchr(s, '/');
	if (!d) return NOSIZE;
	*d = 0; d++;
	if (strchr(d, '/')) return NOSIZE;

	res = (size_t)strtoul(d, &stoi, 10);

	if (!ras_str_empty(stoi)) return NOSIZE;
	if (atype == RAT_IPV6 && res > 128) return NOSIZE;
	else if (atype == RAT_IPV4 && res > 32) return NOSIZE;

	return res;
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
