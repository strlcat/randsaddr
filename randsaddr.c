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

static struct s_envcfg randsaddr = { .do_connect = YES, .do_fullbytes = YES, .randsources[0] = "/dev/urandom", };
const struct s_envcfg *randsaddr_config = &randsaddr;

static struct s_addrcfg addrs6[RAS_NADDRS];
static size_t naddrs6;
static struct s_addrcfg addrs4[RAS_NADDRS];
static size_t naddrs4;

/* We shall not write to these outside of init function. */
static const struct s_addrcfg *caddrs6 = &addrs6[0];
static const struct s_addrcfg *caddrs4 = &addrs4[0];

#ifdef USE_LIBDL
int (*ras_libc_socket)(int, int, int);
int (*ras_libc_bind)(int, const struct sockaddr *, socklen_t);
int (*ras_libc_connect)(int, const struct sockaddr *, socklen_t);
ssize_t (*ras_libc_send)(int, const void *, size_t, int);
ssize_t (*ras_libc_sendto)(int, const void *, size_t, int, const struct sockaddr *, socklen_t);
ssize_t (*ras_libc_sendmsg)(int, const struct msghdr *, int);
#endif

static char *parse_flags(struct s_addrcfg *sap, const char *saddr)
{
	size_t x;
	const char *s = (const char *)saddr;

	for (x = 0; x < 4; x++) {
		switch (*s) {
			case '-': /* whitelisted - don't bind to these */
			case 'W':
				sap->whitelisted = YES;
				s++;
			break;
			case 'E': /* build EUI64 style saddr */
				if (sap->s_pfx > 88) sap->atype = RAT_NONE;
				else sap->eui64 = YES;
				s++;
			break;
			case 'B':
				sap->whitelisted = YES;
				sap->dont_bind = YES;
				s++;
			break;
			case 'F':
				sap->fullbytes = YES;
				s++;
			break;
		}
	}

	return (char *)s;
}

static void do_init(void)
{
	static char scfg[RAS_CFGSZ];
	char *s, *d, *t, *p;
	char *nmap, *weight;
	ras_atype type;

#ifdef USE_LIBDL
	/* in case of bad libdl implementation, just crash when attempt to call these will occur, clearly revealing culprit. */
	ras_libc_socket = dlsym(RTLD_NEXT, "socket");
	ras_libc_bind = dlsym(RTLD_NEXT, "bind");
	ras_libc_connect = dlsym(RTLD_NEXT, "connect");
	ras_libc_send = dlsym(RTLD_NEXT, "send");
	ras_libc_sendto = dlsym(RTLD_NEXT, "sendto");
	ras_libc_sendmsg = dlsym(RTLD_NEXT, "sendmsg");
#endif

	if (randsaddr.initdone) return;
	if (randsaddr.disabled) return;

	s = getenv("RANDSADDR");
	if (!s) {
_disable:	randsaddr.disabled = YES;
_done:		randsaddr.initdone = YES;
		memset(scfg, 0, sizeof(scfg));
		return;
	}
	else {
		if (ras_strlcpy(scfg, s, sizeof(scfg)) >= sizeof(scfg)) goto _disable;
		ras_strlxstr(scfg, sizeof(scfg), "\r\n", "\n");
	}

	s = d = scfg; t = NULL;
	while ((s = strtok_r(d, " ,\n\t", &t))) {
		if (d) d = NULL;

		if (ras_str_empty(s)) continue;

		if (!strncasecmp(s, "random=", CSTR_SZ("random="))) {
			size_t x;

			for (x = 0; randsaddr.randsources[x] && x < RAS_NRANDPATHS; x++);
			if (x >= RAS_NRANDPATHS) continue;
			randsaddr.randsources[x] = s+CSTR_SZ("random=");
			continue;
		}
		else if (!strcasecmp(s, "socket")) {
			randsaddr.do_socket = YES;
			continue;
		}
		else if (!strcasecmp(s, "-socket")) {
			randsaddr.do_socket = NO;
			continue;
		}
		else if (!strcasecmp(s, "bind")) {
			randsaddr.do_bind = YES;
			continue;
		}
		else if (!strcasecmp(s, "-bind")) {
			randsaddr.do_bind = NO;
			continue;
		}
		else if (!strcasecmp(s, "connect")) {
			randsaddr.do_connect = YES;
			continue;
		}
		else if (!strcasecmp(s, "-connect")) {
			randsaddr.do_connect = NO;
			continue;
		}
		else if (!strcasecmp(s, "send")) {
			randsaddr.do_send = YES;
			continue;
		}
		else if (!strcasecmp(s, "-send")) {
			randsaddr.do_send = NO;
			continue;
		}
		else if (!strcasecmp(s, "sendto")) {
			randsaddr.do_sendto = YES;
			continue;
		}
		else if (!strcasecmp(s, "-sendto")) {
			randsaddr.do_sendto = NO;
			continue;
		}
		else if (!strcasecmp(s, "sendmsg")) {
			randsaddr.do_sendmsg = YES;
			continue;
		}
		else if (!strcasecmp(s, "-sendmsg")) {
			randsaddr.do_sendmsg = NO;
			continue;
		}
		else if (!strcasecmp(s, "eui64")) {
			randsaddr.do_eui64 = YES;
			continue;
		}
		else if (!strcasecmp(s, "-eui64")) {
			randsaddr.do_eui64 = NO;
			continue;
		}
		else if (!strcasecmp(s, "reuseaddr")) {
			randsaddr.do_reuseaddr = YES;
			continue;
		}
		else if (!strcasecmp(s, "-reuseaddr")) {
			randsaddr.do_reuseaddr = NO;
			continue;
		}
		else if (!strcasecmp(s, "fullbytes")) {
			randsaddr.do_fullbytes = YES;
			continue;
		}
		else if (!strcasecmp(s, "-fullbytes")) {
			randsaddr.do_fullbytes = NO;
			continue;
		}
		else if (!strcasecmp(s, "env")) {
			randsaddr.do_clear_env = NO;
			continue;
		}
		else if (!strcasecmp(s, "-env")) {
			randsaddr.do_clear_env = YES;
			continue;
		}

		nmap = weight = NULL;
		p = strchr(s, '=');
		if (p) { /* netmap */
			*p = 0; p++; nmap = p;
		}
		p = strchr(nmap ? nmap : s, '#');
		if (p) { /* weight */
			*p = 0; p++; weight = p;
		}

		type = ras_addr_type(s);
		if (type == RAT_IPV6) {
			if (naddrs6 >= RAS_NADDRS) continue;
			addrs6[naddrs6].atype = type;
			addrs6[naddrs6].eui64 = randsaddr_config->do_eui64;
			addrs6[naddrs6].fullbytes = randsaddr_config->do_fullbytes;
			addrs6[naddrs6].s_pfx = ras_saddr_prefix(s);
			s = parse_flags(&addrs6[naddrs6], s);
			if (ras_stobaddr(RAT_IPV6, addrs6[naddrs6].sa.ipa, s) != YES) {
				addrs6[naddrs6].atype = RAT_NONE;
				continue;
			}
			if (nmap) {
				addrs6[naddrs6].remap = YES;
				addrs6[naddrs6].d_pfx = ras_saddr_prefix(nmap);
				if (ras_stobaddr(RAT_IPV6, addrs6[naddrs6].da.ipa, nmap) != YES) {
					addrs6[naddrs6].atype = RAT_NONE;
					continue;
				}
			}
			if (weight) {
				addrs6[naddrs6].weight = (size_t)strtoul(weight, &p, 10);
				if (!ras_str_empty(p)) addrs6[naddrs6].weight = NOSIZE;
				else randsaddr.totalweight += addrs6[naddrs6].weight;
			}
			else addrs6[naddrs6].weight = NOSIZE;
			naddrs6++;
		}
		else if (type == RAT_IPV4) {
			if (naddrs4 >= RAS_NADDRS) continue;
			addrs4[naddrs4].atype = type;
			addrs4[naddrs4].fullbytes = randsaddr_config->do_fullbytes;
			addrs4[naddrs4].s_pfx = ras_saddr_prefix(s);
			s = parse_flags(&addrs4[naddrs4], s);
			if (ras_stobaddr(RAT_IPV4, addrs4[naddrs4].sa.ipa, s) != YES) {
				addrs4[naddrs4].atype = RAT_NONE;
				continue;
			}
			if (nmap) {
				addrs4[naddrs4].remap = YES;
				addrs4[naddrs4].d_pfx = ras_saddr_prefix(nmap);
				if (ras_stobaddr(RAT_IPV4, addrs4[naddrs4].da.ipa, nmap) != YES) {
					addrs4[naddrs4].atype = RAT_NONE;
					continue;
				}
			}
			if (weight) {
				addrs4[naddrs4].weight = (size_t)strtoul(weight, &p, 10);
				if (!ras_str_empty(p)) addrs4[naddrs4].weight = NOSIZE;
				else randsaddr.totalweight += addrs4[naddrs4].weight;
			}
			else addrs4[naddrs4].weight = NOSIZE;
			naddrs4++;
		}
	}

	ras_prng_init();

	if (randsaddr.do_clear_env) {
		s = getenv("RANDSADDR");
		if (s) memset(s, 0, strlen(s));
		unsetenv("RANDSADDR");
	}

	goto _done;
}

ras_yesno ras_addr_bindable(int af, const union s_addr *psa)
{
	size_t x;

	if (af == AF_INET6) for (x = 0; x < naddrs6; x++) {
		if (caddrs6[x].atype == RAT_IPV6
		&& caddrs6[x].dont_bind == YES
		&& ras_compare_prefix(RAT_IPV6, &psa->v6a.sin6_addr.s6_addr, caddrs6[x].sa.v6b, caddrs6[x].s_pfx)) {
			return NO;
		}
	}
	if (af == AF_INET) for (x = 0; x < naddrs4; x++) {
		if (caddrs4[x].atype == RAT_IPV4
		&& caddrs4[x].dont_bind == YES
		&& ras_compare_prefix(RAT_IPV4, &psa->v4a.sin_addr, caddrs4[x].sa.v4b, caddrs4[x].s_pfx)) {
			return NO;
		}
	}
	return YES;
}

ras_yesno ras_addr_remapped(int af, union s_addr *pda, const union s_addr *psa)
{
	ras_yesno res = NO;
	const struct s_addrcfg *sap = NULL;
	size_t x;

	memcpy(pda, psa, sizeof(union s_addr));

	if (af == AF_INET6) for (x = 0; x < naddrs6; x++) {
		if (caddrs6[x].atype == RAT_IPV6
		&& caddrs6[x].remap == YES
		&& ras_compare_prefix(RAT_IPV6, &psa->v6a.sin6_addr.s6_addr, caddrs6[x].sa.v6b, caddrs6[x].s_pfx)) {
			res = YES;
			sap = &caddrs6[x];
			break;
		}
	}
	if (af == AF_INET) for (x = 0; x < naddrs4; x++) {
		if (caddrs4[x].atype == RAT_IPV4
		&& caddrs4[x].remap == YES
		&& ras_compare_prefix(RAT_IPV4, &psa->v4a.sin_addr, caddrs4[x].sa.v4b, caddrs4[x].s_pfx)) {
			res = YES;
			sap = &caddrs4[x];
			break;
		}
	}

	if (res) {
		if (af == AF_INET6) {
			if (!ras_mkrandaddr6(&pda->v6a.sin6_addr.s6_addr, sap->da.v6b, sap->d_pfx, sap->fullbytes)) return NO;
			if (sap->eui64) ras_mkeui64addr(&pda->v6a.sin6_addr.s6_addr, &pda->v6a.sin6_addr.s6_addr);
		}
		else if (af == AF_INET) {
			if (!ras_mkrandaddr4(&pda->v4a.sin_addr, sap->da.v4b, sap->d_pfx, sap->fullbytes)) return NO;
		}
	}

	return res;
}

/* returns YES on successful bind(2) event, otherwise returns NO */
static ras_yesno common_bind_random(int sockfd, in_port_t portid, ras_yesno from_bind)
{
	const struct s_addrcfg *sap;
	size_t x;
	union s_addr sa;

	if (naddrs6 == 0) goto _try4;
_na6:	x = ras_prng_index(0, naddrs6 > 0 ? (naddrs6-1) : 0);
	sap = &caddrs6[x];
	if (sap->whitelisted == YES && sap->dont_bind != YES) goto _na6; /* whitelisted: get another */
	if (sap->remap == YES && from_bind == YES) return NO;
	if (sap->weight != NOSIZE) { /* bias white randomness by weights distribution */
		x = ras_prng_index(0, randsaddr_config->totalweight);
		if (x > sap->weight) goto _na6;
	}
	if (sap->atype == RAT_IPV6) { /* fail of you to provide valid cfg */
		memset(&sa, 0, sizeof(sa));
		if (!ras_mkrandaddr6(&sa.v6a.sin6_addr.s6_addr, sap->sa.v6b, sap->s_pfx, sap->fullbytes)) {
			goto _try4;
		}
		if (sap->eui64) ras_mkeui64addr(&sa.v6a.sin6_addr.s6_addr, &sa.v6a.sin6_addr.s6_addr);
		for (x = 0; x < naddrs6; x++) { /* whitelisted range: get another */
			if (caddrs6[x].whitelisted == YES
			&& caddrs6[x].dont_bind != YES
			&& ras_compare_prefix(RAT_IPV6, &sa.v6a.sin6_addr.s6_addr, caddrs6[x].sa.v6b, caddrs6[x].s_pfx)) {
				goto _na6;
			}
		}
		sa.v6a.sin6_family = AF_INET6;
		sa.v6a.sin6_port = portid;
		if (!ras_addr_bindable(AF_INET6, &sa)) goto _try4;
		if (randsaddr_config->do_reuseaddr) {
			int v = 1;
			setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, &v, sizeof(v));
		}
		/* This call shall ignore any errors since it's just hint anyway. */
#ifdef USE_LIBDL
		if (ras_libc_bind(sockfd, (struct sockaddr *)&sa.v6a, sizeof(struct sockaddr_in6)) == 0) return YES;
#else
		if (syscall(SYS_bind, sockfd, (struct sockaddr *)&sa.v6a, sizeof(struct sockaddr_in6)) == 0) return YES;
#endif
		else goto _try4;
	}

_try4:	if (naddrs4 == 0) return NO;
_na4:	x = ras_prng_index(0, naddrs4 > 0 ? (naddrs4-1) : 0);
	sap = &caddrs4[x];
	if (sap->whitelisted == YES && sap->dont_bind != YES) goto _na4; /* whitelisted: get another */
	if (sap->remap == YES && from_bind == YES) return NO;
	if (sap->weight != NOSIZE) { /* bias white randomness by weights distribution */
		x = ras_prng_index(0, (size_t)randsaddr_config->totalweight);
		if (x > sap->weight) goto _na4;
	}
	if (sap->atype == RAT_IPV4) {
		memset(&sa, 0, sizeof(sa));
		if (!ras_mkrandaddr6(&sa.v4a.sin_addr, sap->sa.v4b, sap->s_pfx, sap->fullbytes)) {
			return NO;
		}
		for (x = 0; x < naddrs4; x++) { /* whitelisted range: get another */
			if (caddrs4[x].whitelisted == YES
			&& caddrs4[x].dont_bind != YES
			&& ras_compare_prefix(RAT_IPV4, &sa.v4a.sin_addr, caddrs4[x].sa.v4b, caddrs4[x].s_pfx)) {
				goto _na4;
			}
		}
		sa.v4a.sin_family = AF_INET;
		sa.v4a.sin_port = portid;
		if (!ras_addr_bindable(AF_INET, &sa)) return NO;
		if (randsaddr_config->do_reuseaddr) {
			int v = 1;
			setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, &v, sizeof(v));
		}
		/* This call shall ignore any errors since it's just hint anyway. */
#ifdef USE_LIBDL
		if (ras_libc_bind(sockfd, (struct sockaddr *)&sa.v4a, sizeof(struct sockaddr_in)) == 0) return YES;
#else
		if (syscall(SYS_bind, sockfd, (struct sockaddr *)&sa.v4a, sizeof(struct sockaddr_in)) == 0) return YES;
#endif
		else return NO;
	}

	return NO;
}

static pthread_mutex_t init_mutex = PTHREAD_MUTEX_INITIALIZER;

void ras_init(void)
{
	pthread_mutex_lock(&init_mutex);
	do_init();
	pthread_mutex_unlock(&init_mutex);
}

static pthread_mutex_t bind_mutex = PTHREAD_MUTEX_INITIALIZER;

ras_yesno ras_bind_random(int sockfd, in_port_t portid, ras_yesno from_bind)
{
	ras_yesno res;

	pthread_mutex_lock(&bind_mutex);
	res = common_bind_random(sockfd, portid, from_bind);
	pthread_mutex_unlock(&bind_mutex);

	return res;
}
