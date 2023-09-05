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

static struct s_addrcfg *addrs6;
static size_t naddrs6;
static struct s_addrcfg *addrs4;
static size_t naddrs4;

/* We shall not write to these outside of init function. */
static const struct s_addrcfg *caddrs6;
static const struct s_addrcfg *caddrs4;

#ifdef USE_LIBDL
int (*ras_libc_socket)(int, int, int);
int (*ras_libc_bind)(int, const struct sockaddr *, socklen_t);
int (*ras_libc_connect)(int, const struct sockaddr *, socklen_t);
ssize_t (*ras_libc_send)(int, const void *, size_t, int);
ssize_t (*ras_libc_sendto)(int, const void *, size_t, int, const struct sockaddr *, socklen_t);
ssize_t (*ras_libc_sendmsg)(int, const struct msghdr *, int);
#endif

void ras_fatal(const char *fmt, ...)
{
	va_list ap;

	fputs("randsaddr: ", stderr);
	va_start(ap, fmt);
	vfprintf(stderr, fmt, ap);
	va_end(ap);
	fputc('\n', stderr);
	abort();
}

void ras_malloc_ub(const void *badptr)
{
	ras_fatal("xmalloc failed at %p", badptr);
}

int ras_malloc_oom(int fail, ras_malloc_oom_caller where)
{
	if (!fail) return YES;
	ras_fatal("Out of Memory");
	return NO;
}

void ras_malloc_error(ras_malloc_oom_caller where)
{
	ras_fatal("Out of Memory");
}

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
			case 'T': /* valid only for TCP sockets */
				sap->stype = RST_TCP;
				s++;
			break;
			case 'U': /* valid only for UDP sockets */
				sap->stype = RST_UDP;
				s++;
			break;
		}
	}

	return (char *)s;
}

static void parse_addr_ops(struct s_addrcfg *addrs, ras_atype type, char *addrop)
{
	char *s, *d, *p, sc, dc;

	sc = dc = *addrop;
	s = d = addrop+1;

_again:	p = strchr(s, '%');
	if (p) {
		*p = 0; p++; dc = *p; p++; d = p;
	}

	addrs->sadm = ras_realloc(addrs->sadm, (addrs->nadm + 1) * sizeof(struct s_addrmod));
	if (ras_stobaddr(type, addrs->sadm[addrs->nadm].sa.ipa, s) == YES) {
		switch (sc) {
			case '&':
			case 'N': addrs->sadm[addrs->nadm].aop = RBO_AND; break;
			case '|':
			case 'O': addrs->sadm[addrs->nadm].aop = RBO_OR; break;
			case '^':
			case 'X': addrs->sadm[addrs->nadm].aop = RBO_XOR; break;
		}
	}
	else addrs->sadm[addrs->nadm].aop = RBO_NONE;
	addrs->nadm++;

	s = d; sc = dc;
	if (p) goto _again;
}

static void do_init(void)
{
	static char *scfg;
	char *s, *d, *t, *p;
	char *nmap, *weight, *addrop;
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
		randsaddr.disabled = YES;
_done:		randsaddr.initdone = YES;
		return;
	}
	else {
		scfg = ras_strdup(s);
		ras_strlxstr(scfg, ras_szalloc(scfg), "\r\n", "\n");
	}

	s = d = scfg; t = NULL;
	while ((s = strtok_r(d, " ,\n\t", &t))) {
		if (d) d = NULL;

		if (ras_str_empty(s)) continue;

		if (!strncasecmp(s, "random=", CSTR_SZ("random="))) {
			size_t x;

			for (x = 0; randsaddr.randsources[x] && x < STAT_ARRAY_SZ(randsaddr_config->randsources); x++);
			if (x >= STAT_ARRAY_SZ(randsaddr_config->randsources)) continue;
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
#ifdef IP_FREEBIND
		else if (!strcasecmp(s, "freebind")) {
			randsaddr.do_freebind = YES;
			continue;
		}
		else if (!strcasecmp(s, "-freebind")) {
			randsaddr.do_freebind = NO;
			continue;
		}
#endif
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

		nmap = weight = addrop = NULL;
		p = strchr(s, '=');
		if (p) { /* netmap */
			*p = 0; p++; nmap = p;
		}
		p = strchr(nmap ? nmap : s, '#');
		if (p) { /* weight */
			*p = 0; p++; weight = p;
		}
		p = strchr(weight ? weight : s, '%');
		if (p) { /* modifiers */
			*p = 0; p++; addrop = p;
		}

		type = ras_addr_type(s);
		if (type == RAT_IPV6) {
			addrs6 = ras_realloc(addrs6, (naddrs6 + 1) * sizeof(struct s_addrcfg));
			addrs6[naddrs6].atype = type;
			addrs6[naddrs6].stype = RST_ANY;
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
			if (addrop) parse_addr_ops(&addrs6[naddrs6], RAT_IPV6, addrop);
			naddrs6++;
		}
		else if (type == RAT_IPV4) {
			addrs4 = ras_realloc(addrs4, (naddrs4 + 1) * sizeof(struct s_addrcfg));
			addrs4[naddrs4].atype = type;
			addrs4[naddrs4].stype = RST_ANY;
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
			if (addrop) parse_addr_ops(&addrs4[naddrs4], RAT_IPV4, addrop);
			naddrs4++;
		}
	}

	ras_prng_init();

	if (randsaddr.do_clear_env) {
		s = getenv("RANDSADDR");
		if (s) memset(s, 0, strlen(s));
		unsetenv("RANDSADDR");
	}

	caddrs6 = (const struct s_addrcfg *)addrs6;
	caddrs4 = (const struct s_addrcfg *)addrs4;

	goto _done;
}

ras_stype ras_socket_type(int sockfd)
{
	int res;
	socklen_t sl;

	sl = (socklen_t)sizeof(res);
	if (getsockopt(sockfd, SOL_SOCKET, SO_TYPE, (void *)&res, &sl) == -1) return RST_ERROR;

	switch (res) {
		case SOCK_STREAM: return RST_TCP;
		case SOCK_DGRAM:  return RST_UDP;
		default:	  return RST_ANY; /* dunno, you gave me something other (AF_UNIX?) */
	}
	return RST_ERROR;
}

ras_yesno ras_addr_bindable_socket(int sockfd, int af, const union s_addr *psa)
{
	size_t x;
	ras_stype st;

	if (sockfd != -1) {
		st = ras_socket_type(sockfd);
		if (st == RST_ERROR) return NO;
	}

	if (af == AF_INET6) for (x = 0; x < naddrs6; x++) {
		if (caddrs6[x].atype != RAT_IPV6) continue;
		if (caddrs6[x].dont_bind == YES
		&& ras_compare_prefix(RAT_IPV6, &psa->v6a.sin6_addr.s6_addr, caddrs6[x].sa.v6b, caddrs6[x].s_pfx)) {
			return NO;
		}
		if (sockfd != -1) {
			if (caddrs6[x].stype != RST_ANY
			&& caddrs6[x].stype != st
			&& ras_compare_prefix(RAT_IPV6, &psa->v6a.sin6_addr.s6_addr, caddrs6[x].sa.v6b, caddrs6[x].s_pfx)) {
				return NO;
			}
		}
	}
	if (af == AF_INET) for (x = 0; x < naddrs4; x++) {
		if (caddrs4[x].atype != RAT_IPV4) continue;
		if (caddrs4[x].dont_bind == YES
		&& ras_compare_prefix(RAT_IPV4, &psa->v4a.sin_addr, caddrs4[x].sa.v4b, caddrs4[x].s_pfx)) {
			return NO;
		}
		if (sockfd != -1) {
			if (caddrs4[x].stype != RST_ANY
			&& caddrs4[x].stype != st
			&& ras_compare_prefix(RAT_IPV4, &psa->v4a.sin_addr, caddrs4[x].sa.v4b, caddrs4[x].s_pfx)) {
				return NO;
			}
		}
	}
	return YES;
}

ras_yesno ras_addr_bindable(int af, const union s_addr *psa)
{
	return ras_addr_bindable_socket(-1, af, psa);
}

ras_yesno ras_addr_remapped_socket(int sockfd, int af, union s_addr *pda, const union s_addr *psa)
{
	ras_yesno res = NO;
	const struct s_addrcfg *sap = NULL;
	size_t x;
	ras_stype st;

	if (sockfd != -1) {
		st = ras_socket_type(sockfd);
		if (st == RST_ERROR) return NO;
	}

	memcpy(pda, psa, sizeof(union s_addr));

	if (af == AF_INET6) for (x = 0; x < naddrs6; x++) {
		if (caddrs6[x].atype != RAT_IPV6) continue;
		if (sockfd != -1) { /* socktype specific one */
			if (caddrs6[x].stype == RST_ANY) goto _ag6;
			if (caddrs6[x].remap == YES
			&& caddrs6[x].stype == st
			&& ras_compare_prefix(RAT_IPV6, &psa->v6a.sin6_addr.s6_addr, caddrs6[x].sa.v6b, caddrs6[x].s_pfx)) {
				res = YES;
				sap = &caddrs6[x];
				break;
			}
		}
		else { /* more generic one */
_ag6:			if (caddrs6[x].remap == YES
			&& ras_compare_prefix(RAT_IPV6, &psa->v6a.sin6_addr.s6_addr, caddrs6[x].sa.v6b, caddrs6[x].s_pfx)) {
				res = YES;
				sap = &caddrs6[x];
				break;
			}
		}
	}
	if (af == AF_INET) for (x = 0; x < naddrs4; x++) {
		if (caddrs4[x].atype != RAT_IPV4) continue;
		if (sockfd != -1) {
			if (caddrs4[x].stype == RST_ANY) goto _ag4;
			if (caddrs4[x].remap == YES
			&& caddrs4[x].stype == st
			&& ras_compare_prefix(RAT_IPV4, &psa->v4a.sin_addr, caddrs4[x].sa.v4b, caddrs4[x].s_pfx)) {
				res = YES;
				sap = &caddrs4[x];
				break;
			}
		}
		else {
_ag4:			if (caddrs4[x].remap == YES
			&& ras_compare_prefix(RAT_IPV4, &psa->v4a.sin_addr, caddrs4[x].sa.v4b, caddrs4[x].s_pfx)) {
				res = YES;
				sap = &caddrs4[x];
				break;
			}
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

static void exec_addrops(ras_atype type, void *sa, const struct s_addrmod *adm, size_t nadm)
{
	size_t x, sz;

	switch (type) {
		case RAT_IPV6: sz = 16; break;
		case RAT_IPV4: sz = 4; break;
		default: sz = 0; break;
	}

	for (x = 0; x < nadm; x++) {
		switch (adm[x].aop) {
			case RBO_NONE: break;
			case RBO_AND: ras_and_block(sa, adm[x].sa.ipa, sz); break;
			case RBO_OR: ras_or_block(sa, adm[x].sa.ipa, sz); break;
			case RBO_XOR: ras_xor_block(sa, adm[x].sa.ipa, sz); break;
		}
	}
}

/* returns YES on successful bind(2) event, otherwise returns NO */
static ras_yesno common_bind_random(int sockfd, in_port_t portid, ras_yesno from_bind)
{
	const struct s_addrcfg *sap;
	size_t x;
	union s_addr sa;
	ras_stype st;
	size_t na6, na4;

	if (randsaddr.disabled) return NO;

	st = ras_socket_type(sockfd);
	if (st == RST_ERROR) return NO; /* If I ignore it, maybe it'll go away... */

	na6 = naddrs6;
	na4 = naddrs4;

_xa6:	if (na6 == 0) goto _try4;
_na6:	x = ras_prng_index(0, na6 > 0 ? (na6-1) : 0);
	sap = &caddrs6[x];
	if (sap->whitelisted == YES && sap->dont_bind != YES) goto _na6; /* whitelisted: get another */
	if (sap->remap == YES && from_bind == YES) return NO;
	if (sap->weight != NOSIZE) { /* bias white randomness by weights distribution */
		x = ras_prng_index(0, randsaddr_config->totalweight);
		if (x > sap->weight) goto _na6;
	}
	if (sap->atype == RAT_IPV6) { /* fail of you to provide valid cfg */
		if (sap->stype != RST_ANY && sap->stype != st) {
			na6--; /* this can create DoS condition, so keep a counter around */
			goto _xa6; /* we don't want this socket, get another */
		}

		memset(&sa, 0, sizeof(sa));
		if (!ras_mkrandaddr6(&sa.v6a.sin6_addr.s6_addr, sap->sa.v6b, sap->s_pfx, sap->fullbytes)) {
			goto _try4;
		}
		exec_addrops(sap->atype, &sa.v6a.sin6_addr.s6_addr, sap->sadm, sap->nadm);
		if (sap->eui64) ras_mkeui64addr(&sa.v6a.sin6_addr.s6_addr, &sa.v6a.sin6_addr.s6_addr);
		/* intentional use of full naddrs6 follows, this is intended */
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
#ifdef SO_REUSEPORT
			setsockopt(sockfd, SOL_SOCKET, SO_REUSEPORT, &v, sizeof(v));
#endif
		}
#ifdef IP_FREEBIND
		if (randsaddr_config->do_freebind) {
			int v = 1;
			setsockopt(sockfd, IPPROTO_IP, IP_FREEBIND, &v, sizeof(v));
		}
#endif
		/* This call shall ignore any errors since it's just hint anyway. */
#ifdef USE_LIBDL
		if (ras_libc_bind(sockfd, (struct sockaddr *)&sa.v6a, sizeof(struct sockaddr_in6)) == 0) return YES;
#else
		if (syscall(SYS_bind, sockfd, (struct sockaddr *)&sa.v6a, sizeof(struct sockaddr_in6)) == 0) return YES;
#endif
		else goto _try4;
	}

_try4:	if (na4 == 0) return NO;
_na4:	x = ras_prng_index(0, na4 > 0 ? (na4-1) : 0);
	sap = &caddrs4[x];
	if (sap->whitelisted == YES && sap->dont_bind != YES) goto _na4; /* whitelisted: get another */
	if (sap->remap == YES && from_bind == YES) return NO;
	if (sap->weight != NOSIZE) { /* bias white randomness by weights distribution */
		x = ras_prng_index(0, (size_t)randsaddr_config->totalweight);
		if (x > sap->weight) goto _na4;
	}
	if (sap->atype == RAT_IPV4) {
		if (sap->stype != RST_ANY && sap->stype != st) {
			na4--; /* this can create DoS condition, so keep a counter around */
			goto _try4; /* we don't want this socket, get another */
		}

		memset(&sa, 0, sizeof(sa));
		if (!ras_mkrandaddr4(&sa.v4a.sin_addr, sap->sa.v4b, sap->s_pfx, sap->fullbytes)) {
			return NO;
		}
		exec_addrops(sap->atype, &sa.v4a.sin_addr, sap->sadm, sap->nadm);
		/* intentional use of full naddrs4 follows, this is intended */
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
#ifdef SO_REUSEPORT
			setsockopt(sockfd, SOL_SOCKET, SO_REUSEPORT, &v, sizeof(v));
#endif
		}
#ifdef IP_FREEBIND
		if (randsaddr_config->do_freebind) {
			int v = 1;
			setsockopt(sockfd, IPPROTO_IP, IP_FREEBIND, &v, sizeof(v));
		}
#endif
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
