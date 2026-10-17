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

	for (x = 0; x < 6; x++) {
		switch (*s) {
			case '-': /* whitelisted - don't bind to these */
			case 'W':
				sap->whitelisted = YES;
				s++;
			break;
			case 'E': /* build EUI64 style saddr */
				if (sap->s_pfx > 88) sap->sa.atype = RAT_NONE;
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
	if (ras_stobaddr(type, addrs->sadm[addrs->nadm].sa.maxsb, s) == YES) {
		addrs->sadm[addrs->nadm].sa.atype = type;
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

static ras_yesno file_flag_disabled(void)
{
	int fd;
	size_t n, sz;
	char tmp[64];

	if (randsaddr_config->disabled) return YES;
	if (!randsaddr_config->disfile) return NO;
	if (!randsaddr_config->dispass) return NO;

	if (access(randsaddr_config->disfile, R_OK) == -1) return NO;
	fd = open(randsaddr_config->disfile, O_RDONLY);
	if (fd == -1) return NO;
	sz = (size_t)read(fd, tmp, sizeof(tmp));
	close(fd);
	n = strlen(randsaddr_config->dispass);
	if (sz == NOSIZE || sz < n) return NO;
	if (!strncmp(tmp, randsaddr_config->dispass, n)) return YES;
	return NO;
}

/* the "fnt" arg is currently unused, but might come handy in future. */
static void do_init(ras_fntyp fnt, const char *cfg)
{
	static char *scfg, *rsenv;
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

	if (randsaddr_config->initdone) return;
	if (randsaddr_config->disabled) return;

	rsenv = NULL;
	if (cfg) scfg = ras_strdup(cfg);
	else {
		rsenv = getenv("RANDSADDR");
		if (!rsenv) {
			randsaddr.disabled = YES;
_done:			randsaddr.initdone = YES;
			return;
		}
		else {
			scfg = ras_strdup(rsenv);
			ras_strlxstr(scfg, ras_szalloc(scfg), "\r\n", "\n");
		}
	}

	s = d = scfg; t = NULL;
	while ((s = strtok_r(d, " ,\n\t", &t))) {
		if (d) d = NULL;

		if (ras_str_empty(s)) continue;

		if (!strncasecmp(s, "random=", CSTR_SZ("random="))) {
			size_t x;

			for (x = 0; randsaddr_config->randsources[x] && x < STAT_ARRAY_SZ(randsaddr_config->randsources); x++);
			if (x >= STAT_ARRAY_SZ(randsaddr_config->randsources)) continue;
			randsaddr.randsources[x] = s+CSTR_SZ("random=");
			continue;
		}
		else if (!strncasecmp(s, "maclist=", CSTR_SZ("maclist="))) {
			read_mac_list(s+CSTR_SZ("maclist="));
			continue;
		}
		else if (!strncasecmp(s, "disable=", CSTR_SZ("disable="))) {
			p = strchr(s+CSTR_SZ("disable="), ':');
			if (!p) continue;
			*p = 0; p++;
			randsaddr.disfile = s+CSTR_SZ("disable=");
			randsaddr.dispass = p;
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
		else if (!strcasecmp(s, "ensure")) {
			randsaddr.do_ensure = YES;
			continue;
		}
		else if (!strcasecmp(s, "-ensure")) {
			randsaddr.do_ensure = NO;
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
		else if (!strcasecmp(s, "session")) {
			randsaddr.do_session = YES;
			continue;
		}
		else if (!strcasecmp(s, "-session")) {
			randsaddr.do_session = NO;
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
			addrs6[naddrs6].sa.atype = type;
			addrs6[naddrs6].stype = RST_ANY;
			addrs6[naddrs6].eui64 = randsaddr_config->do_eui64;
			addrs6[naddrs6].fullbytes = randsaddr_config->do_fullbytes;
			addrs6[naddrs6].s_pfx = ras_saddr_prefix(s);
			s = parse_flags(&addrs6[naddrs6], s);
			if (ras_stobaddr(RAT_IPV6, addrs6[naddrs6].sa.maxsb, s) != YES) {
				addrs6[naddrs6].sa.atype = RAT_NONE;
				continue;
			}
			if (nmap) {
				addrs6[naddrs6].remap = YES;
				addrs6[naddrs6].d_pfx = ras_saddr_prefix(nmap);
				if (ras_stobaddr(RAT_IPV6, addrs6[naddrs6].da.maxsb, nmap) != YES) {
					addrs6[naddrs6].sa.atype = RAT_NONE;
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
			addrs4[naddrs4].sa.atype = type;
			addrs4[naddrs4].stype = RST_ANY;
			addrs4[naddrs4].fullbytes = randsaddr_config->do_fullbytes;
			addrs4[naddrs4].s_pfx = ras_saddr_prefix(s);
			s = parse_flags(&addrs4[naddrs4], s);
			if (ras_stobaddr(RAT_IPV4, addrs4[naddrs4].sa.maxsb, s) != YES) {
				addrs4[naddrs4].sa.atype = RAT_NONE;
				continue;
			}
			if (nmap) {
				addrs4[naddrs4].remap = YES;
				addrs4[naddrs4].d_pfx = ras_saddr_prefix(nmap);
				if (ras_stobaddr(RAT_IPV4, addrs4[naddrs4].da.maxsb, nmap) != YES) {
					addrs4[naddrs4].sa.atype = RAT_NONE;
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

	if (randsaddr_config->do_clear_env) {
		if (rsenv) memset(rsenv, 0, strlen(rsenv));
		unsetenv("RANDSADDR");
	}

	caddrs6 = (const struct s_addrcfg *)addrs6;
	caddrs4 = (const struct s_addrcfg *)addrs4;

	goto _done;
}

static ras_yesno __ras_mkrandaddr6(void *d_addr, const void *s_addr, size_t prefix, ras_yesno want_full)
{
	ras_yesno r;

	if (randsaddr_config->do_session) {
		if (randsaddr_config->session_done6) memcpy(d_addr, randsaddr_config->session_addr_data6.inet6, sizeof(randsaddr.session_addr_data6.inet6));
		else {
			r = ras_mkrandaddr6(d_addr, s_addr, prefix, want_full);
			if (!r) return r;
			memcpy(&randsaddr.session_addr_data6.inet6, d_addr, sizeof(randsaddr.session_addr_data6.inet6));
			randsaddr.session_done6 = YES;
		}
		return YES;
	}
	return ras_mkrandaddr6(d_addr, s_addr, prefix, want_full);
}

static ras_yesno __ras_mkrandaddr4(void *d_addr, const void *s_addr, size_t prefix, ras_yesno want_full)
{
	ras_yesno r;

	if (randsaddr_config->do_session) {
		if (randsaddr_config->session_done4) memcpy(d_addr, randsaddr_config->session_addr_data4.inet4, sizeof(randsaddr.session_addr_data4.inet4));
		else {
			r = ras_mkrandaddr6(d_addr, s_addr, prefix, want_full);
			if (!r) return r;
			memcpy(&randsaddr.session_addr_data4.inet4, d_addr, sizeof(randsaddr.session_addr_data4.inet4));
			randsaddr.session_done4 = YES;
		}
		return YES;
	}
	return ras_mkrandaddr4(d_addr, s_addr, prefix, want_full);
}

ras_atype ras_socket_domain(int sockfd)
{
	int res;
	socklen_t sl;

	sl = (socklen_t)sizeof(res);
	if (getsockopt(sockfd, SOL_SOCKET, SO_DOMAIN, (void *)&res, &sl) == -1) return RAT_NONE;

	switch (res) {
		case AF_INET:	return RAT_IPV4;
		case AF_INET6:	return RAT_IPV6;
	}
	/* dunno, you gave me something other (AF_UNIX?) */
	return RAT_NONE;
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
		default:	  return RST_ANY;
	}
	return RST_ERROR;
}

ras_yesno ras_addr_bindable_socket(int sockfd, const struct s_addr *psa)
{
	size_t x;
	ras_stype st = RST_ERROR;

	if (psa->atype != RAT_IPV4 && psa->atype != RAT_IPV6) return NO;

	if (sockfd != -1) {
		st = ras_socket_type(sockfd);
		if (st == RST_ERROR) return NO;
	}

	if (psa->atype == RAT_IPV6) for (x = 0; x < naddrs6; x++) {
		if (caddrs6[x].sa.atype != RAT_IPV6) continue;
		if (caddrs6[x].dont_bind == YES
		&& ras_compare_prefix(RAT_IPV6, psa->inet6, caddrs6[x].sa.inet6, caddrs6[x].s_pfx)) {
			return NO;
		}
		if (sockfd != -1) {
			if (caddrs6[x].stype != RST_ANY
			&& caddrs6[x].stype != st
			&& ras_compare_prefix(RAT_IPV6, psa->inet6, caddrs6[x].sa.inet6, caddrs6[x].s_pfx)) {
				return NO;
			}
		}
	}
	if (psa->atype == RAT_IPV4) for (x = 0; x < naddrs4; x++) {
		if (caddrs4[x].sa.atype != RAT_IPV4) continue;
		if (caddrs4[x].dont_bind == YES
		&& ras_compare_prefix(RAT_IPV4, psa->inet4, caddrs4[x].sa.inet4, caddrs4[x].s_pfx)) {
			return NO;
		}
		if (sockfd != -1) {
			if (caddrs4[x].stype != RST_ANY
			&& caddrs4[x].stype != st
			&& ras_compare_prefix(RAT_IPV4, psa->inet4, caddrs4[x].sa.inet4, caddrs4[x].s_pfx)) {
				return NO;
			}
		}
	}
	return YES;
}

ras_yesno ras_addr_bindable(const struct s_addr *psa)
{
	return ras_addr_bindable_socket(-1, psa);
}

ras_yesno ras_addr_remapped_socket(int sockfd, struct s_addr *pda, const struct s_addr *psa)
{
	ras_yesno res = NO;
	const struct s_addrcfg *sap = NULL;
	size_t x;
	ras_stype st;

	if (psa->atype != RAT_IPV4 && psa->atype != RAT_IPV6) return NO;

	if (sockfd != -1) {
		st = ras_socket_type(sockfd);
		if (st == RST_ERROR) return NO;
	}

	if (psa->atype == RAT_IPV6) for (x = 0; x < naddrs6; x++) {
		if (caddrs6[x].sa.atype != RAT_IPV6) continue;
		if (sockfd != -1) { /* socktype specific one */
			if (caddrs6[x].stype == RST_ANY) goto _ag6;
			if (caddrs6[x].remap == YES
			&& caddrs6[x].stype == st
			&& ras_compare_prefix(RAT_IPV6, psa->inet6, caddrs6[x].sa.inet6, caddrs6[x].s_pfx)) {
				res = YES;
				sap = &caddrs6[x];
				break;
			}
		}
		else { /* more generic one */
_ag6:			if (caddrs6[x].remap == YES
			&& ras_compare_prefix(RAT_IPV6, psa->inet6, caddrs6[x].sa.inet6, caddrs6[x].s_pfx)) {
				res = YES;
				sap = &caddrs6[x];
				break;
			}
		}
	}
	if (psa->atype == RAT_IPV4) for (x = 0; x < naddrs4; x++) {
		if (caddrs4[x].sa.atype != RAT_IPV4) continue;
		if (sockfd != -1) {
			if (caddrs4[x].stype == RST_ANY) goto _ag4;
			if (caddrs4[x].remap == YES
			&& caddrs4[x].stype == st
			&& ras_compare_prefix(RAT_IPV4, psa->inet4, caddrs4[x].sa.inet4, caddrs4[x].s_pfx)) {
				res = YES;
				sap = &caddrs4[x];
				break;
			}
		}
		else {
_ag4:			if (caddrs4[x].remap == YES
			&& ras_compare_prefix(RAT_IPV4, psa->inet4, caddrs4[x].sa.inet4, caddrs4[x].s_pfx)) {
				res = YES;
				sap = &caddrs4[x];
				break;
			}
		}
	}

	if (res) {
		memcpy(pda, psa, sizeof(struct s_addr));
		if (psa->atype == RAT_IPV6) {
			if (!__ras_mkrandaddr6(pda->inet6, sap->da.inet6, sap->d_pfx, sap->fullbytes)) return NO;
			if (sap->eui64) ras_mkeui64addr(pda->inet6, pda->inet6);
		}
		else if (psa->atype == RAT_IPV4) {
			if (!__ras_mkrandaddr4(pda->inet4, sap->da.inet4, sap->d_pfx, sap->fullbytes)) return NO;
		}
	}

	return res;
}

static ras_yesno rand_addr_sock(ras_fntyp fnt, int sockfd, in_port_t portid, struct s_addr *dsa)
{
	const struct s_addrcfg *sap;
	size_t x;
	struct s_addr sa;
	ras_atype at;
	ras_stype st;
	size_t na6, na4;

	if (sockfd == -1 && (fnt != RFN_RNDADDR4 && fnt != RFN_RNDADDR6)) return NO;

	if (sockfd != -1) {
		/* do not honor global knobs in case if running from rndaddr program */
		if (randsaddr_config->disabled) return NO;
		if (file_flag_disabled() == YES) return NO;
	}

	if (sockfd != -1) {
		at = ras_socket_domain(sockfd);
		if (at == RAT_NONE) return NO;
	}
	else {
		if (fnt == RFN_RNDADDR4) at = RAT_IPV4;
		else if (fnt == RFN_RNDADDR6) at = RAT_IPV6;
		else return NO;
	}

	if (sockfd != -1) {
		st = ras_socket_type(sockfd);
		if (st == RST_ERROR) return NO;
	}
	else st = RST_ANY;

	na6 = naddrs6;
	na4 = naddrs4;

	if (at != RAT_IPV6) goto _try4;
_xa6:	if (na6 == 0) goto _try4;
_na6:	x = ras_prng_index(0, na6 > 0 ? (na6-1) : 0);
	sap = &caddrs6[x];
	if (sap->whitelisted == YES && sap->dont_bind != YES) goto _na6; /* whitelisted: get another */
	if (sap->remap == YES && fnt == RFN_BIND) return NO;
	if (sap->weight != NOSIZE) { /* bias white randomness by weights distribution */
		x = ras_prng_index(0, randsaddr_config->totalweight);
		if (x > sap->weight) goto _na6;
	}
	if (sap->sa.atype == RAT_IPV6) { /* fail of you to provide valid cfg */
		if (sap->stype != RST_ANY && sap->stype != st) {
			na6--; /* this can create DoS condition, so keep a counter around */
			goto _xa6; /* we don't want this socket, get another */
		}

		memset(&sa, 0, sizeof(sa));
		sa.atype = RAT_IPV6;

		if (!__ras_mkrandaddr6(sa.inet6, sap->sa.inet6, sap->s_pfx, sap->fullbytes)) {
			goto _try4;
		}
		ras_apply_addrmods(&sa, sap->sadm, sap->nadm);
		if (sap->eui64) ras_mkeui64addr(sa.inet6, sa.inet6);
		/* intentional use of full naddrs6 follows, this is intended */
		for (x = 0; x < naddrs6; x++) { /* whitelisted range: get another */
			if (caddrs6[x].whitelisted == YES
			&& caddrs6[x].dont_bind != YES
			&& ras_compare_prefix(RAT_IPV6, sa.inet6, caddrs6[x].sa.inet6, caddrs6[x].s_pfx)) {
				goto _na6;
			}
		}

		if (sockfd == -1) {
			/* Just copy the result of function, and return success */
			memcpy(dsa, &sa, sizeof(struct s_addr));
			return YES;
		}
		else {
			struct ras_sockaddr ska;

			if (!ras_addr_bindable(&sa)) goto _try4;
			ras_saddr_to_sockaddr(&ska, &sa, portid);
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
			if (ras_libc_bind(sockfd, (struct sockaddr *)&ska.inet6, sizeof_s(struct ras_sockaddr, inet6)) == 0) return YES;
#else
			if (syscall(SYS_bind, sockfd, (struct sockaddr *)&ska.inet6, sizeof_s(struct ras_sockaddr, inet6)) == 0) return YES;
#endif
			else goto _try4;
		}
	}

_try4:	if (na4 == 0) return NO;
	if (at != RAT_IPV4) return NO;
_na4:	x = ras_prng_index(0, na4 > 0 ? (na4-1) : 0);
	sap = &caddrs4[x];
	if (sap->whitelisted == YES && sap->dont_bind != YES) goto _na4; /* whitelisted: get another */
	if (sap->remap == YES && fnt == RFN_BIND) return NO;
	if (sap->weight != NOSIZE) { /* bias white randomness by weights distribution */
		x = ras_prng_index(0, (size_t)randsaddr_config->totalweight);
		if (x > sap->weight) goto _na4;
	}
	if (sap->sa.atype == RAT_IPV4) {
		if (sap->stype != RST_ANY && sap->stype != st) {
			na4--; /* this can create DoS condition, so keep a counter around */
			goto _try4; /* we don't want this socket, get another */
		}

		memset(&sa, 0, sizeof(sa));
		sa.atype = RAT_IPV4;

		if (!__ras_mkrandaddr4(sa.inet4, sap->sa.inet4, sap->s_pfx, sap->fullbytes)) {
			return NO;
		}
		ras_apply_addrmods(&sa, sap->sadm, sap->nadm);
		/* intentional use of full naddrs4 follows, this is intended */
		for (x = 0; x < naddrs4; x++) { /* whitelisted range: get another */
			if (caddrs4[x].whitelisted == YES
			&& caddrs4[x].dont_bind != YES
			&& ras_compare_prefix(RAT_IPV4, sa.inet4, caddrs4[x].sa.inet4, caddrs4[x].s_pfx)) {
				goto _na4;
			}
		}

		if (sockfd == -1) {
			/* Just copy the result of function, and return success */
			memcpy(dsa, &sa, sizeof(struct s_addr));
			return YES;
		}
		else {
			struct ras_sockaddr ska;

			if (!ras_addr_bindable(&sa)) return NO;
			ras_saddr_to_sockaddr(&ska, &sa, portid);
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
			if (ras_libc_bind(sockfd, (struct sockaddr *)&ska.inet4, sizeof_s(struct ras_sockaddr, inet4)) == 0) return YES;
#else
			if (syscall(SYS_bind, sockfd, (struct sockaddr *)&ska.inet4, sizeof_s(struct ras_sockaddr, inet4)) == 0) return YES;
#endif
			else return NO;
		}
	}

	return NO;
}

static pthread_mutex_t init_mutex = PTHREAD_MUTEX_INITIALIZER;

void ras_init(ras_fntyp fnt, const char *cfg)
{
	pthread_mutex_lock(&init_mutex);
	do_init(fnt, cfg);
	pthread_mutex_unlock(&init_mutex);
}

static pthread_mutex_t bind_mutex = PTHREAD_MUTEX_INITIALIZER;

ras_yesno ras_bind_random(ras_fntyp fnt, int sockfd, in_port_t portid, struct s_addr *dsa)
{
	ras_yesno res;

	pthread_mutex_lock(&bind_mutex);
	if (fnt == RFN_RNDADDR4 || fnt == RFN_RNDADDR6) res = rand_addr_sock(fnt, -1, 0, dsa);
	else res = rand_addr_sock(fnt, sockfd, portid, NULL);
	pthread_mutex_unlock(&bind_mutex);

	return res;
}
