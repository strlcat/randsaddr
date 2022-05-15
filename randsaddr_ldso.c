#include <stdio.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <limits.h>
#include <sys/mman.h>
#include <stdint.h>
#include <stdarg.h>
#include <errno.h>
#include <sys/syscall.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <pthread.h>
#include "randsaddr.h"

#define SADDRLEN INET6_ADDRSTRLEN+4
#define NADDRS 64

union s_addr {
	uint8_t ipa[16];
	struct sockaddr_in6 v6a;
	uint8_t v6b[16];
	struct sockaddr_in v4a;
	uint8_t v4b[4];
};

struct s_addrcfg {
	ras_atype atype;
	char s_addr[SADDRLEN];
	size_t s_pfx;
	union s_addr sa;
	ras_yesno eui64;
	ras_yesno whitelisted;
	ras_yesno dont_bind;
	ras_yesno fullbytes;
	ras_yesno remap;
	char d_addr[SADDRLEN];
	size_t d_pfx;
	union s_addr da;
};

struct s_envcfg {
	char s_cfg[sizeof(struct s_addrcfg)*NADDRS*2];

	ras_yesno initdone;
	ras_yesno disabled;

	ras_yesno do_socket; /* dangerous for servers! */
	ras_yesno do_bind; /* dangerous for servers! */
	ras_yesno do_connect;
	ras_yesno do_send;
	ras_yesno do_sendto;
	ras_yesno do_sendmsg;
	ras_yesno do_reuseaddr;
	ras_yesno do_eui64;
	ras_yesno do_fullbytes;
	ras_yesno do_clear_env;
};

static struct s_envcfg randsaddr = { .do_connect = YES, .do_fullbytes = YES, };
static const struct s_envcfg *crandsaddr = &randsaddr;

static struct s_addrcfg addrs6[NADDRS];
static size_t naddrs6;
static struct s_addrcfg addrs4[NADDRS];
static size_t naddrs4;

/* We shall not write to these outside of init function. */
static const struct s_addrcfg *caddrs6 = &addrs6[0];
static const struct s_addrcfg *caddrs4 = &addrs4[0];

void __attribute__((constructor)) randsaddr_init(void)
{
	char *scfg, *s, *d, *t;
	size_t sz, x, y;
	ras_atype type;
	struct s_addrcfg *sap;
	char tmp[SADDRLEN];

	if (randsaddr.initdone) return;
	if (randsaddr.disabled) return;

	s = getenv("RANDSADDR");
	if (!s) {
_disable:	randsaddr.disabled = YES;
_done:		randsaddr.initdone = YES;
		return;
	}
	else {
		if (xstrlcpy(randsaddr.s_cfg, s, sizeof(randsaddr.s_cfg)) >= sizeof(randsaddr.s_cfg)) goto _disable;
		scfg = randsaddr.s_cfg;
	}

	s = d = scfg; t = NULL;
	while ((s = strtok_r(d, ",", &t))) {
		if (d) d = NULL;

		if (!strcasecmp(s, "socket")) {
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

		d = strchr(s, '=');
		if (d) {
			*d = 0; d++;
		}

		type = addr_type(s);
		if (type == RAT_IPV6) {
			if (naddrs6 >= NADDRS) continue;
			addrs6[naddrs6].atype = type;
			if (xstrlcpy(addrs6[naddrs6].s_addr, s, sizeof(addrs6[naddrs6].s_addr)) >= sizeof(addrs6[naddrs6].s_addr)) {
				addrs6[naddrs6].atype = RAT_NONE;
				continue;
			}
			addrs6[naddrs6].eui64 = crandsaddr->do_eui64;
			addrs6[naddrs6].fullbytes = crandsaddr->do_fullbytes;
			addrs6[naddrs6].s_pfx = NOSIZE; /* filled later */
			if (d) {
				addrs6[naddrs6].remap = YES;
				if (xstrlcpy(addrs6[naddrs6].d_addr, d, sizeof(addrs6[naddrs6].d_addr)) >= sizeof(addrs6[naddrs6].d_addr)) {
					addrs6[naddrs6].atype = RAT_NONE;
					continue;
				}
				addrs6[naddrs6].d_pfx = NOSIZE; /* filled later */
			}
			naddrs6++;
		}
		else if (type == RAT_IPV4) {
			if (naddrs4 >= NADDRS) continue;
			naddrs4 = naddrs4;
			addrs4[naddrs4].atype = type;
			if (xstrlcpy(addrs4[naddrs4].s_addr, s, sizeof(addrs4[naddrs4].s_addr)) >= sizeof(addrs4[naddrs4].s_addr)) {
				addrs4[naddrs4].atype = RAT_NONE;
				continue;
			}
			addrs4[naddrs4].fullbytes = crandsaddr->do_fullbytes;
			addrs4[naddrs4].s_pfx = NOSIZE; /* filled later */
			if (d) {
				addrs4[naddrs4].remap = YES;
				if (xstrlcpy(addrs4[naddrs4].d_addr, d, sizeof(addrs4[naddrs4].d_addr)) >= sizeof(addrs4[naddrs4].d_addr)) {
					addrs4[naddrs4].atype = RAT_NONE;
					continue;
				}
				addrs4[naddrs4].d_pfx = NOSIZE; /* filled later */
			}
			naddrs4++;
		}
	}

	if (randsaddr.do_clear_env) {
		s = getenv("RANDSADDR");
		if (s) memset(s, 0, strlen(s));
		unsetenv("RANDSADDR");
	}

	sap = addrs6;
	sz = naddrs6;
	if (sz == 0) {
_for4:		sap = addrs4;
		sz = naddrs4;
		if (sz == 0) goto _done;
	}

	for (x = 0; x < sz; x++) {
		if (sap[x].atype != RAT_IPV4 && sap[x].atype != RAT_IPV6) {
			sap[x].atype = RAT_NONE;
			continue;
		}
		s = sap[x].s_addr;
		d = strchr(s, '/');
		if (!d) {
			sap[x].atype = RAT_NONE;
			continue;
		}
		*d = 0; d++;
		if (strchr(d, '/')) {
			sap[x].atype = RAT_NONE;
			continue;
		}
		sap[x].s_pfx = (size_t)atoi(d);
		if (sap[x].s_pfx > 128) {
			sap[x].atype = RAT_NONE;
			continue;
		}
		else if (sap[x].atype == RAT_IPV4 && sap[x].s_pfx > 32) {
			sap[x].atype = RAT_NONE;
			continue;
		}
		s = sap[x].s_addr;
		for (y = 0; y < 4; y++) {
			switch (*s) {
				case '-': /* whitelisted - don't bind to these */
				case 'W':
					sap[x].whitelisted = YES;
					s++;
				break;
				case 'E': /* build EUI64 style saddr */
					if (sap[x].s_pfx > 88) sap[x].atype = RAT_NONE;
					else sap[x].eui64 = 1;
					s++;
				break;
				case 'B':
					sap[x].whitelisted = YES;
					sap[x].dont_bind = YES;
					s++;
				break;
				case 'F':
					sap[x].fullbytes = YES;
					s++;
				break;
			}
		}

		strxstr(s, "[", "");
		strxstr(s, "]", "");
		if (inet_pton(sap[x].atype == RAT_IPV4 ? AF_INET : AF_INET6, s, sap[x].sa.ipa) < 1) {
			sap[x].atype = RAT_NONE;
			continue;
		}

		xstrlcpy(tmp, s, SADDRLEN);
		xstrlcpy(sap[x].s_addr, tmp, SADDRLEN);

		if (sap[x].remap == NO) continue;

		s = sap[x].d_addr;
		d = strchr(s, '/');
		if (!d) {
			sap[x].atype = RAT_NONE;
			continue;
		}
		*d = 0; d++;
		if (strchr(d, '/')) {
			sap[x].atype = RAT_NONE;
			continue;
		}
		sap[x].d_pfx = (size_t)atoi(d);
		if (sap[x].d_pfx > 128) {
			sap[x].atype = RAT_NONE;
			continue;
		}
		else if (sap[x].atype == RAT_IPV4 && sap[x].d_pfx > 32) {
			sap[x].atype = RAT_NONE;
			continue;
		}

		strxstr(s, "[", "");
		strxstr(s, "]", "");
		if (inet_pton(sap[x].atype == RAT_IPV4 ? AF_INET : AF_INET6, s, sap[x].da.ipa) < 1) {
			sap[x].atype = RAT_NONE;
			continue;
		}
	}
	if (sap && sap == addrs6) goto _for4;

	goto _done;
}

static ras_yesno addr_bindable(int af, const union s_addr *psa)
{
	size_t x;

	if (af == AF_INET6) for (x = 0; x < naddrs6; x++) {
		if (caddrs6[x].atype == RAT_IPV6
		&& caddrs6[x].dont_bind == YES
		&& compare_prefix(RAT_IPV6, &psa->v6a.sin6_addr.s6_addr, caddrs6[x].sa.v6b, caddrs6[x].s_pfx)) {
			return NO;
		}
	}
	if (af == AF_INET) for (x = 0; x < naddrs4; x++) {
		if (caddrs4[x].atype == RAT_IPV4
		&& caddrs4[x].dont_bind == YES
		&& compare_prefix(RAT_IPV4, &psa->v4a.sin_addr, caddrs4[x].sa.v4b, caddrs4[x].s_pfx)) {
			return NO;
		}
	}
	return YES;
}

static ras_yesno addr_remapped(int af, union s_addr *pda, const union s_addr *psa)
{
	ras_yesno res = NO;
	const struct s_addrcfg *sap = NULL;
	size_t x;

	memcpy(pda, psa, sizeof(union s_addr));

	if (af == AF_INET6) for (x = 0; x < naddrs6; x++) {
		if (caddrs6[x].atype == RAT_IPV6
		&& caddrs6[x].remap == YES
		&& compare_prefix(RAT_IPV6, &psa->v6a.sin6_addr.s6_addr, caddrs6[x].sa.v6b, caddrs6[x].s_pfx)) {
			res = YES;
			sap = &caddrs6[x];
		}
	}
	if (af == AF_INET) for (x = 0; x < naddrs4; x++) {
		if (caddrs4[x].atype == RAT_IPV4
		&& caddrs4[x].remap == YES
		&& compare_prefix(RAT_IPV4, &psa->v4a.sin_addr, caddrs4[x].sa.v4b, caddrs4[x].s_pfx)) {
			res = YES;
			sap = &caddrs4[x];
		}
	}

	if (res) {
		if (af == AF_INET6) {
			if (!mkrandaddr6(&pda->v6a.sin6_addr.s6_addr, sap->da.v6b, sap->d_pfx, sap->fullbytes)) return NO;
			if (sap->eui64) mkeui64addr(&pda->v6a.sin6_addr.s6_addr, &pda->v6a.sin6_addr.s6_addr);
		}
		else if (af == AF_INET) {
			if (!mkrandaddr4(&pda->v4a.sin_addr, sap->da.v4b, sap->d_pfx, sap->fullbytes)) return NO;
		}
	}

	return res;
}

/* returns YES on successful bind(2) event, otherwise returns NO */
static ras_yesno common_bind_random(int sockfd, in_port_t portid)
{
	const struct s_addrcfg *sap;
	size_t x;
	union s_addr sa;

	if (naddrs6 == 0) goto _try4;
_na6:	x = prng_index(0, naddrs6 > 0 ? (naddrs6-1) : 0);
	sap = caddrs6;
	if (sap->whitelisted == YES && sap->dont_bind != YES) goto _na6; /* whitelisted: get another */
	if (sap->atype == RAT_IPV6) { /* fail of you to provide valid cfg */
		memset(&sa, 0, sizeof(sa));
		if (!mkrandaddr6(&sa.v6a.sin6_addr.s6_addr, sap->sa.v6b, sap->s_pfx, sap->fullbytes)) {
			goto _try4;
		}
		if (sap->eui64) mkeui64addr(&sa.v6a.sin6_addr.s6_addr, &sa.v6a.sin6_addr.s6_addr);
		for (x = 0; x < naddrs6; x++) { /* whitelisted range: get another */
			if (caddrs6[x].whitelisted == YES
			&& caddrs6[x].dont_bind != YES
			&& compare_prefix(RAT_IPV6, &sa.v6a.sin6_addr.s6_addr, caddrs6[x].sa.v6b, caddrs6[x].s_pfx)) {
				goto _na6;
			}
		}
		sa.v6a.sin6_family = AF_INET6;
		sa.v6a.sin6_port = portid;
		if (!addr_bindable(AF_INET6, &sa)) goto _try4;
		if (crandsaddr->do_reuseaddr) {
			int v = 1;
			setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, &v, sizeof(v));
		}
		/* This call shall ignore any errors since it's just hint anyway. */
		if (syscall(SYS_bind, sockfd, (struct sockaddr *)&sa.v6a, sizeof(struct sockaddr_in6)) == 0) return YES;
		else goto _try4;
	}

_try4:	if (naddrs4 == 0) return NO;
_na4:	x = prng_index(0, naddrs4 > 0 ? (naddrs4-1) : 0);
	sap = caddrs4;
	if (sap->whitelisted == YES && sap->dont_bind != YES) goto _na4; /* whitelisted: get another */
	if (sap->atype == RAT_IPV4) {
		memset(&sa, 0, sizeof(sa));
		if (!mkrandaddr6(&sa.v4a.sin_addr, sap->sa.v4b, sap->s_pfx, sap->fullbytes)) {
			return NO;
		}
		for (x = 0; x < naddrs4; x++) { /* whitelisted range: get another */
			if (caddrs4[x].whitelisted == YES
			&& caddrs4[x].dont_bind != YES
			&& compare_prefix(RAT_IPV4, &sa.v4a.sin_addr, caddrs4[x].sa.v4b, caddrs4[x].s_pfx)) {
				goto _na4;
			}
		}
		sa.v4a.sin_family = AF_INET;
		sa.v4a.sin_port = portid;
		if (!addr_bindable(AF_INET, &sa)) return NO;
		if (crandsaddr->do_reuseaddr) {
			int v = 1;
			setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, &v, sizeof(v));
		}
		/* This call shall ignore any errors since it's just hint anyway. */
		if (syscall(SYS_bind, sockfd, (struct sockaddr *)&sa.v4a, sizeof(struct sockaddr_in)) == 0) return YES;
		else return NO;
	}

	return NO;
}

static pthread_mutex_t bind_mutex_randsaddr = PTHREAD_MUTEX_INITIALIZER;

static ras_yesno bind_random(int sockfd, in_port_t portid)
{
	ras_yesno res;

	pthread_mutex_lock(&bind_mutex_randsaddr);
	res = common_bind_random(sockfd, portid);
	pthread_mutex_unlock(&bind_mutex_randsaddr);

	return res;
}

int socket(int domain, int type, int protocol)
{
	int res;

	res = syscall(SYS_socket, domain, type, protocol);
	if (res == -1) return res;
	if (crandsaddr->do_socket) bind_random(res, 0);
	return res;
}

int bind(int sockfd, const struct sockaddr *addr, socklen_t addrlen)
{
	ras_yesno did_bind = NO;
	const struct sockaddr *paddr = (const struct sockaddr *)addr;
	size_t x;
	union s_addr sa, da;

	if (crandsaddr->do_bind == NO) goto _call;

	x = (size_t)addrlen;
	if (addr->sa_family == AF_INET6) memcpy(&sa.v6a, addr, x > sizeof(sa.v6a) ? sizeof(sa.v6a) : x);
	else if (addr->sa_family == AF_INET) memcpy(&sa.v4a, addr, x > sizeof(sa.v4a) ? sizeof(sa.v4a) : x);
	else goto _call;

	if (addr_remapped(addr->sa_family, &da, &sa)) {
		if (addr->sa_family == AF_INET6) paddr = (const struct sockaddr *)&da.v6a;
		else if (addr->sa_family == AF_INET) paddr = (const struct sockaddr *)&da.v4a;
		if (!addr_bindable(addr->sa_family, &da)) paddr = (const struct sockaddr *)addr;
		goto _call;
	}
	if (!addr_bindable(addr->sa_family, &sa)) goto _call;

	if (addr->sa_family == AF_INET6) did_bind = bind_random(sockfd, sa.v6a.sin6_port);
	else if (addr->sa_family == AF_INET) did_bind = bind_random(sockfd, sa.v4a.sin_port);
	else goto _call;

_call:	if (did_bind) {
		errno = 0;
		return 0;
	}
	return syscall(SYS_bind, sockfd, paddr, addrlen);
}

int connect(int sockfd, const struct sockaddr *addr, socklen_t addrlen)
{
	if (crandsaddr->do_connect) bind_random(sockfd, 0);
	return syscall(SYS_connect, sockfd, addr, addrlen);
}

ssize_t send(int sockfd, const void *buf, size_t len, int flags)
{
	if (crandsaddr->do_send) bind_random(sockfd, 0);
	return syscall(SYS_sendto, sockfd, buf, len, flags, NULL, 0);
}

ssize_t sendto(int sockfd, const void *buf, size_t len, int flags, const struct sockaddr *dest_addr, socklen_t addrlen)
{
	if (crandsaddr->do_sendto) bind_random(sockfd, 0);
	return syscall(SYS_sendto, sockfd, buf, len, flags, dest_addr, addrlen);
}

ssize_t sendmsg(int sockfd, const struct msghdr *msg, int flags)
{
	if (crandsaddr->do_sendmsg) bind_random(sockfd, 0);
	return syscall(SYS_sendmsg, msg, flags);
}
