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
#include "randsaddr.h"

union s_addr {
	uint8_t ipa[16];
	struct sockaddr_in6 v6a;
	uint8_t v6b[16];
	struct sockaddr_in v4a;
	uint8_t v4b[4];
};

struct s_addrcfg {
	char *str;
	size_t pfx;
	ras_atype atype;
	union s_addr sa;
	ras_yesno eui64;
	ras_yesno whitelisted;
	ras_yesno dont_bind;
};

static ras_yesno randsaddr_disabled;

static ras_yesno randsaddr_do_socket; /* dangerous for servers! */
static ras_yesno randsaddr_do_bind; /* dangerous for servers! */
static ras_yesno randsaddr_do_connect = YES;
static ras_yesno randsaddr_do_send;
static ras_yesno randsaddr_do_sendto;
static ras_yesno randsaddr_do_sendmsg;
static ras_yesno randsaddr_do_reuseaddr;
static ras_yesno randsaddr_do_eui64;

static struct s_addrcfg *addrs6;
static size_t naddrs6;
static struct s_addrcfg *addrs4;
static size_t naddrs4;

int xmalloc_oom(int fail, xmalloc_oom_caller where)
{
	if (!fail) return 1;

	errno = ENOMEM;
	perror("xmalloc");
	exit(errno);
}

void xmalloc_ub(const void *addr)
{
	errno = EFAULT;
	perror("xmalloc");
	exit(errno);
}

void xmalloc_error(xmalloc_oom_caller where)
{
	perror("xmalloc");
	exit(errno);
}

void __attribute__((constructor)) randsaddr_init(void)
{
	static int initdone;
	char *scfg, *s, *d, *t;
	size_t sz, x, y;
	ras_atype type;
	struct s_addrcfg *sap;

	if (initdone) return;
	if (randsaddr_disabled) return;

	s = getenv("RANDSADDR");
	if (!s) {
		randsaddr_disabled = YES;
_done:		initdone = YES;
		return;
	}
	else {
		scfg = xstrdup(s);
		memset(s, 0, strlen(s));
		unsetenv("RANDSADDR");
	}

	s = d = scfg; t = NULL;
	while ((s = strtok_r(d, ",", &t))) {
		if (d) d = NULL;

		if (!strcasecmp(s, "socket")) {
			randsaddr_do_socket = YES;
			continue;
		}
		else if (!strcasecmp(s, "-socket")) {
			randsaddr_do_socket = NO;
			continue;
		}
		else if (!strcasecmp(s, "bind")) {
			randsaddr_do_bind = YES;
			continue;
		}
		else if (!strcasecmp(s, "-bind")) {
			randsaddr_do_bind = NO;
			continue;
		}
		else if (!strcasecmp(s, "connect")) {
			randsaddr_do_connect = YES;
			continue;
		}
		else if (!strcasecmp(s, "-connect")) {
			randsaddr_do_connect = NO;
			continue;
		}
		else if (!strcasecmp(s, "send")) {
			randsaddr_do_send = YES;
			continue;
		}
		else if (!strcasecmp(s, "-send")) {
			randsaddr_do_send = NO;
			continue;
		}
		else if (!strcasecmp(s, "sendto")) {
			randsaddr_do_sendto = YES;
			continue;
		}
		else if (!strcasecmp(s, "-sendto")) {
			randsaddr_do_sendto = NO;
			continue;
		}
		else if (!strcasecmp(s, "sendmsg")) {
			randsaddr_do_sendmsg = YES;
			continue;
		}
		else if (!strcasecmp(s, "-sendmsg")) {
			randsaddr_do_sendmsg = NO;
			continue;
		}
		else if (!strcasecmp(s, "eui64")) {
			randsaddr_do_eui64 = YES;
			continue;
		}
		else if (!strcasecmp(s, "-eui64")) {
			randsaddr_do_eui64 = NO;
			continue;
		}
		else if (!strcasecmp(s, "reuseaddr")) {
			randsaddr_do_reuseaddr = YES;
			continue;
		}
		else if (!strcasecmp(s, "-reuseaddr")) {
			randsaddr_do_reuseaddr = NO;
			continue;
		}

		type = addr_type(s);
		if (type == RAT_IPV6) {
			sz = DYN_ARRAY_SZ(addrs6);
			addrs6 = xrealloc(addrs6, (sz+1)*sizeof(struct s_addrcfg));
			addrs6[sz].atype = type;
			addrs6[sz].str = xstrdup(s); /* [-/W][B][E]2001:db8:76ba:8aef::/64 */
			addrs6[sz].eui64 = randsaddr_do_eui64;
			addrs6[sz].pfx = NOSIZE; /* filled later */
			naddrs6 = DYN_ARRAY_SZ(addrs6);
		}
		else if (type == RAT_IPV4) {
			sz = DYN_ARRAY_SZ(addrs4);
			addrs4 = xrealloc(addrs4, (sz+1)*sizeof(struct s_addrcfg));
			addrs4[sz].atype = type;
			addrs4[sz].str = xstrdup(s); /* [-/W][B]192.0.2.1/24 */
			addrs4[sz].pfx = NOSIZE; /* filled later */
			naddrs4 = DYN_ARRAY_SZ(addrs4);
		}
	}

	pfree(scfg);

	sap = addrs6;
	sz = naddrs6;
	if (sz == 0) {
_for4:		sap = addrs4;
		sz = naddrs4;
		if (sz == 0) goto _done;
	}

	for (x = 0; x < sz; x++) {
		if (sap[x].atype != RAT_IPV4 && sap[x].atype != RAT_IPV6) {
			sap[x].pfx = NOSIZE;
			continue;
		}
		s = sap[x].str;
		d = strchr(s, '/');
		if (!d) {
			sap[x].pfx = NOSIZE;
			continue;
		}
		*d = 0; d++;
		if (strchr(d, '/')) {
			sap[x].pfx = NOSIZE;
			continue;
		}
		sap[x].pfx = (size_t)atoi(d);
		if (sap[x].pfx > 128) {
			sap[x].pfx = NOSIZE;
			continue;
		}
		else if (sap[x].atype == RAT_IPV4 && sap[x].pfx > 32) {
			sap[x].pfx = NOSIZE;
			continue;
		}
		s = sap[x].str;
		for (y = 0; y < 2; y++) {
			switch (*s) {
				case '-': /* whitelisted - don't bind to these */
				case 'W':
					sap[x].whitelisted = YES;
					s++;
				break;
				case 'E': /* build EUI64 style saddr */
					if (sap[x].pfx > 88) sap[x].pfx = NOSIZE;
					else sap[x].eui64 = 1;
					s++;
				break;
				case 'B':
					sap[x].whitelisted = YES;
					sap[x].dont_bind = YES;
					s++;
				break;
			}
		}

		strxstr(s, "[", "");
		strxstr(s, "]", "");
		if (inet_pton(sap[x].atype == RAT_IPV4 ? AF_INET : AF_INET6, s, sap[x].sa.ipa) < 1) {
			sap[x].pfx = NOSIZE;
			continue;
		}

		d = sap[x].str;
		sap[x].str = xstrdup(s);
		pfree(d);
	}
	if (sap && sap == addrs6) goto _for4;

	goto _done;
}

static void common_bind_random(int sockfd)
{
	struct s_addrcfg *sap;
	size_t x;
	union s_addr sa;

	if (randsaddr_disabled) return;

	if (!addrs6) goto _try4;
_na6:	x = prng_index(0, naddrs6 > 0 ? (naddrs6-1) : 0);
	sap = &addrs6[x];
	if (sap->whitelisted == YES) goto _na6; /* whitelisted: get another */
	if (sap->pfx != NOSIZE) { /* fail of you to provide valid cfg */
		memset(&sa, 0, sizeof(sa));
		if (!mkrandaddr6(&sa.v6a.sin6_addr.s6_addr, sap->sa.v6b, sap->pfx)) goto _try4;
		if (sap->eui64) mkeui64addr(&sa.v6a.sin6_addr.s6_addr, &sa.v6a.sin6_addr.s6_addr);
		for (x = 0; x < naddrs6; x++) { /* whitelisted range: get another */
			if (addrs6[x].whitelisted == YES && compare_prefix(RAT_IPV6, &sa.v6a.sin6_addr.s6_addr, addrs6[x].sa.v6b, addrs6[x].pfx)) {
				goto _na6;
			}
		}
		sa.v6a.sin6_family = AF_INET6;
		if (randsaddr_do_reuseaddr) {
			int v = 1;
			setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, &v, sizeof(v));
		}
		/* This call shall ignore any errors since it's just hint anyway. */
		if (syscall(SYS_bind, sockfd, (struct sockaddr *)&sa.v6a, sizeof(struct sockaddr_in6)) == -1) goto _try4;
		return;
	}

_try4:	if (!addrs4) return;
_na4:	x = prng_index(0, naddrs4 > 0 ? (naddrs4-1) : 0);
	sap = &addrs4[x];
	if (sap->whitelisted == YES) goto _na4; /* whitelisted: get another */
	if (sap->pfx != NOSIZE) {
		memset(&sa, 0, sizeof(sa));
		if (!mkrandaddr4(&sa.v4a.sin_addr, sap->sa.v4b, sap->pfx)) return;
		for (x = 0; x < naddrs4; x++) { /* whitelisted range: get another */
			if (addrs4[x].whitelisted == YES && compare_prefix(RAT_IPV4, &sa.v4a.sin_addr, addrs4[x].sa.v4b, addrs4[x].pfx)) {
				goto _na4;
			}
		}
		sa.v4a.sin_family = AF_INET;
		if (randsaddr_do_reuseaddr) {
			int v = 1;
			setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, &v, sizeof(v));
		}
		/* This call shall ignore any errors since it's just hint anyway. */
		if (syscall(SYS_bind, sockfd, (struct sockaddr *)&sa.v4a, sizeof(struct sockaddr_in)) == -1) return;
		return;
	}
}

int socket(int domain, int type, int protocol)
{
	int res;

	res = syscall(SYS_socket, domain, type, protocol);
	if (res == -1) return res;
	if (randsaddr_do_socket) common_bind_random(res);
	return res;
}

int bind(int sockfd, const struct sockaddr *addr, socklen_t addrlen)
{
	ras_yesno did_bind = NO;
	size_t x;
	union s_addr sa;

	if (randsaddr_do_bind == NO) goto _call;

	x = (size_t)addrlen;
	if (addr->sa_family == AF_INET6) memcpy(&sa.v6a, addr, x > sizeof(sa.v6a) ? sizeof(sa.v6a) : x);
	else if (addr->sa_family == AF_INET) memcpy(&sa.v4a, addr, x > sizeof(sa.v4a) ? sizeof(sa.v4a) : x);
	else goto _call;

	if (addrs6 && addr->sa_family == AF_INET6) for (x = 0; x < naddrs6; x++) {
		if (addrs6[x].dont_bind == YES && compare_prefix(RAT_IPV6, &sa.v6a.sin6_addr.s6_addr, addrs6[x].sa.v6b, addrs6[x].pfx)) {
			goto _call;
		}
	}
	if (addrs4 && addr->sa_family == AF_INET) for (x = 0; x < naddrs4; x++) {
		if (addrs4[x].dont_bind == YES && compare_prefix(RAT_IPV4, &sa.v4a.sin_addr, addrs4[x].sa.v4b, addrs4[x].pfx)) {
			goto _call;
		}
	}

	common_bind_random(sockfd);
	did_bind = YES;

_call:	if (did_bind) {
		errno = 0;
		return 0;
	}
	return syscall(SYS_bind, sockfd, addr, addrlen);
}

int connect(int sockfd, const struct sockaddr *addr, socklen_t addrlen)
{
	if (randsaddr_do_connect) common_bind_random(sockfd);
	return syscall(SYS_connect, sockfd, addr, addrlen);
}

ssize_t send(int sockfd, const void *buf, size_t len, int flags)
{
	if (randsaddr_do_send) common_bind_random(sockfd);
	return syscall(SYS_sendto, sockfd, buf, len, flags, NULL, 0);
}

ssize_t sendto(int sockfd, const void *buf, size_t len, int flags, const struct sockaddr *dest_addr, socklen_t addrlen)
{
	if (randsaddr_do_sendto) common_bind_random(sockfd);
	return syscall(SYS_sendto, sockfd, buf, len, flags, dest_addr, addrlen);
}

ssize_t sendmsg(int sockfd, const struct msghdr *msg, int flags)
{
	if (randsaddr_do_sendmsg) common_bind_random(sockfd);
	return syscall(SYS_sendmsg, msg, flags);
}
