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
	int af;
	union s_addr sa;
	short eui64;
	short wl;
};

static char *randsaddr_envcfg;
static int randsaddr_disabled;

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

static void randsaddr_init(void)
{
	static int initdone;
	char *s, *d, *t;
	size_t sz, x, y;
	int type;
	struct s_addrcfg *sap;

	if (initdone) return;
	if (randsaddr_disabled) return;

	/*
	 * RANDSADDR=[-][E]2001:db8:76ba:8aef::/64,[-]192.0.2.1/24,...
	 */
	s = getenv("RANDSADDR");
	if (!s) {
		randsaddr_disabled = 1;
_done:		initdone = 1;
		return;
	}
	else randsaddr_envcfg = xstrdup(s);

	s = d = randsaddr_envcfg; t = NULL;
	while ((s = strtok_r(d, ",", &t))) {
		if (d) d = NULL;

		type = addr_type(s);
		if (type == AF_INET6) {
			sz = DYN_ARRAY_SZ(addrs6);
			addrs6 = xrealloc(addrs6, (sz+1)*sizeof(struct s_addrcfg));
			addrs6[sz].af = type;
			addrs6[sz].str = xstrdup(s); /* [-][E]2001:db8:76ba:8aef::/64 */
			addrs6[sz].pfx = NOSIZE; /* filled later */
			naddrs6 = DYN_ARRAY_SZ(addrs6);
		}
		else if (type == AF_INET) {
			sz = DYN_ARRAY_SZ(addrs4);
			addrs4 = xrealloc(addrs4, (sz+1)*sizeof(struct s_addrcfg));
			addrs4[sz].af = type;
			addrs4[sz].str = xstrdup(s); /* [-]192.0.2.1/24 */
			addrs4[sz].pfx = NOSIZE; /* filled later */
			naddrs4 = DYN_ARRAY_SZ(addrs4);
		}
	}

	sap = addrs6;
	sz = naddrs6;
	if (sz == 0) {
_for4:		sap = addrs4;
		sz = naddrs4;
		if (sz == 0) goto _done;
	}

	for (x = 0; x < sz; x++) {
		s = sap[x].str;
		d = strchr(s, '/');
		if (!d) continue;
		*d = 0; d++;
		sap[x].pfx = (size_t)atoi(d);
		if (sap[x].pfx > 128) sap[x].pfx = NOSIZE;
		else if (sap[x].af == AF_INET && sap[x].pfx > 32) sap[x].pfx = NOSIZE;

		s = sap[x].str;
		for (y = 0; y < 2; y++) {
			switch (*s) {
				case '-': /* whitelisted - don't bind to these */
					sap[x].wl = 1;
					sap[x].pfx = NOSIZE;
					s++;
				break;
				case 'E': /* build EUI64 style saddr */
					if (sap[x].pfx > 88) sap[x].pfx = NOSIZE;
					else sap[x].eui64 = 1;
					s++;
				break;
			}
		}

		if (sap[x].wl != 1) {
			if (inet_pton(sap[x].af, s, sap[x].sa.ipa) < 1) sap[x].pfx = NOSIZE;
		}

		d = sap[x].str;
		sap[x].str = xstrdup(s);
		pfree(d);
	}
	if (sap && sap == addrs6) goto _for4;

	goto _done;
}

int connect(int sockfd, const struct sockaddr *addr, socklen_t addrlen)
{
	union s_addr sa;
	struct s_addrcfg *sap;
	size_t x;

	randsaddr_init();
	if (randsaddr_disabled) goto _call;

	if (!addrs6) goto _try4;
_na6:	x = prng_index(0, naddrs6 > 0 ? (naddrs6-1) : 0);
	sap = &addrs6[x];
	if (sap->wl == 1) goto _na6; /* whitelisted: get another */
	if (sap->pfx != NOSIZE) { /* fail of you to provide valid cfg */
		memset(&sa, 0, sizeof(sa));
		if (!mkrandaddr6(&sa.v6a.sin6_addr.s6_addr, sap->sa.v6b, sap->pfx)) goto _try4;
		if (sap->eui64) mkeui64addr(&sa.v6a.sin6_addr.s6_addr, &sa.v6a.sin6_addr.s6_addr);
		sa.v6a.sin6_family = AF_INET6;
		if (bind(sockfd, (struct sockaddr *)&sa.v6a, sizeof(struct sockaddr_in6)) == -1) goto _try4;
		goto _call;
	}

_try4:	if (!addrs4) goto _call;
_na4:	x = prng_index(0, naddrs4 > 0 ? (naddrs4-1) : 0);
	sap = &addrs4[x];
	if (sap->wl == 1) goto _na4; /* whitelisted: get another */
	if (sap->pfx != NOSIZE) {
		memset(&sa, 0, sizeof(sa));
		if (!mkrandaddr4(&sa.v4a.sin_addr, sap->sa.v4b, sap->pfx)) goto _call;
		sa.v4a.sin_family = AF_INET;
		if (bind(sockfd, (struct sockaddr *)&sa.v4a, sizeof(struct sockaddr_in)) == -1) goto _call;
		goto _call;
	}

_call:	return syscall(SYS_connect, sockfd, addr, addrlen);
}
