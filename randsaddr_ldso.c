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

static char *randsaddr_envcfg;
static int randsaddr_disabled;
static uint8_t v6pfx[16];
static size_t v6pfxlen = NOSIZE;
static uint8_t v4pfx[4];
static size_t v4pfxlen = NOSIZE;
static int eui64;

static void randsaddr_init(void)
{
	static int initdone;
	char *s, *d, *t;
	char *v4s, *v6s;

	if (initdone) return;
	if (randsaddr_disabled) return;

	/*
	 * RANDSADDR=[E]2001:db8:76ba:8aef::/64,192.0.2.1/24
	 */
	randsaddr_envcfg = getenv("RANDSADDR");
	if (!randsaddr_envcfg) {
_dis:		randsaddr_disabled = 1;
_done:		initdone = 1;
		return;
	}

	s = d = randsaddr_envcfg; t = v4s = v6s = NULL;
	while ((s = strtok_r(d, ",", &t))) {
		if (d) d = NULL;

		if (!v6s) v6s = s;
		else if (!v4s) v4s = s;
		else break;
	}

	if (!v6s) goto _dis;
	if (v6s[0] == 'E') {
		eui64 = 1;
		v6s++;
	}
	s = strchr(v6s, '/');
	if (s) {
		*s = 0; s++;
		if (inet_pton(AF_INET6, v6s, v6pfx) < 1) v6pfxlen = NOSIZE;
		v6pfxlen = (size_t)atoi(s);
		if (v6pfxlen > 128) v6pfxlen = NOSIZE;
	}
	if (!v4s) goto _done;
	s = strchr(v4s, '/');
	if (s) {
		*s = 0; s++;
		if (inet_pton(AF_INET, v4s, v4pfx) < 1) v4pfxlen = NOSIZE;
		v4pfxlen = (size_t)atoi(s);
		if (v4pfxlen > 32) v4pfxlen = NOSIZE;
	}
	goto _done;
}

int connect(int sockfd, const struct sockaddr *addr, socklen_t addrlen)
{
	union {
		struct sockaddr_in6 v6a;
		struct sockaddr_in v4a;
	} s_addr;

	randsaddr_init();
	if (randsaddr_disabled) goto _call;

	memset(&s_addr, 0, sizeof(s_addr));
	if (v6pfxlen != NOSIZE) {
		if (!mkrandaddr6(&s_addr.v6a.sin6_addr.s6_addr, v6pfx, v6pfxlen)) goto _try4;
		if (eui64) mkeui64addr(&s_addr.v6a.sin6_addr.s6_addr, &s_addr.v6a.sin6_addr.s6_addr);
		s_addr.v6a.sin6_family = AF_INET6;
		if (bind(sockfd, (struct sockaddr *)&s_addr.v6a, sizeof(struct sockaddr_in6)) == -1) goto _try4;
		goto _call;
	}

_try4:	if (v4pfxlen != NOSIZE) {
		if (!mkrandaddr4(&s_addr.v4a.sin_addr, v4pfx, v4pfxlen)) goto _call;
		s_addr.v4a.sin_family = AF_INET;
		if (bind(sockfd, (struct sockaddr *)&s_addr.v4a, sizeof(struct sockaddr_in)) == -1) goto _call;
		goto _call;
	}

_call:	return syscall(SYS_connect, sockfd, addr, addrlen);
}
