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

#ifndef _RANDSADDR_H
#define _RANDSADDR_H

#ifndef _DEFAULT_SOURCE
#define _DEFAULT_SOURCE
#endif
#ifndef _BSD_SOURCE
#define _BSD_SOURCE
#endif
#ifndef _XOPEN_SOURCE
#define _XOPEN_SOURCE 700
#endif

#ifdef USE_LIBDL
#define _GNU_SOURCE
#endif

#include <stddef.h>
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
#ifdef USE_LIBDL
#include <dlfcn.h>
#endif

#include "randsaddr.h"
#include "tfdef.h"
#include "tfe.h"
#include "tfprng.h"

enum { NO, YES };
enum { RAT_NONE, RAT_IPV4, RAT_IPV6 };

typedef _Bool ras_yesno;
typedef short ras_atype;

#define NOSIZE ((size_t)-1)

#define STAT_ARRAY_SZ(x) (sizeof(x)/sizeof(*x))
#define CSTR_SZ(x) (sizeof(x)-1)

#define RAS_CFGSZ 10240

#define RAS_ADDRLEN INET6_ADDRSTRLEN+4
#define RAS_NADDRS 256
#define RAS_NRANDPATHS 8

union s_addr {
	uint8_t ipa[16];
	struct sockaddr_in6 v6a;
	uint8_t v6b[16];
	struct sockaddr_in v4a;
	uint8_t v4b[4];
};

struct s_addrcfg {
	ras_atype atype;
	size_t s_pfx;
	union s_addr sa;
	ras_yesno eui64;
	ras_yesno whitelisted;
	ras_yesno dont_bind;
	ras_yesno fullbytes;
	ras_yesno remap;
	size_t d_pfx;
	union s_addr da;
};

struct s_envcfg {
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

	char *randsources[RAS_NRANDPATHS];
};

extern const struct s_envcfg *randsaddr_config;

#ifdef USE_LIBDL
extern int (*ras_libc_socket)(int, int, int);
extern int (*ras_libc_bind)(int, const struct sockaddr *, socklen_t);
extern int (*ras_libc_connect)(int, const struct sockaddr *, socklen_t);
extern ssize_t (*ras_libc_send)(int, const void *, size_t, int);
extern ssize_t (*ras_libc_sendto)(int, const void *, size_t, int, const struct sockaddr *, socklen_t);
extern ssize_t (*ras_libc_sendmsg)(int, const struct msghdr *, int);
#endif

extern ras_yesno ras_mkrandaddr6(void *, const void *, size_t, ras_yesno);
extern void ras_mkeui64addr(void *, const void *);
extern ras_yesno ras_mkrandaddr4(void *, const void *, size_t, ras_yesno);

extern void ras_prng_init(void);
extern uint8_t ras_prng_getrandc(ras_yesno);
extern size_t ras_prng_index(size_t, size_t);

extern ras_atype ras_addr_type(const char *);
extern ras_yesno ras_stobaddr(ras_atype, void *, const char *);
extern size_t ras_saddr_prefix(const char *);
extern ras_yesno ras_compare_prefix(ras_atype, const void *, const void *, size_t);

static inline ras_yesno ras_str_empty(const char *str)
{
	if (!*str) return YES;
	return NO;
}
extern size_t ras_strlcpy(char *, const char *, size_t);
extern size_t ras_strlxstr(char *, size_t, const char *, const char *);
extern size_t ras_strxstr(char *, const char *, const char *);

extern void ras_init(void);
extern ras_yesno ras_addr_bindable(int, const union s_addr *);
extern ras_yesno ras_addr_remapped(int, union s_addr *, const union s_addr *);
extern ras_yesno ras_bind_random(int, in_port_t, ras_yesno);

#endif
