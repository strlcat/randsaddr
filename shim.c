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

static inline ras_yesno af_valid(int af)
{
	switch (af) {
		case AF_INET:
		case AF_INET6:	return YES;
	}
	return NO;
}

#ifdef SHARED
void __attribute__((constructor)) ras_shim_init(void)
{
	ras_init();
}
#endif

int socket(int domain, int type, int protocol)
{
	int res;

#ifndef SHARED
	ras_init();
#endif
#ifdef USE_LIBDL
	res = ras_libc_socket(domain, type, protocol);
#else
	res = syscall(SYS_socket, domain, type, protocol);
#endif
	if (res == -1) return res;
	if (af_valid(domain) != YES) return res;
	if (randsaddr_config->do_socket) ras_bind_random(res, 0, NO);
	return res;
}

int bind(int sockfd, const struct sockaddr *addr, socklen_t addrlen)
{
	ras_yesno did_bind = NO;
	const struct sockaddr *paddr = (const struct sockaddr *)addr;
	size_t x;
	union s_addr sa, da;

#ifndef SHARED
	ras_init();
#endif
	if (af_valid(paddr->sa_family) != YES) goto _call;
	if (randsaddr_config->do_bind == NO) {
		if (randsaddr_config->do_socket) return 0;
		goto _call;
	}

	x = (size_t)addrlen;
	if (addr->sa_family == AF_INET6) memcpy(&sa.v6a, addr, x > sizeof(sa.v6a) ? sizeof(sa.v6a) : x);
	else if (addr->sa_family == AF_INET) memcpy(&sa.v4a, addr, x > sizeof(sa.v4a) ? sizeof(sa.v4a) : x);
	else goto _call;

	if (ras_addr_remapped(addr->sa_family, &da, &sa)) {
		if (addr->sa_family == AF_INET6) paddr = (const struct sockaddr *)&da.v6a;
		else if (addr->sa_family == AF_INET) paddr = (const struct sockaddr *)&da.v4a;
		if (!ras_addr_bindable(addr->sa_family, &da)) paddr = (const struct sockaddr *)addr;
		goto _call;
	}
	if (!ras_addr_bindable(addr->sa_family, &sa)) goto _call;

	if (addr->sa_family == AF_INET6) did_bind = ras_bind_random(sockfd, sa.v6a.sin6_port, YES);
	else if (addr->sa_family == AF_INET) did_bind = ras_bind_random(sockfd, sa.v4a.sin_port, YES);
	else goto _call;

_call:	if (did_bind) {
		errno = 0;
		return 0;
	}
#ifdef USE_LIBDL
	return ras_libc_bind(sockfd, paddr, addrlen);
#else
	return syscall(SYS_bind, sockfd, paddr, addrlen);
#endif
}

int connect(int sockfd, const struct sockaddr *addr, socklen_t addrlen)
{
#ifndef SHARED
	ras_init();
#endif
	if (randsaddr_config->do_connect) {
		/* even if connecting to peer, destination addr->sa_family must match source one, right? */
		if (af_valid(addr->sa_family)) ras_bind_random(sockfd, 0, NO);
	}
#ifdef USE_LIBDL
	return ras_libc_connect(sockfd, addr, addrlen);
#else
	return syscall(SYS_connect, sockfd, addr, addrlen);
#endif
}

ssize_t send(int sockfd, const void *buf, size_t len, int flags)
{
#ifndef SHARED
	ras_init();
#endif
	if (randsaddr_config->do_send) ras_bind_random(sockfd, 0, NO);
#ifdef USE_LIBDL
	return ras_libc_send(sockfd, buf, len, flags);
#else
	return syscall(SYS_sendto, sockfd, buf, len, flags, NULL, 0);
#endif
}

ssize_t sendto(int sockfd, const void *buf, size_t len, int flags, const struct sockaddr *dest_addr, socklen_t addrlen)
{
#ifndef SHARED
	ras_init();
#endif
	if (randsaddr_config->do_sendto) ras_bind_random(sockfd, 0, NO);
#ifdef USE_LIBDL
	return ras_libc_sendto(sockfd, buf, len, flags, dest_addr, addrlen);
#else
	return syscall(SYS_sendto, sockfd, buf, len, flags, dest_addr, addrlen);
#endif
}

ssize_t sendmsg(int sockfd, const struct msghdr *msg, int flags)
{
#ifndef SHARED
	ras_init();
#endif
	if (randsaddr_config->do_sendmsg) ras_bind_random(sockfd, 0, NO);
#ifdef USE_LIBDL
	return ras_libc_sendmsg(sockfd, msg, flags);
#else
	return syscall(SYS_sendmsg, sockfd, msg, flags);
#endif
}
