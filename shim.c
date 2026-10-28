/*
 * randsaddr: randomize source address of outgoing sockets.
 *
 * randsaddr is copyrighted:
 * Copyright (C) 2022, 2023, 2024, 2026 Rys Andrey. All rights reserved.
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
	/* can't get where we are now so don't claim false hints. */
	ras_init(RFN_UNKNOWN, NULL);
}
#endif

int socket(int domain, int type, int protocol)
{
	int res;

#ifndef SHARED
	ras_init(RFN_SOCKET, NULL);
#endif
#ifdef USE_LIBDL
	res = ras_libc_socket(domain, type, protocol);
#else
	res = syscall(SYS_socket, domain, type, protocol);
#endif
	if (res == -1) return res;
	if (af_valid(domain) != YES) return res;
	if (randsaddr_config->do_socket) ras_bind_random(RFN_SOCKET, res, 0, NULL);
	return res;
}

int bind(int sockfd, const struct sockaddr *addr, socklen_t addrlen)
{
	ras_yesno did_bind = NO;
	const struct sockaddr *paddr = (const struct sockaddr *)addr;
	size_t x;
	struct s_addr sa, da;
	struct ras_sockaddr ska;
	in_port_t portid;

#ifndef SHARED
	ras_init(RFN_BIND, NULL);
#endif
	if (af_valid(paddr->sa_family) != YES) goto _call;
	if (randsaddr_config->do_bind == NO) {
		if (randsaddr_config->do_socket) return 0;
		goto _call;
	}

	x = (size_t)addrlen;
	if (addr->sa_family == AF_INET6) {
		struct sockaddr_in6 *adrp = (struct sockaddr_in6 *)addr;

		memset(&sa, 0, sizeof(struct s_addr));
		sa.atype = RAT_IPV6;
		portid = adrp->sin6_port;
		memcpy(&sa.inet6, &adrp->sin6_addr, x > sizeof(sa.inet6) ? sizeof(sa.inet6) : x);
		ras_saddr_to_sockaddr(&ska, &sa, portid);
	}
	else if (addr->sa_family == AF_INET) {
		struct sockaddr_in *adrp = (struct sockaddr_in *)addr;

		memset(&sa, 0, sizeof(struct s_addr));
		sa.atype = RAT_IPV4;
		portid = adrp->sin_port;
		memcpy(&sa.inet4, &adrp->sin_addr, x > sizeof(sa.inet4) ? sizeof(sa.inet4) : x);
		ras_saddr_to_sockaddr(&ska, &sa, portid);
	}
	else goto _call;

	if (ras_addr_remapped_socket(sockfd, &da, &sa) == YES) {
		ras_saddr_to_sockaddr(&ska, &da, portid);
		if (addr->sa_family == AF_INET6) paddr = (const struct sockaddr *)&ska.inet6;
		else if (addr->sa_family == AF_INET) paddr = (const struct sockaddr *)&ska.inet4;
		if (ras_addr_bindable_socket(sockfd, &da) != YES) paddr = (const struct sockaddr *)addr;
		goto _call;
	}
	if (ras_addr_bindable_socket(sockfd, &sa) != YES) {
		ras_saddr_to_sockaddr(&ska, &da, portid);
		goto _call;
	}

	if (addr->sa_family == AF_INET6) did_bind = ras_bind_random(RFN_BIND, sockfd, portid, NULL);
	else if (addr->sa_family == AF_INET) did_bind = ras_bind_random(RFN_BIND, sockfd, portid, NULL);
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
	ras_init(RFN_CONNECT, NULL);
#endif
	if (randsaddr_config->do_connect) {
		/* even if connecting to peer, destination addr->sa_family must match source one, right? */
		if (af_valid(addr->sa_family)) ras_bind_random(RFN_CONNECT, sockfd, 0, NULL);
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
	ras_init(RFN_SEND, NULL);
#endif
	if (randsaddr_config->do_send) ras_bind_random(RFN_SEND, sockfd, 0, NULL);
#ifdef USE_LIBDL
	return ras_libc_send(sockfd, buf, len, flags);
#else
	return syscall(SYS_sendto, sockfd, buf, len, flags, NULL, 0);
#endif
}

ssize_t write(int fd, const void *buf, size_t len)
{
#ifndef SHARED
	ras_init(RFN_SEND, NULL);
#endif
	if (randsaddr_config->do_send) ras_bind_random(RFN_SEND, fd, 0, NULL);
#ifdef USE_LIBDL
	return ras_libc_write(fd, buf, len);
#else
	return syscall(SYS_write, fd, buf, len);
#endif
}

ssize_t writev(int fd, const struct iovec *iov, int iovcnt)
{
#ifndef SHARED
	ras_init(RFN_SEND, NULL);
#endif
	if (randsaddr_config->do_send) ras_bind_random(RFN_SEND, fd, 0, NULL);
#ifdef USE_LIBDL
	return ras_libc_writev(fd, iov, iovcnt);
#else
	return syscall(SYS_writev, fd, iov, iovcnt);
#endif
}

ssize_t sendto(int sockfd, const void *buf, size_t len, int flags, const struct sockaddr *dest_addr, socklen_t addrlen)
{
#ifndef SHARED
	ras_init(RFN_SENDTO, NULL);
#endif
	if (randsaddr_config->do_sendto) ras_bind_random(RFN_SENDTO, sockfd, 0, NULL);
#ifdef USE_LIBDL
	return ras_libc_sendto(sockfd, buf, len, flags, dest_addr, addrlen);
#else
	return syscall(SYS_sendto, sockfd, buf, len, flags, dest_addr, addrlen);
#endif
}

ssize_t sendmsg(int sockfd, const struct msghdr *msg, int flags)
{
#ifndef SHARED
	ras_init(RFN_SENDMSG, NULL);
#endif
	if (randsaddr_config->do_sendmsg) ras_bind_random(RFN_SENDMSG, sockfd, 0, NULL);
#ifdef USE_LIBDL
	return ras_libc_sendmsg(sockfd, msg, flags);
#else
	return syscall(SYS_sendmsg, sockfd, msg, flags);
#endif
}

#ifdef USE_LINUX
#ifdef __ANDROID__
int sendmmsg(int sockfd, const struct mmsghdr *msgvec, unsigned int vlen, int flags)
#else
int sendmmsg(int sockfd, struct mmsghdr *msgvec, unsigned int vlen, int flags)
#endif
{
#ifndef SHARED
	ras_init(RFN_SENDMSG, NULL);
#endif
	if (randsaddr_config->do_sendmsg) ras_bind_random(RFN_SENDMSG, sockfd, 0, NULL);
#ifdef USE_LIBDL
	return ras_libc_sendmmsg(sockfd, msgvec, vlen, flags);
#else
	return syscall(SYS_sendmmsg, sockfd, msgvec, vlen, flags);
#endif
}
#endif
