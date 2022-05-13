## randsaddr: randomize source address before connect(2).

### What is it for?
randsaddr.so is `LD_PRELOAD` style object which hooks `connect(2)` system call.
It does so to perform a source address randomization by calling an additional
`bind(2)` in process of establishing connection, but transparently for caller,
who didn't use `bind(2)` before (_most_ Unix network clients at the time of writing).
It is perfect to use in IPv6 networks, where `hostid` 64 bit part can be randomized
for reasons of non traceability, or when you have spare `/48` or more `netid` bits
available and you can randomize them for additional (pseudo)anonymity!

### Building

It shall be simple. Type make, the result pre-loadable object file is `randsaddr.so`.
You may want to install it on system into `/usr/lib` directory. Just copy it there:

```
cp randsaddr.so /usr/lib
```

### Example

Suppose you have four `/60`'s available to play with,
(each allows 16 `/64` subnets, total 64, distributed),
and a Linux box (further examples will assume so):

```
2001:db8:7:4aa0::/60
2001:db8:7:7870::/60
2001:db8:a5:1200::/60
2001:db8:8:9e30::/60
```

1. You need to tell Linux kernel that it is possible to bind to any nonexistent
IP address on this box. Do so by enabling this feature:

```
echo 1 > /proc/sys/net/ipv4/ip_nonlocal_bind
echo 1 > /proc/sys/net/ipv6/ip_nonlocal_bind
```

2. You need to provide Linux kernel with a route that basically says that requested
address space is there in our control. Assuming example ranges above, do so by enabling this:

```
ip -6 route add local 2001:db8:7:4aa0::/60 dev lo
ip -6 route add local 2001:db8:7:7870::/60 dev lo
ip -6 route add local 2001:db8:a5:1200::/60 dev lo
ip -6 route add local 2001:db8:8:9e30::/60 dev lo
```

Above commands shall be run as superuser.

3. Optionally, set up your iptables/nftables to allow these new ranges. This is out of
scope of this document, as your netfilter configurations may vary (or be absent).

4. Now the fun part. Any userspace unprivileged program now can call `bind(2)` to
ranges we defined and kernel will happily allow this, trying to communicate with
remote on behalf (of course if your netfilter configuration permits packet flow).

Before running application that does talk to IPv6 network, do this (assuming examples above):

```
export LD_PRELOAD=/usr/lib/randsaddr.so
export RANDSADDR="2001:db8:7:4aa0::/60,2001:db8:7:7870::/60,2001:db8:a5:1200::/60,2001:db8:8:9e30::/60"
```

Here, `LD_PRELOAD` instructs dynamic linker to override the `connect` function with ours from `randsaddr.so`.
Next, `RANDSADDR` is configuration environment variables which simply specifies subnet ranges which it can
randomize (assuming kernel already was prepared to do so with commands above).

Now run the application, and enjoy seeing it doing TCP/UDP traffic from randomized IPv6 addressess of your prefix(es).

### Making it permanent

Superuser privilege commands can be inserted into script like `/etc/rc.local` (your OS may define different location).

User commands to pre-load `randsaddr.so` must be performed from a shell, or from start-up script which may look like so:

```
#!/bin/sh
# Propagade this into children
export LD_PRELOAD=/usr/lib/randsaddr.so
export RANDSADDR="2001:db8:7:4aa0::/60,2001:db8:7:7870::/60,2001:db8:a5:1200::/60,2001:db8:8:9e30::/60"
exec your-app args etc. "${@}"
```

, and placing it alongside of original binary, placing it in place of original binary and renaming original binary ...
Unix offers so many opportunities, you've got the idea I hope.

### Further notes

Some apps (like Google Chrome) may consider `LD_PRELOAD` dangerous, and they will unset it automatically. There is little
you can do about it other than getting Chromium source, rebuilding it with removal of these anti-feature. I dunno.
You may install proxy (maybe transparent one) which tolerate `LD_PRELOAD` and forward Chrome traffic through it.
One comes to mind is Tor, with which this hack works flawlessly (at least for me now).

Another way is building this feature into libc or even implementing it as a Linux kernel module. I didn't considered
these yet, provided I had very little timeframe to implement this hack, so I decided to proceed with `LD_PRELOAD`
approach. One such easy hack-able libc is musl libc, I think it will be trivial to insert this code there.
Although, I think your system runs on glibc, which is harder to deal with. And there is Android with bionic libc...

I guess most programs which do `connect(2)` won't poke at libc internals anyway. Portable apps shall not call
`syscall(2)` even.

### Copyright

This hack was written by Rys Andrey, May2022. It is licensed under MIT license.
