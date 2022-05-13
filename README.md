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

### Usage

The `randsaddr.so` shared object must be loaded into your application address space:

```
LD_PRELOAD=/usr/lib/randsaddr.so your-app args etc.
```

If no `RANDSADDR` environment variable was passed, it will do nothing but act as a shim object.

To make it work as intended, `RANDSADDR` environment variable shall be set.

Syntax for `RANDSADDR` environment variable is:

```
RANDSADDR=[[-][socket,connect,send,sendto,sendmsg,eui64]][-E]SUBNET/PREFIX,[SUBNET/PREFIX]
```
, where `SUBNET/PREFIX` takes a canonical IP address range syntax, like

```
192.0.2.0/24
```
for IPv4, or
```
2001:db8::/32
```
for IPv6 (preferred).

List of syscalls which `randsaddr.so` will control is given as comma separated list: `socket,connect,send,sendto,sendmsg`.
If a single entry, e.g. `send` is prefixed with dash, like `-send`, it's usage will be disabled and forced to pass through.

Note that `socket` used with server daemons may produce their misbehavior.

Additionally, `eui64` will enable, and `-eui64` will disable generation of EUI64 style IPv6 addresses.

Each `SUBNET/PREFIX` can also be configured with `E` (eui64 style for this subnet) and `-` (remove subnet from address space).

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

Now run the application, and enjoy seeing it doing TCP/UDP traffic from randomized IPv6 addresses of your prefix(es).

### Making it permanent

Superuser privilege commands can be inserted into script like `/etc/rc.local` (your OS may define different location).

User commands to pre-load `randsaddr.so` must be performed from a shell, or from start-up script which may look like so:

```
#!/bin/sh
# Propagade this into children
export LD_PRELOAD=/usr/lib/randsaddr.so
export RANDSADDR="sendto,2001:db8:7:4aa0::/60,2001:db8:7:7870::/60,2001:db8:a5:1200::/60,2001:db8:8:9e30::/60"
exec your-app args etc. "${@}"
```

, and placing it alongside of original binary, placing it in place of original binary and renaming original binary ...
Unix offers so many opportunities, you've got the idea I hope.

### Additional options for RANDSADDR environment variable

There are several prefixes for each subnet range you can use to alter randsaddr behavior:

`E`, like `E2001:db8:7:4aa0::/60`, will mark this subnet range as `EUI64` style. Addresses generated for this
subnet will take form like `2001:db8:7:4aa0:8a8:7cff:fee3:1a32`. The `ff:fe` in middle of `hostid` is constant
which, according to IPv6 standard, specifies that `hostid` was simply copied from NIC's MAC address.
So, `:8a8:7cff:fee3:1a32` part literally says "My MAC address is `08:a8:7c:e3:1a:32`".

No worries tho, these bits are gathered randomly, but this may make an impression on foreign observer that
they communicate with some real device instead of random stranger. This feature is disabled by default.

`-`, like `-2001:db8:7:4aa0::/60` will exclude this range from address space. Your configuration might look like:

```
export RANDSADDR="2001:db8:7::/48,-2001:db8:7:4aa0::/60"
```
, which says "Use all available `2001:db8:7::/48` space but NOT addresses from `2001:db8:7:4aa0::/60`".

### IPv4 compatibility

You probably don't own much of "real" IPv4 addresses today. But you might do. So IPv4 is also supported, and
you can mix IPv4 subnets with IPv6 ones in `RANDSADDR`. Otherwise, IPv4 shall be a fast no-op.

### Performance

Not tested much. Since configuration parsing done once first `connect(2)` is done, it shall be fast enough after that.
I didn't took much tests. At least it _looks like_ it shall be fast enough (just one or two calls to fast PRNG plus table lookup).

I guess I need move configuration parsing to init stage which will be done just after linker will load the object.

If just preloaded without `RANDSADDR` envvar, randsaddr code shall effectively become no-op, immediately skipping to real `connect`.

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
