## randsaddr: randomize network source address.

### What is it for?

randsaddr.so is `LD_PRELOAD` style object which hooks BSD networking syscalls to force an application to use random source address.
It does so to perform a source address randomization by calling an additional
`bind(2)` in process of establishing connection, but transparently for caller,
who didn't use `bind(2)` before (_most_ Unix network clients at the time of writing).
It is perfect to use in IPv6 networks, where `hostid` 64 bit part can be randomized
for reasons of non traceability, or when you have spare `/48` or more `netid` bits
available and you can randomize them for additional (pseudo)anonymity!

### Building

It shall be simple. Type `make`, the result pre-loadable object file is `randsaddr.so`.

You may want to install it on system into `/usr/lib` (or `/usr/lib64`, pick one) directory.

Just copy it there:

```
# su -
# cp randsaddr.so /usr/lib
```

### Usage

The `randsaddr.so` shared object must be loaded into your application address space:

```
$ LD_PRELOAD=/usr/lib/randsaddr.so your-app args etc.
```

If no `RANDSADDR` environment variable was passed, it will do nothing but act as a shim object.

To make it work as intended, `RANDSADDR` environment variable shall be set.

Syntax for `RANDSADDR` environment variable is:

_brief syntax_

```
RANDSADDR=SUBNET/PREFIX[,SUBNET/PREFIX,...]
```

_full syntax_

```
RANDSADDR=[random=FILE][[-][env,socket,bind,connect,send,sendto,sendmsg,eui64,reuseaddr,fullbytes]][BEFW]SUBNET/PREFIX[,SUBNET/PREFIX][,REMAP_SUBNET/PREFIX=MAPPED_SUBNET/PREFIX]
```
, where `SUBNET/PREFIX` takes a canonical CIDR IP address range syntax, like

```
192.0.2.0/24
```
for IPv4 (here `192.0.2.0` is SUBNET and `24` is PREFIX), or
```
2001:db8::/32
```
for IPv6 (here `2001:db8::` is SUBNET and `32` is PREFIX).

randsaddr then will pick a subnet from provided list randomly each time `connect(2)` (or other enabled syscall) is called, and make an random address out of it, then `bind(2)` it to a socket fd.

List of syscalls which `randsaddr.so` will control is given as comma separated list: `socket,bind,connect,send,sendto,sendmsg`.
If a single entry, e.g. `send` is prefixed with dash, like `-send`, it's usage will be disabled and forced to pass through.

Note that `socket` used with server daemons may produce their misbehavior!

`bind` call is special: it allows remapping of subnets an application tries to bind to transparently, say, to rebind IPv6 "any address" `::/128` to randomly generated address from `2001:db8:ffff:eeee:8:9::/96`, one can specify `::/128=2001:db8:ffff:eeee:8:9::/96`, or to exclude certain subnets from address space with `B` prefix flag (see below).

Each `SUBNET/PREFIX` can also be configured with it's prefix flags:

* `E`: make address look like eui64 address from specified subnet,
* `W`: whitelist (exclude) this subnet from broader subnet, say, `2001:db8:1::/48,W2001:db8:1:a::/64` will not produce addresses belonging to `2001:db8:1:a::/64` subnet at all,
* `B`: with `bind` call, do never allow this subnet to be bindable at all (this is littly different from `W`: it's scope is limited only to `bind` call),
* `F`: always fill address nibbles (never allow addressess like `2001:db8:0a:0d:fd00:1c::2` with multiple zero four bit groups to be generated)

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
# echo 1 > /proc/sys/net/ipv4/ip_nonlocal_bind
# echo 1 > /proc/sys/net/ipv6/ip_nonlocal_bind
```

2. You need to provide Linux kernel with a route that basically says that requested
address space is there in our control. Assuming example ranges above, do so by enabling this:

```
# ip -6 route add local 2001:db8:7:4aa0::/60 dev lo
# ip -6 route add local 2001:db8:7:7870::/60 dev lo
# ip -6 route add local 2001:db8:a5:1200::/60 dev lo
# ip -6 route add local 2001:db8:8:9e30::/60 dev lo
```

Above commands shall be run as superuser (hence `#` prompt).

3. You probably will need to do this on non-Ethernet (level3) interface. Ethernet will want your router
to map each address you've generated to MAC address of NIC, which is hardly achievable in a "normal" way.
A Wireguard, PP(T)P or GRETUN tunnel will work pretty well.
Most SLAAC setups (for IPv6) or Level2 (IPv4/ARP) will NOT work though.

Keep in mind: your OS must "write" packets to interface,
not "ask" your router about "am I allowed to send packet as `address` from `hwaddr`?".

4. Optionally, set up your iptables/nftables to allow these new ranges. This is out of
scope of this document, as your netfilter configurations may vary (or be absent).

5. Now the fun part. Any userspace (unprivileged) program now can call `bind(2)` to
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

Among SUBNET prefixes, these comma separated keywords can be passed:

* `-env` will erase contents of RANDSADDR environment variable after parsing it, whilst `env` will keep the contents intact (the default).
Hence, `-env` will make configuration for current process private, and it will not propagade into it's children.
It is useful for privacy concerns, like, running Tor or transmission daemon. Note that even if
`unsetenv(3)` is called after erasing environment variable, most libcs will not get `RANDSADDR` name get removed from environ.
* `random=FILE` will add random source pointed to by `FILE`. For example, specifying `random=/dev/random` would increase amount
of true random data, from which addressess will be generated. The random source `/dev/urandom` is always used anyways, further
files only add random data to it. This option can be specified up to 8 times (enough for most applications).
* `reuseaddr` will enable `setsockopt(2)` `SO_REUSEADDR` option to specify that this address can be captured right now.
Most of the times this option is not needed at all. It might be a thing with IPv4.
* `eui64` will enable `E` prefix option for any IPv6 subnet.
* `fullbytes` will enable `F` prefix option for any subnet.

Each keyword can be preceeded with dash symbol `-` to reverse it's effect.

### IPv4 compatibility

You probably don't own much of "real" IPv4 addresses today. But you might do. So IPv4 is also supported, and
you can mix IPv4 subnets with IPv6 ones in `RANDSADDR`. Otherwise, IPv4 shall be a fast no-op.

### Performance

Not tested much. Since configuration parsing done once first `connect(2)` is done, it shall be fast enough after that.
I didn't took much tests. At least it _looks like_ it shall be fast enough (just one or two calls to fast PRNG plus table lookup).

I guess I need move configuration parsing to init stage which will be done just after linker will load the object.

If just preloaded without `RANDSADDR` envvar, randsaddr code shall effectively become no-op, immediately skipping to real `connect`.

### Static library

Among with `randsaddr.so` shared object, an `librandsaddr.a` is created, which contains code suitable for linking statically
when building programs from source code. Most libcs which can be linked statically will tolerate symbol overrides.

When building, specify additional `LDFLAGS` or `LIBS` to point to this library for linking.

### Further notes

Some apps (like Google Chrome) may consider `LD_PRELOAD` dangerous, and they will unset it automatically, or bail out.
There is little you can do about it other than getting Chromium source, rebuilding it with removal of these anti-feature.
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
