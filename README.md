PortShellCrypter -- PSC
=======================

This project - as well as its sister project [crash](https://github.com/stealth/crash) - belongs
to my anti-censorship tool-set that allows to setup fully working encrypted shells and TCP/UDP
forwarding in hostile censoring environments.

[![asciicast](https://asciinema.org/a/383043.svg)](https://asciinema.org/a/383043)
*DNS lookup and SSH session forwarded across an UART connection to a Pi*

PSC allows to e2e encrypt shell sessions, single- or multip-hop, being
agnostic of the underlying transport, as long as it is reliable and can send/receive
Base64 encoded data without modding/filtering. Along with the e2e pty that
you receive (for example inside a portshell), you can forward TCP and UDP
connections, similar to OpenSSH's `-L` parameter. This works transparently
and without the need of an IP address assigned locally at the starting
point. This allows forensicans and pentesters to create network connections
for example via:

* UART sessions to a device
* `adb shell` sessions, if the OEM `adbd` doesn't support TCP forwarding
* telnet sessions
* modem dialups without ppp
* other kinds of console logins
* mixed SSH/telnet/modem sessions
* ...

Just imagine you would have an invisible ppp session inside your shell session,
without the remote peer actually supporting ppp.

It runs on *Linux, Android, OSX, Windows, FreeBSD, NetBSD* and (possibly) *OpenBSD*.

PSC also includes *SOCKS4* and *SOCKS5* proxy support in order to have actual
web browsing sessions via portshells or modem dialups remotely.

Build
-----

Edit the `Makefile` to reflect your pre shared keys, as defined at the top of the `Makefile`.

Then just type `make` on *Linux* and *OSX*.

On *BSD* you need to install *GNU make* and invoke `gmake` instead.

On *Windows* you need to install [cygwin](https://cygwin.com/install.html) and select
the appropriate `gcc, gcc-g++, make` and `git` packages.

On *Linux*, PSC will use *Unix98* pseudo terminals, on other systems it will use *POSIX*
pty's but that should be transparent to you. I once added *4.4BSD* pty and *SunOS*
support back in the stone age for a particular reason, so it may or may not
build even with *Solaris*.

*proudly sponsored by:*
<p align="center">
<a href="https://github.com/c-skills/welcome">
<img src="https://github.com/c-skills/welcome/blob/master/logo.jpg"/>
</a>
</p>


Usage
-----

Plain and simple. On your local box, execute `pscl`, and pass any
TCP or UDP ports you want to forward *from* the remote site to a particular
address. For example:

```
linux:~ > ./pscl -T 1234:[192.168.0.254]:22 -U 1234:[8.8.8.8]:53

PortShellCrypter [pscl] v0.60 (C) 2006-2020 stealth -- github.com/stealth/psc

pscl: set up local TCP port 1234 to proxy to 192.168.0.254:22 @ remote.
pscl: set up local UDP port 1234 to proxy to 8.8.8.8:53 @ remote.

pscl: Waiting for [pscr] session to appear ...
linux:~ >

[ UART / SSH / ... login to remote side ... ]
```

On the remote site (the last hop) with the shell session, no matter if its in
a portshell, SSH, console login etc, you execute `pscr`:


```
linux:~ > ./pscr

PortShellCrypter [pscr] v0.60 (C) 2006-2020 stealth -- github.com/stealth/psc


pscl: Seen STARTTLS sequence, enabling crypto.
linux:~ >
```

Once you execute `pscr`, both ends establish a crypto handshake and lay an additional
protocol over your existing session that is transparent for you. You can then
connect to `127.0.0.1:1234` on your local box to reach `192.168.0.254:22` via
TCP or the `8.8.8.8` resolver via UDP. This also works with [IPv6] addresses,
if the remote site has IPv6 connectivity. Actually, you can even use it to translate
IPv4 software to IPv6, since you always connect to `127.0.0.1` on the local side.

You can pass multiple `-T` and `-U` parameters. If you lost track if your session
is already e2e encrypted, you can send a `SIGUSR1` to the local `pscl` process, and it
will tell you.

PSC is also useful if you want to use tor from a remote SSH shell, where you
can forward the socks5 and the DNS port to the remote hosts `127.0.0.1` address.
Since SSH does not forward UDP packets, you would normally use two `socat` connectors
or similar to resolve via the tor node. PSC has the advantage of keeping the UDP
datagram boundaries, while `socat` over `SSH -L` may break datagram boundaries
and create malformed DNS requests.

The session will be encrypted with `aes_256_ctr` of a PSK that you choose in the
`Makefile`. This crypto scheme is mallable, but adding AAD or OAD data blows up
the packet size, where every byte counts since on interactive sessions and due to
Base64 encoding, each typed character already causes much more data to be sent.


UART sessions may be used via `screen` but for example not via `minicom` since
minicom will create invisible windows with status lines and acts like a filter
that destroys PSC's protocol. PSC tries to detect filtering and can live with
certain amount of data mangling, but in some situations it is not possible to recover.
Similar thing with `tmux`. You should avoid stacking pty handlers with PSC that
mess/handle their incoming data too much.

The `SHELL` environment variable needs to be set for both `pscl` and `pscr` in order
for PSC to know which shell to execute on the pty. `SHELL` is set in most environments
by default, but in case it isn't, PSC needs to be executed like `SHELL=/bin/bash pscl`
etc.


SOCKS4 and SOCKS5 support
-------------------------

`pscl` also supports forwarding of TCP connections via *SOCKS4* (`-4 port`) and *SOCKS5*
(`-5 port`). This sets up *port* as SOCKS port for TCP connections, so for instance you
can browse remote networks from a portshell session without the need to open any other
connection during a pentest. If you pass `-N` to `pscl`, it enables DNS name resolution
on the remote side, so you can also use chrome with it. But be warned: There is a privacy
problem with browsers that try to resolve a sequence of DNS names upon startup that
is not under your control. Also, if your remote side has a broken DNS setup, your typing
shell may block for several seconds if DNS reply packets are missing. There are no good
async resolver functions which are embeddable and portable so I had to rely on
`getaddrinfo()` in the single thread at the price of possible blockings for several seconds
if DNS problems exist. Thats why name resolving has to be enabled explicitly. `pscr`
tries to minimize this potential problem with DNS lookup caches though, so in most
situation it should just work painlessly.
If you pass `-X IP-address` (must be the first argument), you can bind your local proxy
to an address different from `127.0.0.1`, so you can share the proxy in your local network.


Scripting
---------

As of version 0.64, *psc* supports scripting-sockets so you no longer need `screen` to
get/put files or dump paste buffers to the remote console. Instead, you start your local
session like so:

```
~ > ./pscl -S ~/psc.script_sock
```

You can then go ahead and use it as before. If you need to 'paste' something you do like:

```
~ > ./pscsh -S ~/psc.script_sock -f script_/helloworld
```

This will 'type' the content of `script_/helloworld` to the console. While scripting,
the stdin of `pscl` is blocked so that the injected input does not mix up with any
typing. If `-S` is omitted in `pscsh`, `~/psc.script_sock` is used automatically.
For safety reasons, scripts must start with the `script_` prefix.

As a bonus, `pscr` now contains the ability to base64 en/decode files, even with CR
embedded characters for convenience. It is compatible to `uuencode -m`.

