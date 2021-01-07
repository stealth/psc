PortShellCrypter -- PSC
=======================

PSC allows to e2e encrypt shell sessions across multiple hosts, being
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

Build
-----

Edit the `Makefile` to reflect your pre shared keys, as defined
at the top of the Makefile. Then just type `make`.

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
is already e2e encrypted, you can type `Ctrl-C` and `pscl` will tell you.

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
certain amout of data mangling, but in some situations it is not possible to recover.
Similar thing with `tmux`. You should avoid stacking pty handlers with PSC that
mess/handle their incoming data too much.

Demo
----

Theres a demo video on [![asciicast](https://asciinema.org/a/383043.svg)](https://asciinema.org/a/383043) that shows DNS lookups and SSH session forwarded across a UART to a Pi.



