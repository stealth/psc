PortShellCrypter -- PSC
=======================

This project - as well as its sister project [crash](https://github.com/stealth/crash) - belongs
to my anti-censorship tool-set that allows to setup fully working encrypted shells and TCP/UDP
forwarding in hostile censoring environments. It is also useful for forensics to dump data from
devices via UART or adb when no other means are available.

[![asciicast](https://asciinema.org/a/383043.svg)](https://asciinema.org/a/383043)
*DNS lookup and SSH session forwarded across an UART connection to a Pi*

PSC allows to e2e encrypt shell sessions, single- or multip-hop, being
agnostic of the underlying transport, as long as it is reliable and can send/receive
Base64 encoded data without modding/filtering. Along with the e2e pty that
you receive (for example inside a port-shell), you can forward TCP and UDP
connections, similar to OpenSSH's `-L` parameter. This works transparently
and without the need of an IP address assigned locally at the starting
point. This allows forensicans and pen-testers to create network connections
for example via:

* UART sessions to a device
* `adb shell` sessions, if the OEM `adbd` doesn't support TCP forwarding
* telnet sessions
* modem dial-ups without ppp
* other kinds of console logins
* mixed SSH/telnet/modem sessions
* ...

Just imagine you would have an invisible ppp session inside your shell session,
without the remote peer actually supporting ppp.

It runs on *Linux, Android, OSX, Windows, FreeBSD, NetBSD* and (possibly) *OpenBSD*.

PSC also includes *SOCKS4* and *SOCKS5* proxy support in order to have actual
web browsing sessions via port-shells or modem dial-ups remotely.

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
a port-shell, SSH, console login etc, you execute `pscr`:


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
`Makefile`. This crypto scheme is malleable, but adding AAD or OAD data blows up
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
can browse remote networks from a port-shell session without the need to open any other
connection during a pen-test. If you pass `-N` to `pscl`, it enables DNS name resolution
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


Bounce commands
---------------

*psc* contains features to allow TCP-connections or binary data blobs being forwarded from/to remote
devices across multiple hops even if it is not possible to install the `pscr` binary at
the remote site. This is very useful for forensic purposes if you do not have any means
to otherwise download artefacts from the device (which can be an UART connected phone for example)
or need to forward connections without touching the FS to not destroy evidence on the system
or when the root-FS is ro mounted and you can't upload your tool-set.

This solely works by local pty punkrock and handing over a bounce-command to `pscl` that it will
drop on the remote shell (without `pscr` running) and some state engine magic that filters out
and handles the data at the local side. Usually this requires to set the remote pty to raw mode
at first before issuing the actual command.

If you want to forward a TCP connection, this example requires `stty` and `nc` installed on the
device, but it could theoretically be anything else that does equivalent.

Start a local session:

`TERM=dumb ./pscl -B '1234:[stty -echo raw;nc example.com 22]'`

This will issue the command `stty -echo raw;nc example.com 22` to the remote device if you
connect locally to port 1234 and then just forwards any data it sees back and forth and
rate-limiting the traffic so it will not exceed the devices' tty speed (115200 is the default).

When the local session is started, connect to the remote device by UART, ssh or whatever it is and once
you have the remote shell, also type locally:

`ssh root@127.0.0.1 -p 1234` to bounce the SSH connection from your local box across the remote
device to the `example.com` destination. Of course the `pscr` variant is preferred as it is only possible
to bounce a single connection at a time (although you can pass multiple `-B` commands for various
forwards) and theres a chance to hang the shell after the TCP session since the pty is in `raw -echo`
mode and depending on whether the final remote peer also closes the connection, it might be
that the shell just hangs after that. If you happen to find a pscl notification that the connection
has finished and see a prompt, you should `reset` it, so that a new connection can be started.
While data is being forwarded, you will see 7bit ASCII `<` and `>` notifications in `pscl` which are just
local for easier debugging and progress detection.

Note that the connection to the remote site has to be 8bit clean, i.e. the ssh, telnet, UART or whatever
channel *must not handle escape sequences* (unlike when using `pscr`). For ssh connections this means you
have to use `ssh -e none` in the `pscl` session.

Next, following some examples to handle binary file xfer where *rfile* denotes the remote file and
*lfile* the local file.

To start a session to drop remote files, locally:

`TERM=dumb ./pscl -B '1234:[stty -echo raw;dd of=rfile.bin bs=1 count=7350;echo FIN]'`

Where you need to specify the amount of data that the remote side is expecting. It would also
work without (e.g. `cat>...`) but then the session will hang after transmission has finished as
`cat` is endlessly expecting input.

Then, ssh or whatever is necessary to get a shell on the remote device. Again, locally:

`dd if=lfile.bin|nc 127.0.0.1 1234`

which will connect to `pscl`'s local port 1234 and trigger the dump command on the remote side,
forwarding the binary data of the local `lfile.bin` to remotes `rfile.bin`. Due to rate-limiting
this can take a while and you *only trust your psc progress screen* whether the transfer is finished.
The local `dd ...|nc ...` command will only show you the local status which can eat entire files
in msecs due to local TCP buffers while the file is still being transfered through the pty.
So make sure you only press `Ctrl-C` when the *psc* screen tells you it is finished.

Likewise, similar commands could be used to transfer binary data from a remote device to the
local box for forensic purposes. Again, start of the session locally:

`TERM=dumb ./pscl -B '1234:[stty -echo raw;dd if=rfile.bin]'` or

`TERM=dumb ./pscl -B '1234:[stty -echo raw;cat rfile.bin]'`

Then, ssh to remote device to get the shell, then again locally:

`nc 127.0.0.1 1234|dd of=lfile.bin bs=1 count=7350`

To obtain `rfile.bin` of size 7350 copied to local file `lfile.bin`

If `stty -echo raw` is not available on the device, something like `python -c 'import tty;tty.setraw(0)'`
also works. Note that on the remote device you need to have a tty (not just a port-shell) when using bounce
commands, since the `stty` command to set raw mode requires a real tty.

If doing all the tests only locally w/o any connection between `pscl` and the command that you bounce,
you need to add `TERM=dumb` before the `pscl ...` comands. It can be omitted if running across a connection.


Flow control
------------

If *psc* runs across a serial connection, it is very likely that flow control is disabled and sending data
too fast would just make it vanish and corrupt the session. In this case you have to invoke *both ends* with
the `-l` parameter to set a baud rate (e.g. `-l 115200`). If bounce commands are used the same problem exists
with the pty in raw mode and rate limiting is automatically enabled to `115200` but a higher value
can be set if desired.
Note that browsing animated web sites is pure PITA with rate limiting from the 90's even though *psc*
does its best to still allow typing the shell during the connection. SSH connections OTOH work surprisingly
good.

UART / modem line
-----------------

Some UART chipsets seem to have different RX vs TX speeds. So even though you have a 115200 baud
UART connection set up, the local (upload) part is even more limited or otherwise data bits are lost.
During my raspi tests, I had to use `pscl -l 57600 ...` on the local side while using `pscr -l 115200 ...`
on the device. For bounce-commands I also had to use the 57600 even if the connection was at 115200.
If possible also use soft flow control with your serial console program. Also check the `contrib`
folder in order to patch your console program to be escape-character safe.


SIGUSR1 / SIGUSR2
-----------------

You can send `SIGUSR1` to `pscl` so it tells you whether the session is encrypted. If the remote
`pscr` dies or exits without possibility to signal that to the local part, `pscl` will stay
in encryption mode and therefore hang. In this case you can force a reset to plaintext mode
by sending `SIGUSR2`, so a new session can be started.

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

