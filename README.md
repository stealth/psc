PSeudoCrypt/PortShellCrypt -- PSC
=================================

License
-------

See LICENSE.txt

What it is
----------

PSC allows for end-to-end encryption of __SSH__,
__telnet__, __minicom__ or even portshell sessions across multiple hosts.
Basically it works like the _screen_ program but it transparently
encrypts/decrypts the things you type until it reaches its
real destination. So you can start
`psc-local` on your local box, `ssh` through 10 hops for example,
and at the end-box you start `psc-remote` and anything between
the 10 hops is not just __SSH__ encrypted but also encrypted
by PSC between your local host and the end-box. So, noone inbetween,
even if he controls the __SSH__ shells you use on the intermediate hops,
can see what you type.
PSC can also establish a full functional terminal over a simple
portshell (_inetd_ portshell for example) so you can run command-line
completion, _mc_ or whatever you want to on that portshell.
This normally wont work, since `stdin/stdout` of a portshell is a socket,
but by using PSC you add an additional crypto and pty layer to the
connection so you end up in a full functional shell as you would
get one from __SSH__.

You can use integrated __RC4__ crypto (weak) or blowfish OFB via openssl
if you compile with `-DUSE_SSL` (recommended).


Usage
------

Please see above. Edit the `Makefile` to reflect your secret keys and then

    $ make
    $ ./psc-local
    $

Do whatever you need to to get to your remote-host and start

    > ./psc-remote
    psc-2013-STARTTLpsc: Seen STARTTLS sequence, enabling crypto.
    >

there (needs file-copying in the first place). Done.
You will then be dropped in the pty'ed/encrypted'ed remote shell.
When exiting, the session is plaintext again. Repeat until root
kills you.
If you dont have Unix98 PTY support, disable `HAVE_UNIX98` in the `Makefile`.
PSC works also inside other pty based programs such as _ssh_ and _screen_.


Related work
------------

In 2001 I wrote _pt-why_ which uses __SSL__ to establish the crypto
communication. It worked but was not 7-bit clean. PSC is 7-bit clean,
it uses a Base64 encoding plus #,$,%,* and \n character for
detecing unwanted echos and to signal the end of the crypted communication.
These 5 characters are not part of the Base64 character set, so it
doesnt clash but we have still 7-Bit ASCII stream which makes it
work on most communication channels.


Checking crypto state
---------------------

In order to be sure whether your connection is really encrypted and
noone in between just prints

    psc: Seen STARTTLS sequence, enabling crypto.

to your screen, you can hit `Ctrl-C`, sending a __SIGINT__ to your local _psc_
command. Then it will tell you whether it has enabled crypto or not.

NOTE that psc only helps against attackers on the middle hops, not
on your local machine or the end point.

Misc
----

If you have questions beyond how to type 'make' you can reach me
at sebastian.krahmer [at] gmail.com

