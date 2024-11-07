contrib
=======

This directory contains some contributions.

tio noprefix patch
------------------

tio is a nice serial console client that has all the nice magic switches
and cmdline friendlieness that you expect on Linux-like systems.

Apply the patch to [tio](https://github.com/tio/tio) @commit `bfefd04b5567ba2b5`
in order to allow serial console session w/o tapering of the I/O stream so you
can pipe arbitrary data through your pty for the bounce command (this patch
works like ssh's `-e none`).

Adding this patch to current versions is not necessary anymore as its already
been integrated.

Then add to your `~/.tioconfig`:
```
prefix-ctrl-key = none
```

Which disables prefix parsing.



tio limit patch
---------------

tio will collect input bytes into a buffer before sending it to the serial line,
which could lead to peeks above the acceptable baudrate. This dirty patch adds rate
limiting in the write cycle. Also consider using `tio -o 1` if you get bit flips
during transmission.

