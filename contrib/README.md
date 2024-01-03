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

Then add to your `~/.tioconfig`:
```
prefix-ctrl-key = none
```

Which disables prefix parsing.

