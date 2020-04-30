# ellidri installation guide

This document will walk you through the necessary and recommended steps to have
a working installation of ellidri.  Namely,

1. Download ellidri
2. Create an systemd unit/init script
3. Create a user on your system
4. Generate or localize your certificates
5. Write ellidri's configuration file
6. Enable SASL with SQLite

This guide assume the following locations:

- `/usr/bin/ellidri` is the path to ellidri
- `/etc/ellidri.yaml` is ellidri's configuration file,
- `/etc/motd` is the Message Of The Day

You may change these locations whenever they appear (either in this guide or
files pointed by this guide).


## 1. Download ellidri

Some Linux distributions already have ellidri packaged:

- Arch Linux: <https://aur.archlinux.org/packages/ellidri/>

If you have installed ellidri through one of these packages, you can skip the
second step.  Otherwise, you can download the latest release here:
<https://git.sr.ht/~taiite/ellidri/refs>.

You can also install ellidri from source.  Instructions are in `README.md` at
the root of the repository.


## 2. Create an systemd unit/init script

If you haven't installed ellidri through one of the previous packages, you need
to create a systemd unit, or a init script (this guide only covers systemd
usage).  You may find one in the repository, at [`doc/ellidri.service`][unit].
Download this file and move it to `/etc/systemd/system/ellidri.service`.

[unit]: https://git.sr.ht/~taiite/ellidri/tree/master/doc/ellidri.service


## 3. Create a user on your system

To avoid running ellidri as root, you may want to create a dedicated user.  To
do so, use the following command:

    useradd -r -s /usr/bin/nologin ellidri


## 4. Generate or locate your certificates

If you want your installation to be public (i.e. available from the Internet),
you'll need a valid certificate.  You can obtain one from Let's Encrypt for
example, with certbot: <https://certbot.eff.org/>.

By default, certbot installs certificates at
`/etc/letsencrypt/live/your.domain/`.


## 5. Write ellidri's configuration file

Copy [`doc/config_example.yaml`][config] to `/etc/ellidri.yaml` and modify its
contents to your liking.  `domain` should be the same as the domain of the
certificate you've got from step 4.

You can now start ellidri with `systemctl start ellidri`.

After any change you make to the configuration file, you can apply them with
`systemctl reload ellidri`.

[config]: https://git.sr.ht/~taiite/ellidri/tree/master/doc/config_example.yaml


## 6. Enable SASL with SQLite

TODO
