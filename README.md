[![builds.sr.ht status](https://builds.sr.ht/~taiite/ellidri.svg)](https://builds.sr.ht/~taiite/ellidri?)
[![crates.io](https://img.shields.io/crates/v/ellidri.svg)](https://crates.io/crates/ellidri)

# kawaii

ellidri is an [IRC server][ircd] (or IRCd, for short), that aims to be simple to
setup, widely compatible, feature complete and scalable.

Join the IRC channel: [#ellidri on freenode][irc]!

[ircd]: https://en.wikipedia.org/wiki/IRCd
[v3]: https://ircv3.net/
[irc]: https://webchat.freenode.net/#ellidri


## Features

- RFC [1459][r1] and [2812][r2] compliance (almost! see [#1][i1])
- IRCv3 support
- TODO: Secure and production-ready setup with TLS out-of-the-box
- Configurable via a file
- SASL support with SQLite and PostgreSQL
- kawaii messages

[Supported extensions][ext]: `account-notify`, `away-notify`, `batch`,
`cap-notify`, `echo-message`, `extended-join`, `invite-notify`,
`labeled-response`, `message-ids`, `message-tags`, `multi-prefix`, `sasl`,
`server-time`, `setname`, `userhost-in-names`

ellidri doesn't support any server-to-server (S2S) protocol.  As such, it is
impossible to make several instances of ellidri manage the same IRC network.

ellidri requires UTF-8 from clients, and for now it only supports `ascii` as
casemapping.

[r1]: https://tools.ietf.org/html/rfc1459
[r2]: https://tools.ietf.org/html/rfc2812
[i1]: https://todo.sr.ht/~taiite/ellidri/1
[ext]: https://ircv3.net/irc/


## Build and install

Prerequisites:

- The Rust compiler (at least version 1.39, or v1.41 when using PostgreSQL) and
  Cargo: <https://rustup.rs/>
- SQLite 3 (if the `sqlite` feature is enabled)
- PostgreSQL client libraries (if the `postgres` feature is enabled)
- On Linux, the OpenSSL library and its development files

Install ellidri with `cargo install ellidri`, or with the [AUR package][aur].

During development, build it with `cargo build`, and run it with `cargo run`.

For packaging, build it with `cargo build --release --locked`.  The `release`
flag will enable optimizations and the `locked` flag will require a valid lock
file (`Cargo.lock`), to make sure that the same dependencies are used for
development and for release.  The executable is generated at
`target/release/ellidri`.

[aur]: https://aur.archlinux.org/packages/ellidri/


## Usage

ellidri must be started with a configuration file, for example:

```conf
# Configuration file
domain  your.domain.tld

# Bind to an address and port.
bind_to 127.0.0.1:6667

# TLS-enabled port, with a PKCS12 archive.
bind_to 0.0.0.0:7000 /var/lib/ellidri/identity.p12

# Default is /etc/motd
motd_file  custom_motd.txt
```

And start ellidri with the `--config` argument like so:

```
ellidri --config /path/to/the.configuration.file
```

An example configuration file with all settings and their defaults can be found
in `doc/ellidri.conf`.

## Contributing

Patches are welcome!  Here are some links to get started:

- Documentation: <https://docs.rs/ellidri>
- Git repository: <https://git.sr.ht/~taiite/ellidri>
- Submit PRs on [Github][gh] or send patches to the mailing list:
  <https://lists.sr.ht/~taiite/public-inbox>
- Report bugs on the issue tracker: <https://todo.sr.ht/~taiite/ellidri>

[gh]: https://github.com/hhirtz/ellidri


## Acknowledgments

ellidri couldn't have existed without the help of <https://ircdocs.horse>.
Thank you Daniel Oaks and [all other contributors][ac]!

Also thanks to the [IRCv3 working group][i3] for all the work on modernizing
the IRC protocol!

[ac]: https://github.com/ircdocs/modern-irc/graphs/contributors
[i3]: https://ircv3.net/charter


## License

ellidri is under the ISC license.  See `LICENSE` for a copy.
