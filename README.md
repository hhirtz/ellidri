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
- TLS connections
- Multiple listening ports
- SASL support with SQLite and PostgreSQL
- kawaii messages

Supported extensions:

- [cap-notify](https://ircv3.net/specs/core/capability-negotiation#cap-notify)
- [echo-message](https://ircv3.net/specs/extensions/echo-message-3.2)
- [extended-join](https://ircv3.net/specs/extensions/extended-join-3.1)
- [invite-notify](https://ircv3.net/specs/extensions/invite-notify-3.2)
- [message-ids](https://ircv3.net/specs/extensions/message-ids)
- [message-tags](https://ircv3.net/specs/extensions/message-tags)
- [multi-prefix](https://ircv3.net/specs/extensions/multi-prefix-3.1)
- [sasl](https://ircv3.net/specs/extensions/sasl-3.1)
- [server-time](https://ircv3.net/specs/extensions/server-time-3.2.html)
- [setname](https://ircv3.net/specs/extensions/setname)
- [userhost-in-names](https://ircv3.net/specs/extensions/userhost-in-names-3.2)

ellidri doesn't support any server-to-server (S2S) protocol.  As such, it is
impossible to make several instances of ellidri manage the same IRC network.

ellidri will just support the UTF-8 encoding for messages, and for now it only
supports the `ascii` casemapping.

[r1]: https://tools.ietf.org/html/rfc1459
[r2]: https://tools.ietf.org/html/rfc2812
[i1]: https://todo.sr.ht/~taiite/ellidri/1


## Build and install

Prerequisites:

- The Rust compiler (at least version 1.39) and Cargo: <https://rustup.rs/>
- SQLite 3 (if the `sqlite` feature is enabled)
- PostgreSQL client libraries (if the `postgres` feature is enabled)
- On Linux, the OpenSSL library and its development files

Install ellidri with `cargo install ellidri`, or with the [AUR package][aur].

Build it with `cargo build`.  Append the `--release` flag to build with
optimizations enabled.

[aur]: https://aur.archlinux.org/packages/ellidri/


## Usage

ellidri needs a configuration file to run.  Its format is the following:

```
file   =  *( line "\n" )
line   =  sp key sp value sp
key    =  word
value  =  *( word / sp )
sp     =  any sequence of whitespace
```

An example configuration file with all settings and their defaults can be found
in `doc/ellidri.conf`.

To start ellidri, pass the path of the configuration file as its first argument:

```shell
cargo run -- doc/ellidri.conf
# or
./target/debug/ellidri doc/ellidri.conf
# or
./target/release/ellidri doc/ellidri.conf
```


## Contributing

Patches are welcome!  Here are some links to get started:

- Documentation: <https://docs.rs/ellidri>
- Git repository: <https://git.sr.ht/~taiite/ellidri>
- Send patches to the mailing list: <https://lists.sr.ht/~taiite/public-inbox>
- Report bugs on the issue tracker: <https://todo.sr.ht/~taiite/ellidri>


## Acknowledgments

ellidri couldn't have existed without the help of <https://ircdocs.horse>.
Thank you Daniel Oaks and [all other contributors][ac]!

Also thanks to the [IRCv3 working group][i3] for all the work on modernizing
the IRC protocol!

[ac]: https://github.com/ircdocs/modern-irc/graphs/contributors
[i3]: https://ircv3.net/charter


## License

ellidri is under the ISC license.  See `LICENSE` for a copy.
