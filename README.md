# kawaii

This repository contains some crates that may be helpful to the IRC smith of the
21st century!  They were built around ellidri, a modern [IRC server][ircd] (or
IRCd, for short).  You will especially find:

- an IRC parsing library, ellidri-tokens, which provides tools to correctly and
  efficiently parse IRC messages and mode strings,
- ellidri-unicase, providing a wrapper around strings to make them
  case-insensitive regarding IRC's different case mappings,
- an IRC server, ellidri, that aims to be simple to setup, feature complete and
  scalable.

To discuss about ellidri and cie, join the IRC channel: [#ellidri on
freenode][irc]!  There is also a test server running at [ellidri.org][org], if
you want to try it out!

The rest of this document is about ellidri, the IRC server.  All other projects
have their own `README.md`.

[ircd]: https://en.wikipedia.org/wiki/IRCd
[v3]: https://ircv3.net/
[irc]: https://webchat.freenode.net/#ellidri
[org]: https://ellidri.org/


## Features

- IRCv3 server
- Configurable via a file that can be reloaded at runtime
- kawaii messages

[Supported extensions][ext]: `account-notify`, `away-notify`, `batch`,
`cap-notify`, `echo-message`, `extended-join`, `invite-notify`,
`labeled-response`, `message-ids`, `message-tags`, `multi-prefix`,
`server-time`, `setname`, `userhost-in-names`

ellidri doesn't support any server-to-server (S2S) protocol.  As such, it is
impossible to make several instances of ellidri manage the same IRC network.

ellidri requires UTF-8 from clients, and for now it only supports `ascii` as
casemapping.

[r1]: https://tools.ietf.org/html/rfc1459
[r2]: https://tools.ietf.org/html/rfc2812
[ext]: https://ircv3.net/irc/


## Build and install

Prerequisites:

- The Rust compiler and Cargo: <https://rustup.rs/>

Install ellidri with `cargo install ellidri`, or with the [AUR package][aur].

During development, build it with `cargo build`, and run it with `cargo run`.

For packaging, build it with `cargo build --release --locked`.  The `release`
flag will enable optimizations and the `locked` flag will require a valid lock
file (`Cargo.lock`), to make sure that the same dependencies are used for
development and for release.  The executable is generated at
`target/release/ellidri`.

[aur]: https://aur.archlinux.org/packages/ellidri/


## Usage

See [`doc/setup-guide.md`][setup] for a step-by-step guide to have a working
setup.

[setup]: https://git.sr.ht/~taiite/ellidri/tree/master/doc/setup-guide.md


## Contributing

Patches are welcome!  Here are some links to get started:

- Documentation: <https://docs.rs/ellidri> (please note!  This documentation
  only shows public items, but private items are also documented!  Developers
  can generate the documentation by hand with the command below)
- Git repository: <https://git.sr.ht/~taiite/ellidri>
- Submit PRs on [Github][gh] or send patches to the mailing list:
  <https://lists.sr.ht/~taiite/public-inbox>
- Report bugs on the issue tracker: <https://todo.sr.ht/~taiite/ellidri>

When developing ellidri, you can use the following command to generate the
documentation of all items:

```
cargo doc --no-deps --document-private-items --open
```

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
