# kawai

ellidri, your kawai IRC server.


## Features

- RFC [1459][0] and [2812][1] compliance (almost!)
- Capabilities (version 302)

[0]: https://tools.ietf.org/html/rfc1459
[1]: https://tools.ietf.org/html/rfc2812


## Build and Install

Prerequisites:

- The Rust compiler (at least version 1.41) and Cargo: <https://rustup.rs/>
- On Linux, the OpenSSL library and its development files

Install ellidri with `cargo install ellidri`

Build it with `cargo build`.  Append the `--release` flag to build with
optimizations enabled.


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

To start ellidri, pass the path of the configuration file as its first argument.


## License

ellidri is under the ISC license.  See `LICENSE` for a copy.
