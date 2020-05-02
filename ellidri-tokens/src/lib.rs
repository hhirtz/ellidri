//! Parse IRC like a boss.
//!
//! This library provides helpers to tokenize and build IRC messages, while keeping the number of
//! allocations minimal.

#![forbid(unsafe_code)]
#![warn(clippy::all, rust_2018_idioms)]
#![allow(
    clippy::filter_map,
    clippy::find_map,
    clippy::shadow_unrelated,
    clippy::use_self
)]

pub use buffers::{Buffer, MessageBuffer, TagBuffer};
pub use command::Command;
pub use message::{tag_escape, tags, Message, Tag, MESSAGE_LENGTH, PARAMS_LENGTH};

mod buffers;
mod command;
mod message;
pub mod mode;
pub mod rpl;

/// Assert all data of a message.
///
/// Empty elements in `params` will not be asserted with their equivalent in `msg.params`, but will
/// still count for the assertion of the number of parameters.
pub fn assert_msg(
    msg: &Message<'_>,
    prefix: Option<&str>,
    command: Result<Command, &str>,
    params: &[&str],
) {
    assert_eq!(msg.prefix, prefix, "prefix of {:?}", msg);
    assert_eq!(msg.command, command, "command of {:?}", msg);
    assert_eq!(
        msg.num_params,
        params.len(),
        "number of parameters of {:?}",
        msg
    );
    for (i, (actual, expected)) in msg.params.iter().zip(params.iter()).enumerate() {
        if expected.is_empty() {
            // Some parameters may be of different form every time they are generated (e.g.
            // NAMREPLY params, since the order comes from `HashMap::iter`), so we skip them.
            continue;
        }
        assert_eq!(actual, expected, "parameter #{} of {:?}", i, msg);
    }
}
