//! Channel data and management.
//!
//! See: https://tools.ietf.org/html/rfc2811.html

use std::collections::HashMap;
use std::net::SocketAddr;

/// Channel data.
#[derive(Default)]
pub struct Channel {
    /// Set of channel members, identified by their socket address, and
    /// associated with their channel mode.
    pub members: HashMap<SocketAddr, Modes>,
    //modes: Modes,

    /// The topic.
    pub topic: String,
}

impl Channel {
    /// Adds a member with the default mode.
    pub fn add_member(&mut self, addr: SocketAddr) {
        self.members.insert(addr, Modes::default());
    }

    /// Removes a member.
    pub fn remove_member(&mut self, addr: SocketAddr) {
        self.members.remove(&addr);
    }

    /// True if `self.topic` is not empty.
    pub fn has_topic(&self) -> bool {
        !self.topic.is_empty()
    }
}

/// To be implemented.
#[derive(Default)]
pub struct Modes;