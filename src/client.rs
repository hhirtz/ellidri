//! Client management and connection state.

use crate::message::{Command, MessageBuffer, ResponseBuffer};
use crate::modes;
use futures::sync::mpsc;
use std::sync::Arc;
use std::collections::HashSet;
use std::str::SplitWhitespace;

#[derive(Clone)]
pub struct MessageQueueItem(Arc<[u8]>);

impl From<Vec<u8>> for MessageQueueItem {
    fn from(bytes: Vec<u8>) -> Self {
        Self(Arc::from(bytes))
    }
}

impl From<ResponseBuffer> for MessageQueueItem {
    fn from(response: ResponseBuffer) -> Self {
        Self::from(response.build())
    }
}

impl AsRef<[u8]> for MessageQueueItem {
    fn as_ref(&self) -> &[u8] {
        self.0.as_ref()
    }
}

pub type MessageQueue = mpsc::UnboundedSender<MessageQueueItem>;

/// A state machine that represent the connection with a client. It keeps track of what message the
/// client can send.
///
/// For example, a client that has only sent a "NICK" message cannot send a "JOIN" message.
#[derive(Clone, Copy, Debug, PartialEq)]
pub enum ConnectionState {
    ConnectionEstablished,
    NickGiven,
    UserGiven,
    CapGiven,
    CapNickGiven,
    CapUserGiven,
    CapNegotiation,
    Registered,
    Quit,
}

impl Default for ConnectionState {
    fn default() -> ConnectionState {
        ConnectionState::ConnectionEstablished
    }
}

impl ConnectionState {
    pub fn apply(self, command: Command, sub_command: &str) -> Result<ConnectionState, ()> {
        match self {
            ConnectionState::ConnectionEstablished => match command {
                Command::Cap if sub_command == "LS" => Ok(ConnectionState::CapGiven),
                Command::Pass => Ok(self),
                Command::Nick => Ok(ConnectionState::NickGiven),
                Command::User => Ok(ConnectionState::UserGiven),
                Command::Quit => Ok(ConnectionState::Quit),
                _ => Err(()),
            }
            ConnectionState::NickGiven => match command {
                Command::Nick | Command::Pass => Ok(self),
                Command::User => Ok(ConnectionState::Registered),
                Command::Quit => Ok(ConnectionState::Quit),
                _ => Err(()),
            }
            ConnectionState::UserGiven => match command {
                Command::Pass => Ok(self),
                Command::Nick => Ok(ConnectionState::Registered),
                Command::Quit => Ok(ConnectionState::Quit),
                _ => Err(()),
            }
            ConnectionState::CapGiven => match command {
                Command::Pass => Ok(self),
                Command::Nick => Ok(ConnectionState::CapNickGiven),
                Command::User => Ok(ConnectionState::CapUserGiven),
                Command::Quit => Ok(ConnectionState::Quit),
                _ => Err(()),
            }
            ConnectionState::CapNickGiven => match command {
                Command::Pass | Command::Nick => Ok(self),
                Command::User => Ok(ConnectionState::CapNegotiation),
                Command::Quit => Ok(ConnectionState::Quit),
                _ => Err(()),
            }
            ConnectionState::CapUserGiven => match command {
                Command::Pass => Ok(self),
                Command::Nick => Ok(ConnectionState::CapNegotiation),
                Command::Quit => Ok(ConnectionState::Quit),
                _ => Err(()),
            }
            ConnectionState::CapNegotiation => match command {
                Command::Pass | Command::Nick => Ok(self),
                Command::Cap if sub_command == "END" => Ok(ConnectionState::Registered),
                Command::Cap => Ok(self),
                Command::Quit => Ok(ConnectionState::Quit),
                _ => Err(()),
            }
            ConnectionState::Registered => match command {
                Command::Pass | Command::User => Err(()),
                Command::Quit => Ok(ConnectionState::Quit),
                _ => Ok(self),
            }
            ConnectionState::Quit => Err(()),
        }
    }

    pub fn is_registered(self) -> bool {
        self == ConnectionState::Registered
    }
}

pub const CAP_LS: &str = "";
lazy_static::lazy_static! {
    static ref CAPABILITIES: HashSet<&'static str> = ["cap-notify"].iter().cloned().collect();
}

#[derive(Default)]
pub struct Capabilities {
    pub v302: bool,
    pub cap_notify: bool,
}

pub struct CapQuery<'a> {
    inner: SplitWhitespace<'a>,
}

impl<'a> CapQuery<'a> {
    pub fn parse(s: &'a str) -> Self {
        Self {
            inner: s.split_whitespace(),
        }
    }
}

impl<'a> Iterator for CapQuery<'a> {
    type Item = (&'a str, bool);

    fn next(&mut self) -> Option<Self::Item> {
        self.inner.next().map(|word| {
            if word.starts_with('-') {
                (&word[1..], false)
            } else {
                (word, true)
            }
        })
    }
}

pub fn are_supported_capabilities(capabilities: &str) -> bool {
    CapQuery::parse(capabilities).all(|(cap,  _)| CAPABILITIES.contains(cap))
}

const FULL_NAME_LENGTH: usize = 63;

/// Client data.
pub struct Client {
    /// The queue of messages to be sent to the client.
    ///
    /// This is the write end of a mpsc channel of messages (similar to go channels). It is
    /// currently unbounded, meaning sending messages to this channel do not block.
    queue: MessageQueue,

    capabilities: Capabilities,
    state: ConnectionState,

    nick: String,
    user: String,
    real: String,
    host: String,

    /// The nick!user@host
    full_name: String,

    /// Whether the client has issued a PASS command with the right password.
    pub has_given_password: bool,

    // Modes: https://tools.ietf.org/html/rfc2812.html#section-3.1.5
    pub away: bool,
    pub invisible: bool,
    pub registered: bool,
    pub operator: bool,
}

impl Client {
    /// Initialize the data for a new client, given its message queue.
    ///
    /// The nickname is set to "*", as it seems it's what freenode server does.  The username and
    /// the realname are set to empty strings.
    pub fn new(queue: MessageQueue, host: String) -> Self {
        let mut full_name = String::with_capacity(FULL_NAME_LENGTH);
        full_name.push('*');
        full_name.push_str(&host);
        Self {
            queue,
            nick: String::from("*"),
            host,
            full_name,
            capabilities: Capabilities::default(),
            state: ConnectionState::default(),
            user: String::new(),
            real: String::new(),
            has_given_password: false,
            away: false,
            invisible: false,
            registered: false,
            operator: false,
        }
    }

    pub fn update_capabilities(&mut self, capabilities: &str) {
        for (capability, enable) in CapQuery::parse(capabilities) {
            match capability {
                "cap-notify" => self.capabilities.cap_notify = enable,
                _ => {}
            }
        }
    }

    pub fn set_cap_version(&mut self, version: &str) {
        if version == "302" {
            self.capabilities.v302 = true;
        }
    }

    pub fn write_enabled_capabilities(&self, response: &mut ResponseBuffer) {
        let mut msg = response.message(Command::Cap).param(&self.nick);
        let trailing = msg.raw_trailing_param();
        if self.capabilities.cap_notify {
            trailing.push_str("cap-notify");
            trailing.push(' ');
        }
        trailing.pop();
    }

    pub fn write_capabilities(&self, response: &mut ResponseBuffer) {
        response.message(Command::Cap).param(&self.nick).param("LS").trailing_param(CAP_LS);
    }

    /// Change the connection state of the client given the command it just sent.
    ///
    /// # Panics
    ///
    /// This function panics if the command cannot be issued in the client current state.
    /// `Client::can_issue_command` should be called before.
    pub fn apply_command(&mut self, command: Command, sub_command: &str) -> ConnectionState {
        self.state = self.state.apply(command, sub_command).unwrap();
        self.state
    }

    /// Whether or not the client can issue the given command.
    ///
    /// This function does not change the connection state.
    pub fn can_issue_command(&self, command: Command, sub_command: &str) -> bool {
        self.state.apply(command, sub_command).is_ok()
    }

    pub fn is_registered(&self) -> bool {
        self.state == ConnectionState::Registered
    }

    /// Add a message to the client message queue.
    ///
    /// Use this function to send messages to the client.
    pub fn send(&self, msg: MessageQueueItem) {
        self.queue.unbounded_send(msg).unwrap();
    }

    pub fn full_name(&self) -> &str {
        &self.full_name
    }

    fn update_full_name(&mut self) {
        self.full_name.clear();
        self.full_name.push_str(&self.nick);
        self.full_name.push('!');
        self.full_name.push_str(&self.user);
        self.full_name.push('@');
        self.full_name.push_str(&self.host);
    }

    /// The nickname of the client
    pub fn nick(&self) -> &str {
        &self.nick
    }

    /// Change the nickname of the client.
    ///
    /// This function does not change the connection state.
    pub fn set_nick(&mut self, nick: &str) {
        self.nick.clear();
        self.nick.push_str(nick);
        self.update_full_name();
    }

    /// Change the username and the realname of the client.
    ///
    /// This function does not change the connection state.
    pub fn set_user_real(&mut self, user: &str, real: &str) {
        self.user.push_str(user);
        self.real.push_str(real);
        self.update_full_name();
    }

    pub fn state(&self) -> ConnectionState {
        self.state
    }

    pub fn write_modes(&self, mut out: MessageBuffer<'_>) {
        let modes = out.raw_param();
        modes.push('+');
        if self.away { modes.push('a'); }
        if self.invisible { modes.push('i'); }
        if self.operator { modes.push('o'); }
    }

    pub fn apply_mode_change(&mut self, change: modes::UserModeChange) -> bool {
        use modes::UserModeChange::*;
        let applied;
        match change {
            Invisible(value) => {
                applied = self.invisible != value;
                self.invisible = value;
            },
        }
        applied
    }
}
