//! Client data, connection state and capability logic.

use crate::{data, util};
use ellidri_tokens::{mode, Buffer, MessageBuffer, ReplyBuffer};
use std::fmt::Write as _;
use std::sync::Arc;
use tokio::sync::mpsc;

#[derive(Clone, Debug)]
pub struct MessageQueueItem {
    pub start: usize,
    buf: Arc<String>,
}

impl From<Buffer> for MessageQueueItem {
    fn from(val: Buffer) -> Self {
        Self {
            start: 0,
            buf: Arc::new(val.build()),
        }
    }
}

impl From<ReplyBuffer> for MessageQueueItem {
    fn from(val: ReplyBuffer) -> Self {
        Self {
            start: 0,
            buf: Arc::new(val.build()),
        }
    }
}

impl AsRef<str> for MessageQueueItem {
    /// # Panics
    ///
    /// This function panics when `self.start` is greater than the content's length.
    fn as_ref(&self) -> &str {
        &self.buf.as_ref()[self.start..]
    }
}

pub type MessageQueue = mpsc::UnboundedSender<MessageQueueItem>;

/// A state machine that represent the connection with a client. It keeps track of what message the
/// client can send.
///
/// For example, a client that has only sent a "NICK" message cannot send a "JOIN" message.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
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
    pub fn apply(self, request: &data::Request<'_>) -> Result<ConnectionState, ()> {
        use data::Request::*;
        match self {
            ConnectionState::ConnectionEstablished => match request {
                CapLs { .. } | CapReq { .. } => Ok(ConnectionState::CapGiven),
                CapEnd | CapList { .. } | Pass { .. } | Ping { .. } => Ok(self),
                Nick { .. } => Ok(ConnectionState::NickGiven),
                User { .. } => Ok(ConnectionState::UserGiven),
                Quit { .. } => Ok(ConnectionState::Quit),
                _ => Err(()),
            },
            ConnectionState::NickGiven => match request {
                CapLs { .. } | CapReq { .. } => Ok(ConnectionState::CapGiven),
                CapEnd | CapList { .. } | Nick { .. } | Pass { .. } | Ping { .. } => Ok(self),
                User { .. } => Ok(ConnectionState::Registered),
                Quit { .. } => Ok(ConnectionState::Quit),
                _ => Err(()),
            },
            ConnectionState::UserGiven => match request {
                CapLs { .. } | CapReq { .. } => Ok(ConnectionState::CapGiven),
                CapEnd | CapList { .. } | Pass { .. } | Ping { .. } => Ok(self),
                Nick { .. } => Ok(ConnectionState::Registered),
                Quit { .. } => Ok(ConnectionState::Quit),
                _ => Err(()),
            },
            ConnectionState::CapGiven => match request {
                CapEnd => Ok(ConnectionState::ConnectionEstablished),
                CapList { .. } | CapLs { .. } | CapReq { .. } | Pass { .. } | Ping { .. } => {
                    Ok(self)
                }
                Nick { .. } => Ok(ConnectionState::CapNickGiven),
                User { .. } => Ok(ConnectionState::CapUserGiven),
                Quit { .. } => Ok(ConnectionState::Quit),
                _ => Err(()),
            },
            ConnectionState::CapNickGiven => match request {
                CapEnd => Ok(ConnectionState::NickGiven),
                CapList { .. }
                | CapLs { .. }
                | CapReq { .. }
                | Nick { .. }
                | Pass { .. }
                | Ping { .. } => Ok(self),
                User { .. } => Ok(ConnectionState::CapNegotiation),
                Quit { .. } => Ok(ConnectionState::Quit),
                _ => Err(()),
            },
            ConnectionState::CapUserGiven => match request {
                CapEnd => Ok(ConnectionState::UserGiven),
                CapList { .. } | CapLs { .. } | CapReq { .. } | Pass { .. } | Ping { .. } => {
                    Ok(self)
                }
                Nick { .. } => Ok(ConnectionState::CapNegotiation),
                Quit { .. } => Ok(ConnectionState::Quit),
                _ => Err(()),
            },
            ConnectionState::CapNegotiation => match request {
                CapEnd => Ok(ConnectionState::Registered),
                CapList { .. }
                | CapLs { .. }
                | CapReq { .. }
                | Nick { .. }
                | Pass { .. }
                | Ping { .. } => Ok(self),
                Quit { .. } => Ok(ConnectionState::Quit),
                _ => Err(()),
            },
            ConnectionState::Registered => match request {
                Pass { .. } | User { .. } => Err(()),
                Quit { .. } => Ok(ConnectionState::Quit),
                _ => Ok(self),
            },
            ConnectionState::Quit => Err(()),
        }
    }

    pub fn is_registered(self) -> bool {
        self == ConnectionState::Registered
    }
}

const FULL_NAME_LENGTH: usize = 64;

/// Client data.
pub struct Client {
    /// The queue of messages to be sent to the client.
    ///
    /// This is the write end of a mpsc channel of messages (similar to go channels). It is
    /// currently unbounded, meaning sending messages to this channel does not block.
    queue: MessageQueue,

    pub domain: Arc<str>,

    pub cap_version: data::cap::Version,
    pub cap_enabled: data::Capabilities,
    state: ConnectionState,

    nick: String,
    user: String,
    real: String,
    host: String,
    account: Option<String>,

    /// The nick!user@host
    full_name: String,

    /// The time when the user has signed in
    signon_time: u64,

    /// The time of the last action
    last_action_time: u64,

    /// Whether the client has issued a PASS command with the right password.
    pub has_given_password: bool,

    // Modes: https://tools.ietf.org/html/rfc2812.html#section-3.1.5
    pub away_message: Option<String>,
    pub invisible: bool,
    pub operator: bool,
}

impl Client {
    /// Initialize the data for a new client, given its message queue.
    ///
    /// The nickname is set to "*", as it seems it's what freenode server does.  The username and
    /// the realname are set to empty strings.
    pub fn new(domain: Arc<str>, queue: MessageQueue, host: String) -> Self {
        let now = util::time();
        Self {
            queue,
            domain,
            full_name: String::with_capacity(FULL_NAME_LENGTH),
            cap_version: data::cap::Version::V300,
            cap_enabled: data::Capabilities::default(),
            state: ConnectionState::default(),
            nick: String::from("*"),
            user: String::new(),
            real: String::new(),
            host,
            account: None,
            signon_time: now,
            last_action_time: now,
            has_given_password: false,
            away_message: None,
            invisible: false,
            operator: false,
        }
    }

    /// Add a message to the client message queue.
    ///
    /// Use this function to send messages to the client.
    pub fn send(&self, msg: impl Into<MessageQueueItem>) {
        let mut msg = msg.into();
        if self.cap_enabled.has_message_tags() {
            msg.start = 0;
        }
        let _ = self.queue.send(msg);
    }

    pub fn reply(&self, label: &str) -> ReplyBuffer {
        ReplyBuffer::new(&self.domain, &self.nick, label)
    }

    pub fn state(&self) -> ConnectionState {
        self.state
    }

    /// Change the connection state of the client given the command it just sent.
    ///
    /// # Panics
    ///
    /// This function panics if the command cannot be issued in the client current state.
    /// `Client::can_issue_command` should be called before.
    pub fn apply_request(&mut self, request: &data::Request<'_>) -> ConnectionState {
        self.state = self.state.apply(request).unwrap();
        self.state
    }

    /// Whether or not the client can issue the given command.
    ///
    /// This function does not change the connection state.
    pub fn can_issue_request(&self, request: &data::Request<'_>) -> bool {
        self.state.apply(request).is_ok()
    }

    pub fn is_registered(&self) -> bool {
        self.state == ConnectionState::Registered
    }

    pub fn full_name(&self) -> &str {
        &self.full_name
    }

    fn update_full_name(&mut self) {
        self.full_name.clear();
        let _ = write!(self.full_name, "{}!~{}@{}", self.nick, self.user, self.host);
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

    /// The username of the client
    pub fn user(&self) -> &str {
        &self.user
    }

    /// Change the username of the client.
    pub fn set_user(&mut self, user: &str) {
        self.user.clear();
        self.user.push_str(user);
        self.update_full_name();
    }

    /// The realname of the client
    pub fn real(&self) -> &str {
        &self.real
    }

    /// Change the realname of the client.
    pub fn set_real(&mut self, real: &str) {
        self.real.clear();
        self.real.push_str(real);
    }

    /// The host of the client
    pub fn host(&self) -> &str {
        &self.host
    }

    pub fn account(&self) -> Option<&str> {
        self.account.as_ref().map(|s| s.as_ref())
    }

    pub fn signon_time(&self) -> u64 {
        self.signon_time
    }

    pub fn idle_time(&self) -> u64 {
        util::time() - self.last_action_time
    }

    pub fn update_idle_time(&mut self) {
        self.last_action_time = util::time();
    }

    pub fn away_message(&self) -> Option<&str> {
        self.away_message.as_ref().map(|s| s.as_ref())
    }

    pub fn write_modes(&self, mut out: MessageBuffer<'_>) {
        let modes = out.raw_param();
        modes.push('+');
        if self.away_message.is_some() {
            modes.push('a');
        }
        if self.invisible {
            modes.push('i');
        }
        if self.operator {
            modes.push('o');
        }
    }

    pub fn apply_mode_change(&mut self, change: mode::UserChange) -> bool {
        use mode::UserChange::*;
        let applied;
        match change {
            Invisible(value) => {
                applied = self.invisible != value;
                self.invisible = value;
            }
            DeOperator => {
                applied = self.operator;
                self.operator = false;
            }
        }
        applied
    }
}
