//! Client management and connection state.

use crate::message::{Command, MessageBuffer, Reply, rpl, ResponseBuffer};
use crate::modes;
use futures::sync::mpsc;
use std::sync::Arc;

const FULL_NAME_LENGTH: usize = 63;

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

/// Client data.
pub struct Client {
    /// The queue of messages to be sent to the client.
    ///
    /// This is the write end of a mpsc channel of messages (similar to go channels). It is
    /// currently unbounded, meaning sending messages to this channel do not block.
    queue: MessageQueue,

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

    /// Change the connection state of the client given the command it just sent.
    ///
    /// # Panics
    ///
    /// This function panics if the command cannot be issued in the client current state.
    /// `Client::can_issue_command` should be called before.
    pub fn apply_command(&mut self, cmd: Command) -> ConnectionState {
        self.state = self.state.apply(cmd).unwrap();
        self.state
    }

    /// Whether or not the client can issue the given command.
    ///
    /// This function does not change the connection state.
    pub fn can_issue_command(&self, cmd: Command) -> bool {
        self.state.apply(cmd).is_ok()
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

    pub fn modes(&self, mut out: MessageBuffer<'_>) {
        let modes = out.raw_param();
        modes.push('+');
        if self.away { modes.push('a'); }
        if self.invisible { modes.push('i'); }
        if self.operator { modes.push('o'); }
        out.build();
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

/// A state machine that represent the connection with a client. It keeps track of what message the
/// client can send.
///
/// For example, a client that has only sent a "NICK" message cannot send a "JOIN" message.
#[derive(Clone, Copy, Debug, PartialEq)]
pub enum ConnectionState {
    ConnectionEstablished,
    NickGiven,
    UserGiven,
    Registered,
    Quit,
}

impl Default for ConnectionState {
    fn default() -> ConnectionState {
        ConnectionState::ConnectionEstablished
    }
}

impl ConnectionState {
    pub fn apply(self, cmd: Command) -> Result<ConnectionState, Reply> {
        match cmd {
            Command::Nick => match self {
                ConnectionState::ConnectionEstablished => Ok(ConnectionState::NickGiven),
                ConnectionState::UserGiven => Ok(ConnectionState::Registered),
                ConnectionState::Quit => Err(""),
                _ => Ok(self),
            }
            Command::User => match self {
                ConnectionState::ConnectionEstablished => Ok(ConnectionState::UserGiven),
                ConnectionState::NickGiven => Ok(ConnectionState::Registered),
                _ => Err(rpl::ERR_ALREADYREGISTRED),
            }
            Command::Quit => match self {
                ConnectionState::Quit => Err(""),
                _ => Ok(ConnectionState::Quit),
            }
            _ => match self {
                ConnectionState::Registered => Ok(self),
                ConnectionState::Quit => Err(""),
                _ => Err(rpl::ERR_NOTREGISTERED),
            }
        }
    }

    pub fn is_registered(self) -> bool {
        self == ConnectionState::Registered
    }
}
