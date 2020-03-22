//! Client data, connection state and capability logic.

use crate::message::{Buffer, Command, MessageBuffer, ReplyBuffer};
use crate::modes;
use crate::util::time;
use std::sync::Arc;
use tokio::sync::mpsc;

#[derive(Clone, Debug)]
pub struct MessageQueueItem {
    pub start: usize,
    buf: Arc<str>,
}

impl From<String> for MessageQueueItem {
    fn from(bytes: String) -> Self {
        Self { start: 0, buf: Arc::from(bytes) }
    }
}

impl From<Buffer> for MessageQueueItem {
    fn from(response: Buffer) -> Self {
        Self { start: 0, buf: Arc::from(response.build()) }
    }
}

impl From<ReplyBuffer> for MessageQueueItem {
    fn from(response: ReplyBuffer) -> Self {
        Self { start: 0, buf: Arc::from(response.build()) }
    }
}

impl AsRef<str> for MessageQueueItem {
    fn as_ref(&self) -> &str {
        &self.buf.as_ref()[self.start..]
    }
}

impl AsRef<[u8]> for MessageQueueItem {
    fn as_ref(&self) -> &[u8] {
        self.buf.as_ref()[self.start..].as_bytes()
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
    pub fn apply(self, command: Command, sub_command: &str) -> Result<ConnectionState, ()> {
        match self {
            ConnectionState::ConnectionEstablished => match command {
                Command::Cap if sub_command == "LS" => Ok(ConnectionState::CapGiven),
                Command::Cap if sub_command == "REQ" => Ok(ConnectionState::CapGiven),
                Command::Authenticate | Command::Cap | Command::Pass => Ok(self),
                Command::Nick => Ok(ConnectionState::NickGiven),
                Command::User => Ok(ConnectionState::UserGiven),
                Command::Quit => Ok(ConnectionState::Quit),
                _ => Err(()),
            }
            ConnectionState::NickGiven => match command {
                Command::Cap if sub_command == "LS" => Ok(ConnectionState::CapNickGiven),
                Command::Cap if sub_command == "REQ" => Ok(ConnectionState::CapNickGiven),
                Command::Authenticate | Command::Cap | Command::Nick | Command::Pass => Ok(self),
                Command::User => Ok(ConnectionState::Registered),
                Command::Quit => Ok(ConnectionState::Quit),
                _ => Err(()),
            }
            ConnectionState::UserGiven => match command {
                Command::Cap if sub_command == "LS" => Ok(ConnectionState::CapUserGiven),
                Command::Cap if sub_command == "REQ" => Ok(ConnectionState::CapUserGiven),
                Command::Authenticate | Command::Cap | Command::Pass => Ok(self),
                Command::Nick => Ok(ConnectionState::Registered),
                Command::Quit => Ok(ConnectionState::Quit),
                _ => Err(()),
            }
            ConnectionState::CapGiven => match command {
                Command::Cap if sub_command == "END" => Ok(ConnectionState::ConnectionEstablished),
                Command::Authenticate | Command::Cap | Command::Pass => Ok(self),
                Command::Nick => Ok(ConnectionState::CapNickGiven),
                Command::User => Ok(ConnectionState::CapUserGiven),
                Command::Quit => Ok(ConnectionState::Quit),
                _ => Err(()),
            }
            ConnectionState::CapNickGiven => match command {
                Command::Cap if sub_command == "END" => Ok(ConnectionState::NickGiven),
                Command::Authenticate | Command::Cap | Command::Pass | Command::Nick => Ok(self),
                Command::User => Ok(ConnectionState::CapNegotiation),
                Command::Quit => Ok(ConnectionState::Quit),
                _ => Err(()),
            }
            ConnectionState::CapUserGiven => match command {
                Command::Cap if sub_command == "END" => Ok(ConnectionState::UserGiven),
                Command::Authenticate | Command::Cap | Command::Pass => Ok(self),
                Command::Nick => Ok(ConnectionState::CapNegotiation),
                Command::Quit => Ok(ConnectionState::Quit),
                _ => Err(()),
            }
            ConnectionState::CapNegotiation => match command {
                Command::Cap if sub_command == "END" => Ok(ConnectionState::Registered),
                Command::Authenticate | Command::Cap | Command::Pass | Command::Nick => Ok(self),
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

// TODO factorize this with a macro?
pub mod cap {
    use std::collections::HashSet;

    pub const CAP_NOTIFY: &str    = "cap-notify";
    pub const ECHO_MESSAGE: &str  = "echo-message";
    pub const EXTENDED_JOIN: &str = "extended-join";
    pub const INVITE_NOTIFY: &str = "invite-notify";
    pub const MESSAGE_TAGS: &str  = "message-tags";
    pub const MULTI_PREFIX: &str  = "multi-prefix";
    pub const SASL: &str          = "sasl";
    pub const SERVER_TIME: &str   = "server-time";
    pub const SETNAME: &str       = "setname";
    pub const USERHOST_IN_NAMES: &str = "userhost-in-names";

    // TODO replace with const fn
    lazy_static::lazy_static! {
        pub static ref ALL: HashSet<&'static str> =
            [ CAP_NOTIFY
            , ECHO_MESSAGE
            , EXTENDED_JOIN
            , INVITE_NOTIFY
            , MULTI_PREFIX
            , MESSAGE_TAGS
            , SASL
            , SERVER_TIME
            , SETNAME
            , USERHOST_IN_NAMES
            ].iter().cloned().collect();
    }

    pub const LS_COMMON: &str =
"cap-notify echo-message extended-join invite-notify message-tags multi-prefix server-time setname \
userhost-in-names";

    pub fn are_supported(capabilities: &str) -> bool {
        query(capabilities).all(|(cap,  _)| ALL.contains(cap))
    }

    pub fn query(buf: &str) -> impl Iterator<Item=(&str, bool)> {
        buf.split_whitespace().map(|word| {
            if word.starts_with('-') {
                (&word[1..], false)
            } else {
                (word, true)
            }
        })
    }
}

pub const AUTHENTICATE_CHUNK_LEN: usize = 400;
pub const AUTHENTICATE_WHOLE_LEN: usize = 1024;

#[derive(Clone, Default)]
pub struct Capabilities {
    pub v302: bool,
    pub cap_notify: bool,
    pub echo_message: bool,
    pub extended_join: bool,
    pub invite_notify: bool,
    pub message_tags: bool,
    pub multi_prefix: bool,
    pub sasl: bool,
    pub server_time: bool,
    pub setname: bool,
    pub userhost_in_names: bool,
}

impl Capabilities {
    pub fn has_message_tags(&self) -> bool {
        self.message_tags || self.server_time
    }
}

const FULL_NAME_LENGTH: usize = 63;

/// Client data.
pub struct Client {
    /// The queue of messages to be sent to the client.
    ///
    /// This is the write end of a mpsc channel of messages (similar to go channels). It is
    /// currently unbounded, meaning sending messages to this channel do not block.
    queue: MessageQueue,

    pub capabilities: Capabilities,
    state: ConnectionState,
    auth_buffer: String,
    auth_buffer_complete: bool,
    auth_id: Option<usize>,

    nick: String,
    user: String,
    real: String,
    host: String,
    identity: Option<String>,

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
    pub registered: bool,
    pub operator: bool,
}

impl Client {
    /// Initialize the data for a new client, given its message queue.
    ///
    /// The nickname is set to "*", as it seems it's what freenode server does.  The username and
    /// the realname are set to empty strings.
    pub fn new(queue: MessageQueue, host: String) -> Self {
        let now = time();
        Self {
            queue,
            full_name: String::with_capacity(FULL_NAME_LENGTH),
            capabilities: Capabilities::default(),
            state: ConnectionState::default(),
            auth_buffer: String::new(),
            auth_buffer_complete: false,
            auth_id: None,
            nick: String::from("*"),
            user: String::new(),
            real: String::new(),
            host,
            identity: None,
            signon_time: now,
            last_action_time: now,
            has_given_password: false,
            away_message: None,
            invisible: false,
            registered: false,
            operator: false,
        }
    }

    pub fn state(&self) -> ConnectionState {
        self.state
    }

    // TODO factorize this with a macro?
    pub fn update_capabilities(&mut self, capabilities: &str) {
        for (capability, enable) in cap::query(capabilities) {
            match capability {
                cap::CAP_NOTIFY => self.capabilities.cap_notify = enable,
                cap::ECHO_MESSAGE => self.capabilities.echo_message = enable,
                cap::EXTENDED_JOIN => self.capabilities.extended_join = enable,
                cap::INVITE_NOTIFY => self.capabilities.invite_notify = enable,
                cap::MESSAGE_TAGS => self.capabilities.message_tags = enable,
                cap::MULTI_PREFIX => self.capabilities.multi_prefix = enable,
                cap::SASL => self.capabilities.sasl = enable,
                cap::SERVER_TIME => self.capabilities.server_time = enable,
                cap::SETNAME => self.capabilities.setname = enable,
                cap::USERHOST_IN_NAMES => self.capabilities.userhost_in_names = enable,
                _ => {}
            }
        }
    }

    pub fn set_cap_version(&mut self, version: &str) {
        if version == "302" {
            self.capabilities.v302 = true;
            self.capabilities.cap_notify = true;
        }
    }

    // TODO factorize this with a macro?
    pub fn write_enabled_capabilities(&self, response: &mut ReplyBuffer) {
        let mut msg = response.reply(Command::Cap).param("LIST");
        let trailing = msg.raw_trailing_param();
        let len = trailing.len();
        if self.capabilities.cap_notify {
            trailing.push_str(cap::CAP_NOTIFY);
            trailing.push(' ');
        }
        if self.capabilities.echo_message {
            trailing.push_str(cap::ECHO_MESSAGE);
            trailing.push(' ');
        }
        if self.capabilities.extended_join {
            trailing.push_str(cap::EXTENDED_JOIN);
            trailing.push(' ');
        }
        if self.capabilities.invite_notify {
            trailing.push_str(cap::INVITE_NOTIFY);
            trailing.push(' ');
        }
        if self.capabilities.message_tags {
            trailing.push_str(cap::MESSAGE_TAGS);
            trailing.push(' ');
        }
        if self.capabilities.multi_prefix {
            trailing.push_str(cap::MULTI_PREFIX);
            trailing.push(' ');
        }
        if self.capabilities.sasl {
            trailing.push_str(cap::SASL);
            trailing.push(' ');
        }
        if self.capabilities.server_time {
            trailing.push_str(cap::SERVER_TIME);
            trailing.push(' ');
        }
        if self.capabilities.setname {
            trailing.push_str(cap::SETNAME);
            trailing.push(' ');
        }
        if self.capabilities.userhost_in_names {
            trailing.push_str(cap::USERHOST_IN_NAMES);
            trailing.push(' ');
        }
        if len < trailing.len() {
            trailing.pop();
        }
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

    /// Whether the client has negociated the capability necessary to issue the given command.
    pub fn is_capable_of(&self, command: Command) -> bool {
        match command {
            Command::Authenticate => self.capabilities.sasl,
            Command::SetName => self.capabilities.setname,
            Command::TagMsg => self.capabilities.has_message_tags(),
            _ => true,
        }
    }

    pub fn is_registered(&self) -> bool {
        self.state == ConnectionState::Registered
    }

    pub fn auth_id(&self) -> Option<usize> {
        self.auth_id
    }

    pub fn auth_set_id(&mut self, auth_id: usize) {
        self.auth_id = Some(auth_id);
    }

    pub fn auth_buffer_push(&mut self, buf: &str) -> Result<bool, ()> {
        if self.auth_buffer_complete {
            self.auth_buffer_complete = false;
            self.auth_buffer.clear();
        }
        if AUTHENTICATE_CHUNK_LEN < buf.len() ||
            AUTHENTICATE_WHOLE_LEN < self.auth_buffer.len() + buf.len()
        {
            return Err(());
        }
        if buf != "+" {
            self.auth_buffer.push_str(buf);
        }
        self.auth_buffer_complete = buf.len() < AUTHENTICATE_CHUNK_LEN;
        Ok(self.auth_buffer_complete)
    }

    pub fn auth_buffer_decode(&self) -> Result<Vec<u8>, base64::DecodeError> {
        if !self.auth_buffer_complete {
            return Err(base64::DecodeError::InvalidLength);
        }
        base64::decode(&self.auth_buffer)
    }

    /// Free authentication-related buffers.
    pub fn auth_reset(&mut self) {
        self.auth_buffer = String::new();
        self.auth_buffer_complete = false;
        self.auth_id = None;
    }

    /// Add a message to the client message queue.
    ///
    /// Use this function to send messages to the client.
    pub fn send<M>(&self, msg: M)
        where M: Into<MessageQueueItem>
    {
        let mut msg = msg.into();
        if self.capabilities.has_message_tags() {
            msg.start = 0;
        }
        let _ = self.queue.send(msg);
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

    pub fn identity(&self) -> Option<&str> {
        self.identity.as_ref().map(|s| s.as_ref())
    }

    pub fn log_in(&mut self, identity: String) {
        self.identity = Some(identity);
    }

    pub fn signon_time(&self) -> u64 {
        self.signon_time
    }

    pub fn idle_time(&self) -> u64 {
        time() - self.last_action_time
    }

    pub fn update_idle_time(&mut self) {
        self.last_action_time = time();
    }

    pub fn away_message(&self) -> Option<&str> {
        self.away_message.as_ref().map(|s| s.as_ref())
    }

    pub fn set_away(&mut self, reason: &str) {
        self.away_message = Some(reason.to_owned());
    }

    pub fn reset_away(&mut self) {
        self.away_message = None;
    }

    pub fn write_modes(&self, mut out: MessageBuffer<'_>) {
        let modes = out.raw_param();
        modes.push('+');
        if self.away_message.is_some() { modes.push('a'); }
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_connection_state_apply() {
        use Command::*;

        let def = ConnectionState::default();

        let normal = def
            .apply(Nick, "").unwrap()
            .apply(User, "").unwrap();
        assert_eq!(normal, ConnectionState::Registered);

        let with_password = def
            .apply(Pass, "").unwrap()
            .apply(Nick, "").unwrap()
            .apply(User, "").unwrap();
        assert_eq!(with_password, ConnectionState::Registered);

        let choosing_caps = def
            .apply(Cap, "LS").unwrap()
            .apply(Nick, "").unwrap()
            .apply(User, "").unwrap();
        assert_eq!(choosing_caps, ConnectionState::CapNegotiation);

        let requested_caps = def
            .apply(Nick, "").unwrap()
            .apply(Cap, "REQ").unwrap()
            .apply(User, "").unwrap()
            .apply(Cap, "END").unwrap();
        assert_eq!(requested_caps, ConnectionState::Registered);

        let spurious_commands = def
            .apply(Nick, "").unwrap()
            .apply(Cap, "LIST").unwrap()
            .apply(Quit, "").unwrap()
            .apply(Nick, "");
        assert_eq!(spurious_commands, Err(()));
    }
}  // mod tests
