//! Client management and connection state.

use crate::message::{Command, Message, Reply, rpl};
use crate::state::MessageQueue;

pub const USER_MODES: &[u8] = b"aiwros";
pub const SETTABLE_USER_MODES: &[u8] = b"iws";

const FULL_NAME_LENGTH: usize = 63;

/// Client data.
pub struct Client {
    /// The queue of messages to be sent to the client.
    ///
    /// This is the write end of a mpsc channel of messages (similar to go channels). It is
    /// currently unbounded, meaning sending messages to this channel do not block.
    queue: MessageQueue,

    /// The state of the connection with the client.
    ///
    /// This keeps track of whether the client has registered or not, if it's currently querying
    /// capabilities, etc.
    state: ConnectionState,

    /// The nickname.
    nick: String,

    /// The username.
    user: String,

    /// The real name.
    real: String,

    /// The client hostname.
    host: String,

    /// The nick!user@host
    full_name: String,

    /// The reason sent when a client quits.
    ///
    /// Set when it issues a "QUIT" message.
    quit_message: Option<String>,

    // Modes: https://tools.ietf.org/html/rfc2812.html#section-3.1.5
    pub away: bool,
    pub invisible: bool,
    pub wallops: bool,
    pub restricted: bool,
    pub operator: bool,
    pub server_notices: bool,
}

impl Client {
    /// Initialize the data for a new client, given its message queue.
    ///
    /// The nickname is set to "*", as it seems it's what freenode server does.  The username and
    /// the realname are set to empty strings.
    pub fn new(queue: MessageQueue, host: String) -> Client {
        let mut full_name = String::with_capacity(FULL_NAME_LENGTH);
        full_name.push('*');
        full_name.push_str(&host);
        Client {
            queue,
            state: ConnectionState::default(),
            nick: String::from("*"),
            user: String::new(),
            real: String::new(),
            host,
            full_name,
            quit_message: None,
            away: false,
            invisible: false,
            wallops: false,
            restricted: false,
            operator: false,
            server_notices: false,
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

    /// The client quit message, or a default one if it has not set any.
    pub fn quit_message(&self) -> &str {
        self.quit_message.as_ref().map_or("Left without saying anything...", String::as_str)
    }

    /// Sets the client quit message (or reason).
    pub fn set_quit_message(&mut self, reason: Option<&str>) {
        self.quit_message = reason.map(str::to_owned)
    }

    /// Add a message to the client message queue.
    ///
    /// Use this function to send messages to the client.
    pub fn send(&self, msg: Message<'static>) {
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

    pub fn modes(&self) -> String {
        let mut modes = String::with_capacity(USER_MODES.len());
        if self.away { modes.push('a'); }
        if self.invisible { modes.push('i'); }
        if self.wallops { modes.push('w'); }
        if self.restricted { modes.push('r'); }
        if self.operator { modes.push('o'); }
        if self.server_notices { modes.push('s'); }
        modes
    }

    pub fn set_mode(&mut self, mode: u8, value: bool) {
        match mode {
            b'i' => { self.invisible = value; },
            b'w' => { self.wallops = value; },
            b's' => { self.server_notices = value; },
            _ => {},
        }
    }
}

/// A state machine that represent the connection with a client. It keeps track of what message the
/// client can send.
///
/// For example, a client that has sent a "NICK" message only cannot send a "JOIN" message.
#[derive(Clone, Copy, Debug, PartialEq)]
pub enum ConnectionState {
    /// The client just connected to the server, and must register. Its registration is kept track
    /// of by `RegistrationState`.
    ConnectionEstablished(RegistrationState),

    //CapabilityNegociation(RegistrationState),

    /// The client is registered, and can send any command except "USER".
    Registered,
}

impl Default for ConnectionState {
    /// The connection state of a client that has just connected to the server.
    fn default() -> ConnectionState {
        ConnectionState::ConnectionEstablished(RegistrationState::Stranger)
    }
}

impl ConnectionState {
    /// Given a connection state and a command, returns the next connection state after a client
    /// has sent the command, or a reply code to send the client if this command cannot be issued.
    ///
    /// # Example
    ///
    /// ```rust
    /// use ellidri::client::{ConnectionState, RegistrationState};
    /// use ellidri::message::{Command, rpl};
    ///
    /// let state = ConnectionState::ConnectionEstablished(RegistrationState::NickGiven);
    /// assert_eq!(state.apply(Command::User), Ok(ConnectionState::Registered));
    ///
    /// let state = ConnectionState::Registered;
    /// assert_eq!(state.apply(Command::User), Err(rpl::ERR_ALREADYREGISTRED));
    /// ```
    pub fn apply(self, cmd: Command) -> Result<ConnectionState, Reply> {
        match self {
            ConnectionState::ConnectionEstablished(reg) => {
                let reg = reg.apply(cmd)?;
                if reg.is_registered() {
                    Ok(ConnectionState::Registered)
                } else {
                    Ok(ConnectionState::ConnectionEstablished(reg))
                }
            },
            ConnectionState::Registered => match cmd {
                Command::User => Err(rpl::ERR_ALREADYREGISTRED),
                _ => Ok(ConnectionState::Registered),
            },
        }
    }

    /// True iff self == ConnectionState::Registered.
    pub fn is_registered(self) -> bool {
        match self {
            ConnectionState::Registered => true,
            _ => false,
        }
    }
}

/// A state machine that represents a registration (process of sending "NICK" and "USER").
#[derive(Clone, Copy, Debug, PartialEq)]
pub enum RegistrationState {
    /// The client hasn't began the registration.
    Stranger,

    /// The client has sent one or more "NICK", but has not sent any "USER".
    NickGiven,

    /// The client has sent a "USER", but has not sent any "NICK".
    UserGiven,

    /// The client has sent a "USER" and a "NICK", and completed its registration.
    Registered,
}

impl RegistrationState {
    /// Given a registration state and a command, returns the next registration state after the
    /// client has sent the command, or a reply code if the command cannot be sent.
    pub fn apply(self, cmd: Command) -> Result<Self, Reply> {
        match cmd {
            Command::Nick => self.apply_nick(),
            Command::User => self.apply_user(),
            _ => Err(rpl::ERR_NOTREGISTERED),
        }
    }

    /// True iff self == RegistrationState::Registered.
    pub fn is_registered(self) -> bool {
        match self {
            RegistrationState::Registered => true,
            _ => false,
        }
    }

    /// Apply a "NICK" message.
    fn apply_nick(self) -> Result<Self, Reply> {
        match self {
            RegistrationState::Stranger |
            RegistrationState::NickGiven => Ok(RegistrationState::NickGiven),
            RegistrationState::UserGiven |
            RegistrationState::Registered => Ok(RegistrationState::Registered),
        }
    }

    /// Apply a "USER" message.
    fn apply_user(self) -> Result<Self, Reply> {
        match self {
            RegistrationState::Stranger => Ok(RegistrationState::UserGiven),
            RegistrationState::NickGiven => Ok(RegistrationState::Registered),
            _ => Err(rpl::ERR_ALREADYREGISTRED),
        }
    }
}
