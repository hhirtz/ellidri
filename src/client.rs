//! Client data, connection state and capability logic.

use crate::util;
use ellidri_tokens::{Buffer, Command, MessageBuffer, mode, TagBuffer};
use std::cell::RefCell;
use std::sync::Arc;
use tokio::sync::mpsc;

#[derive(Clone, Debug)]
pub struct MessageQueueItem {
    pub start: usize,
    buf: Arc<String>,
}

impl From<Buffer> for MessageQueueItem {
    fn from(val: Buffer) -> Self {
        Self { start: 0, buf: Arc::new(val.build()) }
    }
}

impl AsRef<str> for MessageQueueItem {
    /// # Panics
    ///
    /// This function panics when `self.start` is greater than the content's length.
    fn as_ref(&self) -> &str {
        &self.buf[self.start..]
    }
}

impl AsRef<[u8]> for MessageQueueItem {
    /// # Panics
    ///
    /// This function panics when `self.start` is greater than the content's length.
    fn as_ref(&self) -> &[u8] {
        let s: &str = self.as_ref();
        s.as_bytes()
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

macro_rules! caps {
    ( $( $cap:ident $cap_str:literal $cap_member:ident )* |
      $( $specap:ident $specap_str:literal $specap_member:ident )*
    ) => {
        pub mod cap {
            use std::collections::HashSet;

            $( pub const $cap: &str = $cap_str; )*
            $( pub const $specap: &str = $specap_str; )*

            lazy_static::lazy_static! {
                pub static ref ALL: HashSet<&'static str> = [
                    $( $cap ),*, $( $specap ),*
                ].iter().cloned().collect();
            }

            const _LS_COMMON: &str = concat!( $( $cap_str, " " ),* );

            pub fn are_supported(capabilities: &str) -> bool {
                query(capabilities).all(|(cap,  _)| ALL.contains(cap))
            }

            pub fn ls_common() -> &'static str {
                &_LS_COMMON[.._LS_COMMON.len() - 1]
            }

            pub fn query(buf: &str) -> impl Iterator<Item=(&str, bool)> {
                buf.split_whitespace().map(|word| {
                    if word.starts_with('-') {
                        // NOPANIC  word starts with '-', which is encoded on 1 byte in UTF-8
                        (&word[1..], false)
                    } else {
                        (word, true)
                    }
                })
            }
        }

        #[derive(Clone, Default)]
        pub struct Capabilities {
            pub v302: bool,
            $( pub $cap_member: bool, )*
            $( pub $specap_member: bool, )*
        }

        impl Capabilities {
            pub fn update(&mut self, capabilities: &str) {
                for (capability, enable) in cap::query(capabilities) {
                    match capability {
                        $( cap::$cap => self.$cap_member = enable, )*
                        $( cap::$specap => self.$specap_member = enable, )*
                        _ => {}
                    }
                }
            }

            pub fn write_enabled(&self, mut msg: MessageBuffer<'_>) {
                msg = msg.param("LIST");
                let trailing = msg.raw_trailing_param();
                let len = trailing.len();
            $(
                if self.$cap_member {
                    trailing.push_str(cap::$cap);
                    trailing.push(' ');
                }
            )*
            $(
                if self.$specap_member {
                    trailing.push_str(cap::$specap);
                    trailing.push(' ');
                }
            )*
                if len < trailing.len() { trailing.pop(); }
            }
        }
    };
}

caps! {
    ACCOUNT_NOTIFY    "account-notify"     account_notify
    AWAY_NOTIFY       "away-notify"        away_notify
    BATCH             "batch"              batch
    CAP_NOTIFY        "cap-notify"         cap_notify
    ECHO_MESSAGE      "echo-message"       echo_message
    EXTENDED_JOIN     "extended-join"      extended_join
    INVITE_NOTIFY     "invite-notify"      invite_notify
    LABELED_RESPONSE  "labeled-response"   labeled_response
    MESSAGE_TAGS      "message-tags"       message_tags
    MULTI_PREFIX      "multi-prefix"       multi_prefix
    SERVER_TIME       "server-time"        server_time
    SETNAME           "setname"            setname
    USERHOST_IN_NAMES "userhost-in-names"  userhost_in_names
    |
    SASL "sasl" sasl
}

pub const AUTHENTICATE_CHUNK_LEN: usize = 400;
pub const AUTHENTICATE_WHOLE_LEN: usize = 1024;

impl Capabilities {
    pub fn has_labeled_response(&self) -> bool {
        self.batch && self.labeled_response
    }

    pub fn has_message_tags(&self) -> bool {
        self.message_tags || self.server_time
    }

    pub fn set_cap_version(&mut self, version: &str) {
        if version == "302" {
            self.v302 = true;
            self.cap_notify = true;
        }
    }

    /// Whether the given command can be issued with these capabilities.
    pub fn is_capable_of(&self, command: Command) -> bool {
        match command {
            Command::Authenticate => self.sasl,
            Command::SetName => self.setname,
            Command::TagMsg => self.message_tags,
            _ => true,
        }
    }
}

const FULL_NAME_LENGTH: usize = 63;

/// Client data.
pub struct Client {
    /// The queue of messages to be sent to the client.
    ///
    /// This is the write end of a mpsc channel of messages (similar to go channels). It is
    /// currently unbounded, meaning sending messages to this channel does not block.
    queue: MessageQueue,

    pub domain: Arc<str>,

    capabilities: Capabilities,
    state: ConnectionState,

    auth_buffer: String,
    auth_buffer_complete: bool,
    auth_id: Option<usize>,

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
    pub registered: bool,
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
            capabilities: Capabilities::default(),
            state: ConnectionState::default(),
            auth_buffer: String::new(),
            auth_buffer_complete: false,
            auth_id: None,
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
            registered: false,
            operator: false,
        }
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

    pub fn reply(&self, label: &str) -> ReplyBuffer {
        ReplyBuffer::new(self.queue.clone(), self.domain.clone(), &self.nick, label)
    }

    pub fn state(&self) -> ConnectionState {
        self.state
    }

    pub fn capabilities(&self) -> &Capabilities {
        &self.capabilities
    }

    pub fn set_cap_version(&mut self, version: &str) {
        self.capabilities.set_cap_version(version);
    }

    pub fn update_capabilities(&mut self, capabilities: &str) {
        self.capabilities.update(capabilities);
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

    pub fn account(&self) -> Option<&str> {
        self.account.as_ref().map(|s| s.as_ref())
    }

    pub fn log_in(&mut self, account: String) {
        self.account = Some(account);
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
        if self.away_message.is_some() { modes.push('a'); }
        if self.invisible { modes.push('i'); }
        if self.operator { modes.push('o'); }
    }

    pub fn apply_mode_change(&mut self, change: mode::UserChange) -> bool {
        use mode::UserChange::*;
        let applied;
        match change {
            Invisible(value) => {
                applied = self.invisible != value;
                self.invisible = value;
            },
            DeOperator => {
                applied = self.operator;
                self.operator = false;
            }
        }
        applied
    }
}

thread_local! {
    static LABEL: RefCell<String> = RefCell::new(String::new());
    static NICK: RefCell<String> = RefCell::new(String::new());
}

pub struct ReplyBuffer {
    queue: MessageQueue,
    domain: Arc<str>,
    batch: Option<u8>,
    label_len: usize,
}

impl ReplyBuffer {
    fn new(queue: MessageQueue, domain: Arc<str>, nick: &str, label: &str) -> Self {
        Self::set_nick(nick);
        Self::set_label(label);
        Self {
            queue,
            domain,
            batch: None,
            label_len: label.len(),
        }
    }

    pub fn set_nick(nick: &str) {
        NICK.with(|s| {
            let mut s = s.borrow_mut();
            s.clear();
            s.push_str(nick);
        });
    }

    fn set_label(label: &str) {
        LABEL.with(|s| {
            let mut s = s.borrow_mut();
            s.clear();
            s.push_str(label);
        });
    }

    pub fn start_batch(&mut self, name: &str) {
        use std::fmt::Write;

        let new_batch = self.new_batch();
        let mut buf = Buffer::with_capacity(self.label_len + name.len() + 24);
        {
            let mut msg = buf.tagged_message("");
            if self.label_len != 0 {
                msg = LABEL.with(|s| msg.tag("label", Some(&s.borrow())));
            }
            let mut msg = msg.prefixed_command(&self.domain, "BATCH");
            let _ = write!(msg.raw_param(), "+{}", new_batch);
            msg.param("labeled-response");
        }
        let _ = self.queue.send(buf.into());
    }

    pub fn start_lr_batch(&mut self) {
        if self.label_len == 0 {
            return;
        }
        self.start_batch("labeled-response");
        self.label_len = 0;
    }

    pub fn end_batch(&mut self) {
        use std::fmt::Write;

        let old_batch = self.batch.unwrap();
        self.batch = if old_batch == 0 {None} else {Some(old_batch - 1)};

        let mut buf = Buffer::with_capacity(16);
        {
            let mut msg = buf.message("", "BATCH");
            let _ = write!(msg.raw_param(), "-{}", old_batch);
        }
        let _ = self.queue.send(buf.into());
    }

    pub fn end_lr(&mut self) {
        if self.label_len != 0 {
            // This isn't a batch response, and we've sent nothing with the label, so ACK
            let mut buf = Buffer::with_capacity(self.label_len + 16);
            LABEL.with(|s| {
                buf.tagged_message("")
                    .tag("label", Some(&s.borrow()))
                    .prefixed_command(&self.domain, "ACK");
            });
            self.label_len = 0;
            let _ = self.queue.send(buf.into());
        } else if self.batch.is_some() {
            // This is a labeled-response batch, end it.
            self.end_batch();
        }
    }

    pub fn reply<C, F>(&mut self, command: C, capacity: usize, map: F)
        where C: Into<Command>,
              F: FnOnce(MessageBuffer<'_>),
    {
        NICK.with(|s| self.prefixed_message(command, capacity, |msg| {
            map(msg.param(&s.borrow()));
        }));
    }

    pub fn prefixed_message<C, F>(&mut self, command: C, capacity: usize, map: F)
        where C: Into<Command>,
              F: FnOnce(MessageBuffer<'_>),
    {
        send_message(&self.queue, &mut self.label_len, self.batch, &self.domain, command, capacity, map);
    }

    pub fn message<C, F>(&mut self, prefix: &str, command: C, capacity: usize, map: F)
        where C: Into<Command>,
              F: FnOnce(MessageBuffer<'_>),
    {
        send_message(&self.queue, &mut self.label_len, self.batch, prefix, command, capacity, map);
    }

    pub fn tagged_message<F>(&mut self, client_tags: &str, capacity: usize, map: F)
        where F: FnOnce(TagBuffer<'_>),
    {
        send_tagged_message(&self.queue, &mut self.label_len, self.batch, client_tags, capacity, map);
    }

    pub fn send_auth_buffer<T>(&mut self, buf: T)
        where T: AsRef<[u8]>,
    {
        if buf.as_ref().is_empty() {
            self.message("", Command::Authenticate,0, |msg| {
                msg.param("+");
            });
            return;
        }

        let encoded = base64::encode(buf);
        let mut i = 0;
        while i < encoded.len() {
            let max = encoded.len().min(i + AUTHENTICATE_CHUNK_LEN);
            // NOPANIC
            // i < encoded.len() && (max == encoded.len() || max == i + x), x > 0  ==>  i < max
            // max <= encoded.len()
            let chunk = &encoded[i..max];
            self.message("", Command::Authenticate,0, |msg| {
                msg.param(chunk);
            });
            i = max;
        }
        if i % AUTHENTICATE_CHUNK_LEN == 0 {
            self.message("", Command::Authenticate,0, |msg| {
                msg.param("+");
            });
        }
    }

    fn new_batch(&mut self) -> u8 {
        let new_batch = self.batch.map_or(0, |old_batch| old_batch + 1);
        self.batch = Some(new_batch);
        new_batch
    }
}
fn send_message<C, F>(queue: &MessageQueue, label_len: &mut usize, batch: Option<u8>,
                      prefix: &str, command: C, capacity: usize, map: F)
    where C: Into<Command>,
          F: FnOnce(MessageBuffer<'_>),
{
    send_tagged_message(queue, label_len, batch, "", capacity, |msg| {
        map(msg.prefixed_command(prefix, command))
    })
}

fn send_tagged_message<F>(queue: &MessageQueue, label_len: &mut usize, batch: Option<u8>,
                          client_tags: &str, capacity: usize, map: F)
    where F: FnOnce(TagBuffer<'_>),
{
    let capacity = 0.min(*label_len + capacity);
    let mut buf = Buffer::with_capacity(capacity);
    {
        let mut msg = buf.tagged_message(client_tags);
        if *label_len != 0 {
            msg = LABEL.with(|s| msg.tag("label", Some(&s.borrow())));
            *label_len = 0;
        }
        if let Some(batch) = batch {
            msg = msg.tag("batch", Some(batch));
        }
        if cfg!(debug_assertions) {
            map(msg);
            let len = buf.len();
            if capacity < len {
                log::debug!("Reallocated message (from cap {} to len {}):\n{:?}",
                                capacity, len, buf.get());
            } else if len < capacity / 2 {
                log::debug!("Buffer used less than half of its capacity ({}, used {}):\n{:?}",
                                capacity, len, buf.get());
            }
        } else {
            map(msg);
        };
    }
    let _ = queue.send(buf.into());
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
