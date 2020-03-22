//! Shared state and API to handle incoming commands.
//!
//! This module is split in several files:
//!
//! - `mod.rs`: public API of the server state and send utilities
//! - `rfc2812.rs` : handlers for messages defined in the RFC 2812
//! - `capabilities.rs` : handlers for the CAP command
//! - `message_tags.rs` : handler for the TAGMSG command

#![allow(clippy::needless_pass_by_value)]

use crate::{auth, config, lines};
use crate::channel::Channel;
use crate::client::{Client, MessageQueue, MessageQueueItem};
use crate::message::{Buffer, Command, Message, ReplyBuffer, rpl};
use crate::modes;
use crate::util::time_str;
use ellidri_unicase::{u, UniCase};
use slab::Slab;
use std::{cmp, fs, io, net};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::Mutex;

mod capabilities;
mod message_tags;
mod rfc2812;
mod sasl;
mod setname;
#[cfg(test)]
mod test;

#[macro_export]
macro_rules! server_version(() => {concat!(env!("CARGO_PKG_NAME"), "-", env!("CARGO_PKG_VERSION"))});

/// Information about ellidri from an IRC client perspective.
///
/// Sent to client with the INFO command.
const SERVER_INFO: &str = include_str!("info.txt");

const MAX_TAG_DATA_LENGTH: usize = 4094;

type ChannelMap = HashMap<UniCase<String>, Channel>;
type ClientMap = Slab<Client>;
type NicksMap = HashMap<UniCase<String>, usize>;
type HandlerResult = Result<(), ()>;

pub struct CommandContext<'a> {
    id: usize,
    rb: &'a mut ReplyBuffer,
    client_tags: &'a str,
}

/// State of an IRC network.
///
/// This is used by ellidri to maintain a consistent state of the network.  Note that this is just
/// an `Arc` to the real data, so it's cheap to clone and clones share the same data.
///
/// At the time of writing, this only support the client-to-server API, so the network can only
/// consist of one server.  Maybe in the long term it will support incoming messages from other
/// servers.
///
/// The API is designed with `async` support only, because this type heavily relies on [tokio][1].
///
/// [1]: https://tokio.rs
///
/// # Example
///
/// ```rust
/// # use ellidri::State;
/// # use ellidri::{auth, config};
/// # use ellidri::message::Message;
/// # tokio::runtime::Runtime::new().unwrap().block_on(async {
/// // Initialize a `StateConfig` and create the state.
/// let sasl_backend = auth::choose_provider(config::SaslBackend::None, None).unwrap();
/// let state = State::new(config::State {
///     domain: "ellidri.dev".to_owned(),
///     ..config::State::sample()
/// }, sasl_backend);
///
/// // The IP address of the client, to build the host string.
/// let client_addr = std::net::SocketAddr::from(([127, 0, 0, 1], 12345));
///
/// // The state uses a MPSC queue and pushes the messages meant to be sent
/// // to the client onto the queue.
/// let (msg_queue, mut outgoing_msgs) = tokio::sync::mpsc::unbounded_channel();
///
/// // Each client is identified by an integer.
/// let client_id = state.peer_joined(client_addr, msg_queue).await;
///
/// // `handle_message` is used to pass messages from the client to the state.
/// let nick = Message::parse("NICK ser\r\n").unwrap();
/// let user = Message::parse("USER ser 0 * :ser\r\n").unwrap();
/// state.handle_message(client_id, nick).await;
/// state.handle_message(client_id, user).await;
///
/// // The user has registered, so the state should have pushed
/// // the welcome message, the motd, etc. onto the queue.
/// // It is safe to unwrap here while the peer is saved in the state.
/// let msg = outgoing_msgs.recv().await.unwrap();
///
/// // Outgoing messages implement `AsRef<[u8]>`, so they can be used with `std::io::Write`.
/// // They also implement `AsRef<str>` because they are UTF-8 encoded.
/// // Note that one call to `recv` can contain multiple IRC messages.
/// let msg: &str = msg.as_ref();
/// let mut lines = msg.split("\r\n");
///
/// // The first IRC message from the server is RPL_WELCOME.
/// assert_eq!(lines.next().unwrap(),
///            ":ellidri.dev 001 ser :Welcome home, ser!ser@127.0.0.1");
/// # });
/// ```
#[derive(Clone)]
pub struct State(Arc<Mutex<StateInner>>);

impl State {
    /// Intialize the IRC state from the given configuration.
    pub fn new(config: config::State, auth_provider: Box<dyn auth::Provider>) -> Self {
        let inner = StateInner::new(config, auth_provider);
        Self(Arc::new(Mutex::new(inner)))
    }

    pub async fn login_timeout(&self) -> u64 {
        self.0.lock().await.login_timeout
    }

    /// Adds a new connection to the state.
    ///
    /// Each connection is identified by its address.  The queue is used to push messages back to
    /// the peer.
    pub async fn peer_joined(&self, addr: net::SocketAddr, queue: MessageQueue) -> usize {
        self.0.lock().await.peer_joined(addr, queue)
    }

    /// Removes the given connection from the state, with an optional error.
    ///
    /// If the peer has quit unexpctedly, `err` should be set to `Some` and reflect the cause of
    /// the quit, so that other peers can be correctly informed.
    pub async fn peer_quit(&self, id: usize, err: Option<io::Error>) {
        // TODO remove `addr` and instead make it return a usize to identify the client
        // then clients can be a Slab
        self.0.lock().await.peer_quit(id, err);
    }

    /// Updates the state according to the given message from the given client.
    pub async fn handle_message(&self, id: usize, msg: Message<'_>) -> HandlerResult {
        self.0.lock().await.handle_message(id, msg)
    }

    pub async fn remove_if_unregistered(&self, id: usize) {
        self.0.lock().await.remove_if_unregistered(id);
    }
}

// TODO mv StateInner State
// et mettre des Mutex aux bons endroits
//
// - 1 RwLock sur tout org_*
// - 1 Mutex sur (clients, channels)
// - 1 RwLock sur motd
// - 1 RwLock sur password
// - 1 RwLock sur default_chan_mode
// - 1 RwLock sur opers
//
// NOPE pck cc faut les clients pour envoyer des trucs, du coup ça sert à rien

/// The actual shared data (state) of the IRC server.
pub(crate) struct StateInner {
    /// The domain of the server. This string is used as a prefix for replies sent to clients.
    domain: String,

    /// `org_name`, `org_location` and `org_mail` contain information about the administrators of
    /// the server.
    ///
    /// Sent as a reply to the ADMIN command.  See the sample configuration file `doc/ellidri.conf`
    /// for the meaning of each value.
    org_name: String,
    org_location: String,
    org_mail: String,

    /// HashMap to associate a socket address to each client.
    clients: ClientMap,

    // TODO WHOWAS: make it point to nick history
    nicks: NicksMap,

    /// HashMap to associate the name of each channel with their metadata.
    channels: ChannelMap,

    /// The formatted time when this instance is created. It is sent to the client when they
    /// register (in a "003 RPL_CREATED" reply).
    created_at: String,

    /// The message of the day.
    motd: Option<String>,

    /// The global password. Clients need to issue a PASS command with this password to register.
    password: Option<String>,

    /// Modes applied at the creation of new channels.
    default_chan_mode: String,

    /// A list of (name, password) that are valid OPER parameters.
    opers: Vec<(String, String)>,

    channellen: usize,
    kicklen: usize,
    namelen: usize,
    nicklen: usize,
    topiclen: usize,
    userlen: usize,

    login_timeout: u64,

    auth_provider: Box<dyn auth::Provider>,
}

impl StateInner {
    pub fn new(config: config::State, auth_provider: Box<dyn auth::Provider>) -> Self {
        let motd = config.motd_file.and_then(|file| match fs::read_to_string(&file) {
            Ok(motd) => Some(motd),
            Err(err) => {
                log::warn!("Failed to read {:?}: {}", file, err);
                None
            }
        });
        Self {
            domain: config.domain,
            org_name: config.org_name,
            org_location: config.org_location,
            org_mail: config.org_mail,
            clients: Slab::new(),
            nicks: HashMap::new(),
            channels: HashMap::new(),
            created_at: time_str(),
            motd,
            password: config.password,
            default_chan_mode: config.default_chan_mode,
            opers: config.opers,
            channellen: config.channellen,
            kicklen: config.kicklen,
            namelen: config.namelen,
            nicklen: config.nicklen,
            topiclen: config.topiclen,
            userlen: config.userlen,
            login_timeout: config.login_timeout,
            auth_provider,
        }
    }

    pub fn peer_joined(&mut self, addr: net::SocketAddr, queue: MessageQueue) -> usize {
        log::debug!("{}: Connected", addr);
        self.clients.insert(Client::new(queue, addr.ip().to_string()))
    }

    pub fn peer_quit(&mut self, id: usize, err: Option<io::Error>) {
        log::debug!("{}: Disconnected", id);
        if !self.clients.contains(id) {
            return;
        }
        let client = self.clients.remove(id);
        if let Some(err) = err {
            let err = err.to_string();
            self.remove_client(id, client, Some(&err));
        } else {
            self.remove_client(id, client, None);
        }
    }

    /// This function is called by `peer_quit` and `cmd_quit` to do the various cleanup needed when
    /// a client disconnects:
    ///
    /// - remove the client from `StateInner::clients`,
    /// - remove the client from each channel it was in,
    /// - send a QUIT message to all cilents in these channels,
    /// - TODO: remove the client from channel invites (TODO: store invites in client instead of
    ///   channel),
    /// - remove empty channels
    fn remove_client(&mut self, id: usize, client: Client, reason: Option<&str>) {
        let mut response = Buffer::new();
        {
            let msg = response.message(client.full_name(), Command::Quit);
            if let Some(reason) = reason {
                msg.trailing_param(reason);
            }
        }
        let msg = MessageQueueItem::from(response);

        for channel in self.channels.values() {
            if channel.members.contains_key(&id) {
                for member in channel.members.keys() {
                    self.send(*member, msg.clone());
                }
            }
        }

        self.channels.retain(|_, channel| {
            channel.members.remove(&id);
            !channel.members.is_empty()
        });

        self.nicks.remove(u(client.nick()));
    }

    pub fn handle_message(&mut self, id: usize, msg: Message<'_>) -> HandlerResult {
        let client = match self.clients.get(id) {
            Some(client) => client,
            None => return Err(()),
        };
        let mut rb = ReplyBuffer::new(&self.domain, client.nick());

        if MAX_TAG_DATA_LENGTH < msg.tags.len() {
            rb.reply(rpl::ERR_INPUTTOOLONG).trailing_param(lines::INPUT_TOO_LONG);
            client.send(rb);
            return Ok(());
        }

        let command = match msg.command {
            Ok(cmd) => cmd,
            Err(unknown) => {
                if client.is_registered() {
                    rb.reply(rpl::ERR_UNKNOWNCOMMAND)
                        .param(unknown)
                        .trailing_param(lines::UNKNOWN_COMMAND);
                } else {
                    rb.reply(rpl::ERR_NOTREGISTERED).trailing_param(lines::NOT_REGISTERED);
                }
                client.send(rb);
                return Ok(());
            }
        };

        if !client.is_capable_of(command) {
            return Ok(());
        }

        if !msg.has_enough_params() {
            match command {
                Command::Nick | Command::Whois => {
                    rb.reply(rpl::ERR_NONICKNAMEGIVEN)
                        .trailing_param(lines::NEED_MORE_PARAMS);
                }
                Command::PrivMsg | Command::Notice | Command::TagMsg if msg.num_params == 0 => {
                    rb.reply(rpl::ERR_NORECIPIENT).trailing_param(lines::NEED_MORE_PARAMS);
                }
                Command::PrivMsg | Command::Notice if msg.num_params == 1 => {
                    rb.reply(rpl::ERR_NOTEXTTOSEND).trailing_param(lines::NEED_MORE_PARAMS);
                }
                _ => {
                    rb.reply(rpl::ERR_NEEDMOREPARAMS)
                        .param(command.as_str())
                        .trailing_param(lines::NEED_MORE_PARAMS);
                }
            }
            client.send(rb);
            return Ok(());
        }

        if !client.can_issue_command(command, msg.params[0]) {
            if client.is_registered() || command == Command::User {
                rb.reply(rpl::ERR_ALREADYREGISTRED).trailing_param(lines::ALREADY_REGISTERED);
            } else {
                rb.reply(rpl::ERR_NOTREGISTERED).trailing_param(lines::NOT_REGISTERED);
            }
            client.send(rb);
            return Ok(());
        }

        let ps = msg.params;
        let n = msg.num_params;
        let ctx = CommandContext {
            id,
            rb: &mut rb,
            client_tags: msg.tags,
        };

        log::debug!("{}: {} {:?}", id, command, &ps[..n]);
        let cmd_result = match command {
            Command::Admin => self.cmd_admin(ctx),
            Command::Authenticate => self.cmd_authenticate(ctx, ps[0]),
            Command::Cap => self.cmd_cap(ctx, &ps[..n]),
            Command::Info => self.cmd_info(ctx),
            Command::Invite => self.cmd_invite(ctx, ps[0], ps[1]),
            Command::Join => self.cmd_join(ctx, ps[0], ps[1]),
            Command::Kick => self.cmd_kick(ctx, ps[0], ps[1], ps[2]),
            Command::List => self.cmd_list(ctx, ps[0]),
            Command::Lusers => self.cmd_lusers(ctx),
            Command::Mode => self.cmd_mode(ctx, ps[0], ps[1], &ps[2..cmp::max(2, n)]),
            Command::Motd => self.cmd_motd(ctx),
            Command::Names => self.cmd_names(ctx, ps[0]),
            Command::Nick => self.cmd_nick(ctx, ps[0]),
            Command::Notice => self.cmd_notice(ctx, ps[0], ps[1]),
            Command::Oper => self.cmd_oper(ctx, ps[0], ps[1]),
            Command::Part => self.cmd_part(ctx, ps[0], ps[1]),
            Command::Pass => self.cmd_pass(ctx, ps[0]),
            Command::Ping => self.cmd_ping(ctx, ps[0]),
            Command::Pong => Ok(()),
            Command::PrivMsg => self.cmd_privmsg(ctx, ps[0], ps[1]),
            Command::Quit => self.cmd_quit(ctx, ps[0]),
            Command::SetName => self.cmd_setname(ctx, ps[0]),
            Command::TagMsg => self.cmd_tagmsg(ctx, ps[0]),
            Command::Time => self.cmd_time(ctx),
            Command::Topic => self.cmd_topic(ctx, ps[0], if n == 1 {None} else {Some(ps[1])}),
            Command::User => self.cmd_user(ctx, ps[0], ps[3]),
            Command::Version => self.cmd_version(ctx),
            Command::Who => self.cmd_who(ctx, ps[0], ps[1]),
            Command::Whois => self.cmd_whois(ctx, ps[0]),
            Command::Reply(_) => Ok(()),
        };

        if !self.clients.contains(id) {
            return Err(());
        }
        if cmd_result.is_ok() {
            let client = self.clients.get_mut(id).unwrap();
            let old_state = client.state();
            let new_state = client.apply_command(command, msg.params[0]);
            if new_state.is_registered() && !old_state.is_registered() {
                self.write_welcome(&mut rb, id);
            } else if !old_state.is_registered() {
                log::debug!("{}: {:?} + {:?} == {:?}", id, old_state, command, new_state);
            }
        }
        if !rb.is_empty() {
            self.send(id, MessageQueueItem::from(rb));
        }

        Ok(())
    }

    pub fn remove_if_unregistered(&mut self, id: usize) {
        if let Some(client) = self.clients.get(id) {
            if !client.is_registered() {
                self.clients.remove(id);
            }
        }
    }
}

/// Returns `Ok(channel)` when `name` is an existing channel name.  Otherwise returns `Err(())` and
/// send an error to the client.
fn find_channel<'a>(id: usize, rb: &mut ReplyBuffer, channels: &'a ChannelMap,
                    name: &str) -> Result<&'a Channel, ()>
{
    match channels.get(u(name)) {
        Some(channel) => Ok(channel),
        None => {
            log::debug!("{}:         no such channel", id);
            rb.reply(rpl::ERR_NOSUCHCHANNEL).param(name).trailing_param(lines::NO_SUCH_CHANNEL);
            Err(())
        }
    }
}

/// Returns `Ok(member_modes)` when the client identified by `addr` is in the given `channel`.
/// Otherwise returns `Err(())` and send an error to the client.
///
/// `channel_name` is needed for the error reply.
fn find_member(id: usize, rb: &mut ReplyBuffer, channel: &Channel,
               channel_name: &str) -> Result<crate::channel::MemberModes, ()>
{
    match channel.members.get(&id) {
        Some(modes) => Ok(*modes),
        None => {
            log::debug!("{}:         not on channel", id);
            rb.reply(rpl::ERR_NOTONCHANNEL)
                .param(channel_name)
                .trailing_param(lines::NOT_ON_CHANNEL);
            Err(())
        }
    }
}

/// Returns `Ok((address, client))` when the client identified by the nickname `nick` is connected
/// and registered.  Otherwise returns `Err(())` and send an error to the client.
fn find_nick<'a>(id: usize, rb: &mut ReplyBuffer, clients: &'a ClientMap, nicks: &'a NicksMap,
                 nick: &str) -> Result<(usize, &'a Client), ()>
{
    nicks.get(u(nick))
        .map(|id| (*id, &clients[*id]))
        .filter(|(_, c)| c.is_registered())
        .ok_or_else(|| {
            log::debug!("{}:         nick doesn't exist", id);
            rb.reply(rpl::ERR_NOSUCHNICK).param(nick).trailing_param(lines::NO_SUCH_NICK);
        })
}

// Send utilities
impl StateInner {
    /// Sends the given message to the given client.
    fn send(&self, id: usize, msg: MessageQueueItem) {
        if let Some(client) = self.clients.get(id) {
            client.send(msg);
        }
    }

    /// Sends the given message to all users in the given channel.
    fn broadcast(&self, target: &str, msg: &MessageQueueItem) {
        let channel = &self.channels[u(target)];
        for member in channel.members.keys() {
            self.send(*member, msg.clone());
        }
    }

    fn write_i_support(&self, rb: &mut ReplyBuffer) {
        use std::fmt::Write as _;

        rb.reply(rpl::ISUPPORT)
            .param("CASEMAPPING=ascii")
            .param("CHANLIMIT=#:,&:")
            .param("CHANTYPES=#&")
            .param(modes::CHANMODES)
            .param("EXCEPTS")
            .param("HOSTLEN=39")  // max size of an IPv6 address
            .param("INVEX")
            .param("MODES")
            .param("PREFIX=(qaohv)~&@%+")
            .param("SAFELIST")
            .param("TARGMAX=JOIN:,KICK:1,LIST:,NAMES:,NOTICE:1,PART:,PRIVMSG:1,WHOIS:1")
            .trailing_param(lines::I_SUPPORT);

        {
            let mut msg = rb.reply(rpl::ISUPPORT);
            write!(msg.raw_param(), "CHANNELLEN={}", self.channellen).unwrap();
            write!(msg.raw_param(), "KICKLEN={}", self.kicklen).unwrap();
            write!(msg.raw_param(), "NAMELEN={}", self.namelen).unwrap();
            write!(msg.raw_param(), "NICKLEN={}", self.nicklen).unwrap();
            write!(msg.raw_param(), "TOPICLEN={}", self.topiclen).unwrap();
            msg.trailing_param(lines::I_SUPPORT);
        }
    }

    fn write_lusers(&self, rb: &mut ReplyBuffer) {
        lines::luser_client(rb.reply(rpl::LUSERCLIENT), self.clients.len());
        // TODO LUSEROP  store the count of operators to avoid going through `clients` every time?
        // TODO LUSERUNKNOWN
        if !self.channels.is_empty() {
            rb.reply(rpl::LUSERCHANNELS)
                .param(&self.channels.values().filter(|c| !c.secret).count().to_string())
                .trailing_param(lines::LUSER_CHANNELS);
        }
        lines::luser_me(rb.reply(rpl::LUSERME), self.clients.len());
    }

    fn write_motd(&self, rb: &mut ReplyBuffer) {
        if let Some(ref motd) = self.motd {
            lines::motd_start(rb.reply(rpl::MOTDSTART), &self.domain);
            for line in motd.lines() {
                let mut msg = rb.reply(rpl::MOTD);
                let trailing = msg.raw_trailing_param();
                trailing.push_str("- ");
                trailing.push_str(line);
            }
            rb.reply(rpl::ENDOFMOTD).trailing_param(lines::END_OF_MOTD);
        } else {
            rb.reply(rpl::ERR_NOMOTD).trailing_param(lines::NO_MOTD);
        }
    }

    /// Sends the list of nicknames in the channel `channel_name` to the given client.
    fn write_names(&self, id: usize, rb: &mut ReplyBuffer, channel_name: &str) {
        let channel = match self.channels.get(u(channel_name)) {
            Some(channel) => channel,
            None => return,
        };
        if channel.secret && !channel.members.contains_key(&id) {
            return;
        }
        if !channel.members.is_empty() {
            let client_caps = self.clients[id].capabilities.clone();

            let mut message = rb.reply(rpl::NAMREPLY)
                .param(channel.symbol())
                .param(channel_name);
            let trailing = message.raw_trailing_param();
            for (member, modes) in &channel.members {
                if client_caps.multi_prefix {
                    modes.all_symbols(trailing);
                } else if let Some(s) = modes.symbol() {
                    trailing.push(s);
                }
                if client_caps.userhost_in_names {
                    trailing.push_str(self.clients[*member].full_name());
                } else {
                    trailing.push_str(self.clients[*member].nick());
                }
                trailing.push(' ');
            }
            trailing.pop();  // Remove last space, not ':' since !channel.members.is_empty()
        }
        rb.reply(rpl::ENDOFNAMES).param(channel_name).trailing_param(lines::END_OF_NAMES);
    }

    /// Sends the topic of the channel `channel_name` to the given client.
    fn write_topic(&self, rb: &mut ReplyBuffer, channel_name: &str) {
        let channel = &self.channels[u(channel_name)];
        if let Some(ref topic) = channel.topic {
            rb.reply(rpl::TOPIC).param(channel_name).trailing_param(topic);
        } else {
            rb.reply(rpl::NOTOPIC).param(channel_name).trailing_param(lines::NO_TOPIC);
        }
    }

    /// Sends welcome messages. Called when a client has completed its registration.
    fn write_welcome(&self, rb: &mut ReplyBuffer, id: usize) {
        lines::welcome(rb.reply(rpl::WELCOME), self.clients[id].full_name());
        rb.reply(rpl::YOURHOST).trailing_param(lines::YOUR_HOST);
        lines::created(rb.reply(rpl::CREATED), &self.created_at);
        rb.reply(rpl::MYINFO)
            .param(&self.domain)
            .param(server_version!())
            .param(modes::USER_MODES)
            .param(modes::SIMPLE_CHAN_MODES)
            .param(modes::EXTENDED_CHAN_MODES);
        self.write_i_support(rb);
        self.write_lusers(rb);
        self.write_motd(rb);
    }
}

/// Whether a string is accepted as a channel name by ellidri or not.
#[must_use]
fn is_valid_channel_name(s: &str, max_len: usize) -> bool {
    // https://tools.ietf.org/html/rfc2811.html#section-2.1
    let ctrl_g = 7 as char;
    if s.is_empty() {
        return false;
    }
    let first = s.as_bytes()[0];
    s.len() <= max_len
        && (first == b'#' || first == b'&')
        && s.chars().all(|c| c != ' ' && c != ',' && c != ctrl_g && c != ':')
}

/// Whether a string is accepted as a nickname by ellidri or not.
#[must_use]
fn is_valid_nickname(s: &str, max_len: usize) -> bool {
    let s = s.as_bytes();
    let is_valid_nickname_char = |&c: &u8| {
        (b'0' <= c && c <= b'9')
            || (b'a' <= c && c <= b'z')
            || (b'A' <= c && c <= b'Z')
            // "[", "]", "\", "`", "_", "^", "{", "|", "}"
            || (0x5b <= c && c <= 0x60)
            || (0x7b <= c && c <= 0x7d)
    };
    !s.is_empty()
        && s.len() <= max_len
        && s.iter().all(is_valid_nickname_char)
        && s[0] != b'-' && !(b'0' <= s[0] && s[0] <= b'9')
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_is_valid_channel_name() {
        const MAX_LEN: usize = 50;

        assert!(is_valid_channel_name("#Channel9", MAX_LEN));

        assert!(!is_valid_channel_name("", MAX_LEN));
        assert!(!is_valid_channel_name("channel", MAX_LEN));
        assert!(!is_valid_channel_name("#chan nel", MAX_LEN));
        assert!(!is_valid_nickname("#longnicknameverylongohwowthisisalongnicknameohwowmuchlong01234",
                                   MAX_LEN));
    }

    #[test]
    fn test_is_valid_nickname() {
        const DEFAULT_MAX_LEN: usize = 9;

        assert!(is_valid_nickname("nickname", DEFAULT_MAX_LEN));
        assert!(is_valid_nickname("my{}_\\^", DEFAULT_MAX_LEN));
        assert!(is_valid_nickname("brice007", DEFAULT_MAX_LEN));

        assert!(!is_valid_nickname("", DEFAULT_MAX_LEN));
        assert!(!is_valid_nickname(" space ", DEFAULT_MAX_LEN));
        assert!(!is_valid_nickname("sp ace", DEFAULT_MAX_LEN));
        assert!(!is_valid_nickname("007brice", DEFAULT_MAX_LEN));
        assert!(!is_valid_nickname("longnicknameverylongohwowthisisalongnickname", DEFAULT_MAX_LEN));
    }
}
