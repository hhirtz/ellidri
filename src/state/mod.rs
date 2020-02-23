//! Shared state and API to handle incoming commands.
//!
//! This module is split in several files:
//!
//! - `mod.rs`: public API of the server state and send utilities
//! - `rfc2812.rs` : handlers for messages defined in the RFC 2812
//! - `capabilities.rs` : handlers for the CAP command

use crate::channel::Channel;
use crate::client::{Client, MessageQueue, MessageQueueItem};
use crate::config::StateConfig;
use crate::lines;
use crate::message::{Buffer, Command, Message, ReplyBuffer, rpl};
use crate::modes;
use crate::util::time_str;
use ellidri_unicase::UniCase;
use std::{cmp, fs, io, net};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::Mutex;

mod capabilities;
mod rfc2812;
#[cfg(test)]
mod test;

#[macro_export]
macro_rules! server_version(() => {concat!(env!("CARGO_PKG_NAME"), "-", env!("CARGO_PKG_VERSION"))});

/// Information about ellidri from an IRC client perspective.
///
/// Sent to client with the INFO command.
const SERVER_INFO: &str = include_str!("info.txt");

// TODO make those configurable at runtime
const MAX_CHANNEL_NAME_LENGTH: usize = 50;
const MAX_NICKNAME_LENGTH: usize = 9;
const MAX_TAG_DATA_LENGTH: usize = 4094;

type ChannelMap = HashMap<UniCase<String>, Channel>;
type ClientMap = HashMap<net::SocketAddr, Client>;
type HandlerResult = Result<(), ()>;

struct CommandContext<'a> {
    addr: &'a net::SocketAddr,
    rb: &'a mut ReplyBuffer,
    tags: &'a str,
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
/// # Example
///
/// ```rust
/// # use ellidri::State;
/// # use ellidri::config::StateConfig;
/// # use ellidri::message::Message;
/// # tokio::runtime::Runtime::new().unwrap().block_on(async {
/// // Initialize a `StateConfig` and create the state.
/// let state = State::new(StateConfig {
///     domain: "ellidri.dev".to_owned(),
///     ..StateConfig::default()
/// });
///
/// // Each client is identified by its address.
/// let client_addr = std::net::SocketAddr::from(([127, 0, 0, 1], 12345));
///
/// // The state uses a MPSC queue and pushes the messages meant to be sent
/// // to the client onto the queue.
/// let (msg_queue, mut outgoing_msgs) = tokio::sync::mpsc::unbounded_channel();
/// state.peer_joined(client_addr, msg_queue).await;
///
/// // `handle_message` is used to pass messages from the client to the state.
/// let nick = Message::parse("NICK ser\r\n").unwrap();
/// let user = Message::parse("USER ser 0 * :ser\r\n").unwrap();
/// state.handle_message(&client_addr, nick).await;
/// state.handle_message(&client_addr, user).await;
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
///
/// [1]: https://tokio.rs
#[derive(Clone)]
pub struct State(Arc<Mutex<StateInner>>);

impl State {
    /// Intialize the IRC state from the given configuration.
    pub fn new(config: StateConfig) -> Self {
        let inner = StateInner::new(config);
        Self(Arc::new(Mutex::new(inner)))
    }

    /// Adds a new connection to the state.
    ///
    /// Each connection is identified by its address.  The queue is used to push messages back to
    /// the peer.
    pub async fn peer_joined(&self, addr: net::SocketAddr, queue: MessageQueue) {
        self.0.lock().await.peer_joined(addr, queue);
    }

    /// Removes the given connection from the state, with an optional error.
    ///
    /// If the peer has quit unexpctedly, `err` should be set to `Some` and reflect the cause of
    /// the quit, so that other peers can be correctly informed.
    pub async fn peer_quit(&self, addr: &net::SocketAddr, err: Option<io::Error>) {
        self.0.lock().await.peer_quit(addr, err);
    }

    /// Updates the state according to the given message from the given client.
    pub async fn handle_message(&self, addr: &net::SocketAddr, msg: Message<'_>) {
        self.0.lock().await.handle_message(addr, msg);
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
}

impl StateInner {
    pub fn new(config: StateConfig) -> Self {
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
            clients: HashMap::new(),
            channels: HashMap::new(),
            created_at: time_str(),
            motd,
            password: config.password,
            default_chan_mode: config.default_chan_mode,
            opers: config.opers,
        }
    }

    pub fn peer_joined(&mut self, addr: net::SocketAddr, queue: MessageQueue) {
        log::debug!("{}: Connected", addr);
        self.clients.insert(addr, Client::new(queue, addr.ip().to_string()));
    }

    pub fn peer_quit(&mut self, addr: &net::SocketAddr, err: Option<io::Error>) {
        log::debug!("{}: Disconnected", addr);
        if let Some(client) = self.clients.remove(addr) {
            if let Some(err) = err {
                let s = err.to_string();
                self.remove_client(addr, client, Some(s.as_ref()));
            } else {
                self.remove_client(addr, client, None);
            }
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
    fn remove_client(&mut self, addr: &net::SocketAddr, client: Client, reason: Option<&str>) {
        let mut response = Buffer::new();
        {
            let msg = response.message(client.full_name(), Command::Quit);
            if let Some(reason) = reason {
                msg.trailing_param(reason);
            }
        }
        let msg = MessageQueueItem::from(response);

        for channel in self.channels.values() {
            if channel.members.contains_key(addr) {
                for member in channel.members.keys() {
                    self.send(member, msg.clone());
                }
            }
        }

        self.channels.retain(|_, channel| {
            channel.members.remove(addr);
            !channel.members.is_empty()
        });
    }

    pub fn handle_message(&mut self, addr: &net::SocketAddr, msg: Message<'_>) {
        // TODO unwrap clients.get(addr) when ellidri closes the connection to clients that have quit?
        let client = match self.clients.get(addr) {
            Some(client) => client,
            None => return,
        };
        let mut rb = ReplyBuffer::new(&self.domain, client.nick());

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
                return;
            }
        };

        if MAX_TAG_DATA_LENGTH < msg.tags.len() {
            rb.reply(rpl::ERR_INPUTTOOLONG).trailing_param(lines::INPUT_TOO_LONG);
            client.send(rb);
            return;
        }

        if !msg.has_enough_params() {
            match command {
                Command::Nick | Command::Whois => {
                    rb.reply(rpl::ERR_NONICKNAMEGIVEN)
                        .trailing_param(lines::NEED_MORE_PARAMS);
                }
                Command::PrivMsg | Command::Notice if msg.num_params == 0 => {
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
            return;
        }

        if !client.can_issue_command(command, msg.params[0]) {
            if client.is_registered() || command == Command::User {
                rb.reply(rpl::ERR_ALREADYREGISTRED).trailing_param(lines::ALREADY_REGISTERED);
            } else {
                rb.reply(rpl::ERR_NOTREGISTERED).trailing_param(lines::NOT_REGISTERED);
            }
            client.send(rb);
            return;
        }

        let ps = msg.params;
        let n = msg.num_params;
        log::debug!("{}: {} {:?}", addr, command, &ps[..n]);
        let cmd_result = match command {
            Command::Admin => self.cmd_admin(&mut rb),
            Command::Cap => self.cmd_cap(addr, &mut rb, &ps[..n]),
            Command::Info => self.cmd_info(&mut rb),
            Command::Invite => self.cmd_invite(addr, &mut rb, ps[0], ps[1]),
            Command::Join => self.cmd_join(addr, &mut rb, ps[0], ps[1]),
            Command::Kick => self.cmd_kick(addr, &mut rb, ps[0], ps[1], ps[2]),
            Command::List => self.cmd_list(addr, &mut rb, ps[0]),
            Command::Lusers => self.cmd_lusers(&mut rb),
            Command::Mode => self.cmd_mode(addr, &mut rb, ps[0], ps[1], &ps[2..cmp::max(2, n)]),
            Command::Motd => self.cmd_motd(&mut rb),
            Command::Names => self.cmd_names(addr, &mut rb, ps[0]),
            Command::Nick => self.cmd_nick(addr, &mut rb, ps[0]),
            Command::Notice => self.cmd_notice(addr, &mut rb, ps[0], ps[1]),
            Command::Oper => self.cmd_oper(addr, &mut rb, ps[0], ps[1]),
            Command::Part => self.cmd_part(addr, &mut rb, ps[0], ps[1]),
            Command::Pass => self.cmd_pass(addr, ps[0]),
            Command::Ping => self.cmd_ping(&mut rb, ps[0]),
            Command::Pong => Ok(()),
            Command::PrivMsg => self.cmd_privmsg(addr, &mut rb, ps[0], ps[1]),
            Command::Quit => self.cmd_quit(addr, ps[0]),
            Command::Time => self.cmd_time(&mut rb),
            Command::Topic => self.cmd_topic(addr, &mut rb, ps[0], if n == 1 {None} else {Some(ps[1])}),
            Command::User => self.cmd_user(addr, &mut rb, ps[0], ps[3]),
            Command::Version => self.cmd_version(&mut rb),
            Command::Who => self.cmd_who(&mut rb, ps[0], ps[1]),
            Command::Whois => self.cmd_whois(addr, &mut rb, ps[0]),
            Command::Reply(_) => Ok(()),
        };

        if !rb.is_empty() {
            self.send(addr, MessageQueueItem::from(rb));
        }
        if cmd_result.is_ok() {
            let client = self.clients.get_mut(addr).unwrap();
            let old_state = client.state();
            let new_state = client.apply_command(command, msg.params[0]);
            if new_state.is_registered() && !old_state.is_registered() {
                let client = &self.clients[addr];
                let mut rb = ReplyBuffer::new(&self.domain, client.nick());
                self.write_welcome(&mut rb, client.full_name());
                client.send(rb);
            }
        }
    }
}

/// Returns `Ok(channel)` when `name` is an existing channel name.  Otherwise returns `Err(())` and
/// send an error to the client.
fn find_channel<'a>(addr: &net::SocketAddr, rb: &mut ReplyBuffer, channels: &'a ChannelMap,
                    name: &str) -> Result<&'a Channel, ()>
{
    match channels.get(<&UniCase<str>>::from(name)) {
        Some(channel) => Ok(channel),
        None => {
            log::debug!("{}:         no such channel", addr);
            rb.reply(rpl::ERR_NOSUCHCHANNEL).param(name).trailing_param(lines::NO_SUCH_CHANNEL);
            Err(())
        }
    }
}

/// Returns `Ok(member_modes)` when the client identified by `addr` is in the given `channel`.
/// Otherwise returns `Err(())` and send an error to the client.
///
/// `channel_name` is needed for the error reply.
fn find_member(addr: &net::SocketAddr, rb: &mut ReplyBuffer, channel: &Channel,
               channel_name: &str) -> Result<crate::channel::MemberModes, ()>
{
    match channel.members.get(addr) {
        Some(modes) => Ok(*modes),
        None => {
            log::debug!("{}:         not on channel", addr);
            rb.reply(rpl::ERR_NOTONCHANNEL)
                .param(channel_name)
                .trailing_param(lines::NOT_ON_CHANNEL);
            Err(())
        }
    }
}

/// Returns `Ok((address, client))` when the client identified by the nickname `nick` is connected
/// and registered.  Otherwise returns `Err(())` and send an error to the client.
fn find_nick<'a>(addr: &net::SocketAddr, rb: &mut ReplyBuffer, clients: &'a ClientMap,
                 nick: &str) -> Result<(net::SocketAddr, &'a Client), ()>
{
    match clients.iter().find(|(_, client)| client.nick() == nick && client.is_registered()) {
        Some((addr, client)) => Ok((*addr, client)),
        None => {
            log::debug!("{}:         nick doesn't exist", addr);
            rb.reply(rpl::ERR_NOSUCHNICK).param(nick).trailing_param(lines::NO_SUCH_NICK);
            Err(())
        }
    }
}

// Send utilities
impl StateInner {
    /// Sends the given message to the given client.
    fn send(&self, addr: &net::SocketAddr, msg: MessageQueueItem) {
        if let Some(client) = self.clients.get(addr) {
            client.send(msg);
        }
    }

    /// Sends the given message to all users in the given channel.
    fn broadcast(&self, target: &str, msg: MessageQueueItem) {
        let channel = &self.channels[<&UniCase<str>>::from(target)];
        for member in channel.members.keys() {
            self.send(member, msg.clone());
        }
    }

    fn write_i_support(&self, rb: &mut ReplyBuffer) {
        rb.reply(rpl::ISUPPORT)
            .param("CASEMAPPING=ascii")
            .param(&format!("CHANLEN={}", MAX_CHANNEL_NAME_LENGTH))
            .param("CHANTYPES=#&")
            .param(modes::CHANMODES)
            .param("EXCEPTS")
            .param("INVEX")
            .param("MODES")
            .param(&format!("NICKLEN={}", MAX_NICKNAME_LENGTH))
            .trailing_param(lines::I_SUPPORT);
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
    fn write_names(&self, addr: &net::SocketAddr, rb: &mut ReplyBuffer, channel_name: &str) {
        if let Some(channel) = self.channels.get(<&UniCase<str>>::from(channel_name)) {
            if channel.secret && !channel.members.contains_key(&addr) { return; }
            if !channel.members.is_empty() {
                let mut message = rb.reply(rpl::NAMREPLY)
                    .param(channel.symbol())
                    .param(channel_name);
                let trailing = message.raw_trailing_param();
                for (member, modes) in &channel.members {
                    if let Some(s) = modes.symbol() { trailing.push(s); }
                    trailing.push_str(self.clients[member].nick());
                    trailing.push(' ');
                }
                trailing.pop();  // Remove last space
            }
            rb.reply(rpl::ENDOFNAMES).param(channel_name).trailing_param(lines::END_OF_NAMES);
        }
    }

    /// Sends the topic of the channel `channel_name` to the given client.
    fn write_topic(&self, rb: &mut ReplyBuffer, channel_name: &str) {
        let channel = &self.channels[<&UniCase<str>>::from(channel_name)];
        if let Some(ref topic) = channel.topic {
            rb.reply(rpl::TOPIC).param(channel_name).trailing_param(topic);
        } else {
            rb.reply(rpl::NOTOPIC).param(channel_name).trailing_param(lines::NO_TOPIC);
        }
    }

    /// Sends welcome messages. Called when a client has completed its registration.
    fn write_welcome(&self, rb: &mut ReplyBuffer, name: &str) {
        lines::welcome(rb.reply(rpl::WELCOME), name);
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
