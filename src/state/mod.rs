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
use crate::message::{Command, Message, Reply, rpl, ResponseBuffer};
use crate::modes;
use crate::util::time_str;
use ellidri_unicase::UniCase;
use std::{cmp, fs, io, net};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::Mutex;

mod capabilities;
mod rfc2812;

const SERVER_INFO: &str = include_str!("info.txt");
const SERVER_VERSION: &str = concat!(env!("CARGO_PKG_NAME"), "-", env!("CARGO_PKG_VERSION"));
const MAX_CHANNEL_NAME_LENGTH: usize = 50;
const MAX_NICKNAME_LENGTH: usize = 9;

type ChannelMap = HashMap<UniCase<String>, Channel>;
type ClientMap = HashMap<net::SocketAddr, Client>;
type HandlerResult = Result<(), ()>;

/// Reference-counted pointer to the shared state of the IRC server.
#[derive(Clone)]
pub struct State(Arc<Mutex<StateInner>>);

impl State {
    pub fn new(config: StateConfig) -> Self {
        let inner = StateInner::new(config);
        Self(Arc::new(Mutex::new(inner)))
    }

    /// Called when the connection to a new peer is created.
    pub async fn peer_joined(&self, addr: net::SocketAddr, queue: MessageQueue) {
        self.0.lock().await.peer_joined(addr, queue);
    }

    /// Called when the connection to a peer is closed.
    pub async fn peer_quit(&self, addr: &net::SocketAddr, err: Option<io::Error>) {
        self.0.lock().await.peer_quit(addr, err);
    }

    /// Called when a connected peer sends a message.
    pub async fn handle_message(&self, addr: &net::SocketAddr, msg: Message<'_>) {
        self.0.lock().await.handle_message(addr, msg);
    }
}

/// The actual shared data (state) of the IRC server.
struct StateInner {
    /// The domain of the server. This string is used as a prefix for replies sent to clients.
    domain: String,

    /// Information about the administrators of the server. Sent as a reply to the ADMIN command.
    org_name: String,
    org_location: String,
    org_mail: String,

    clients: ClientMap,
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

    fn remove_client(&mut self, addr: &net::SocketAddr, client: Client, reason: Option<&str>) {
        let mut response = ResponseBuffer::new();
        {
            let msg = response.prefixed_message(client.full_name(), Command::Quit);
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
            channel.members.remove(&addr);
            !channel.members.is_empty()
        });

        // TODO remove from channel invites
    }

    pub fn handle_message(&mut self, addr: &net::SocketAddr, msg: Message<'_>) {
        let client = self.clients.get(addr);
        if client.is_none() {
            return;
        }
        let client = client.unwrap();

        let command = match msg.command {
            Ok(cmd) => cmd,
            Err(unknown) => {
                let mut response = ResponseBuffer::new();
                if client.is_registered() {
                    response.prefixed_message(&self.domain, rpl::ERR_UNKNOWNCOMMAND)
                        .param(client.nick())
                        .param(unknown)
                        .trailing_param(lines::UNKNOWN_COMMAND);
                } else {
                    response.prefixed_message(&self.domain, rpl::ERR_NOTREGISTERED)
                        .param(client.nick())
                        .trailing_param(lines::NOT_REGISTERED);
                }
                client.send(MessageQueueItem::from(response));
                return;
            }
        };

        if !msg.has_enough_params() {
            let mut response = ResponseBuffer::new();
            match command {
                Command::Nick | Command::Whois => {
                    response.prefixed_message(&self.domain, rpl::ERR_NONICKNAMEGIVEN)
                        .param(client.nick())
                        .trailing_param(lines::NEED_MORE_PARAMS);
                }
                Command::PrivMsg | Command::Notice if msg.num_params == 0 => {
                    response.prefixed_message(&self.domain, rpl::ERR_NORECIPIENT)
                        .param(client.nick())
                        .trailing_param(lines::NEED_MORE_PARAMS);
                }
                Command::PrivMsg | Command::Notice if msg.num_params == 1 => {
                    response.prefixed_message(&self.domain, rpl::ERR_NOTEXTTOSEND)
                        .param(client.nick())
                        .trailing_param(lines::NEED_MORE_PARAMS);
                }
                _ => {
                    response.prefixed_message(&self.domain, rpl::ERR_NEEDMOREPARAMS)
                        .param(client.nick())
                        .param(command.as_str())
                        .trailing_param(lines::NEED_MORE_PARAMS);
                }
            }
            client.send(MessageQueueItem::from(response));
            return;
        }

        if !client.can_issue_command(command, msg.params[0]) {
            let mut response = ResponseBuffer::new();
            if client.is_registered() || command == Command::User {
                response.prefixed_message(&self.domain, rpl::ERR_ALREADYREGISTRED)
                    .param(client.nick())
                    .trailing_param(lines::ALREADY_REGISTERED);
            } else {
                response.prefixed_message(&self.domain, rpl::ERR_NOTREGISTERED)
                    .param(client.nick())
                    .trailing_param(lines::NOT_REGISTERED);
            }
            client.send(MessageQueueItem::from(response));
            return;
        }

        // TODO intialize a responsebuffer because of labeled-response's ACK

        let ps = msg.params;
        let n = msg.num_params;
        let cmd_result = match command {
            Command::Admin => self.cmd_admin(addr),
            Command::Cap => self.cmd_cap(addr, &ps[..n]),
            Command::Info => self.cmd_info(addr),
            Command::Invite => self.cmd_invite(addr, ps[0], ps[1]),
            Command::Join => self.cmd_join(addr, ps[0], ps[1]),
            Command::Kick => self.cmd_kick(addr, ps[0], ps[1], ps[2]),
            Command::List => self.cmd_list(addr, ps[0]),
            Command::Lusers => self.cmd_lusers(addr),
            Command::Mode => self.cmd_mode(addr, ps[0], ps[1], &ps[2..cmp::max(2, n)]),
            Command::Motd => self.cmd_motd(addr),
            Command::Names => self.cmd_names(addr, ps[0]),
            Command::Nick => self.cmd_nick(addr, ps[0]),
            Command::Notice => self.cmd_notice(addr, ps[0], ps[1]),
            Command::Oper => self.cmd_oper(addr, ps[0], ps[1]),
            Command::Part => self.cmd_part(addr, ps[0], ps[1]),
            Command::Pass => self.cmd_pass(addr, ps[0]),
            Command::Ping => self.cmd_ping(addr, ps[0]),
            Command::Pong => Ok(()),
            Command::PrivMsg => self.cmd_privmsg(addr, ps[0], ps[1]),
            Command::Quit => self.cmd_quit(addr, ps[0]),
            Command::Time => self.cmd_time(addr),
            Command::Topic => self.cmd_topic(addr, ps[0], if n == 1 {None} else {Some(ps[1])}),
            Command::User => self.cmd_user(addr, ps[0], ps[3]),
            Command::Version => self.cmd_version(addr),
            Command::Who => self.cmd_who(addr, ps[0], ps[1]),
            Command::Whois => self.cmd_whois(addr, ps[0]),
            Command::Reply(_) => Ok(()),
        };

        if cmd_result.is_ok() {
            let client = self.clients.get_mut(addr).unwrap();
            let old_state = client.state();
            let new_state = client.apply_command(command, msg.params[0]);
            if new_state.is_registered() && !old_state.is_registered() {
                self.send_welcome(addr);
            }
        }
    }
}

/// Sends a reply to the client.
///
/// See `StateInner::send_reply` for more information.
fn send_reply(addr: &net::SocketAddr, domain: &str, clients: &ClientMap,
              r: Reply, params: &[&str])
{
    let client = &clients[addr];
    let mut response = ResponseBuffer::new();
    {
        let mut msg = response.prefixed_message(domain, r).param(client.nick());
        if !params.is_empty() {
            for p in &params[0..params.len() - 1] {
                msg = msg.param(p);
            }
            msg.trailing_param(params[params.len() - 1]);
        }
    }
    client.send(MessageQueueItem::from(response));
}

// TODO update logging in command handlers

/// Returns `Ok(channel)` when `name` is an existing channel name.  Otherwise returns `Err(())` and
/// send an error to the client.
fn find_channel<'a>(addr: &net::SocketAddr, domain: &str, clients: &ClientMap,
                    channels: &'a ChannelMap, name: &str) -> Result<&'a Channel, ()>
{
    match channels.get(<&UniCase<str>>::from(name)) {
        Some(channel) => Ok(channel),
        None => {
            log::debug!("{}:         no such channel", addr);
            send_reply(addr, domain, clients, rpl::ERR_NOSUCHCHANNEL,
                       &[name, lines::NO_SUCH_CHANNEL]);
            Err(())
        }
    }
}

/// Returns `Ok(member_modes)` when the client identified by `addr` is in the given `channel`.
/// Otherwise returns `Err(())` and send an error to the client.
///
/// `channel_name` is needed for the error reply.
fn find_member(addr: &net::SocketAddr, domain: &str, clients: &ClientMap, channel: &Channel,
               channel_name: &str) -> Result<crate::channel::MemberModes, ()>
{
    match channel.members.get(addr) {
        Some(modes) => Ok(*modes),
        None => {
            log::debug!("{}:         not on channel", addr);
            send_reply(addr, domain, clients, rpl::ERR_NOTONCHANNEL,
                       &[channel_name, lines::NOT_ON_CHANNEL]);
            Err(())
        }
    }
}

/// Returns `Ok((address, client))` when the client identified by the nickname `nick` is connected
/// and registered.  Otherwise returns `Err(())` and send an error to the client.
fn find_nick<'a>(addr: &net::SocketAddr, domain: &str, clients: &'a ClientMap,
                 nick: &str) -> Result<(net::SocketAddr, &'a Client), ()>
{
    match clients.iter().find(|(_, client)| client.nick() == nick && client.is_registered()) {
        Some((addr, client)) => Ok((*addr, client)),
        None => {
            log::debug!("{}:         nick doesn't exist", addr);
            send_reply(addr, domain, clients, rpl::ERR_NOSUCHNICK, &[nick, lines::NO_SUCH_NICK]);
            Err(())
        }
    }
}

// Send utilities
impl StateInner {
    /// Sends the given message to all users in the given channel.
    fn broadcast(&self, target: &str, msg: MessageQueueItem) {
        let channel = &self.channels[<&UniCase<str>>::from(target)];
        for member in channel.members.keys() {
            self.clients[member].send(msg.clone());
        }
    }

    /// Sends the given message to the given client.
    fn send(&self, addr: &net::SocketAddr, msg: MessageQueueItem) {
        if let Some(client) = self.clients.get(addr) {
            client.send(msg);
        }
    }

    // TODO replace those with write_* equivalents
    // that take a responsebuffer instead of an address

    /// Creates a message from the given reply and parameters, and sends it to the given client.
    /// It also adds the needed client's nick as the first parameter.
    fn send_reply(&self, addr: &net::SocketAddr, r: Reply, params: &[&str]) {
        send_reply(addr, &self.domain, &self.clients, r, params);
    }

    fn write_i_support(&self, response: &mut ResponseBuffer, nick: &str) {
        response.prefixed_message(&self.domain, rpl::ISUPPORT)
            .param(nick)
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

    /// Sends the list of nicknames in the channel `channel_name` to the given client.
    fn send_names(&self, addr: &net::SocketAddr, channel_name: &str) {
        if let Some(channel) = self.channels.get(<&UniCase<str>>::from(channel_name)) {
            if channel.secret && !channel.members.contains_key(&addr) { return; }
            let client = &self.clients[&addr];
            let mut response = ResponseBuffer::new();
            if !channel.members.is_empty() {
                let mut message = response.prefixed_message(&self.domain, rpl::NAMREPLY)
                    .param(client.nick())
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
            response.prefixed_message(&self.domain, rpl::ENDOFNAMES)
                .param(client.nick())
                .param(channel_name)
                .trailing_param(lines::END_OF_NAMES);
            self.send(addr, MessageQueueItem::from(response));
        }
    }

    /// Sends the topic of the channel `channel_name` to the given client.
    fn send_topic(&self, addr: &net::SocketAddr, channel_name: &str) {
        let channel = &self.channels[<&UniCase<str>>::from(channel_name)];
        if let Some(ref topic) = channel.topic {
            self.send_reply(addr, rpl::TOPIC, &[channel_name, topic]);
        } else {
            self.send_reply(addr, rpl::NOTOPIC, &[channel_name, lines::NO_TOPIC]);
        }
    }

    /// Sends welcome messages. Called when a client has completed its registration.
    fn send_welcome(&self, addr: &net::SocketAddr) {
        let client = &self.clients[addr];
        let mut response = ResponseBuffer::new();
        response.prefixed_message(&self.domain, rpl::WELCOME)
            .param(client.nick())
            .trailing_param(lines::WELCOME);
        response.prefixed_message(&self.domain, rpl::YOURHOST)
            .param(client.nick())
            .trailing_param(lines::YOUR_HOST);
        lines::created(response.prefixed_message(&self.domain, rpl::CREATED).param(client.nick()),
                       &self.created_at);
        response.prefixed_message(&self.domain, rpl::MYINFO)
            .param(client.nick())
            .param(&self.domain)
            .param(SERVER_VERSION)
            .param(modes::USER_MODES)
            .param(modes::SIMPLE_CHAN_MODES)
            .param(modes::EXTENDED_CHAN_MODES);
        self.write_i_support(&mut response, client.nick());
        client.send(MessageQueueItem::from(response));
        let _ = self.cmd_lusers(addr);
        let _ = self.cmd_motd(addr);
    }
}
