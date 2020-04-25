//! Shared state and API to handle incoming commands.
//!
//! This module is split in several files:
//!
//! - `mod.rs`: public API of the server state and send utilities
//! - `rfc2812.rs`: handlers for messages defined in the RFC 2812
//! - `ircv3.rs`: handlers for messages defined in IRCv3 extensions
//! - `test.rs`: testing utilities

#![allow(clippy::needless_pass_by_value)]

use crate::{auth, config, lines, util};
use crate::channel::Channel;
use crate::client::{Client, MessageQueue, MessageQueueItem, ReplyBuffer};
use ellidri_tokens::{Buffer, Command, Message, mode, rpl, tags};
use ellidri_unicase::{u, UniCase};
use slab::Slab;
use std::{cmp, fmt, fs, net};
use std::collections::{HashMap, HashSet};
use std::fmt::Write as _;
use std::sync::Arc;
use tokio::sync::{Mutex, Notify};

mod ircv3;
mod rfc2812;
#[cfg(test)]
mod test;

const SERVER_VERSION: &str = concat!(env!("CARGO_PKG_NAME"), "-", env!("CARGO_PKG_VERSION"));

/// Information about ellidri from an IRC client perspective.
///
/// Sent to client with the INFO command.
const SERVER_INFO: &str = include_str!("info.txt");

const MAX_TAG_DATA_LENGTH: usize = 4094;
const MAX_LABEL_LENGTH: usize = 64;

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
#[derive(Clone)]
pub struct State(Arc<Mutex<StateInner>>);

impl State {
    /// Intialize the IRC state from the given configuration.
    ///
    /// `rehash` will be notified/pinged whenever an operator sends a REHASH command.
    pub fn new(config: config::State, auth_provider: Box<dyn auth::Provider>, rehash: Arc<Notify>)
               -> Self
    {
        let inner = StateInner::new(config, auth_provider, rehash);
        Self(Arc::new(Mutex::new(inner)))
    }

    /// Reload state configuration.
    ///
    /// `cfg.motd_file` must be the contents of the MOTD file instead of its path.
    pub async fn rehash(&self, cfg: config::State, auth_provider: Box<dyn auth::Provider>) {
        self.0.lock().await.rehash(cfg, auth_provider);
    }

    /// Adds a new connection to the state.
    ///
    /// The given `addr`ess is used to build the client's host, and the given `queue` is used to
    /// push messages back to the client.
    ///
    /// Each connection is identified by an integer.  This function returns the identifier for this
    /// connection, which must be used to handle messages from this client.
    pub async fn peer_joined(&self, addr: net::SocketAddr, queue: MessageQueue) -> usize {
        self.0.lock().await.peer_joined(addr, queue)
    }

    /// Removes the given connection from the state, with an optional error.
    ///
    /// If the peer has quit unexpctedly, `err` should be set to `Some` and reflect the cause of
    /// the quit, so that other peers can be correctly informed.
    pub async fn peer_quit<E>(&self, id: usize, err: Option<E>)
        where E: fmt::Display,
    {
        self.0.lock().await.peer_quit(id, err);
    }

    /// Updates the state according to the given message from the given client.
    pub async fn handle_message(&self, id: usize, msg: Message<'_>) -> Result<u32, ()> {
        self.0.lock().await.handle_message(id, msg)
    }

    pub async fn remove_if_unregistered(&self, id: usize) {
        self.0.lock().await.remove_if_unregistered(id);
    }

    /// Returns the timeout for registration, in milliseconds.
    pub async fn login_timeout(&self) -> u64 {
        self.0.lock().await.login_timeout
    }
}

/// The actual shared data (state) of the IRC server.
pub(crate) struct StateInner {
    /// The domain of the server. This string is used as a prefix for replies sent to clients.
    domain: Arc<str>,

    /// `org_name`, `org_location` and `org_mail` contain information about the administrators of
    /// the server.
    ///
    /// Sent as a reply to the ADMIN command.  See the sample configuration file `doc/ellidri.conf`
    /// for the meaning of each value.
    org_name: String,
    org_location: String,
    org_mail: String,

    /// Map that associates a socket address to each client.
    clients: ClientMap,

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
    opers: Vec<config::Oper>,

    /// Limits in number of characters for user input.
    awaylen: usize,
    channellen: usize,
    keylen: usize,
    kicklen: usize,
    namelen: usize,
    nicklen: usize,
    topiclen: usize,
    userlen: usize,

    /// Registration timeout, in milliseconds.
    login_timeout: u64,

    /// SASL backend.
    auth_provider: Box<dyn auth::Provider>,

    /// Channel to send rehash notifications
    rehash: Arc<Notify>,
}

impl StateInner {
    pub fn new(config: config::State, auth_provider: Box<dyn auth::Provider>, rehash: Arc<Notify>)
               -> Self
    {
        log::info!("Loading MOTD from {:?}", config.motd_file);
        let motd = match fs::read_to_string(&config.motd_file) {
            Ok(motd) => Some(motd),
            Err(err) => {
                log::warn!("Failed to read {:?}: {}", config.motd_file, err);
                None
            }
        };
        Self {
            domain: Arc::from(config.domain),
            org_name: config.org_name,
            org_location: config.org_location,
            org_mail: config.org_mail,
            clients: Slab::new(),
            nicks: HashMap::new(),
            channels: HashMap::new(),
            created_at: util::time_str(),
            motd,
            password: config.password,
            default_chan_mode: config.default_chan_mode,
            opers: config.opers,
            awaylen: config.awaylen,
            channellen: config.channellen,
            keylen: config.keylen,
            kicklen: config.kicklen,
            namelen: config.namelen,
            nicklen: config.nicklen,
            topiclen: config.topiclen,
            userlen: config.userlen,
            login_timeout: config.login_timeout,
            auth_provider,
            rehash,
        }
    }

    pub fn rehash(&mut self, config: config::State, auth_provider: Box<dyn auth::Provider>) {
        self.domain = Arc::from(config.domain);
        self.org_name = config.org_name;
        self.org_location = config.org_location;
        self.motd = if config.motd_file.is_empty() {None} else {Some(config.motd_file)};
        self.password = config.password;
        self.default_chan_mode = config.default_chan_mode;
        self.opers = config.opers;
        self.awaylen = config.awaylen;
        self.channellen = config.channellen;
        self.keylen = config.keylen;
        self.kicklen = config.kicklen;
        self.namelen = config.namelen;
        self.topiclen = config.topiclen;
        self.userlen = config.userlen;
        self.login_timeout = config.login_timeout;
        self.auth_provider = auth_provider;
    }

    pub fn peer_joined(&mut self, addr: net::SocketAddr, queue: MessageQueue) -> usize {
        log::debug!("{}: Connected", addr);
        let client = Client::new(self.domain.clone(), queue, addr.ip().to_string());
        self.clients.insert(client)
    }

    pub fn peer_quit<E>(&mut self, id: usize, err: Option<E>)
        where E: fmt::Display,
    {
        log::debug!("{}: Disconnected", id);
        if !self.clients.contains(id) {
            return;
        }
        let client = self.clients.remove(id);
        if let Some(err) = err {
            let err = err.to_string();
            self.remove_client(id, client, &err, Some(&err));
        } else {
            self.remove_client(id, client, lines::CLOSING_LINK, None);
        }
    }

    /// This function is called by `peer_quit` and `cmd_quit` to do the various cleanup needed when
    /// a client disconnects:
    ///
    /// - remove the client from `StateInner::clients`,
    /// - remove the client from each channel it was in,
    /// - send a QUIT message to all cilents in these channels,
    /// - TODO: remove the client from channel invites
    /// - remove empty channels
    fn remove_client(&mut self, id: usize, client: Client, err: &str, reason: Option<&str>) {
        let mut response = Buffer::new();
        {
            let msg = response.message(client.full_name(), Command::Quit);
            if let Some(reason) = reason {
                msg.trailing_param(reason);
            }
        }
        self.send_notification(id, response, |_, _| true);

        let mut error = Buffer::new();
        error.message("", "ERROR").trailing_param(err);
        client.send(error);

        self.channels.retain(|_, channel| {
            channel.members.remove(&id);
            !channel.members.is_empty()
        });

        self.nicks.remove(u(client.nick()));
    }

    pub fn handle_message(&mut self, id: usize, msg: Message<'_>) -> Result<u32, ()> {
        let client = match self.clients.get(id) {
            Some(client) => client,
            None => return Err(()),
        };

        let label = if client.capabilities().has_labeled_response() {
            tags(msg.tags)
                .find(|tag| tag.key == "label")
                .and_then(|tag| tag.value)
                .filter(|label| label.len() <= MAX_LABEL_LENGTH)
                .unwrap_or("")
        } else {
            ""
        };

        let mut rb = client.reply(label);
        let is_operator = client.operator;

        if MAX_TAG_DATA_LENGTH < msg.tags.len() {
            rb.reply(rpl::ERR_INPUTTOOLONG, 2+lines::INPUT_TOO_LONG.len(), |msg| {
                msg.trailing_param(lines::INPUT_TOO_LONG);
            });
            return Ok(3);
        }

        let command = match msg.command {
            Ok(cmd) => cmd,
            Err(unknown) => {
                if client.is_registered() {
                    let capacity = 1+unknown.len() + 2+lines::UNKNOWN_COMMAND.len();
                    rb.reply(rpl::ERR_UNKNOWNCOMMAND, capacity, |msg| {
                        msg.param(unknown).trailing_param(lines::UNKNOWN_COMMAND);
                    });
                } else {
                    rb.reply(rpl::ERR_NOTREGISTERED, 2+lines::NOT_REGISTERED.len(), |msg| {
                        msg.trailing_param(lines::NOT_REGISTERED);
                    });
                }
                return Ok(1);
            }
        };

        if !client.capabilities().is_capable_of(command) {
            if client.is_registered() {
                let command = command.as_str();
                let capacity = 1+command.len() + 2+lines::UNKNOWN_COMMAND.len();
                rb.reply(rpl::ERR_UNKNOWNCOMMAND, capacity, |msg| {
                    msg.param(command).trailing_param(lines::UNKNOWN_COMMAND);
                });
            } else {
                rb.reply(rpl::ERR_NOTREGISTERED, 2+lines::NOT_REGISTERED.len(), |msg| {
                    msg.trailing_param(lines::NOT_REGISTERED);
                });
            }
            return Ok(2);
        }

        if !msg.has_enough_params() {
            match command {
                Command::Nick | Command::Whois => {
                    rb.reply(rpl::ERR_NONICKNAMEGIVEN, 2+lines::NEED_MORE_PARAMS.len(), |msg| {
                        msg.trailing_param(lines::NEED_MORE_PARAMS);
                    });
                }
                Command::PrivMsg | Command::Notice | Command::TagMsg if msg.num_params == 0 => {
                    rb.reply(rpl::ERR_NORECIPIENT, 2+lines::NEED_MORE_PARAMS.len(), |msg| {
                        msg.trailing_param(lines::NEED_MORE_PARAMS);
                    });
                }
                Command::PrivMsg | Command::Notice if msg.num_params == 1 => {
                    rb.reply(rpl::ERR_NOTEXTTOSEND, 2+lines::NEED_MORE_PARAMS.len(), |msg| {
                        msg.trailing_param(lines::NEED_MORE_PARAMS);
                    });
                }
                _ => {
                    let command = command.as_str();
                    let capacity = 1+command.len() + 2+lines::NEED_MORE_PARAMS.len();
                    rb.reply(rpl::ERR_NEEDMOREPARAMS, capacity, |msg| {
                        msg.param(command).trailing_param(lines::NEED_MORE_PARAMS);
                    });
                }
            }
            return Ok(1);
        }

        if !client.can_issue_command(command, msg.params[0]) {
            if client.is_registered() {
                rb.reply(rpl::ERR_ALREADYREGISTRED, 2+lines::ALREADY_REGISTERED.len(), |msg| {
                    msg.trailing_param(lines::ALREADY_REGISTERED);
                });
            } else {
                rb.reply(rpl::ERR_NOTREGISTERED, 2+lines::NOT_REGISTERED.len(), |msg| {
                    msg.trailing_param(lines::NOT_REGISTERED);
                });
            }
            return Ok(2);
        }

        let sub_command = msg.params[0];
        let cmd_result = self.handle_message_inner(id, &mut rb, msg);

        if !self.clients.contains(id) {
            return Err(());
        }

        let used_points = if cmd_result.is_ok() {
            let client = self.clients.get_mut(id).unwrap();
            let old_state = client.state();
            let new_state = client.apply_command(command, sub_command);
            if new_state.is_registered() && !old_state.is_registered() {
                self.send_welcome(id, &mut rb);
            } else if !old_state.is_registered() {
                log::debug!("{}: {:?} + {:?} == {:?}", id, old_state, command, new_state);
            }
            points_of(command)
        } else {
            points_of(command).saturating_mul(2)
        };
        rb.end_lr();

        Ok(if is_operator {1} else {used_points})
    }

    fn handle_message_inner<'a>(&mut self, id: usize, rb: &'a mut ReplyBuffer, msg: Message<'a>) -> HandlerResult {
        let command = msg.command.unwrap();
        let ps = msg.params;
        let n = msg.num_params;
        let ctx = CommandContext {
            id,
            rb,
            client_tags: msg.tags,
        };

        log::debug!("{}: {} {:?}", id, command, &ps[..n]);
        match command {
            Command::Admin => self.cmd_admin(ctx),
            Command::Authenticate => self.cmd_authenticate(ctx, ps[0]),
            Command::Away => self.cmd_away(ctx, ps[0]),
            Command::Cap => self.cmd_cap(ctx, &ps[..n]),
            Command::Info => self.cmd_info(ctx),
            Command::Invite => self.cmd_invite(ctx, ps[0], ps[1]),
            Command::Join => self.cmd_join(ctx, ps[0], ps[1]),
            Command::Kick => self.cmd_kick(ctx, ps[0], ps[1], ps[2]),
            Command::Kill => self.cmd_kill(ctx, ps[0], ps[1]),
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
            Command::Rehash => self.cmd_rehash(ctx),
            Command::SetName => self.cmd_setname(ctx, ps[0]),
            Command::TagMsg => self.cmd_tagmsg(ctx, ps[0]),
            Command::Time => self.cmd_time(ctx),
            Command::Topic => self.cmd_topic(ctx, ps[0], if n == 1 {None} else {Some(ps[1])}),
            Command::User => self.cmd_user(ctx, ps[0], ps[3]),
            Command::Version => self.cmd_version(ctx),
            Command::Who => self.cmd_who(ctx, ps[0], ps[1]),
            Command::Whois => self.cmd_whois(ctx, ps[0]),
            Command::Reply(_) => Ok(()),
        }
    }

    pub fn remove_if_unregistered(&mut self, id: usize) {
        if let Some(client) = self.clients.get(id) {
            if !client.is_registered() {
                self.nicks.remove(u(client.nick()));
                self.clients.remove(id);
            }
        }
    }
}

fn points_of(command: Command) -> u32 {
    match command {
        Command::Admin => 1,
        Command::Authenticate => 8,
        Command::Away => 4,
        Command::Cap => 1,
        Command::Info => 2,
        Command::Invite => 4,
        Command::Join => 4,
        Command::Kick => 2,
        Command::Kill => 2,
        Command::List => 6,
        Command::Lusers => 2,
        Command::Mode => 2,
        Command::Motd => 2,
        Command::Names => 2,
        Command::Nick => 4,
        Command::Notice => 4,
        Command::Oper => 8,
        Command::Part => 4,
        Command::Pass => 2,
        Command::Ping => 1,
        Command::Pong => 1,
        Command::PrivMsg => 4,
        Command::Quit => 1,
        Command::Rehash => 1,
        Command::SetName => 4,
        Command::TagMsg => 4,
        Command::Time => 2,
        Command::Topic => 3,
        Command::User => 1,
        Command::Version => 1,
        Command::Who => 3,
        Command::Whois => 3,
        Command::Reply(_) => 1,
    }
}

/// Returns `Ok(channel)` when `name` is an existing channel name.  Otherwise returns `Err(())` and
/// send an error to the client.
fn find_channel<'a>(id: usize, rb: &mut ReplyBuffer, channels: &'a ChannelMap, channel_name: &str)
                    -> Result<&'a Channel, ()>
{
    match channels.get(u(channel_name)) {
        Some(channel) => Ok(channel),
        None => {
            log::debug!("{}:         no such channel", id);
            let capacity = 1+channel_name.len() + 2+lines::NO_SUCH_CHANNEL.len();
            rb.reply(rpl::ERR_NOSUCHCHANNEL, capacity, |msg| {
                msg.param(channel_name).trailing_param(lines::NO_SUCH_CHANNEL);
            });
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
            let capacity = 1+channel_name.len() + 2+lines::NOT_ON_CHANNEL.len();
            rb.reply(rpl::ERR_NOTONCHANNEL, capacity, |msg| {
                msg.param(channel_name).trailing_param(lines::NOT_ON_CHANNEL);
            });
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
            rb.reply(rpl::ERR_NOSUCHNICK, 1+nick.len() + 2+lines::NO_SUCH_NICK.len(), |msg| {
                msg.param(nick).trailing_param(lines::NO_SUCH_NICK);
            });
        })
}

// Send utilities
impl StateInner {
    fn build_message(&self, ctx: &mut CommandContext<'_>, from: &Client, cmd: Command, target: &str,
                     content: Option<&str>) -> MessageQueueItem
    {
        let msgid = util::new_message_id();
        let time = util::time_precise();
        let capacity = ctx.client_tags.len() + from.full_name().len() +
            target.len() + content.map_or(0, str::len) + 30;

        if from.capabilities().echo_message && from.capabilities().has_message_tags() {
            ctx.rb.tagged_message(ctx.client_tags, capacity, |msg| {
                let msg = msg.tag("msgid", Some(&msgid))
                    .tag("time", Some(&time))
                    .prefixed_command(from.full_name(), cmd)
                    .param(target);
                if let Some(content) = content {
                    msg.trailing_param(content);
                }
            });
        } else if from.capabilities().echo_message {
            ctx.rb.message(from.full_name(), cmd, capacity, |mut msg| {
                msg = msg.param(target);
                if let Some(content) = content {
                    msg.trailing_param(content);
                }
            });
        }

        let mut buf = Buffer::with_capacity(capacity);
        let mut tags_len = 0;
        {
            let msg_buf = buf.tagged_message(ctx.client_tags)
                .tag("msgid", Some(&msgid))
                .tag("time", Some(&time))
                .save_tags_len(&mut tags_len)
                .prefixed_command(from.full_name(), cmd)
                .param(target);
            if let Some(content) = content {
                msg_buf.trailing_param(content);
            }
        }
        let mut msg = MessageQueueItem::from(buf);
        msg.set_start(tags_len);
        msg
    }

    fn send_query_or_channel_msg(&mut self, mut ctx: CommandContext<'_>, cmd: Command, target: &str,
                                 content: Option<&str>) -> HandlerResult
    {
        let client = &self.clients[ctx.id];

        if content == Some("") {
            let capacity = 1+cmd.as_str().len() + 2+lines::NEED_MORE_PARAMS.len();
            ctx.rb.reply(rpl::ERR_NOTEXTTOSEND, capacity, |msg| {
                msg.param(cmd.as_str()).trailing_param(lines::NEED_MORE_PARAMS);
            });
            return Err(());
        }

        if is_valid_channel_name(target, self.channellen) {
            let channel = find_channel(ctx.id, &mut ctx.rb, &self.channels, target)?;
            if !channel.can_talk(ctx.id) {
                log::debug!("{}:     can't send to channel", ctx.id);
                let capacity = 1+target.len() + 2+lines::CANNOT_SEND_TO_CHAN.len();
                ctx.rb.reply(rpl::ERR_CANNOTSENDTOCHAN, capacity, |msg| {
                    msg.param(target).trailing_param(lines::CANNOT_SEND_TO_CHAN);
                });
                return Err(());
            }

            let msg = self.build_message(&mut ctx, client, cmd, target, content);

            for &id in self.channels[u(target)].members.keys() {
                if id == ctx.id {
                    continue;
                }
                if let Some(client) = self.clients.get(id) {
                    if !client.capabilities().is_capable_of(cmd) {
                        continue;
                    }
                    client.send(msg.clone());
                    client.send(MessageQueueItem::Flush);
                }
            }
        } else {
            let (_, target_client) = find_nick(ctx.id, &mut ctx.rb, &self.clients, &self.nicks, target)?;
            if !target_client.capabilities().is_capable_of(cmd) {
                return Err(());
            }
            let msg = self.build_message(&mut ctx, client, cmd, target, content);

            target_client.send(msg);
            target_client.send(MessageQueueItem::Flush);
            if let Some(ref away_msg) = target_client.away_message {
                ctx.rb.reply(rpl::AWAY, 1+target.len() + 2+away_msg.len(), |msg| {
                    msg.param(target).trailing_param(away_msg);
                });
            }
        }
        self.clients.get_mut(ctx.id).unwrap().update_idle_time();

        Ok(())
    }

    fn send_notification<T, F>(&self, from: usize, msg: T, mut filter: F)
        where T: Into<MessageQueueItem>,
              F: FnMut(usize, &Client) -> bool,
    {
        let msg = msg.into();
        let mut noticed = self.channels.values()
            .filter(|channel| channel.members.contains_key(&from))
            .flat_map(|channel| channel.members.keys().cloned())
            .collect::<HashSet<_>>();
        noticed.insert(from);
        let iter = noticed.into_iter()
            .filter(|&id| from != id && filter(id, &self.clients[id]));
        for id in iter {
            let c = &self.clients[id];
            c.send(msg.clone());
            c.send(MessageQueueItem::Flush);
        }
    }

    fn send_i_support(&self, rb: &mut ReplyBuffer) {
        rb.reply(rpl::ISUPPORT, 222, |msg| {
            msg.param("CASEMAPPING=ascii")
                .param("CHANLIMIT=#:,&:")
                .param("CHANTYPES=#&")
                .param(mode::CHANMODES)
                .param("EXCEPTS")
                .param("HOSTLEN=39")  // max size of an IPv6 address
                .param("INVEX")
                .param("MODES")
                .param("PREFIX=(qaohv)~&@%+")
                .param("SAFELIST")
                .param("TARGMAX=JOIN:,KICK:1,LIST:,NAMES:,NOTICE:1,PART:,PRIVMSG:1,WHOIS:1")
                .trailing_param(lines::I_SUPPORT);
        });

        rb.reply(rpl::ISUPPORT, 110, |mut msg| {
            let _ = write!(msg.raw_param(), "AWAYLEN={}", self.awaylen);
            let _ = write!(msg.raw_param(), "CHANNELLEN={}", self.channellen);
            let _ = write!(msg.raw_param(), "KEYLEN={}", self.keylen);
            let _ = write!(msg.raw_param(), "KICKLEN={}", self.kicklen);
            let _ = write!(msg.raw_param(), "NAMELEN={}", self.namelen);
            let _ = write!(msg.raw_param(), "NICKLEN={}", self.nicklen);
            let _ = write!(msg.raw_param(), "TOPICLEN={}", self.topiclen);
            msg.trailing_param(lines::I_SUPPORT);
        });
    }

    fn send_lusers(&self, rb: &mut ReplyBuffer) {
        rb.reply(rpl::LUSERCLIENT, 42, |msg| {
            lines::luser_client(msg, self.clients.len())
        });

        let (op, unknown) = self.clients.iter().fold((0, 0), |(op, unknown), (_, client)| {
            if !client.is_registered() {
                (op, unknown + 1)
            } else if client.operator {
                (op + 1, unknown)
            } else {
                (op, unknown)
            }
        });
        if 0 < op {
            rb.reply(rpl::LUSEROP, 9 + lines::LUSER_OP.len(), |msg| {
                msg.fmt_param(op).trailing_param(lines::LUSER_OP);
            });
        }
        if 0 < unknown {
            rb.reply(rpl::LUSERUNKNOWN, 9 + lines::LUSER_UNKNOWN.len(), |msg| {
                msg.fmt_param(unknown).trailing_param(lines::LUSER_UNKNOWN);
            });
        }
        if !self.channels.is_empty() {
            let n = self.channels.values().filter(|c| !c.secret).count();
            rb.reply(rpl::LUSERCHANNELS, 9 + lines::LUSER_CHANNELS.len(), |msg| {
                msg.fmt_param(n).trailing_param(lines::LUSER_CHANNELS);
            });
        }
        rb.reply(rpl::LUSERME, 40, |msg| {
            lines::luser_me(msg, self.clients.len())
        });
    }

    fn send_motd(&self, rb: &mut ReplyBuffer) {
        if let Some(ref motd) = self.motd {
            let capacity = self.domain.len() + 25;
            rb.reply(rpl::MOTDSTART, capacity, |msg| lines::motd_start(msg, &self.domain));
            for line in motd.lines() {
                rb.reply(rpl::MOTD, 2+2+line.len(), |mut msg| {
                    let trailing = msg.raw_trailing_param();
                    trailing.push_str("- ");
                    trailing.push_str(line);
                });
            }
            rb.reply(rpl::ENDOFMOTD, 2+lines::END_OF_MOTD.len(), |msg| {
                msg.trailing_param(lines::END_OF_MOTD);
            });
        } else {
            rb.reply(rpl::ERR_NOMOTD, 2+lines::NO_MOTD.len(), |msg| {
                msg.trailing_param(lines::NO_MOTD);
            });
        }
    }

    /// Sends the list of nicknames in the channel `channel_name` to the given client.
    fn send_names(&self, id: usize, rb: &mut ReplyBuffer, channel_name: &str) {
        let channel = match self.channels.get(u(channel_name)) {
            Some(channel) => channel,
            None => return,
        };
        if channel.secret && !channel.members.contains_key(&id) {
            return;
        }

        if !channel.members.is_empty() {
            let client_caps = self.clients[id].capabilities().clone();

            rb.reply(rpl::NAMREPLY, 400, |mut msg| {
                msg = msg.param(channel.symbol()).param(channel_name);
                let trailing = msg.raw_trailing_param();
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
            });
        }
        rb.reply(rpl::ENDOFNAMES, 1+channel_name.len() + 2+lines::END_OF_NAMES.len(), |msg| {
            msg.param(channel_name).trailing_param(lines::END_OF_NAMES);
        });
    }

    /// Sends the topic of the channel `channel_name` to the given client.
    fn send_topic(&self, rb: &mut ReplyBuffer, channel_name: &str, send_error: bool) {
        let channel = &self.channels[u(channel_name)];
        if let Some(ref topic) = channel.topic {
            rb.reply(rpl::TOPIC, 1+channel_name.len() + 2+topic.content.len(), |msg| {
                msg.param(channel_name).trailing_param(&topic.content);
            });
            rb.reply(rpl::TOPICWHOTIME, 1+channel_name.len() + 1+topic.who.len() + 1+10, |msg| {
                msg.param(channel_name)
                    .param(&topic.who)
                    .fmt_param(topic.time);
            });
        } else if send_error {
            rb.reply(rpl::NOTOPIC, 1+channel_name.len() + 2+lines::NO_TOPIC.len(), |msg| {
                msg.param(channel_name).trailing_param(lines::NO_TOPIC);
            });
        }
    }

    /// Sends welcome messages. Called when a client has completed its registration.
    fn send_welcome(&self, id: usize, rb: &mut ReplyBuffer) {
        let client = &self.clients[id];
        rb.reply(rpl::WELCOME, client.full_name().len() + 16, |msg| {
            lines::welcome(msg, client.nick());
        });
        let capacity = self.domain.len() + SERVER_VERSION.len() + 32;
        rb.reply(rpl::YOURHOST, capacity, |msg| {
            lines::your_host(msg, &self.domain, SERVER_VERSION);
        });
        let capacity = self.created_at.len() + 33;
        rb.reply(rpl::CREATED, capacity, |msg| {
            lines::created(msg, &self.created_at);
        });
        let capacity = 1+self.domain.len() + 1+SERVER_VERSION.len() +
            1+mode::USER_MODES.len() + 1+mode::SIMPLE_CHAN_MODES.len() +
            1+mode::EXTENDED_CHAN_MODES.len();
        rb.reply(rpl::MYINFO, capacity, |msg| {
            msg.param(&self.domain)
                .param(SERVER_VERSION)
                .param(mode::USER_MODES)
                .param(mode::SIMPLE_CHAN_MODES)
                .param(mode::EXTENDED_CHAN_MODES);
        });
        self.send_i_support(rb);
        self.send_lusers(rb);
        self.send_motd(rb);
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

/// Whether a nickname must not be taken by a regular user.
#[must_use]
fn is_restricted_nickname(s: &str) -> bool {
    s.len() < 16 && s.ends_with("Serv")
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
