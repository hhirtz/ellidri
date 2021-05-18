//! Shared state and API to handle incoming commands.

#![allow(clippy::needless_pass_by_value)]

use crate::{Channel, Client, config, data, lines, util};
use crate::client::{MessageQueue, MessageQueueItem};
use crate::data::Request;
use ellidri_tokens::{mode, rpl, Buffer, Command, Message, ReplyBuffer};
use ellidri_unicase::{u, UniCase};
use slab::Slab;
use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use std::{fmt, fs, net};
use tokio::sync::{Mutex, Notify};

mod v1;
mod v3;

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
    pub async fn new(config: config::State, rehash: Arc<Notify>) -> Self {
        let inner = StateInner::new(config, rehash).await;
        Self(Arc::new(Mutex::new(inner)))
    }

    /// Reload state configuration.
    ///
    /// `cfg.motd_file` must be the contents of the MOTD file instead of its path.
    pub async fn rehash(&self, cfg: config::State) {
        self.0.lock().await.rehash(cfg);
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
    pub async fn peer_quit(&self, id: usize, err: Option<impl fmt::Display>) {
        self.0.lock().await.peer_quit(id, err);
    }

    /// Updates the state according to the given message from the given client.
    pub async fn handle_message(&self, id: usize, msg: Message<'_>) -> u32 {
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
    password: String,

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

    /// Channel to send rehash notifications
    rehash: Arc<Notify>,
}

impl StateInner {
    pub async fn new(config: config::State, rehash: Arc<Notify>) -> Self {
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
            rehash,
        }
    }

    pub fn rehash(&mut self, config: config::State) {
        self.domain = Arc::from(config.domain);
        self.org_name = config.org_name;
        self.org_location = config.org_location;
        self.org_mail = config.org_mail;
        self.motd = if config.motd_file.is_empty() {
            None
        } else {
            Some(config.motd_file)
        };
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
    }

    pub fn peer_joined(&mut self, addr: net::SocketAddr, queue: MessageQueue) -> usize {
        log::debug!("{}: Connected", addr);
        let client = Client::new(self.domain.clone(), queue, addr.ip().to_string());
        self.clients.insert(client)
    }

    pub fn peer_quit(&mut self, id: usize, err: Option<impl fmt::Display>) {
        log::debug!("{}: Disconnected", id);

        if let Some(err) = err {
            self.remove_client(id, format_args!("{}", err), format_args!("{}", err));
        } else {
            self.remove_client(id, lines::CLOSING_LINK, lines::CONNECTION_RESET);
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
    fn remove_client(&mut self, id: usize, msg_to_client: impl fmt::Display, msg_to_others: impl fmt::Display) {
        if !self.clients.contains(id) {
            return;
        }

        let client = self.clients.remove(id);
        self.nicks.remove(u(client.nick()));

        if client.is_registered() {
            let mut quit_notice = Buffer::new();
            quit_notice.message(client.full_name(), Command::Quit).fmt_trailing_param(msg_to_others);

            let quit_notice = MessageQueueItem::from(quit_notice);
            client.send(quit_notice.clone());
            self.send_notification(id, quit_notice, |_, _| true);

            self.channels.retain(|_, channel| {
                channel.members.remove(&id);
                !channel.members.is_empty()
            });
        }

        let mut error = Buffer::new();
        error.message("", "ERROR").fmt_trailing_param(msg_to_client);
        client.send(error);
    }

    pub fn handle_message(&mut self, id: usize, msg: Message<'_>) -> u32 {
        let client = match self.clients.get(id) {
            Some(client) => client,
            None => return 999_999,
        };

        if MAX_TAG_DATA_LENGTH < msg.tags.len() {
            let mut rb = client.reply("");
            rb
                .reply(rpl::ERR_INPUTTOOLONG)
                .trailing_param(lines::INPUT_TOO_LONG);
            client.send(rb);
            return 3;
        }

        let label = msg.tags()
            .find(|tag| tag.key == "label")
            .and_then(|tag| tag.value)
            .filter(|label| label.len() <= MAX_LABEL_LENGTH)
            .unwrap_or("");

        let mut rb = client.reply(label);
        let is_operator = client.operator;

        let req = match Request::new(&msg) {
            Ok(req) => req,
            Err(data::Error::ErroneousNickname(name)) => {
                rb.reply(rpl::ERR_ERRONEUSNICKNAME).param(name).trailing_param(lines::ERRONEOUS_NICKNAME);
                client.send(rb);
                return 6;
            }
            Err(data::Error::InvalidCap) => {
                rb.reply(Command::Cap).param("NAK").trailing_param(msg.params[1]);
                client.send(rb);
                return 6;
            }
            Err(data::Error::InvalidCapCmd(cmd)) => {
                rb.reply(rpl::ERR_INVALIDCAPCMD).param(cmd).trailing_param(lines::UNKNOWN_COMMAND);
                client.send(rb);
                return 6;
            }
            Err(data::Error::NoSuchChannel(name)) => {
                rb.reply(rpl::ERR_NOSUCHCHANNEL).param(name).trailing_param(lines::NO_SUCH_CHANNEL);
                client.send(rb);
                return 6;
            }
            Err(data::Error::NoSuchNick(name)) => {
                rb.reply(rpl::ERR_NOSUCHNICK).param(name).trailing_param(lines::NO_SUCH_NICK);
                client.send(rb);
                return 6;
            }
            Err(data::Error::NeedMoreParams(command, n)) => {
                match command {
                    Command::Nick | Command::WhoIs => {
                        rb.reply(rpl::ERR_NONICKNAMEGIVEN).trailing_param(lines::NEED_MORE_PARAMS);
                    }
                    Command::PrivMsg | Command::Notice | Command::TagMsg if n == 0 => {
                        rb.reply(rpl::ERR_NORECIPIENT).trailing_param(lines::NEED_MORE_PARAMS);
                    }
                    Command::PrivMsg | Command::Notice if n == 1 => {
                        rb.reply(rpl::ERR_NOTEXTTOSEND).trailing_param(lines::NEED_MORE_PARAMS);
                    }
                    _ => {
                        rb.reply(rpl::ERR_NEEDMOREPARAMS).param(command.as_str()).trailing_param(lines::NEED_MORE_PARAMS);
                    }
                }
                client.send(rb);
                return 6;
            }
            Err(data::Error::UnknownCommand(unknown)) => {
                if client.is_registered() {
                    rb.reply(rpl::ERR_UNKNOWNCOMMAND).param(unknown).trailing_param(lines::UNKNOWN_COMMAND);
                } else {
                    rb.reply(rpl::ERR_NOTREGISTERED).trailing_param(lines::NOT_REGISTERED);
                }
                client.send(rb);
                return 6;
            }
        };

        if !client.can_issue_request(&req) {
            if client.is_registered() {
                rb.reply(rpl::ERR_ALREADYREGISTRED).trailing_param(lines::ALREADY_REGISTERED);
            } else {
                rb.reply(rpl::ERR_NOTREGISTERED).trailing_param(lines::NOT_REGISTERED);
            }
            client.send(rb);
            return 2;
        }

        let points = req.points();
        let ctx = CommandContext {
            id,
            rb: &mut rb,
            client_tags: msg.tags,
        };

        log::debug!("{}: {:?}", id, req);
        let res = match req.clone() {
            // Requests about general server info.
            Request::Admin => self.cmd_admin(ctx),
            Request::Info => self.cmd_info(ctx),
            Request::LUsers => self.cmd_lusers(ctx),
            Request::Motd => self.cmd_motd(ctx),
            Request::Time => self.cmd_time(ctx),
            Request::Version => self.cmd_version(ctx),
            Request::WhoChannel(args) => self.cmd_who_channel(ctx, args),
            Request::WhoMask(args) => self.cmd_who_mask(ctx, args),
            Request::WhoUser(args) => self.cmd_who_user(ctx, args),
            Request::WhoAll(args) => self.cmd_who_all(ctx, args),
            Request::WhoIs(args) => self.cmd_whois(ctx, args),

            // IRCop restricted requests.
            Request::Kill(args) => self.cmd_kill(ctx, args),
            Request::Oper(args) => self.cmd_oper(ctx, args),
            Request::Rehash => self.cmd_rehash(ctx),

            // Requests about channel info.
            Request::List(args) => self.cmd_list(ctx, args),
            Request::ListAll => self.cmd_list_all(ctx),
            Request::Names(args) => self.cmd_names(ctx, args),
            Request::NamesAll => self.cmd_names_all(ctx),
            Request::TopicGet(args) => self.cmd_topic_get(ctx, args),
            Request::TopicSet(args) => self.cmd_topic_set(ctx, args),

            // Client session related requests.
            Request::CapLs(args) => self.cmd_cap_ls(ctx, args),
            Request::CapList => self.cmd_cap_list(ctx),
            Request::CapReq(args) => self.cmd_cap_req(ctx, args),
            Request::CapEnd => self.cmd_cap_end(ctx),
            Request::Pass(args) => self.cmd_pass(ctx, args),
            Request::Ping(args) => self.cmd_ping(ctx, args),
            Request::Pong(args) => self.cmd_pong(ctx, args),
            Request::Quit(args) => self.cmd_quit(ctx, args),
            Request::User(args) => self.cmd_user(ctx, args),

            // Client info related requests.
            Request::Away(args) => self.cmd_away(ctx, args),
            Request::ModeUserGet(args) => self.cmd_mode_user_get(ctx, args),
            Request::ModeUserSet(args) => self.cmd_mode_user_set(ctx, args),
            Request::Nick(args) => self.cmd_nick(ctx, args),
            Request::SetName(args) => self.cmd_setname(ctx, args),

            // Channel management requests.
            Request::Invite(args) => self.cmd_invite(ctx, args),
            Request::Join(args) => self.cmd_join(ctx, args),
            Request::Kick(args) => self.cmd_kick(ctx, args),
            Request::MessageAll(args) => self.cmd_message_all(ctx, args),
            Request::MessageChannel(args) => self.cmd_message_channel(ctx, args),
            Request::MessageUser(args) => self.cmd_message_user(ctx, args),
            Request::ModeChannelGet(args) => self.cmd_mode_channel_get(ctx, args),
            Request::ModeChannelSet(args) => self.cmd_mode_channel_set(ctx, args),
            Request::Part(args) => self.cmd_part(ctx, args),
            Request::PartAll => self.cmd_part_all(ctx),
        };

        if !self.clients.contains(id) {
            // Command handler removed the client from the network state.
            return 999_999;
        }

        let used_points = if res.is_ok() {
            let client = self.clients.get_mut(id).unwrap();
            let old_state = client.state();
            let new_state = client.apply_request(&req);

            if new_state.is_registered() && !old_state.is_registered() {
                log::debug!("{}: {:?} + {:?} == {:?}", id, old_state, msg.command, new_state);
                self.send_welcome(id, &mut rb);
            } else if !old_state.is_registered() {
                log::debug!("{}: {:?} + {:?} == {:?}", id, old_state, msg.command, new_state);
            }

            points
        } else {
            points.saturating_mul(2)
        };

        rb.lr_end();
        if !rb.is_empty() {
            self.clients[id].send(rb);
        }

        if is_operator { 1 } else { used_points }
    }

    pub fn remove_if_unregistered(&mut self, id: usize) {
        if let Some(client) = self.clients.get(id) {
            if !client.is_registered() {
                self.remove_client(id, lines::REGISTRATION_TIMEOUT, "");
            }
        }
    }
}

/// Returns `Ok(channel)` when `name` is an existing channel name.  Otherwise returns `Err(())`.
fn find_channel_quiet<'a>(
    id: usize,
    channels: &'a ChannelMap,
    channel_name: data::ChannelName<'_>,
) -> Result<&'a Channel, ()> {
    match channels.get(channel_name.u()) {
        Some(channel) => Ok(channel),
        None => {
            log::debug!("{}:         no such channel", id);
            Err(())
        }
    }
}

/// Returns `Ok(channel)` when `name` is an existing channel name.  Otherwise returns `Err(())` and
/// send an error to the client.
fn find_channel<'a>(
    id: usize,
    rb: &mut ReplyBuffer,
    channels: &'a ChannelMap,
    channel_name: data::ChannelName<'_>,
) -> Result<&'a Channel, ()> {
    match find_channel_quiet(id, channels, channel_name) {
        Ok(channel) => Ok(channel),
        Err(()) => {
            rb.reply(rpl::ERR_NOSUCHCHANNEL).param(channel_name.get()).trailing_param(lines::NO_SUCH_CHANNEL);
            Err(())
        }
    }
}

/// Returns `Ok(member_modes)` when the client identified by `addr` is in the given `channel`.
/// Otherwise returns `Err(())` and send an error to the client.
///
/// `channel_name` is needed for the error reply.
fn find_member(
    id: usize,
    rb: &mut ReplyBuffer,
    channel: &Channel,
    channel_name: data::ChannelName<'_>,
) -> Result<crate::channel::MemberModes, ()> {
    match channel.members.get(&id) {
        Some(modes) => Ok(*modes),
        None => {
            log::debug!("{}:         not on {:?}", id, channel_name.get());
            rb.reply(rpl::ERR_NOTONCHANNEL).param(channel_name.get()).trailing_param(lines::NOT_ON_CHANNEL);
            Err(())
        }
    }
}

/// Returns `Ok((address, client))` when the client identified by the nickname `nick` is connected
/// and registered.  Otherwise returns `Err(())` and send an error to the client.
fn find_nick<'a>(
    id: usize,
    rb: &mut ReplyBuffer,
    clients: &'a ClientMap,
    nicks: &'a NicksMap,
    nick: data::Nickname<'_>,
) -> Result<(usize, &'a Client), ()> {
    nicks
        .get(nick.u())
        .map(|id| (*id, &clients[*id]))
        .filter(|(_, c)| c.is_registered())
        .ok_or_else(|| {
            log::debug!("{}:         nick doesn't exist", id);
            rb.reply(rpl::ERR_NOSUCHNICK).param(nick.get()).trailing_param(lines::NO_SUCH_NICK);
        })
}

// Send utilities
impl StateInner {
    fn send_notification(
        &self,
        issuer: usize,
        buf: impl Into<MessageQueueItem>,
        mut filter: impl FnMut(usize, &Client) -> bool,
    ) {
        let msg = buf.into();

        let noticed = self
            .channels
            .values()
            .filter(|channel| channel.members.contains_key(&issuer))
            .flat_map(|channel| channel.members.keys().cloned())
            .collect::<HashSet<_>>();

        for target_id in noticed {
            let target = match self.clients.get(target_id) {
                Some(target) => target,
                None => continue,
            };

            if issuer == target_id || !filter(target_id, target) {
                continue;
            }

            target.send(msg.clone());
        }
    }

    fn send_i_support(&self, rb: &mut ReplyBuffer) {
        rb.reply(rpl::ISUPPORT)
            .param("CASEMAPPING=ascii")
            .param("CHANLIMIT=#&:")
            .param("CHANTYPES=#&")
            .param(mode::CHANMODES)
            .param("EXCEPTS")
            .param("HOSTLEN=39") // max size of an IPv6 address
            .param("INVEX")
            .param("MODES")
            .param("PREFIX=(qaohv)~&@%+")
            .param("SAFELIST")
            .param("TARGMAX=JOIN:,KICK:,LIST:,NAMES:,NOTICE:1,PART:,PRIVMSG:1,WHOIS:1")
            .fmt_param(format_args!("AWAYLEN={}", self.awaylen))
            .fmt_param(format_args!("CHANNELLEN={}", self.channellen))
            .trailing_param(lines::I_SUPPORT);
        rb.reply(rpl::ISUPPORT)
            .fmt_param(format_args!("KEYLEN={}", self.keylen))
            .fmt_param(format_args!("KICKLEN={}", self.kicklen))
            .fmt_param(format_args!("NAMELEN={}", self.namelen))
            .fmt_param(format_args!("NICKLEN={}", self.nicklen))
            .fmt_param(format_args!("TOPICLEN={}", self.topiclen))
            .trailing_param(lines::I_SUPPORT);
    }

    fn send_lusers(&self, id: usize, rb: &mut ReplyBuffer) {
        rb.reply(rpl::LUSERCLIENT)
            .fmt_trailing_param(lines_luser_client!(self.clients.len()));

        let (op, unknown) = self
            .clients
            .iter()
            .fold((0, 0), |(op, unknown), (_, client)| {
                if !client.is_registered() {
                    (op, unknown + 1)
                } else if client.operator {
                    (op + 1, unknown)
                } else {
                    (op, unknown)
                }
            });
        if 0 < op {
            rb.reply(rpl::LUSEROP)
                .fmt_param(op)
                .trailing_param(lines::LUSER_OP);
        }
        if 0 < unknown {
            rb.reply(rpl::LUSERUNKNOWN)
                .fmt_param(&unknown)
                .trailing_param(lines::LUSER_UNKNOWN);
        }

        let channels = self
            .channels
            .values()
            .filter(|c| !c.secret || c.members.contains_key(&id))
            .count();
        if 0 < channels {
            rb.reply(rpl::LUSERCHANNELS)
                .fmt_param(channels)
                .trailing_param(lines::LUSER_CHANNELS);
        }

        rb.reply(rpl::LUSERME)
            .fmt_trailing_param(lines_luser_me!(self.clients.len()));
    }

    fn send_motd(&self, rb: &mut ReplyBuffer) {
        if let Some(ref motd) = self.motd {
            rb.reply(rpl::MOTDSTART)
                .fmt_trailing_param(lines_motd_start!(&self.domain));

            for line in motd.lines() {
                rb.reply(rpl::MOTD)
                    .fmt_trailing_param(format_args!("- {}", line));
            }

            rb.reply(rpl::ENDOFMOTD).trailing_param(lines::END_OF_MOTD);
        } else {
            rb.reply(rpl::ERR_NOMOTD).trailing_param(lines::NO_MOTD);
        }
    }

    /// Sends the list of nicknames in the channel `channel_name` to the given client.
    fn send_names(&self, id: usize, rb: &mut ReplyBuffer, channel_name: data::ChannelName<'_>) {
        let channel = match self.channels.get(channel_name.u()) {
            Some(channel) => channel,
            None => return,
        };
        if channel.secret && !channel.members.contains_key(&id) {
            return;
        }

        if !channel.members.is_empty() {
            let client_caps = self.clients[id].cap_enabled;

            let mut msg = rb.reply(rpl::NAMREPLY)
                .param(channel.symbol())
                .param(channel_name.get());

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

            trailing.pop(); // Remove last space, not ':' since !channel.members.is_empty()
        }

        rb.reply(rpl::ENDOFNAMES).param(channel_name.get()).trailing_param(lines::END_OF_NAMES);
    }

    /// Sends the topic of the channel `channel_name` to the given client.
    fn send_topic(&self, rb: &mut ReplyBuffer, channel_name: data::ChannelName<'_>, send_error: bool) {
        let channel = &self.channels[channel_name.u()];

        if let Some(ref topic) = channel.topic {
            rb.reply(rpl::TOPIC).param(channel_name.get()).trailing_param(&topic.content);
            rb.reply(rpl::TOPICWHOTIME).param(channel_name.get()).param(&topic.who).fmt_param(topic.time);
        } else if send_error {
            rb.reply(rpl::NOTOPIC).param(channel_name.get()).trailing_param(lines::NO_TOPIC);
        }
    }

    /// Sends welcome messages. Called when a client has completed its registration.
    fn send_welcome(&self, id: usize, rb: &mut ReplyBuffer) {
        let client = &self.clients[id];

        rb.lr_batch_begin();
        rb.reply(rpl::WELCOME).fmt_trailing_param(lines_welcome!(client.nick()));
        rb.reply(rpl::YOURHOST).fmt_trailing_param(lines_your_host!(&self.domain, SERVER_VERSION));
        rb.reply(rpl::CREATED).fmt_trailing_param(lines_created!(&self.created_at));
        rb.reply(rpl::MYINFO)
            .param(&self.domain)
            .param(SERVER_VERSION)
            .param(mode::USER_MODES)
            .param(mode::SIMPLE_CHAN_MODES)
            .param(mode::EXTENDED_CHAN_MODES);
        self.send_i_support(rb);
        self.send_lusers(id, rb);
        self.send_motd(rb);
    }
}
