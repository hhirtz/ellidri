//! Shared state and API to handle incoming commands.

use std::collections::{HashMap, HashSet};
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};

use chrono::{DateTime, Local};
use futures::sync::mpsc;

use crate::channel::Channel;
use crate::client::Client;
use crate::config::{AdminInfo, StateConfig};
use crate::lines;
use crate::message::{Command, Message, MessageBuilder, MessageQueueItem, Params, Reply, rpl,
                     ResponseBuffer};
use crate::misc::UniCase;
use crate::modes;

const SERVER_INFO: &str = include_str!("info.txt");
const SERVER_VERSION: &str = concat!(env!("CARGO_PKG_NAME"), "-", env!("CARGO_PKG_VERSION"));
const MAX_CHANNEL_NAME_LENGTH: usize = 50;
const MAX_NICKNAME_LENGTH: usize = 9;

pub type MessageQueue = mpsc::UnboundedSender<MessageQueueItem>;

/// Shared state of the IRC server.
///
/// It's a pointer to the actual data, so it's cheap to clone.
#[derive(Clone)]
pub struct State(Arc<Mutex<StateInner>>);

impl State {
    /// Initialize a new state with the given `prefix` and `motd`.
    ///
    /// `prefix` is the domain of the server. It's used as prefix for most replies.  `motd` is the
    /// message of the day.
    ///
    /// # TODO
    ///
    /// Make it accept a "config" struct, or use a builder pattern.
    pub fn new(config: StateConfig) -> State {
        let inner = StateInner::new(config);
        State(Arc::new(Mutex::new(inner)))
    }

    /// Adds a new client into the state.
    ///
    /// Called when a connection is accepted.
    pub fn insert(&self, addr: SocketAddr, queue: MessageQueue) {
        self.0.lock().unwrap().clients.insert(addr, Client::new(queue, addr.ip().to_string()));
    }

    /// Removes a client from the state.
    ///
    /// Called when a connection drops, or the client issued a "QUIT" message.
    pub fn remove(&self, addr: SocketAddr) {
        self.0.lock().unwrap().remove(addr);
    }

    /// Creates a message with the given `cmd` and `params`, and send it to the given client.
    pub fn send_command(&self, addr: SocketAddr, cmd: Command, params: &[&str]) {
        self.0.lock().unwrap().send_command(addr, cmd, params);
    }

    /// Creates a message with the given `reply` and `params`, and send it to the given client.
    ///
    /// It also adds the client's nickname as the first argument.
    pub fn send_reply(&self, addr: SocketAddr, reply: Reply, params: &[&str]) {
        self.0.lock().unwrap().send_reply(addr, reply, params);
    }

    /// Returns true when the given client can issue the given command.
    ///
    /// This depends of the "state" the connection is in. For example, if a client has not sent a
    /// "NICK" and an "USER" message, it cannot send a "JOIN" message.
    pub fn can_issue_command(&self, addr: SocketAddr, cmd: Command) -> bool {
        self.0.lock().unwrap().clients[&addr].can_issue_command(cmd)
    }

    // Command handlers

    pub fn cmd_admin(&self, addr: SocketAddr) {
        self.0.lock().unwrap().cmd_admin(addr);
    }

    pub fn cmd_info(&self, addr: SocketAddr) {
        self.0.lock().unwrap().cmd_info(addr);
    }

    pub fn cmd_invite(&self, addr: SocketAddr, nick: &str, channel: &str) {
        self.0.lock().unwrap().cmd_invite(addr, nick, channel);
    }

    pub fn cmd_join(&self, addr: SocketAddr, targets: &str, keys: Option<&str>) {
        let mut lock = self.0.lock().unwrap();
        let mut keys = keys.unwrap_or("").split(',');
        for target in targets.split(',') {
            lock.cmd_join(addr, target, keys.next());
        }
    }

    pub fn cmd_list(&self, addr: SocketAddr, targets: Option<&str>) {
        self.0.lock().unwrap().cmd_list(addr, targets.unwrap_or(""));
    }

    pub fn cmd_lusers(&self, addr: SocketAddr) {
        self.0.lock().unwrap().cmd_lusers(addr);
    }

    pub fn cmd_mode(&self, addr: SocketAddr, target: &str,
                    modes: Option<&str>, modeparams: Params<'_>)
    {
        self.0.lock().unwrap().cmd_mode(addr, target, modes, modeparams);
    }

    pub fn cmd_motd(&self, addr: SocketAddr) {
        self.0.lock().unwrap().cmd_motd(addr);
    }

    pub fn cmd_names(&self, addr: SocketAddr, targets: Option<&str>) {
        self.0.lock().unwrap().cmd_names(addr, targets.unwrap_or(""));
    }

    pub fn cmd_nick(&self, addr: SocketAddr, nick: &str) {
        self.0.lock().unwrap().cmd_nick(addr, nick);
    }

    pub fn cmd_notice(&self, addr: SocketAddr, targets: &str, content: &str) {
        let lock = self.0.lock().unwrap();
        for target in targets.split(',') {
            lock.cmd_notice(addr, target, content);
        }
    }

    pub fn cmd_oper(&self, addr: SocketAddr, name: &str, password: &str) {
        self.0.lock().unwrap().cmd_oper(addr, name, password);
    }

    pub fn cmd_part(&self, addr: SocketAddr, targets: &str, reason: Option<&str>) {
        let mut lock = self.0.lock().unwrap();
        for target in targets.split(',') {
            lock.cmd_part(addr, target, reason);
        }
    }

    pub fn cmd_pass(&self, addr: SocketAddr, password: &str) {
        self.0.lock().unwrap().cmd_pass(addr, password);
    }

    pub fn cmd_privmsg(&self, addr: SocketAddr, targets: &str, content: &str) {
        let lock = self.0.lock().unwrap();
        for target in targets.split(',') {
            lock.cmd_privmsg(addr, target, content);
        }
    }

    pub fn cmd_quit(&self, addr: SocketAddr, reason: Option<&str>) {
        self.0.lock().unwrap().cmd_quit(addr, reason);
    }

    pub fn cmd_time(&self, addr: SocketAddr) {
        self.0.lock().unwrap().cmd_time(addr);
    }

    pub fn cmd_topic(&self, addr: SocketAddr, target: &str, topic: Option<&str>) {
        self.0.lock().unwrap().cmd_topic(addr, target, topic);
    }

    pub fn cmd_user(&self, addr: SocketAddr, user: &str, real: &str,
                    invisible: bool, wallops: bool)
    {
        self.0.lock().unwrap().cmd_user(addr, user, real, invisible, wallops);
    }

    pub fn cmd_version(&self, addr: SocketAddr) {
        self.0.lock().unwrap().cmd_version(addr);
    }
}

/// The actual shared data (state) of the IRC server.
///
/// It is hidden behind the `State` pointer. Most of its methods are wrapped by `State`'s methods
/// (that just lock reads or writes to the data).
///
/// Most command handling methods are split in two: one that checks whether the given client can
/// issue the command (depending on the given parameters), and the other that actually executes the
/// command.
///
/// The first set of methods have names like `check_cmd_$command`, the other have names like
/// `apply_cmd_$command`.
struct StateInner {
    /// The domain of the server. This string is used as a prefix for most replies and commands
    /// sent to clients.
    domain: String,

    /// Information about the administrators of the server. Sent as a reply to the ADMIN command.
    admin: AdminInfo,

    /// The set of clients, identified by their socket address.
    clients: HashMap<SocketAddr, Client>,

    /// The set of channels, identified by their case-insensitive name.
    channels: HashMap<UniCase<String>, Channel>,

    /// The UTC local time when the `StateInner` instance is created. It is sent to the client when
    /// they register (in a "003 RPL_CREATED" reply, as per the RFC).
    created_at: DateTime<Local>,

    /// The message of the day.
    motd: Option<String>,

    /// The global password. Clients need to issue a PASS command with this password to register.
    password: Option<String>,

    /// Modes applied at the creation of new channels.
    default_chan_mode: String,

    opers: Vec<(String, String)>,
    //oper_hosts: Vec<String>,
}

impl StateInner {
    /// Creates a new shared state. See `State::new`.
    pub fn new(config: StateConfig) -> StateInner {
        StateInner {
            domain: config.domain,
            admin: config.admin,
            clients: HashMap::new(),
            channels: HashMap::new(),
            created_at: Local::now(),
            motd: config.motd,
            password: config.password,
            default_chan_mode: config.default_chan_mode,
            opers: config.opers,
            //oper_hosts: config.oper_hosts,
        }
    }

    /// Removes a client from the state. See `State::remove`.
    pub fn remove(&mut self, addr: SocketAddr) {
        let client = self.clients.remove(&addr).unwrap();
        let msg = Message::with_prefix(client.full_name(), Command::Quit)
            .trailing_param(client.quit_message())
            .into_bytes();
        for chan in self.channels.values() {
            if chan.quiet { continue; }
            if chan.members.contains_key(&addr) {
                for &member in chan.members.keys() {
                    self.send(member, msg.clone());
                }
            }
        }

        self.channels.retain(|_, chan| {
            chan.members.remove(&addr);
            !chan.members.is_empty()
        });
    }
}

// Send utilities
impl StateInner {
    /// Sends the given message to all users in the given channel.
    pub fn broadcast(&self, target: &str, msg: MessageQueueItem) {
        let chan = &self.channels[<&UniCase<str>>::from(target)];
        for &member in chan.members.keys() {
            self.send(member, msg.clone());
        }
    }

    /// Sends the given message to the given client.
    pub fn send(&self, addr: SocketAddr, msg: MessageQueueItem) {
        if let Some(client) = self.clients.get(&addr) {
            client.send(msg);
        }
    }

    /// Creates a message from the given command and parameters, and sends it to the given client.
    pub fn send_command(&self, addr: SocketAddr, cmd: Command, params: &[&str]) {
        if let Some(client) = self.clients.get(&addr) {
            let mut msg = Message::with_prefix(&self.domain, cmd);
            let msg = if !params.is_empty() {
                for p in &params[..params.len() - 1] {
                    msg = msg.param(p);
                }
                msg.trailing_param(params[params.len() - 1])
            } else {
                msg.build()
            };
            client.send(msg.into_bytes());
        }
    }

    /// Creates a message from the given reply and parameters, and sends it to the given client.
    ///
    /// It also adds the client's nick as the first parameter, as it is needed for server replies.
    pub fn send_reply(&self, addr: SocketAddr, reply: Reply, params: &[&str]) {
        if let Some(client) = self.clients.get(&addr) {
            let mut msg = Message::with_prefix(&self.domain, Command::Reply(reply))
                .param(client.nick());
            let msg = if !params.is_empty() {
                for p in &params[..params.len() - 1] {
                    msg = msg.param(p);
                }
                msg.trailing_param(params[params.len() - 1])
            } else {
                msg.build()
            };
            client.send(msg.into_bytes());
        }
    }

    fn send_i_support(&self, response: &mut ResponseBuffer, nick: &str) {
        response.message(&self.domain, rpl::ISUPPORT)
            .param(nick)
            .param("CASEMAPPING=ascii")
            .param(format!("CHANLEN={}", MAX_CHANNEL_NAME_LENGTH))
            .param(modes::CHANMODES)
            .param("EXCEPTS")
            .param("INVEX")
            .param("MODES")
            .param(format!("NICKLEN={}", MAX_NICKNAME_LENGTH))
            .trailing_param(lines::I_SUPPORT);
    }

    /// Sends the list of nicknames in the channel `chan_name` to the given client.
    fn send_names(&self, addr: SocketAddr, chan_name: &str) {
        if let Some(chan) = &self.channels.get(<&UniCase<str>>::from(chan_name)) {
            if chan.secret && !chan.members.contains_key(&addr) { return; }
            let client = &self.clients[&addr];
            let mut response = ResponseBuffer::new();
            if !chan.quiet && !chan.members.is_empty() {
                let mut message = response.message(&self.domain, rpl::NAMREPLY)
                    .param(client.nick())
                    .param(chan.symbol())
                    .param(chan_name);
                let trailing = message.raw_trailing_param();
                let mut members = chan.members.iter();
                if let Some((member, modes)) = members.next() {
                    if let Some(s) = modes.symbol() { trailing.push(s); }
                    trailing.push_str(self.clients[member].nick());
                    for (member, modes) in members {
                        trailing.push(' ');
                        if let Some(s) = modes.symbol() { trailing.push(s); }
                        trailing.push_str(self.clients[member].nick());
                    }
                }
                message.build();
            } else if chan.quiet && chan.members.contains_key(&addr) {
                let mut message = response.message(&self.domain, rpl::NAMREPLY)
                    .param(client.nick())
                    .param(chan.symbol())
                    .param(chan_name);
                let trailing = message.raw_trailing_param();
                if let Some(s) = chan.members[&addr].symbol() { trailing.push(s); }
                trailing.push_str(client.nick());
                message.build();
            }
            response.message(&self.domain, rpl::ENDOFNAMES)
                .param(client.nick())
                .param(chan_name)
                .trailing_param(lines::END_OF_NAMES);
            self.send(addr, response.build());
        }
    }

    /// Sends the topic of the channel `chan_name` to the given client.
    fn send_topic(&self, addr: SocketAddr, chan_name: &str) {
        let chan = &self.channels[<&UniCase<str>>::from(chan_name)];
        if let Some(ref topic) = chan.topic {
            self.send_reply(addr, rpl::TOPIC, &[chan_name, topic]);
        } else {
            self.send_reply(addr, rpl::NOTOPIC, &[chan_name, lines::NO_TOPIC]);
        }
    }

    /// Sends welcome messages. Called when a client has completed its registration.
    fn send_welcome(&self, addr: SocketAddr) {
        let client = &self.clients[&addr];
        let mut response = ResponseBuffer::new();
        response.message(&self.domain, rpl::WELCOME)
            .param(client.nick())
            .trailing_param(lines::WELCOME);
        response.message(&self.domain, rpl::YOURHOST)
            .param(client.nick())
            .trailing_param(lines::YOUR_HOST);
        lines::created(response.message(&self.domain, rpl::CREATED)
            .param(client.nick()), &self.created_at);
        response.message(&self.domain, rpl::MYINFO)
            .param(client.nick())
            .param(&self.domain)
            .param(SERVER_VERSION)
            .param(modes::USER_MODES)
            .param(modes::SIMPLE_CHAN_MODES)
            .param(modes::EXTENDED_CHAN_MODES)
            .build();
        self.send_i_support(&mut response, client.nick());
        client.send(response.build());
        self.cmd_lusers(addr);
        self.cmd_motd(addr);
    }
}

// Command handlers
impl StateInner {
    // ADMIN

    pub fn cmd_admin(&self, addr: SocketAddr) {
        log::debug!("{}: Request admin", addr);
        let client = &self.clients[&addr];
        let mut response = ResponseBuffer::new();
        response.message(&self.domain, rpl::ADMINME)
            .param(client.nick())
            .param(&self.domain)
            .trailing_param(lines::ADMIN_ME);
        response.message(&self.domain, rpl::ADMINLOC1)
            .param(client.nick())
            .trailing_param(&self.admin.location);
        response.message(&self.domain, rpl::ADMINLOC2)
            .param(client.nick())
            .trailing_param(&self.admin.org_name);
        response.message(&self.domain, rpl::ADMINMAIL)
            .param(client.nick())
            .trailing_param(&self.admin.mail);
        client.send(response.build());
    }

    // INFO

    pub fn cmd_info(&self, addr: SocketAddr) {
        let client = &self.clients[&addr];
        let mut response = ResponseBuffer::new();
        for line in SERVER_INFO.lines() {
            response.message(&self.domain, rpl::INFO)
                .param(client.nick())
                .trailing_param(line);
        }
        response.message(&self.domain, rpl::ENDOFINFO)
            .param(client.nick())
            .trailing_param(lines::END_OF_INFO);
        client.send(response.build());
    }

    // INVITE

    fn apply_cmd_invite(&mut self, addr: SocketAddr, target_addr: SocketAddr,
                            target_nick: &str, channel: &str) {
        let invited = if let Some(chan) = self.channels.get_mut(<&UniCase<str>>::from(channel)) {
            chan.invites.insert(target_addr)
        } else {
            true
        };
        if invited {
            let client = &self.clients[&addr];
            let mut response = ResponseBuffer::new();
            response.message(&self.domain, rpl::INVITING)
                .param(client.nick())
                .param(channel)
                .param(target_nick)
                .build();
            client.send(response.build());
            let mut target_res = ResponseBuffer::new();
            target_res.message(client.full_name(), Command::Invite)
                .param(target_nick)
                .param(channel)
                .build();
            self.clients[&target_addr].send(target_res.build());
        }
    }

    pub fn cmd_invite(&mut self, addr: SocketAddr, nick: &str, channel: &str) {
        if let Some(&target) = self.clients.iter().find(|(_,c)| c.nick() == nick).map(|(a,_)| a) {
            if let Some(chan) = self.channels.get(<&UniCase<str>>::from(channel)) {
                if let Some(ref modes) = chan.members.get(&addr) {
                    if !chan.invite_only || modes.operator {
                        self.apply_cmd_invite(addr, target, nick, channel);
                    } else {
                        self.send_reply(addr, rpl::ERR_CHANOPRIVSNEEDED,
                                        &[channel, lines::CHAN_O_PRIVS_NEEDED]);
                        return;
                    }
                } else {
                    self.send_reply(addr, rpl::ERR_NOTONCHANNEL,
                                    &[channel, lines::NOT_ON_CHANNEL_TOPIC]);
                    return;
                }
            } else {
                self.apply_cmd_invite(addr, target, nick, channel);
            }
        } else {
            self.send_reply(addr, rpl::ERR_NOSUCHNICK, &[nick, lines::NO_SUCH_NICK]);
        }
    }

    // JOIN

    pub fn cmd_join(&mut self, addr: SocketAddr, target: &str, key: Option<&str>) {
        if !is_valid_channel_name(target) {
            log::debug!("{}: Can't join {:?}: Invalid channel name", addr, target);
            self.send_reply(addr, rpl::ERR_NOSUCHCHANNEL, &[target, lines::NO_SUCH_CHANNEL]);
            return;
        }
        if let Some(chan) = self.channels.get(<&UniCase<str>>::from(target)) {
            let nick = self.clients[&addr].nick();
            if chan.key.as_ref().map_or(false, |ck| key.map_or(true, |k| ck != k)) {
                log::debug!("{}: Can't join {:?}: Bad key", addr, target);
                self.send_reply(addr, rpl::ERR_BADCHANKEY,
                                &[target, lines::BAD_CHAN_KEY]);
                return;
            }
            if chan.user_limit.map_or(false, |user_limit| user_limit <= chan.members.len()) {
                log::debug!("{}: Can't join {:?}: user limit reached", addr, target);
                self.send_reply(addr, rpl::ERR_CHANNELISFULL,
                                &[target, lines::CHANNEL_IS_FULL]);
                return;
            }
            if !chan.is_invited(addr, nick) {
                log::debug!("{}: Can't join {:?}: not invited", addr, target);
                self.send_reply(addr, rpl::ERR_INVITEONLYCHAN,
                                &[target, lines::INVITE_ONLY_CHAN]);
                return;
            }
            if chan.is_banned(nick) {
                log::debug!("{}: Can't join {:?}: Banned", addr, target);
                self.send_reply(addr, rpl::ERR_BANNEDFROMCHAN,
                                &[target, lines::BANNED_FROM_CHAN]);
                return;
            }
        }
        log::debug!("{}: Join {}", addr, target);
        let default_chan_mode = &self.default_chan_mode;
        let chan = self.channels.entry(UniCase(target.to_owned()))
            .or_insert_with(|| Channel::new(&default_chan_mode));
        chan.add_member(addr);
        let client = &self.clients[&addr];
        let join = Message::with_prefix(client.full_name(), Command::Join)
            .param(target)
            .build()
            .into_bytes();
        if chan.quiet {
            client.send(join);
        } else {
            self.broadcast(target, join);
        }
        self.send_topic(addr, target);
        self.send_names(addr, target);
    }

    // LIST

    pub fn cmd_list(&self, addr: SocketAddr, targets: &str) {
        log::debug!("{}: get list of {:?}", addr, targets);
        let client = &self.clients[&addr];
        let mut response = ResponseBuffer::new();
        if targets.is_empty() {
            for (name, channel) in self.channels.iter() {
                if channel.secret && !channel.members.contains_key(&addr) { continue; }
                let msg = response.message(&self.domain, rpl::LIST)
                    .param(client.nick())
                    .param(name);
                channel.list_entry(msg);
            }
        } else {
            for name in targets.split(',') {
                if let Some(channel) = self.channels.get(<&UniCase<str>>::from(name)) {
                    if channel.secret && !channel.members.contains_key(&addr) { continue; }
                    let msg = response.message(&self.domain, rpl::LIST)
                        .param(client.nick())
                        .param(name);
                    channel.list_entry(msg);
                }
            }
        }
        response.message(&self.domain, rpl::LISTEND)
            .param(client.nick())
            .trailing_param(lines::END_OF_LIST);
        client.send(response.build());
    }

    // LUSERS

    pub fn cmd_lusers(&self, addr: SocketAddr) {
        log::debug!("{}: Request lusers", addr);
        let client = &self.clients[&addr];
        let mut response = ResponseBuffer::new();
        let cs = self.clients.len();
        lines::luser_client(response.message(&self.domain, rpl::LUSERCLIENT)
            .param(client.nick()), cs);
        // TODO LUSEROP
        // TODO LUSERUNKNOWN
        if !self.channels.is_empty() {
            response.message(&self.domain, rpl::LUSERCHANNELS)
                .param(client.nick())
                .param(self.channels.values().filter(|c| !c.secret).count().to_string())
                .trailing_param(lines::LUSER_CHANNELS);
        }
        lines::luser_me(response.message(&self.domain, rpl::LUSERME).param(client.nick()), cs);
        client.send(response.build());
    }

    // MODE

    fn apply_cmd_mode_chan_get(&self, addr: SocketAddr, target: &str) {
        log::debug!("{}: getting modes of {:?}", addr, target);
        if let Some(chan) = self.channels.get(<&UniCase<str>>::from(target)) {
            let client = &self.clients[&addr];
            let mut response = ResponseBuffer::new();
            let msg = response.message(&self.domain, rpl::CHANNELMODEIS)
                .param(client.nick())
                .param(target);
            chan.modes(msg, chan.members.contains_key(&addr));
            client.send(response.build());
        } else {
            self.send_reply(addr, rpl::ERR_NOSUCHCHANNEL, &[target, lines::NO_SUCH_CHANNEL]);
        }
    }

    fn check_cmd_mode_chan_set(&self, addr: SocketAddr, target: &str) -> bool {
        if let Some(chan) = self.channels.get(<&UniCase<str>>::from(target)) {
            if let Some(modes) = chan.members.get(&addr) {
                if modes.operator {
                    true
                } else {
                    log::debug!("{}: can't set modes of {:?}: not operator", addr, target);
                    self.send_reply(addr, rpl::ERR_CHANOPRIVSNEEDED,
                                    &[target, lines::CHAN_O_PRIVS_NEEDED]);
                    false
                }
            } else {
                log::debug!("{}: can't set modes of {:?}: not in channel", addr, target);
                let nick = self.clients[&addr].nick();
                self.send_reply(addr, rpl::ERR_USERNOTINCHANNEL,
                                &[nick, target, lines::USER_NOT_IN_CHANNEL]);
                false
            }
        } else {
            log::debug!("{}: can't set modes of {:?}: no such channel", addr, target);
            self.send_reply(addr, rpl::ERR_NOSUCHCHANNEL, &[target, lines::NO_SUCH_CHANNEL]);
            false
        }
    }

    fn apply_cmd_mode_chan_set(&mut self, addr: SocketAddr, target: &str,
                               modes: &str, modeparams: Params<'_>)
    {
        log::debug!("{}: settings modes of {:?} to {:?} (params eluded)",
                    addr, target, modes);
        let modes = modes.trim();
        if modes.is_empty() {
            // Received a "MODE #chan :", nothing left to be done...
            return;
        }
        let mut applied_modes = String::new();
        let mut applied_modeparams = Vec::new();
        let mut response = ResponseBuffer::new();
        let chan = self.channels.get_mut(<&UniCase<str>>::from(target)).unwrap();
        let clients = &self.clients;
        for maybe_change in modes::ChannelQuery::new(modes, modeparams) { match maybe_change {
            Ok(modes::ChannelModeChange::GetBans) => {
                response.list(&self.domain, rpl::BANLIST, rpl::ENDOFBANLIST,
                              lines::END_OF_BAN_LIST, &chan.ban_mask,
                              |msg| msg.param(clients[&addr].nick()).param(target));
            }
            Ok(modes::ChannelModeChange::GetExceptions) => {
                response.list(&self.domain, rpl::EXCEPTLIST, rpl::ENDOFEXCEPTLIST,
                              lines::END_OF_EXCEPT_LIST, &chan.exception_mask,
                              |msg| msg.param(clients[&addr].nick()).param(target));
            }
            Ok(modes::ChannelModeChange::GetInvitations) => {
                response.list(&self.domain, rpl::INVITELIST, rpl::ENDOFINVITELIST,
                              lines::END_OF_INVITE_LIST, &chan.invitation_mask,
                              |msg| msg.param(clients[&addr].nick()).param(target));
            }
            Ok(change) => match chan.apply_mode_change(change, |a| clients[a].nick()) {
                Ok(true) => {
                    log::debug!("  - Applied {:?}", change);
                    if let Some(symbol) = change.symbol() {
                        applied_modes.push(if change.value() {'+'} else {'-'});
                        applied_modes.push(symbol);
                    }
                    if let Some(param) = change.param() {
                        applied_modeparams.push(param.to_owned());
                    }
                }
                Ok(false) => {}
                Err(rpl::ERR_USERNOTINCHANNEL) => {
                    response.message(&self.domain, rpl::ERR_USERNOTINCHANNEL)
                        .param(self.clients[&addr].nick())
                        .param(change.param().unwrap())
                        .trailing_param(lines::USER_NOT_IN_CHANNEL);
                }
                Err(rpl::ERR_KEYSET) => {
                    response.message(&self.domain, rpl::ERR_KEYSET)
                        .param(self.clients[&addr].nick())
                        .param(target)
                        .trailing_param(lines::KEY_SET);
                }
                Err(_) => {}
            }
            Err(modes::Error::UnknownMode(mode)) => {
                response.message(&self.domain, rpl::ERR_UNKNOWNMODE)
                    .param(self.clients[&addr].nick())
                    .param(mode.to_string())
                    .trailing_param(lines::UNKNOWN_MODE);
            },
            Err(_) => {},
        } }
        if !response.is_empty() {
            self.clients[&addr].send(response.build());
        }
        if !applied_modes.is_empty() {
            let msg = Message::with_prefix(self.clients[&addr].full_name(), Command::Mode)
                .param(target)
                .param(applied_modes);
            let msg = applied_modeparams.into_iter()
                .fold(msg, MessageBuilder::param)
                .build()
                .into_bytes();
            self.broadcast(target, msg);
        }
    }

    fn check_cmd_mode_user_set(&self, addr: SocketAddr, target_user: &str) -> bool {
        if !self.clients.values().any(|c| c.nick() == target_user) {
            log::debug!("{}: can't set modes: no such nick", addr);
            self.send_reply(addr, rpl::ERR_NOSUCHNICK, &[target_user, lines::NO_SUCH_NICK]);
            return false;
        }
        if target_user != self.clients[&addr].nick() {
            log::debug!("{}: can't set modes: users don't match", addr);
            self.send_reply(addr, rpl::ERR_USERSDONTMATCH,
                            &[target_user, lines::USERS_DONT_MATCH]);
            return false;
        }
        true
    }

    fn apply_cmd_mode_user_set(&mut self, addr: SocketAddr, target: &str, modes: &str) {
        log::debug!("{}: setting user modes to {:?}", addr, modes);
        let modes = modes.trim();
        if modes.is_empty() {
            // Received a "MODE person :", nothing left to be done...
            return;
        }
        let client = self.clients.get_mut(&addr).unwrap();
        let mut response = ResponseBuffer::new();
        let mut applied_modes = String::new();
        for maybe_change in modes::UserQuery::new(modes) { match maybe_change {
            Ok(change) => if client.apply_mode_change(change) {
                log::debug!("  - Applied {:?}", change);
                applied_modes.push(if change.value() {'+'} else {'-'});
                applied_modes.push(change.symbol());
            }
            Err(modes::Error::UnknownMode(mode)) => {
                response.message(&self.domain, rpl::ERR_UMODEUNKNOWNFLAG)
                    .param(client.nick())
                    .param(mode.to_string())
                    .trailing_param(lines::UNKNOWN_MODE);
            }
            Err(_) => {}
        } }
        if !applied_modes.is_empty() {
            response.message(client.full_name(), Command::Mode)
                .param(target)
                .trailing_param(applied_modes);
        }
        if !response.is_empty() {
            client.send(response.build());
        }
    }

    fn check_cmd_mode_user_get(&self, addr: SocketAddr, target_user: &str) -> bool {
        self.check_cmd_mode_user_set(addr, target_user)
    }

    fn apply_cmd_mode_user_get(&self, addr: SocketAddr) {
        log::debug!("{}: getting user modes", addr);
        let client = &self.clients[&addr];
        let mut response = ResponseBuffer::new();
        let msg = response.message(&self.domain, rpl::UMODEIS)
            .param(client.nick());
        client.modes(msg);
        client.send(response.build());
    }

    pub fn cmd_mode(&mut self, addr: SocketAddr, target: &str,
                          modes: Option<&str>, modeparams: Params<'_>)
    {
        if is_channel_name(target) {
            if let Some(modes) = modes {
                if !self.check_cmd_mode_chan_set(addr, target) {
                    return;
                }
                self.apply_cmd_mode_chan_set(addr, target, modes, modeparams);
            } else {
                self.apply_cmd_mode_chan_get(addr, target);
            }
        } else if let Some(modes) = modes {
            if !self.check_cmd_mode_user_set(addr, target) {
                return;
            }
            self.apply_cmd_mode_user_set(addr, target, modes);
        } else {
            if !self.check_cmd_mode_user_get(addr, target) {
                return;
            }
            self.apply_cmd_mode_user_get(addr);
        }
    }

    // MOTD

    pub fn cmd_motd(&self, addr: SocketAddr) {
        let mut r = ResponseBuffer::new();
        let client = &self.clients[&addr];
        if let Some(ref motd) = self.motd {
            log::debug!("{}: Sending motd", addr);
            lines::motd_start(r.message(&self.domain, rpl::MOTDSTART).param(client.nick()),
                              &self.domain);
            for line in motd.lines() {
                let mut msg = r.message(&self.domain, rpl::MOTD)
                    .param(client.nick());
                let trailing = msg.raw_trailing_param();
                trailing.push_str("- ");
                trailing.push_str(line);
            }
            r.message(&self.domain, rpl::ENDOFMOTD)
                .param(client.nick())
                .trailing_param(lines::END_OF_MOTD);
        } else {
            log::debug!("{}: Sending no-motd error", addr);
            r.message(&self.domain, rpl::ERR_NOMOTD).trailing_param(lines::NO_MOTD);
        }
        client.send(r.build());
    }

    // NAMES

    pub fn cmd_names(&self, addr: SocketAddr, targets: &str) {
        log::debug!("{}: Request names of {:?}", addr, targets);
        if targets.is_empty() || targets == "*" {
            self.send_reply(addr, rpl::ENDOFNAMES, &["*", lines::END_OF_NAMES]);
        } else {
            for target in targets.split(',') {
                self.send_names(addr, target);
            }
        }
    }

    // NICK

    pub fn cmd_nick(&mut self, addr: SocketAddr, nick: &str) {
        if !is_valid_nickname(nick) {
            log::debug!("{}: Can't change nick to {:?}: Bad nickname", addr, nick);
            let client = &self.clients[&addr];
            let msg = Message::with_prefix(&self.domain, rpl::ERR_ERRONEUSNICKNAME)
                .param(client.nick())
                .param(nick)
                .trailing_param(lines::ERRONEOUS_NICNAME);
            client.send(msg.into_bytes());
            return;
        } else if self.clients.values().any(|c| c.nick() == nick) {
            log::debug!("{}: Can't change nick to {:?}: Already in use", addr, nick);
            let client = &self.clients[&addr];
            let msg = Message::with_prefix(&self.domain, rpl::ERR_NICKNAMEINUSE)
                .param(client.nick())
                .param(nick)
                .trailing_param(lines::NICKNAME_IN_USE);
            client.send(msg.into_bytes());
            return;
        }
        log::debug!("{}: Changing nick to {:?}", addr, nick);
        let client = self.clients.get_mut(&addr).unwrap();
        let old_state = client.state();
        let new_state = client.apply_command(Command::Nick);
        let msg = Message::with_prefix(client.full_name(), Command::Nick)
            .param(nick)
            .build()
            .into_bytes();
        client.set_nick(nick);
        if old_state.is_registered() {
            let mut noticed = self.channels
                .values()
                .filter(|chan| !chan.quiet && chan.members.contains_key(&addr))
                .flat_map(|chan| chan.members.keys())
                .collect::<HashSet<_>>();
            noticed.insert(&addr);
            for &client in noticed.into_iter() {
                self.send(client, msg.clone());
            }
        } else if new_state.is_registered() {
            self.send_welcome(addr);
        }
    }

    // NOTICE

    fn cmd_notice_user(&self, addr: SocketAddr, target: &str, user: &Client, content: &str) {
        let msg = Message::with_prefix(self.clients[&addr].full_name(), Command::Notice)
            .param(target)
            .trailing_param(content)
            .into_bytes();
        user.send(msg);
    }

    fn cmd_notice_chan(&self, addr: SocketAddr, target: &str, chan: &Channel, content: &str) {
        let msg = Message::with_prefix(self.clients[&addr].full_name(), Command::Notice)
            .param(target)
            .trailing_param(content)
            .into_bytes();
        chan.members.keys()
            .filter(|&&a| a != addr)
            .for_each(|&member| self.send(member, msg.clone()));
    }

    pub fn cmd_notice(&self, addr: SocketAddr, target: &str, content: &str) {
        if content.is_empty() {
            self.send_reply(addr, rpl::ERR_NOTEXTTOSEND, &[lines::NO_TEXT_TO_SEND]);
            return;
        }
        if let Some(ref chan) = self.channels.get(<&UniCase<str>>::from(target)) {
            if chan.can_talk(addr) {
                self.cmd_notice_chan(addr, target, chan, content);
                return;
            } else {
                log::debug!("{}: Can't send privmsg to {:?}", addr, target);
                self.send_reply(addr, rpl::ERR_CANNOTSENDTOCHAN,
                                &[target, lines::CANNOT_SEND_TO_CHAN]);
                return;
            }
        }
        if is_valid_nickname(target) {
            if let Some(user) = self.clients.values().find(|c| c.nick() == target) {
                self.cmd_notice_user(addr, target, user, content);
                return;
            }
        }
        log::debug!("{}: Can't send privmsg to {:?}: No such channel", addr, target);
        self.send_reply(addr, rpl::ERR_NOSUCHNICK, &[target, lines::NO_SUCH_NICK]);
    }

    // OPER

    pub fn cmd_oper(&mut self, addr: SocketAddr, name: &str, password: &str) {
        // TODO oper_hosts
        if !self.opers.iter().any(|(n, p)| n == name && p == password) {
            self.send_reply(addr, rpl::ERR_PASSWDMISMATCH, &[lines::PASSWORD_MISMATCH]);
            return;
        }
        log::debug!("{}: Log as operator", addr);
        let client = self.clients.get_mut(&addr).unwrap();
        client.operator = true;
        let mut response = ResponseBuffer::new();
        response.message(&self.domain, Command::Mode)
            .param(client.nick())
            .param("+o")
            .build();
        response.message(&self.domain, rpl::YOUREOPER)
            .param(client.nick())
            .param(lines::YOURE_OPER)
            .build();
        client.send(response.build());
    }

    // PART

    pub fn cmd_part(&mut self, addr: SocketAddr, target: &str, reason: Option<&str>) {
        let is_on_chan = self.channels.get(<&UniCase<str>>::from(target))
            .map_or(false, |chan| chan.members.contains_key(&addr));
        if !is_on_chan {
            self.send_reply(addr, rpl::ERR_NOTONCHANNEL, &[target, lines::NOT_ON_CHANNEL_PART]);
            return;
        }
        log::debug!("{}: part {:?} {:?}", addr, target, reason);
        let chan = self.channels.get_mut(<&UniCase<str>>::from(target)).unwrap();
        chan.members.remove(&addr);
        let client = &self.clients[&addr];
        let msg = if let Some(reason) = reason {
            Message::with_prefix(client.nick(), Command::Part).param(target).trailing_param(reason)
        } else {
            Message::with_prefix(client.nick(), Command::Part).param(target).build()
        }.into_bytes();
        client.send(msg.clone());
        if chan.members.is_empty() {
            self.channels.remove(<&UniCase<str>>::from(target));
        } else if !chan.quiet {
            self.broadcast(target, msg);
        }
    }

    // PASS

    pub fn cmd_pass(&mut self, addr: SocketAddr, pass: &str) {
        if self.password.as_ref().map_or(false, |p| p == pass) {
            self.clients.get_mut(&addr).unwrap().has_given_password = true;
        }
    }

    // PRIVMSG

    fn cmd_privmsg_user(&self, addr: SocketAddr, target: &str, user: &Client, content: &str) {
        let msg = Message::with_prefix(self.clients[&addr].full_name(), Command::PrivMsg)
            .param(target)
            .trailing_param(content)
            .into_bytes();
        user.send(msg);
    }

    #[cfg(not(feature = "irdille"))]
    fn cmd_privmsg_chan(&self, addr: SocketAddr, target: &str, chan: &Channel, content: &str) {
        let msg = Message::with_prefix(self.clients[&addr].full_name(), Command::PrivMsg)
            .param(target)
            .trailing_param(content)
            .into_bytes();
        chan.members.keys()
            .filter(|&&a| a != addr)
            .for_each(|&member| self.send(member, msg.clone()));
    }

    #[cfg(feature = "irdille")]
    fn cmd_privmsg_chan(&self, addr: SocketAddr, target: &str, chan: &Channel, content: &str) {
        let mut content = String::from(content);
        let mut modified = false;
        let rand = rand::random::<f64>();
        for (proba, regex, repl) in &chan.msg_modifier {
            if rand < *proba {
                content = regex.replace_all(&content, repl.as_str()).into();
                modified = true;
            }
        }
        let client = &self.clients[&addr];
        let msg = Message::with_prefix(client.full_name(), Command::PrivMsg)
            .param(target)
            .trailing_param(&content)
            .into_bytes();
        chan.members.keys()
            .filter(|&&a| a != addr)
            .for_each(|&member| self.send(member, msg.clone()));
        if modified {
            let mut response = ResponseBuffer::new();
            response.message(client.full_name(), rpl::IRDILLE_MODIFIEDPRIVMSG)
                .param(target)
                .trailing_param(content);
            client.send(response.build());
        }
    }

    pub fn cmd_privmsg(&self, addr: SocketAddr, target: &str, content: &str) {
        if content.is_empty() {
            self.send_reply(addr, rpl::ERR_NOTEXTTOSEND, &[lines::NO_TEXT_TO_SEND]);
            return;
        }
        if let Some(ref chan) = self.channels.get(<&UniCase<str>>::from(target)) {
            if chan.can_talk(addr) {
                log::debug!("{}: privmsg to {:?}", addr, target);
                self.cmd_privmsg_chan(addr, target, chan, content);
                return;
            } else {
                log::debug!("{}: Can't send privmsg to {:?}", addr, target);
                self.send_reply(addr, rpl::ERR_CANNOTSENDTOCHAN,
                                &[target, lines::CANNOT_SEND_TO_CHAN]);
                return;
            }
        }
        if is_valid_nickname(target) {
            if let Some(user) = self.clients.values().find(|c| c.nick() == target) {
                log::debug!("{}: privmsg to {:?}", addr, target);
                self.cmd_privmsg_user(addr, target, user, content);
                return;
            }
        }
        log::debug!("{}: Can't send privmsg to {:?}: No such channel", addr, target);
        self.send_reply(addr, rpl::ERR_NOSUCHNICK, &[target, lines::NO_SUCH_NICK]);
    }

    // QUIT

    pub fn cmd_quit(&mut self, addr: SocketAddr, reason: Option<&str>) {
        log::debug!("{}: quit {:?}", addr, reason);
        self.clients.get_mut(&addr).unwrap().set_quit_message(reason);
    }

    // TIME

    pub fn cmd_time(&self, addr: SocketAddr) {
        log::debug!("{}: Request time", addr);
        let time = Local::now().to_rfc2822();
        self.send_reply(addr, rpl::TIME, &[&self.domain, &time]);
    }

    // TOPIC

    fn cmd_topic_set(&mut self, addr: SocketAddr, target: &str, topic: &str) {
        let chan = if let Some(chan) = self.channels.get_mut(<&UniCase<str>>::from(target)) {
            if let Some(modes) = chan.members.get(&addr) {
                if modes.operator || !chan.topic_restricted {
                    chan
                } else {
                    log::debug!("{}: Can't set topic of {:?}: not operator", addr, target);
                    self.send_reply(addr, rpl::ERR_CHANOPRIVSNEEDED,
                                    &[target, lines::CHAN_O_PRIVS_NEEDED]);
                    return;
                }
            } else {
            log::debug!("{}: Can't set topic of {:?}: not on channel", addr, target);
                self.send_reply(addr, rpl::ERR_NOTONCHANNEL,
                                &[target, lines::NOT_ON_CHANNEL_TOPIC]);
                return;
            }
        } else {
            log::debug!("{}: Can't set topic of {:?}: no such channel", addr, target);
            self.send_reply(addr, rpl::ERR_NOSUCHCHANNEL, &[target, lines::NO_SUCH_CHANNEL]);
            return;
        };
        log::debug!("{}: Set topic of {:?} to {:?}", addr, target, topic);
        if topic.is_empty() {
            chan.topic = None;
        } else {
            chan.topic = Some(topic.to_owned());
        }
        let msg = Message::with_prefix(self.clients[&addr].full_name(), Command::Topic)
            .param(target)
            .trailing_param(topic)
            .into_bytes();
        self.broadcast(target, msg);
    }

    fn cmd_topic_get(&self, addr: SocketAddr, target: &str) {
        log::debug!("{}: get topic of {:?}", addr, target);
        if let Some(chan) = self.channels.get(<&UniCase<str>>::from(target)) {
            if chan.members.contains_key(&addr) {
                self.send_topic(addr, target);
                return;
            }
        }
        self.send_reply(addr, rpl::ERR_NOTONCHANNEL, &[target, lines::NOT_ON_CHANNEL_TOPIC]);
    }

    pub fn cmd_topic(&mut self, addr: SocketAddr, target: &str, topic: Option<&str>) {
        if let Some(topic) = topic {
            self.cmd_topic_set(addr, target, topic);
        } else {
            self.cmd_topic_get(addr, target);
        }
    }

    // USER

    pub fn cmd_user(&mut self, addr: SocketAddr, user: &str, real: &str,
                          invisible: bool, wallops: bool)
    {
        log::debug!("{}: Register as {}, '{}'", addr, user, real);
        let client = self.clients.get_mut(&addr).unwrap();
        if self.password.is_some() && !client.has_given_password {
            let mut response = ResponseBuffer::new();
            response.message(&self.domain, rpl::ERR_PASSWDMISMATCH)
                .param(client.nick())
                .trailing_param(lines::PASSWORD_MISMATCH);
            client.send(response.build());
            return;
        }
        client.set_user_real(user, real);
        client.invisible = invisible;
        client.wallops = wallops;
        let old_state = client.state();
        let new_state = client.apply_command(Command::User);
        if new_state.is_registered() && !old_state.is_registered() {
            self.send_welcome(addr);
        }
    }

    // VERSION

    pub fn cmd_version(&self, addr: SocketAddr) {
        log::debug!("{}: Request version", addr);
        let client = &self.clients[&addr];
        let mut response = ResponseBuffer::new();
        response.message(&self.domain, rpl::VERSION)
            .param(client.nick())
            .param(SERVER_VERSION)
            .param(&self.domain)
            .build();
        self.send_i_support(&mut response, client.nick());
        client.send(response.build());
    }
}

fn is_channel_name(s: &str) -> bool {
    let s = s.as_bytes();
    !s.is_empty()
        && s.len() <= MAX_CHANNEL_NAME_LENGTH
        && (s[0] == b'#' || s[0] == b'&' || s[0] == b'!' || s[0] == b'+')
}

fn is_valid_channel_name(s: &str) -> bool {
    // https://tools.ietf.org/html/rfc2811.html#section-2.1
    let ctrl_g = 7 as char;
    is_channel_name(s) && s.chars().all(|c| c != ' ' && c != ',' && c != ctrl_g && c != ':')
}

fn is_valid_nickname(s: &str) -> bool {
    let s = s.as_bytes();
    let is_valid_nickname_char = |&c: &u8| {
        (b'0' <= c && c <= b'9')
            || (b'a' <= c && c <= b'z')
            || (b'A' <= c && c <= b'Z')
            // "[", "]", "\", "`", "_", "^", "{", "|", "}"
            || (0x5b <= c && c <= 0x60)
            || (0x7b <= c && c <= 0x7d)
    };
    s.len() <= MAX_NICKNAME_LENGTH
        && s.iter().all(is_valid_nickname_char)
        && s[0] != b'-' && !(b'0' <= s[0] && s[0] <= b'9')
}
