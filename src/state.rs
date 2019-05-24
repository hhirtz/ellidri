//! Shared state and API to handle incoming commands.

use std::collections::{HashMap, HashSet};
use std::net::SocketAddr;
use std::sync::{Arc, RwLock};

use chrono::{DateTime, Utc};
use futures::sync::mpsc;

use crate::client::{Client, SETTABLE_USER_MODES, USER_MODES};
use crate::lines;
use crate::message::{Command, Message, Params, Reply, rpl, ResponseBuffer};
use crate::modes;

const MAX_CHANNEL_NAME_LENGTH: usize = 50;
const MAX_NICKNAME_LENGTH: usize = 9;

pub type MessageQueueItem = Arc<[u8]>;
pub type MessageQueue = mpsc::UnboundedSender<MessageQueueItem>;

/// Shared state of the IRC server.
///
/// It's a pointer to the actual data, so it's cheap to clone.
#[derive(Clone)]
pub struct State(Arc<RwLock<StateInner>>);

impl State {
    /// Initialize a new state with the given `prefix` and `motd`.
    ///
    /// `prefix` is the domain of the server. It's used as prefix for most replies.  `motd` is the
    /// message of the day.
    ///
    /// # TODO
    ///
    /// Make it accept a "config" struct, or use a builder pattern.
    pub fn new(prefix: String, motd: Option<String>, default_chan_mode: String) -> State
    {
        let inner = StateInner::new(prefix, motd, default_chan_mode);
        State(Arc::new(RwLock::new(inner)))
    }

    /// Adds a new client into the state.
    ///
    /// Called when a connection is accepted.
    pub fn insert(&self, addr: SocketAddr, queue: MessageQueue) {
        self.0.write().unwrap().clients.insert(addr, Client::new(queue, addr.ip().to_string()));
    }

    /// Removes a client from the state.
    ///
    /// Called when a connection drops, or the client issued a "QUIT" message.
    pub fn remove(&self, addr: SocketAddr) {
        self.0.write().unwrap().remove(addr);
    }

    /// Creates a message with the given `cmd` and `params`, and send it to the given client.
    pub fn send_command(&self, addr: SocketAddr, cmd: Command, params: &[&str]) {
        self.0.read().unwrap().send_command(addr, cmd, params);
    }

    /// Creates a message with the given `reply` and `params`, and send it to the given client.
    ///
    /// It also adds the client's nickname as the first argument.
    pub fn send_reply(&self, addr: SocketAddr, reply: Reply, params: &[&str]) {
        self.0.read().unwrap().send_reply(addr, reply, params);
    }

    /// Returns true when the given client can issue the given command.
    ///
    /// This depends of the "state" the connection is in. For example, if a client has not sent a
    /// "NICK" and an "USER" message, it cannot send a "JOIN" message.
    pub fn can_issue_command(&self, addr: SocketAddr, cmd: Command) -> bool {
        self.0.read().unwrap().clients[&addr].can_issue_command(cmd)
    }

    /// Handles a "JOIN" message.
    pub fn cmd_join(&self, addr: SocketAddr, targets: &str, keys: Option<&str>) {
        let mut keys = keys.unwrap_or("").split(',');
        for target in targets.split(',') {
            if self.0.read().unwrap().check_cmd_join(addr, target, keys.next()) {
                self.0.write().unwrap().apply_cmd_join(addr, target);
            }
        }
    }

    /// Handles a "MODE" message.
    pub fn cmd_mode(&self, addr: SocketAddr, target: &str, modes: Option<&str>, modeparams: Params)
    {
        self.0.write().unwrap().apply_cmd_mode(addr, target, modes, modeparams);
    }

    /// Handles a "MOTD" message.
    pub fn cmd_motd(&self, addr: SocketAddr) {
        self.0.read().unwrap().apply_cmd_motd(addr);
    }

    /// Handles a "NICK" message.
    pub fn cmd_nick(&self, addr: SocketAddr, nick: &str) {
        if self.0.read().unwrap().check_cmd_nick(addr, nick) {
            self.0.write().unwrap().apply_cmd_nick(addr, nick);
        }
    }

    /// Handles a "PART" message.
    pub fn cmd_part(&self, addr: SocketAddr, targets: &str, reason: Option<&str>) {
        for target in targets.split(',') {
            if self.0.read().unwrap().check_cmd_part(addr, target, reason) {
                self.0.write().unwrap().apply_cmd_part(addr, target, reason);
            }
        }
    }

    /// Handles a "PRIVMSG" message.
    pub fn cmd_privmsg(&self, addr: SocketAddr, targets: &str, content: &str) {
        if self.0.read().unwrap().check_cmd_privmsg(addr, targets, content) {
            self.0.read().unwrap().apply_cmd_privmsg(addr, targets, content);
        }
    }

    /// Handles a "QUIT" message.
    pub fn cmd_quit(&self, addr: SocketAddr, reason: Option<&str>) {
        self.0.write().unwrap().apply_cmd_quit(addr, reason);
    }

    /// Handles a "TOPIC" message.
    pub fn cmd_topic(&self, addr: SocketAddr, target: &str, topic: Option<&str>) {
        if let Some(topic) = topic {
            if self.0.read().unwrap().check_cmd_topic_set(addr, target) {
                self.0.write().unwrap().apply_cmd_topic_set(addr, target, topic);
            }
        } else {
            self.0.read().unwrap().apply_cmd_topic_get(addr, target);
        }
    }

    /// Handles a "USER" message.
    pub fn cmd_user(&self, addr: SocketAddr, user: &str, real: &str,
                    invisible: bool, wallops: bool)
    {
        self.0.write().unwrap().apply_cmd_user(addr, user, real, invisible, wallops);
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
    prefix: String,

    /// The set of clients, identified by their socket address.
    clients: HashMap<SocketAddr, Client>,

    /// The set of channels, identified by their name.
    channels: HashMap<String, Channel>,

    /// The UTC local time when the `StateInner` instance is created. It is sent to the client when
    /// they register (in a "003 RPL_CREATED" reply, as per the RFC).
    created_at: DateTime<Utc>,

    /// The message of the day.
    motd: Option<String>,

    /// Modes applied at the creation of new channels.
    default_chan_mode: String,
}

impl StateInner {
    /// Creates a new shared state. See `State::new`.
    pub fn new(prefix: String, motd: Option<String>, default_chan_mode: String) -> StateInner {
        StateInner {
            prefix,
            clients: HashMap::new(),
            channels: HashMap::new(),
            created_at: Utc::now(),
            motd,
            default_chan_mode,
        }
    }

    /// Removes a client from the state. See `State::remove`.
    pub fn remove(&mut self, addr: SocketAddr) {
        let client = self.clients.remove(&addr).unwrap();
        let msg = Message::with_prefix(client.full_name(), Command::Quit)
            .trailing_param(client.quit_message())
            .into_bytes();
        for chan in self.channels.values() {
            if chan.members.contains_key(&addr) {
                for &member in chan.members.keys() {
                    self.send(member, msg.clone());
                }
            }
        }

        self.channels.iter_mut()
            .filter(|(_, chan)| chan.members.contains_key(&addr))
            .for_each(|(_, chan)| chan.remove_member(addr));
    }

    /// Whether or not a "JOIN" message with the given parameters can be issued by the given
    /// client.
    pub fn check_cmd_join(&self, addr: SocketAddr, target: &str, key: Option<&str>) -> bool {
        if is_valid_channel_name(target) {
            if let Some(chan) = self.channels.get(target) {
                // TODO if-let chains
                if let Some(ref chan_key) = chan.key {
                    if key.map_or(true, |key| key != chan_key) {
                        log::debug!("{}: Can't join {:?}: Bad key", addr, target);
                        self.send_reply(addr, rpl::ERR_BADCHANKEY,
                                        &[target, lines::BAD_CHAN_KEY]);
                        return false;
                    }
                }
                if chan.can_join(self.clients[&addr].nick()) {
                    true
                } else {
                    log::debug!("{}: Can't join {:?}: Banned", addr, target);
                    self.send_reply(addr, rpl::ERR_BANNEDFROMCHAN,
                                    &[target, lines::BANNED_FROM_CHAN]);
                    false
                }
            } else {
                true
            }
        } else {
            log::debug!("{}: Can't join {:?}: Invalid channel name", addr, target);
            self.send_reply(addr, rpl::ERR_NOSUCHCHANNEL, &[target, lines::NO_SUCH_CHANNEL]);
            false
        }
    }

    /// Applies a "JOIN" command issued by the given client with the given parameters.
    pub fn apply_cmd_join(&mut self, addr: SocketAddr, target: &str) {
        log::debug!("{}: Join {}", addr, target);
        let default_chan_mode = &self.default_chan_mode;
        let chan = self.channels.entry(target.into())
            .or_insert_with(|| Channel::new(&default_chan_mode));
        chan.add_member(addr);
        let modes = chan.modes();
        let client = &self.clients[&addr];
        let join = Message::with_prefix(client.full_name(), Command::Join).param(target).build();
        self.broadcast(target, join.into_bytes());
        let modes = Message::with_prefix(&self.prefix, Command::Mode)
            .param(target)
            .param(modes)
            .build()
            .into_bytes();
        client.send(modes);
        self.send_topic(addr, target);
        self.send_names(addr, target);
    }

    /// Sends the chan modes to addr.
    fn apply_cmd_mode_chan_get(&self, addr: SocketAddr, target: &str) {
        log::debug!("{}: getting modes of {:?}", addr, target);
        if let Some(chan) = self.channels.get(target) {
            let modes = chan.modes();
            let msg = Message::with_prefix(&self.prefix, Command::Reply(rpl::CHANNELMODEIS))
                .param(self.clients[&addr].nick())
                .param(target)
                .param(modes);
            let msg = chan.user_limit.iter()
                .fold(msg, |msg, limit| msg.param(limit.to_string()));
            let msg = chan.key.iter()
                .fold(msg, |msg, key| msg.param(key.to_string()));
            let msg = msg.build().into_bytes();
            self.clients[&addr].send(msg);
        } else {
            self.send_reply(addr, rpl::ERR_NOSUCHCHANNEL, &[target, lines::NO_SUCH_CHANNEL]);
        }
    }

    fn check_cmd_mode_chan_set(&self, addr: SocketAddr, target: &str) -> bool {
        if let Some(chan) = self.channels.get(target) {
            if let Some(modes) = chan.members.get(&addr) {
                if modes.channel_operator {
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
                               modes: &str, modeparams: Params)
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
        let chan = self.channels.get_mut(target).unwrap();
        let clients = &self.clients;
        for maybe_change in modes::ChannelQuery::new(modes, modeparams) { match maybe_change {
            Ok(modes::ChannelModeChange::GetBans) => {
                response.list(&self.prefix, rpl::BANLIST, rpl::ENDOFBANLIST,
                              lines::END_OF_BAN_LIST, &chan.ban_mask,
                              |msg| msg.param(clients[&addr].nick()).param(target));
            }
            Ok(modes::ChannelModeChange::GetExceptions) => {
                response.list(&self.prefix, rpl::EXCEPTLIST, rpl::ENDOFEXCEPTLIST,
                              lines::END_OF_EXCEPT_LIST, &chan.exception_mask,
                              |msg| msg.param(clients[&addr].nick()).param(target));
            }
            Ok(modes::ChannelModeChange::GetInvitations) => {
                response.list(&self.prefix, rpl::INVITELIST, rpl::ENDOFINVITELIST,
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
                    response.message(&self.prefix, rpl::ERR_USERNOTINCHANNEL)
                        .param(self.clients[&addr].nick())
                        .param(change.param().unwrap())
                        .trailing_param(lines::USER_NOT_IN_CHANNEL);
                }
                Err(rpl::ERR_KEYSET) => {
                    response.message(&self.prefix, rpl::ERR_KEYSET)
                        .param(self.clients[&addr].nick())
                        .param(target)
                        .trailing_param(lines::KEY_SET);
                }
                Err(_) => {}
            }
            Err(modes::Error::UnknownMode(mode)) => {
                response.message(&self.prefix, rpl::ERR_UNKNOWNMODE)
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
                .fold(msg, |msg, param| msg.param(param))
                .build()
                .into_bytes();
            self.broadcast(target, msg);
        }
    }

    /// Check if the given `client` can set the mode of the given `target_user`.
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
        let bmodes = modes.as_bytes();
        let mut applied_modes = String::new();
        let mut mode_value = true;
        if bmodes[0] != b'+' && bmodes[0] != b'-' {
            applied_modes.push('+');
        }
        for &mode in bmodes {
            if mode == b'+' {
                mode_value = true;
                applied_modes.push('+');
            } else if mode == b'-' {
                mode_value = false;
                applied_modes.push('-');
            } else if SETTABLE_USER_MODES.contains(&mode) {
                client.set_mode(mode, mode_value);
                applied_modes.push(mode as char);
            } else if !USER_MODES.contains(&mode) {
                let msg = Message::with_prefix(&self.prefix,
                                               Command::Reply(rpl::ERR_UMODEUNKNOWNFLAG))
                    .param(client.nick())
                    .trailing_param(lines::UNKNOWN_MODE)
                    .into_bytes();
                client.send(msg);
            }
        }
        let msg = Message::with_prefix(client.full_name(), Command::Mode)
            .param(target)
            .trailing_param(applied_modes)
            .into_bytes();
        client.send(msg);
    }

    /// Check if the given `client` can get the mode of the given `target_user`.
    fn check_cmd_mode_user_get(&self, addr: SocketAddr, target_user: &str) -> bool {
        self.check_cmd_mode_user_set(addr, target_user)
    }

    /// Applies a "MODE" command when the target is a user.
    fn apply_cmd_mode_user_get(&self, addr: SocketAddr) {
        log::debug!("{}: getting user modes", addr);
        let client = &self.clients[&addr];
        let modes = client.modes();
        let msg = Message::with_prefix(&self.prefix, Command::Reply(rpl::UMODEIS))
            .param(modes)
            .build()
            .into_bytes();
        client.send(msg);
    }

    /// Applies a "MODE" command issued by the given client.
    pub fn apply_cmd_mode(&mut self, addr: SocketAddr, target: &str,
                          modes: Option<&str>, modeparams: Params)
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

    /// Applies a "MOTD" command issued by the given client.
    pub fn apply_cmd_motd(&self, addr: SocketAddr) {
        if let Some(ref motd) = self.motd {
            log::debug!("{}: Sending motd", addr);
            let m = format!("- {} Senpai's message of the day -", self.prefix);
            self.send_reply(addr, rpl::MOTDSTART, &[&m]);
            for line in motd.lines() {
                let m = format!("- {}", line);
                self.send_reply(addr, rpl::MOTD, &[&m]);
            }
            self.send_reply(addr, rpl::ENDOFMOTD, &[lines::END_OF_MOTD]);
        } else {
            log::debug!("{}: Sending no-motd error", addr);
            self.send_reply(addr, rpl::ERR_NOMOTD, &[lines::NO_MOTD]);
        }
    }

    /// Whether or not a "NICK" message with the given parameters can be issued by the given
    /// client.
    pub fn check_cmd_nick(&self, addr: SocketAddr, nick: &str) -> bool {
        if !is_valid_nickname(nick) {
            log::debug!("{}: Can't change nick to {:?}: Bad nickname", addr, nick);
            self.send_reply(addr, rpl::ERR_ERRONEUSNICKNAME, &[nick, lines::ERRONEOUS_NICNAME]);
            false
        } else if self.clients.values().any(|c| c.nick() == nick) {
            log::debug!("{}: Can't change nick to {:?}: Already in use", addr, nick);
            self.send_reply(addr, rpl::ERR_NICKNAMEINUSE, &[nick, lines::NICKNAME_IN_USE]);
            false
        } else {
            true
        }
    }

    /// Applies a "NICK" command issued by the given client with the given parameter.
    pub fn apply_cmd_nick(&mut self, addr: SocketAddr, nick: &str) {
        log::debug!("{}: Changing nick to {:?}", addr, nick);
        let msg = Message::with_prefix(self.clients[&addr].nick(), Command::Nick)
            .param(nick)
            .build()
            .into_bytes();
        let noticed = self.channels
            .values()
            .filter(|chan| chan.members.contains_key(&addr))
            .flat_map(|chan| chan.members.keys())
            .collect::<HashSet<_>>();
        for &client in noticed.into_iter() {
            self.send(client, msg.clone());
        }
        let client = self.clients.get_mut(&addr).unwrap();
        client.set_nick(nick);
        let old_state = client.state();
        let new_state = client.apply_command(Command::Nick);
        if new_state.is_registered() && !old_state.is_registered() {
            self.send_welcome(addr);
        }
    }

    /// Whether or not a "PART" message with the given parameters can be issued by the given
    /// client.
    pub fn check_cmd_part(&self, addr: SocketAddr, target: &str, _reason: Option<&str>) -> bool {
        let is_on_chan = self.channels.get(target)
            .map_or(false, |chan| chan.members.contains_key(&addr));
        if !is_on_chan {
            self.send_reply(addr, rpl::ERR_NOTONCHANNEL, &[target, lines::NOT_ON_CHANNEL_PART]);
            false
        } else {
            true
        }
    }

    /// Applies a "PART" command issued by the given client with the given parameters.
    pub fn apply_cmd_part(&mut self, addr: SocketAddr, target: &str, reason: Option<&str>) {
        let nick = self.clients[&addr].full_name();
        let msg = if let Some(reason) = reason {
            Message::with_prefix(nick, Command::Part).param(target).trailing_param(reason)
        } else {
            Message::with_prefix(nick, Command::Part).param(target).build()
        };
        self.broadcast(target, msg.into_bytes());
        let chan = self.channels.get_mut(target).unwrap();
        chan.members.remove(&addr);
    }

    /// Whether or not a "PRIVMSG" message with the given parameters can be issued by the given
    /// client.
    pub fn check_cmd_privmsg(&self, addr: SocketAddr, target: &str, content: &str) -> bool {
        if content.is_empty() {
            self.send_reply(addr, rpl::ERR_NOTEXTTOSEND, &[lines::NO_TEXT_TO_SEND]);
            return false;
        }
        if let Some(ref chan) = self.channels.get(target) {
            if chan.can_talk(addr) {
                true
            } else {
                log::debug!("{}: Can't send privmsg to {:?}", addr, target);
                self.send_reply(addr, rpl::ERR_CANNOTSENDTOCHAN,
                                &[target, lines::CANNOT_SEND_TO_CHAN]);
                false
            }
        } else {
            log::debug!("{}: Can't send privmsg to {:?}: No such channel", addr, target);
            self.send_reply(addr, rpl::ERR_NOSUCHNICK, &[target, lines::NO_SUCH_NICK]);
            false
        }
    }

    /// Applies a "PRIVMSG" command issued by the given client with the given parameters.
    pub fn apply_cmd_privmsg(&self, addr: SocketAddr, targets: &str, content: &str) {
        log::debug!("{}: Privmsg to {:?}", addr, targets);
        let client = &self.clients[&addr];
        let msg = Message::with_prefix(client.full_name(), Command::PrivMsg)
            .param(targets)
            .trailing_param(content)
            .into_bytes();
        let chan = &self.channels[targets];
        chan.members.keys()
            .filter(|&&a| a != addr)
            .for_each(|&member| self.send(member, msg.clone()));
    }

    /// Applies a "QUIT" command issued by the given client with the given parameters.
    pub fn apply_cmd_quit(&mut self, addr: SocketAddr, reason: Option<&str>) {
        self.clients.get_mut(&addr).unwrap().set_quit_message(reason);
    }

    /// Whether or not a "TOPIC" message with the two given parameters can be issued by the given
    /// client.
    ///
    /// "TOPIC" has been split in two handlers, a getter and a setter.
    pub fn check_cmd_topic_set(&self, addr: SocketAddr, target: &str) -> bool {
        if let Some(chan) = self.channels.get(target) {
            if let Some(modes) = chan.members.get(&addr) {
                if modes.channel_operator || !chan.topic_restricted {
                    true
                } else {
                    self.send_reply(addr, rpl::ERR_CHANOPRIVSNEEDED,
                                    &[target, lines::CHAN_O_PRIVS_NEEDED]);
                    false
                }
            } else {
                self.send_reply(addr, rpl::ERR_NOTONCHANNEL,
                                &[target, lines::NOT_ON_CHANNEL_TOPIC]);
                false
            }
        } else {
            self.send_reply(addr, rpl::ERR_NOTONCHANNEL, &[target, lines::NOT_ON_CHANNEL_TOPIC]);
            false
        }
    }

    /// Apply a "TOPIC" command issued by the given client with the given parameters.
    ///
    /// "TOPIC" has been split in two handlers, a getter and a setter.
    pub fn apply_cmd_topic_set(&mut self, addr: SocketAddr, target: &str, topic: &str) {
        log::debug!("{} Set topic of {:?} to {:?}", addr, target, topic);
        let chan = self.channels.get_mut(target).unwrap();
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

    /// Applies a "TOPIC" command issued by the given client with the given parameter.
    pub fn apply_cmd_topic_get(&self, addr: SocketAddr, target: &str) {
        if let Some(chan) = self.channels.get(target) {
            if chan.members.contains_key(&addr) {
                self.send_topic(addr, target);
                return;
            }
        }
        self.send_reply(addr, rpl::ERR_NOTONCHANNEL, &[target, lines::NOT_ON_CHANNEL_TOPIC]);
    }

    /// Applies a "USER" command issued by the given client with the given parameters.
    pub fn apply_cmd_user(&mut self, addr: SocketAddr, user: &str, real: &str,
                          invisible: bool, wallops: bool)
    {
        log::debug!("{}: Register as {}, '{}'", addr, user, real);
        let client = self.clients.get_mut(&addr).unwrap();
        client.set_user_real(user, real);
        client.invisible = invisible;
        client.wallops = wallops;
        let old_state = client.state();
        let new_state = client.apply_command(Command::User);
        if new_state.is_registered() && !old_state.is_registered() {
            self.send_welcome(addr);
        }
    }

    /// Sends the given message to all users in the given channel.
    pub fn broadcast(&self, target: &str, msg: MessageQueueItem) {
        let chan = &self.channels[target];
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
            let mut msg = Message::with_prefix(&self.prefix, cmd);
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
            let mut msg = Message::with_prefix(&self.prefix, Command::Reply(reply))
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

    /// Sends the list of nicknames in the channel `chan_name` to the given client.
    fn send_names(&self, addr: SocketAddr, chan_name: &str) {
        let chan = &self.channels[chan_name];
        if !chan.members.is_empty() {
            let mut names = String::with_capacity(512);
            for (member, modes) in chan.members.iter() {
                let nick = self.clients[member].nick();
                names.push(' ');
                names.push(modes.symbol());
                names.push_str(nick);
            }
            self.send_reply(addr, rpl::NAMREPLY, &[chan.symbol(), chan_name, names.trim_start()]);
        }
        self.send_reply(addr, rpl::ENDOFNAMES, &[chan_name, lines::END_OF_NAMES]);
    }

    /// Sends the topic of the channel `chan_name` to the given client.
    fn send_topic(&self, addr: SocketAddr, chan_name: &str) {
        let chan = &self.channels[chan_name];
        if let Some(ref topic) = chan.topic {
            self.send_reply(addr, rpl::TOPIC, &[chan_name, topic]);
        } else {
            self.send_reply(addr, rpl::NOTOPIC, &[chan_name, lines::NO_TOPIC]);
        }
    }

    /// Sends welcome messages. Called when a client has completed its registration.
    fn send_welcome(&self, addr: SocketAddr) {
        self.send_reply(addr, rpl::WELCOME, &[lines::WELCOME]);
        self.send_reply(addr, rpl::YOURHOST, &[lines::YOUR_HOST]);
        let m = format!("We've been together since {}", self.created_at.to_rfc2822());
        self.send_reply(addr, rpl::CREATED, &[&m]);
        self.send_reply(addr, rpl::MYINFO, &[&self.prefix, env!("CARGO_PKG_VERSION"), "i", "i"]);
        self.apply_cmd_motd(addr);
    }
}

/// Channel data.
#[derive(Default)]
struct Channel {
    /// Set of channel members, identified by their socket address, and associated with their
    /// channel mode.
    pub members: HashMap<SocketAddr, MemberModes>,

    /// The topic.
    pub topic: Option<String>,

    pub user_limit: Option<usize>,
    pub key: Option<String>,

    // https://tools.ietf.org/html/rfc2811.html#section-4.3
    pub ban_mask: HashSet<String>,
    pub exception_mask: HashSet<String>,
    pub invitation_mask: HashSet<String>,

    // Modes: https://tools.ietf.org/html/rfc2811.html#section-4.2
    pub anonymous: bool,
    pub invite_only: bool,
    pub moderated: bool,
    pub no_privmsg_from_outside: bool,
    pub quiet: bool,
    pub private: bool,
    pub secret: bool,
    pub reop: bool,
    pub topic_restricted: bool,
}

impl Channel {
    /// Creates a channel with the 'n' mode set.
    pub fn new(modes: &str) -> Channel {
        let mut chan = Channel::default();
        for change in modes::ChannelQuery::simple(modes).filter_map(Result::ok) {
            chan.apply_mode_change(change, |_| "").unwrap();
        }
        chan
    }

    /// Adds a member with the default mode.
    pub fn add_member(&mut self, addr: SocketAddr) {
        let modes = if self.members.is_empty() {
            MemberModes {
                channel_creator: true,
                channel_operator: true,
                voice: false,
            }
        } else {
            MemberModes::default()
        };
        self.members.insert(addr, modes);
    }

    /// Removes a member.
    pub fn remove_member(&mut self, addr: SocketAddr) {
        self.members.remove(&addr);
    }

    pub fn can_join(&self, nick: &str) -> bool {
        !self.ban_mask.contains(nick)
            || self.exception_mask.contains(nick)
            || self.invitation_mask.contains(nick)
    }

    pub fn can_talk(&self, addr: SocketAddr) -> bool {
        if self.moderated {
            self.members.get(&addr).map(|m| m.voice || m.channel_operator).unwrap_or(false)
        } else {
            !self.no_privmsg_from_outside || self.members.contains_key(&addr)
        }
    }

    pub fn modes(&self) -> String {
        let mut modes = String::from("+");
        if self.anonymous { modes.push('a'); }
        if self.invite_only { modes.push('i'); }
        if self.moderated { modes.push('m'); }
        if self.no_privmsg_from_outside { modes.push('n'); }
        if self.quiet { modes.push('q'); }
        if self.private { modes.push('p'); }
        if self.reop { modes.push('r'); }
        if self.topic_restricted { modes.push('t'); }
        if self.user_limit.is_some() { modes.push('l'); }
        if self.key.is_some() { modes.push('k'); }
        modes
    }

    pub fn apply_mode_change<'a, F>(&mut self, change: modes::ChannelModeChange,
                                    nick_of: F) -> Result<bool, Reply>
        where F: Fn(&SocketAddr) -> &'a str
    {
        use modes::ChannelModeChange::*;
        let mut applied = false;
        match change {
            Anonymous(value) => {
                applied = self.anonymous != value;
                self.anonymous = value;
            },
            InviteOnly(value) => {
                applied = self.invite_only != value;
                self.invite_only = value;
            },
            Moderated(value) => {
                applied = self.moderated != value;
                self.moderated = value;
            },
            NoPrivMsgFromOutside(value) => {
                applied = self.no_privmsg_from_outside != value;
                self.no_privmsg_from_outside = value;
            },
            Quiet(value) => {
                applied = self.quiet != value;
                self.quiet = value;
            },
            Private(value) => {
                applied = self.private != value;
                self.private = value;
            },
            Secret(value) => {
                applied = self.secret != value;
                self.secret = value;
            },
            TopicRestricted(value) => {
                applied = self.topic_restricted != value;
                self.topic_restricted = value;
            },
            Key(value, key) => if value {
                if self.key.is_some() {
                    return Err(rpl::ERR_KEYSET);
                } else {
                    applied = true;
                    self.key = Some(key.to_owned());
                }
            } else if let Some(ref chan_key) = self.key {
                if key == chan_key {
                    applied = true;
                    self.key = None;
                }
            },
            UserLimit(Some(s)) => if let Ok(limit) = s.parse() {
                applied = self.user_limit.map_or(true, |chan_limit| chan_limit != limit);
                self.user_limit = Some(limit);
            },
            UserLimit(None) => {
                applied = self.user_limit.is_some();
                self.user_limit = None;
            },
            ChangeBan(value, param) => {
                applied = if value {
                    self.ban_mask.insert(param.to_owned())
                } else {
                    self.ban_mask.remove(param)
                };
            },
            ChangeException(value, param) => {
                applied = if value {
                    self.exception_mask.insert(param.to_owned())
                } else {
                    self.exception_mask.remove(param)
                };
            },
            ChangeInvitation(value, param) => {
                applied = if value {
                    self.invitation_mask.insert(param.to_owned())
                } else {
                    self.invitation_mask.remove(param)
                };
            },
            ChangeOperator(value, param) => {
                let mut has_it = false;
                for (member, modes) in self.members.iter_mut() {
                    if nick_of(member) == param {
                        has_it = true;
                        applied = modes.channel_operator != value;
                        modes.channel_operator = value;
                        break;
                    }
                }
                if !has_it {
                    return Err(rpl::ERR_USERNOTINCHANNEL);
                }
            },
            ChangeVoice(value, param) => {
                let mut has_it = false;
                for (member, modes) in self.members.iter_mut() {
                    if nick_of(member) == param {
                        has_it = true;
                        applied = modes.channel_operator != value;
                        modes.channel_operator = value;
                        break;
                    }
                }
                if !has_it {
                    return Err(rpl::ERR_USERNOTINCHANNEL);
                }
            },
            _ => {},
        }
        Ok(applied)
    }

    pub fn symbol(&self) -> &'static str {
        if self.secret {
            "@"
        } else if self.private {
            "*"
        } else {
            "="
        }
    }
}

/// Modes applied to clients on a per-channel basis.
///
/// https://tools.ietf.org/html/rfc2811.html#section-4.1
#[derive(Default)]
struct MemberModes {
    pub channel_creator: bool,
    pub channel_operator: bool,
    pub voice: bool,
}

impl MemberModes {
    pub fn symbol(&self) -> char {
        if self.channel_operator {
            '@'
        } else if self.voice {
            '+'
        } else {
            ' '
        }
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
