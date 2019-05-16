//! Shared state and API to handle incoming commands.

use std::collections::{HashMap, HashSet};
use std::net::SocketAddr;
use std::sync::{Arc, RwLock};

use chrono::{DateTime, Utc};
use futures::sync::mpsc;

use crate::client::Client;
use crate::lines;
use crate::message::{Command, Message, Reply, rpl};

const MAX_CHANNEL_NAME_LENGTH: usize = 50;
const MAX_NICKNAME_LENGTH: usize = 9;

pub type MessageQueue = mpsc::UnboundedSender<Message>;

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
    pub fn new(prefix: String, motd: Option<String>) -> State {
        let inner = StateInner::new(prefix, motd);
        State(Arc::new(RwLock::new(inner)))
    }

    /// Adds a new client into the state.
    ///
    /// Called when a connection is accepted.
    pub fn insert(&self, addr: SocketAddr, queue: MessageQueue) {
        self.0.write().unwrap().clients.insert(addr, Client::new(queue));
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
        if self.0.read().unwrap().check_cmd_join(addr, targets, keys) {
            self.0.write().unwrap().apply_cmd_join(addr, targets, keys);
        }
    }

    /// Handles a "MODE" message.
    pub fn cmd_mode(&self, addr: SocketAddr, target: &str, modes: Option<&str>) {
        if let Some(modes) = modes {
            if self.0.read().unwrap().check_cmd_set_modes(addr, target, modes) {
                self.0.write().unwrap().apply_cmd_set_modes(addr, target, modes);
            }
        } else {
            self.0.read().unwrap().apply_cmd_get_modes(addr, target);
        }
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
            if self.0.read().unwrap().check_cmd_set_topic(addr, target, topic) {
                self.0.write().unwrap().apply_cmd_set_topic(addr, target, topic);
            }
        } else {
            self.0.read().unwrap().apply_cmd_get_topic(addr, target);
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
}

impl StateInner {
    /// Creates a new shared state. See `State::new`.
    pub fn new(prefix: String, motd: Option<String>) -> StateInner {
        StateInner {
            prefix,
            clients: HashMap::new(),
            channels: HashMap::new(),
            created_at: Utc::now(),
            motd,
        }
    }

    /// Removes a client from the state. See `State::remove`.
    pub fn remove(&mut self, addr: SocketAddr) {
        let client = self.clients.remove(&addr).unwrap();
        let msg = Message::new(client.nick(), Command::Quit, &[&client.quit_message()]);

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
    pub fn check_cmd_join(&self, addr: SocketAddr, targets: &str, keys: Option<&str>) -> bool {
        if is_valid_channel_name(targets) {
            true
        } else {
            log::debug!("{}: Can't join {:?}: Invalid channel name", addr, targets);
            self.send_reply(addr, rpl::ERR_NOSUCHCHANNEL, &[targets, lines::NO_SUCH_CHANNEL]);
            false
        }
    }

    /// Applies a "JOIN" command issued by the given client with the given parameters.
    pub fn apply_cmd_join(&mut self, addr: SocketAddr, targets: &str, keys: Option<&str>) {
        log::debug!("{}: Join {} (keys={:?})", addr, targets, keys);
        let chan = self.channels.entry(targets.into()).or_insert_with(Channel::new);
        let modes = chan.modes();
        let nick = self.clients[&addr].nick();
        chan.add_member(addr);
        self.broadcast(targets, Message::new(nick, Command::Join, &[targets]));
        self.send_command(addr, Command::Mode, &[targets, &modes]);
        self.send_topic(addr, targets);
        self.send_names(addr, targets);
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
        let msg = Message::new(self.clients[&addr].nick(), Command::Nick, &[nick]);
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
        let nick = self.clients[&addr].nick();
        let msg = if let Some(reason) = reason {
            Message::new(nick, Command::Part, &[target, reason])
        } else {
            Message::new(nick, Command::Part, &[target])
        };
        self.broadcast(target, msg);
        let chan = self.channels.get_mut(target).unwrap();
        chan.members.remove(&addr);
    }

    /// Whether or not a "PRIVMSG" message with the given parameters can be issued by the given
    /// client.
    pub fn check_cmd_privmsg(&self, addr: SocketAddr, targets: &str, _content: &str) -> bool {
        if let Some(ref chan) = self.channels.get(targets) {
            if chan.members.contains_key(&addr) {
                true
            } else {
                log::debug!("{}: Can't send privmsg to {:?}: Not in channel", addr, targets);
                self.send_reply(addr, rpl::ERR_CANNOTSENDTOCHAN,
                                &[targets, lines::CANNOT_SEND_TO_CHAN]);
                false
            }
        } else {
            log::debug!("{}: Can't send privmsg to {:?}: No such channel", addr, targets);
            self.send_reply(addr, rpl::ERR_NOSUCHNICK, &[targets, lines::NO_SUCH_NICK]);
            false
        }
    }

    /// Applies a "PRIVMSG" command issued by the given client with the given parameters.
    pub fn apply_cmd_privmsg(&self, addr: SocketAddr, targets: &str, content: &str) {
        log::debug!("{}: Privmsg to {:?}", addr, targets);
        let client = &self.clients[&addr];
        let msg = Message::new(client.nick(), Command::PrivMsg, &[targets, content]);
        let chan = &self.channels[targets];
        chan.members.keys()
            .filter(|&&a| a != addr)
            .for_each(|&member| self.send(member, msg.clone()));
    }

    /// Applies a "QUIT" command issued by the given client with the given parameters.
    pub fn apply_cmd_quit(&mut self, addr: SocketAddr, reason: Option<&str>) {
        self.clients.get_mut(&addr).unwrap().set_quit_message(reason);
    }

    /// Whether or not a "MODE" message with the two given parameters can be issued by the given
    /// client.
    ///
    /// "MODE" and "TOPIC" have been split in two handlers, one to get the mode/topic, the other to
    /// set it.
    pub fn check_cmd_set_modes(&self, addr: SocketAddr, target: &str, modes: &str) -> bool {
        if modes.is_empty() {
            false
        } else if is_valid_nickname(target) {
            if target == self.clients[&addr].nick() {
                true
            } else {
                self.send_reply(addr, rpl::ERR_USERSDONTMATCH, &[target, lines::USERS_DONT_MATCH]);
                false
            }
        } else if is_valid_channel_name(target) {
            if let Some(chan) = self.channels.get(target) {
                if let Some(member) = chan.members.get(&addr) {
                    if member.channel_operator {
                        true
                    } else {
                        self.send_reply(addr, rpl::ERR_CHANOPRIVSNEEDED,
                                        &[target, lines::CHAN_O_PRIVS_NEEDED]);
                        false
                    }
                } else {
                    self.send_reply(addr, rpl::ERR_USERNOTINCHANNEL,
                                    &["you", target, lines::USER_NOT_IN_CHANNEL]);
                    false
                }
            } else {
                self.send_reply(addr, rpl::ERR_NOSUCHNICK, &[target, lines::NO_SUCH_NICK]);
                false
            }
        } else {
            self.send_reply(addr, rpl::ERR_NOSUCHNICK, &[target, lines::NO_SUCH_NICK]);
            false
        }
    }

    /// Apply a "MODE" command issued by the given client with the given parameters.
    ///
    /// "MODE" and "TOPIC" have been split in two handlers, one to get the mode/topic, the other to
    /// set it.
    pub fn apply_cmd_set_modes(&mut self, addr: SocketAddr, target: &str, modes: &str) {
        log::debug!("{}: Set mode of {:?} to {:?}", addr, target, modes);
        if is_channel_name(target) {
            match self.channels.get_mut(target).unwrap().update_modes(modes) {
                Ok(modes) => {
                    let nick = self.clients[&addr].nick();
                    let msg = Message::new(nick, Command::Mode, &[&modes]);
                    self.broadcast(target, msg);
                },
                Err(flag) => self.send_reply(addr, rpl::ERR_UNKNOWNMODE,
                                             &[flag, lines::UNKNOWN_MODE]),
            }
        } else {
            // TODO
            log::warn!("cmd_set_modes: unimplemented for users");
        }
    }

    /// Applies a "MODE" command issued by the given client with the given parameter.
    ///
    /// "MODE" and "TOPIC" have been split in two handlers, one to get the mode/topic, the other to
    /// set it.
    pub fn apply_cmd_get_modes(&self, addr: SocketAddr, target: &str) {
        if is_channel_name(target) {
            let modes = self.channels[target].modes();
            self.send_reply(addr, rpl::CHANNELMODEIS, &[target, &modes]);
        } else {
            //self.send_err_nosuchchannel(addr, target);
        }
    }

    /// Whether or not a "TOPIC" message with the two given parameters can be issued by the given
    /// client.
    ///
    /// "MODE" and "TOPIC" have been split in two handlers, one to get the mode/topic, the other to
    /// set it.
    pub fn check_cmd_set_topic(&self, addr: SocketAddr, target: &str, topic: &str) -> bool {
        // TODO
        log::warn!("cmd_set_topic: unimplemented");
        false
    }

    /// Apply a "TOPIC" command issued by the given client with the given parameters.
    ///
    /// "MODE" and "TOPIC" have been split in two handlers, one to get the mode/topic, the other to
    /// set it.
    pub fn apply_cmd_set_topic(&mut self, addr: SocketAddr, target: &str, modes: &str) {
        // TODO
        log::warn!("cmd_set_topic: unimplemented");
    }

    /// Applies a "TOPIC" command issued by the given client with the given parameter.
    ///
    /// "MODE" and "TOPIC" have been split in two handlers, one to get the mode/topic, the other to
    /// set it.
    pub fn apply_cmd_get_topic(&self, addr: SocketAddr, target: &str) {
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
    pub fn broadcast(&self, target: &str, msg: Message) {
        let chan = &self.channels[target];
        for &member in chan.members.keys() {
            self.send(member, msg.clone());
        }
    }

    /// Sends the given message to the given client.
    pub fn send(&self, addr: SocketAddr, msg: Message) {
        if let Some(client) = self.clients.get(&addr) {
            log::trace!("us -> {}: {}", addr, msg);
            client.send(msg);
        }
    }

    /// Creates a message from the given command and parameters, and sends it to the given client.
    pub fn send_command(&self, addr: SocketAddr, cmd: Command, params: &[&str]) {
        let msg = Message::new(&self.prefix, cmd, params);
        self.send(addr, msg);
    }

    /// Creates a message from the given reply and parameters, and sends it to the given client.
    ///
    /// It also adds the client's nick as the first parameter, as it is needed for server replies.
    pub fn send_reply(&self, addr: SocketAddr, reply: Reply, params: &[&str]) {
        let nick = self.clients[&addr].nick();
        let reply = format!("{} {}", reply, nick);
        let msg = Message::new(&self.prefix, reply, params);
        self.send(addr, msg);
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
            self.send_reply(addr, rpl::NAMREPLY, &["@", chan_name, &names]);
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
    pub ban_mask: String,
    pub invitation_mask: String,

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
    pub fn new() -> Channel {
        Channel {
            no_privmsg_from_outside: true,
            ..Channel::default()
        }
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

    pub fn update_modes<'a>(&mut self, modes: &'a str) -> Result<String, &'a str> {
        let bmodes = modes.as_bytes();
        let mut value = true;
        let mut applied_modes = String::new();

        if bmodes[0] != b'+' && bmodes[0] != b'-' {
            applied_modes.push('+');
        }

        for i in 0..bmodes.len() {
            let mode = bmodes[i];
            if mode == b'+' {
                value = true;
                applied_modes.push('+');
            } else if mode == b'-' {
                value = false;
                applied_modes.push('-');
            } else if mode == b'a' {
                self.anonymous = value;
                applied_modes.push('a');
            } else if mode == b'i' {
                self.invite_only = value;
                applied_modes.push('i');
            } else if mode == b'm' {
                self.moderated = value;
                applied_modes.push('m');
            } else if mode == b'n' {
                self.no_privmsg_from_outside = value;
                applied_modes.push('n');
            } else if mode == b'q' {
                self.quiet = value;
                applied_modes.push('q');
            } else if mode == b'p' {
                self.private = value;
                applied_modes.push('p');
            } else if mode == b'r' {
                self.reop = value;
                applied_modes.push('r');
            } else if mode == b't' {
                self.topic_restricted = value;
                applied_modes.push('t');
            } else {
                return Err(&modes[i..=i]);
            }
        }

        Ok(applied_modes)
    }

    fn modes(&self) -> String {
        let mut modes = String::from("+");
        if self.anonymous { modes.push('a'); }
        if self.invite_only { modes.push('i'); }
        if self.moderated { modes.push('m'); }
        if self.no_privmsg_from_outside { modes.push('n'); }
        if self.quiet { modes.push('q'); }
        if self.private { modes.push('p'); }
        if self.reop { modes.push('r'); }
        if self.topic_restricted { modes.push('t'); }
        modes
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
    !s.is_empty() && s.len() <= MAX_CHANNEL_NAME_LENGTH
        && (s[0] == b'#' || s[0] == b'&' || s[0] == b'!' || s[0] == b'+')
}

fn is_valid_channel_name(s: &str) -> bool {
    // 7 == ctrl+G
    // https://tools.ietf.org/html/rfc2811.html#section-2.1
    is_channel_name(s) && s.as_bytes()[1..].iter().all(|&c| c != b' ' && c != b',' && c != 7)
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
