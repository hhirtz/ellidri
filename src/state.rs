//! Shared state and API to handle incoming commands.

use crate::channel::Channel;
use crate::client::{Client, MessageQueue, MessageQueueItem};
use crate::config::StateConfig;
use crate::lines;
use crate::message::{Command, Message, Reply, rpl, ResponseBuffer};
use crate::misc::{time_now, UniCase};
use crate::modes;
use std::{cmp, fs, io, net};
use std::collections::{HashMap, HashSet};
use std::sync::{Arc, Mutex};

const SERVER_INFO: &str = include_str!("info.txt");
const SERVER_VERSION: &str = concat!(env!("CARGO_PKG_NAME"), "-", env!("CARGO_PKG_VERSION"));
const MAX_CHANNEL_NAME_LENGTH: usize = 50;
const MAX_NICKNAME_LENGTH: usize = 9;

fn is_valid_channel_name(s: &str) -> bool {
    // https://tools.ietf.org/html/rfc2811.html#section-2.1
    let ctrl_g = 7 as char;
    let first = s.as_bytes()[0];
    !s.is_empty()
        && s.len() <= MAX_CHANNEL_NAME_LENGTH
        && (first == b'#' || first == b'&' || first == b'!' || first == b'+')
        && s.chars().all(|c| c != ' ' && c != ',' && c != ctrl_g && c != ':')
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

/// Pointer to the shared state of the IRC server.
#[derive(Clone)]
pub struct State(Arc<Mutex<StateInner>>);

impl State {
    pub fn new(config: StateConfig) -> State {
        let inner = StateInner::new(config);
        State(Arc::new(Mutex::new(inner)))
    }

    pub fn peer_joined(&self, addr: net::SocketAddr, queue: MessageQueue) {
        self.0.lock().unwrap().peer_joined(addr, queue);
    }

    pub fn peer_quit(&self, addr: &net::SocketAddr, err: Option<io::Error>) {
        self.0.lock().unwrap().peer_quit(addr, err);
    }

    pub fn handle_message(&self, addr: &net::SocketAddr, msg: Message<'_>) {
        self.0.lock().unwrap().handle_message(addr, msg);
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
    org_name: String,
    org_location: String,
    org_mail: String,

    clients: HashMap<net::SocketAddr, Client>,

    channels: HashMap<UniCase<String>, Channel>,

    /// The formatted time when this instance is created. It is sent to the client when they
    /// register (in a "003 RPL_CREATED" reply).
    created_at: String,

    /// The message of the day.
    motd: Option<String>,

    /// The global password. Clients need to issue a PASS command with this password to register.
    password: Option<String>,

    /// Modes applied at the creation of new channels.
    default_chan_mode: String,

    opers: Vec<(String, String)>,
}

impl StateInner {
    /// Creates a new shared state. See `State::new`.
    pub fn new(config: StateConfig) -> StateInner {
        let motd = config.motd_file.and_then(|file| match fs::read_to_string(&file) {
            Ok(motd) => Some(motd),
            Err(err) => {
                log::warn!("Failed to read {:?}: {}", file, err);
                None
            }
        });
        StateInner {
            domain: config.domain,
            org_name: config.org_name,
            org_location: config.org_location,
            org_mail: config.org_mail,
            clients: HashMap::new(),
            channels: HashMap::new(),
            created_at: time_now(),
            motd,
            password: config.password,
            default_chan_mode: config.default_chan_mode,
            opers: config.opers,
        }
    }

    pub fn peer_joined(&mut self, addr: net::SocketAddr, queue: MessageQueue) {
        log::debug!("{}: Connected", addr);
        self.clients.insert(addr, Client::new(queue, addr.to_string()));
    }

    pub fn peer_quit(&mut self, addr: &net::SocketAddr, err: Option<io::Error>) {
        log::debug!("{}: Disconnected", addr);
        if let Some(client) = self.clients.remove(addr) {
            self.remove_client(addr, client, err.map(|err| err.to_string()));
        }
    }

    fn remove_client(&mut self, addr: &net::SocketAddr, client: Client, reason: Option<String>) {
        let mut response = ResponseBuffer::new();
        let msg = response.message(client.full_name(), Command::Quit);
        if let Some(reason) = reason {
            msg.trailing_param(&reason);
        } else {
            msg.build();
        }
        let msg = MessageQueueItem::from(response);

        for channel in self.channels.values() {
            if channel.members.contains_key(&addr) {
                for member in channel.members.keys() {
                    self.send(member, msg.clone());
                }
            }
        }

        self.channels.retain(|_, channel| {
            channel.members.remove(&addr);
            !channel.members.is_empty()
        });
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
                    response.message(&self.domain, rpl::ERR_UNKNOWNCOMMAND)
                        .param(unknown)
                        .trailing_param(lines::UNKNOWN_COMMAND);
                } else {
                    response.message(&self.domain, rpl::ERR_NOTREGISTERED)
                        .trailing_param(lines::NOT_REGISTERED);
                }
                client.send(MessageQueueItem::from(response));
                return;
            }
        };

        if !msg.has_enough_params() {
            let mut response = ResponseBuffer::new();
            match command {
                Command::Nick => {
                    response.message(&self.domain, rpl::ERR_NONICKNAMEGIVEN)
                        .trailing_param(lines::NEED_MORE_PARAMS);
                }
                Command::PrivMsg | Command::Notice if msg.num_params == 0 => {
                    response.message(&self.domain, rpl::ERR_NORECIPIENT)
                        .trailing_param(lines::NEED_MORE_PARAMS);
                }
                Command::PrivMsg | Command::Notice if msg.num_params == 1 => {
                    response.message(&self.domain, rpl::ERR_NOTEXTTOSEND)
                        .trailing_param(lines::NEED_MORE_PARAMS);
                }
                _ => {
                    response.message(&self.domain, rpl::ERR_NEEDMOREPARAMS)
                        .param(command.as_str())
                        .trailing_param(lines::NEED_MORE_PARAMS);
                }
            }
            client.send(MessageQueueItem::from(response));
            return;
        }

        if !client.can_issue_command(command) {
            let mut response = ResponseBuffer::new();
            if client.is_registered() || command == Command::User {
                response.message(&self.domain, rpl::ERR_ALREADYREGISTRED)
                    .trailing_param(lines::ALREADY_REGISTERED);
            } else {
                response.message(&self.domain, rpl::ERR_NOTREGISTERED)
                    .trailing_param(lines::NOT_REGISTERED);
            }
            client.send(MessageQueueItem::from(response));
            return;
        }

        let ps = &msg.params;
        let n = msg.num_params;
        match command {
            Command::Admin => self.cmd_admin(addr),
            Command::Cap => self.cmd_cap(addr, &msg.params[..n]),
            Command::Info => self.cmd_info(addr),
            Command::Invite => self.cmd_invite(addr, ps[0], ps[1]),
            Command::Join => self.cmd_join(addr, ps[0], ps[1]),
            Command::List => self.cmd_list(addr, ps[0]),
            Command::Lusers => self.cmd_lusers(addr),
            Command::Mode => self.cmd_mode(addr, ps[0], ps[1], &msg.params[2..cmp::max(2, n)]),
            Command::Motd => self.cmd_motd(addr),
            Command::Names => self.cmd_names(addr, ps[0]),
            Command::Nick => self.cmd_nick(addr, ps[0]),
            Command::Notice => self.cmd_notice(addr, ps[0], ps[1]),
            Command::Oper => self.cmd_oper(addr, ps[0], ps[1]),
            Command::Part => self.cmd_part(addr, ps[0], ps[1]),
            Command::Pass => self.cmd_pass(addr, ps[0]),
            Command::Ping => self.cmd_ping(addr, ps[0]),
            Command::Pong => {}
            Command::PrivMsg => self.cmd_privmsg(addr, ps[0], ps[1]),
            Command::Quit => self.cmd_quit(addr, ps[0]),
            Command::Time => self.cmd_time(addr),
            Command::Topic => self.cmd_topic(addr, ps[0], ps[1]),
            Command::User => self.cmd_user(addr, ps[0], ps[3]),
            Command::Version => self.cmd_version(addr),
            Command::Reply(_) => {}
        }
    }
}

// Send utilities
impl StateInner {
    /// Sends the given message to all users in the given channel.
    fn broadcast(&self, target: &str, msg: MessageQueueItem) {
        let channel = &self.channels[<&UniCase<str>>::from(target)];
        for member in channel.members.keys() {
            self.send(member, msg.clone());
        }
    }

    /// Sends the given message to the given client.
    fn send(&self, addr: &net::SocketAddr, msg: MessageQueueItem) {
        if let Some(client) = self.clients.get(addr) {
            client.send(msg);
        }
    }

    /// Creates a message from the given reply and parameters, and sends it to the given client.
    /// It also adds the needed client's nick as the first parameter.
    fn send_reply(&self, addr: &net::SocketAddr, r: Reply, params: &[&str]) {
        let client = &self.clients[addr];
        let mut response = ResponseBuffer::new();
        let mut msg = response.message(&self.domain, r).param(client.nick());
        if params.is_empty() {
            msg.build();
        } else {
            for p in &params[0..params.len() - 1] {
                msg = msg.param(p);
            }
            msg.trailing_param(params[params.len() - 1]);
        }
        client.send(MessageQueueItem::from(response));
    }

    fn send_i_support(&self, response: &mut ResponseBuffer, nick: &str) {
        response.message(&self.domain, rpl::ISUPPORT)
            .param(nick)
            .param("CASEMAPPING=ascii")
            .param(&format!("CHANLEN={}", MAX_CHANNEL_NAME_LENGTH))
            .param(modes::CHANMODES)
            .param("EXCEPTS")
            .param("INVEX")
            .param("MODES")
            .param(&format!("NICKLEN={}", MAX_NICKNAME_LENGTH))
            .trailing_param(lines::I_SUPPORT);
    }

    /// Sends the list of nicknames in the channel `channel_name` to the given client.
    fn send_names(&self, addr: &net::SocketAddr, channel_name: &str) {
        if let Some(channel) = &self.channels.get(<&UniCase<str>>::from(channel_name)) {
            if channel.secret && !channel.members.contains_key(&addr) { return; }
            let client = &self.clients[&addr];
            let mut response = ResponseBuffer::new();
            if !channel.members.is_empty() {
                let mut message = response.message(&self.domain, rpl::NAMREPLY)
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
                message.build();
            }
            response.message(&self.domain, rpl::ENDOFNAMES)
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
        response.message(&self.domain, rpl::WELCOME)
            .param(client.nick())
            .trailing_param(lines::WELCOME);
        response.message(&self.domain, rpl::YOURHOST)
            .param(client.nick())
            .trailing_param(lines::YOUR_HOST);
        lines::created(response.message(&self.domain, rpl::CREATED).param(client.nick()),
                       &self.created_at);
        response.message(&self.domain, rpl::MYINFO)
            .param(client.nick())
            .param(&self.domain)
            .param(SERVER_VERSION)
            .param(modes::USER_MODES)
            .param(modes::SIMPLE_CHAN_MODES)
            .param(modes::EXTENDED_CHAN_MODES)
            .build();
        self.send_i_support(&mut response, client.nick());
        client.send(MessageQueueItem::from(response));
        self.cmd_lusers(addr);
        self.cmd_motd(addr);
    }
}

// Command handlers
impl StateInner {
    // ADMIN

    fn cmd_admin(&self, addr: &net::SocketAddr) {
        log::debug!("{}: Request admin info", addr);
        let client = &self.clients[&addr];
        let mut response = ResponseBuffer::new();
        response.message(&self.domain, rpl::ADMINME)
            .param(client.nick())
            .param(&self.domain)
            .trailing_param(lines::ADMIN_ME);
        response.message(&self.domain, rpl::ADMINLOC1)
            .param(client.nick())
            .trailing_param(&self.org_location);
        response.message(&self.domain, rpl::ADMINLOC2)
            .param(client.nick())
            .trailing_param(&self.org_name);
        response.message(&self.domain, rpl::ADMINMAIL)
            .param(client.nick())
            .trailing_param(&self.org_mail);
        client.send(MessageQueueItem::from(response));
    }

    // CAP

    fn cmd_cap(&mut self, addr: &net::SocketAddr, params: &[&str]) {
        // TODO
        unimplemented!()
    }

    // INFO

    fn cmd_info(&self, addr: &net::SocketAddr) {
        log::debug!("{}: Request server info", addr);
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
        client.send(MessageQueueItem::from(response));
    }

    // INVITE

    fn cmd_invite(&mut self, addr: &net::SocketAddr, target_nick: &str, channel_name: &str) {
        let target_addr = self.clients.iter().find(|(_,c)| c.nick() == target_nick).map(|(a,_)| a);
        if target_addr.is_none() {
            log::debug!("{}: Can't invite {:?} to {:?}: Target nick doesn't exist", addr, target_nick, channel_name);
            self.send_reply(addr, rpl::ERR_NOSUCHNICK, &[target_nick, lines::NO_SUCH_NICK]);
            return;
        }
        let target_addr = target_addr.unwrap();

        if let Some(channel) = self.channels.get(<&UniCase<str>>::from(channel_name)) {
            let modes = channel.members.get(addr);
            if modes.is_none() {
                log::debug!("{}: Can't invite {:?} to {:?}: Not on channel", addr, target_nick, channel_name);
                self.send_reply(addr, rpl::ERR_NOTONCHANNEL,
                    &[channel_name, lines::NOT_ON_CHANNEL_TOPIC]);
                return;
            }
            if channel.invite_only && !modes.unwrap().operator {
                log::debug!("{}: Can't invite {:?} to {:?}: Not operator", addr, target_nick, channel_name);
                self.send_reply(addr, rpl::ERR_CHANOPRIVSNEEDED,
                    &[channel_name, lines::CHAN_O_PRIVS_NEEDED]);
                return;
            }
        }

        log::debug!("{}: Invite {:?} to {:?}", addr, target_nick, channel_name);
        let invited = if let Some(channel) = self.channels.get_mut(<&UniCase<str>>::from(channel_name)) {
            channel.invites.insert(*target_addr)
        } else {
            true
        };

        if invited {
            let client = &self.clients[&addr];
            let mut response = ResponseBuffer::new();
            response.message(&self.domain, rpl::INVITING)
                .param(client.nick())
                .param(channel_name)
                .param(target_nick)
                .build();
            client.send(MessageQueueItem::from(response));

            let mut target_res = ResponseBuffer::new();
            target_res.message(client.full_name(), Command::Invite)
                .param(target_nick)
                .param(channel_name)
                .build();
            self.clients[target_addr].send(MessageQueueItem::from(target_res));
        }
    }

    // JOIN

    fn cmd_join(&mut self, addr: &net::SocketAddr, target: &str, key: &str) {
        if !is_valid_channel_name(target) {
            log::debug!("{}: Can't join {:?}: Invalid channel name", addr, target);
            self.send_reply(addr, rpl::ERR_NOSUCHCHANNEL, &[target, lines::NO_SUCH_CHANNEL]);
            return;
        }
        if let Some(channel) = self.channels.get(<&UniCase<str>>::from(target)) {
            let nick = self.clients[&addr].nick();
            if channel.key.as_ref().map_or(false, |ck| key == ck) {
                log::debug!("{}: Can't join {:?}: Bad key", addr, target);
                self.send_reply(addr, rpl::ERR_BADCHANKEY, &[target, lines::BAD_CHAN_KEY]);
                return;
            }
            if channel.user_limit.map_or(false, |user_limit| user_limit <= channel.members.len()) {
                log::debug!("{}: Can't join {:?}: user limit reached", addr, target);
                self.send_reply(addr, rpl::ERR_CHANNELISFULL, &[target, lines::CHANNEL_IS_FULL]);
                return;
            }
            if !channel.is_invited(addr, nick) {
                log::debug!("{}: Can't join {:?}: not invited", addr, target);
                self.send_reply(addr, rpl::ERR_INVITEONLYCHAN, &[target, lines::INVITE_ONLY_CHAN]);
                return;
            }
            if channel.is_banned(nick) {
                log::debug!("{}: Can't join {:?}: Banned", addr, target);
                self.send_reply(addr, rpl::ERR_BANNEDFROMCHAN, &[target, lines::BANNED_FROM_CHAN]);
                return;
            }
        }

        log::debug!("{}: Join {}", addr, target);
        let default_chan_mode = &self.default_chan_mode;
        let channel = self.channels.entry(UniCase(target.to_owned()))
            .or_insert_with(|| Channel::new(&default_chan_mode));
        channel.add_member(*addr);
        let client = &self.clients[&addr];
        let mut join_response = ResponseBuffer::new();
        join_response.message(client.full_name(), Command::Join).param(target).build();
        self.broadcast(target, MessageQueueItem::from(join_response));
        self.send_topic(addr, target);
        self.send_names(addr, target);
    }

    // LIST

    fn cmd_list(&self, addr: &net::SocketAddr, targets: &str) {
        log::debug!("{}: get list of {:?}", addr, targets);
        let client = &self.clients[&addr];
        let mut response = ResponseBuffer::new();
        if targets.is_empty() {
            for (name, channel) in self.channels.iter() {
                if channel.secret && !channel.members.contains_key(&addr) {
                    continue;
                }
                let msg = response.message(&self.domain, rpl::LIST)
                    .param(client.nick())
                    .param(name.as_ref());
                channel.list_entry(msg);
            }
        } else {
            for name in targets.split(',') {
                if let Some(channel) = self.channels.get(<&UniCase<str>>::from(name)) {
                    if channel.secret && !channel.members.contains_key(&addr) {
                        continue;
                    }
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
        client.send(MessageQueueItem::from(response));
    }

    // LUSERS

    fn cmd_lusers(&self, addr: &net::SocketAddr) {
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
                .param(&self.channels.values().filter(|c| !c.secret).count().to_string())
                .trailing_param(lines::LUSER_CHANNELS);
        }
        lines::luser_me(response.message(&self.domain, rpl::LUSERME).param(client.nick()), cs);
        client.send(MessageQueueItem::from(response));
    }

    // MODE

    fn cmd_mode_chan_get(&self, addr: &net::SocketAddr, target: &str) {
        log::debug!("{}: getting modes of {:?}", addr, target);
        if let Some(channel) = self.channels.get(<&UniCase<str>>::from(target)) {
            let client = &self.clients[&addr];
            let mut response = ResponseBuffer::new();
            let msg = response.message(&self.domain, rpl::CHANNELMODEIS)
                .param(client.nick())
                .param(target);
            channel.modes(msg, channel.members.contains_key(&addr));
            client.send(MessageQueueItem::from(response));
        } else {
            self.send_reply(addr, rpl::ERR_NOSUCHCHANNEL, &[target, lines::NO_SUCH_CHANNEL]);
        }
    }

    fn cmd_mode_chan_set(&mut self, addr: &net::SocketAddr, target: &str,
                               modes: &str, modeparams: &[&str])
    {
        let channel = self.channels.get_mut(<&UniCase<str>>::from(target));
        if channel.is_none() {
            log::debug!("{}: can't set modes of {:?}: no such channel", addr, target);
            self.send_reply(addr, rpl::ERR_NOSUCHCHANNEL, &[target, lines::NO_SUCH_CHANNEL]);
            return;
        }
        let channel = channel.unwrap();
        let client_modes = channel.members.get(addr);
        if client_modes.is_none() {
            log::debug!("{}: can't set modes of {:?}: not in channel", addr, target);
            let nick = self.clients[&addr].nick();
            self.send_reply(addr, rpl::ERR_USERNOTINCHANNEL,
                            &[nick, target, lines::USER_NOT_IN_CHANNEL]);
            return;
        }
        let client_modes = client_modes.unwrap();
        if !client_modes.operator {
            log::debug!("{}: can't set modes of {:?}: not operator", addr, target);
            self.send_reply(addr, rpl::ERR_CHANOPRIVSNEEDED, &[target, lines::CHAN_O_PRIVS_NEEDED]);
            return;
        }

        log::debug!("{}: settings modes of {:?} to {:?} (params eluded)", addr, target, modes);
        let mut applied_modes = String::new();
        let mut applied_modeparams = Vec::new();
        let mut response = ResponseBuffer::new();
        let clients = &self.clients;
        for maybe_change in modes::ChannelQuery::new(modes, modeparams.iter().cloned()) { match maybe_change {
            Ok(modes::ChannelModeChange::GetBans) => {
                response.list(&self.domain, rpl::BANLIST, rpl::ENDOFBANLIST,
                              lines::END_OF_BAN_LIST, &channel.ban_mask,
                              |msg| msg.param(clients[&addr].nick()).param(target));
            }
            Ok(modes::ChannelModeChange::GetExceptions) => {
                response.list(&self.domain, rpl::EXCEPTLIST, rpl::ENDOFEXCEPTLIST,
                              lines::END_OF_EXCEPT_LIST, &channel.exception_mask,
                              |msg| msg.param(clients[&addr].nick()).param(target));
            }
            Ok(modes::ChannelModeChange::GetInvitations) => {
                response.list(&self.domain, rpl::INVITELIST, rpl::ENDOFINVITELIST,
                              lines::END_OF_INVITE_LIST, &channel.invitation_mask,
                              |msg| msg.param(clients[&addr].nick()).param(target));
            }
            Ok(change) => match channel.apply_mode_change(change, |a| clients[a].nick()) {
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
                    .param(&mode.to_string())
                    .trailing_param(lines::UNKNOWN_MODE);
            },
            Err(_) => {},
        } }
        if !response.is_empty() {
            self.clients[&addr].send(MessageQueueItem::from(response));
        }
        if !applied_modes.is_empty() {
            let mut response = ResponseBuffer::new();
            let mut msg = response.message(self.clients[&addr].full_name(), Command::Mode)
                .param(target)
                .param(&applied_modes);
            for mp in applied_modeparams {
                msg = msg.param(&mp);
            }
            self.broadcast(target, MessageQueueItem::from(response));
        }
    }

    fn cmd_mode_user_check(&self, addr: &net::SocketAddr, target_user: &str) -> bool {
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

    fn cmd_mode_user_set(&mut self, addr: &net::SocketAddr, target: &str, modes: &str) {
        log::debug!("{}: setting user modes to {:?}", addr, modes);
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
                    .param(&mode.to_string())
                    .trailing_param(lines::UNKNOWN_MODE);
            }
            Err(_) => {}
        } }
        if !applied_modes.is_empty() {
            response.message(client.full_name(), Command::Mode)
                .param(target)
                .trailing_param(&applied_modes);
        }
        if !response.is_empty() {
            client.send(MessageQueueItem::from(response));
        }
    }

    fn cmd_mode_user_get(&self, addr: &net::SocketAddr) {
        log::debug!("{}: getting user modes", addr);
        let client = &self.clients[&addr];
        let mut response = ResponseBuffer::new();
        let msg = response.message(&self.domain, rpl::UMODEIS)
            .param(client.nick());
        client.modes(msg);
        client.send(MessageQueueItem::from(response));
    }

    fn cmd_mode(&mut self, addr: &net::SocketAddr, target: &str,
                          modes: &str, modeparams: &[&str])
    {
        if is_valid_channel_name(target) {
            if modes.is_empty() {
                self.cmd_mode_chan_get(addr, target);
            } else {
                self.cmd_mode_chan_set(addr, target, modes, modeparams);
            }
        } else {
            if !self.cmd_mode_user_check(addr, target) {
                return;
            }
            if modes.is_empty() {
                self.cmd_mode_user_get(addr);
            } else {
                self.cmd_mode_user_set(addr, target, modes);
            }
        }
    }

    // MOTD

    fn cmd_motd(&self, addr: &net::SocketAddr) {
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
                msg.build();
            }
            r.message(&self.domain, rpl::ENDOFMOTD)
                .param(client.nick())
                .trailing_param(lines::END_OF_MOTD);
        } else {
            log::debug!("{}: Sending no-motd error", addr);
            r.message(&self.domain, rpl::ERR_NOMOTD).trailing_param(lines::NO_MOTD);
        }
        client.send(MessageQueueItem::from(r));
    }

    // NAMES

    fn cmd_names(&self, addr: &net::SocketAddr, targets: &str) {
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

    pub fn cmd_nick(&mut self, addr: &net::SocketAddr, nick: &str) {
        if !is_valid_nickname(nick) {
            log::debug!("{}: Can't change nick to {:?}: Bad nickname", addr, nick);
            let client = &self.clients[&addr];
            let mut response = ResponseBuffer::new();
            response.message(&self.domain, rpl::ERR_ERRONEUSNICKNAME)
                .param(client.nick())
                .param(nick)
                .trailing_param(lines::ERRONEOUS_NICNAME);
            client.send(MessageQueueItem::from(response));
            return;
        }
        if self.clients.values().any(|c| c.nick() == nick) {
            log::debug!("{}: Can't change nick to {:?}: Already in use", addr, nick);
            let client = &self.clients[&addr];
            let mut response = ResponseBuffer::new();
            response.message(&self.domain, rpl::ERR_NICKNAMEINUSE)
                .param(client.nick())
                .param(nick)
                .trailing_param(lines::NICKNAME_IN_USE);
            client.send(MessageQueueItem::from(response));
            return;
        }
        log::debug!("{}: Changing nick to {:?}", addr, nick);
        let client = self.clients.get_mut(addr).unwrap();
        client.set_nick(nick);
        let old_state = client.state();
        let new_state = client.apply_command(Command::Nick);
        let mut response = ResponseBuffer::new();
        response.message(client.full_name(), Command::Nick).param(nick).build();
        let msg = MessageQueueItem::from(response);
        if old_state.is_registered() {
            let mut noticed = self.channels.values()
                .filter(|channel| channel.members.contains_key(addr))
                .flat_map(|channel| channel.members.keys())
                .collect::<HashSet<_>>();
            noticed.insert(addr);
            for client in noticed {
                self.send(client, msg.clone());
            }
        } else if new_state.is_registered() {
            self.send_welcome(addr);
        }
    }

    // NOTICE

    fn cmd_notice_user(&self, addr: &net::SocketAddr, target: &str, user: &Client, content: &str) {
        log::debug!("{}: Send notice to {:?}: {:?}", addr, target, content);
        let mut response = ResponseBuffer::new();
        response.message(self.clients[&addr].full_name(), Command::Notice)
            .param(target)
            .trailing_param(content);
        let msg = MessageQueueItem::from(response);
        user.send(msg);
    }

    fn cmd_notice_channel(&self, addr: &net::SocketAddr, target: &str, channel: &Channel, content: &str) {
        log::debug!("{}: Send notice to {:?}: {:?}", addr, target, content);
        let mut response = ResponseBuffer::new();
        response.message(self.clients[&addr].full_name(), Command::Notice)
            .param(target)
            .trailing_param(content);
        let msg = MessageQueueItem::from(response);
        channel.members.keys()
            .filter(|&a| a != addr)
            .for_each(|member| self.send(member, msg.clone()));
    }

    fn cmd_notice(&self, addr: &net::SocketAddr, target: &str, content: &str) {
        if content.is_empty() {
            self.send_reply(addr, rpl::ERR_NOTEXTTOSEND, &[lines::NEED_MORE_PARAMS]);
            return;
        }
        if let Some(ref channel) = self.channels.get(<&UniCase<str>>::from(target)) {
            if channel.can_talk(addr) {
                self.cmd_notice_channel(addr, target, channel, content);
                return;
            } else {
                log::debug!("{}: Can't send notice to {:?}: No voice", addr, target);
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
        log::debug!("{}: Can't send notice to {:?}: No such channel", addr, target);
        self.send_reply(addr, rpl::ERR_NOSUCHNICK, &[target, lines::NO_SUCH_NICK]);
    }

    // OPER

    fn cmd_oper(&mut self, addr: &net::SocketAddr, name: &str, password: &str) {
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
        client.send(MessageQueueItem::from(response));
    }

    // PART

    fn cmd_part(&mut self, addr: &net::SocketAddr, target: &str, reason: &str) {
        let is_on_channel = self.channels.get(<&UniCase<str>>::from(target))
            .map_or(false, |channel| channel.members.contains_key(&addr));
        if !is_on_channel {
            self.send_reply(addr, rpl::ERR_NOTONCHANNEL, &[target, lines::NOT_ON_CHANNEL_PART]);
            return;
        }

        log::debug!("{}: part {:?} {:?}", addr, target, reason);
        let channel = self.channels.get_mut(<&UniCase<str>>::from(target)).unwrap();
        channel.members.remove(&addr);
        let client = &self.clients[&addr];
        let mut response = ResponseBuffer::new();
        if !reason.is_empty() {
            response.message(client.nick(), Command::Part).param(target).trailing_param(reason);
        } else {
            response.message(client.nick(), Command::Part).param(target).build();
        }
        let msg = MessageQueueItem::from(response);
        client.send(msg.clone());
        if channel.members.is_empty() {
            self.channels.remove(<&UniCase<str>>::from(target));
        }
        self.broadcast(target, msg);
    }

    // PASS

    fn cmd_pass(&mut self, addr: &net::SocketAddr, pass: &str) {
        if self.password.as_ref().map_or(false, |p| p == pass) {
            self.clients.get_mut(&addr).unwrap().has_given_password = true;
        }
    }

    // PING

    pub fn cmd_ping(&mut self, addr: &net::SocketAddr, payload: &str) {
        let client = &self.clients[addr];
        let mut response = ResponseBuffer::new();
        response.message(&self.domain, Command::Pong).trailing_param(payload);
        client.send(MessageQueueItem::from(response));
    }

    // PRIVMSG

    fn cmd_privmsg_user(&self, addr: &net::SocketAddr, target: &str, user: &Client, content: &str) {
        let mut response = ResponseBuffer::new();
        response.message(self.clients[&addr].full_name(), Command::PrivMsg)
            .param(target)
            .trailing_param(content);
        user.send(MessageQueueItem::from(response));
    }

    fn cmd_privmsg_channel(&self, addr: &net::SocketAddr, target: &str, channel: &Channel, content: &str) {
        let mut response = ResponseBuffer::new();
        response.message(self.clients[&addr].full_name(), Command::PrivMsg)
            .param(target)
            .trailing_param(content);
        let msg = MessageQueueItem::from(response);
        channel.members.keys()
            .filter(|&a| a != addr)
            .for_each(|member| self.send(member, msg.clone()));
    }

    fn cmd_privmsg(&self, addr: &net::SocketAddr, target: &str, content: &str) {
        if content.is_empty() {
            self.send_reply(addr, rpl::ERR_NOTEXTTOSEND, &[lines::NEED_MORE_PARAMS]);
            return;
        }
        if let Some(ref channel) = self.channels.get(<&UniCase<str>>::from(target)) {
            if channel.can_talk(addr) {
                log::debug!("{}: privmsg to {:?}", addr, target);
                self.cmd_privmsg_channel(addr, target, channel, content);
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

    fn cmd_quit(&mut self, addr: &net::SocketAddr, reason: &str) {
        log::debug!("{}: quit {:?}", addr, reason);
        let client = self.clients.remove(addr).unwrap();
        let mut response = ResponseBuffer::new();
        response.message(&self.domain, "ERROR").trailing_param(lines::CLOSING_LINK);
        client.send(MessageQueueItem::from(response));
        self.remove_client(addr, client, if reason.is_empty() {None} else {Some(reason.to_owned())});
    }

    // TIME

    fn cmd_time(&self, addr: &net::SocketAddr) {
        log::debug!("{}: Request time", addr);
        let time = time_now();
        self.send_reply(addr, rpl::TIME, &[&self.domain, &time]);
    }

    // TOPIC

    fn cmd_topic_set(&mut self, addr: &net::SocketAddr, target: &str, topic: &str) {
        let channel = if let Some(channel) = self.channels.get_mut(<&UniCase<str>>::from(target)) {
            if let Some(modes) = channel.members.get(&addr) {
                if modes.operator || !channel.topic_restricted {
                    channel
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
            channel.topic = None;
        } else {
            channel.topic = Some(topic.to_owned());
        }
        let mut response = ResponseBuffer::new();
        response.message(self.clients[&addr].full_name(), Command::Topic)
            .param(target)
            .trailing_param(topic);
        self.broadcast(target, MessageQueueItem::from(response));
    }

    fn cmd_topic_get(&self, addr: &net::SocketAddr, target: &str) {
        log::debug!("{}: get topic of {:?}", addr, target);
        if let Some(channel) = self.channels.get(<&UniCase<str>>::from(target)) {
            if channel.members.contains_key(&addr) {
                self.send_topic(addr, target);
                return;
            }
        }
        self.send_reply(addr, rpl::ERR_NOTONCHANNEL, &[target, lines::NOT_ON_CHANNEL_TOPIC]);
    }

    fn cmd_topic(&mut self, addr: &net::SocketAddr, target: &str, topic: &str) {
        if topic.is_empty() {
            self.cmd_topic_get(addr, target);
        } else {
            self.cmd_topic_set(addr, target, topic);
        }
    }

    // USER

    fn cmd_user(&mut self, addr: &net::SocketAddr, user: &str, real: &str) {
        log::debug!("{}: Register as {}, '{}'", addr, user, real);
        let client = self.clients.get_mut(&addr).unwrap();
        if self.password.is_some() && !client.has_given_password {
            let mut response = ResponseBuffer::new();
            response.message(&self.domain, rpl::ERR_PASSWDMISMATCH)
                .param(client.nick())
                .trailing_param(lines::PASSWORD_MISMATCH);
            client.send(MessageQueueItem::from(response));
            return;
        }
        client.set_user_real(user, real);
        let old_state = client.state();
        let new_state = client.apply_command(Command::User);
        if new_state.is_registered() && !old_state.is_registered() {
            self.send_welcome(addr);
        }
    }

    // VERSION

    fn cmd_version(&self, addr: &net::SocketAddr) {
        log::debug!("{}: Request version", addr);
        let client = &self.clients[&addr];
        let mut response = ResponseBuffer::new();
        response.message(&self.domain, rpl::VERSION)
            .param(client.nick())
            .param(SERVER_VERSION)
            .param(&self.domain)
            .build();
        self.send_i_support(&mut response, client.nick());
        client.send(MessageQueueItem::from(response));
    }
}
