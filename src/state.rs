//! Shared state and API to handle incoming commands.

use crate::channel::Channel;
use crate::client::{cap, Client, MessageQueue, MessageQueueItem};
use crate::config::StateConfig;
use crate::lines;
use crate::message::{Command, Message, Reply, rpl, ResponseBuffer};
use crate::modes;
use crate::util::time_str;
use ellidri_unicase::UniCase;
use std::{cmp, fs, io, net};
use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use tokio::sync::Mutex;

const SERVER_INFO: &str = include_str!("info.txt");
const SERVER_VERSION: &str = concat!(env!("CARGO_PKG_NAME"), "-", env!("CARGO_PKG_VERSION"));
const MAX_CHANNEL_NAME_LENGTH: usize = 50;
const MAX_NICKNAME_LENGTH: usize = 9;

type ChannelMap = HashMap<UniCase<String>, Channel>;
type ClientMap = HashMap<net::SocketAddr, Client>;
type Result = std::result::Result<(), ()>;

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

fn send_reply<'a>(addr: &net::SocketAddr, domain: &str, clients: &'a ClientMap,
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

fn find_channel<'a>(addr: &net::SocketAddr, domain: &str, clients: &ClientMap,
                    channels: &'a ChannelMap, name: &str) -> std::result::Result<&'a Channel, ()>
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

fn find_nick<'a>(addr: &net::SocketAddr, domain: &str, clients: &'a ClientMap,
                 nick: &str) -> std::result::Result<(net::SocketAddr, &'a Client), ()>
{
    match clients.iter().find(|(_, client)| client.nick() == nick) {
        Some((addr, client)) => Ok((*addr, client)),
        None => {
            log::debug!("{}:         nick doesn't exist", addr);
            send_reply(addr, domain, clients, rpl::ERR_NOSUCHNICK, &[nick, lines::NO_SUCH_NICK]);
            Err(())
        }
    }
}

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
            self.remove_client(addr, client, err.map(|err| err.to_string()));
        }
    }

    fn remove_client(&mut self, addr: &net::SocketAddr, client: Client, reason: Option<String>) {
        let mut response = ResponseBuffer::new();
        {
            let msg = response.prefixed_message(client.full_name(), Command::Quit);
            if let Some(reason) = reason {
                msg.trailing_param(&reason);
            }
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

// Command handlers
impl StateInner {
    // ADMIN

    fn cmd_admin(&self, addr: &net::SocketAddr) -> Result {
        log::debug!("{}: ADMIN", addr);
        let mut response = ResponseBuffer::new();
        let client = &self.clients[&addr];

        response.prefixed_message(&self.domain, rpl::ADMINME)
            .param(client.nick())
            .param(&self.domain)
            .trailing_param(lines::ADMIN_ME);
        response.prefixed_message(&self.domain, rpl::ADMINLOC1)
            .param(client.nick())
            .trailing_param(&self.org_location);
        response.prefixed_message(&self.domain, rpl::ADMINLOC2)
            .param(client.nick())
            .trailing_param(&self.org_name);
        response.prefixed_message(&self.domain, rpl::ADMINMAIL)
            .param(client.nick())
            .trailing_param(&self.org_mail);
        client.send(MessageQueueItem::from(response));
        Ok(())
    }

    // CAP

    fn cmd_cap_list(&self, addr: &net::SocketAddr) -> Result {
        log::debug!("{}: CAP LIST", addr);
        let mut response = ResponseBuffer::new();

        let client = &self.clients[addr];
        client.write_enabled_capabilities(&mut response);
        client.send(MessageQueueItem::from(response));
        Ok(())
    }

    fn cmd_cap_ls(&mut self, addr: &net::SocketAddr, version: &str) -> Result {
        log::debug!("{}: CAP LS {}", addr, version);
        let mut response = ResponseBuffer::new();

        let client = self.clients.get_mut(addr).unwrap();
        client.set_cap_version(version);
        client.write_capabilities(&mut response);
        client.send(MessageQueueItem::from(response));
        Ok(())
    }

    fn cmd_cap_req(&mut self, addr: &net::SocketAddr, capabilities: &str) -> Result {
        log::debug!("{}: CAP REQ {}", addr, capabilities);
        let mut response = ResponseBuffer::new();
        let client = self.clients.get_mut(addr).unwrap();

        if !cap::are_supported(capabilities) {
            response.message(Command::Cap).param("NAK").trailing_param(capabilities);
            client.send(MessageQueueItem::from(response));
            return Err(());
        }
        client.update_capabilities(capabilities);
        response.message(Command::Cap).param("ACK").trailing_param(capabilities);
        client.send(MessageQueueItem::from(response));
        Ok(())
    }

    fn cmd_cap(&mut self, addr: &net::SocketAddr, params: &[&str]) -> Result {
        match params[0] {
            "END" => Ok(()),
            "LIST" => self.cmd_cap_list(addr),
            "LS" => self.cmd_cap_ls(addr, *params.get(1).unwrap_or(&"")),
            "REQ" => self.cmd_cap_req(addr, *params.get(1).unwrap_or(&"")),
            _ => {
                log::debug!("{}: CAP: Bad command {:?}", addr, params[0]);
                self.send_reply(addr, rpl::ERR_INVALIDCAPCMD, &[params[0], lines::UNKNOWN_COMMAND]);
                Err(())
            }
        }
    }

    // INFO

    fn cmd_info(&self, addr: &net::SocketAddr) -> Result {
        log::debug!("{}: INFO", addr);
        let mut response = ResponseBuffer::new();
        let client = &self.clients[addr];

        for line in SERVER_INFO.lines() {
            response.prefixed_message(&self.domain, rpl::INFO)
                .param(client.nick())
                .trailing_param(line);
        }
        response.prefixed_message(&self.domain, rpl::ENDOFINFO)
            .param(client.nick())
            .trailing_param(lines::END_OF_INFO);
        client.send(MessageQueueItem::from(response));
        Ok(())
    }

    // INVITE

    fn cmd_invite(&mut self, addr: &net::SocketAddr, target_nick: &str, channel_name: &str) -> Result {
        let (target_addr, _) = find_nick(addr, &self.domain, &self.clients, target_nick)?;

        if let Some(channel) = self.channels.get(<&UniCase<str>>::from(channel_name)) {
            let modes = channel.members.get(addr);
            if modes.is_none() {
                log::debug!("{}: INVITE {:?} {:?}: Not on channel", addr, target_nick, channel_name);
                self.send_reply(addr, rpl::ERR_NOTONCHANNEL,
                                &[channel_name, lines::NOT_ON_CHANNEL]);
                return Err(());
            }
            if channel.invite_only && !modes.unwrap().operator {
                log::debug!("{}: INVITE {:?} {:?}: Not operator", addr, target_nick, channel_name);
                self.send_reply(addr, rpl::ERR_CHANOPRIVSNEEDED,
                                &[channel_name, lines::CHAN_O_PRIVS_NEEDED]);
                return Err(());
            }
        }

        let invited = match self.channels.get_mut(<&UniCase<str>>::from(channel_name)) {
            Some(channel) => channel.invites.insert(target_addr),
            None => true,
        };
        if !invited {
            return Err(());
        }

        log::debug!("{}: INVITE {:?} {:?}", addr, target_nick, channel_name);
        let client = &self.clients[addr];
        let mut response = ResponseBuffer::new();

        response.prefixed_message(&self.domain, rpl::INVITING)
            .param(client.nick())
            .param(channel_name)
            .param(target_nick);
        client.send(MessageQueueItem::from(response));

        let mut invite = ResponseBuffer::new();
        invite.prefixed_message(client.full_name(), Command::Invite)
            .param(target_nick)
            .param(channel_name);
        self.clients[&target_addr].send(MessageQueueItem::from(invite));

        Ok(())
    }

    // JOIN

    fn cmd_join(&mut self, addr: &net::SocketAddr, target: &str, key: &str) -> Result {
        if !is_valid_channel_name(target) {
            log::debug!("{}: JOIN {:?}: Invalid channel name", addr, target);
            self.send_reply(addr, rpl::ERR_NOSUCHCHANNEL, &[target, lines::NO_SUCH_CHANNEL]);
            return Err(());
        }
        if let Some(channel) = self.channels.get(<&UniCase<str>>::from(target)) {
            if channel.members.contains_key(addr) {
                log::debug!("{}: JOIN {:?}: Already in channel", addr, target);
                return Err(());
            }
            let nick = self.clients[&addr].nick();
            if channel.key.as_ref().map_or(false, |ck| key == ck) {
                log::debug!("{}: JOIN {:?}: Bad key", addr, target);
                self.send_reply(addr, rpl::ERR_BADCHANKEY, &[target, lines::BAD_CHAN_KEY]);
                return Err(());
            }
            if channel.user_limit.map_or(false, |user_limit| user_limit <= channel.members.len()) {
                log::debug!("{}: JOIN {:?}: user limit reached", addr, target);
                self.send_reply(addr, rpl::ERR_CHANNELISFULL, &[target, lines::CHANNEL_IS_FULL]);
                return Err(());
            }
            if !channel.is_invited(addr, nick) {
                log::debug!("{}: JOIN {:?}: not invited", addr, target);
                self.send_reply(addr, rpl::ERR_INVITEONLYCHAN, &[target, lines::INVITE_ONLY_CHAN]);
                return Err(());
            }
            if channel.is_banned(nick) {
                log::debug!("{}: JOIN {:?}: Banned", addr, target);
                self.send_reply(addr, rpl::ERR_BANNEDFROMCHAN, &[target, lines::BANNED_FROM_CHAN]);
                return Err(());
            }
        }

        log::debug!("{}: JOIN {}", addr, target);
        let client = self.clients.get_mut(addr).unwrap();

        let default_chan_mode = &self.default_chan_mode;
        let channel = self.channels.entry(UniCase(target.to_owned()))
            .or_insert_with(|| Channel::new(&default_chan_mode));
        channel.add_member(*addr);
        client.update_idle_time();

        let mut join_response = ResponseBuffer::new();
        join_response.prefixed_message(client.full_name(), Command::Join).param(target);
        self.broadcast(target, MessageQueueItem::from(join_response));
        self.send_topic(addr, target);
        self.send_names(addr, target);

        Ok(())
    }

    // KICK

    fn cmd_kick(&mut self, addr: &net::SocketAddr, channel_names: &str, nicks: &str, reason: &str) -> Result {
        let channel = find_channel(addr, &self.domain, &self.clients, &self.channels, channel_names)?;
        let member_modes = match channel.members.get(addr) {
            Some(member_modes) => member_modes,
            None => {
                log::debug!("{}: KICK {:?} {:?}: not on channel", addr, nicks, channel_names);
                self.send_reply(addr, rpl::ERR_NOTONCHANNEL,
                                &[channel_names, lines::NOT_ON_CHANNEL]);
                return Err(());
            }
        };
        if !member_modes.operator {
            log::debug!("{}: KICK {:?} {:?}: not operator", addr, nicks, channel_names);
            self.send_reply(addr, rpl::ERR_CHANOPRIVSNEEDED,
                            &[channel_names, lines::CHAN_O_PRIVS_NEEDED]);
            return Err(());
        }
        let clients = &self.clients;
        let kicked_addrs = channel.members.keys()
            .find(|addr| clients[addr].nick() == nicks)
            .copied();
        let kicked_addrs = match kicked_addrs {
            Some(kicked_addrs) => kicked_addrs,
            None => {
                log::debug!("{}: KICK {:?} {:?}: targets not on channel",
                            addr, nicks, channel_names);
                self.send_reply(addr, rpl::ERR_NOTONCHANNEL,
                                &[nicks, channel_names, lines::USER_NOT_IN_CHANNEL]);
                return Err(());
            }
        };

        log::debug!("{}: KICK {:?} {:?}", addr, nicks, channel_names);
        let client = &self.clients[addr];

        let mut kick_response = ResponseBuffer::new();
        {
            let msg = kick_response.prefixed_message(client.full_name(), Command::Kick)
                .param(channel_names)
                .param(nicks);
            if !reason.is_empty() {
                msg.trailing_param(reason);
            }
        }
        let msg = MessageQueueItem::from(kick_response);
        let channel = self.channels.get_mut(<&UniCase<str>>::from(channel_names)).unwrap();
        for member in channel.members.keys() {
            self.clients[member].send(msg.clone());
        }
        channel.members.remove(&kicked_addrs);

        Ok(())
    }

    // LIST

    fn cmd_list(&self, addr: &net::SocketAddr, targets: &str) -> Result {
        log::debug!("{}: get list of {:?}", addr, targets);
        let mut response = ResponseBuffer::new();
        let client = &self.clients[addr];

        if targets.is_empty() {
            for (name, channel) in &self.channels {
                if channel.secret && !channel.members.contains_key(addr) {
                    continue;
                }
                let msg = response.prefixed_message(&self.domain, rpl::LIST)
                    .param(client.nick())
                    .param(name.as_ref());
                channel.list_entry(msg);
            }
        } else {
            for name in targets.split(',') {
                if let Some(channel) = self.channels.get(<&UniCase<str>>::from(name)) {
                    if channel.secret && !channel.members.contains_key(addr) {
                        continue;
                    }
                    let msg = response.prefixed_message(&self.domain, rpl::LIST)
                        .param(client.nick())
                        .param(name);
                    channel.list_entry(msg);
                }
            }
        }
        response.prefixed_message(&self.domain, rpl::LISTEND)
            .param(client.nick())
            .trailing_param(lines::END_OF_LIST);
        client.send(MessageQueueItem::from(response));

        Ok(())
    }

    // LUSERS

    fn cmd_lusers(&self, addr: &net::SocketAddr) -> Result {
        log::debug!("{}: LUSERS", addr);
        let mut response = ResponseBuffer::new();
        let client = &self.clients[&addr];

        lines::luser_client(
            response.prefixed_message(&self.domain, rpl::LUSERCLIENT).param(client.nick()),
            self.clients.len());
        // TODO LUSEROP
        // TODO LUSERUNKNOWN
        if !self.channels.is_empty() {
            response.prefixed_message(&self.domain, rpl::LUSERCHANNELS)
                .param(client.nick())
                .param(&self.channels.values().filter(|c| !c.secret).count().to_string())
                .trailing_param(lines::LUSER_CHANNELS);
        }
        lines::luser_me(response.prefixed_message(&self.domain, rpl::LUSERME).param(client.nick()),
                        self.clients.len());
        client.send(MessageQueueItem::from(response));

        Ok(())
    }

    // MODE

    fn cmd_mode_chan_get(&self, addr: &net::SocketAddr, target: &str) -> Result {
        let channel = find_channel(addr, &self.domain, &self.clients, &self.channels, target)?;

        log::debug!("{}: MODE {:?}", addr, target);
        let mut response = ResponseBuffer::new();
        let client = &self.clients[&addr];

        let msg = response.prefixed_message(&self.domain, rpl::CHANNELMODEIS)
            .param(client.nick())
            .param(target);
        channel.modes(msg, channel.members.contains_key(addr));
        client.send(MessageQueueItem::from(response));

        Ok(())
    }

    fn cmd_mode_chan_set(&mut self, addr: &net::SocketAddr, target: &str,
                               modes: &str, modeparams: &[&str]) -> Result
    {
        let channel = match self.channels.get_mut(<&UniCase<str>>::from(target)) {
            Some(channel) => channel,
            None => {
                log::debug!("{}: MODE {:?}: no such channel", addr, target);
                self.send_reply(addr, rpl::ERR_NOSUCHCHANNEL, &[target, lines::NO_SUCH_CHANNEL]);
                return Err(());
            }
        };
        let client_modes = match channel.members.get(addr) {
            Some(client_modes) => client_modes,
            None => {
                log::debug!("{}: MODE {:?}: not in channel", addr, target);
                let nick = self.clients[&addr].nick();
                self.send_reply(addr, rpl::ERR_USERNOTINCHANNEL,
                                &[nick, target, lines::USER_NOT_IN_CHANNEL]);
                return Err(());
            }
        };
        if modes::needs_chanop(modes) && !client_modes.operator {
            log::debug!("{}: MODE {:?} {:?}: not operator", addr, target, modes);
            self.send_reply(addr, rpl::ERR_CHANOPRIVSNEEDED, &[target, lines::CHAN_O_PRIVS_NEEDED]);
            return Err(());
        }

        log::debug!("{}: MODE {:?} {:?} (params eluded)", addr, target, modes);
        let mut response = ResponseBuffer::new();
        let clients = &self.clients;

        let mut applied_modes = String::new();
        let mut applied_modeparams = Vec::new();
        for maybe_change in modes::channel_query(modes, modeparams.iter().cloned()) { match maybe_change {
            Ok(modes::ChannelModeChange::GetBans) => {
                response.reply_list(&self.domain, rpl::BANLIST, rpl::ENDOFBANLIST,
                                    lines::END_OF_BAN_LIST, &channel.ban_mask,
                                    |msg| msg.param(clients[&addr].nick()).param(target));
            }
            Ok(modes::ChannelModeChange::GetExceptions) => {
                response.reply_list(&self.domain, rpl::EXCEPTLIST, rpl::ENDOFEXCEPTLIST,
                                    lines::END_OF_EXCEPT_LIST, &channel.exception_mask,
                                    |msg| msg.param(clients[&addr].nick()).param(target));
            }
            Ok(modes::ChannelModeChange::GetInvitations) => {
                response.reply_list(&self.domain, rpl::INVITELIST, rpl::ENDOFINVITELIST,
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
                    response.prefixed_message(&self.domain, rpl::ERR_USERNOTINCHANNEL)
                        .param(self.clients[&addr].nick())
                        .param(change.param().unwrap())
                        .trailing_param(lines::USER_NOT_IN_CHANNEL);
                }
                Err(rpl::ERR_KEYSET) => {
                    response.prefixed_message(&self.domain, rpl::ERR_KEYSET)
                        .param(self.clients[&addr].nick())
                        .param(target)
                        .trailing_param(lines::KEY_SET);
                }
                Err(_) => {}
            }
            Err(modes::Error::UnknownMode(mode)) => {
                response.prefixed_message(&self.domain, rpl::ERR_UNKNOWNMODE)
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
            {
                let mut msg = response.prefixed_message(self.clients[&addr].full_name(), Command::Mode)
                    .param(target)
                    .param(&applied_modes);
                for mp in applied_modeparams {
                    msg = msg.param(&mp);
                }
            }
            self.broadcast(target, MessageQueueItem::from(response));
        }

        Ok(())
    }

    fn cmd_mode_user_check(&self, addr: &net::SocketAddr, target_nick: &str) -> Result {
        let (target_addr, _) = find_nick(addr, &self.domain, &self.clients, target_nick)?;
        if &target_addr != addr {
            log::debug!("{}: can't set modes: users don't match", addr);
            self.send_reply(addr, rpl::ERR_USERSDONTMATCH,
                            &[target_nick, lines::USERS_DONT_MATCH]);
            return Err(());
        }
        Ok(())
    }

    fn cmd_mode_user_set(&mut self, addr: &net::SocketAddr, target: &str, modes: &str) -> Result {
        log::debug!("{}: setting user modes to {:?}", addr, modes);
        let mut response = ResponseBuffer::new();
        let client = self.clients.get_mut(&addr).unwrap();

        let mut applied_modes = String::new();
        for maybe_change in modes::user_query(modes) { match maybe_change {
            Ok(change) => if client.apply_mode_change(change) {
                log::debug!("  - Applied {:?}", change);
                applied_modes.push(if change.value() {'+'} else {'-'});
                applied_modes.push(change.symbol());
            }
            Err(modes::Error::UnknownMode(mode)) => {
                response.prefixed_message(&self.domain, rpl::ERR_UMODEUNKNOWNFLAG)
                    .param(client.nick())
                    .param(&mode.to_string())
                    .trailing_param(lines::UNKNOWN_MODE);
            }
            Err(_) => {}
        } }
        if !applied_modes.is_empty() {
            response.prefixed_message(client.full_name(), Command::Mode)
                .param(target)
                .trailing_param(&applied_modes);
        }
        if !response.is_empty() {
            client.send(MessageQueueItem::from(response));
        }

        Ok(())
    }

    fn cmd_mode_user_get(&self, addr: &net::SocketAddr) -> Result {
        log::debug!("{}: getting user modes", addr);
        let mut response = ResponseBuffer::new();
        let client = &self.clients[&addr];

        let msg = response.prefixed_message(&self.domain, rpl::UMODEIS)
            .param(client.nick());
        client.write_modes(msg);
        client.send(MessageQueueItem::from(response));

        Ok(())
    }

    fn cmd_mode(&mut self, addr: &net::SocketAddr, target: &str,
                modes: &str, modeparams: &[&str]) -> Result
    {
        if is_valid_channel_name(target) {
            if modes.is_empty() {
                self.cmd_mode_chan_get(addr, target)
            } else {
                self.cmd_mode_chan_set(addr, target, modes, modeparams)
            }
        } else {
            self.cmd_mode_user_check(addr, target)?;
            if modes.is_empty() {
                self.cmd_mode_user_get(addr)
            } else {
                self.cmd_mode_user_set(addr, target, modes)
            }
        }
    }

    // MOTD

    fn cmd_motd(&self, addr: &net::SocketAddr) -> Result {
        log::debug!("{}: MOTD", addr);
        let mut response = ResponseBuffer::new();
        let client = &self.clients[&addr];

        if let Some(ref motd) = self.motd {
            lines::motd_start(response.prefixed_message(&self.domain, rpl::MOTDSTART).param(client.nick()),
                              &self.domain);
            for line in motd.lines() {
                let mut msg = response.prefixed_message(&self.domain, rpl::MOTD)
                    .param(client.nick());
                let trailing = msg.raw_trailing_param();
                trailing.push_str("- ");
                trailing.push_str(line);
            }
            response.prefixed_message(&self.domain, rpl::ENDOFMOTD)
                .param(client.nick())
                .trailing_param(lines::END_OF_MOTD);
        } else {
            response.prefixed_message(&self.domain, rpl::ERR_NOMOTD)
                .param(client.nick())
                .trailing_param(lines::NO_MOTD);
        }
        client.send(MessageQueueItem::from(response));

        Ok(())
    }

    // NAMES

    fn cmd_names(&self, addr: &net::SocketAddr, targets: &str) -> Result {
        log::debug!("{}: NAMES {:?}", addr, targets);

        if targets.is_empty() || targets == "*" {
            self.send_reply(addr, rpl::ENDOFNAMES, &["*", lines::END_OF_NAMES]);
        } else {
            for target in targets.split(',') {
                self.send_names(addr, target);
            }
        }

        Ok(())
    }

    // NICK

    pub fn cmd_nick(&mut self, addr: &net::SocketAddr, nick: &str) -> Result {
        if !is_valid_nickname(nick) {
            log::debug!("{}: NICK {:?}: Bad nickname", addr, nick);
            self.send_reply(addr, rpl::ERR_ERRONEUSNICKNAME, &[nick, lines::ERRONEOUS_NICNAME]);
            return Err(());
        }
        if self.clients.values().any(|c| c.nick() == nick) {
            log::debug!("{}: NICK {:?}: Already in use", addr, nick);
            self.send_reply(addr, rpl::ERR_NICKNAMEINUSE, &[nick, lines::NICKNAME_IN_USE]);
            return Err(());
        }

        let client = self.clients.get_mut(addr).unwrap();

        if !client.is_registered() {
            log::debug!("{}: NICK {:?}: Is not registered", addr, nick);
            client.set_nick(nick);
            return Ok(());
        }

        log::debug!("{}: NICK {:?}", addr, nick);
        let mut response = ResponseBuffer::new();

        response.prefixed_message(client.full_name(), Command::Nick).param(nick);
        let msg = MessageQueueItem::from(response);
        client.send(msg.clone());

        client.set_nick(nick);

        let noticed = self.channels.values()
            .filter(|channel| channel.members.contains_key(addr))
            .flat_map(|channel| channel.members.keys())
            .collect::<HashSet<_>>();
        for addr in noticed {
            self.send(addr, msg.clone());
        }

        Ok(())
    }

    // NOTICE

    fn cmd_notice(&mut self, addr: &net::SocketAddr, target: &str, content: &str) -> Result {
        if content.is_empty() {
            self.send_reply(addr, rpl::ERR_NOTEXTTOSEND, &[lines::NEED_MORE_PARAMS]);
            return Err(());
        }
        if is_valid_channel_name(target) {
            let channel = find_channel(addr, &self.domain, &self.clients, &self.channels, target)?;

            if !channel.can_talk(addr) {
                log::debug!("{}: NOTICE {:?}", addr, target);
                self.send_reply(addr, rpl::ERR_CANNOTSENDTOCHAN,
                                &[target, lines::CANNOT_SEND_TO_CHAN]);
                return Err(());
            }

            log::debug!("{}: NOTICE {:?}", addr, target);
            let mut response = ResponseBuffer::new();

            response.prefixed_message(self.clients[addr].full_name(), Command::Notice)
                .param(target)
                .trailing_param(content);
            let msg = MessageQueueItem::from(response);
            channel.members.keys()
                .filter(|&a| a != addr)
                .for_each(|member| self.send(member, msg.clone()));
        } else {
            let (_, target_client) = find_nick(addr, &self.domain, &self.clients, target)?;

            log::debug!("{}: NOTICE {:?}", addr, target);
            let mut response = ResponseBuffer::new();

            response.prefixed_message(self.clients[addr].full_name(), Command::Notice)
                .param(target)
                .trailing_param(content);
            target_client.send(MessageQueueItem::from(response));
        }
        self.clients.get_mut(addr).unwrap().update_idle_time();
        Ok(())
    }

    // OPER

    fn cmd_oper(&mut self, addr: &net::SocketAddr, name: &str, password: &str) -> Result {
        // TODO oper_hosts
        if !self.opers.iter().any(|(n, p)| n == name && p == password) {
            log::debug!("{}: OPER {:?} {:?}: Password mismatch", addr, name, password);
            self.send_reply(addr, rpl::ERR_PASSWDMISMATCH, &[lines::PASSWORD_MISMATCH]);
            return Err(());
        }
        log::debug!("{}: OPER", addr);
        let mut response = ResponseBuffer::new();
        let client = self.clients.get_mut(&addr).unwrap();

        client.operator = true;
        response.prefixed_message(&self.domain, Command::Mode)
            .param(client.nick())
            .param("+o");
        response.prefixed_message(&self.domain, rpl::YOUREOPER)
            .param(client.nick())
            .param(lines::YOURE_OPER);
        client.send(MessageQueueItem::from(response));

        Ok(())
    }

    // PART

    fn cmd_part(&mut self, addr: &net::SocketAddr, target: &str, reason: &str) -> Result {
        let channel = match self.channels.get_mut(<&UniCase<str>>::from(target)) {
            Some(channel) => channel,
            None => {
                log::debug!("{}: PART {:?}: Not on channel", addr, target);
                self.send_reply(addr, rpl::ERR_NOTONCHANNEL, &[target, lines::NOT_ON_CHANNEL]);
                return Err(());
            }
        };
        if !channel.members.contains_key(addr) {
            log::debug!("{}: PART {:?}: Not on channel", addr, target);
            self.send_reply(addr, rpl::ERR_NOTONCHANNEL, &[target, lines::NOT_ON_CHANNEL]);
            return Err(());
        }

        log::debug!("{}: PART {:?} {:?}", addr, target, reason);
        let mut response = ResponseBuffer::new();
        let client = &self.clients[&addr];

        channel.members.remove(&addr);
        if reason.is_empty() {
            response.prefixed_message(client.full_name(), Command::Part).param(target);
        } else {
            response.prefixed_message(client.full_name(), Command::Part).param(target).trailing_param(reason);
        }
        let msg = MessageQueueItem::from(response);
        client.send(msg.clone());
        if channel.members.is_empty() {
            self.channels.remove(<&UniCase<str>>::from(target));
        }
        self.broadcast(target, msg);
        Ok(())
    }

    // PASS

    fn cmd_pass(&mut self, addr: &net::SocketAddr, password: &str) -> Result {
        log::debug!("{}: PASS {:?}", addr, password);

        if self.password.as_ref().map_or(false, |p| p == password) {
            self.clients.get_mut(&addr).unwrap().has_given_password = true;
        }

        Ok(())
    }

    // PING

    fn cmd_ping(&mut self, addr: &net::SocketAddr, payload: &str) -> Result {
        log::debug!("{}: PING {:?}", addr, payload);
        let mut response = ResponseBuffer::new();
        let client = &self.clients[addr];

        response.prefixed_message(&self.domain, Command::Pong).trailing_param(payload);
        client.send(MessageQueueItem::from(response));

        Ok(())
    }

    // PRIVMSG

    fn cmd_privmsg(&mut self, addr: &net::SocketAddr, target: &str, content: &str) -> Result {
        if content.is_empty() {
            self.send_reply(addr, rpl::ERR_NOTEXTTOSEND, &[lines::NEED_MORE_PARAMS]);
            return Err(());
        }
        if is_valid_channel_name(target) {
            let channel = find_channel(addr, &self.domain, &self.clients, &self.channels, target)?;

            if !channel.can_talk(addr) {
                log::debug!("{}: PRIVMSG {:?}", addr, target);
                self.send_reply(addr, rpl::ERR_CANNOTSENDTOCHAN,
                                &[target, lines::CANNOT_SEND_TO_CHAN]);
                return Err(());
            }

            log::debug!("{}: PRIVMSG {:?}", addr, target);
            let mut response = ResponseBuffer::new();

            response.prefixed_message(self.clients[addr].full_name(), Command::PrivMsg)
                .param(target)
                .trailing_param(content);
            let msg = MessageQueueItem::from(response);
            channel.members.keys()
                .filter(|&a| a != addr)
                .for_each(|member| self.send(member, msg.clone()));
        } else {
            let (_, target_client) = find_nick(addr, &self.domain, &self.clients, target)?;

            log::debug!("{}: PRIVMSG {:?}", addr, target);
            let mut response = ResponseBuffer::new();

            response.prefixed_message(self.clients[addr].full_name(), Command::PrivMsg)
                .param(target)
                .trailing_param(content);
            target_client.send(MessageQueueItem::from(response));
        }
        self.clients.get_mut(addr).unwrap().update_idle_time();
        Ok(())
    }

    // QUIT

    fn cmd_quit(&mut self, addr: &net::SocketAddr, reason: &str) -> Result {
        log::debug!("{}: QUIT {:?}", addr, reason);
        let mut response = ResponseBuffer::new();
        let client = self.clients.remove(addr).unwrap();

        response.prefixed_message(&self.domain, "ERROR").trailing_param(lines::CLOSING_LINK);
        client.send(MessageQueueItem::from(response));
        self.remove_client(addr, client, if reason.is_empty() {None} else {Some(reason.to_owned())});

        Err(())
    }

    // TIME

    fn cmd_time(&self, addr: &net::SocketAddr) -> Result {
        log::debug!("{}: TIME", addr);
        let time = time_str();
        self.send_reply(addr, rpl::TIME, &[&self.domain, &time]);
        Ok(())
    }

    // TOPIC

    fn cmd_topic_set(&mut self, addr: &net::SocketAddr, target: &str, topic: &str) -> Result {
        let channel = match self.channels.get_mut(<&UniCase<str>>::from(target)) {
            Some(channel) => channel,
            None => {
                log::debug!("{}: TOPIC {:?}: no such channel", addr, target);
                self.send_reply(addr, rpl::ERR_NOSUCHCHANNEL, &[target, lines::NO_SUCH_CHANNEL]);
                return Err(());
            }
        };
        let modes = match channel.members.get(addr) {
            Some(modes) => modes,
            None => {
                log::debug!("{}: TOPIC {:?}: not on channel", addr, target);
                self.send_reply(addr, rpl::ERR_NOTONCHANNEL, &[target, lines::NOT_ON_CHANNEL]);
                return Err(());
            }
        };
        if !modes.operator && channel.topic_restricted {
            log::debug!("{}: TOPIC {:?}: not operator", addr, target);
            self.send_reply(addr, rpl::ERR_CHANOPRIVSNEEDED, &[target, lines::CHAN_O_PRIVS_NEEDED]);
            return Err(());
        }

        log::debug!("{}: TOPIC {:?} {:?}", addr, target, topic);
        let mut response = ResponseBuffer::new();

        channel.topic = if topic.is_empty() { None } else { Some(topic.to_owned()) };
        response.prefixed_message(self.clients[&addr].full_name(), Command::Topic)
            .param(target)
            .trailing_param(topic);
        self.broadcast(target, MessageQueueItem::from(response));

        Ok(())
    }

    fn cmd_topic_get(&self, addr: &net::SocketAddr, target: &str) -> Result {
        let channel = find_channel(addr, &self.domain, &self.clients, &self.channels, target)?;
        if channel.secret && !channel.members.contains_key(addr) {
            log::debug!("{}: TOPIC {:?}: Not on channel", addr, target);
            self.send_reply(addr, rpl::ERR_NOTONCHANNEL, &[target, lines::NOT_ON_CHANNEL]);
            return Err(());
        }

        log::debug!("{}: TOPIC {:?}", addr, target);
        self.send_topic(addr, target);

        Ok(())
    }

    fn cmd_topic(&mut self, addr: &net::SocketAddr, target: &str, topic: Option<&str>) -> Result {
        if let Some(topic) = topic {
            self.cmd_topic_set(addr, target, topic)
        } else {
            self.cmd_topic_get(addr, target)
        }
    }

    // USER

    fn cmd_user(&mut self, addr: &net::SocketAddr, user: &str, real: &str) -> Result {
        let client = self.clients.get_mut(&addr).unwrap();
        if self.password.is_some() && !client.has_given_password {
            log::debug!("{}: USER {:?} _ _ {:?}: Password mismatch", addr, user, real);
            let mut response = ResponseBuffer::new();
            response.prefixed_message(&self.domain, rpl::ERR_PASSWDMISMATCH)
                .param(client.nick())
                .trailing_param(lines::PASSWORD_MISMATCH);
            client.send(MessageQueueItem::from(response));
            return Err(());
        }

        log::debug!("{}: USER {:?} _ _ {:?}", addr, user, real);
        client.set_user_real(user, real);

        Ok(())
    }

    // VERSION

    fn cmd_version(&self, addr: &net::SocketAddr) -> Result {
        log::debug!("{}: VERSION", addr);
        let mut response = ResponseBuffer::new();
        let client = &self.clients[&addr];

        response.prefixed_message(&self.domain, rpl::VERSION)
            .param(client.nick())
            .param(SERVER_VERSION)
            .param(&self.domain);
        self.write_i_support(&mut response, client.nick());
        client.send(MessageQueueItem::from(response));

        Ok(())
    }

    // WHO

    fn cmd_who(&self, addr: &net::SocketAddr, mask: &str, o: &str) -> Result {
        log::debug!("{}: WHO {:?}", addr, mask);
        let mut response = ResponseBuffer::new();

        let mask = if mask.is_empty() {"*"} else {mask};
        let o = o == "o";  // best line
        let client_nick = self.clients[addr].nick();
        for client in self.clients.values() {
            if client.nick() != mask || (o && !client.operator) {
                continue;
            }
            response.prefixed_message(&self.domain, rpl::WHOREPLY)
                .param(client_nick)
                .param("*")
                .param(client.user())
                .param(client.host())
                .param(&self.domain)
                .param(client.nick())
                .param("H")
                .trailing_param(client.real());
        }
        response.prefixed_message(&self.domain, rpl::ENDOFWHO)
            .param(client_nick)
            .param(mask)
            .trailing_param(lines::END_OF_WHO);
        self.send(addr, MessageQueueItem::from(response));

        Ok(())
    }

    // WHOIS

    fn cmd_whois(&self, addr: &net::SocketAddr, nick: &str) -> Result {
        let (_, target_client) = find_nick(addr, &self.domain, &self.clients, nick)?;

        log::debug!("{}: WHOIS {:?}", addr, nick);
        let client = &self.clients[addr];

        let mut response = ResponseBuffer::new();
        response.prefixed_message(&self.domain, rpl::WHOISUSER)
            .param(client.nick())
            .param(target_client.nick())
            .param(target_client.user())
            .param(target_client.host())
            .param("*")
            .trailing_param(target_client.real());
        response.prefixed_message(&self.domain, rpl::WHOISSERVER)
            .param(client.nick())
            .param(target_client.nick())
            .param(&self.domain)
            .trailing_param(&self.org_name);
        response.prefixed_message(&self.domain, rpl::WHOISIDLE)
            .param(client.nick())
            .param(target_client.nick())
            .param(&client.idle_time().to_string())
            .param(&client.signon_time().to_string())
            .trailing_param(lines::WHOIS_IDLE);
        response.prefixed_message(&self.domain, rpl::ENDOFWHOIS)
            .param(client.nick())
            .param(target_client.nick())
            .trailing_param(lines::END_OF_WHOIS);
        client.send(MessageQueueItem::from(response));

        Ok(())
    }
}
