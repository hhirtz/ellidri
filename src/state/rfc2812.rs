//! Handlers for the RFC 2812 client-to-server interface.
//!
//! <https://tools.ietf.org/html/rfc2812.html>

use crate::channel::Channel;
use crate::client::MessageQueueItem;
use crate::lines;
use crate::message::{Buffer, Command, rpl, ReplyBuffer};
use crate::modes;
use crate::util::time_str;
use ellidri_unicase::UniCase;
use std::collections::HashSet;
use std::net;
use super::{HandlerResult as Result, find_channel, find_member, find_nick};

/// Whether a string is accepted as a channel name by ellidri or not.
fn is_valid_channel_name(s: &str) -> bool {
    // https://tools.ietf.org/html/rfc2811.html#section-2.1
    let ctrl_g = 7 as char;
    if s.is_empty() {
        return false;
    }
    let first = s.as_bytes()[0];
    s.len() <= super::MAX_CHANNEL_NAME_LENGTH
        && (first == b'#' || first == b'&')
        && s.chars().all(|c| c != ' ' && c != ',' && c != ctrl_g && c != ':')
}

/// Whether a string is accepted as a nickname by ellidri or not.
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
    !s.is_empty()
        && s.len() <= super::MAX_NICKNAME_LENGTH
        && s.iter().all(is_valid_nickname_char)
        && s[0] != b'-' && !(b'0' <= s[0] && s[0] <= b'9')
}

// Command handlers
impl super::StateInner {
    // ADMIN

    pub fn cmd_admin(&self, rb: &mut ReplyBuffer) -> Result {
        rb.reply(rpl::ADMINME).param(&self.domain).trailing_param(lines::ADMIN_ME);
        rb.reply(rpl::ADMINLOC1).trailing_param(&self.org_location);
        rb.reply(rpl::ADMINLOC2).trailing_param(&self.org_name);
        rb.reply(rpl::ADMINMAIL).trailing_param(&self.org_mail);

        Ok(())
    }

    // INFO

    pub fn cmd_info(&self, rb: &mut ReplyBuffer) -> Result {
        for line in super::SERVER_INFO.lines() {
            rb.reply(rpl::INFO).trailing_param(line);
        }
        rb.reply(rpl::ENDOFINFO).trailing_param(lines::END_OF_INFO);

        Ok(())
    }

    // INVITE

    // TODO 443 USERONCHANNEL
    pub fn cmd_invite(&mut self, addr: &net::SocketAddr, rb: &mut ReplyBuffer,
                      nick: &str, channel_name: &str) -> Result
    {
        let (target_addr, _) = find_nick(addr, rb, &self.clients, nick)?;

        if let Some(channel) = self.channels.get(<&UniCase<str>>::from(channel_name)) {
            let member_modes = find_member(addr, rb, channel, channel_name)?;
            if channel.invite_only && !member_modes.operator {
                log::debug!("{}:     not operator", addr);
                rb.reply(rpl::ERR_CHANOPRIVSNEEDED)
                    .param(channel_name)
                    .trailing_param(lines::CHAN_O_PRIVS_NEEDED);
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

        rb.reply(rpl::INVITING).param(channel_name).param(nick);

        let mut invite = Buffer::new();
        invite.prefixed_message(self.clients[addr].full_name(), Command::Invite)
            .param(nick)
            .param(channel_name);
        self.clients[&target_addr].send(invite);

        Ok(())
    }

    // JOIN

    pub fn cmd_join(&mut self, addr: &net::SocketAddr, rb: &mut ReplyBuffer,
                    target: &str, key: &str) -> Result
    {
        if !is_valid_channel_name(target) {
            log::debug!("{}:     Invalid channel name", addr);
            rb.reply(rpl::ERR_NOSUCHCHANNEL).param(target).trailing_param(lines::NO_SUCH_CHANNEL);
            return Err(());
        }
        if let Some(channel) = self.channels.get(<&UniCase<str>>::from(target)) {
            if channel.members.contains_key(addr) {
                log::debug!("{}:     Already in channel", addr);
                return Err(());
            }
            let nick = self.clients[&addr].nick();
            if channel.key.as_ref().map_or(false, |ck| key == ck) {
                log::debug!("{}:     Bad key", addr);
                rb.reply(rpl::ERR_BADCHANKEY).param(target).trailing_param(lines::BAD_CHAN_KEY);
                return Err(());
            }
            if channel.user_limit.map_or(false, |user_limit| user_limit <= channel.members.len()) {
                log::debug!("{}:     user limit reached", addr);
                rb.reply(rpl::ERR_CHANNELISFULL)
                    .param(target)
                    .trailing_param(lines::CHANNEL_IS_FULL);
                return Err(());
            }
            if !channel.is_invited(addr, nick) {
                log::debug!("{}:     not invited", addr);
                rb.reply(rpl::ERR_INVITEONLYCHAN)
                    .param(target)
                    .trailing_param(lines::INVITE_ONLY_CHAN);
                return Err(());
            }
            if channel.is_banned(nick) {
                log::debug!("{}:     Banned", addr);
                rb.reply(rpl::ERR_BANNEDFROMCHAN)
                    .param(target)
                    .trailing_param(lines::BANNED_FROM_CHAN);
                return Err(());
            }
        }

        let client = self.clients.get_mut(addr).unwrap();

        let default_chan_mode = &self.default_chan_mode;
        let channel = self.channels.entry(UniCase(target.to_owned()))
            .or_insert_with(|| Channel::new(&default_chan_mode));
        channel.add_member(*addr);
        client.update_idle_time();

        let mut join_response = Buffer::new();
        join_response.prefixed_message(client.full_name(), Command::Join).param(target);
        self.broadcast(target, MessageQueueItem::from(join_response));
        self.write_topic(rb, target);
        self.write_names(addr, rb, target);

        Ok(())
    }

    // KICK

    pub fn cmd_kick(&mut self, addr: &net::SocketAddr, rb: &mut ReplyBuffer, target: &str,
                    nick: &str, reason: &str) -> Result
    {
        let channel = find_channel(addr, rb, &self.channels, target)?;
        let member_modes = find_member(addr, rb, channel, target)?;
        if !member_modes.operator {
            log::debug!("{}:     not operator", addr);
            rb.reply(rpl::ERR_CHANOPRIVSNEEDED)
                .param(target)
                .trailing_param(lines::CHAN_O_PRIVS_NEEDED);
            return Err(());
        }
        let clients = &self.clients;
        let kicked_addrs = channel.members.keys()
            .find(|addr| clients[addr].nick() == nick)
            .copied();
        let kicked_addrs = match kicked_addrs {
            Some(kicked_addrs) => kicked_addrs,
            None => {
                log::debug!("{}:     targets not on channel", addr);
                rb.reply(rpl::ERR_USERNOTINCHANNEL)
                    .param(nick)
                    .param(target)
                    .trailing_param(lines::USER_NOT_IN_CHANNEL);
                return Err(());
            }
        };

        let mut kick_response = Buffer::new();
        {
            let msg = kick_response.prefixed_message(self.clients[addr].full_name(), Command::Kick)
                .param(target)
                .param(nick);
            if !reason.is_empty() {
                msg.trailing_param(reason);
            }
        }
        let msg = MessageQueueItem::from(kick_response);
        let channel = self.channels.get_mut(<&UniCase<str>>::from(target)).unwrap();
        for member in channel.members.keys() {
            self.clients[member].send(msg.clone());
        }
        channel.members.remove(&kicked_addrs);

        Ok(())
    }

    // LIST

    pub fn cmd_list(&self, addr: &net::SocketAddr, rb: &mut ReplyBuffer, targets: &str) -> Result {
        if targets.is_empty() {
            for (name, channel) in &self.channels {
                if channel.secret && !channel.members.contains_key(addr) {
                    continue;
                }
                let msg = rb.reply(rpl::LIST).param(name.as_ref());
                channel.list_entry(msg);
            }
        } else {
            for name in targets.split(',') {
                if let Some(channel) = self.channels.get(<&UniCase<str>>::from(name)) {
                    if channel.secret && !channel.members.contains_key(addr) {
                        continue;
                    }
                    let msg = rb.reply(rpl::LIST).param(name);
                    channel.list_entry(msg);
                }
            }
        }

        rb.reply(rpl::LISTEND).trailing_param(lines::END_OF_LIST);

        Ok(())
    }

    // LUSERS

    pub fn cmd_lusers(&self, rb: &mut ReplyBuffer) -> Result {
        self.write_lusers(rb);
        Ok(())
    }

    // MODE

    fn cmd_mode_chan_get(&self, addr: &net::SocketAddr, rb: &mut ReplyBuffer,
                         target: &str) -> Result
    {
        let channel = find_channel(addr, rb, &self.channels, target)?;
        let msg = rb.reply(rpl::CHANNELMODEIS).param(target);
        channel.modes(msg, channel.members.contains_key(addr));

        Ok(())
    }

    fn cmd_mode_chan_set(&mut self, addr: &net::SocketAddr, rb: &mut ReplyBuffer, target: &str,
                               modes: &str, modeparams: &[&str]) -> Result
    {
        let channel = match self.channels.get_mut(<&UniCase<str>>::from(target)) {
            Some(channel) => channel,
            None => {
                log::debug!("{}:     no such channel", addr);
                rb.reply(rpl::ERR_NOSUCHCHANNEL)
                    .param(target)
                    .trailing_param(lines::NO_SUCH_CHANNEL);
                return Err(());
            }
        };
        let member_modes = find_member(addr, rb, channel, target)?;
        if modes::needs_chanop(modes) && !member_modes.operator {
            log::debug!("{}:     not operator", addr);
            rb.reply(rpl::ERR_CHANOPRIVSNEEDED)
                .param(target)
                .trailing_param(lines::CHAN_O_PRIVS_NEEDED);
            return Err(());
        }

        let reply_list = |rb: &mut ReplyBuffer, item, end, line, it: &HashSet<String>| {
            for i in it {
                rb.reply(item).param(target).param(i);
            }
            rb.reply(end).trailing_param(line);
        };

        let clients = &self.clients;

        let mut applied_modes = String::new();
        let mut applied_modeparams = Vec::new();
        for maybe_change in modes::channel_query(modes, modeparams.iter().cloned()) { match maybe_change {
            Ok(modes::ChannelModeChange::GetBans) => {
                reply_list(rb, rpl::BANLIST, rpl::ENDOFBANLIST, lines::END_OF_BAN_LIST,
                           &channel.ban_mask);
            }
            Ok(modes::ChannelModeChange::GetExceptions) => {
                reply_list(rb, rpl::EXCEPTLIST, rpl::ENDOFEXCEPTLIST, lines::END_OF_EXCEPT_LIST,
                           &channel.exception_mask);
            }
            Ok(modes::ChannelModeChange::GetInvitations) => {
                reply_list(rb, rpl::INVITELIST, rpl::ENDOFINVITELIST, lines::END_OF_INVITE_LIST,
                           &channel.exception_mask);
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
                    rb.reply(rpl::ERR_USERNOTINCHANNEL)
                        .param(change.param().unwrap())
                        .trailing_param(lines::USER_NOT_IN_CHANNEL);
                }
                Err(rpl::ERR_KEYSET) => {
                    rb.reply(rpl::ERR_KEYSET).param(target).trailing_param(lines::KEY_SET);
                }
                Err(_) => {}
            }
            Err(modes::Error::UnknownMode(mode)) => {
                rb.reply(rpl::ERR_UNKNOWNMODE)
                    .param(&mode.to_string())
                    .trailing_param(lines::UNKNOWN_MODE);
            },
            Err(_) => {},
        } }

        if !applied_modes.is_empty() {
            let mut response = Buffer::new();
            {
                let mut msg = response.prefixed_message(self.clients[addr].full_name(), Command::Mode)
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

    fn cmd_mode_user_check(&self, addr: &net::SocketAddr, rb: &mut ReplyBuffer,
                           nick: &str) -> Result
    {
        let (target_addr, _) = find_nick(addr, rb, &self.clients, nick)?;
        if &target_addr != addr {
            log::debug!("{}:     users don't match", addr);
            rb.reply(rpl::ERR_USERSDONTMATCH).param(nick).trailing_param(lines::USERS_DONT_MATCH);
            return Err(());
        }
        Ok(())
    }

    fn cmd_mode_user_set(&mut self, addr: &net::SocketAddr, rb: &mut ReplyBuffer,
                         target: &str, modes: &str) -> Result
    {
        let client = self.clients.get_mut(&addr).unwrap();

        let mut applied_modes = String::new();
        for maybe_change in modes::user_query(modes) { match maybe_change {
            Ok(change) => if client.apply_mode_change(change) {
                log::debug!("  - Applied {:?}", change);
                applied_modes.push(if change.value() {'+'} else {'-'});
                applied_modes.push(change.symbol());
            }
            Err(modes::Error::UnknownMode(mode)) => {
                rb.reply(rpl::ERR_UMODEUNKNOWNFLAG)
                    .param(&mode.to_string())
                    .trailing_param(lines::UNKNOWN_MODE);
            }
            Err(_) => {}
        } }
        if !applied_modes.is_empty() {
            rb.prefixed_message(client.full_name(), Command::Mode)
                .param(target)
                .trailing_param(&applied_modes);
        }

        Ok(())
    }

    fn cmd_mode_user_get(&self, addr: &net::SocketAddr, rb: &mut ReplyBuffer) -> Result {
        let client = &self.clients[&addr];
        let msg = rb.reply(rpl::UMODEIS);
        client.write_modes(msg);
        Ok(())
    }

    pub fn cmd_mode(&mut self, addr: &net::SocketAddr, rb: &mut ReplyBuffer, target: &str,
                modes: &str, modeparams: &[&str]) -> Result
    {
        if is_valid_channel_name(target) {
            if modes.is_empty() {
                self.cmd_mode_chan_get(addr, rb, target)
            } else {
                self.cmd_mode_chan_set(addr, rb, target, modes, modeparams)
            }
        } else {
            self.cmd_mode_user_check(addr, rb, target)?;
            if modes.is_empty() {
                self.cmd_mode_user_get(addr, rb)
            } else {
                self.cmd_mode_user_set(addr, rb, target, modes)
            }
        }
    }

    // MOTD

    pub fn cmd_motd(&self, rb: &mut ReplyBuffer) -> Result {
        self.write_motd(rb);
        Ok(())
    }

    // NAMES

    pub fn cmd_names(&self, addr: &net::SocketAddr, rb: &mut ReplyBuffer, targets: &str) -> Result {
        if targets.is_empty() || targets == "*" {
            rb.reply(rpl::ENDOFNAMES).param("*").trailing_param(lines::END_OF_NAMES);
        } else {
            for target in targets.split(',') {
                self.write_names(addr, rb, target);
            }
        }

        Ok(())
    }

    // NICK

    pub fn cmd_nick(&mut self, addr: &net::SocketAddr, rb: &mut ReplyBuffer, nick: &str) -> Result {
        if !is_valid_nickname(nick) {
            log::debug!("{}:     Bad nickname", addr);
            rb.reply(rpl::ERR_ERRONEUSNICKNAME)
                .param(nick)
                .trailing_param(lines::ERRONEOUS_NICNAME);
            return Err(());
        }
        if self.clients.values().any(|c| c.nick() == nick) {
            log::debug!("{}:     Already in use", addr);
            rb.reply(rpl::ERR_NICKNAMEINUSE).param(nick).trailing_param(lines::NICKNAME_IN_USE);
            return Err(());
        }

        let client = self.clients.get_mut(addr).unwrap();

        if !client.is_registered() {
            log::debug!("{}:     Is not registered", addr);
            client.set_nick(nick);
            return Ok(());
        }

        let mut nick_response = Buffer::new();

        nick_response.prefixed_message(client.full_name(), Command::Nick).param(nick);
        let msg = MessageQueueItem::from(nick_response);

        client.set_nick(nick);

        let mut noticed = self.channels.values()
            .filter(|channel| channel.members.contains_key(addr))
            .flat_map(|channel| channel.members.keys())
            .collect::<HashSet<_>>();
        noticed.insert(addr);
        for addr in noticed {
            self.send(addr, msg.clone());
        }

        Ok(())
    }

    // NOTICE

    fn cmd_privnotice(&mut self, addr: &net::SocketAddr, rb: &mut ReplyBuffer, cmd: Command,
                      target: &str, content: &str) -> Result
    {
        if content.is_empty() {
            rb.reply(rpl::ERR_NOTEXTTOSEND).trailing_param(lines::NEED_MORE_PARAMS);
            return Err(());
        }
        if is_valid_channel_name(target) {
            let channel = find_channel(addr, rb, &self.channels, target)?;
            if !channel.can_talk(addr) {
                log::debug!("{}:     can't send to channel", addr);
                rb.reply(rpl::ERR_CANNOTSENDTOCHAN)
                    .param(target)
                    .trailing_param(lines::CANNOT_SEND_TO_CHAN);
                return Err(());
            }

            let mut response = Buffer::new();

            response.prefixed_message(self.clients[addr].full_name(), cmd)
                .param(target)
                .trailing_param(content);
            let msg = MessageQueueItem::from(response);
            channel.members.keys()
                .filter(|&a| a != addr)
                .for_each(|member| self.send(member, msg.clone()));
        } else {
            let (_, target_client) = find_nick(addr, rb, &self.clients, target)?;
            let mut response = Buffer::new();
            response.prefixed_message(self.clients[addr].full_name(), cmd)
                .param(target)
                .trailing_param(content);
            target_client.send(response);
        }
        self.clients.get_mut(addr).unwrap().update_idle_time();

        Ok(())
    }

    pub fn cmd_notice(&mut self, addr: &net::SocketAddr, rb: &mut ReplyBuffer,
                      target: &str, content: &str) -> Result
    {
        self.cmd_privnotice(addr, rb, Command::Notice, target, content)
    }

    // OPER

    pub fn cmd_oper(&mut self, addr: &net::SocketAddr, rb: &mut ReplyBuffer,
                    name: &str, password: &str) -> Result
    {
        // TODO oper_hosts
        if !self.opers.iter().any(|(n, p)| n == name && p == password) {
            log::debug!("{}:     Password mismatch", addr);
            rb.reply(rpl::ERR_PASSWDMISMATCH).trailing_param(lines::PASSWORD_MISMATCH);
            return Err(());
        }

        let client = self.clients.get_mut(&addr).unwrap();
        client.operator = true;
        rb.prefixed_message(&self.domain, Command::Mode).param(client.nick()).param("+o");
        rb.reply(rpl::YOUREOPER).trailing_param(lines::YOURE_OPER);

        Ok(())
    }

    // PART

    pub fn cmd_part(&mut self, addr: &net::SocketAddr, rb: &mut ReplyBuffer,
                    target: &str, reason: &str) -> Result
    {
        let channel = match self.channels.get_mut(<&UniCase<str>>::from(target)) {
            Some(channel) => channel,
            None => {
                log::debug!("{}:     Not on channel", addr);
                rb.reply(rpl::ERR_NOTONCHANNEL).param(target).trailing_param(lines::NOT_ON_CHANNEL);
                return Err(());
            }
        };
        find_member(addr, rb, channel, target)?;

        let mut response = Buffer::new();
        let client = &self.clients[&addr];

        channel.members.remove(addr);
        if reason.is_empty() {
            response.prefixed_message(client.full_name(), Command::Part).param(target);
        } else {
            response.prefixed_message(client.full_name(), Command::Part)
                .param(target)
                .trailing_param(reason);
        }
        let msg = MessageQueueItem::from(response);
        client.send(msg.clone());
        if channel.members.is_empty() {
            self.channels.remove(<&UniCase<str>>::from(target));
        } else {
            self.broadcast(target, msg);
        }

        Ok(())
    }

    // PASS

    pub fn cmd_pass(&mut self, addr: &net::SocketAddr, password: &str) -> Result {
        if self.password.as_ref().map_or(false, |p| p == password) {
            self.clients.get_mut(&addr).unwrap().has_given_password = true;
        }

        Ok(())
    }

    // PING

    pub fn cmd_ping(&mut self, rb: &mut ReplyBuffer, payload: &str) -> Result
    {
        rb.prefixed_message(&self.domain, Command::Pong).trailing_param(payload);

        Ok(())
    }

    // PRIVMSG

    pub fn cmd_privmsg(&mut self, addr: &net::SocketAddr, rb: &mut ReplyBuffer,
                       target: &str, content: &str) -> Result
    {
        self.cmd_privnotice(addr, rb, Command::PrivMsg, target, content)
    }

    // QUIT

    pub fn cmd_quit(&mut self, addr: &net::SocketAddr, reason: &str) -> Result {
        let mut response = Buffer::new();
        let client = self.clients.remove(addr).unwrap();
        response.prefixed_message(&self.domain, "ERROR").trailing_param(lines::CLOSING_LINK);
        client.send(MessageQueueItem::from(response));
        self.remove_client(addr, client, if reason.is_empty() {None} else {Some(reason)});

        Err(())
    }

    // TIME

    pub fn cmd_time(&self, rb: &mut ReplyBuffer) -> Result {
        rb.reply(rpl::TIME).param(&self.domain).trailing_param(&time_str());
        Ok(())
    }

    // TOPIC

    fn cmd_topic_set(&mut self, addr: &net::SocketAddr, rb: &mut ReplyBuffer,
                     target: &str, topic: &str) -> Result
    {
        let channel = match self.channels.get_mut(<&UniCase<str>>::from(target)) {
            Some(channel) => channel,
            None => {
                log::debug!("{}:     no such channel", addr);
                rb.reply(rpl::ERR_NOSUCHCHANNEL)
                    .param(target)
                    .trailing_param(lines::NO_SUCH_CHANNEL);
                return Err(());
            }
        };
        let member_modes = find_member(addr, rb, channel, target)?;
        if !member_modes.operator && channel.topic_restricted {
            log::debug!("{}:     not operator", addr);
            rb.reply(rpl::ERR_CHANOPRIVSNEEDED)
                .param(target)
                .trailing_param(lines::CHAN_O_PRIVS_NEEDED);
            return Err(());
        }

        let mut response = Buffer::new();
        channel.topic = if topic.is_empty() { None } else { Some(topic.to_owned()) };
        response.prefixed_message(self.clients[&addr].full_name(), Command::Topic)
            .param(target)
            .trailing_param(topic);
        self.broadcast(target, MessageQueueItem::from(response));

        Ok(())
    }

    fn cmd_topic_get(&self, addr: &net::SocketAddr, rb: &mut ReplyBuffer, target: &str) -> Result {
        let channel = find_channel(addr, rb, &self.channels, target)?;
        if channel.secret {
            find_member(addr, rb, channel, target)?;
        }
        self.write_topic(rb, target);

        Ok(())
    }

    pub fn cmd_topic(&mut self, addr: &net::SocketAddr, rb: &mut ReplyBuffer,
                     target: &str, topic: Option<&str>) -> Result
    {
        if let Some(topic) = topic {
            self.cmd_topic_set(addr, rb, target, topic)
        } else {
            self.cmd_topic_get(addr, rb, target)
        }
    }

    // USER

    pub fn cmd_user(&mut self, addr: &net::SocketAddr, rb: &mut ReplyBuffer,
                    user: &str, real: &str) -> Result
    {
        let client = self.clients.get_mut(&addr).unwrap();
        if self.password.is_some() && !client.has_given_password {
            log::debug!("{}:     Password mismatch", addr);
            rb.reply(rpl::ERR_PASSWDMISMATCH).trailing_param(lines::PASSWORD_MISMATCH);
            return Err(());
        }
        client.set_user_real(user, real);

        Ok(())
    }

    // VERSION

    pub fn cmd_version(&self, rb: &mut ReplyBuffer) -> Result {
        rb.reply(rpl::VERSION).param(crate::server_version!()).param(&self.domain);
        self.write_i_support(rb);
        Ok(())
    }

    // WHO

    pub fn cmd_who(&self, rb: &mut ReplyBuffer, mask: &str, o: &str) -> Result
    {
        let mask = if mask.is_empty() {"*"} else {mask};
        let o = o == "o";  // best line
        for client in self.clients.values() {
            if client.nick() != mask || (o && !client.operator) || client.invisible {
                continue;
            }
            rb.reply(rpl::WHOREPLY)
                .param("*")
                .param(client.user())
                .param(client.host())
                .param(&self.domain)
                .param(client.nick())
                .param("H")
                .trailing_param(client.real());
        }
        rb.reply(rpl::ENDOFWHO).param(mask).trailing_param(lines::END_OF_WHO);

        Ok(())
    }

    // WHOIS

    pub fn cmd_whois(&self, addr: &net::SocketAddr, rb: &mut ReplyBuffer, nick: &str) -> Result {
        let (_, target_client) = find_nick(addr, rb, &self.clients, nick)?;

        rb.reply(rpl::WHOISUSER)
            .param(target_client.nick())
            .param(target_client.user())
            .param(target_client.host())
            .param("*")
            .trailing_param(target_client.real());
        rb.reply(rpl::WHOISSERVER)
            .param(target_client.nick())
            .param(&self.domain)
            .trailing_param(&self.org_name);
        rb.reply(rpl::WHOISIDLE)
            .param(target_client.nick())
            .param(&target_client.idle_time().to_string())
            .param(&target_client.signon_time().to_string())
            .trailing_param(lines::WHOIS_IDLE);
        rb.reply(rpl::ENDOFWHOIS).param(target_client.nick()).trailing_param(lines::END_OF_WHOIS);

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use super::super::test;
    use crate::message::Command;

    #[test]
    fn test_is_valid_channel_name() {
        assert!(is_valid_channel_name("#Channel9"));

        assert!(!is_valid_channel_name(""));
        assert!(!is_valid_channel_name("channel"));
        assert!(!is_valid_channel_name("#chan nel"));
    }

    #[test]
    fn test_is_valid_nickname() {
        assert!(is_valid_nickname("nickname"));
        assert!(is_valid_nickname("my{}_\\^"));
        assert!(is_valid_nickname("brice007"));

        assert!(!is_valid_nickname(""));
        assert!(!is_valid_nickname(" space "));
        assert!(!is_valid_nickname("sp ace"));
        assert!(!is_valid_nickname("007brice"));
        assert!(!is_valid_nickname("longnicknameverylongohwowthisisalongnickname"));
    }

    #[test]
    fn test_cmd_invite() {
        let mut state = test::simple_state();
        let mut buf = String::with_capacity(512);

        let (a1, mut q1) = test::add_registered_client(&mut state, "c1");
        test::flush(&mut q1);
        let (a2, mut q2) = test::add_registered_client(&mut state, "c2");
        test::flush(&mut q2);
        let (a3, mut q3) = test::add_registered_client(&mut state, "c3");
        test::flush(&mut q3);

        test::handle_message(&mut state, &a1, "INVITE whoops #channel");
        test::collect(&mut buf, &mut q1);
        test::collect(&mut buf, &mut q2);
        test::collect(&mut buf, &mut q3);
        test::assert_msgs(&buf, &[
            (Some(test::DOMAIN), Err(rpl::ERR_NOSUCHNICK), &["c1", "whoops", lines::NO_SUCH_NICK]),
        ]);

        test::handle_message(&mut state, &a1, "INVITE c2 #channel");
        buf.clear();
        test::collect(&mut buf, &mut q1);
        test::collect(&mut buf, &mut q2);
        test::collect(&mut buf, &mut q3);
        test::assert_msgs(&buf, &[
            (Some(test::DOMAIN), Err(rpl::INVITING), &["c1", "#channel", "c2"]),
            (Some("c1!X@127.0.0.1"), Ok(Command::Invite), &["c2", "#channel"]),
        ]);

        test::handle_message(&mut state, &a1, "JOIN #channel");
        buf.clear();
        test::collect(&mut buf, &mut q1);
        test::collect(&mut buf, &mut q2);
        test::collect(&mut buf, &mut q3);
        test::assert_msgs(&buf, &[
            (Some("c1!X@127.0.0.1"), Ok(Command::Join), &["#channel"]),
            (Some(test::DOMAIN), Err(rpl::NOTOPIC), &["c1", "#channel", lines::NO_TOPIC]),
            (Some(test::DOMAIN), Err(rpl::NAMREPLY), &["c1", "=", "#channel", "@c1"]),
            (Some(test::DOMAIN), Err(rpl::ENDOFNAMES), &["c1", "#channel", lines::END_OF_NAMES]),
        ]);
        assert_eq!(state.channels[<&UniCase<str>>::from("#chAnnel")].members.len(), 1);
        assert!(state.channels[<&UniCase<str>>::from("#chAnnel")].members[&a1].operator);

        test::handle_message(&mut state, &a2, "JOIN #channel");
        buf.clear();
        test::collect(&mut buf, &mut q1);
        test::collect(&mut buf, &mut q2);
        test::collect(&mut buf, &mut q3);
        test::assert_msgs(&buf, &[
            (Some("c2!X@127.0.0.1"), Ok(Command::Join), &["#channel"]),
            (Some("c2!X@127.0.0.1"), Ok(Command::Join), &["#channel"]),
            (Some(test::DOMAIN), Err(rpl::NOTOPIC), &["c2", "#channel", lines::NO_TOPIC]),
            (Some(test::DOMAIN), Err(rpl::NAMREPLY), &["c2", "=", "#channel", ""]),
            (Some(test::DOMAIN), Err(rpl::ENDOFNAMES), &["c2", "#channel", lines::END_OF_NAMES]),
        ]);

        test::handle_message(&mut state, &a1, "MODE #channel +i");
        buf.clear();
        test::collect(&mut buf, &mut q1);
        test::collect(&mut buf, &mut q2);
        test::collect(&mut buf, &mut q3);
        test::assert_msgs(&buf, &[
            (Some("c1!X@127.0.0.1"), Ok(Command::Mode), &["#channel", "+i"]),
            (Some("c1!X@127.0.0.1"), Ok(Command::Mode), &["#channel", "+i"]),
        ]);

        test::handle_message(&mut state, &a3, "JOIN #channel");
        buf.clear();
        test::collect(&mut buf, &mut q1);
        test::collect(&mut buf, &mut q2);
        test::collect(&mut buf, &mut q3);
        test::assert_msgs(&buf, &[
            (Some(test::DOMAIN), Err(rpl::ERR_INVITEONLYCHAN), &["c3", "#channel", lines::INVITE_ONLY_CHAN]),
        ]);

        test::handle_message(&mut state, &a2, "INVITE c3 #channel");
        buf.clear();
        test::collect(&mut buf, &mut q1);
        test::collect(&mut buf, &mut q2);
        test::collect(&mut buf, &mut q3);
        test::assert_msgs(&buf, &[
            (Some(test::DOMAIN), Err(rpl::ERR_CHANOPRIVSNEEDED), &["c2", "#channel", lines::CHAN_O_PRIVS_NEEDED]),
        ]);

        test::handle_message(&mut state, &a1, "INVITE c3 #channel");
        buf.clear();
        test::collect(&mut buf, &mut q1);
        test::collect(&mut buf, &mut q2);
        test::collect(&mut buf, &mut q3);
        test::assert_msgs(&buf, &[
            (Some(test::DOMAIN), Err(rpl::INVITING), &["c1", "#channel", "c3"]),
            (Some("c1!X@127.0.0.1"), Ok(Command::Invite), &["c3", "#channel"]),
        ]);

        test::handle_message(&mut state, &a3, "JOIN #channel");
        buf.clear();
        test::collect(&mut buf, &mut q1);
        test::collect(&mut buf, &mut q2);
        test::collect(&mut buf, &mut q3);
        test::assert_msgs(&buf, &[
            (Some("c3!X@127.0.0.1"), Ok(Command::Join), &["#channel"]),
            (Some("c3!X@127.0.0.1"), Ok(Command::Join), &["#channel"]),
            (Some("c3!X@127.0.0.1"), Ok(Command::Join), &["#channel"]),
            (Some(test::DOMAIN), Err(rpl::NOTOPIC), &["c3", "#channel", lines::NO_TOPIC]),
            (Some(test::DOMAIN), Err(rpl::NAMREPLY), &["c3", "=", "#channel", ""]),
            (Some(test::DOMAIN), Err(rpl::ENDOFNAMES), &["c3", "#channel", lines::END_OF_NAMES]),
        ]);
    }
}  // mod tests
