//! RFC2812 implementation
//!
//! <https://tools.ietf.org/html/rfc2812.html>

use crate::channel::Channel;
use crate::client::{cap, MessageQueueItem};
use crate::lines;
use crate::message::{Command, rpl, ResponseBuffer};
use crate::modes;
use crate::util::time_str;
use ellidri_unicase::UniCase;
use std::collections::HashSet;
use std::net;
use super::{Result, find_channel, find_member, find_nick};

fn is_valid_channel_name(s: &str) -> bool {
    // https://tools.ietf.org/html/rfc2811.html#section-2.1
    let ctrl_g = 7 as char;
    let first = s.as_bytes()[0];
    !s.is_empty()
        && s.len() <= super::MAX_CHANNEL_NAME_LENGTH
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
    s.len() <= super::MAX_NICKNAME_LENGTH
        && s.iter().all(is_valid_nickname_char)
        && s[0] != b'-' && !(b'0' <= s[0] && s[0] <= b'9')
}

// Command handlers
impl super::StateInner {
    // ADMIN

    pub fn cmd_admin(&self, addr: &net::SocketAddr) -> Result {
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

    pub fn cmd_cap(&mut self, addr: &net::SocketAddr, params: &[&str]) -> Result {
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

    pub fn cmd_info(&self, addr: &net::SocketAddr) -> Result {
        log::debug!("{}: INFO", addr);
        let mut response = ResponseBuffer::new();
        let client = &self.clients[addr];

        for line in super::SERVER_INFO.lines() {
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

    pub fn cmd_invite(&mut self, addr: &net::SocketAddr, target_nick: &str, channel_name: &str) -> Result {
        let (target_addr, _) = find_nick(addr, &self.domain, &self.clients, target_nick)?;

        if let Some(channel) = self.channels.get(<&UniCase<str>>::from(channel_name)) {
            let member_modes = find_member(addr, &self.domain, &self.clients, channel, channel_name)?;
            if channel.invite_only && !member_modes.operator {
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

    pub fn cmd_join(&mut self, addr: &net::SocketAddr, target: &str, key: &str) -> Result {
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

    pub fn cmd_kick(&mut self, addr: &net::SocketAddr, channel_names: &str, nicks: &str, reason: &str) -> Result {
        let channel = find_channel(addr, &self.domain, &self.clients, &self.channels, channel_names)?;
        let member_modes = find_member(addr, &self.domain, &self.clients, channel, channel_names)?;
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
                self.send_reply(addr, rpl::ERR_USERNOTINCHANNEL,
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

    pub fn cmd_list(&self, addr: &net::SocketAddr, targets: &str) -> Result {
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

    pub fn cmd_lusers(&self, addr: &net::SocketAddr) -> Result {
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
        let member_modes = find_member(addr, &self.domain, &self.clients, channel, target)?;
        if modes::needs_chanop(modes) && !member_modes.operator {
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

    pub fn cmd_mode(&mut self, addr: &net::SocketAddr, target: &str,
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

    pub fn cmd_motd(&self, addr: &net::SocketAddr) -> Result {
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

    pub fn cmd_names(&self, addr: &net::SocketAddr, targets: &str) -> Result {
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

    pub fn cmd_notice(&mut self, addr: &net::SocketAddr, target: &str, content: &str) -> Result {
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

    pub fn cmd_oper(&mut self, addr: &net::SocketAddr, name: &str, password: &str) -> Result {
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

    pub fn cmd_part(&mut self, addr: &net::SocketAddr, target: &str, reason: &str) -> Result {
        let channel = match self.channels.get_mut(<&UniCase<str>>::from(target)) {
            Some(channel) => channel,
            None => {
                log::debug!("{}: PART {:?}: Not on channel", addr, target);
                self.send_reply(addr, rpl::ERR_NOTONCHANNEL, &[target, lines::NOT_ON_CHANNEL]);
                return Err(());
            }
        };
        find_member(addr, &self.domain, &self.clients, channel, target)?;

        log::debug!("{}: PART {:?} {:?}", addr, target, reason);
        let mut response = ResponseBuffer::new();
        let client = &self.clients[&addr];

        channel.members.remove(addr);
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

    pub fn cmd_pass(&mut self, addr: &net::SocketAddr, password: &str) -> Result {
        log::debug!("{}: PASS {:?}", addr, password);

        if self.password.as_ref().map_or(false, |p| p == password) {
            self.clients.get_mut(&addr).unwrap().has_given_password = true;
        }

        Ok(())
    }

    // PING

    pub fn cmd_ping(&mut self, addr: &net::SocketAddr, payload: &str) -> Result {
        log::debug!("{}: PING {:?}", addr, payload);
        let mut response = ResponseBuffer::new();
        let client = &self.clients[addr];

        response.prefixed_message(&self.domain, Command::Pong).trailing_param(payload);
        client.send(MessageQueueItem::from(response));

        Ok(())
    }

    // PRIVMSG

    pub fn cmd_privmsg(&mut self, addr: &net::SocketAddr, target: &str, content: &str) -> Result {
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

    pub fn cmd_quit(&mut self, addr: &net::SocketAddr, reason: &str) -> Result {
        log::debug!("{}: QUIT {:?}", addr, reason);
        let mut response = ResponseBuffer::new();
        let client = self.clients.remove(addr).unwrap();

        response.prefixed_message(&self.domain, "ERROR").trailing_param(lines::CLOSING_LINK);
        client.send(MessageQueueItem::from(response));
        self.remove_client(addr, client, if reason.is_empty() {None} else {Some(reason)});

        Err(())
    }

    // TIME

    pub fn cmd_time(&self, addr: &net::SocketAddr) -> Result {
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
        let member_modes = find_member(addr, &self.domain, &self.clients, channel, target)?;
        if !member_modes.operator && channel.topic_restricted {
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
        if channel.secret {
            find_member(addr, &self.domain, &self.clients, channel, target)?;
        }

        log::debug!("{}: TOPIC {:?}", addr, target);
        self.send_topic(addr, target);

        Ok(())
    }

    pub fn cmd_topic(&mut self, addr: &net::SocketAddr, target: &str, topic: Option<&str>) -> Result {
        if let Some(topic) = topic {
            self.cmd_topic_set(addr, target, topic)
        } else {
            self.cmd_topic_get(addr, target)
        }
    }

    // USER

    pub fn cmd_user(&mut self, addr: &net::SocketAddr, user: &str, real: &str) -> Result {
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

    pub fn cmd_version(&self, addr: &net::SocketAddr) -> Result {
        log::debug!("{}: VERSION", addr);
        let mut response = ResponseBuffer::new();
        let client = &self.clients[&addr];

        response.prefixed_message(&self.domain, rpl::VERSION)
            .param(client.nick())
            .param(super::SERVER_VERSION)
            .param(&self.domain);
        self.write_i_support(&mut response, client.nick());
        client.send(MessageQueueItem::from(response));

        Ok(())
    }

    // WHO

    pub fn cmd_who(&self, addr: &net::SocketAddr, mask: &str, o: &str) -> Result {
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

    pub fn cmd_whois(&self, addr: &net::SocketAddr, nick: &str) -> Result {
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
