//! Handlers for the RFC 2812 client-to-server interface.
//!
//! <https://tools.ietf.org/html/rfc2812.html>

use crate::channel::Channel;
use crate::client::MessageQueueItem;
use crate::lines;
use crate::message::{Buffer, Command, ReplyBuffer, rpl};
use crate::modes;
use crate::util::{new_message_id, time_precise, time_str};
use ellidri_unicase::UniCase;
use std::collections::HashSet;
use super::{CommandContext, HandlerResult as Result, find_channel, find_member, find_nick};

// Command handlers
impl super::StateInner {
    // ADMIN

    pub fn cmd_admin(&self, ctx: CommandContext<'_>) -> Result {
        ctx.rb.reply(rpl::ADMINME).param(&self.domain).trailing_param(lines::ADMIN_ME);
        ctx.rb.reply(rpl::ADMINLOC1).trailing_param(&self.org_location);
        ctx.rb.reply(rpl::ADMINLOC2).trailing_param(&self.org_name);
        ctx.rb.reply(rpl::ADMINMAIL).trailing_param(&self.org_mail);

        Ok(())
    }

    // INFO

    pub fn cmd_info(&self, ctx: CommandContext<'_>) -> Result {
        for line in super::SERVER_INFO.lines() {
            ctx.rb.reply(rpl::INFO).trailing_param(line);
        }
        ctx.rb.reply(rpl::ENDOFINFO).trailing_param(lines::END_OF_INFO);

        Ok(())
    }

    // INVITE

    pub fn cmd_invite(&mut self, ctx: CommandContext<'_>, nick: &str, channel_name: &str) -> Result {
        let (target_addr, _) = find_nick(ctx.addr, ctx.rb, &self.clients, nick)?;

        if let Some(channel) = self.channels.get(<&UniCase<str>>::from(channel_name)) {
            let member_modes = find_member(ctx.addr, ctx.rb, channel, channel_name)?;
            if channel.invite_only && !member_modes.operator {
                log::debug!("{}:     not operator", ctx.addr);
                ctx.rb.reply(rpl::ERR_CHANOPRIVSNEEDED)
                    .param(channel_name)
                    .trailing_param(lines::CHAN_O_PRIVS_NEEDED);
                return Err(());
            }
            if channel.members.contains_key(&target_addr) {
                log::debug!("{}:     user on channel", ctx.addr);
                ctx.rb.reply(rpl::ERR_USERONCHANNEL)
                    .param(nick)
                    .param(channel_name)
                    .trailing_param(lines::USER_ON_CHANNEL);
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

        ctx.rb.reply(rpl::INVITING).param(channel_name).param(nick);

        let mut invite = Buffer::new();
        invite.message(self.clients[ctx.addr].full_name(), Command::Invite)
            .param(nick)
            .param(channel_name);
        self.clients[&target_addr].send(invite);

        Ok(())
    }

    // JOIN

    pub fn cmd_join(&mut self, ctx: CommandContext<'_>, target: &str, key: &str) -> Result {
        if !super::is_valid_channel_name(target, self.channellen) {
            log::debug!("{}:     Invalid channel name", ctx.addr);
            ctx.rb.reply(rpl::ERR_NOSUCHCHANNEL).param(target).trailing_param(lines::NO_SUCH_CHANNEL);
            return Err(());
        }
        if let Some(channel) = self.channels.get(<&UniCase<str>>::from(target)) {
            if channel.members.contains_key(ctx.addr) {
                log::debug!("{}:     Already in channel", ctx.addr);
                return Err(());
            }
            let nick = self.clients[ctx.addr].nick();
            if channel.key.as_ref().map_or(false, |ck| key == ck) {
                log::debug!("{}:     Bad key", ctx.addr);
                ctx.rb.reply(rpl::ERR_BADCHANKEY).param(target).trailing_param(lines::BAD_CHAN_KEY);
                return Err(());
            }
            if channel.user_limit.map_or(false, |user_limit| user_limit <= channel.members.len()) {
                log::debug!("{}:     user limit reached", ctx.addr);
                ctx.rb.reply(rpl::ERR_CHANNELISFULL)
                    .param(target)
                    .trailing_param(lines::CHANNEL_IS_FULL);
                return Err(());
            }
            if !channel.is_invited(ctx.addr, nick) {
                log::debug!("{}:     not invited", ctx.addr);
                ctx.rb.reply(rpl::ERR_INVITEONLYCHAN)
                    .param(target)
                    .trailing_param(lines::INVITE_ONLY_CHAN);
                return Err(());
            }
            if channel.is_banned(nick) {
                log::debug!("{}:     Banned", ctx.addr);
                ctx.rb.reply(rpl::ERR_BANNEDFROMCHAN)
                    .param(target)
                    .trailing_param(lines::BANNED_FROM_CHAN);
                return Err(());
            }
        }

        let client = self.clients.get_mut(ctx.addr).unwrap();

        let default_chan_mode = &self.default_chan_mode;
        let channel = self.channels.entry(UniCase(target.to_owned()))
            .or_insert_with(|| Channel::new(&default_chan_mode));
        channel.add_member(*ctx.addr);
        client.update_idle_time();

        let mut join_response = Buffer::new();
        join_response.message(client.full_name(), Command::Join).param(target);
        self.broadcast(target, MessageQueueItem::from(join_response));
        self.write_topic(ctx.rb, target);
        self.write_names(ctx.addr, ctx.rb, target);

        Ok(())
    }

    // KICK

    pub fn cmd_kick(&mut self, ctx: CommandContext<'_>, target: &str,
                    nick: &str, reason: &str) -> Result
    {
        let channel = find_channel(ctx.addr, ctx.rb, &self.channels, target)?;
        let member_modes = find_member(ctx.addr, ctx.rb, channel, target)?;
        if !member_modes.operator {
            log::debug!("{}:     not operator", ctx.addr);
            ctx.rb.reply(rpl::ERR_CHANOPRIVSNEEDED)
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
                log::debug!("{}:     targets not on channel", ctx.addr);
                ctx.rb.reply(rpl::ERR_USERNOTINCHANNEL)
                    .param(nick)
                    .param(target)
                    .trailing_param(lines::USER_NOT_IN_CHANNEL);
                return Err(());
            }
        };

        let mut kick_response = Buffer::new();
        {
            let msg = kick_response.message(self.clients[ctx.addr].full_name(), Command::Kick)
                .param(target)
                .param(nick);
            if !reason.is_empty() {
                msg.trailing_param(&reason[..reason.len().min(self.kicklen)]);
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

    pub fn cmd_list(&self, ctx: CommandContext<'_>, targets: &str) -> Result {
        if targets.is_empty() {
            for (name, channel) in &self.channels {
                if channel.secret && !channel.members.contains_key(ctx.addr) {
                    continue;
                }
                let msg = ctx.rb.reply(rpl::LIST).param(name.as_ref());
                channel.list_entry(msg);
            }
        } else {
            for name in targets.split(',') {
                if let Some(channel) = self.channels.get(<&UniCase<str>>::from(name)) {
                    if channel.secret && !channel.members.contains_key(ctx.addr) {
                        continue;
                    }
                    let msg = ctx.rb.reply(rpl::LIST).param(name);
                    channel.list_entry(msg);
                }
            }
        }

        ctx.rb.reply(rpl::LISTEND).trailing_param(lines::END_OF_LIST);

        Ok(())
    }

    // LUSERS

    pub fn cmd_lusers(&self, ctx: CommandContext<'_>) -> Result {
        self.write_lusers(ctx.rb);
        Ok(())
    }

    // MODE

    fn cmd_mode_chan_get(&self, ctx: CommandContext<'_>, target: &str) -> Result {
        let channel = find_channel(ctx.addr, ctx.rb, &self.channels, target)?;
        let msg = ctx.rb.reply(rpl::CHANNELMODEIS).param(target);
        channel.modes(msg, channel.members.contains_key(ctx.addr));

        Ok(())
    }

    fn cmd_mode_chan_set(&mut self, ctx: CommandContext<'_>, target: &str,
                               modes: &str, modeparams: &[&str]) -> Result
    {
        let channel = match self.channels.get_mut(<&UniCase<str>>::from(target)) {
            Some(channel) => channel,
            None => {
                log::debug!("{}:     no such channel", ctx.addr);
                ctx.rb.reply(rpl::ERR_NOSUCHCHANNEL)
                    .param(target)
                    .trailing_param(lines::NO_SUCH_CHANNEL);
                return Err(());
            }
        };
        let member_modes = find_member(ctx.addr, ctx.rb, channel, target)?;
        if modes::needs_chanop(modes) && !member_modes.operator {
            log::debug!("{}:     not operator", ctx.addr);
            ctx.rb.reply(rpl::ERR_CHANOPRIVSNEEDED)
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
                reply_list(ctx.rb, rpl::BANLIST, rpl::ENDOFBANLIST, lines::END_OF_BAN_LIST,
                           &channel.ban_mask);
            }
            Ok(modes::ChannelModeChange::GetExceptions) => {
                reply_list(ctx.rb, rpl::EXCEPTLIST, rpl::ENDOFEXCEPTLIST, lines::END_OF_EXCEPT_LIST,
                           &channel.exception_mask);
            }
            Ok(modes::ChannelModeChange::GetInvitations) => {
                reply_list(ctx.rb, rpl::INVITELIST, rpl::ENDOFINVITELIST, lines::END_OF_INVITE_LIST,
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
                    ctx.rb.reply(rpl::ERR_USERNOTINCHANNEL)
                        .param(change.param().unwrap())
                        .trailing_param(lines::USER_NOT_IN_CHANNEL);
                }
                Err(rpl::ERR_KEYSET) => {
                    ctx.rb.reply(rpl::ERR_KEYSET).param(target).trailing_param(lines::KEY_SET);
                }
                Err(_) => {}
            }
            Err(modes::Error::UnknownMode(mode)) => {
                ctx.rb.reply(rpl::ERR_UNKNOWNMODE)
                    .param(&mode.to_string())
                    .trailing_param(lines::UNKNOWN_MODE);
            },
            Err(_) => {},
        } }

        if !applied_modes.is_empty() {
            let mut response = Buffer::new();
            {
                let mut msg = response.message(self.clients[ctx.addr].full_name(), Command::Mode)
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

    fn cmd_mode_user_check(&self, ctx: &mut CommandContext<'_>, nick: &str) -> Result {
        let (target_addr, _) = find_nick(ctx.addr, ctx.rb, &self.clients, nick)?;
        if &target_addr != ctx.addr {
            log::debug!("{}:     users don't match", ctx.addr);
            ctx.rb.reply(rpl::ERR_USERSDONTMATCH)
                .param(nick)
                .trailing_param(lines::USERS_DONT_MATCH);
            return Err(());
        }
        Ok(())
    }

    fn cmd_mode_user_set(&mut self, ctx: CommandContext<'_>, target: &str, modes: &str) -> Result {
        let client = self.clients.get_mut(ctx.addr).unwrap();

        let mut applied_modes = String::new();
        for maybe_change in modes::user_query(modes) { match maybe_change {
            Ok(change) => if client.apply_mode_change(change) {
                log::debug!("  - Applied {:?}", change);
                applied_modes.push(if change.value() {'+'} else {'-'});
                applied_modes.push(change.symbol());
            }
            Err(modes::Error::UnknownMode(mode)) => {
                ctx.rb.reply(rpl::ERR_UMODEUNKNOWNFLAG)
                    .param(&mode.to_string())
                    .trailing_param(lines::UNKNOWN_MODE);
            }
            Err(_) => {}
        } }
        if !applied_modes.is_empty() {
            ctx.rb.message(client.full_name(), Command::Mode)
                .param(target)
                .trailing_param(&applied_modes);
        }

        Ok(())
    }

    fn cmd_mode_user_get(&self, ctx: CommandContext<'_>) -> Result {
        let client = &self.clients[ctx.addr];
        let msg = ctx.rb.reply(rpl::UMODEIS);
        client.write_modes(msg);
        Ok(())
    }

    pub fn cmd_mode(&mut self, mut ctx: CommandContext<'_>, target: &str,
                modes: &str, modeparams: &[&str]) -> Result
    {
        if super::is_valid_channel_name(target, self.channellen) {
            if modes.is_empty() {
                self.cmd_mode_chan_get(ctx, target)
            } else {
                self.cmd_mode_chan_set(ctx, target, modes, modeparams)
            }
        } else {
            self.cmd_mode_user_check(&mut ctx, target)?;
            if modes.is_empty() {
                self.cmd_mode_user_get(ctx)
            } else {
                self.cmd_mode_user_set(ctx, target, modes)
            }
        }
    }

    // MOTD

    pub fn cmd_motd(&self, ctx: CommandContext<'_>) -> Result {
        self.write_motd(ctx.rb);
        Ok(())
    }

    // NAMES

    pub fn cmd_names(&self, ctx: CommandContext<'_>, targets: &str) -> Result {
        if targets.is_empty() || targets == "*" {
            ctx.rb.reply(rpl::ENDOFNAMES).param("*").trailing_param(lines::END_OF_NAMES);
        } else {
            for target in targets.split(',') {
                self.write_names(ctx.addr, ctx.rb, target);
            }
        }

        Ok(())
    }

    // NICK

    pub fn cmd_nick(&mut self, ctx: CommandContext<'_>, nick: &str) -> Result {
        if !super::is_valid_nickname(nick, self.nicklen) {
            log::debug!("{}:     Bad nickname", ctx.addr);
            ctx.rb.reply(rpl::ERR_ERRONEUSNICKNAME)
                .param(nick)
                .trailing_param(lines::ERRONEOUS_NICNAME);
            return Err(());
        }
        if self.clients.values().any(|c| c.nick() == nick) {
            log::debug!("{}:     Already in use", ctx.addr);
            ctx.rb.reply(rpl::ERR_NICKNAMEINUSE).param(nick).trailing_param(lines::NICKNAME_IN_USE);
            return Err(());
        }

        let client = self.clients.get_mut(ctx.addr).unwrap();

        if !client.is_registered() {
            log::debug!("{}:     Is not registered", ctx.addr);
            client.set_nick(nick);
            return Ok(());
        }

        let mut nick_response = Buffer::new();

        nick_response.message(client.full_name(), Command::Nick).param(nick);
        let msg = MessageQueueItem::from(nick_response);

        client.set_nick(nick);

        let mut noticed = self.channels.values()
            .filter(|channel| channel.members.contains_key(ctx.addr))
            .flat_map(|channel| channel.members.keys())
            .collect::<HashSet<_>>();
        noticed.insert(ctx.addr);
        for addr in noticed {
            self.send(addr, msg.clone());
        }

        Ok(())
    }

    // NOTICE

    fn cmd_privnotice(&mut self, ctx: CommandContext<'_>, cmd: Command,
                      target: &str, content: &str) -> Result
    {
        if content.is_empty() {
            ctx.rb.reply(rpl::ERR_NOTEXTTOSEND).trailing_param(lines::NEED_MORE_PARAMS);
            return Err(());
        }
        if super::is_valid_channel_name(target, self.channellen) {
            let channel = find_channel(ctx.addr, ctx.rb, &self.channels, target)?;
            if !channel.can_talk(ctx.addr) {
                log::debug!("{}:     can't send to channel", ctx.addr);
                ctx.rb.reply(rpl::ERR_CANNOTSENDTOCHAN)
                    .param(target)
                    .trailing_param(lines::CANNOT_SEND_TO_CHAN);
                return Err(());
            }

            let mut response = Buffer::new();

            let client = &self.clients[ctx.addr];
            let mut client_tags_len = 0;
            response.tagged_message(ctx.client_tags, &mut client_tags_len)
                .tag("time", Some(&time_precise()))
                .tag("msgid", Some(&new_message_id()))
                .prefixed_command(client.full_name(), cmd)
                .param(target)
                .trailing_param(content);
            let mut msg = MessageQueueItem::from(response);
            msg.start = client_tags_len;
            channel.members.keys()
                .filter(|&a| client.capabilities.echo_message || a != ctx.addr)
                .for_each(|member| self.send(member, msg.clone()));
        } else {
            let (_, target_client) = find_nick(ctx.addr, ctx.rb, &self.clients, target)?;
            let client = &self.clients[ctx.addr];
            let mut client_tags_len = 0;
            let mut response = Buffer::new();
            response.tagged_message(ctx.client_tags, &mut client_tags_len)
                .tag("time", Some(&time_precise()))
                .tag("msgid", Some(&new_message_id()))
                .prefixed_command(client.full_name(), cmd)
                .param(target)
                .trailing_param(content);
            let mut msg = MessageQueueItem::from(response);
            msg.start = client_tags_len;
            if client.capabilities.echo_message {
                client.send(msg.clone());
            }
            target_client.send(msg);
        }
        self.clients.get_mut(ctx.addr).unwrap().update_idle_time();

        Ok(())
    }

    pub fn cmd_notice(&mut self, ctx: CommandContext<'_>, target: &str, content: &str) -> Result {
        self.cmd_privnotice(ctx, Command::Notice, target, content)
    }

    // OPER

    pub fn cmd_oper(&mut self, ctx: CommandContext<'_>, name: &str, password: &str) -> Result {
        // TODO oper_hosts
        if !self.opers.iter().any(|(n, p)| n == name && p == password) {
            log::debug!("{}:     Password mismatch", ctx.addr);
            ctx.rb.reply(rpl::ERR_PASSWDMISMATCH).trailing_param(lines::PASSWORD_MISMATCH);
            return Err(());
        }

        let client = self.clients.get_mut(ctx.addr).unwrap();
        client.operator = true;
        ctx.rb.message(&self.domain, Command::Mode).param(client.nick()).param("+o");
        ctx.rb.reply(rpl::YOUREOPER).trailing_param(lines::YOURE_OPER);

        Ok(())
    }

    // PART

    pub fn cmd_part(&mut self, ctx: CommandContext<'_>, target: &str, reason: &str) -> Result {
        let channel = match self.channels.get_mut(<&UniCase<str>>::from(target)) {
            Some(channel) => channel,
            None => {
                log::debug!("{}:     Not on channel", ctx.addr);
                ctx.rb.reply(rpl::ERR_NOTONCHANNEL)
                    .param(target)
                    .trailing_param(lines::NOT_ON_CHANNEL);
                return Err(());
            }
        };
        find_member(ctx.addr, ctx.rb, channel, target)?;

        let mut response = Buffer::new();
        let client = &self.clients[ctx.addr];

        channel.members.remove(ctx.addr);
        if reason.is_empty() {
            response.message(client.full_name(), Command::Part).param(target);
        } else {
            response.message(client.full_name(), Command::Part).param(target).trailing_param(reason);
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

    pub fn cmd_pass(&mut self, ctx: CommandContext<'_>, password: &str) -> Result {
        if self.password.as_ref().map_or(false, |p| p == password) {
            self.clients.get_mut(ctx.addr).unwrap().has_given_password = true;
        }

        Ok(())
    }

    // PING

    pub fn cmd_ping(&mut self, ctx: CommandContext<'_>, payload: &str) -> Result
    {
        ctx.rb.message(&self.domain, Command::Pong).trailing_param(payload);
        Ok(())
    }

    // PRIVMSG

    pub fn cmd_privmsg(&mut self, ctx: CommandContext<'_>, target: &str, content: &str) -> Result {
        self.cmd_privnotice(ctx, Command::PrivMsg, target, content)
    }

    // QUIT

    // TODO append "Quit: " in front of the user supplied message
    pub fn cmd_quit(&mut self, ctx: CommandContext<'_>, reason: &str) -> Result {
        let mut response = Buffer::new();
        let client = self.clients.remove(ctx.addr).unwrap();
        response.message(&self.domain, "ERROR").trailing_param(lines::CLOSING_LINK);
        client.send(MessageQueueItem::from(response));
        self.remove_client(ctx.addr, client, if reason.is_empty() {None} else {Some(reason)});

        Err(())
    }

    // TIME

    pub fn cmd_time(&self, ctx: CommandContext<'_>) -> Result {
        ctx.rb.reply(rpl::TIME).param(&self.domain).trailing_param(&time_str());
        Ok(())
    }

    // TOPIC

    fn cmd_topic_set(&mut self, ctx: CommandContext<'_>, target: &str, topic: &str) -> Result {
        let channel = match self.channels.get_mut(<&UniCase<str>>::from(target)) {
            Some(channel) => channel,
            None => {
                log::debug!("{}:     no such channel", ctx.addr);
                ctx.rb.reply(rpl::ERR_NOSUCHCHANNEL)
                    .param(target)
                    .trailing_param(lines::NO_SUCH_CHANNEL);
                return Err(());
            }
        };
        let member_modes = find_member(ctx.addr, ctx.rb, channel, target)?;
        if !member_modes.operator && channel.topic_restricted {
            log::debug!("{}:     not operator", ctx.addr);
            ctx.rb.reply(rpl::ERR_CHANOPRIVSNEEDED)
                .param(target)
                .trailing_param(lines::CHAN_O_PRIVS_NEEDED);
            return Err(());
        }

        let mut response = Buffer::new();
        channel.topic = if topic.is_empty() { None } else { Some(topic.to_owned()) };
        response.message(self.clients[ctx.addr].full_name(), Command::Topic)
            .param(target)
            .trailing_param(&topic[..topic.len().min(self.topiclen)]);
        self.broadcast(target, MessageQueueItem::from(response));

        Ok(())
    }

    fn cmd_topic_get(&self, ctx: CommandContext<'_>, target: &str) -> Result {
        let channel = find_channel(ctx.addr, ctx.rb, &self.channels, target)?;
        if channel.secret {
            find_member(ctx.addr, ctx.rb, channel, target)?;
        }
        self.write_topic(ctx.rb, target);

        Ok(())
    }

    pub fn cmd_topic(&mut self, ctx: CommandContext<'_>,
                     target: &str, topic: Option<&str>) -> Result
    {
        if let Some(topic) = topic {
            self.cmd_topic_set(ctx, target, topic)
        } else {
            self.cmd_topic_get(ctx, target)
        }
    }

    // USER

    pub fn cmd_user(&mut self, ctx: CommandContext<'_>, user: &str, real: &str) -> Result {
        let client = self.clients.get_mut(ctx.addr).unwrap();
        if self.password.is_some() && !client.has_given_password {
            log::debug!("{}:     Password mismatch", ctx.addr);
            ctx.rb.reply(rpl::ERR_PASSWDMISMATCH).trailing_param(lines::PASSWORD_MISMATCH);
            return Err(());
        }
        client.set_user_real(&user[..user.len().min(self.userlen)], real);

        Ok(())
    }

    // VERSION

    pub fn cmd_version(&self, ctx: CommandContext<'_>) -> Result {
        ctx.rb.reply(rpl::VERSION).param(crate::server_version!()).param(&self.domain);
        self.write_i_support(ctx.rb);
        Ok(())
    }

    // WHO

    pub fn cmd_who(&self, ctx: CommandContext<'_>, mask: &str, o: &str) -> Result
    {
        let mask = if mask.is_empty() {"*"} else {mask};
        let o = o == "o";  // best line
        for client in self.clients.values() {
            if client.nick() != mask || (o && !client.operator) || client.invisible {
                continue;
            }
            ctx.rb.reply(rpl::WHOREPLY)
                .param("*")
                .param(client.user())
                .param(client.host())
                .param(&self.domain)
                .param(client.nick())
                .param("H")
                .trailing_param(client.real());
        }
        ctx.rb.reply(rpl::ENDOFWHO).param(mask).trailing_param(lines::END_OF_WHO);

        Ok(())
    }

    // WHOIS

    pub fn cmd_whois(&self, ctx: CommandContext<'_>, nick: &str) -> Result {
        let (_, target_client) = find_nick(ctx.addr, ctx.rb, &self.clients, nick)?;

        ctx.rb.reply(rpl::WHOISUSER)
            .param(target_client.nick())
            .param(target_client.user())
            .param(target_client.host())
            .param("*")
            .trailing_param(target_client.real());
        ctx.rb.reply(rpl::WHOISSERVER)
            .param(target_client.nick())
            .param(&self.domain)
            .trailing_param(&self.org_name);
        ctx.rb.reply(rpl::WHOISIDLE)
            .param(target_client.nick())
            .param(&target_client.idle_time().to_string())
            .param(&target_client.signon_time().to_string())
            .trailing_param(lines::WHOIS_IDLE);
        ctx.rb.reply(rpl::ENDOFWHOIS)
            .param(target_client.nick())
            .trailing_param(lines::END_OF_WHOIS);

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use super::super::test;
    use crate::message::Command;

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

        // c1 c2 c3 all registered
        test::handle_message(&mut state, &a1, "INVITE whoops #channel");
        test::collect(&mut buf, &mut q1);
        test::collect(&mut buf, &mut q2);
        test::collect(&mut buf, &mut q3);
        test::assert_msgs(&buf, &[
            (Some(test::DOMAIN), Err(rpl::ERR_NOSUCHNICK), &["c1", "whoops", lines::NO_SUCH_NICK]),
        ]);

        // c1 c2 c3 all registered
        test::handle_message(&mut state, &a1, "INVITE c2 #channel");
        buf.clear();
        test::collect(&mut buf, &mut q1);
        test::collect(&mut buf, &mut q2);
        test::collect(&mut buf, &mut q3);
        test::assert_msgs(&buf, &[
            (Some(test::DOMAIN), Err(rpl::INVITING), &["c1", "#channel", "c2"]),
            (Some("c1!X@127.0.0.1"), Ok(Command::Invite), &["c2", "#channel"]),
        ]);

        // c1 c2 c3 all registered - c2 invited
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

        // c1 c2 c3 all registered - c1 on channel - c2 invited
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

        // c1 c2 c3 all registered - c1 on channel - c2 on channel
        test::handle_message(&mut state, &a1, "MODE #channel +i");
        buf.clear();
        test::collect(&mut buf, &mut q1);
        test::collect(&mut buf, &mut q2);
        test::collect(&mut buf, &mut q3);
        test::assert_msgs(&buf, &[
            (Some("c1!X@127.0.0.1"), Ok(Command::Mode), &["#channel", "+i"]),
            (Some("c1!X@127.0.0.1"), Ok(Command::Mode), &["#channel", "+i"]),
        ]);

        // c1 c2 c3 all registered - channel is invite-only - c1 on channel - c2 on channel
        test::handle_message(&mut state, &a3, "JOIN #channel");
        buf.clear();
        test::collect(&mut buf, &mut q1);
        test::collect(&mut buf, &mut q2);
        test::collect(&mut buf, &mut q3);
        test::assert_msgs(&buf, &[
            (Some(test::DOMAIN), Err(rpl::ERR_INVITEONLYCHAN), &["c3", "#channel", lines::INVITE_ONLY_CHAN]),
        ]);

        // c1 c2 c3 all registered - channel is invite-only - c1 on channel - c2 on channel
        test::handle_message(&mut state, &a2, "INVITE c3 #channel");
        buf.clear();
        test::collect(&mut buf, &mut q1);
        test::collect(&mut buf, &mut q2);
        test::collect(&mut buf, &mut q3);
        test::assert_msgs(&buf, &[
            (Some(test::DOMAIN), Err(rpl::ERR_CHANOPRIVSNEEDED), &["c2", "#channel", lines::CHAN_O_PRIVS_NEEDED]),
        ]);

        // channel is invite-only - c1 on channel - c2 on channel - c3 is invited
        test::handle_message(&mut state, &a1, "INVITE c3 #channel");
        buf.clear();
        test::collect(&mut buf, &mut q1);
        test::collect(&mut buf, &mut q2);
        test::collect(&mut buf, &mut q3);
        test::assert_msgs(&buf, &[
            (Some(test::DOMAIN), Err(rpl::INVITING), &["c1", "#channel", "c3"]),
            (Some("c1!X@127.0.0.1"), Ok(Command::Invite), &["c3", "#channel"]),
        ]);

        // channel is invite-only - c1 on channel - c2 on channel - c3 is invited
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

        // channel is invite-only - c1 on channel - c2 on channel - c3 on channel
        test::handle_message(&mut state, &a3, "PART #channel");
        buf.clear();
        test::collect(&mut buf, &mut q1);
        test::collect(&mut buf, &mut q2);
        test::collect(&mut buf, &mut q3);
        test::assert_msgs(&buf, &[
            (Some("c3!X@127.0.0.1"), Ok(Command::Part), &["#channel"]),
            (Some("c3!X@127.0.0.1"), Ok(Command::Part), &["#channel"]),
            (Some("c3!X@127.0.0.1"), Ok(Command::Part), &["#channel"]),
        ]);

        // c3 registered - channel is invite-only - c1 on channel - c2 on channel
        test::handle_message(&mut state, &a3, "JOIN #channel");
        buf.clear();
        test::collect(&mut buf, &mut q1);
        test::collect(&mut buf, &mut q2);
        test::collect(&mut buf, &mut q3);
        test::assert_msgs(&buf, &[
            (Some(test::DOMAIN), Err(rpl::ERR_INVITEONLYCHAN), &["c3", "#channel", lines::INVITE_ONLY_CHAN]),
        ]);

        // channel is invite-only - c1 on channel - c2 on channel
        test::handle_message(&mut state, &a1, "INVITE c2 #channel");
        buf.clear();
        test::collect(&mut buf, &mut q1);
        test::collect(&mut buf, &mut q2);
        test::collect(&mut buf, &mut q3);
        test::assert_msgs(&buf, &[
            (Some(test::DOMAIN), Err(rpl::ERR_USERONCHANNEL), &["c1", "c2", "#channel", lines::USER_ON_CHANNEL]),
        ]);
    }
}  // mod tests
