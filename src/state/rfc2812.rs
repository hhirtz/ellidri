//! Handlers for the RFC 2812 client-to-server interface.
//!
//! <https://tools.ietf.org/html/rfc2812.html>

use crate::channel::Channel;
use crate::client::{Client, MessageQueueItem};
use crate::{lines, modes, util};
use crate::message::{Buffer, Command, ReplyBuffer, rpl};
use ellidri_unicase::{u, UniCase};
use std::iter;
use super::{CommandContext, HandlerResult as Result, find_channel, find_member, find_nick};

// Command handlers
impl super::StateInner {
    // ADMIN

    pub fn cmd_admin(&self, ctx: CommandContext<'_>) -> Result {
        ctx.rb.start_lr_batch();
        ctx.rb.reply(rpl::ADMINME).param(&self.domain).trailing_param(lines::ADMIN_ME);
        ctx.rb.reply(rpl::ADMINLOC1).trailing_param(&self.org_location);
        ctx.rb.reply(rpl::ADMINLOC2).trailing_param(&self.org_name);
        ctx.rb.reply(rpl::ADMINMAIL).trailing_param(&self.org_mail);

        Ok(())
    }

    // AWAY

    pub fn cmd_away(&mut self, ctx: CommandContext<'_>, reason: &str) -> Result {
        let client = &mut self.clients[ctx.id];
        if reason.is_empty() {
            client.away_message = None;
            ctx.rb.reply(rpl::UNAWAY).trailing_param(lines::UN_AWAY);
        } else {
            let away_message = reason[..reason.len().min(self.awaylen)].to_owned();
            client.away_message = Some(away_message);
            ctx.rb.reply(rpl::NOWAWAY).trailing_param(lines::NOW_AWAY);
        }
        let mut away_notify = Buffer::new();
        {
            let msg = away_notify.message(client.full_name(), Command::Away);
            if let Some(ref away_message) = client.away_message {
                msg.trailing_param(away_message);
            }
        }
        self.send_notification(ctx.id, away_notify, |_, client| client.capabilities().away_notify);
        Ok(())
    }

    // INFO

    pub fn cmd_info(&self, ctx: CommandContext<'_>) -> Result {
        ctx.rb.start_lr_batch();
        for line in super::SERVER_INFO.lines() {
            ctx.rb.reply(rpl::INFO).trailing_param(line);
        }
        ctx.rb.reply(rpl::ENDOFINFO).trailing_param(lines::END_OF_INFO);

        Ok(())
    }

    // INVITE

    pub fn cmd_invite(&mut self, ctx: CommandContext<'_>, nick: &str, target: &str) -> Result {
        let (invited, invited_cli) = find_nick(ctx.id, ctx.rb, &self.clients, &self.nicks, nick)?;
        let channel = match self.channels.get_mut(u(target)) {
            Some(channel) => channel,
            None => {
                log::debug!("{}:     no such channel", ctx.id);
                ctx.rb.reply(rpl::ERR_NOSUCHCHANNEL)
                    .param(target)
                    .trailing_param(lines::NO_SUCH_CHANNEL);
                return Err(());
            },
        };
        if !channel.can_invite(ctx.id) {
            log::debug!("{}:     not operator", ctx.id);
            ctx.rb.reply(rpl::ERR_CHANOPRIVSNEEDED)
                .param(target)
                .trailing_param(lines::CHAN_O_PRIVS_NEEDED);
            return Err(());
        }
        if channel.members.contains_key(&invited) {
            log::debug!("{}:     user on channel", ctx.id);
            ctx.rb.reply(rpl::ERR_USERONCHANNEL)
                .param(nick)
                .param(target)
                .trailing_param(lines::USER_ON_CHANNEL);
            return Err(());
        }

        if !channel.invites.insert(invited) {
            return Err(());
        }

        ctx.rb.start_lr_batch();
        ctx.rb.reply(rpl::INVITING).param(nick).param(target);
        if let Some(away_msg) = invited_cli.away_message() {
            ctx.rb.reply(rpl::AWAY).param(nick).trailing_param(away_msg);
        }

        let mut invite = Buffer::new();
        invite.message(self.clients[ctx.id].full_name(), Command::Invite)
            .param(nick)
            .param(target);
        let invite = MessageQueueItem::from(invite);
        self.clients[invited].send(invite.clone());
        for member in channel.members.keys().filter(|a| **a != ctx.id) {
            let c = &self.clients[*member];
            if c.capabilities().invite_notify && channel.can_invite(*member) {
                c.send(invite.clone());
            }
        }

        Ok(())
    }

    // JOIN

    fn check_join(client: &Client, channel: &Channel, target: &str, key: &str,
                  ctx: &mut CommandContext<'_>) -> Result
    {
        if channel.members.contains_key(&ctx.id) {
            log::debug!("{}:     Already in channel", ctx.id);
            return Err(());
        }
        if channel.key.as_ref().map_or(false, |ck| key != ck) {
            log::debug!("{}:     Bad key", ctx.id);
            ctx.rb.reply(rpl::ERR_BADCHANKEY).param(target).trailing_param(lines::BAD_CHAN_KEY);
            return Err(());
        }
        if channel.user_limit.map_or(false, |user_limit| user_limit <= channel.members.len()) {
            log::debug!("{}:     user limit reached", ctx.id);
            ctx.rb.reply(rpl::ERR_CHANNELISFULL)
                .param(target)
                .trailing_param(lines::CHANNEL_IS_FULL);
            return Err(());
        }
        if !channel.is_invited(ctx.id, client.nick()) {
            log::debug!("{}:     not invited", ctx.id);
            ctx.rb.reply(rpl::ERR_INVITEONLYCHAN)
                .param(target)
                .trailing_param(lines::INVITE_ONLY_CHAN);
            return Err(());
        }
        if channel.is_banned(client.nick()) || channel.is_banned(client.full_name()) {
            log::debug!("{}:     Banned", ctx.id);
            ctx.rb.reply(rpl::ERR_BANNEDFROMCHAN)
                .param(target)
                .trailing_param(lines::BANNED_FROM_CHAN);
            return Err(());
        }
        Ok(())
    }

    fn chan_and_keys<'a>(channels: &'a str, keys: &'a str)
        -> impl Iterator<Item=(&'a str,&'a str)> + 'a
    {
        channels.split(',')
            .zip(keys.split(',').chain(iter::repeat("")))
            .filter(|(chan, _)| !chan.is_empty())
    }

    fn send_join(&self, id: usize, rb: &mut ReplyBuffer, target: &str, client: &Client) {
        let mut join = Buffer::new();
        join.message(client.full_name(), Command::Join).param(target);
        let join = MessageQueueItem::from(join);

        let mut extended_join = Buffer::new();
        extended_join.message(client.full_name(), Command::Join)
            .param(target)
            .param(client.identity().unwrap_or("*"))
            .trailing_param(client.real());
        let extended_join = MessageQueueItem::from(extended_join);

        let channel = &self.channels[u(target)];
        for member in channel.members.keys().filter(|m| **m != id) {
            let member = &self.clients[*member];
            if member.capabilities().extended_join {
                member.send(extended_join.clone());
            } else {
                member.send(join.clone());
            }
        }
        rb.message(client.full_name(), Command::Join).param(target);

        if let Some(ref away_message) = client.away_message {
            let mut away_notify = Buffer::new();
            away_notify.message(client.full_name(), Command::Away).trailing_param(away_message);
            let away_notify = MessageQueueItem::from(away_notify);

            for member in channel.members.keys().filter(|m| **m != id) {
                let member = &self.clients[*member];
                if member.capabilities().away_notify {
                    member.send(away_notify.clone());
                }
            }
        }
    }

    pub fn cmd_join(&mut self, mut ctx: CommandContext<'_>, targets: &str, keys: &str) -> Result {
        let client = &self.clients[ctx.id];

        let mut update_idle = false;
        for (target, key) in super::StateInner::chan_and_keys(targets, keys) {
            if !super::is_valid_channel_name(target, self.channellen) {
                log::debug!("{}:     Invalid channel name", ctx.id);
                ctx.rb.reply(rpl::ERR_NOSUCHCHANNEL)
                    .param(target)
                    .trailing_param(lines::NO_SUCH_CHANNEL);
                return Err(());
            }
            let ok = self.channels.get(u(target))
                .map_or(Ok(()), |channel| {
                    super::StateInner::check_join(client, channel, target, key, &mut ctx)
                })
                .is_ok();

            if ok {
                let default_chan_mode = &self.default_chan_mode;
                let channel = self.channels.entry(UniCase(target.to_owned()))
                    .or_insert_with(|| Channel::new(&default_chan_mode));
                channel.add_member(ctx.id);

                ctx.rb.start_lr_batch();
                self.send_join(ctx.id, ctx.rb, target, client);
                self.write_topic(ctx.rb, target);
                self.write_names(ctx.id, ctx.rb, target);
                update_idle = true;
            }
        }
        if update_idle {
            let client = self.clients.get_mut(ctx.id).unwrap();
            client.update_idle_time();
        }

        Ok(())
    }

    // KICK

    pub fn cmd_kick(&mut self, ctx: CommandContext<'_>, target: &str,
                    nick: &str, reason: &str) -> Result
    {
        let channel = find_channel(ctx.id, ctx.rb, &self.channels, target)?;
        let member_modes = find_member(ctx.id, ctx.rb, channel, target)?;
        if !member_modes.operator {
            log::debug!("{}:     not operator", ctx.id);
            ctx.rb.reply(rpl::ERR_CHANOPRIVSNEEDED)
                .param(target)
                .trailing_param(lines::CHAN_O_PRIVS_NEEDED);
            return Err(());
        }
        let clients = &self.clients;
        let kicked_addrs = channel.members.keys()
            .find(|id| clients[**id].nick().eq_ignore_ascii_case(nick))
            .copied();
        let kicked_addrs = match kicked_addrs {
            Some(kicked_addrs) => kicked_addrs,
            None => {
                log::debug!("{}:     targets not on channel", ctx.id);
                ctx.rb.reply(rpl::ERR_USERNOTINCHANNEL)
                    .param(nick)
                    .param(target)
                    .trailing_param(lines::USER_NOT_IN_CHANNEL);
                return Err(());
            }
        };

        let reason = &reason[..reason.len().min(self.kicklen)];
        let client = &self.clients[ctx.id];
        let mut kick_response = Buffer::new();
        {
            let msg = kick_response.message(client.full_name(), Command::Kick)
                .param(target)
                .param(nick);
            if !reason.is_empty() {
                msg.trailing_param(reason);
            }
        }
        let msg = MessageQueueItem::from(kick_response);
        let channel = self.channels.get_mut(u(target)).unwrap();
        for member in channel.members.keys().filter(|m| **m != ctx.id) {
            self.clients[*member].send(msg.clone());
        }
        let msg = ctx.rb.message(client.full_name(), Command::Kick)
            .param(target)
            .param(nick);
        if !reason.is_empty() {
            msg.trailing_param(reason);
        }
        channel.members.remove(&kicked_addrs);

        Ok(())
    }

    // LIST

    pub fn cmd_list(&self, ctx: CommandContext<'_>, targets: &str) -> Result {
        let client = &self.clients[ctx.id];
        ctx.rb.start_lr_batch();
        if targets.is_empty() {
            for (name, channel) in &self.channels {
                if channel.secret && !client.operator && !channel.members.contains_key(&ctx.id) {
                    continue;
                }
                let msg = ctx.rb.reply(rpl::LIST).param(name.as_ref());
                channel.list_entry(msg);
            }
        } else {
            for name in targets.split(',') {
                if let Some(channel) = self.channels.get(u(name)) {
                    if channel.secret && !client.operator && !channel.members.contains_key(&ctx.id) {
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
        ctx.rb.start_lr_batch();
        self.write_lusers(ctx.rb);
        Ok(())
    }

    // MODE

    fn cmd_mode_chan_get(&self, ctx: CommandContext<'_>, target: &str) -> Result {
        let channel = find_channel(ctx.id, ctx.rb, &self.channels, target)?;
        let msg = ctx.rb.reply(rpl::CHANNELMODEIS).param(target);
        channel.modes(msg, channel.members.contains_key(&ctx.id) || self.clients[ctx.id].operator);

        Ok(())
    }

    fn cmd_mode_chan_set(&mut self, ctx: CommandContext<'_>, target: &str,
                               modes: &str, modeparams: &[&str]) -> Result
    {
        let channel = match self.channels.get_mut(u(target)) {
            Some(channel) => channel,
            None => {
                log::debug!("{}:     no such channel", ctx.id);
                ctx.rb.reply(rpl::ERR_NOSUCHCHANNEL)
                    .param(target)
                    .trailing_param(lines::NO_SUCH_CHANNEL);
                return Err(());
            }
        };
        let client = &self.clients[ctx.id];
        let member_modes = find_member(ctx.id, ctx.rb, channel, target)?;
        if !client.operator && !member_modes.can_change(modes, modeparams) {
            log::debug!("{}:     not operator", ctx.id);
            ctx.rb.reply(rpl::ERR_CHANOPRIVSNEEDED)
                .param(target)
                .trailing_param(lines::CHAN_O_PRIVS_NEEDED);
            return Err(());
        }

        let reply_list = |rb: &mut ReplyBuffer, item, end, line, it: &[String]| {
            for i in it {
                rb.reply(item).param(target).param(i);
            }
            rb.reply(end).param(target).trailing_param(line);
        };

        let clients = &self.clients;

        let mut applied_modes = String::new();
        let mut applied_modeparams = Vec::new();
        let mut last_applied_value = true;
        for maybe_change in modes::channel_query(modes, modeparams) { match maybe_change {
            Ok(modes::ChannelModeChange::GetBans) => {
                reply_list(ctx.rb, rpl::BANLIST, rpl::ENDOFBANLIST, lines::END_OF_BAN_LIST,
                           channel.ban_mask.patterns());
            }
            Ok(modes::ChannelModeChange::GetExceptions) => {
                reply_list(ctx.rb, rpl::EXCEPTLIST, rpl::ENDOFEXCEPTLIST, lines::END_OF_EXCEPT_LIST,
                           channel.exception_mask.patterns());
            }
            Ok(modes::ChannelModeChange::GetInvitations) => {
                reply_list(ctx.rb, rpl::INVITELIST, rpl::ENDOFINVITELIST, lines::END_OF_INVITE_LIST,
                           channel.exception_mask.patterns());
            }
            Ok(change) => match channel.apply_mode_change(change, |a| clients[*a].nick()) {
                Ok(true) => {
                    log::debug!("    - Applied {:?}", change);
                    let change_value = change.value();
                    if last_applied_value != change_value || applied_modes.is_empty() {
                        applied_modes.push(if change_value {'+'} else {'-'});
                        last_applied_value = change_value;
                    }
                    applied_modes.push(change.symbol());
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
                Err(_) => { unreachable!(); }
            }
            Err(modes::Error::UnknownMode(mode)) => {
                let mut msg = ctx.rb.reply(rpl::ERR_UNKNOWNMODE);
                msg.raw_param().push(mode);
                msg.trailing_param(lines::UNKNOWN_MODE);
            },
            Err(_) => {},
        } }

        if !applied_modes.is_empty() {
            ctx.rb.start_lr_batch();
            let client = &self.clients[ctx.id];
            let mut mode_change = Buffer::new();
            {
                let mut msg = mode_change.message(client.full_name(), Command::Mode)
                    .param(target)
                    .param(&applied_modes);
                for mp in &applied_modeparams {
                    msg = msg.param(mp);
                }
            }
            let mode_change = MessageQueueItem::from(mode_change);
            for member in channel.members.keys().filter(|m| **m != ctx.id) {
                self.clients[*member].send(mode_change.clone());
            }
            let mut msg = ctx.rb.message(client.full_name(), Command::Mode)
                .param(target)
                .param(&applied_modes);
            for mp in &applied_modeparams {
                msg = msg.param(mp);
            }
        }

        Ok(())
    }

    fn cmd_mode_user_check(&self, ctx: &mut CommandContext<'_>, nick: &str) -> Result {
        if !self.clients[ctx.id].nick().eq_ignore_ascii_case(nick) {
            log::debug!("{}:     users don't match", ctx.id);
            ctx.rb.reply(rpl::ERR_USERSDONTMATCH)
                .param(nick)
                .trailing_param(lines::USERS_DONT_MATCH);
            return Err(());
        }
        Ok(())
    }

    fn cmd_mode_user_set(&mut self, ctx: CommandContext<'_>, target: &str, modes: &str) -> Result {
        let client = self.clients.get_mut(ctx.id).unwrap();

        let mut applied_modes = String::new();
        for maybe_change in modes::user_query(modes) { match maybe_change {
            Ok(change) => if client.apply_mode_change(change) {
                log::debug!("  - Applied {:?}", change);
                applied_modes.push(if change.value() {'+'} else {'-'});
                applied_modes.push(change.symbol());
            }
            Err(modes::Error::UnknownMode(mode)) => {
                let mut msg = ctx.rb.reply(rpl::ERR_UMODEUNKNOWNFLAG);
                msg.raw_param().push(mode);
                msg.trailing_param(lines::UNKNOWN_MODE);
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
        let client = &self.clients[ctx.id];
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
        ctx.rb.start_lr_batch();
        self.write_motd(ctx.rb);
        Ok(())
    }

    // NAMES

    pub fn cmd_names(&self, ctx: CommandContext<'_>, targets: &str) -> Result {
        if targets.is_empty() || targets == "*" {
            ctx.rb.reply(rpl::ENDOFNAMES).param("*").trailing_param(lines::END_OF_NAMES);
        } else {
            ctx.rb.start_lr_batch();
            for target in targets.split(',') {
                self.write_names(ctx.id, ctx.rb, target);
            }
        }

        Ok(())
    }

    // NICK

    pub fn cmd_nick(&mut self, ctx: CommandContext<'_>, nick: &str) -> Result {
        if !super::is_valid_nickname(nick, self.nicklen) {
            log::debug!("{}:     Bad nickname", ctx.id);
            ctx.rb.reply(rpl::ERR_ERRONEUSNICKNAME)
                .param(nick)
                .trailing_param(lines::ERRONEOUS_NICKNAME);
            return Err(());
        }
        if self.nicks.contains_key(u(nick)) {
            log::debug!("{}:     Already in use", ctx.id);
            ctx.rb.reply(rpl::ERR_NICKNAMEINUSE).param(nick).trailing_param(lines::NICKNAME_IN_USE);
            return Err(());
        }

        let client = self.clients.get_mut(ctx.id).unwrap();
        self.nicks.remove(u(client.nick()));
        self.nicks.insert(UniCase(nick.to_owned()), ctx.id);
        ctx.rb.set_nick(nick);

        if !client.is_registered() {
            log::debug!("{}:     Is not registered", ctx.id);
            client.set_nick(nick);
            return Ok(());
        }

        let mut nick_response = Buffer::new();
        nick_response.message(client.full_name(), Command::Nick).param(nick);
        ctx.rb.message(client.full_name(), Command::Nick).param(nick);
        client.set_nick(nick);
        self.send_notification(ctx.id, nick_response, |_, _| true);

        Ok(())
    }

    // NOTICE

    pub fn cmd_notice(&mut self, ctx: CommandContext<'_>, target: &str, content: &str) -> Result {
        self.send_query_or_channel_msg(ctx, Command::Notice, target, Some(content))
    }

    // OPER

    pub fn cmd_oper(&mut self, ctx: CommandContext<'_>, name: &str, password: &str) -> Result {
        // TODO oper_hosts
        if !self.opers.iter().any(|(n, p)| n == name && p == password) {
            log::debug!("{}:     Password mismatch", ctx.id);
            ctx.rb.reply(rpl::ERR_PASSWDMISMATCH).trailing_param(lines::PASSWORD_MISMATCH);
            return Err(());
        }

        let client = self.clients.get_mut(ctx.id).unwrap();
        client.operator = true;
        ctx.rb.start_lr_batch();
        ctx.rb.message(&self.domain, Command::Mode).param(client.nick()).param("+o");
        ctx.rb.reply(rpl::YOUREOPER).trailing_param(lines::YOURE_OPER);

        Ok(())
    }

    // PART

    pub fn cmd_part(&mut self, ctx: CommandContext<'_>, targets: &str, reason: &str) -> Result {
        let client = &self.clients[ctx.id];

        let mut res = Ok(());
        for target in targets.split(',').filter(|s| !s.is_empty()) {
            ctx.rb.start_lr_batch();
            let channel = match self.channels.get_mut(u(target)) {
                Some(channel) => channel,
                None => {
                    log::debug!("{}:     Not on channel", ctx.id);
                    ctx.rb.reply(rpl::ERR_NOTONCHANNEL)
                        .param(target)
                        .trailing_param(lines::NOT_ON_CHANNEL);
                    res = Err(());
                    continue;
                }
            };
            find_member(ctx.id, ctx.rb, channel, target)?;

            if channel.members.is_empty() {
                self.channels.remove(u(target));
            } else {
                let mut part_notice = Buffer::new();

                channel.members.remove(&ctx.id);
                if reason.is_empty() {
                    part_notice.message(client.full_name(), Command::Part).param(target);
                } else {
                    part_notice.message(client.full_name(), Command::Part)
                        .param(target)
                        .trailing_param(reason);
                }
                let part_notice = MessageQueueItem::from(part_notice);
                for member in channel.members.keys() {
                    self.clients[*member].send(part_notice.clone());
                }
            }

            let msg = ctx.rb.message(client.full_name(), Command::Part).param(target);
            if !reason.is_empty() {
                msg.trailing_param(reason);
            }
        }

        res
    }

    // PASS

    pub fn cmd_pass(&mut self, ctx: CommandContext<'_>, password: &str) -> Result {
        if self.password.as_ref().map_or(false, |p| p == password) {
            self.clients.get_mut(ctx.id).unwrap().has_given_password = true;
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
        self.send_query_or_channel_msg(ctx, Command::PrivMsg, target, Some(content))
    }

    // QUIT

    pub fn cmd_quit(&mut self, ctx: CommandContext<'_>, reason: &str) -> Result {
        let mut response = Buffer::new();
        let client = self.clients.remove(ctx.id);
        response.message("", "ERROR").trailing_param(lines::CLOSING_LINK);
        client.send(MessageQueueItem::from(response));
        self.remove_client(ctx.id, client, if reason.is_empty() {None} else {Some(reason)});
        Ok(())
    }

    // TIME

    pub fn cmd_time(&self, ctx: CommandContext<'_>) -> Result {
        ctx.rb.reply(rpl::TIME).param(&self.domain).trailing_param(&util::time_str());
        Ok(())
    }

    // TOPIC

    fn cmd_topic_set(&mut self, ctx: CommandContext<'_>, target: &str, topic: &str) -> Result {
        let channel = match self.channels.get_mut(u(target)) {
            Some(channel) => channel,
            None => {
                log::debug!("{}:     no such channel", ctx.id);
                ctx.rb.reply(rpl::ERR_NOSUCHCHANNEL)
                    .param(target)
                    .trailing_param(lines::NO_SUCH_CHANNEL);
                return Err(());
            }
        };
        let member_modes = find_member(ctx.id, ctx.rb, channel, target)?;
        if !member_modes.operator && channel.topic_restricted {
            log::debug!("{}:     not operator", ctx.id);
            ctx.rb.reply(rpl::ERR_CHANOPRIVSNEEDED)
                .param(target)
                .trailing_param(lines::CHAN_O_PRIVS_NEEDED);
            return Err(());
        }

        let topic = &topic[..topic.len().min(self.topiclen)];
        channel.topic = if topic.is_empty() { None } else { Some(topic.to_owned()) };

        let mut topic_notice = Buffer::new();
        topic_notice.message(self.clients[ctx.id].full_name(), Command::Topic)
            .param(target)
            .trailing_param(topic);
        let topic_notice = MessageQueueItem::from(topic_notice);
        for member in channel.members.keys().filter(|m| **m != ctx.id) {
            self.clients[*member].send(topic_notice.clone());
        }
        ctx.rb.message(self.clients[ctx.id].full_name(), Command::Topic)
            .param(target)
            .trailing_param(topic);

        Ok(())
    }

    fn cmd_topic_get(&self, ctx: CommandContext<'_>, target: &str) -> Result {
        let channel = find_channel(ctx.id, ctx.rb, &self.channels, target)?;
        if channel.secret {
            find_member(ctx.id, ctx.rb, channel, target)?;
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
        let client = self.clients.get_mut(ctx.id).unwrap();
        if self.password.is_some() && !client.has_given_password {
            log::debug!("{}:     Password mismatch", ctx.id);
            ctx.rb.reply(rpl::ERR_PASSWDMISMATCH).trailing_param(lines::PASSWORD_MISMATCH);
            return Err(());
        }
        client.set_user(&user[..user.len().min(self.userlen)]);
        client.set_real(&real[..real.len().min(self.namelen)]);

        Ok(())
    }

    // VERSION

    pub fn cmd_version(&self, ctx: CommandContext<'_>) -> Result {
        ctx.rb.start_lr_batch();
        ctx.rb.reply(rpl::VERSION).param(crate::server_version!()).param(&self.domain);
        self.write_i_support(ctx.rb);
        Ok(())
    }

    // WHO

    pub fn cmd_who(&self, ctx: CommandContext<'_>, mask: &str, o: &str) -> Result
    {
        let mask = if mask.is_empty() {"*"} else {mask};
        let o = o == "o";  // best line
        let client = &self.clients[ctx.id];

        if let Some(channel) = self.channels.get(u(mask)) {
            ctx.rb.start_lr_batch();
            let in_channel = channel.members.contains_key(&ctx.id);
            if !channel.secret || in_channel || client.operator {
                for (member, modes) in &channel.members {
                    let c = &self.clients[*member];
                    if (o && !c.operator) ||
                        (!client.operator && c.invisible && !in_channel && *member != ctx.id)
                    {
                        continue;
                    }
                    let mut msg = ctx.rb.reply(rpl::WHOREPLY)
                        .param(mask)
                        .param(c.user())
                        .param(c.host())
                        .param(&self.domain)
                        .param(c.nick());
                    let param = msg.raw_param();
                    param.push(if c.away_message().is_some() { 'G' } else { 'H' });
                    if client.capabilities().multi_prefix {
                        modes.all_symbols(param);
                    } else if let Some(symbol) = modes.symbol() {
                        param.push(symbol);
                    }
                    msg.trailing_param(c.real());
                }
            }
        } else if let Some(&a) = self.nicks.get(u(mask)) {
            ctx.rb.start_lr_batch();
            let c = &self.clients[a];
            if (!o || c.operator) && c.is_registered() {
                let mut channel_name = None;
                let mut member = Default::default();
                for (name, ch) in &self.channels {
                    if let Some(member_modes) = ch.members.get(&a) {
                        if !c.invisible || ch.members.contains_key(&ctx.id) {
                            channel_name = Some(name.as_ref());
                            member = *member_modes;
                            break;
                        }
                    }
                }
                if !c.invisible || a == ctx.id || channel_name.is_some() || client.operator {
                    let client = &self.clients[ctx.id];
                    let channel_name = channel_name.unwrap_or("*");
                    let mut msg = ctx.rb.reply(rpl::WHOREPLY)
                        .param(channel_name)
                        .param(c.user())
                        .param(c.host())
                        .param(&self.domain)
                        .param(c.nick());
                    let param = msg.raw_param();
                    param.push(if c.away_message().is_some() { 'G' } else { 'H' });
                    if client.capabilities().multi_prefix {
                        member.all_symbols(param);
                    } else if let Some(symbol) = member.symbol() {
                        param.push(symbol);
                    }
                    msg.trailing_param(c.real());
                }
            }
        }
        ctx.rb.reply(rpl::ENDOFWHO).param(mask).trailing_param(lines::END_OF_WHO);

        Ok(())
    }

    // WHOIS

    pub fn cmd_whois(&self, ctx: CommandContext<'_>, nick: &str) -> Result {
        let (_, target_client) = find_nick(ctx.id, ctx.rb, &self.clients, &self.nicks, nick)?;

        ctx.rb.start_lr_batch();
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
            .fmt_param(target_client.idle_time())
            .fmt_param(target_client.signon_time())
            .trailing_param(lines::WHOIS_IDLE);
        if let Some(away_msg) = target_client.away_message() {
            ctx.rb.reply(rpl::AWAY).param(target_client.nick()).trailing_param(away_msg);
        }
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

        let (c1, mut q1) = test::add_registered_client(&mut state, "c1");
        test::flush(&mut q1);
        let (c2, mut q2) = test::add_registered_client(&mut state, "c2");
        test::flush(&mut q2);
        let (c3, mut q3) = test::add_registered_client(&mut state, "c3");
        test::flush(&mut q3);

        // c1 c2 c3 all registered
        test::handle_message(&mut state, c1, "INVITE c2 #channel");
        buf.clear();
        test::collect(&mut buf, &mut q1);
        test::collect(&mut buf, &mut q2);
        test::collect(&mut buf, &mut q3);
        test::assert_msgs(&buf, &[
            (Some(test::DOMAIN), Err(rpl::ERR_NOSUCHCHANNEL), &["c1", "#channel", lines::NO_SUCH_CHANNEL]),
        ]);

        // c1 c2 c3 all registered - c2 invited
        test::handle_message(&mut state, c1, "JOIN #channel");
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
        assert_eq!(state.channels[u("#chAnnel")].members.len(), 1);
        assert!(state.channels[u("#chAnnel")].members[&c1].operator);

        // c1 c2 c3 all registered
        test::handle_message(&mut state, c1, "INVITE c2 #channel");
        buf.clear();
        test::collect(&mut buf, &mut q1);
        test::collect(&mut buf, &mut q2);
        test::collect(&mut buf, &mut q3);
        test::assert_msgs(&buf, &[
            (Some(test::DOMAIN), Err(rpl::INVITING), &["c1", "c2", "#channel"]),
            (Some("c1!X@127.0.0.1"), Ok(Command::Invite), &["c2", "#channel"]),
        ]);

        // c1 c2 c3 all registered - c1 on channel - c2 invited
        test::handle_message(&mut state, c2, "JOIN #channel");
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
        test::handle_message(&mut state, c1, "MODE #channel +i");
        buf.clear();
        test::collect(&mut buf, &mut q1);
        test::collect(&mut buf, &mut q2);
        test::collect(&mut buf, &mut q3);
        test::assert_msgs(&buf, &[
            (Some("c1!X@127.0.0.1"), Ok(Command::Mode), &["#channel", "+i"]),
            (Some("c1!X@127.0.0.1"), Ok(Command::Mode), &["#channel", "+i"]),
        ]);

        // c1 c2 c3 all registered - channel is invite-only - c1 on channel - c2 on channel
        test::handle_message(&mut state, c3, "JOIN #channel");
        buf.clear();
        test::collect(&mut buf, &mut q1);
        test::collect(&mut buf, &mut q2);
        test::collect(&mut buf, &mut q3);
        test::assert_msgs(&buf, &[
            (Some(test::DOMAIN), Err(rpl::ERR_INVITEONLYCHAN), &["c3", "#channel", lines::INVITE_ONLY_CHAN]),
        ]);

        // c1 c2 c3 all registered - channel is invite-only - c1 on channel - c2 on channel
        test::handle_message(&mut state, c2, "INVITE c3 #channel");
        buf.clear();
        test::collect(&mut buf, &mut q1);
        test::collect(&mut buf, &mut q2);
        test::collect(&mut buf, &mut q3);
        test::assert_msgs(&buf, &[
            (Some(test::DOMAIN), Err(rpl::ERR_CHANOPRIVSNEEDED), &["c2", "#channel", lines::CHAN_O_PRIVS_NEEDED]),
        ]);

        // channel is invite-only - c1 on channel - c2 on channel - c3 is invited
        test::handle_message(&mut state, c1, "INVITE c3 #channel");
        buf.clear();
        test::collect(&mut buf, &mut q1);
        test::collect(&mut buf, &mut q2);
        test::collect(&mut buf, &mut q3);
        test::assert_msgs(&buf, &[
            (Some(test::DOMAIN), Err(rpl::INVITING), &["c1", "c3", "#channel"]),
            (Some("c1!X@127.0.0.1"), Ok(Command::Invite), &["c3", "#channel"]),
        ]);

        // channel is invite-only - c1 on channel - c2 on channel - c3 is invited
        test::handle_message(&mut state, c3, "JOIN #channel");
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
        test::handle_message(&mut state, c3, "PART #channel");
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
        test::handle_message(&mut state, c3, "JOIN #channel");
        buf.clear();
        test::collect(&mut buf, &mut q1);
        test::collect(&mut buf, &mut q2);
        test::collect(&mut buf, &mut q3);
        test::assert_msgs(&buf, &[
            (Some(test::DOMAIN), Err(rpl::ERR_INVITEONLYCHAN), &["c3", "#channel", lines::INVITE_ONLY_CHAN]),
        ]);

        // channel is invite-only - c1 on channel - c2 on channel
        test::handle_message(&mut state, c1, "INVITE c2 #channel");
        buf.clear();
        test::collect(&mut buf, &mut q1);
        test::collect(&mut buf, &mut q2);
        test::collect(&mut buf, &mut q3);
        test::assert_msgs(&buf, &[
            (Some(test::DOMAIN), Err(rpl::ERR_USERONCHANNEL), &["c1", "c2", "#channel", lines::USER_ON_CHANNEL]),
        ]);
    }

    #[test]
    fn test_cmd_join() {
        let mut state = test::simple_state();
        let mut buf = String::with_capacity(512);

        let (c1, mut q1) = test::add_registered_client(&mut state, "c1");
        test::flush(&mut q1);
        let (c2, mut q2) = test::add_registered_client(&mut state, "c2");
        test::flush(&mut q2);

        // c1 c2 all registered
        test::handle_message(&mut state, c1, "JOIN #channel");
        buf.clear();
        test::collect(&mut buf, &mut q1);
        test::collect(&mut buf, &mut q2);
        test::assert_msgs(&buf, &[
            (Some("c1!X@127.0.0.1"), Ok(Command::Join), &["#channel"]),
            (Some(test::DOMAIN), Err(rpl::NOTOPIC), &["c1", "#channel", lines::NO_TOPIC]),
            (Some(test::DOMAIN), Err(rpl::NAMREPLY), &["c1", "=", "#channel", "@c1"]),
            (Some(test::DOMAIN), Err(rpl::ENDOFNAMES), &["c1", "#channel", lines::END_OF_NAMES]),
        ]);
        assert!(state.channels.get(u("#channel")).is_some());
        assert!(state.channels[u("#channel")].members.contains_key(&c1));

        // c2 all registered - c1 on #channel
        test::handle_message(&mut state, c1, "JOIN #channel");
        buf.clear();
        test::collect(&mut buf, &mut q1);
        test::collect(&mut buf, &mut q2);
        test::assert_msgs(&buf, &[]);

        // c2 all registered - c1 on #channel
        test::handle_message(&mut state, c1, "MODE #channel +k key");
        buf.clear();
        test::collect(&mut buf, &mut q1);
        test::collect(&mut buf, &mut q2);
        test::assert_msgs(&buf, &[
            (Some("c1!X@127.0.0.1"), Ok(Command::Mode), &["#channel", "+k", "key"]),
        ]);
        assert!(state.channels[u("#channel")].key.as_ref().unwrap() == "key");

        // c2 all registered - c1 on #channel+kkey
        test::handle_message(&mut state, c2, "JOIN #channel,#home");
        buf.clear();
        test::collect(&mut buf, &mut q1);
        test::collect(&mut buf, &mut q2);
        test::assert_msgs(&buf, &[
            (Some(test::DOMAIN), Err(rpl::ERR_BADCHANKEY), &["c2", "#channel", lines::BAD_CHAN_KEY]),
            (Some("c2!X@127.0.0.1"), Ok(Command::Join), &["#home"]),
            (Some(test::DOMAIN), Err(rpl::NOTOPIC), &["c2", "#home", lines::NO_TOPIC]),
            (Some(test::DOMAIN), Err(rpl::NAMREPLY), &["c2", "=", "#home", "@c2"]),
            (Some(test::DOMAIN), Err(rpl::ENDOFNAMES), &["c2", "#home", lines::END_OF_NAMES]),
        ]);
        assert!(state.channels.get(u("#home")).is_some());
        assert!(state.channels[u("#home")].members.contains_key(&c2));
        // TODO continue
    }
}  // mod tests
