//! Handlers for the client-to-server interface defined in the RFCs.
//!
//! <https://tools.ietf.org/html/rfc2812.html>
//! <https://modern.ircdocs.horse/>

use super::{find_channel, find_member, find_nick, CommandContext, HandlerResult as Result};
use crate::channel::{MemberModes, Topic};
use crate::client::MessageQueueItem;
use crate::{data, lines, util, Channel, Client};
use ellidri_tokens::{mode, rpl, Buffer, Command, ReplyBuffer};
use ellidri_unicase::{u, UniCase};

// Command handlers
impl super::StateInner {
    // ADMIN

    pub fn cmd_admin(&self, ctx: CommandContext<'_>) -> Result {
        ctx.rb.lr_batch_begin();
        ctx.rb
            .reply(rpl::ADMINME)
            .param(&self.domain)
            .trailing_param(lines::ADMIN_ME);
        ctx.rb
            .reply(rpl::ADMINLOC1)
            .trailing_param(&self.org_location);
        ctx.rb.reply(rpl::ADMINLOC2).trailing_param(&self.org_name);
        ctx.rb.reply(rpl::ADMINMAIL).trailing_param(&self.org_mail);
        Ok(())
    }

    // AWAY

    pub fn cmd_away(&mut self, ctx: CommandContext<'_>, reason: Option<&str>) -> Result {
        let client = &mut self.clients[ctx.id];

        if client.away_message().is_some() == reason.is_some() {
            log::debug!("{}:     useless away", ctx.id);
            return Err(());
        }

        let awaylen = self.awaylen;
        client.away_message = reason.map(|r| r[..r.len().min(awaylen)].to_owned());

        if reason.is_some() {
            ctx.rb.reply(rpl::NOWAWAY).trailing_param(lines::NOW_AWAY);
        } else {
            ctx.rb.reply(rpl::UNAWAY).trailing_param(lines::UN_AWAY);
        }

        let mut away_notify = Buffer::with_capacity(512);
        {
            let msg = away_notify.message(client.full_name(), Command::Away);
            if let Some(ref away_message) = client.away_message {
                msg.trailing_param(away_message);
            }
        }
        self.send_notification(ctx.id, away_notify, |_, client| {
            client.cap_enabled.away_notify
        });
        Ok(())
    }

    // INFO

    pub fn cmd_info(&self, ctx: CommandContext<'_>) -> Result {
        ctx.rb.lr_batch_begin();
        for line in super::SERVER_INFO.lines() {
            ctx.rb.reply(rpl::INFO).trailing_param(line);
        }
        ctx.rb
            .reply(rpl::ENDOFINFO)
            .trailing_param(lines::END_OF_INFO);
        Ok(())
    }

    // INVITE

    pub fn cmd_invite(&mut self, ctx: CommandContext<'_>, args: data::req::Invite<'_>) -> Result {
        let (who_id, who_data) = find_nick(ctx.id, ctx.rb, &self.clients, &self.nicks, args.who)?;

        let channel = match self.channels.get_mut(args.to.u()) {
            Some(channel) => channel,
            None => {
                log::debug!("{}:     no such channel", ctx.id);
                ctx.rb
                    .reply(rpl::ERR_NOSUCHCHANNEL)
                    .param(args.to.get())
                    .trailing_param(lines::NO_SUCH_CHANNEL);
                return Err(());
            }
        };
        if !channel.can_invite(ctx.id) {
            log::debug!("{}:     not operator", ctx.id);
            ctx.rb
                .reply(rpl::ERR_CHANOPRIVSNEEDED)
                .param(args.to.get())
                .trailing_param(lines::CHAN_O_PRIVS_NEEDED);
            return Err(());
        }
        if channel.members.contains_key(&who_id) {
            log::debug!("{}:     user on channel", ctx.id);
            ctx.rb
                .reply(rpl::ERR_USERONCHANNEL)
                .param(args.who.get())
                .param(args.to.get())
                .trailing_param(lines::USER_ON_CHANNEL);
            return Err(());
        }

        if !channel.invites.insert(who_id) {
            return Err(());
        }

        ctx.rb.lr_batch_begin();
        ctx.rb
            .reply(rpl::INVITING)
            .param(args.who.get())
            .param(args.to.get());
        if let Some(away_msg) = who_data.away_message() {
            ctx.rb
                .reply(rpl::AWAY)
                .param(args.who.get())
                .trailing_param(away_msg);
        }

        let mut invite = Buffer::with_capacity(512);
        invite
            .message(self.clients[ctx.id].full_name(), Command::Invite)
            .param(args.who.get())
            .param(args.to.get());
        let invite = MessageQueueItem::from(invite);

        self.clients[who_id].send(invite.clone());

        for member in channel.members.keys().filter(|a| **a != ctx.id) {
            let c = &self.clients[*member];
            if c.cap_enabled.invite_notify && channel.can_invite(*member) {
                c.send(invite.clone());
            }
        }

        Ok(())
    }

    // JOIN

    fn check_join(
        client: &Client,
        channel: &Channel,
        channel_name: &str,
        key: Option<&str>,
        ctx: &mut CommandContext<'_>,
    ) -> Result {
        if channel.members.contains_key(&ctx.id) {
            log::debug!("{}:     Already in channel", ctx.id);
            return Err(());
        }
        if channel.key.as_deref() != key {
            log::debug!("{}:     Bad key", ctx.id);
            ctx.rb
                .reply(rpl::ERR_BADCHANKEY)
                .param(channel_name)
                .trailing_param(lines::BAD_CHAN_KEY);
            return Err(());
        }
        if channel
            .user_limit
            .map_or(false, |user_limit| user_limit <= channel.members.len())
        {
            log::debug!("{}:     user limit reached", ctx.id);
            ctx.rb
                .reply(rpl::ERR_CHANNELISFULL)
                .param(channel_name)
                .trailing_param(lines::CHANNEL_IS_FULL);
            return Err(());
        }
        if !channel.is_invited(ctx.id, client.nick()) {
            log::debug!("{}:     not invited", ctx.id);
            ctx.rb
                .reply(rpl::ERR_INVITEONLYCHAN)
                .param(channel_name)
                .trailing_param(lines::INVITE_ONLY_CHAN);
            return Err(());
        }
        if channel.is_banned(client.nick()) || channel.is_banned(client.full_name()) {
            log::debug!("{}:     Banned", ctx.id);
            ctx.rb
                .reply(rpl::ERR_BANNEDFROMCHAN)
                .param(channel_name)
                .trailing_param(lines::BANNED_FROM_CHAN);
            return Err(());
        }
        Ok(())
    }

    fn send_join(&self, id: usize, rb: &mut ReplyBuffer, channel_name: &str, client: &Client) {
        rb.message(client.full_name(), Command::Join)
            .param(channel_name);

        let mut join = Buffer::with_capacity(512);
        join.message(client.full_name(), Command::Join)
            .param(channel_name);
        let join = MessageQueueItem::from(join);

        let mut extended_join = Buffer::with_capacity(512);
        extended_join
            .message(client.full_name(), Command::Join)
            .param(channel_name)
            .param(client.account().unwrap_or("*"))
            .trailing_param(client.real());
        let extended_join = MessageQueueItem::from(extended_join);

        let channel = &self.channels[u(channel_name)];
        for member in channel.members.keys().filter(|m| **m != id) {
            let member = &self.clients[*member];
            if member.cap_enabled.extended_join {
                member.send(extended_join.clone());
            } else {
                member.send(join.clone());
            }
        }

        if let Some(ref away_message) = client.away_message {
            let mut away_notify = Buffer::with_capacity(512);
            away_notify
                .message(client.full_name(), Command::Away)
                .trailing_param(away_message);
            let away_notify = MessageQueueItem::from(away_notify);

            for member in channel.members.keys().filter(|m| **m != id) {
                let member = &self.clients[*member];
                if member.cap_enabled.away_notify {
                    member.send(away_notify.clone());
                }
            }
        }
    }

    pub fn cmd_join(&mut self, mut ctx: CommandContext<'_>, list: data::JoinList<'_>) -> Result {
        let client = &self.clients[ctx.id];

        let mut update_idle = false;
        for (channel_name, key) in list.iter() {
            let ok = self
                .channels
                .get(u(channel_name.get()))
                .map_or(Ok(()), |channel| {
                    Self::check_join(
                        client,
                        channel,
                        channel_name.get(),
                        key.as_ref().map(data::Key::get),
                        &mut ctx,
                    )
                })
                .is_ok();

            if ok {
                let default_chan_mode = &self.default_chan_mode;
                let channel = self
                    .channels
                    .entry(UniCase::new(channel_name.get().to_owned()))
                    .or_insert_with(|| Channel::new(&default_chan_mode));
                channel.add_member(ctx.id);

                ctx.rb.lr_batch_begin();
                self.send_join(ctx.id, &mut ctx.rb, channel_name.get(), client);
                self.send_topic(&mut ctx.rb, channel_name, false);
                self.send_names(ctx.id, &mut ctx.rb, channel_name);
                update_idle = true;
            }
        }
        if update_idle {
            let client = &mut self.clients[ctx.id];
            client.update_idle_time();
        }

        Ok(())
    }

    // KICK

    fn send_kick(
        id: usize,
        rb: &mut ReplyBuffer,
        clients: &super::ClientMap,
        channel: &Channel,
        channel_name: &str,
        kicked_id: usize,
        kicked_nick: &str,
        reason: Option<&str>,
    ) {
        let client = &clients[id];

        let msg = rb
            .message(client.full_name(), Command::Kick)
            .param(channel_name)
            .param(kicked_nick);
        if let Some(reason) = reason {
            msg.trailing_param(reason);
        }

        let mut kick_response = Buffer::with_capacity(512);
        {
            let msg = kick_response
                .message(client.full_name(), Command::Kick)
                .param(channel_name)
                .param(kicked_nick);
            if let Some(reason) = reason {
                msg.trailing_param(reason);
            }
        }
        let msg = MessageQueueItem::from(kick_response);

        for member in channel.members.keys().filter(|m| **m != id) {
            clients[*member].send(msg.clone());
        }
        clients[kicked_id].send(msg);
    }

    pub fn cmd_kick(&mut self, mut ctx: CommandContext<'_>, args: data::req::Kick<'_>) -> Result {
        let channel = match self.channels.get_mut(args.from.u()) {
            Some(channel) => channel,
            None => {
                log::debug!("{}:         no such channel", ctx.id);
                ctx.rb
                    .reply(rpl::ERR_NOSUCHCHANNEL)
                    .param(args.from.get())
                    .trailing_param(lines::NO_SUCH_CHANNEL);
                return Err(());
            }
        };
        let member_modes = find_member(ctx.id, ctx.rb, channel, args.from)?;

        // TODO halfop + check if kicking an op.
        if !member_modes.operator {
            log::debug!("{}:     not operator", ctx.id);
            ctx.rb
                .reply(rpl::ERR_CHANOPRIVSNEEDED)
                .param(args.from.get())
                .trailing_param(lines::CHAN_O_PRIVS_NEEDED);
            return Err(());
        }

        let kicklen = self.kicklen;
        let reason = args
            .reason
            .map(|reason| &reason[..reason.len().min(kicklen)]);

        for kicked_nick in args.who.iter() {
            let kicked_id = find_nick(ctx.id, ctx.rb, &self.clients, &self.nicks, kicked_nick)
                .ok()
                .and_then(|(id, _)| channel.members.remove(&id).map(|_| id));
            if let Some(kicked_id) = kicked_id {
                Self::send_kick(
                    ctx.id,
                    &mut ctx.rb,
                    &self.clients,
                    channel,
                    args.from.get(),
                    kicked_id,
                    kicked_nick.get(),
                    reason,
                );
            } else {
                log::debug!("{}:     {:?} not on channel", ctx.id, kicked_nick.get());
                ctx.rb
                    .reply(rpl::ERR_USERNOTINCHANNEL)
                    .param(kicked_nick.get())
                    .param(args.from.get())
                    .trailing_param(lines::USER_NOT_IN_CHANNEL);
            }
        }

        Ok(())
    }

    // KILL

    pub fn cmd_kill(&mut self, ctx: CommandContext<'_>, args: data::req::Kill<'_>) -> Result {
        let client = &self.clients[ctx.id];
        if !client.operator {
            ctx.rb
                .reply(rpl::ERR_NOPRIVILEDGES)
                .trailing_param(lines::NO_PRIVILEDGES);
            return Err(());
        }
        let (target_id, _) = find_nick(ctx.id, ctx.rb, &self.clients, &self.nicks, args.who)?;
        self.remove_client(target_id, format_args!("Killed: {}", args.reason), "Killed");
        Ok(())
    }

    // LIST

    pub fn cmd_list_all(&self, ctx: CommandContext<'_>) -> Result {
        let client = &self.clients[ctx.id];
        ctx.rb.lr_batch_begin();

        for (name, channel) in &self.channels {
            if channel.secret && !client.operator && !channel.members.contains_key(&ctx.id) {
                continue;
            }
            let msg = ctx.rb.reply(rpl::LIST).param(name.get());
            channel.list_entry(msg);
        }

        ctx.rb
            .reply(rpl::LISTEND)
            .trailing_param(lines::END_OF_LIST);

        Ok(())
    }

    pub fn cmd_list(
        &self,
        ctx: CommandContext<'_>,
        targets: data::List<'_, data::ChannelName<'_>>,
    ) -> Result {
        let client = &self.clients[ctx.id];
        ctx.rb.lr_batch_begin();

        for name in targets.iter() {
            if let Some(channel) = self.channels.get(name.u()) {
                if channel.secret && !client.operator && !channel.members.contains_key(&ctx.id) {
                    continue;
                }
                let msg = ctx.rb.reply(rpl::LIST).param(name.get());
                channel.list_entry(msg);
            }
        }

        ctx.rb
            .reply(rpl::LISTEND)
            .trailing_param(lines::END_OF_LIST);

        Ok(())
    }

    // LUSERS

    pub fn cmd_lusers(&self, mut ctx: CommandContext<'_>) -> Result {
        ctx.rb.lr_batch_begin();
        self.send_lusers(ctx.id, &mut ctx.rb);
        Ok(())
    }

    // MODE

    pub fn cmd_mode_channel_get(
        &self,
        ctx: CommandContext<'_>,
        channel_name: data::ChannelName<'_>,
    ) -> Result {
        let channel = find_channel(ctx.id, ctx.rb, &self.channels, channel_name)?;
        let full_info = channel.members.contains_key(&ctx.id) || self.clients[ctx.id].operator;

        let msg = ctx.rb.reply(rpl::CHANNELMODEIS).param(channel_name.get());
        channel.modes(msg, full_info);

        Ok(())
    }

    pub fn cmd_mode_channel_set(
        &mut self,
        mut ctx: CommandContext<'_>,
        args: data::req::ModeChannelSet<'_>,
    ) -> Result {
        let channel = match self.channels.get_mut(args.channel.u()) {
            Some(channel) => channel,
            None => {
                log::debug!("{}:     no such channel", ctx.id);
                ctx.rb
                    .reply(rpl::ERR_NOSUCHCHANNEL)
                    .param(args.channel.get())
                    .trailing_param(lines::NO_SUCH_CHANNEL);
                return Err(());
            }
        };

        let issuer = &self.clients[ctx.id];
        let issuer_modes = find_member(ctx.id, ctx.rb, channel, args.channel)?;

        if !issuer.operator && !issuer_modes.can_change(args.modes) {
            log::debug!("{}:     not operator", ctx.id);
            ctx.rb
                .reply(rpl::ERR_CHANOPRIVSNEEDED)
                .param(args.channel.get())
                .trailing_param(lines::CHAN_O_PRIVS_NEEDED);
            return Err(());
        }

        let reply_list = |rb: &mut ReplyBuffer, item, end, line: &str, it: util::Masks<'_>| {
            for i in it {
                rb.reply(item).param(args.channel.get()).param(i);
            }
            rb.reply(end).param(args.channel.get()).trailing_param(line);
        };

        ctx.rb.lr_batch_begin();

        let clients = &self.clients;
        let mut applied_modes = String::new();
        let mut applied_modeparams = Vec::new();
        let mut last_applied_value = true;
        for maybe_change in args.modes.iter() {
            match maybe_change {
                Ok(mode::ChannelChange::GetBans) => {
                    reply_list(
                        &mut ctx.rb,
                        rpl::BANLIST,
                        rpl::ENDOFBANLIST,
                        lines::END_OF_BAN_LIST,
                        channel.ban_mask.masks(),
                    );
                }
                Ok(mode::ChannelChange::GetExceptions) => {
                    reply_list(
                        &mut ctx.rb,
                        rpl::EXCEPTLIST,
                        rpl::ENDOFEXCEPTLIST,
                        lines::END_OF_EXCEPT_LIST,
                        channel.exception_mask.masks(),
                    );
                }
                Ok(mode::ChannelChange::GetInvitations) => {
                    reply_list(
                        &mut ctx.rb,
                        rpl::INVITELIST,
                        rpl::ENDOFINVITELIST,
                        lines::END_OF_INVITE_LIST,
                        channel.exception_mask.masks(),
                    );
                }
                Ok(change) => {
                    match channel.apply_mode_change(change, self.keylen, |a| clients[a].nick()) {
                        Ok(true) => {
                            log::debug!("    - Applied {:?}", change);
                            let change_value = change.value();
                            if last_applied_value != change_value || applied_modes.is_empty() {
                                applied_modes.push(if change_value { '+' } else { '-' });
                                last_applied_value = change_value;
                            }
                            applied_modes.push(change.symbol());
                            if let Some(param) = change.param() {
                                applied_modeparams.push(param.to_owned());
                            }
                        }
                        Ok(false) => {}
                        Err(rpl::ERR_USERNOTINCHANNEL) => {
                            let change = change.param().unwrap();
                            ctx.rb
                                .reply(rpl::ERR_USERNOTINCHANNEL)
                                .param(change)
                                .trailing_param(lines::USER_NOT_IN_CHANNEL);
                        }
                        Err(rpl::ERR_KEYSET) => {
                            ctx.rb
                                .reply(rpl::ERR_KEYSET)
                                .param(args.channel.get())
                                .trailing_param(lines::KEY_SET);
                        }
                        Err(_) => {
                            unreachable!();
                        }
                    }
                }
                Err(mode::Error::Unknown(mode, _)) => {
                    let mut msg = ctx.rb.reply(rpl::ERR_UNKNOWNMODE);
                    msg.raw_param().push(mode);
                    msg.trailing_param(lines::UNKNOWN_MODE);
                }
                Err(_) => {}
            }
        }

        if !applied_modes.is_empty() {
            let mut mode_notice = Buffer::with_capacity(128);
            {
                let msg = mode_notice
                    .message(issuer.full_name(), Command::Mode)
                    .param(args.channel.get())
                    .param(&applied_modes);
                applied_modeparams.iter().fold(msg, |msg, mp| msg.param(mp));
            }
            let mode_change = MessageQueueItem::from(mode_notice);

            for member in channel.members.keys().filter(|m| **m != ctx.id) {
                self.clients[*member].send(mode_change.clone());
            }

            let msg = ctx
                .rb
                .message(issuer.full_name(), Command::Mode)
                .param(args.channel.get())
                .param(&applied_modes);
            applied_modeparams.iter().fold(msg, |msg, mp| msg.param(mp));
        }

        Ok(())
    }

    pub fn cmd_mode_user_set(
        &mut self,
        ctx: CommandContext<'_>,
        args: data::req::ModeUserSet<'_>,
    ) -> Result {
        let client = &mut self.clients[ctx.id];

        if u(client.nick()) != args.user.u() {
            log::debug!("{}:     users don't match", ctx.id);
            ctx.rb
                .reply(rpl::ERR_USERSDONTMATCH)
                .param(args.user.get())
                .trailing_param(lines::USERS_DONT_MATCH);
            return Err(());
        }

        let mut applied_modes = String::with_capacity(args.modes.len() + 1);
        for maybe_change in args.modes.iter() {
            match maybe_change {
                Ok(change) => {
                    if client.apply_mode_change(change) {
                        log::debug!("  - Applied {:?}", change);
                        applied_modes.push(if change.value() { '+' } else { '-' });
                        applied_modes.push(change.symbol());
                    }
                }
                Err(mode::Error::Unknown(mode, _)) => {
                    let mut msg = ctx.rb.reply(rpl::ERR_UMODEUNKNOWNFLAG);
                    msg.raw_param().push(mode);
                    msg.trailing_param(lines::UNKNOWN_MODE);
                }
                Err(_) => {}
            }
        }
        if !applied_modes.is_empty() {
            ctx.rb
                .message(client.full_name(), Command::Mode)
                .param(args.user.get())
                .param(&applied_modes);
        }

        Ok(())
    }

    pub fn cmd_mode_user_get(
        &self,
        ctx: CommandContext<'_>,
        nickname: data::Nickname<'_>,
    ) -> Result {
        let client = &self.clients[ctx.id];

        if u(client.nick()) != nickname.u() {
            log::debug!("{}:     users don't match", ctx.id);
            ctx.rb
                .reply(rpl::ERR_USERSDONTMATCH)
                .param(nickname.get())
                .trailing_param(lines::USERS_DONT_MATCH);
            return Err(());
        }

        let msg = ctx.rb.reply(rpl::UMODEIS);
        client.write_modes(msg);
        Ok(())
    }

    // MOTD

    pub fn cmd_motd(&self, mut ctx: CommandContext<'_>) -> Result {
        ctx.rb.lr_batch_begin();
        self.send_motd(&mut ctx.rb);
        Ok(())
    }

    // NAMES

    pub fn cmd_names_all(&self, ctx: CommandContext<'_>) -> Result {
        ctx.rb
            .reply(rpl::ENDOFNAMES)
            .param("*")
            .trailing_param(lines::END_OF_NAMES);
        Ok(())
    }

    pub fn cmd_names(
        &self,
        mut ctx: CommandContext<'_>,
        targets: data::List<'_, data::ChannelName<'_>>,
    ) -> Result {
        ctx.rb.lr_batch_begin();

        for target in targets.iter() {
            self.send_names(ctx.id, &mut ctx.rb, target);
        }

        Ok(())
    }

    // NICK

    pub fn cmd_nick(&mut self, ctx: CommandContext<'_>, nick: data::Nickname<'_>) -> Result {
        let issuer = &mut self.clients[ctx.id];

        if let Some(&id) = self.nicks.get(nick.u()) {
            if id != ctx.id {
                log::debug!("{}:     Already in use", ctx.id);
                ctx.rb
                    .reply(rpl::ERR_NICKNAMEINUSE)
                    .param(nick.get())
                    .trailing_param(lines::NICKNAME_IN_USE);
                return Err(());
            } else if issuer.nick() == nick.get() {
                // Return Ok when the client NICK to the exact same nickname, change the nickname
                // if the client changes its case.
                return Ok(());
            }
        }

        self.nicks.remove(u(issuer.nick()));
        self.nicks
            .insert(UniCase::new(nick.get().to_owned()), ctx.id);

        if !issuer.is_registered() {
            log::debug!("{}:     Is not registered", ctx.id);
            issuer.set_nick(nick.get());
            ReplyBuffer::set_nick(nick.get());
            return Ok(());
        }

        let mut nick_response = Buffer::with_capacity(128);
        nick_response
            .message(issuer.full_name(), Command::Nick)
            .param(nick.get());
        ctx.rb
            .message(issuer.full_name(), Command::Nick)
            .param(nick.get());

        issuer.set_nick(nick.get());
        ReplyBuffer::set_nick(nick.get());

        self.send_notification(ctx.id, nick_response, |_, _| true);

        Ok(())
    }

    // OPER

    pub fn cmd_oper(&mut self, ctx: CommandContext<'_>, args: data::req::Oper<'_>) -> Result {
        if !self
            .opers
            .iter()
            .any(|o| o.name == args.name && o.password == args.password)
        {
            log::debug!("{}:     Password mismatch", ctx.id);
            ctx.rb
                .reply(rpl::ERR_PASSWDMISMATCH)
                .trailing_param(lines::PASSWORD_MISMATCH);
            return Err(());
        }

        let client = &mut self.clients[ctx.id];
        client.operator = true;

        ctx.rb.lr_batch_begin();
        ctx.rb
            .prefixed_message(Command::Mode)
            .param(client.nick())
            .param("+o");
        ctx.rb
            .reply(rpl::YOUREOPER)
            .trailing_param(lines::YOURE_OPER);

        Ok(())
    }

    // PART

    pub fn cmd_part(&mut self, ctx: CommandContext<'_>, args: data::req::Part<'_>) -> Result {
        let issuer = &self.clients[ctx.id];

        let mut res = Ok(());

        for channel_name in args.from.iter() {
            ctx.rb.lr_batch_begin();

            let channel = match self.channels.get_mut(channel_name.u()) {
                Some(channel) => channel,
                None => {
                    log::debug!("{}:     Not on channel", ctx.id);
                    ctx.rb
                        .reply(rpl::ERR_NOTONCHANNEL)
                        .param(channel_name.get())
                        .trailing_param(lines::NOT_ON_CHANNEL);
                    res = Err(());
                    continue;
                }
            };

            if channel.members.remove(&ctx.id).is_none() {
                log::debug!("{}:         not on {:?}", ctx.id, channel_name.get());
                ctx.rb
                    .reply(rpl::ERR_NOTONCHANNEL)
                    .param(channel_name.get())
                    .trailing_param(lines::NOT_ON_CHANNEL);
                res = Err(());
                continue;
            }

            if channel.members.is_empty() {
                self.channels.remove(channel_name.u());
            } else {
                let mut part_notice = Buffer::with_capacity(512);
                {
                    let msg = part_notice
                        .message(issuer.full_name(), Command::Part)
                        .param(channel_name.get());
                    if let Some(reason) = args.reason {
                        msg.trailing_param(reason);
                    }
                }
                let part_notice = MessageQueueItem::from(part_notice);

                for member in channel.members.keys() {
                    self.clients[*member].send(part_notice.clone());
                }
            }

            let msg = ctx
                .rb
                .message(issuer.full_name(), Command::Part)
                .param(channel_name.get());
            if let Some(reason) = args.reason {
                msg.trailing_param(reason);
            }
        }

        res
    }

    pub fn cmd_part_all(&mut self, ctx: CommandContext<'_>) -> Result {
        let clients = &self.clients;
        let issuer = &clients[ctx.id];

        self.channels.retain(|channel_name, channel| {
            if channel.members.remove(&ctx.id).is_none() {
                return true;
            }

            ctx.rb.lr_batch_begin();
            ctx.rb
                .message(issuer.full_name(), Command::Part)
                .param(channel_name.get())
                .trailing_param(lines::PART_ALL);

            let is_not_empty = !channel.members.is_empty();
            if is_not_empty {
                let mut part_notice = Buffer::with_capacity(512);

                part_notice
                    .message(issuer.full_name(), Command::Part)
                    .param(channel_name.get())
                    .trailing_param(lines::PART_ALL);

                let part_notice = MessageQueueItem::from(part_notice);

                for member in channel.members.keys() {
                    clients[*member].send(part_notice.clone());
                }
            }

            is_not_empty
        });

        Ok(())
    }

    // PASS

    pub fn cmd_pass(&mut self, ctx: CommandContext<'_>, password: &str) -> Result {
        if self.password == password {
            self.clients[ctx.id].has_given_password = true;
        }

        Ok(())
    }

    // PING

    pub fn cmd_ping(&mut self, ctx: CommandContext<'_>, payload: &str) -> Result {
        ctx.rb
            .prefixed_message(Command::Pong)
            .trailing_param(payload);
        Ok(())
    }

    // PONG

    pub fn cmd_pong(&mut self, _: CommandContext<'_>, _: &str) -> Result {
        Ok(())
    }

    // QUIT

    pub fn cmd_quit(&mut self, ctx: CommandContext<'_>, reason: Option<&str>) -> Result {
        lines::quit(reason, |quit| {
            self.remove_client(ctx.id, lines::CLOSING_LINK, quit)
        });
        Ok(())
    }

    // REHASH

    pub fn cmd_rehash(&self, ctx: CommandContext<'_>) -> Result {
        if self.clients[ctx.id].operator {
            ctx.rb
                .reply(rpl::REHASHING)
                .param("--")
                .trailing_param(lines::REHASHING);
            self.rehash.notify_one();
            Ok(())
        } else {
            ctx.rb
                .reply(rpl::ERR_NOPRIVILEDGES)
                .trailing_param(lines::NO_PRIVILEDGES);
            Err(())
        }
    }

    // TIME

    pub fn cmd_time(&self, ctx: CommandContext<'_>) -> Result {
        let time = util::time_str();
        ctx.rb
            .reply(rpl::TIME)
            .param(&self.domain)
            .trailing_param(&time);
        Ok(())
    }

    // TOPIC

    pub fn cmd_topic_get(
        &self,
        ctx: CommandContext<'_>,
        channel_name: data::ChannelName<'_>,
    ) -> Result {
        let channel = find_channel(ctx.id, ctx.rb, &self.channels, channel_name)?;

        if channel.secret {
            find_member(ctx.id, ctx.rb, channel, channel_name)?;
        }

        self.send_topic(ctx.rb, channel_name, true);

        Ok(())
    }

    pub fn cmd_topic_set(
        &mut self,
        ctx: CommandContext<'_>,
        args: data::req::TopicSet<'_>,
    ) -> Result {
        let channel = match self.channels.get_mut(args.channel.u()) {
            Some(channel) => channel,
            None => {
                log::debug!("{}:     no such channel", ctx.id);
                ctx.rb
                    .reply(rpl::ERR_NOSUCHCHANNEL)
                    .param(args.channel.get())
                    .trailing_param(lines::NO_SUCH_CHANNEL);
                return Err(());
            }
        };

        let member_modes = find_member(ctx.id, ctx.rb, channel, args.channel)?;

        if !member_modes.operator && channel.topic_restricted {
            log::debug!("{}:     not operator", ctx.id);
            ctx.rb
                .reply(rpl::ERR_CHANOPRIVSNEEDED)
                .param(args.channel.get())
                .trailing_param(lines::CHAN_O_PRIVS_NEEDED);
            return Err(());
        }

        let client = &self.clients[ctx.id];
        let topic = &args.topic[..args.topic.len().min(self.topiclen)];

        channel.topic = if topic.is_empty() {
            None
        } else {
            Some(Topic {
                content: topic.to_owned(),
                who: client.nick().to_owned(),
                time: util::time(),
            })
        };

        let mut topic_notice = Buffer::with_capacity(512);
        topic_notice
            .message(client.full_name(), Command::Topic)
            .param(args.channel.get())
            .trailing_param(topic);
        let topic_notice = MessageQueueItem::from(topic_notice);

        for member in channel.members.keys().filter(|m| **m != ctx.id) {
            self.clients[*member].send(topic_notice.clone());
        }

        ctx.rb
            .message(client.full_name(), Command::Topic)
            .param(args.channel.get())
            .trailing_param(topic);

        Ok(())
    }

    // USER

    pub fn cmd_user(&mut self, ctx: CommandContext<'_>, args: data::req::User<'_>) -> Result {
        let client = &mut self.clients[ctx.id];

        if !self.password.is_empty() && !client.has_given_password {
            log::debug!("{}:     Password mismatch", ctx.id);
            ctx.rb
                .reply(rpl::ERR_PASSWDMISMATCH)
                .trailing_param(lines::PASSWORD_MISMATCH);
            self.remove_client(ctx.id, lines::BAD_PASSWORD, "");
            return Err(());
        }

        client.set_user(&args.username[..args.username.len().min(self.userlen)]);
        client.set_real(&args.realname[..args.realname.len().min(self.namelen)]);

        Ok(())
    }

    // VERSION

    pub fn cmd_version(&self, ctx: CommandContext<'_>) -> Result {
        ctx.rb.lr_batch_begin();
        ctx.rb
            .reply(rpl::VERSION)
            .param(super::SERVER_VERSION)
            .param(&self.domain);
        self.send_i_support(ctx.rb);
        Ok(())
    }

    // WHO

    fn who_line(
        &self,
        rb: &mut ReplyBuffer,
        issuer: &Client,
        target: &Client,
        channel: &str,
        modes: MemberModes,
    ) {
        let mut msg = rb
            .reply(rpl::WHOREPLY)
            .param(channel)
            .param(target.user())
            .param(target.host())
            .param(&self.domain)
            .param(target.nick());

        let param = msg.raw_param();
        param.push(if target.away_message.is_some() {
            'G'
        } else {
            'H'
        });
        if issuer.cap_enabled.multi_prefix {
            modes.all_symbols(param);
        } else if let Some(symbol) = modes.symbol() {
            param.push(symbol);
        }

        msg.fmt_trailing_param(format_args!("0 {}", target.real()));
    }

    fn who_user(
        &self,
        issuer_id: usize,
        rb: &mut ReplyBuffer,
        issuer: &Client,
        target_id: usize,
        filter: data::req::WhoFilter,
    ) {
        let target = &self.clients[target_id];

        if (filter.operator && !target.operator) || !target.is_registered() {
            // Either the filter doesn't match, or target is not registered.
            return;
        }

        // Now ellidri will try to find a channel to display with the user.
        let mut channel_name = None;
        let mut member_modes = Default::default();

        // TODO cache channels a client has joined.
        for (name, channel) in &self.channels {
            let this_member = match channel.members.get(&target_id) {
                Some(member_modes) => *member_modes,
                None => continue,
            };
            if !issuer.operator
                && (target.invisible || channel.secret)
                && !channel.members.contains_key(&issuer_id)
            {
                // issuer cannot see that target is in the channel, because it is not in the
                // channel and either target is invisible (and issuer must have a channel in
                // common to see it), or the channel is secret (thus it must not know its
                // existence).  If issuer is in the channel, then it is fine for ellidri to
                // show it with the line because issuer knows the existence of both the channel
                // and target.
                // IRCops bypass these restrictions, they can see secret channels and invisible
                // users.
                continue;
            }

            channel_name = Some(name.as_ref());
            member_modes = this_member;

            break;
        }
        if !target.invisible || target_id == issuer_id || channel_name.is_some() || issuer.operator
        {
            // The client can see the target.
            let channel_name = channel_name.map_or("*", UniCase::get);
            self.who_line(rb, issuer, target, channel_name, member_modes);
        }
    }

    pub fn cmd_who_all(&self, mut ctx: CommandContext<'_>, filter: data::req::WhoFilter) -> Result {
        let issuer = &self.clients[ctx.id];
        if !issuer.operator {
            ctx.rb
                .reply(rpl::ENDOFWHO)
                .param("*")
                .trailing_param(lines::END_OF_WHO);
            return Err(());
        }

        ctx.rb.lr_batch_begin();

        for target_id in self.nicks.values() {
            self.who_user(ctx.id, &mut ctx.rb, issuer, *target_id, filter);
        }

        ctx.rb
            .reply(rpl::ENDOFWHO)
            .param("*")
            .trailing_param(lines::END_OF_WHO);

        Ok(())
    }

    pub fn cmd_who_channel(
        &self,
        mut ctx: CommandContext<'_>,
        args: data::req::WhoChannel<'_>,
    ) -> Result {
        // Little trick right here.  This isn't a loop, but `Option` implements `Iterator`, so
        // `for` can be used instead of `if let Some(_) = _`!!!  This way `break` (or `continue`,
        // but let's just use `break`) can be used to jump outside the non-loop and avoid some
        // indentations.
        for channel in self.channels.get(args.mask.u()) {
            ctx.rb.lr_batch_begin();

            let issuer = &self.clients[ctx.id];

            let in_channel = channel.members.contains_key(&ctx.id);
            if channel.secret && !in_channel && !issuer.operator {
                break;
            }

            // The client can see the channel.
            for (member, modes) in &channel.members {
                let target = &self.clients[*member];
                if (args.filter.operator && !target.operator)
                    || (!issuer.operator && target.invisible && !in_channel && *member != ctx.id)
                {
                    // Either the target isn't an operator while the client filtered for
                    // operators, or the client cannot see the member.
                    continue;
                }
                self.who_line(&mut ctx.rb, issuer, target, args.mask.get(), *modes);
            }
        }

        ctx.rb
            .reply(rpl::ENDOFWHO)
            .param(args.mask.get())
            .trailing_param(lines::END_OF_WHO);

        Ok(())
    }

    pub fn cmd_who_mask(
        &self,
        mut ctx: CommandContext<'_>,
        args: data::req::WhoMask<'_>,
    ) -> Result {
        let issuer = &self.clients[ctx.id];
        if !issuer.operator {
            ctx.rb
                .reply(rpl::ENDOFWHO)
                .param(args.mask.get())
                .trailing_param(lines::END_OF_WHO);
            return Err(());
        }

        ctx.rb.lr_batch_begin();

        if args.mask.is_channel() {
            self.channels
                .iter()
                .filter(|(name, _)| args.mask.is_match(name.get()))
                .flat_map(|(name, channel)| {
                    channel
                        .members
                        .iter()
                        .map(move |(member, modes)| (name, &self.clients[*member], modes))
                })
                .for_each(|(name, target, modes)| {
                    self.who_line(&mut ctx.rb, issuer, target, name.get(), *modes)
                });
        } else {
            for (nick, id) in &self.nicks {
                if !args.mask.is_match(nick.get()) {
                    continue;
                }
                self.who_user(ctx.id, &mut ctx.rb, issuer, *id, args.filter);
            }
        }

        ctx.rb
            .reply(rpl::ENDOFWHO)
            .param(args.mask.get())
            .trailing_param(lines::END_OF_WHO);

        Ok(())
    }

    pub fn cmd_who_user(
        &self,
        mut ctx: CommandContext<'_>,
        args: data::req::WhoUser<'_>,
    ) -> Result {
        if let Some(target_id) = self.nicks.get(args.mask.u()) {
            ctx.rb.lr_batch_begin();
            self.who_user(
                ctx.id,
                &mut ctx.rb,
                &self.clients[ctx.id],
                *target_id,
                args.filter,
            );
        }

        ctx.rb
            .reply(rpl::ENDOFWHO)
            .param(args.mask.get())
            .trailing_param(lines::END_OF_WHO);

        Ok(())
    }

    // WHOIS

    pub fn cmd_whois(&self, ctx: CommandContext<'_>, nick: data::Nickname<'_>) -> Result {
        let (_, target_client) = find_nick(ctx.id, ctx.rb, &self.clients, &self.nicks, nick)?;

        ctx.rb.lr_batch_begin();
        ctx.rb
            .reply(rpl::WHOISUSER)
            .param(target_client.nick())
            .param(target_client.user())
            .param(target_client.host())
            .param("*")
            .trailing_param(target_client.real());
        ctx.rb
            .reply(rpl::WHOISSERVER)
            .param(target_client.nick())
            .param(&self.domain)
            .trailing_param(&self.org_name);
        ctx.rb
            .reply(rpl::WHOISIDLE)
            .param(target_client.nick())
            .fmt_param(&target_client.idle_time())
            .fmt_param(&target_client.signon_time())
            .trailing_param(lines::WHOIS_IDLE);

        if let Some(away_msg) = target_client.away_message() {
            ctx.rb
                .reply(rpl::AWAY)
                .param(target_client.nick())
                .trailing_param(away_msg);
        }

        ctx.rb
            .reply(rpl::ENDOFWHOIS)
            .param(target_client.nick())
            .trailing_param(lines::END_OF_WHOIS);

        Ok(())
    }

    // PRIVMSG
    // NOTICE
    // TAGMSG
    // TODO message_mask

    fn message_build(
        &self,
        ctx: &mut CommandContext<'_>,
        command: Command,
        target: &str,
        content: Option<&str>,
    ) -> MessageQueueItem {
        let issuer = &self.clients[ctx.id];

        let msgid = util::new_message_id();
        let time = util::time_precise();

        if issuer.cap_enabled.echo_message {
            if issuer.cap_enabled.has_message_tags() {
                let mut msg = ctx
                    .rb
                    .tagged_message(ctx.client_tags)
                    .tag("msgid", Some(&msgid))
                    .tag("time", Some(&time));

                if let Some(account) = issuer.account() {
                    msg = msg.tag("account", Some(account));
                }

                let msg = msg
                    .prefixed_command(issuer.full_name(), command)
                    .param(target);

                if let Some(content) = content {
                    msg.trailing_param(content);
                }
            } else {
                let msg = ctx.rb.message(issuer.full_name(), command).param(target);
                if let Some(content) = content {
                    msg.trailing_param(content);
                }
            }
        }

        let mut buf = Buffer::with_capacity(512);
        let mut tag_len = 0;
        {
            let mut msg = buf
                .tagged_message(ctx.client_tags)
                .tag("msgid", Some(&msgid))
                .tag("time", Some(&time));

            if let Some(account) = issuer.account() {
                msg = msg.tag("account", Some(account));
            }

            let msg = msg
                .save_tag_len(&mut tag_len)
                .prefixed_command(issuer.full_name(), command)
                .param(target);

            if let Some(content) = content {
                msg.trailing_param(content);
            }
        }

        let mut msg = MessageQueueItem::from(buf);
        msg.start = tag_len;
        msg
    }

    pub fn cmd_message_all(
        &self,
        _ctx: CommandContext<'_>,
        _args: data::req::MessageAll<'_>,
    ) -> Result {
        // TODO cmd_message_all
        todo!()
    }

    pub fn cmd_message_channel(
        &mut self,
        mut ctx: CommandContext<'_>,
        args: data::req::MessageChannel<'_>,
    ) -> Result {
        let channel = find_channel(ctx.id, &mut ctx.rb, &self.channels, args.to)?;

        if channel.is_banned(self.clients[ctx.id].full_name()) {
            log::debug!("{}:     banned from channel", ctx.id);
            ctx.rb
                .reply(rpl::ERR_CANNOTSENDTOCHAN)
                .param(args.to.get())
                .trailing_param(lines::BANNED_FROM_CHAN);
            return Err(());
        }
        if !channel.can_talk(ctx.id) {
            log::debug!("{}:     can't send to channel", ctx.id);
            ctx.rb
                .reply(rpl::ERR_CANNOTSENDTOCHAN)
                .param(args.to.get())
                .trailing_param(lines::CANNOT_SEND_TO_CHAN);
            return Err(());
        }

        let msg = self.message_build(&mut ctx, args.command, args.to.get(), args.content);

        for target_id in channel.members.keys() {
            if *target_id == ctx.id {
                continue;
            }
            let target = match self.clients.get(*target_id) {
                Some(target) => target,
                None => continue,
            };
            if !target.cap_enabled.is_capable_of(args.command) {
                continue;
            }
            target.send(msg.clone());
        }

        self.clients.get_mut(ctx.id).unwrap().update_idle_time();

        Ok(())
    }

    pub fn cmd_message_user(
        &mut self,
        mut ctx: CommandContext<'_>,
        args: data::req::MessageUser<'_>,
    ) -> Result {
        let (_, target) = find_nick(ctx.id, &mut ctx.rb, &self.clients, &self.nicks, args.to)?;

        if !target.cap_enabled.is_capable_of(args.command) {
            return Err(());
        }

        let msg = self.message_build(&mut ctx, args.command, args.to.get(), args.content);

        target.send(msg);

        if let Some(ref away_message) = target.away_message {
            ctx.rb
                .reply(rpl::AWAY)
                .param(args.to.get())
                .trailing_param(away_message);
        }

        self.clients.get_mut(ctx.id).unwrap().update_idle_time();

        Ok(())
    }
}
