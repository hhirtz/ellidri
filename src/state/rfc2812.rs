//! Handlers for the RFC 2812 client-to-server interface.
//!
//! <https://tools.ietf.org/html/rfc2812.html>

use crate::channel::{Channel, Topic};
use crate::client::{Client, MessageQueueItem, ReplyBuffer};
use crate::{lines, util};
use ellidri_tokens::{Buffer, Command, mode, rpl};
use ellidri_unicase::{u, UniCase};
use std::iter;
use super::{CommandContext, HandlerResult as Result, find_channel, find_member, find_nick};

// Command handlers
impl super::StateInner {
    // ADMIN

    pub fn cmd_admin(&self, ctx: CommandContext<'_>) -> Result {
        ctx.rb.start_lr_batch();
        ctx.rb.reply(rpl::ADMINME, 1+self.domain.len() + 2+lines::ADMIN_ME.len(), |msg| {
            msg.param(&self.domain).trailing_param(lines::ADMIN_ME);
        });
        ctx.rb.reply(rpl::ADMINLOC1, 2+self.org_location.len(), |msg| {
            msg.trailing_param(&self.org_location);
        });
        ctx.rb.reply(rpl::ADMINLOC2, 2+self.org_name.len(), |msg| {
            msg.trailing_param(&self.org_name);
        });
        ctx.rb.reply(rpl::ADMINMAIL, 2+self.org_mail.len(), |msg| {
            msg.trailing_param(&self.org_mail);
        });

        Ok(())
    }

    // AWAY

    pub fn cmd_away(&mut self, ctx: CommandContext<'_>, reason: &str) -> Result {
        let client = &mut self.clients[ctx.id];
        if reason.is_empty() {
            client.away_message = None;
            ctx.rb.reply(rpl::UNAWAY, 2+lines::UN_AWAY.len(), |msg| {
                msg.trailing_param(lines::UN_AWAY);
            });
        } else {
            let away_message = reason[..reason.len().min(self.awaylen)].to_owned();
            client.away_message = Some(away_message);
            ctx.rb.reply(rpl::NOWAWAY, 2+lines::NOW_AWAY.len(), |msg| {
                msg.trailing_param(lines::NOW_AWAY);
            });
        }
        let capacity = 1+client.full_name().len() + 1+4 +
            client.away_message.as_ref().map_or(0, |s| 2+s.len()) + 2;
        let mut away_notify = Buffer::with_capacity(capacity);
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
            ctx.rb.reply(rpl::INFO, 2+line.len(), |msg| {
                msg.trailing_param(line);
            });
        }
        ctx.rb.reply(rpl::ENDOFINFO, 2+lines::END_OF_INFO.len(), |msg| {
            msg.trailing_param(lines::END_OF_INFO);
        });

        Ok(())
    }

    // INVITE

    pub fn cmd_invite(&mut self, ctx: CommandContext<'_>, nick: &str, target: &str) -> Result {
        let (invited, invited_cli) = find_nick(ctx.id, ctx.rb, &self.clients, &self.nicks, nick)?;
        let channel = match self.channels.get_mut(u(target)) {
            Some(channel) => channel,
            None => {
                log::debug!("{}:     no such channel", ctx.id);
                let capacity = 1+target.len() + 2+lines::NO_SUCH_CHANNEL.len();
                ctx.rb.reply(rpl::ERR_NOSUCHCHANNEL, capacity, |msg| {
                    msg.param(target).trailing_param(lines::NO_SUCH_CHANNEL);
                });
                return Err(());
            },
        };
        if !channel.can_invite(ctx.id) {
            log::debug!("{}:     not operator", ctx.id);
            let capacity = 1+target.len() + 2+lines::CHAN_O_PRIVS_NEEDED.len();
            ctx.rb.reply(rpl::ERR_CHANOPRIVSNEEDED, capacity, |msg| {
                msg.param(target).trailing_param(lines::CHAN_O_PRIVS_NEEDED);
            });
            return Err(());
        }
        if channel.members.contains_key(&invited) {
            log::debug!("{}:     user on channel", ctx.id);
            let capacity = 1+nick.len() + 1+target.len() + 2+lines::USER_ON_CHANNEL.len();
            ctx.rb.reply(rpl::ERR_USERONCHANNEL, capacity, |msg| {
                msg.param(nick).param(target).trailing_param(lines::USER_ON_CHANNEL);
            });
            return Err(());
        }

        if !channel.invites.insert(invited) {
            return Err(());
        }

        ctx.rb.start_lr_batch();
        ctx.rb.reply(rpl::INVITING, 1+nick.len() + 1+target.len(), |msg| {
            msg.param(nick).param(target);
        });
        if let Some(away_msg) = invited_cli.away_message() {
            ctx.rb.reply(rpl::AWAY, 1+nick.len() + 2+away_msg.len(), |msg| {
                msg.param(nick).trailing_param(away_msg);
            });
        }

        let full_name = self.clients[ctx.id].full_name();
        let capacity = 1+full_name.len() + 1+6 + 1+nick.len() + 1+target.len();
        let mut invite = Buffer::with_capacity(capacity);
        invite.message(full_name, Command::Invite)
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
            ctx.rb.reply(rpl::ERR_BADCHANKEY, 1+target.len() + 2+lines::BAD_CHAN_KEY.len(), |msg| {
                msg.param(target).trailing_param(lines::BAD_CHAN_KEY);
            });
            return Err(());
        }
        if channel.user_limit.map_or(false, |user_limit| user_limit <= channel.members.len()) {
            log::debug!("{}:     user limit reached", ctx.id);
            let capacity = 1+target.len() + 2+lines::CHANNEL_IS_FULL.len();
            ctx.rb.reply(rpl::ERR_CHANNELISFULL, capacity, |msg| {
                msg.param(target).trailing_param(lines::CHANNEL_IS_FULL);
            });
            return Err(());
        }
        if !channel.is_invited(ctx.id, client.nick()) {
            log::debug!("{}:     not invited", ctx.id);
            let capacity = 1+target.len() + 2+lines::INVITE_ONLY_CHAN.len();
            ctx.rb.reply(rpl::ERR_INVITEONLYCHAN, capacity, |msg| {
                msg.param(target).trailing_param(lines::INVITE_ONLY_CHAN);
            });
            return Err(());
        }
        if channel.is_banned(client.nick()) || channel.is_banned(client.full_name()) {
            log::debug!("{}:     Banned", ctx.id);
            let capacity = 1+target.len() + 2+lines::BANNED_FROM_CHAN.len();
            ctx.rb.reply(rpl::ERR_BANNEDFROMCHAN, capacity, |msg| {
                msg.param(target).trailing_param(lines::BANNED_FROM_CHAN);
            });
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
        let capacity = 1+client.full_name().len() + 1+4 + 1+target.len();
        let mut join = Buffer::with_capacity(capacity);
        join.message(client.full_name(), Command::Join).param(target);
        let join = MessageQueueItem::from(join);

        let capacity = 1+client.full_name().len() + 1+4 + 1+target.len() +
            1+client.account().map_or(1, str::len) + 2+client.real().len();
        let mut extended_join = Buffer::with_capacity(capacity);
        extended_join.message(client.full_name(), Command::Join)
            .param(target)
            .param(client.account().unwrap_or("*"))
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
        rb.message(client.full_name(), Command::Join, 1+target.len(), |msg| {
            msg.param(target);
        });

        if let Some(ref away_message) = client.away_message {
            let capacity = 1+client.full_name().len() + 1+4 + 1+away_message.len();
            let mut away_notify = Buffer::with_capacity(capacity);
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
                let capacity = 1+target.len() + 2+lines::NO_SUCH_CHANNEL.len();
                ctx.rb.reply(rpl::ERR_NOSUCHCHANNEL, capacity, |msg| {
                    msg.param(target).trailing_param(lines::NO_SUCH_CHANNEL);
                });
                return Err(());
            }
            let ok = self.channels.get(u(target))
                .map_or(Ok(()), |channel| {
                    super::StateInner::check_join(client, channel, target, key, &mut ctx)
                })
                .is_ok();

            if ok {
                let default_chan_mode = &self.default_chan_mode;
                let channel = self.channels.entry(UniCase::new(target.to_owned()))
                    .or_insert_with(|| Channel::new(&default_chan_mode));
                channel.add_member(ctx.id);

                ctx.rb.start_lr_batch();
                self.send_join(ctx.id, &mut ctx.rb, target, client);
                self.send_topic(&mut ctx.rb, target, false);
                self.send_names(ctx.id, &mut ctx.rb, target);
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

    pub fn cmd_kick(&mut self, ctx: CommandContext<'_>, target: &str,
                    nick: &str, reason: &str) -> Result
    {
        let channel = find_channel(ctx.id, ctx.rb, &self.channels, target)?;
        let member_modes = find_member(ctx.id, ctx.rb, channel, target)?;
        if !member_modes.operator {
            log::debug!("{}:     not operator", ctx.id);
            let capacity = 1+target.len() + 2+lines::CHAN_O_PRIVS_NEEDED.len();
            ctx.rb.reply(rpl::ERR_CHANOPRIVSNEEDED, capacity, |msg| {
                msg.param(target).trailing_param(lines::CHAN_O_PRIVS_NEEDED);
            });
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
                let capacity = 1+nick.len() + 1+target.len() + 2+lines::USER_NOT_IN_CHANNEL.len();
                ctx.rb.reply(rpl::ERR_USERNOTINCHANNEL, capacity, |msg| {
                    msg.param(nick).param(target).trailing_param(lines::USER_NOT_IN_CHANNEL);
                });
                return Err(());
            }
        };

        let reason = &reason[..reason.len().min(self.kicklen)];
        let client = &self.clients[ctx.id];
        let capacity = 1+target.len() + 1+nick.len() +
            if reason.is_empty() {0} else {2+reason.len()};
        let full_capacity = capacity + 1+client.full_name().len() + 1+4 + 2;
        let mut kick_response = Buffer::with_capacity(full_capacity);
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
        ctx.rb.message(client.full_name(), Command::Kick, capacity, |mut msg| {
            msg = msg.param(target).param(nick);
            if !reason.is_empty() {
                msg.trailing_param(reason);
            }
        });
        channel.members.remove(&kicked_addrs);

        Ok(())
    }

    // KILL

    pub fn cmd_kill(&mut self, ctx: CommandContext<'_>, nick: &str, reason: &str) -> Result {
        if !self.clients[ctx.id].operator {
            ctx.rb.reply(rpl::ERR_NOPRIVILEDGES, 2+lines::NO_PRIVILEDGES.len(), |msg| {
                msg.trailing_param(lines::NO_PRIVILEDGES);
            });
            return Err(());
        }
        let (target_id, _) = find_nick(ctx.id, ctx.rb, &self.clients, &self.nicks, nick)?;
        let target_client = self.clients.remove(target_id);
        self.remove_client(target_id, target_client, reason, Some(reason));

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
                ctx.rb.reply(rpl::LIST, 1+name.get().len() + 2+self.topiclen, |mut msg| {
                    msg = msg.param(name.get());
                    channel.list_entry(msg);
                });
            }
        } else {
            for name in targets.split(',') {
                if let Some(channel) = self.channels.get(u(name)) {
                    if channel.secret && !client.operator && !channel.members.contains_key(&ctx.id) {
                        continue;
                    }
                    ctx.rb.reply(rpl::LIST, 1+name.len() + 2+self.topiclen, |mut msg| {
                        msg = msg.param(name);
                        channel.list_entry(msg);
                    });
                }
            }
        }

        ctx.rb.reply(rpl::LISTEND, 2+lines::END_OF_LIST.len(), |msg| {
            msg.trailing_param(lines::END_OF_LIST);
        });

        Ok(())
    }

    // LUSERS

    pub fn cmd_lusers(&self, mut ctx: CommandContext<'_>) -> Result {
        ctx.rb.start_lr_batch();
        self.send_lusers(&mut ctx.rb);
        Ok(())
    }

    // MODE

    fn cmd_mode_chan_get(&self, ctx: CommandContext<'_>, target: &str) -> Result {
        let channel = find_channel(ctx.id, ctx.rb, &self.channels, target)?;
        let id = ctx.id;
        ctx.rb.reply(rpl::CHANNELMODEIS, 400, |mut msg| {
            msg = msg.param(target);
            let full_info = channel.members.contains_key(&id) || self.clients[id].operator;
            channel.modes(msg, full_info);
        });

        Ok(())
    }

    fn cmd_mode_chan_set(&mut self, mut ctx: CommandContext<'_>, target: &str,
                         modes: &str, mode_params: &[&str]) -> Result
    {
        let client = &self.clients[ctx.id];
        let channel = match self.channels.get_mut(u(target)) {
            Some(channel) => channel,
            None => {
                log::debug!("{}:     no such channel", ctx.id);
                let capacity = 1+target.len() + 2+lines::NO_SUCH_CHANNEL.len();
                ctx.rb.reply(rpl::ERR_NOSUCHCHANNEL, capacity, |msg| {
                    msg.param(target).trailing_param(lines::NO_SUCH_CHANNEL);
                });
                return Err(());
            }
        };
        let member_modes = find_member(ctx.id, ctx.rb, channel, target)?;
        if !client.operator && !member_modes.can_change(modes, mode_params) {
            log::debug!("{}:     not operator", ctx.id);
            let capacity = 1+target.len() + 2+lines::CHAN_O_PRIVS_NEEDED.len();
            ctx.rb.reply(rpl::ERR_CHANOPRIVSNEEDED, capacity, |msg| {
                msg.param(target).trailing_param(lines::CHAN_O_PRIVS_NEEDED);
            });
            return Err(());
        }

        let reply_list = |rb: &mut ReplyBuffer, item, end, line: &str, it: &[String]| {
            for i in it {
                rb.reply(item, 1+target.len() + 1+i.len(), |msg| {
                    msg.param(target).param(i);
                });
            }
            rb.reply(end, 1+target.len() + 2+line.len(), |msg| {
                msg.param(target).trailing_param(line);
            });
        };

        let clients = &self.clients;
        let mut applied_modes = String::new();
        let mut applied_modeparams = Vec::new();
        let mut last_applied_value = true;
        for maybe_change in mode::channel_query(modes, mode_params) { match maybe_change {
            Ok(mode::ChannelChange::GetBans) => {
                reply_list(&mut ctx.rb, rpl::BANLIST, rpl::ENDOFBANLIST, lines::END_OF_BAN_LIST,
                           channel.ban_mask.patterns());
            }
            Ok(mode::ChannelChange::GetExceptions) => {
                reply_list(&mut ctx.rb, rpl::EXCEPTLIST, rpl::ENDOFEXCEPTLIST, lines::END_OF_EXCEPT_LIST,
                           channel.exception_mask.patterns());
            }
            Ok(mode::ChannelChange::GetInvitations) => {
                reply_list(&mut ctx.rb, rpl::INVITELIST, rpl::ENDOFINVITELIST, lines::END_OF_INVITE_LIST,
                           channel.exception_mask.patterns());
            }
            Ok(change) => match channel.apply_mode_change(change, |a| clients[a].nick()) {
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
                    let change = change.param().unwrap();
                    let capacity = 1+change.len() + 2+lines::USER_NOT_IN_CHANNEL.len();
                    ctx.rb.reply(rpl::ERR_USERNOTINCHANNEL, capacity, |msg| {
                        msg.param(change)
                            .trailing_param(lines::USER_NOT_IN_CHANNEL);
                    });
                }
                Err(rpl::ERR_KEYSET) => {
                    ctx.rb.reply(rpl::ERR_KEYSET, 1+target.len() + 2+lines::KEY_SET.len(), |msg| {
                        msg.param(target).trailing_param(lines::KEY_SET);
                    });
                }
                Err(_) => { unreachable!(); }
            }
            Err(mode::Error::Unknown(mode, _)) => {
                ctx.rb.reply(rpl::ERR_UNKNOWNMODE, 1+1 + 2+lines::UNKNOWN_MODE.len(), |mut msg| {
                    msg.raw_param().push(mode);
                    msg.trailing_param(lines::UNKNOWN_MODE);
                });
            },
            Err(_) => {},
        } }

        if !applied_modes.is_empty() {
            ctx.rb.start_lr_batch();
            let client = &self.clients[ctx.id];
            // For now, this isn't possible to use the correct capacity due to a weird rustc bug?
            //let capacity = 1+target.len() + 1+applied_modes.len() +
            //    applied_modeparams.iter().map(|mp| 1 + mp.len()).sum();
            //let full_capacity = capacity + 1+client.full_name().len() + 1+4 + 2;
            let capacity = 0;
            let full_capacity = 0;
            let mut mode_change = Buffer::with_capacity(full_capacity);
            {
                let msg = mode_change.message(client.full_name(), Command::Mode)
                    .param(target)
                    .param(&applied_modes);
                applied_modeparams.iter().fold(msg, |msg, mp| msg.param(mp));
            }
            let mode_change = MessageQueueItem::from(mode_change);
            for member in channel.members.keys().filter(|m| **m != ctx.id) {
                self.clients[*member].send(mode_change.clone());
            }
            ctx.rb.message(client.full_name(), Command::Mode, capacity, |mut msg| {
                msg = msg.param(target).param(&applied_modes);
                applied_modeparams.iter().fold(msg, |msg, mp| msg.param(mp));
            });
        }

        Ok(())
    }

    fn cmd_mode_user_check(&self, ctx: &mut CommandContext<'_>, nick: &str) -> Result {
        if !self.clients[ctx.id].nick().eq_ignore_ascii_case(nick) {
            log::debug!("{}:     users don't match", ctx.id);
            let capacity = 1+nick.len() + 2+lines::USERS_DONT_MATCH.len();
            ctx.rb.reply(rpl::ERR_USERSDONTMATCH, capacity, |msg| {
                msg.param(nick).trailing_param(lines::USERS_DONT_MATCH);
            });
            return Err(());
        }
        Ok(())
    }

    fn cmd_mode_user_set(&mut self, ctx: CommandContext<'_>, target: &str, modes: &str) -> Result {
        let client = &mut self.clients[ctx.id];

        let mut applied_modes = String::with_capacity(modes.len());
        for maybe_change in mode::user_query(modes) { match maybe_change {
            Ok(change) => if client.apply_mode_change(change) {
                log::debug!("  - Applied {:?}", change);
                applied_modes.push(if change.value() {'+'} else {'-'});
                applied_modes.push(change.symbol());
            }
            Err(mode::Error::Unknown(mode, _)) => {
                let capacity = 1+1 + 1+lines::UNKNOWN_MODE.len();
                ctx.rb.reply(rpl::ERR_UMODEUNKNOWNFLAG, capacity, |mut msg| {
                    msg.raw_param().push(mode);
                    msg.trailing_param(lines::UNKNOWN_MODE);
                });
            }
            Err(_) => {}
        } }
        if !applied_modes.is_empty() {
            let capacity = 1+target.len() + 1+applied_modes.len();
            ctx.rb.message(client.full_name(), Command::Mode, capacity, |msg| {
                msg.param(target).param(&applied_modes);
            });
        }

        Ok(())
    }

    fn cmd_mode_user_get(&self, ctx: CommandContext<'_>) -> Result {
        let client = &self.clients[ctx.id];
        ctx.rb.reply(rpl::UMODEIS, 10, |msg| {
            client.write_modes(msg);
        });
        Ok(())
    }

    pub fn cmd_mode(&mut self, mut ctx: CommandContext<'_>, target: &str,
                    modes: &str, mode_params: &[&str]) -> Result
    {
        if super::is_valid_channel_name(target, self.channellen) {
            if modes.is_empty() {
                self.cmd_mode_chan_get(ctx, target)
            } else {
                self.cmd_mode_chan_set(ctx, target, modes, mode_params)
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

    pub fn cmd_motd(&self, mut ctx: CommandContext<'_>) -> Result {
        ctx.rb.start_lr_batch();
        self.send_motd(&mut ctx.rb);
        Ok(())
    }

    // NAMES

    pub fn cmd_names(&self, mut ctx: CommandContext<'_>, targets: &str) -> Result {
        if targets.is_empty() || targets == "*" {
            ctx.rb.reply(rpl::ENDOFNAMES, 1+1 + 2+lines::END_OF_NAMES.len(), |msg| {
                msg.param("*").trailing_param(lines::END_OF_NAMES);
            });
        } else {
            ctx.rb.start_lr_batch();
            for target in targets.split(',') {
                self.send_names(ctx.id, &mut ctx.rb, target);
            }
        }

        Ok(())
    }

    // NICK

    pub fn cmd_nick(&mut self, ctx: CommandContext<'_>, nick: &str) -> Result {
        if !super::is_valid_nickname(nick, self.nicklen) || super::is_restricted_nickname(nick) {
            log::debug!("{}:     Bad nickname", ctx.id);
            let capacity = 1+nick.len() + 2+lines::ERRONEOUS_NICKNAME.len();
            ctx.rb.reply(rpl::ERR_ERRONEUSNICKNAME, capacity, |msg| {
                msg.param(nick).trailing_param(lines::ERRONEOUS_NICKNAME);
            });
            return Err(());
        }
        let client = &mut self.clients[ctx.id];
        if let Some(&id) = self.nicks.get(u(nick)) {
            if id != ctx.id {
                log::debug!("{}:     Already in use", ctx.id);
                let capacity = 1+nick.len() + 2+lines::NICKNAME_IN_USE.len();
                ctx.rb.reply(rpl::ERR_NICKNAMEINUSE, capacity, |msg| {
                    msg.param(nick).trailing_param(lines::NICKNAME_IN_USE);
                });
                return Err(());
            } else if client.nick() == nick {
                return Ok(())
            }
        }

        self.nicks.remove(u(client.nick()));
        self.nicks.insert(UniCase::new(nick.to_owned()), ctx.id);

        if !client.is_registered() {
            log::debug!("{}:     Is not registered", ctx.id);
            client.set_nick(nick);
            return Ok(());
        }

        let capacity = 1+nick.len();
        let full_capacity = capacity + 1+client.full_name().len() + 1+4 + 2;
        let mut nick_response = Buffer::with_capacity(full_capacity);
        nick_response.message(client.full_name(), Command::Nick).param(nick);
        ctx.rb.message(client.full_name(), Command::Nick, capacity, |msg| {
            msg.param(nick);
        });
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
            ctx.rb.reply(rpl::ERR_PASSWDMISMATCH, 2+lines::PASSWORD_MISMATCH.len(), |msg| {
                msg.trailing_param(lines::PASSWORD_MISMATCH);
            });
            return Err(());
        }

        let client = &mut self.clients[ctx.id];
        client.operator = true;
        ctx.rb.start_lr_batch();
        ctx.rb.prefixed_message(Command::Mode, 1+client.nick().len() + 1+2, |msg| {
            msg.param(client.nick()).param("+o");
        });
        ctx.rb.reply(rpl::YOUREOPER, 2+lines::YOURE_OPER.len(), |msg| {
            msg.trailing_param(lines::YOURE_OPER);
        });

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
                    let capacity = 1+target.len() + 2+lines::NOT_ON_CHANNEL.len();
                    ctx.rb.reply(rpl::ERR_NOTONCHANNEL, capacity, |msg| {
                        msg.param(target).trailing_param(lines::NOT_ON_CHANNEL);
                    });
                    res = Err(());
                    continue;
                }
            };
            find_member(ctx.id, ctx.rb, channel, target)?;

            if channel.members.is_empty() {
                self.channels.remove(u(target));
            } else {
                channel.members.remove(&ctx.id);

                let mut part_notice = Buffer::new();
                let capacity = 1+client.full_name().len() + 1+4 + 1+target.len() + 2;
                if reason.is_empty() {
                    part_notice.reserve(capacity);
                    part_notice.message(client.full_name(), Command::Part).param(target);
                } else {
                    part_notice.reserve(capacity + 2+reason.len());
                    part_notice.message(client.full_name(), Command::Part)
                        .param(target)
                        .trailing_param(reason);
                }
                let part_notice = MessageQueueItem::from(part_notice);
                for member in channel.members.keys() {
                    self.clients[*member].send(part_notice.clone());
                }
            }

            let capacity = 1+target.len() + if reason.is_empty() {0} else {2+reason.len()};
            ctx.rb.message(client.full_name(), Command::Part, capacity, |mut msg| {
                msg = msg.param(target);
                if !reason.is_empty() {
                    msg.trailing_param(reason);
                }
            });
        }

        res
    }

    // PASS

    pub fn cmd_pass(&mut self, ctx: CommandContext<'_>, password: &str) -> Result {
        if self.password.as_ref().map_or(false, |p| p == password) {
            self.clients[ctx.id].has_given_password = true;
        }

        Ok(())
    }

    // PING

    pub fn cmd_ping(&mut self, ctx: CommandContext<'_>, payload: &str) -> Result {
        ctx.rb.prefixed_message(Command::Pong, 2+payload.len(), |msg| {
            msg.trailing_param(payload);
        });
        Ok(())
    }

    // PRIVMSG

    pub fn cmd_privmsg(&mut self, ctx: CommandContext<'_>, target: &str, content: &str) -> Result {
        self.send_query_or_channel_msg(ctx, Command::PrivMsg, target, Some(content))
    }

    // QUIT

    pub fn cmd_quit(&mut self, ctx: CommandContext<'_>, reason: &str) -> Result {
        let client = self.clients.remove(ctx.id);
        let reason = if reason.is_empty() {None} else {Some(reason)};
        self.remove_client(ctx.id, client, lines::CLOSING_LINK, reason);
        Ok(())
    }

    // REHASH

    pub fn cmd_rehash(&self, ctx: CommandContext<'_>) -> Result {
        if self.clients[ctx.id].operator {
            ctx.rb.reply(rpl::REHASHING, 1+2 + 2+lines::REHASHING.len(), |msg| {
                msg.param("--").trailing_param(lines::REHASHING);
            });
            self.rehash.notify();
            Ok(())
        } else {
            ctx.rb.reply(rpl::ERR_NOPRIVILEDGES, 2+lines::NO_PRIVILEDGES.len(), |msg| {
                msg.trailing_param(lines::NO_PRIVILEDGES);
            });
            Err(())
        }
    }

    // TIME

    pub fn cmd_time(&self, ctx: CommandContext<'_>) -> Result {
        let time = util::time_str();
        ctx.rb.reply(rpl::TIME, 1+self.domain.len() + 2+time.len(), |msg| {
            msg.param(&self.domain).trailing_param(&time);
        });
        Ok(())
    }

    // TOPIC

    fn cmd_topic_set(&mut self, ctx: CommandContext<'_>, target: &str, topic: &str) -> Result {
        let channel = match self.channels.get_mut(u(target)) {
            Some(channel) => channel,
            None => {
                log::debug!("{}:     no such channel", ctx.id);
                let capacity = 1+target.len() + 2+lines::NO_SUCH_CHANNEL.len();
                ctx.rb.reply(rpl::ERR_NOSUCHCHANNEL, capacity, |msg| {
                    msg.param(target).trailing_param(lines::NO_SUCH_CHANNEL);
                });
                return Err(());
            }
        };
        let member_modes = find_member(ctx.id, ctx.rb, channel, target)?;
        if !member_modes.operator && channel.topic_restricted {
            log::debug!("{}:     not operator", ctx.id);
            let capacity = 1+target.len() + 2+lines::CHAN_O_PRIVS_NEEDED.len();
            ctx.rb.reply(rpl::ERR_CHANOPRIVSNEEDED, capacity, |msg| {
                msg.param(target).trailing_param(lines::CHAN_O_PRIVS_NEEDED);
            });
            return Err(());
        }

        let client = &self.clients[ctx.id];
        let topic = &topic[..topic.len().min(self.topiclen)];
        channel.topic = if topic.is_empty() {
            None
        } else {
            Some(Topic {
                content: topic.to_owned(),
                who: client.nick().to_owned(),
                time: util::time(),
            })
        };

        let capacity = 1+target.len() + 2+topic.len();
        let full_capacity = capacity + 1+client.full_name().len() + 1+5 + 2;
        let mut topic_notice = Buffer::with_capacity(full_capacity);
        topic_notice.message(client.full_name(), Command::Topic)
            .param(target)
            .trailing_param(topic);
        let topic_notice = MessageQueueItem::from(topic_notice);
        for member in channel.members.keys().filter(|m| **m != ctx.id) {
            self.clients[*member].send(topic_notice.clone());
        }
        ctx.rb.message(client.full_name(), Command::Topic, capacity, |msg| {
            msg.param(target).trailing_param(topic);
        });

        Ok(())
    }

    fn cmd_topic_get(&self, ctx: CommandContext<'_>, target: &str) -> Result {
        let channel = find_channel(ctx.id, ctx.rb, &self.channels, target)?;
        if channel.secret {
            find_member(ctx.id, ctx.rb, channel, target)?;
        }
        self.send_topic(ctx.rb, target, true);
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
        let client = &mut self.clients[ctx.id];
        if self.password.is_some() && !client.has_given_password {
            log::debug!("{}:     Password mismatch", ctx.id);
            ctx.rb.reply(rpl::ERR_PASSWDMISMATCH, 2+lines::PASSWORD_MISMATCH.len(), |msg| {
                msg.trailing_param(lines::PASSWORD_MISMATCH);
            });
            let client = self.clients.remove(ctx.id);
            self.remove_client(ctx.id, client, lines::CLOSING_LINK, None);
            return Err(());
        }
        client.set_user(&user[..user.len().min(self.userlen)]);
        client.set_real(&real[..real.len().min(self.namelen)]);

        Ok(())
    }

    // VERSION

    pub fn cmd_version(&self, ctx: CommandContext<'_>) -> Result {
        ctx.rb.start_lr_batch();
        let capacity = 1+crate::server_version!().len() + 1+self.domain.len();
        ctx.rb.reply(rpl::VERSION, capacity, |msg| {
            msg.param(crate::server_version!()).param(&self.domain);
        });
        self.send_i_support(ctx.rb);
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
                    let capacity = 1+mask.len() + 1+c.user().len() + 1+c.host().len() +
                        1+self.domain.len() + 1+c.nick().len() + 1+6 + 2+2+c.real().len();
                    ctx.rb.reply(rpl::WHOREPLY, capacity, |mut msg| {
                        msg = msg.param(mask)
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
                        let trailing = msg.raw_trailing_param();
                        trailing.push_str("0 ");
                        trailing.push_str(c.real());
                    });
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
                    let channel_name = channel_name.map_or("*", UniCase::get);
                    let capacity = 1+mask.len() + 1+c.user().len() + 1+c.host().len() +
                        1+self.domain.len() + 1+c.nick().len() + 1+6 + 2+c.real().len();
                    ctx.rb.reply(rpl::WHOREPLY, capacity, |mut msg| {
                        msg = msg.param(channel_name)
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
                        let trailing = msg.raw_trailing_param();
                        trailing.push_str("0 ");
                        trailing.push_str(c.real());
                    });
                }
            }
        }
        ctx.rb.reply(rpl::ENDOFWHO, 1+mask.len() + 2+lines::END_OF_WHO.len(), |msg| {
            msg.param(mask).trailing_param(lines::END_OF_WHO);
        });

        Ok(())
    }

    // WHOIS

    pub fn cmd_whois(&self, ctx: CommandContext<'_>, nick: &str) -> Result {
        let (_, target_client) = find_nick(ctx.id, ctx.rb, &self.clients, &self.nicks, nick)?;

        // TODO whois channels
        ctx.rb.start_lr_batch();
        let capacity = 1+target_client.nick().len() + 1+target_client.user().len() +
            1+target_client.host().len() + 1+1 + 2+target_client.real().len();
        ctx.rb.reply(rpl::WHOISUSER, capacity, |msg| {
            msg.param(target_client.nick())
                .param(target_client.user())
                .param(target_client.host())
                .param("*")
                .trailing_param(target_client.real());
        });
        let capacity = 1+target_client.nick().len() + 1+self.domain.len() + 2+self.org_name.len();
        ctx.rb.reply(rpl::WHOISSERVER, capacity, |msg| {
            msg.param(target_client.nick()).param(&self.domain).trailing_param(&self.org_name);
        });
        let capacity = 1+target_client.nick().len() + 1+10 + 1+10 + 2+lines::WHOIS_IDLE.len();
        ctx.rb.reply(rpl::WHOISIDLE, capacity, |msg| {
            msg.param(target_client.nick())
                .fmt_param(target_client.idle_time())
                .fmt_param(target_client.signon_time())
                .trailing_param(lines::WHOIS_IDLE);
        });
        if let Some(away_msg) = target_client.away_message() {
            ctx.rb.reply(rpl::AWAY, 1+target_client.nick().len() + 2+away_msg.len(), |msg| {
                msg.param(target_client.nick()).trailing_param(away_msg);
            });
        }
        let capacity = 1+target_client.nick().len() + 2+lines::END_OF_WHOIS.len();
        ctx.rb.reply(rpl::ENDOFWHOIS, capacity, |msg| {
            msg.param(target_client.nick()).trailing_param(lines::END_OF_WHOIS);
        });

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use super::super::test;
    use ellidri_tokens::Command;

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
            (Some("c1!~X@127.0.0.1"), Ok(Command::Join), &["#channel"]),
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
            (Some("c1!~X@127.0.0.1"), Ok(Command::Invite), &["c2", "#channel"]),
        ]);

        // c1 c2 c3 all registered - c1 on channel - c2 invited
        test::handle_message(&mut state, c2, "JOIN #channel");
        buf.clear();
        test::collect(&mut buf, &mut q1);
        test::collect(&mut buf, &mut q2);
        test::collect(&mut buf, &mut q3);
        test::assert_msgs(&buf, &[
            (Some("c2!~X@127.0.0.1"), Ok(Command::Join), &["#channel"]),
            (Some("c2!~X@127.0.0.1"), Ok(Command::Join), &["#channel"]),
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
            (Some("c1!~X@127.0.0.1"), Ok(Command::Mode), &["#channel", "+i"]),
            (Some("c1!~X@127.0.0.1"), Ok(Command::Mode), &["#channel", "+i"]),
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
            (Some("c1!~X@127.0.0.1"), Ok(Command::Invite), &["c3", "#channel"]),
        ]);

        // channel is invite-only - c1 on channel - c2 on channel - c3 is invited
        test::handle_message(&mut state, c3, "JOIN #channel");
        buf.clear();
        test::collect(&mut buf, &mut q1);
        test::collect(&mut buf, &mut q2);
        test::collect(&mut buf, &mut q3);
        test::assert_msgs(&buf, &[
            (Some("c3!~X@127.0.0.1"), Ok(Command::Join), &["#channel"]),
            (Some("c3!~X@127.0.0.1"), Ok(Command::Join), &["#channel"]),
            (Some("c3!~X@127.0.0.1"), Ok(Command::Join), &["#channel"]),
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
            (Some("c3!~X@127.0.0.1"), Ok(Command::Part), &["#channel"]),
            (Some("c3!~X@127.0.0.1"), Ok(Command::Part), &["#channel"]),
            (Some("c3!~X@127.0.0.1"), Ok(Command::Part), &["#channel"]),
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
            (Some("c1!~X@127.0.0.1"), Ok(Command::Join), &["#channel"]),
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
            (Some("c1!~X@127.0.0.1"), Ok(Command::Mode), &["#channel", "+k", "key"]),
        ]);
        assert_eq!(state.channels[u("#channel")].key.as_ref().unwrap(), "key");

        // c2 all registered - c1 on #channel+kkey
        test::handle_message(&mut state, c2, "JOIN #channel,#home");
        buf.clear();
        test::collect(&mut buf, &mut q1);
        test::collect(&mut buf, &mut q2);
        test::assert_msgs(&buf, &[
            (Some(test::DOMAIN), Err(rpl::ERR_BADCHANKEY), &["c2", "#channel", lines::BAD_CHAN_KEY]),
            (Some("c2!~X@127.0.0.1"), Ok(Command::Join), &["#home"]),
            (Some(test::DOMAIN), Err(rpl::NAMREPLY), &["c2", "=", "#home", "@c2"]),
            (Some(test::DOMAIN), Err(rpl::ENDOFNAMES), &["c2", "#home", lines::END_OF_NAMES]),
        ]);
        assert!(state.channels.get(u("#home")).is_some());
        assert!(state.channels[u("#home")].members.contains_key(&c2));
        // TODO continue
    }
}  // mod tests
