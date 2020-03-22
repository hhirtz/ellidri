//! Handlers for commands related to the message-tags specification.

use crate::client::MessageQueueItem;
use crate::lines;
use crate::message::{Buffer, Command, rpl};
use crate::util::{new_message_id, time_precise};
use super::{CommandContext, HandlerResult as Result, find_channel, find_nick};

impl super::StateInner {
    pub fn cmd_tagmsg(&mut self, ctx: CommandContext<'_>, target: &str) -> Result {
        if !self.clients[ctx.id].capabilities.has_message_tags() {
            log::debug!("{}:     hasn't negociated message tags", ctx.id);
            return Err(())
        }
        if super::is_valid_channel_name(target, self.channellen) {
            let channel = find_channel(ctx.id, ctx.rb, &self.channels, target)?;
            if !channel.can_talk(ctx.id) {
                log::debug!("{}:     can't send to channel", ctx.id);
                ctx.rb.reply(rpl::ERR_CANNOTSENDTOCHAN)
                    .param(target)
                    .trailing_param(lines::CANNOT_SEND_TO_CHAN);
                return Err(());
            }

            let mut response = Buffer::new();

            let client = &self.clients[ctx.id];
            let mut client_tags_len = 0;
            response.tagged_message(ctx.client_tags)
                .tag("time", Some(&time_precise()))
                .tag("msgid", Some(&new_message_id()))
                .save_tags_len(&mut client_tags_len)
                .prefixed_command(client.full_name(), Command::TagMsg)
                .param(target);
            let mut msg = MessageQueueItem::from(response);
            msg.start = client_tags_len;
            channel.members.keys()
                .filter(|a| {
                    self.clients[**a].capabilities.has_message_tags()
                        && (client.capabilities.echo_message || **a != ctx.id)
                })
                .for_each(|member| self.send(*member, msg.clone()));
        } else {
            let (_, target_client) = find_nick(ctx.id, ctx.rb, &self.clients, &self.nicks, target)?;
            if !target_client.capabilities.has_message_tags() {
                return Err(());
            }
            let client = &self.clients[ctx.id];
            let mut client_tags_len = 0;
            let mut response = Buffer::new();
            response.tagged_message(ctx.client_tags)
                .tag("time", Some(&time_precise()))
                .tag("msgid", Some(&new_message_id()))
                .save_tags_len(&mut client_tags_len)
                .prefixed_command(client.full_name(), Command::TagMsg)
                .param(target);
            let mut msg = MessageQueueItem::from(response);
            msg.start = client_tags_len;
            if client.capabilities.echo_message {
                client.send(msg.clone());
            }
            target_client.send(msg);

            if let Some(away_msg) = target_client.away_message() {
                ctx.rb.reply(rpl::AWAY).param(target).trailing_param(away_msg);
            }
        }
        self.clients.get_mut(ctx.id).unwrap().update_idle_time();

        Ok(())
    }
}
