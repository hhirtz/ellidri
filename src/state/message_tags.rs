//! Handlers for commands related to the message-tags specification.

use crate::client::MessageQueueItem;
use crate::lines;
use crate::message::{Buffer, Command, rpl};
use crate::util::time_precise;
use super::{CommandContext, HandlerResult as Result, find_channel, find_nick};

impl super::StateInner {
    pub fn cmd_tagmsg(&mut self, ctx: CommandContext<'_>, target: &str) -> Result {
        if super::is_valid_channel_name(target) {
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
                .prefixed_command(client.full_name(), Command::TagMsg)
                .param(target);
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
                .prefixed_command(client.full_name(), Command::TagMsg)
                .param(target);
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
}
