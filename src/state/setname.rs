//! Handlers for commands related to the message-tags specification.

use crate::lines;
use crate::client::MessageQueueItem;
use crate::message::{Buffer, Command};
use std::collections::HashSet;
use super::{CommandContext, HandlerResult as Result};

impl super::StateInner {
    pub fn cmd_setname(&mut self, ctx: CommandContext<'_>, real: &str) -> Result {
        if real.is_empty() || self.namelen < real.len() {
            log::debug!("{}:     Bad realname", ctx.id);
            ctx.rb.message("", "FAIL")
                .param("SETNAME")
                .param("INVALID_REALNAME")
                .trailing_param(lines::INVALID_REALNAME);
            return Err(());
        }

        let client = self.clients.get_mut(ctx.id).unwrap();
        let mut real_response = Buffer::new();

        real_response.message(client.full_name(), Command::SetName).param(real);
        let msg = MessageQueueItem::from(real_response);

        client.set_real(real);

        let mut noticed = self.channels.values()
            .filter(|channel| channel.members.contains_key(&ctx.id))
            .flat_map(|channel| channel.members.keys())
            .collect::<HashSet<_>>();
        noticed.insert(&ctx.id);
        for addr in noticed {
            let c = &self.clients[*addr];
            if c.capabilities.setname {
                c.send(msg.clone());
            }
        }

        Ok(())
    }
}
