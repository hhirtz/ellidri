//! Handlers for commands related to the message-tags specification.

use crate::message::Command;
use super::{CommandContext, HandlerResult as Result};

impl super::StateInner {
    pub fn cmd_tagmsg(&mut self, ctx: CommandContext<'_>, target: &str) -> Result {
        self.send_query_or_channel_msg(ctx, Command::TagMsg, target, None)
    }
}
