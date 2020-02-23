//! Handler for the CAP command
//!
//! Link to the capabilities specification: <https://ircv3.net/specs/core/capability-negotiation>

use crate::client::cap;
use crate::lines;
use crate::message::{Command, rpl};
use super::{CommandContext, HandlerResult as Result};

impl super::StateInner {
    fn cmd_cap_list(&self, ctx: CommandContext<'_>) -> Result {
        let client = &self.clients[ctx.addr];
        client.write_enabled_capabilities(ctx.rb);
        Ok(())
    }

    fn cmd_cap_ls(&mut self, ctx: CommandContext<'_>, version: &str) -> Result {
        let client = self.clients.get_mut(ctx.addr).unwrap();
        client.set_cap_version(version);
        client.write_capabilities(ctx.rb);
        Ok(())
    }

    fn cmd_cap_req(&mut self, ctx: CommandContext<'_>, capabilities: &str) -> Result {
        let client = self.clients.get_mut(ctx.addr).unwrap();
        if !cap::are_supported(capabilities) {
            ctx.rb.reply(Command::Cap).param("NAK").trailing_param(capabilities);
            return Err(());
        }
        client.update_capabilities(capabilities);
        ctx.rb.reply(Command::Cap).param("ACK").trailing_param(capabilities);
        Ok(())
    }

    pub fn cmd_cap(&mut self, ctx: CommandContext<'_>, params: &[&str]) -> Result {
        match params[0] {
            "END" => Ok(()),
            "LIST" => self.cmd_cap_list(ctx),
            "LS" => self.cmd_cap_ls(ctx, *params.get(1).unwrap_or(&"")),
            "REQ" => self.cmd_cap_req(ctx, *params.get(1).unwrap_or(&"")),
            _ => {
                log::debug!("{}:     Bad command", ctx.addr);
                ctx.rb.reply(rpl::ERR_INVALIDCAPCMD)
                    .param(params[0])
                    .trailing_param(lines::UNKNOWN_COMMAND);
                Err(())
            }
        }
    }
}
