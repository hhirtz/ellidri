//! Handlers for the client-to-server interface defined by IRCv3.
//!
//! <https://ircv3.net/irc/>

use super::{CommandContext, HandlerResult as Result};
use crate::{data, lines};
use ellidri_tokens::{Buffer, Command};

/// Handler for the CAP command.
///
/// Link to the capabilities specification: <https://ircv3.net/specs/core/capability-negotiation>
impl super::StateInner {
    pub fn cmd_cap_list(&self, ctx: CommandContext<'_>) -> Result {
        let client = &self.clients[ctx.id];

        let mut msg = ctx.rb.reply(Command::Cap).param("LIST");
        client.cap_enabled.write(msg.raw_trailing_param());

        Ok(())
    }

    pub fn cmd_cap_ls(&mut self, ctx: CommandContext<'_>, version: data::cap::Version) -> Result {
        let client = &mut self.clients[ctx.id];

        if client.cap_version < version {
            client.cap_version = version;
        }

        let mut msg = ctx.rb.reply(Command::Cap).param("LS");

        let trailing = msg.raw_trailing_param();
        trailing.push_str(data::cap::ls_common());

        Ok(())
    }

    pub fn cmd_cap_req(&mut self, ctx: CommandContext<'_>, req: data::cap::Diff) -> Result {
        let client = &mut self.clients[ctx.id];

        client.cap_enabled.update(req);

        let mut msg = ctx.rb.reply(Command::Cap).param("ACK");
        req.write(msg.raw_trailing_param());

        Ok(())
    }

    pub fn cmd_cap_end(&self, _: CommandContext<'_>) -> Result {
        Ok(())
    }
}

/// Handlers for commands related to SASL specifications.
impl super::StateInner {
    pub fn cmd_authenticate(
        &mut self,
        _ctx: CommandContext<'_>,
        _payload: data::auth::Payload<'_>,
    ) -> Result {
        todo!()
    }
}

/// Handlers for commands related to the setname specification.
impl super::StateInner {
    pub fn cmd_setname(&mut self, ctx: CommandContext<'_>, realname: &str) -> Result {
        let client = &mut self.clients[ctx.id];

        if realname.is_empty() || self.namelen < realname.len() {
            log::debug!("{}:     Bad realname", ctx.id);
            ctx.rb
                .message("", "FAIL")
                .param("SETNAME")
                .param("INVALID_REALNAME")
                .trailing_param(lines::INVALID_REALNAME);
            return Err(());
        }

        let mut real_response = Buffer::new();
        real_response
            .message(client.full_name(), Command::SetName)
            .param(realname);
        ctx.rb
            .message(client.full_name(), Command::SetName)
            .param(realname);
        client.set_real(realname);

        self.send_notification(ctx.id, real_response, |_, client| {
            client.cap_enabled.setname
        });

        Ok(())
    }
}
