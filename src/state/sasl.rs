//! Handlers for commands related to the message-tags specification.

use crate::{auth, lines};
use crate::message::{Buffer, rpl};
use super::{CommandContext, HandlerResult as Result};

impl super::StateInner {
    fn continue_auth(&mut self, id: usize, ctx: CommandContext<'_>) -> Result {
        let client = &mut self.clients[id];

        let decoded = match client.auth_buffer_decode() {
            Ok(decoded) => decoded,
            Err(err) => {
                log::debug!("{}:     bad base64: {}", ctx.id, err);
                ctx.rb.reply(rpl::ERR_SASLFAIL).trailing_param(lines::SASL_FAILED);
                client.auth_reset();
                return Err(());
            }
        };

        let mut challenge = Vec::new();
        match self.auth_provider.next_challenge(id, &decoded, &mut challenge) {
            Ok(Some(user)) => {
                log::debug!("{}:     now authenticated", ctx.id);

                lines::logged_in(ctx.rb.reply(rpl::LOGGEDIN)
                    .param(client.nick())
                    .param(client.full_name())
                    .param(&user), &user);
                ctx.rb.reply(rpl::SASLSUCCESS).trailing_param(lines::SASL_SUCCESSFUL);

                let mut account_notify = Buffer::new();
                account_notify.message(client.full_name(), "ACCOUNT").param(&user);

                client.log_in(user);
                client.auth_reset();

                self.send_notification(ctx.id, account_notify, |id, client| {
                    id != ctx.id && client.capabilities().account_notify
                });

                Ok(())
            }
            Ok(None) => {
                auth::write_buffer(ctx.rb, &challenge);
                Ok(())
            }
            Err(err) => {
                log::debug!("{}:     bad response: {:?}", ctx.id, err);
                ctx.rb.reply(rpl::ERR_SASLFAIL).trailing_param(lines::SASL_FAILED);
                client.auth_reset();
                Err(())
            }
        }
    }


    pub fn cmd_authenticate(&mut self, ctx: CommandContext<'_>, payload: &str) -> Result {
        let client = self.clients.get_mut(ctx.id).unwrap();
        if client.identity().is_some() {
            log::debug!("{}:     is already logged in", ctx.id);
            ctx.rb.reply(rpl::ERR_SASLALREADY).trailing_param(lines::SASL_ALREADY);
            client.auth_reset();
            return Err(());
        }
        if payload == "*" && client.auth_id().is_some() {
            ctx.rb.reply(rpl::ERR_SASLABORTED).trailing_param(lines::SASL_ABORTED);
            client.auth_reset();
            return Ok(());
        }
        if let Some(id) = client.auth_id() {
            match client.auth_buffer_push(payload) {
                Ok(true) => self.continue_auth(id, ctx),
                Ok(false) => Ok(()),
                Err(()) => {
                    ctx.rb.reply(rpl::ERR_SASLTOOLONG).trailing_param(lines::SASL_TOO_LONG);
                    log::debug!("{}:     sasl too long", ctx.id);
                    Err(())
                }
            }
        } else {
            let mut challenge = Vec::new();
            let id = match self.auth_provider.start_auth(payload, &mut challenge) {
                Ok(id) => id,
                Err(auth::Error::ProviderUnavailable) => {
                    log::debug!("{}:     sasl unavailable for {:?}", ctx.id, payload);
                    ctx.rb.reply(rpl::ERR_SASLFAIL).trailing_param(lines::SASL_FAILED);
                    return Err(());
                }
                Err(_) => {
                    log::debug!("{}:     unknown mechanism {:?}", ctx.id, payload);
                    let mut msg = ctx.rb.reply(rpl::SASLMECHS);
                    self.auth_provider.write_mechanisms(msg.raw_param());
                    msg.trailing_param(lines::SASL_MECHS);
                    return Err(());
                }
            };
            auth::write_buffer(ctx.rb, &challenge);
            client.auth_set_id(id);
            Ok(())
        }
    }
}
