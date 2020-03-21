//! Handlers for commands related to the message-tags specification.

use crate::{auth, lines};
use crate::message::rpl;
use super::{CommandContext, HandlerResult as Result};

impl super::StateInner {
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
                Ok(true) => {
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
                            let msg = ctx.rb.reply(rpl::LOGGEDIN)
                                .param(client.nick())
                                .param(client.full_name())
                                .param(&user);
                            lines::logged_in(msg, &user);
                            ctx.rb.reply(rpl::SASLSUCCESS).trailing_param(lines::SASL_SUCCESSFUL);
                            client.log_in(user);
                            client.auth_reset();
                        }
                        Ok(None) => {
                            auth::write_buffer(ctx.rb, &challenge);
                        }
                        Err(err) => {
                            log::debug!("{}:     bad response: {:?}", ctx.id, err);
                            ctx.rb.reply(rpl::ERR_SASLFAIL).trailing_param(lines::SASL_FAILED);
                            client.auth_reset();
                            return Err(());
                        }
                    }
                }
                Ok(false) => {}
                Err(()) => {
                    ctx.rb.reply(rpl::ERR_SASLTOOLONG).trailing_param(lines::SASL_TOO_LONG);
                    log::debug!("{}:     sasl too long", ctx.id);
                    return Err(());
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
        }
        Ok(())
    }
}
