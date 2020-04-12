//! Handlers for messages defined in IRCv3 extensions.

use crate::{auth, lines};
use crate::client::cap;
use ellidri_tokens::{Buffer, Command, rpl};
use super::{CommandContext, HandlerResult as Result};

/// Handlers for commands related to the message-tags specification.
impl super::StateInner {
    pub fn cmd_tagmsg(&mut self, ctx: CommandContext<'_>, target: &str) -> Result {
        self.send_query_or_channel_msg(ctx, Command::TagMsg, target, None)
    }
}

/// Handler for the CAP command.
///
/// Link to the capabilities specification: <https://ircv3.net/specs/core/capability-negotiation>
impl super::StateInner {
    fn cmd_cap_list(&self, ctx: CommandContext<'_>) -> Result {
        let client = &self.clients[ctx.id];
        ctx.rb.message("", Command::Cap, 0, |msg| {
            client.capabilities().write_enabled(msg.param(client.nick()));
        });
        Ok(())
    }

    fn cmd_cap_ls(&mut self, ctx: CommandContext<'_>, version: &str) -> Result {
        let id = ctx.id;
        self.clients[id].set_cap_version(version);

        ctx.rb.message("", Command::Cap, 0, |mut msg| {
            msg = msg.param(self.clients[id].nick()).param("LS");
            let mut trailing = msg.raw_trailing_param();

            trailing.push_str(cap::ls_common());
            if self.auth_provider.is_available() {
                trailing.push_str(" sasl");
                if self.clients[id].capabilities().v302 {
                    trailing.push('=');
                    self.auth_provider.write_mechanisms(&mut trailing);
                }
            }
        });

        Ok(())
    }

    fn cmd_cap_req(&mut self, ctx: CommandContext<'_>, capabilities: &str) -> Result {
        let client = &mut self.clients[ctx.id];
        if !cap::are_supported(capabilities) {
            ctx.rb.message("", Command::Cap, 0, |msg| {
                msg.param(client.nick()).param("NAK").trailing_param(capabilities);
            });
            return Err(());
        }
        client.update_capabilities(capabilities);
        ctx.rb.message("", Command::Cap, 0, |msg| {
            msg.param(client.nick()).param("ACK").trailing_param(capabilities);
        });
        Ok(())
    }

    pub fn cmd_cap(&mut self, ctx: CommandContext<'_>, params: &[&str]) -> Result {
        match params[0] {
            "END" => Ok(()),
            "LIST" => self.cmd_cap_list(ctx),
            "LS" => self.cmd_cap_ls(ctx, *params.get(1).unwrap_or(&"")),
            "REQ" => self.cmd_cap_req(ctx, *params.get(1).unwrap_or(&"")),
            _ => {
                log::debug!("{}:     Bad command", ctx.id);
                ctx.rb.reply(rpl::ERR_INVALIDCAPCMD, 0, |msg| {
                    msg.param(params[0]).trailing_param(lines::UNKNOWN_COMMAND);
                });
                Err(())
            }
        }
    }
}

/// Handlers for commands related to SASL specifications.
impl super::StateInner {
    fn continue_auth(&mut self, id: usize, ctx: CommandContext<'_>) -> Result {
        let client = &mut self.clients[id];

        let decoded = match client.auth_buffer_decode() {
            Ok(decoded) => decoded,
            Err(err) => {
                log::debug!("{}:     bad base64: {}", ctx.id, err);
                ctx.rb.reply(rpl::ERR_SASLFAIL, 0, |msg| {
                    msg.trailing_param(lines::SASL_FAILED);
                });
                client.auth_reset();
                return Err(());
            }
        };

        let mut challenge = Vec::new();
        match self.auth_provider.next_challenge(id, &decoded, &mut challenge) {
            Ok(Some(user)) => {
                log::debug!("{}:     now authenticated", ctx.id);

                ctx.rb.reply(rpl::LOGGEDIN, 0, |msg| {
                    let msg = msg.param(client.nick()).param(client.full_name()).param(&user);
                    lines::logged_in(msg, &user);
                });
                ctx.rb.reply(rpl::SASLSUCCESS, 0, |msg| {
                    msg.trailing_param(lines::SASL_SUCCESSFUL);
                });

                if client.capabilities().account_notify {
                    ctx.rb.message(client.full_name(), "ACCOUNT", 0, |msg| {
                        msg.param(&user);
                    });
                }

                let mut account_notify = Buffer::new();
                account_notify.message(client.full_name(), "ACCOUNT").param(&user);

                client.log_in(user);
                client.auth_reset();

                self.send_notification(ctx.id, account_notify, |_, client| {
                    client.capabilities().account_notify
                });

                Ok(())
            }
            Ok(None) => {
                log::debug!("{}:     continuing authentication", ctx.id);
                ctx.rb.send_auth_buffer(challenge);
                Ok(())
            }
            Err(err) => {
                log::debug!("{}:     bad response: {:?}", ctx.id, err);
                ctx.rb.reply(rpl::ERR_SASLFAIL, 0, |msg| {
                    msg.trailing_param(lines::SASL_FAILED);
                });
                client.auth_reset();
                Err(())
            }
        }
    }

    pub fn cmd_authenticate(&mut self, ctx: CommandContext<'_>, payload: &str) -> Result {
        let client = &mut self.clients[ctx.id];
        if client.account().is_some() {
            log::debug!("{}:     is already logged in", ctx.id);
            ctx.rb.reply(rpl::ERR_SASLALREADY, 0, |msg| {
                msg.trailing_param(lines::SASL_ALREADY);
            });
            client.auth_reset();
            return Err(());
        }
        if payload == "*" && client.auth_id().is_some() {
            ctx.rb.reply(rpl::ERR_SASLABORTED, 0, |msg| {
                msg.trailing_param(lines::SASL_ABORTED);
            });
            client.auth_reset();
            return Ok(());
        }
        if let Some(id) = client.auth_id() {
            match client.auth_buffer_push(payload) {
                Ok(true) => self.continue_auth(id, ctx),
                Ok(false) => Ok(()),
                Err(()) => {
                    ctx.rb.reply(rpl::ERR_SASLTOOLONG, 0, |msg| {
                        msg.trailing_param(lines::SASL_TOO_LONG);
                    });
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
                    ctx.rb.reply(rpl::ERR_SASLFAIL, 0, |msg| {
                        msg.trailing_param(lines::SASL_FAILED);
                    });
                    return Err(());
                }
                Err(_) => {
                    log::debug!("{}:     unknown mechanism {:?}", ctx.id, payload);
                    ctx.rb.reply(rpl::SASLMECHS, 0, |mut msg| {
                        self.auth_provider.write_mechanisms(msg.raw_param());
                        msg.trailing_param(lines::SASL_MECHS);
                    });
                    return Err(());
                }
            };
            ctx.rb.send_auth_buffer(challenge);
            client.auth_set_id(id);
            Ok(())
        }
    }
}

/// Handlers for commands related to the setname specification.
impl super::StateInner {
    pub fn cmd_setname(&mut self, ctx: CommandContext<'_>, real: &str) -> Result {
        let client = self.clients.get_mut(ctx.id).unwrap();
        if real.is_empty() || self.namelen < real.len() {
            log::debug!("{}:     Bad realname", ctx.id);
            ctx.rb.message("", "FAIL", 0, |msg| {
                msg.param("SETNAME")
                    .param("INVALID_REALNAME")
                    .trailing_param(lines::INVALID_REALNAME);
            });
            return Err(());
        }

        let mut real_response = Buffer::new();
        real_response.message(client.full_name(), Command::SetName).param(real);
        ctx.rb.message(client.full_name(), Command::SetName, 0, |msg| {
            msg.param(real);
        });
        client.set_real(real);
        self.send_notification(ctx.id, real_response, |_, _| true);

        Ok(())
    }
}
