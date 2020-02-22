//! Handler for the CAP command
//!
//! Link to the capabilities specification: <https://ircv3.net/specs/core/capability-negotiation>

use crate::client::cap;
use crate::lines;
use crate::message::{Command, ReplyBuffer, rpl};
use std::net;
use super::HandlerResult as Result;

impl super::StateInner {
    fn cmd_cap_list(&self, addr: &net::SocketAddr, rb: &mut ReplyBuffer) -> Result {
        let client = &self.clients[addr];
        client.write_enabled_capabilities(rb);
        Ok(())
    }

    fn cmd_cap_ls(&mut self, addr: &net::SocketAddr, rb: &mut ReplyBuffer, version: &str) -> Result {
        let client = self.clients.get_mut(addr).unwrap();
        client.set_cap_version(version);
        client.write_capabilities(rb);
        Ok(())
    }

    fn cmd_cap_req(&mut self, addr: &net::SocketAddr, rb: &mut ReplyBuffer,
                   capabilities: &str) -> Result
    {
        let client = self.clients.get_mut(addr).unwrap();
        if !cap::are_supported(capabilities) {
            rb.reply(Command::Cap).param("NAK").trailing_param(capabilities);
            return Err(());
        }
        client.update_capabilities(capabilities);
        rb.reply(Command::Cap).param("ACK").trailing_param(capabilities);
        Ok(())
    }

    pub fn cmd_cap(&mut self, addr: &net::SocketAddr, rb: &mut ReplyBuffer,
                   params: &[&str]) -> Result
    {
        match params[0] {
            "END" => Ok(()),
            "LIST" => self.cmd_cap_list(addr, rb),
            "LS" => self.cmd_cap_ls(addr, rb, *params.get(1).unwrap_or(&"")),
            "REQ" => self.cmd_cap_req(addr, rb, *params.get(1).unwrap_or(&"")),
            _ => {
                log::debug!("{}:     Bad command", addr);
                rb.reply(rpl::ERR_INVALIDCAPCMD)
                    .param(params[0])
                    .trailing_param(lines::UNKNOWN_COMMAND);
                Err(())
            }
        }
    }
}
