//! Handler for the CAP command
//!
//! Link to the capabilities specification: <https://ircv3.net/specs/core/capability-negotiation>

use crate::client::cap;
use crate::lines;
use crate::message::{Buffer, Command, ReplyBuffer, rpl};
use std::net;
use super::HandlerResult as Result;

impl super::StateInner {
    fn cmd_cap_list(&self, addr: &net::SocketAddr) -> Result {
        let mut response = Buffer::new();

        let client = &self.clients[addr];
        client.write_enabled_capabilities(&mut response);
        client.send(response);
        Ok(())
    }

    fn cmd_cap_ls(&mut self, addr: &net::SocketAddr, version: &str) -> Result {
        let mut response = Buffer::new();

        let client = self.clients.get_mut(addr).unwrap();
        client.set_cap_version(version);
        client.write_capabilities(&mut response);
        client.send(response);
        Ok(())
    }

    fn cmd_cap_req(&mut self, addr: &net::SocketAddr, capabilities: &str) -> Result {
        let mut response = Buffer::new();
        let client = self.clients.get_mut(addr).unwrap();

        if !cap::are_supported(capabilities) {
            response.message(Command::Cap).param("NAK").trailing_param(capabilities);
            client.send(response);
            return Err(());
        }
        client.update_capabilities(capabilities);
        response.message(Command::Cap).param("ACK").trailing_param(capabilities);
        client.send(response);
        Ok(())
    }

    pub fn cmd_cap(&mut self, addr: &net::SocketAddr, rb: &mut ReplyBuffer,
                   params: &[&str]) -> Result
    {
        log::debug!("{}: CAP {:?}", addr, params);
        match params[0] {
            "END" => Ok(()),
            "LIST" => self.cmd_cap_list(addr),
            "LS" => self.cmd_cap_ls(addr, *params.get(1).unwrap_or(&"")),
            "REQ" => self.cmd_cap_req(addr, *params.get(1).unwrap_or(&"")),
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
