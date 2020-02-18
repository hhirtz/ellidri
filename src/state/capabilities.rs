//! Handler for the CAP command
//!
//! Link to the capabilities specification: <https://ircv3.net/specs/core/capability-negotiation>

use crate::client::{cap, MessageQueueItem};
use crate::lines;
use crate::message::{Command, rpl, ResponseBuffer};
use std::net;
use super::Result;

impl super::StateInner {
    fn cmd_cap_list(&self, addr: &net::SocketAddr) -> Result {
        log::debug!("{}: CAP LIST", addr);
        let mut response = ResponseBuffer::new();

        let client = &self.clients[addr];
        client.write_enabled_capabilities(&mut response);
        client.send(MessageQueueItem::from(response));
        Ok(())
    }

    fn cmd_cap_ls(&mut self, addr: &net::SocketAddr, version: &str) -> Result {
        log::debug!("{}: CAP LS {}", addr, version);
        let mut response = ResponseBuffer::new();

        let client = self.clients.get_mut(addr).unwrap();
        client.set_cap_version(version);
        client.write_capabilities(&mut response);
        client.send(MessageQueueItem::from(response));
        Ok(())
    }

    fn cmd_cap_req(&mut self, addr: &net::SocketAddr, capabilities: &str) -> Result {
        log::debug!("{}: CAP REQ {}", addr, capabilities);
        let mut response = ResponseBuffer::new();
        let client = self.clients.get_mut(addr).unwrap();

        if !cap::are_supported(capabilities) {
            response.message(Command::Cap).param("NAK").trailing_param(capabilities);
            client.send(MessageQueueItem::from(response));
            return Err(());
        }
        client.update_capabilities(capabilities);
        response.message(Command::Cap).param("ACK").trailing_param(capabilities);
        client.send(MessageQueueItem::from(response));
        Ok(())
    }

    pub fn cmd_cap(&mut self, addr: &net::SocketAddr, params: &[&str]) -> Result {
        match params[0] {
            "END" => Ok(()),
            "LIST" => self.cmd_cap_list(addr),
            "LS" => self.cmd_cap_ls(addr, *params.get(1).unwrap_or(&"")),
            "REQ" => self.cmd_cap_req(addr, *params.get(1).unwrap_or(&"")),
            _ => {
                log::debug!("{}: CAP: Bad command {:?}", addr, params[0]);
                self.send_reply(addr, rpl::ERR_INVALIDCAPCMD, &[params[0], lines::UNKNOWN_COMMAND]);
                Err(())
            }
        }
    }
}
