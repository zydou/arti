//! Implementation for a SOCKS client handshake.

use super::framework::{HandshakeImpl, ImplNextStep};
use super::{NO_AUTHENTICATION, USERNAME_PASSWORD};
use crate::msg::{SocksAddr, SocksAuth, SocksReply, SocksRequest, SocksStatus, SocksVersion};
use crate::{Error, Result};

use tor_bytes::{Reader, Writer};
use tor_error::{internal, into_internal};

use derive_deftly::Deftly;

use std::net::{IpAddr, Ipv4Addr};

/// The client (initiator) side of a SOCKS handshake.
///
/// Create you have one of these with [`SocksClientHandshake::new()`],
/// and then use [`Handshake::handshake`](crate::Handshake::handshake) to drive it.
#[derive(Clone, Debug, Deftly)]
#[derive_deftly(Handshake)]
pub struct SocksClientHandshake {
    /// The request that we are currently trying to negotiate with the proxy.
    request: SocksRequest,
    /// Our current state in negotiating that request.
    state: State,
    /// If present, the return message that we received from the proxy.
    reply: Option<SocksReply>,
}

/// An internal state for a `SocksClientHandshake`.
#[derive(Clone, Debug)]
enum State {
    /// We have sent nothing yet.
    Initial,
    /// We have sent a SOCKS4 request, and are waiting for a response.
    Socks4Wait,
    /// We have sent a SOCKS5 init message, and are waiting to hear what kind
    /// of authentication to use.
    Socks5AuthWait,
    /// We have sent a SOCKS5 username/password, and are waiting to hear whether
    /// it's accepted.
    Socks5UsernameWait,
    /// We have sent a SOCKS5 request, and are waiting for a response.
    Socks5Wait,
    /// We have received the final reply from the proxy.  This reply may be
    /// successful or unsuccessful, depending on the value of
    /// `SocksClientHandshake::status`.
    Done,
    /// The handshake has failed and no further progress can be made.
    Failed,
}

impl SocksClientHandshake {
    /// Construct a new [`SocksClientHandshake`] that will attempt to negotiate
    /// with a peer using `request`.
    pub fn new(request: SocksRequest) -> Self {
        SocksClientHandshake {
            request,
            state: State::Initial,
            reply: None,
        }
    }

    /// Consume this handshake's state; if it finished successfully,
    /// return the [`SocksReply`] that we got from the proxy..
    pub fn into_reply(self) -> Option<SocksReply> {
        self.reply
    }
}

// XXXX move this so we can rejoin the two impl blocks
impl HandshakeImpl for SocksClientHandshake {
    fn handshake_impl(&mut self, input: &mut Reader<'_>) -> Result<ImplNextStep> {
        use State::*;
        match self.state {
            Initial => match self.request.version() {
                SocksVersion::V4 => self.send_v4(),
                SocksVersion::V5 => self.send_v5_initial(),
            },
            Socks4Wait => self.handle_v4(input),
            Socks5AuthWait => self.handle_v5_auth(input),
            Socks5UsernameWait => self.handle_v5_username_ack(input),
            Socks5Wait => self.handle_v5_final(input),
            Done => Err(Error::AlreadyFinished(internal!(
                "called handshake() after handshaking succeeded"
            ))),
            Failed => Err(Error::AlreadyFinished(internal!(
                "called handshake() after handshaking failed"
            ))),
        }
    }
}

impl SocksClientHandshake {
    /// Send the client side of the socks 4 handshake.
    fn send_v4(&mut self) -> Result<ImplNextStep> {
        let mut msg = Vec::new();

        msg.write_u8(4);
        msg.write_u8(self.request.command().into());
        msg.write_u16(self.request.port());

        let use_v4a = match self.request.addr() {
            SocksAddr::Ip(IpAddr::V4(ipv4)) => {
                msg.write_u32((*ipv4).into());
                false
            }
            _ => {
                msg.write_u32(1);
                true
            }
        };

        match self.request.auth() {
            SocksAuth::NoAuth => msg.write_u8(0),
            SocksAuth::Socks4(s) => {
                msg.write_all(s);
                msg.write_u8(0);
            }
            SocksAuth::Username(_, _) => {
                return Err(internal!("tried to send socks5 auth over socks4.").into())
            }
        }

        if use_v4a {
            // We are using socks4a, so we need to send the address now.
            msg.write_all(self.request.addr().to_string().as_bytes());
            msg.write_u8(0);
        }

        self.state = State::Socks4Wait;
        Ok(ImplNextStep::Reply {
            reply: msg,
        })
    }

    /// Handle a SOCKSv4 response.
    fn handle_v4(&mut self, r: &mut Reader<'_>) -> Result<ImplNextStep> {
        let ver = r.take_u8()?;
        if ver != 0 {
            return Err(Error::Syntax);
        }
        let status = r.take_u8()?;
        let port = r.take_u16()?;
        let ip: Ipv4Addr = r.extract()?;

        self.state = State::Done;
        self.reply = Some(SocksReply::new(
            SocksStatus::from_socks4_status(status),
            SocksAddr::Ip(ip.into()),
            port,
        ));

        Ok(ImplNextStep::Finished {
        })
    }

    /// Send our initial socks5 message (which negotiates our authentication methods).
    fn send_v5_initial(&mut self) -> Result<ImplNextStep> {
        let mut msg = Vec::new();
        msg.write_u8(5);
        match self.request.auth() {
            SocksAuth::NoAuth => {
                msg.write_u8(1); // 1 method.
                msg.write_u8(NO_AUTHENTICATION);
            }
            SocksAuth::Socks4(_) => return Err(internal!("Mismatched authentication type").into()),
            SocksAuth::Username(_, _) => {
                msg.write_u8(2); // 2 methods.
                msg.write_u8(USERNAME_PASSWORD);
                msg.write_u8(NO_AUTHENTICATION);
            }
        }

        self.state = State::Socks5AuthWait;
        Ok(ImplNextStep::Reply {
            reply: msg,
        })
    }

    /// Try to handle a socks5 reply telling us what authentication method to
    /// use, and reply as appropriate.
    fn handle_v5_auth(&mut self, r: &mut Reader<'_>) -> Result<ImplNextStep> {
        let ver = r.take_u8()?;
        if ver != 5 {
            return Err(Error::Syntax);
        }
        let auth = r.take_u8()?;
        let (msg, next_state) = match auth {
            USERNAME_PASSWORD => (self.generate_v5_username_auth()?, State::Socks5UsernameWait),
            NO_AUTHENTICATION => (self.generate_v5_command()?, State::Socks5Wait),
            other => {
                return Err(Error::NotImplemented(
                    format!("authentication type {}", other).into(),
                ))
            }
        };

        self.state = next_state;
        Ok(ImplNextStep::Reply {
            reply: msg,
        })
    }

    /// Return a message to perform username/password authentication.
    fn generate_v5_username_auth(&self) -> Result<Vec<u8>> {
        if let SocksAuth::Username(username, pass) = self.request.auth() {
            let mut msg = Vec::new();

            msg.write_u8(1); // version
            let mut n = msg.write_nested_u8len();
            n.write_all(username);
            n.finish().map_err(into_internal!("id too long"))?;

            let mut n = msg.write_nested_u8len();
            n.write_all(pass);
            n.finish().map_err(into_internal!("password too long"))?;

            Ok(msg)
        } else {
            // Can't perform this authentication when it wasn't what we asked for.
            Err(Error::Syntax)
        }
    }

    /// Try to handle a reply from the socks5 proxy to acknowledge our
    /// username/password authentication, and reply as appropriate.
    fn handle_v5_username_ack(&mut self, r: &mut Reader<'_>) -> Result<ImplNextStep> {
        let ver = r.take_u8()?;
        if ver != 1 {
            return Err(Error::Syntax);
        }
        let result = r.take_u8()?;
        if result != 0 {
            return Err(Error::AuthRejected);
        }

        self.state = State::Socks5Wait;
        Ok(ImplNextStep::Reply {
            reply: self.generate_v5_command()?,
        })
    }

    /// Return a message to encode our final socks5 request.
    ///
    /// (This can be done either in response getting an ACK for our
    /// authentication, or in response to being told that we don't need to
    /// authenticate.)
    fn generate_v5_command(&self) -> Result<Vec<u8>> {
        let mut msg = Vec::new();
        msg.write_u8(5); // version
        msg.write_u8(self.request.command().into());
        msg.write_u8(0); // reserved.
        msg.write(self.request.addr())
            .map_err(into_internal!("Can't encode address"))?;
        msg.write_u16(self.request.port());

        Ok(msg)
    }

    /// Handle a final socks5 reply.
    fn handle_v5_final(&mut self, r: &mut Reader<'_>) -> Result<ImplNextStep> {
        let ver = r.take_u8()?;
        if ver != 5 {
            return Err(Error::Syntax);
        }
        let status: SocksStatus = r.take_u8()?.into();
        let _reserved = r.take_u8()?;
        let addr: SocksAddr = r.extract()?;
        let port = r.take_u16()?;

        self.state = State::Done;
        self.reply = Some(SocksReply::new(status, addr, port));
        Ok(ImplNextStep::Finished {
        })
    }
}

#[cfg(test)]
mod test {
    // @@ begin test lint list maintained by maint/add_warning @@
    #![allow(clippy::bool_assert_comparison)]
    #![allow(clippy::clone_on_copy)]
    #![allow(clippy::dbg_macro)]
    #![allow(clippy::mixed_attributes_style)]
    #![allow(clippy::print_stderr)]
    #![allow(clippy::print_stdout)]
    #![allow(clippy::single_char_pattern)]
    #![allow(clippy::unwrap_used)]
    #![allow(clippy::unchecked_duration_subtraction)]
    #![allow(clippy::useless_vec)]
    #![allow(clippy::needless_pass_by_value)]
    //! <!-- @@ end test lint list maintained by maint/add_warning @@ -->

    use super::*;
    use crate::{msg::SocksCmd, Handshake as _};
    use hex_literal::hex;

    #[test]
    fn socks4_ok() {
        let r = SocksRequest::new(
            SocksVersion::V4,
            SocksCmd::CONNECT,
            SocksAddr::Ip("192.0.2.15".parse().unwrap()),
            443,
            SocksAuth::NoAuth,
        )
        .unwrap();
        let mut hs = SocksClientHandshake::new(r);
        let action = hs.handshake(&[]).unwrap().unwrap();
        assert_eq!(action.drain, 0);
        assert_eq!(action.reply, hex!("04 01 01BB C000020F 00"));
        assert_eq!(action.finished, false);

        let action = hs.handshake(&hex!("00 5A 01BB C000020F")).unwrap().unwrap();
        assert_eq!(action.drain, 8);
        assert!(action.reply.is_empty());
        assert_eq!(action.finished, true);

        let reply = hs.into_reply().unwrap();
        assert_eq!(reply.status(), SocksStatus::SUCCEEDED);
        assert_eq!(reply.port(), 443);
        assert_eq!(reply.addr().to_string(), "192.0.2.15");
    }

    #[test]
    fn socks4a_ok() {
        let r = SocksRequest::new(
            SocksVersion::V4,
            SocksCmd::CONNECT,
            SocksAddr::Hostname("www.torproject.org".to_string().try_into().unwrap()),
            443,
            SocksAuth::Socks4(b"hello".to_vec()),
        )
        .unwrap();
        let mut hs = SocksClientHandshake::new(r);
        let action = hs.handshake(&[]).unwrap().unwrap();
        assert_eq!(action.drain, 0);
        assert_eq!(
            action.reply,
            hex!("04 01 01BB 00000001 68656c6c6f00 7777772e746f7270726f6a6563742e6f726700")
        );
        assert_eq!(action.finished, false);

        let action = hs.handshake(&hex!("00 5A 01BB C0000215")).unwrap().unwrap();
        assert_eq!(action.drain, 8);
        assert!(action.reply.is_empty());
        assert_eq!(action.finished, true);

        let reply = hs.into_reply().unwrap();
        assert_eq!(reply.status(), SocksStatus::SUCCEEDED);
        assert_eq!(reply.port(), 443);
        assert_eq!(reply.addr().to_string(), "192.0.2.21");
    }

    #[test]
    fn socks5_with_no_auth() {
        let r = SocksRequest::new(
            SocksVersion::V5,
            SocksCmd::CONNECT,
            SocksAddr::Hostname("www.torproject.org".to_string().try_into().unwrap()),
            443,
            SocksAuth::NoAuth,
        )
        .unwrap();

        // client begins by proposing authentication types.
        let mut hs = SocksClientHandshake::new(r);
        let action = hs.handshake(&[]).unwrap().unwrap();
        assert_eq!(action.drain, 0);
        assert_eq!(action.reply, hex!("05 01 00"));
        assert_eq!(action.finished, false);

        // proxy chooses noauth; client replies with its handshake.
        let action = hs.handshake(&hex!("0500")).unwrap().unwrap();
        assert_eq!(action.drain, 2);
        assert_eq!(
            action.reply,
            hex!("05 01 00 03 12 7777772e746f7270726f6a6563742e6f7267 01BB")
        );
        assert_eq!(action.finished, false);

        // Proxy says "okay, you're connected."
        // Client is done.
        let action = hs
            .handshake(&hex!("05 00 00 01 C0000215 01BB"))
            .unwrap()
            .unwrap();
        assert_eq!(action.drain, 10);
        assert!(action.reply.is_empty());
        assert_eq!(action.finished, true);

        let reply = hs.into_reply().unwrap();
        assert_eq!(reply.status(), SocksStatus::SUCCEEDED);
        assert_eq!(reply.port(), 443);
        assert_eq!(reply.addr().to_string(), "192.0.2.21");
    }

    #[test]
    fn socks5_with_auth_ok() {
        let r = SocksRequest::new(
            SocksVersion::V5,
            SocksCmd::CONNECT,
            SocksAddr::Hostname("www.torproject.org".to_string().try_into().unwrap()),
            443,
            SocksAuth::Username(b"hello".to_vec(), b"world".to_vec()),
        )
        .unwrap();

        // client begins by proposing authentication types.
        let mut hs = SocksClientHandshake::new(r);
        let action = hs.handshake(&[]).unwrap().unwrap();
        assert_eq!(action.drain, 0);
        assert_eq!(action.reply, hex!("05 02 0200"));
        assert_eq!(action.finished, false);

        // proxy chooses username/password; client replies with "hello"/"world"
        let action = hs.handshake(&hex!("0502")).unwrap().unwrap();
        assert_eq!(action.drain, 2);
        assert_eq!(action.reply, hex!("01 05 68656c6c6f 05 776f726c64"));
        assert_eq!(action.finished, false);

        // Proxy says "yeah, that's good authentication, go ahead."
        // Client says what it actually wants.
        let action = hs.handshake(&hex!("0100")).unwrap().unwrap();
        assert_eq!(action.drain, 2);
        assert_eq!(
            action.reply,
            hex!("05 01 00 03 12 7777772e746f7270726f6a6563742e6f7267 01BB")
        );
        assert_eq!(action.finished, false);

        // Proxy says "okay, you're connected."
        // Client is done.
        let action = hs
            .handshake(&hex!("05 00 00 01 C0000215 01BB"))
            .unwrap()
            .unwrap();
        assert_eq!(action.drain, 10);
        assert!(action.reply.is_empty());
        assert_eq!(action.finished, true);

        let reply = hs.into_reply().unwrap();
        assert_eq!(reply.status(), SocksStatus::SUCCEEDED);
        assert_eq!(reply.port(), 443);
        assert_eq!(reply.addr().to_string(), "192.0.2.21");
    }
}
