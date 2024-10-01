//! Types to implement the SOCKS handshake.

use super::framework::{HandshakeImpl, ImplNextStep};
use crate::msg::{SocksAddr, SocksAuth, SocksCmd, SocksRequest, SocksStatus, SocksVersion};
use crate::{Error, Result};

use tor_bytes::{EncodeResult, Error as BytesError};
use tor_bytes::{Reader, Writer};
use tor_error::internal;

use derive_deftly::Deftly;

use std::net::IpAddr;

/// The Proxy (responder) side of an ongoing SOCKS handshake.
///
/// Create you have one of these with [`SocksProxyHandshake::new()`],
/// and then use [`Handshake::step`](crate::Handshake::step) to drive it.
///
/// Eventually you will hopefully obtain a [`SocksRequest`],
/// on which you should call [`.reply()`](SocksRequest::reply),
/// and send the resulting data to the peer.
#[derive(Clone, Debug, Deftly)]
#[derive_deftly(Handshake)]
pub struct SocksProxyHandshake {
    /// Current state of the handshake. Each completed message
    /// advances the state.
    state: State,
    /// SOCKS5 authentication that has been received (but not yet put
    /// in a SocksRequest object.)
    socks5_auth: Option<SocksAuth>,
    /// Completed SOCKS handshake.
    #[deftly(handshake(output))]
    handshake: Option<SocksRequest>,
}

/// Possible state for a Socks connection.
///
/// Each completed message advances the state.
#[derive(Clone, Debug, Copy, PartialEq, Eq)]
enum State {
    /// Starting state: no messages have been handled yet.
    Initial,
    /// SOCKS5: we've negotiated Username/Password authentication, and
    /// are waiting for the client to send it.
    Socks5Username,
    /// SOCKS5: we've finished the authentication (if any), and
    /// we're waiting for the actual request.
    Socks5Wait,
    /// Ending (successful) state: the client has sent all its messages.
    ///
    /// (Note that we still need to send a reply.)
    Done,
    /// Ending (failed) state: the handshake has failed and cannot continue.
    Failed,
}

impl HandshakeImpl for SocksProxyHandshake {
    fn handshake_impl(&mut self, input: &mut Reader<'_>) -> Result<ImplNextStep> {
        match (self.state, input.peek(1)?[0]) {
            (State::Initial, 4) => self.s4(input),
            (State::Initial, 5) => self.s5_initial(input),
            (State::Initial, v) => Err(Error::BadProtocol(v)),
            (State::Socks5Username, 1) => self.s5_uname(input),
            (State::Socks5Wait, 5) => self.s5(input),
            (State::Done, _) => Err(Error::AlreadyFinished(internal!(
                "called handshake() after handshaking was done"
            ))),
            (State::Failed, _) => Err(Error::AlreadyFinished(internal!(
                "called handshake() after handshaking failed"
            ))),
            (_, _) => Err(Error::Syntax),
        }
    }
}

impl SocksProxyHandshake {
    /// Construct a new SocksProxyHandshake in its initial state
    pub fn new() -> Self {
        SocksProxyHandshake {
            state: State::Initial,
            socks5_auth: None,
            handshake: None,
        }
    }

    /// Complete a socks4 or socks4a handshake.
    fn s4(&mut self, r: &mut Reader<'_>) -> Result<ImplNextStep> {
        let version = r.take_u8()?.try_into()?;
        if version != SocksVersion::V4 {
            return Err(internal!("called s4 on wrong type {:?}", version).into());
        }

        let cmd: SocksCmd = r.take_u8()?.into();
        let port = r.take_u16()?;
        let ip = r.take_u32()?;
        let username: Vec<u8> = r.take_until(0)?.into();
        let auth = if username.is_empty() {
            SocksAuth::NoAuth
        } else {
            SocksAuth::Socks4(username)
        };

        let addr = if ip != 0 && (ip >> 8) == 0 {
            // Socks4a; a hostname is given.
            let hostname = r.take_until(0)?;
            let hostname = std::str::from_utf8(hostname)
                .map_err(|_| Error::Syntax)?
                .to_string();
            let hostname = hostname
                .try_into()
                .map_err(|_| BytesError::InvalidMessage("hostname too long".into()))?;
            SocksAddr::Hostname(hostname)
        } else {
            let ip4: std::net::Ipv4Addr = ip.into();
            SocksAddr::Ip(ip4.into())
        };

        let request = SocksRequest::new(version, cmd, addr, port, auth)?;

        self.state = State::Done;
        self.handshake = Some(request);

        Ok(ImplNextStep::Finished)
    }

    /// Socks5: initial handshake to negotiate authentication method.
    fn s5_initial(&mut self, r: &mut Reader<'_>) -> Result<ImplNextStep> {
        use super::{NO_AUTHENTICATION, USERNAME_PASSWORD};
        let version: SocksVersion = r.take_u8()?.try_into()?;
        if version != SocksVersion::V5 {
            return Err(internal!("called on wrong handshake type {:?}", version).into());
        }

        let nmethods = r.take_u8()?;
        let methods = r.take(nmethods as usize)?;

        // Prefer username/password, then none.
        let (next, reply) = if methods.contains(&USERNAME_PASSWORD) {
            (State::Socks5Username, [5, USERNAME_PASSWORD])
        } else if methods.contains(&NO_AUTHENTICATION) {
            self.socks5_auth = Some(SocksAuth::NoAuth);
            (State::Socks5Wait, [5, NO_AUTHENTICATION])
        } else {
            // In theory we should reply with "NO ACCEPTABLE METHODS".
            return Err(Error::NotImplemented("authentication methods".into()));
        };

        self.state = next;
        Ok(ImplNextStep::Reply {
            reply: reply.into(),
        })
    }

    /// Socks5: second step for username/password authentication.
    fn s5_uname(&mut self, r: &mut Reader<'_>) -> Result<ImplNextStep> {
        let ver = r.take_u8()?;
        if ver != 1 {
            return Err(Error::NotImplemented(
                format!("username/password version {}", ver).into(),
            ));
        }

        let ulen = r.take_u8()?;
        let username = r.take(ulen as usize)?;
        let plen = r.take_u8()?;
        let passwd = r.take(plen as usize)?;

        self.socks5_auth = Some(SocksAuth::Username(username.into(), passwd.into()));
        self.state = State::Socks5Wait;
        Ok(ImplNextStep::Reply { reply: vec![1, 0] })
    }

    /// Socks5: final step, to receive client's request.
    fn s5(&mut self, r: &mut Reader<'_>) -> Result<ImplNextStep> {
        let version: SocksVersion = r.take_u8()?.try_into()?;
        if version != SocksVersion::V5 {
            return Err(
                internal!("called s5 on non socks5 handshake with type {:?}", version).into(),
            );
        }
        let cmd = r.take_u8()?.into();
        let _ignore = r.take_u8()?;
        let addr = r.extract()?;
        let port = r.take_u16()?;

        let auth = self
            .socks5_auth
            .take()
            .ok_or_else(|| internal!("called s5 without negotiating auth"))?;

        let request = SocksRequest::new(version, cmd, addr, port, auth)?;

        self.state = State::Done;
        self.handshake = Some(request);

        Ok(ImplNextStep::Finished)
    }

    /// Return true if this handshake is finished.
    pub fn finished(&self) -> bool {
        self.state == State::Done
    }

    /// Consume this handshake's state; if it finished successfully,
    /// return a SocksRequest.
    pub fn into_request(self) -> Option<SocksRequest> {
        self.handshake
    }
}

impl Default for SocksProxyHandshake {
    fn default() -> Self {
        Self::new()
    }
}

impl SocksRequest {
    /// Format a reply to this request, indicating success or failure.
    ///
    /// Note that an address should be provided only when the request
    /// was for a RESOLVE.
    pub fn reply(&self, status: SocksStatus, addr: Option<&SocksAddr>) -> EncodeResult<Vec<u8>> {
        match self.version() {
            SocksVersion::V4 => self.s4(status, addr),
            SocksVersion::V5 => self.s5(status, addr),
        }
    }

    /// Format a SOCKS4 reply.
    fn s4(&self, status: SocksStatus, addr: Option<&SocksAddr>) -> EncodeResult<Vec<u8>> {
        let mut w = Vec::new();
        w.write_u8(0);
        w.write_u8(status.into_socks4_status());
        match addr {
            Some(SocksAddr::Ip(IpAddr::V4(ip))) => {
                w.write_u16(self.port());
                w.write(ip)?;
            }
            _ => {
                w.write_u16(0);
                w.write_u32(0);
            }
        }
        Ok(w)
    }

    /// Format a SOCKS5 reply.
    fn s5(&self, status: SocksStatus, addr: Option<&SocksAddr>) -> EncodeResult<Vec<u8>> {
        let mut w = Vec::new();
        w.write_u8(5);
        w.write_u8(status.into());
        w.write_u8(0); // reserved.
        if let Some(a) = addr {
            w.write(a)?;
            w.write_u16(self.port());
        } else {
            // TODO: sometimes I think we want to answer with ::, not 0.0.0.0
            w.write(&SocksAddr::Ip(std::net::Ipv4Addr::UNSPECIFIED.into()))?;
            w.write_u16(0);
        }
        Ok(w)
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
    use crate::{Handshake as _, Truncated};
    use hex_literal::hex;

    #[test]
    fn socks4_good() {
        let mut h = SocksProxyHandshake::default();
        let a = h
            .handshake_for_tests(&hex!("04 01 0050 CB007107 00")[..])
            .unwrap()
            .unwrap();
        assert!(a.finished);
        assert!(h.finished());
        assert_eq!(a.drain, 9);
        assert!(a.reply.is_empty()); // no reply -- waiting to see how it goes

        let req = h.into_request().unwrap();
        assert_eq!(req.port(), 80);
        assert_eq!(req.addr().to_string(), "203.0.113.7");
        assert_eq!(req.command(), SocksCmd::CONNECT);

        assert_eq!(
            req.reply(
                SocksStatus::GENERAL_FAILURE,
                Some(&SocksAddr::Ip("127.0.0.1".parse().unwrap()))
            )
            .unwrap(),
            hex!("00 5B 0050 7f000001")
        );
    }

    #[test]
    fn socks4a_good() {
        let mut h = SocksProxyHandshake::new();
        let msg = hex!(
            "04 01 01BB 00000001 73776f72646669736800
                        7777772e6578616d706c652e636f6d00 99"
        );
        let a = h.handshake_for_tests(&msg[..]).unwrap().unwrap();
        assert!(a.finished);
        assert!(h.finished());
        assert_eq!(a.drain, msg.len() - 1);
        assert!(a.reply.is_empty()); // no reply -- waiting to see how it goes

        let req = h.into_request().unwrap();
        assert_eq!(req.port(), 443);
        assert_eq!(req.addr().to_string(), "www.example.com");
        assert_eq!(req.auth(), &SocksAuth::Socks4(b"swordfish".to_vec()));
        assert_eq!(req.command(), SocksCmd::CONNECT);

        assert_eq!(
            req.reply(SocksStatus::SUCCEEDED, None).unwrap(),
            hex!("00 5A 0000 00000000")
        );
    }

    #[test]
    fn socks5_init_noauth() {
        let mut h = SocksProxyHandshake::new();
        let a = h
            .handshake_for_tests(&hex!("05 01 00")[..])
            .unwrap()
            .unwrap();
        assert!(!a.finished);
        assert_eq!(a.drain, 3);
        assert_eq!(a.reply, &[5, 0]);
        assert_eq!(h.state, State::Socks5Wait);
    }

    #[test]
    fn socks5_init_username() {
        let mut h = SocksProxyHandshake::new();
        let a = h
            .handshake_for_tests(&hex!("05 04 00023031")[..])
            .unwrap()
            .unwrap();
        assert!(!a.finished);
        assert_eq!(a.drain, 6);
        assert_eq!(a.reply, &[5, 2]);
        assert_eq!(h.state, State::Socks5Username);
    }

    #[test]
    fn socks5_init_nothing_works() {
        let mut h = SocksProxyHandshake::new();
        let a = h.handshake_for_tests(&hex!("05 02 9988")[..]);
        assert!(matches!(a, Ok(Err(Error::NotImplemented(_)))));
    }

    #[test]
    fn socks5_username_ok() {
        let mut h = SocksProxyHandshake::new();
        let _a = h.handshake_for_tests(&hex!("05 02 9902")).unwrap().unwrap();
        let a = h
            .handshake_for_tests(&hex!("01 08 5761677374616666 09 24776f726466693568"))
            .unwrap()
            .unwrap();
        assert_eq!(a.drain, 20);
        assert_eq!(a.reply, &[1, 0]);
        assert_eq!(h.state, State::Socks5Wait);
        assert_eq!(
            h.socks5_auth.unwrap(),
            // _Horse Feathers_, 1932
            SocksAuth::Username(b"Wagstaff".to_vec(), b"$wordfi5h".to_vec())
        );
    }

    #[test]
    fn socks5_request_ok_ipv4() {
        let mut h = SocksProxyHandshake::new();
        let _a = h.handshake_for_tests(&hex!("05 01 00")).unwrap().unwrap();
        let a = h
            .handshake_for_tests(&hex!("05 01 00 01 7f000007 1f90"))
            .unwrap()
            .unwrap();
        assert_eq!(a.drain, 10);
        assert!(a.finished);
        assert!(a.reply.is_empty());
        assert_eq!(h.state, State::Done);

        let req = h.into_request().unwrap();
        assert_eq!(req.version(), SocksVersion::V5);
        assert_eq!(req.command(), SocksCmd::CONNECT);
        assert_eq!(req.addr().to_string(), "127.0.0.7");
        assert_eq!(req.port(), 8080);
        assert_eq!(req.auth(), &SocksAuth::NoAuth);

        assert_eq!(
            req.reply(
                SocksStatus::HOST_UNREACHABLE,
                Some(&SocksAddr::Hostname(
                    "foo.example.com".to_string().try_into().unwrap()
                ))
            )
            .unwrap(),
            hex!("05 04 00 03 0f 666f6f2e6578616d706c652e636f6d 1f90")
        );
    }

    #[test]
    fn socks5_request_ok_ipv6() {
        let mut h = SocksProxyHandshake::new();
        let _a = h.handshake_for_tests(&hex!("05 01 00")).unwrap().unwrap();
        let a = h
            .handshake_for_tests(&hex!(
                "05 01 00 04 f000 0000 0000 0000 0000 0000 0000 ff11 1f90"
            ))
            .unwrap()
            .unwrap();
        assert_eq!(a.drain, 22);
        assert!(a.finished);
        assert!(a.reply.is_empty());
        assert_eq!(h.state, State::Done);

        let req = h.into_request().unwrap();
        assert_eq!(req.version(), SocksVersion::V5);
        assert_eq!(req.command(), SocksCmd::CONNECT);
        assert_eq!(req.addr().to_string(), "f000::ff11");
        assert_eq!(req.port(), 8080);
        assert_eq!(req.auth(), &SocksAuth::NoAuth);

        assert_eq!(
            req.reply(SocksStatus::GENERAL_FAILURE, Some(req.addr()))
                .unwrap(),
            hex!("05 01 00 04 f000 0000 0000 0000 0000 0000 0000 ff11 1f90")
        );
    }

    #[test]
    fn socks5_request_ok_hostname() {
        let mut h = SocksProxyHandshake::new();
        let _a = h.handshake_for_tests(&hex!("05 01 00")).unwrap().unwrap();
        let a = h
            .handshake_for_tests(&hex!("05 01 00 03 0f 666f6f2e6578616d706c652e636f6d 1f90"))
            .unwrap()
            .unwrap();
        assert_eq!(a.drain, 22);
        assert!(a.finished);
        assert!(a.reply.is_empty());
        assert_eq!(h.state, State::Done);

        let req = h.into_request().unwrap();
        assert_eq!(req.version(), SocksVersion::V5);
        assert_eq!(req.command(), SocksCmd::CONNECT);
        assert_eq!(req.addr().to_string(), "foo.example.com");
        assert_eq!(req.port(), 8080);
        assert_eq!(req.auth(), &SocksAuth::NoAuth);

        assert_eq!(
            req.reply(SocksStatus::SUCCEEDED, None).unwrap(),
            hex!("05 00 00 01 00000000 0000")
        );
    }

    #[test]
    fn empty_handshake() {
        let r = SocksProxyHandshake::new().handshake_for_tests(&[]);
        assert!(matches!(r, Err(Truncated { .. })));
    }

    #[test]
    fn bad_version() {
        let mut h = SocksProxyHandshake::new();
        let r = h.handshake_for_tests(&hex!("06 01 00"));
        assert!(matches!(r, Ok(Err(Error::BadProtocol(6)))));

        let mut h = SocksProxyHandshake::new();
        let _a = h.handshake_for_tests(&hex!("05 01 00")).unwrap();
        let r = h.handshake_for_tests(&hex!("06 01 00"));
        assert!(r.unwrap().is_err());
    }

    #[test]
    fn fused_result() {
        let good_socks4a = &hex!("04 01 0050 CB007107 00")[..];

        // Can't try again after failure.
        let mut h = SocksProxyHandshake::new();
        let r = h.handshake_for_tests(&hex!("06 01 00"));
        assert!(r.unwrap().is_err());
        let r = h.handshake_for_tests(good_socks4a);
        assert!(matches!(r, Ok(Err(Error::AlreadyFinished(_)))));

        // Can't try again after success
        let mut h = SocksProxyHandshake::new();
        let r = h.handshake_for_tests(good_socks4a);
        assert!(r.is_ok());
        let r = h.handshake_for_tests(good_socks4a);
        assert!(matches!(r, Ok(Err(Error::AlreadyFinished(_)))));
    }
}
