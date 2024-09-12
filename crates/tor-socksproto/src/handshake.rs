//! Implement the socks handshakes.

#[cfg(any(feature = "proxy-handshake", feature = "client-handshake"))]
#[macro_use]
pub(crate) mod framework;

#[cfg(feature = "client-handshake")]
pub(crate) mod client;
#[cfg(feature = "proxy-handshake")]
pub(crate) mod proxy;

use crate::msg::SocksAddr;
use std::net::IpAddr;
use tor_bytes::Result as BytesResult;
use tor_bytes::{EncodeResult, Error as BytesError, Readable, Reader, Writeable, Writer};

/// Constant for Username/Password-style authentication.
/// (See RFC 1929)
const USERNAME_PASSWORD: u8 = 0x02;
/// Constant for "no authentication".
const NO_AUTHENTICATION: u8 = 0x00;

/// An action to take in response to a SOCKS handshake message.
#[derive(Clone, Debug)]
#[non_exhaustive]
pub struct Action {
    /// If nonzero, this many bytes should be drained from the
    /// client's inputs.
    pub drain: usize,
    /// If nonempty, this reply should be sent to the other party.
    pub reply: Vec<u8>,
    /// If true, then this handshake is over, either successfully or not.
    pub finished: bool,
}

impl Readable for SocksAddr {
    fn take_from(r: &mut Reader<'_>) -> BytesResult<SocksAddr> {
        let atype = r.take_u8()?;
        match atype {
            1 => {
                let ip4: std::net::Ipv4Addr = r.extract()?;
                Ok(SocksAddr::Ip(ip4.into()))
            }
            3 => {
                let hlen = r.take_u8()?;
                let hostname = r.take(hlen as usize)?;
                let hostname = std::str::from_utf8(hostname)
                    .map_err(|_| BytesError::InvalidMessage("bad utf8 on hostname".into()))?
                    .to_string();
                let hostname = hostname
                    .try_into()
                    .map_err(|_| BytesError::InvalidMessage("hostname too long".into()))?;
                Ok(SocksAddr::Hostname(hostname))
            }
            4 => {
                let ip6: std::net::Ipv6Addr = r.extract()?;
                Ok(SocksAddr::Ip(ip6.into()))
            }
            _ => Err(BytesError::InvalidMessage(
                "unrecognized address type.".into(),
            )),
        }
    }
}

impl Writeable for SocksAddr {
    fn write_onto<W: Writer + ?Sized>(&self, w: &mut W) -> EncodeResult<()> {
        match self {
            SocksAddr::Ip(IpAddr::V4(ip)) => {
                w.write_u8(1);
                w.write(ip)?;
            }
            SocksAddr::Ip(IpAddr::V6(ip)) => {
                w.write_u8(4);
                w.write(ip)?;
            }
            SocksAddr::Hostname(h) => {
                let h = h.as_ref();
                assert!(h.len() < 256);
                let hlen = h.len() as u8;
                w.write_u8(3);
                w.write_u8(hlen);
                w.write(h.as_bytes())?;
            }
        }
        Ok(())
    }
}

#[cfg(all(feature = "client-handshake", feature = "proxy-handshake"))]
#[cfg(test)]
mod test_roundtrip {
    // @@ begin test lint list
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
    //! <!-- @@ end test lint list

    use crate::{
        Handshake as _,
        SocksAddr, SocksAuth, SocksCmd, SocksReply, SocksRequest, SocksStatus, SocksVersion,
    };

    use super::client::SocksClientHandshake;
    use super::proxy::SocksProxyHandshake;

    /// Given a socks request, run a complete (successful round) trip, reply with the
    /// the given status code, and return both sides' results.
    fn run_handshake(request: SocksRequest, status: SocksStatus) -> (SocksRequest, SocksReply) {
        let mut client_hs = SocksClientHandshake::new(request);
        let mut proxy_hs = SocksProxyHandshake::new();
        let mut received_request = None;

        let mut last_proxy_msg = vec![];
        // Prevent infinite loop in case of bugs.
        for _ in 0..100 {
            // Make sure that the client says "truncated" for all prefixes of the proxy's message.
            for truncate in 0..last_proxy_msg.len() {
                let r = client_hs.handshake(&last_proxy_msg[..truncate]);
                assert!(r.is_err());
            }
            // Get the client's actual message.
            let client_action = client_hs.handshake(&last_proxy_msg).unwrap().unwrap();
            assert_eq!(client_action.drain, last_proxy_msg.len());
            if client_action.finished {
                let received_reply = client_hs.into_reply();
                return (received_request.unwrap(), received_reply.unwrap());
            }
            let client_msg = client_action.reply;

            // Make sure that the proxy says "truncated" for all prefixes of the client's message.
            for truncate in 0..client_msg.len() {
                let r = proxy_hs.handshake(&client_msg[..truncate]);
                assert!(r.is_err());
            }
            // Get the proxy's actual reply (if any).
            let proxy_action = proxy_hs.handshake(&client_msg).unwrap().unwrap();
            assert_eq!(proxy_action.drain, client_msg.len());
            last_proxy_msg = if proxy_action.finished {
                // The proxy is done: have it reply with a status code.
                received_request = proxy_hs.clone().into_request();
                received_request
                    .as_ref()
                    .unwrap()
                    .reply(status, None)
                    .unwrap()
            } else {
                proxy_action.reply
            };
        }
        panic!("Handshake ran for too many steps")
    }

    // Invoke run_handshake and assert that the output matches the input.
    fn test_handshake(request: &SocksRequest, status: SocksStatus) {
        let (request_out, status_out) = run_handshake(request.clone(), status);
        assert_eq!(&request_out, request);
        assert_eq!(status_out.status(), status);
    }

    #[test]
    fn socks4() {
        test_handshake(
            &SocksRequest::new(
                SocksVersion::V4,
                SocksCmd::CONNECT,
                SocksAddr::Hostname("www.torproject.org".to_string().try_into().unwrap()),
                443,
                SocksAuth::NoAuth,
            )
            .unwrap(),
            SocksStatus::SUCCEEDED,
        );

        test_handshake(
            &SocksRequest::new(
                SocksVersion::V4,
                SocksCmd::CONNECT,
                SocksAddr::Ip("192.0.2.33".parse().unwrap()),
                22,
                SocksAuth::Socks4(b"swordfish".to_vec()),
            )
            .unwrap(),
            SocksStatus::GENERAL_FAILURE,
        );
    }

    #[test]
    fn socks5() {
        test_handshake(
            &SocksRequest::new(
                SocksVersion::V5,
                SocksCmd::CONNECT,
                SocksAddr::Hostname("www.torproject.org".to_string().try_into().unwrap()),
                443,
                SocksAuth::NoAuth,
            )
            .unwrap(),
            SocksStatus::SUCCEEDED,
        );

        test_handshake(
            &SocksRequest::new(
                SocksVersion::V5,
                SocksCmd::CONNECT,
                SocksAddr::Ip("2001:db8::32".parse().unwrap()),
                443,
                SocksAuth::Username(b"belbo".to_vec(), b"non".to_vec()),
            )
            .unwrap(),
            SocksStatus::GENERAL_FAILURE,
        );
    }
}
