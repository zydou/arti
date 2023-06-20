//! Implement a StreamHandler that proxies connections to ports, typically on
//! localhost.

use std::{collections::HashMap, net::SocketAddr};

use async_trait::async_trait;

use crate::StreamHandler;

pub(crate) struct StreamProxy {
    /// Map from virtual port on the onion service to an address we connect to
    /// in order to implement that port.
    ports: HashMap<u16, SocketAddr>,
}

impl StreamProxy {
    // TODO hss need a new() function.  It should reject non-localhost addresses
    // by default, and have a way to override.  (Alternatively, that should be
    // done in the configuration code?)
}

#[async_trait]
impl StreamHandler for StreamProxy {
    async fn handle_request(&self, circinfo: &(), stream: ()) {
        todo!() // TODO hss: implement

        // - Look up the port for the incoming stream request.
        // - If no port is found, reject the request, and possibly increment a
        //   counter in circinfo.
        // - Otherwise, open a TCP connection to the target address.
        //    - On success, accept the stream, and launch tasks to relay traffic
        //      from the stream to the TCP connection.
        //    - On failure, reject the stream with an error.
    }
}
