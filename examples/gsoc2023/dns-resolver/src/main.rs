#![warn(clippy::missing_docs_in_private_items)]
//! # dns-resolver
//! Use Tor to make a DNS over TCP request for a hostname, and get IP addresses back
//!
//! ### Intro
//! This is a project intended to illustrate how Arti can be used to tunnel
//! arbitrary TCP traffic. Here, a DNS client implementation has been hand crafted
//! to illustrate custom made protocols being able to be used seamlessly over Tor
//!
//! ### Usage
//! Simply run the program:
//! `cargo run <hostname-to-look-up>`
//!
//! The program will then attempt to create a new Tor connection, craft the DNS
//! query, and send it to a DNS server (right now, Cloudflare's 1.1.1.1)
//!
//! The response is then decoded into a struct and pretty printed to the user
//!
//! ### Note on DNS
//! The DNS implementation showcased is not really meant for production. It is just
//! a quick series of hacks to show you how, if you do have a very custom protocol
//! that you need tunnelled over Tor, to use that protocol with Arti. For actually
//! tunneling DNS requests over Tor, it is recommended to use a more tried-and-tested
//! crate.
//!
//! For more information on DNS, you can read [RFC 1035](https://datatracker.ietf.org/doc/html/rfc1035)
//! or [this educational guide](https://mislove.org/teaching/cs4700/spring11/handouts/project1-primer.pdf)
use crate::dns::{AsBytes, FromBytes, Response};
use arti_client::{TorClient, TorClientConfig};
use std::env;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tracing::debug;

mod dns;

#[tokio::main]
async fn main() {
    // Start logging messages
    tracing_subscriber::fmt::init();
    // Get and check CLI arguments
    let args: Vec<String> = env::args().collect();
    if args.len() != 2 {
        eprintln!("Usage: dns-resolver <hostname-to-lookup>");
        return;
    }
    // Create the default TorClientConfig and create a TorClient
    let config = TorClientConfig::default();
    let tor_client = TorClient::create_bootstrapped(config).await.unwrap();
    debug!("Connecting to 1.1.1.1 port 53 for DNS over TCP lookup");
    let mut stream = tor_client.connect(crate::dns::DNS_SERVER).await.unwrap();
    // We now have a TcpStream analogue to use
    match crate::dns::build_query(args[1].as_str()) {
        Ok(query) => {
            let req = query.as_bytes(); // Get raw bytes representation
            stream.write_all(req.as_slice()).await.unwrap();
            // Flushing ensures we actually send data over network right then instead
            // of waiting for buffer to fill up
            stream.flush().await.unwrap();
            debug!("Awaiting response...");
            let mut buf: Vec<u8> = Vec::new();
            // Read the response
            stream.read_to_end(&mut buf).await.unwrap();
            // Interpret the response
            match Response::from_bytes(&buf) {
                Ok(resp) => println!("{resp}"),
                Err(_) => eprintln!("No valid response!"),
            };
        }
        Err(_) => tracing::error!("Invalid domain name entered!"),
    };
}
