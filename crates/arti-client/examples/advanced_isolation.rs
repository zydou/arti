// @@ begin example lint list maintained by maint/add_warning @@
#![allow(unknown_lints)] // @@REMOVE_WHEN(ci_arti_nightly)
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
//! <!-- @@ end example lint list maintained by maint/add_warning @@ -->

// This example showcase how to use the trait IsolationHelper to build complex isolation rules.
// For most usages, using a combination of TorClient::isolated_client and IsolationToken should
// be enough.
use std::collections::HashSet;

use anyhow::Result;
use arti_client::isolation::IsolationHelper;
use arti_client::{IsolationToken, StreamPrefs, TorClient, TorClientConfig};
use tokio_crate as tokio;

use futures::io::{AsyncReadExt, AsyncWriteExt};

/// Example Isolation which isolate streams deemed sensitive from each other, but won't isolate
/// `Innocent` streams from other `Innocent` streams or from `Sensitive` streams.
///
/// More formally, for two streams to share the same circuit, it's required that either:
/// - at least one stream is Innocent
/// - both are Sensitive, with the same inner IsolationToken
#[derive(Debug, Clone, Copy)]
enum IsolateSensitive {
    Sensitive(IsolationToken),
    Innocent,
}

impl IsolateSensitive {
    fn new_sensitive() -> Self {
        IsolateSensitive::Sensitive(IsolationToken::new())
    }
}

impl IsolationHelper for IsolateSensitive {
    fn compatible_same_type(&self, other: &Self) -> bool {
        match (self, other) {
            (IsolateSensitive::Sensitive(i), IsolateSensitive::Sensitive(j)) => {
                i.compatible_same_type(j)
            }
            _ => true,
        }
    }
    fn join_same_type(&self, other: &Self) -> Option<Self> {
        match (self, other) {
            (IsolateSensitive::Sensitive(i), IsolateSensitive::Sensitive(j)) => {
                i.join_same_type(j).map(IsolateSensitive::Sensitive)
            }
            (res @ IsolateSensitive::Sensitive(_), _)
            | (_, res @ IsolateSensitive::Sensitive(_)) => Some(*res),
            _ => Some(IsolateSensitive::Innocent),
        }
    }
}

/// Example Isolation which limit how many different purposes a single circuit can have.
///
/// Note that two IsolateOverused with different MAX_USAGE or different T are different types, so they
/// would get isolated from each other, even if neither has reached its MAX_USAGE.
#[derive(Debug, Clone)]
struct IsolateOverused<T, const MAX_USAGE: usize> {
    usages: HashSet<T>,
}

impl<T: Eq + std::hash::Hash, const MAX_USAGE: usize> IsolateOverused<T, MAX_USAGE> {
    fn new_with_usage(usage: T) -> Self {
        let mut usages = HashSet::new();
        usages.insert(usage);

        IsolateOverused { usages }
    }
}

impl<T: Eq + std::hash::Hash + Clone, const MAX_USAGE: usize> IsolationHelper
    for IsolateOverused<T, MAX_USAGE>
{
    fn compatible_same_type(&self, other: &Self) -> bool {
        self.usages.union(&other.usages).count() <= MAX_USAGE
    }

    fn join_same_type(&self, other: &Self) -> Option<Self> {
        let usages: HashSet<_> = self.usages.union(&other.usages).cloned().collect();
        if usages.len() <= MAX_USAGE {
            Some(IsolateOverused { usages })
        } else {
            None
        }
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt::init();
    let config = TorClientConfig::default();

    eprintln!("connecting to Tor...");
    let tor_client = TorClient::create_bootstrapped(config).await?;

    // requests using this won't be isolated from each others, or from "sensitive" requests
    let innocent = {
        let mut pref = StreamPrefs::new();
        pref.set_isolation(IsolateSensitive::Innocent);
        pref
    };

    // requests using this will be isolated from "sensitive" requests using a different
    // IsolateSensitive::Sensitive. They won't be isolated from each other or from Innocent requests
    let sensitive_1 = {
        let mut pref = StreamPrefs::new();
        pref.set_isolation(IsolateSensitive::new_sensitive());
        pref
    };

    let sensitive_2 = {
        let mut pref = StreamPrefs::new();
        pref.set_isolation(IsolateSensitive::new_sensitive());
        pref
    };

    eprintln!("sending a bunch of sensitive and innocent requests");

    let mut stream = tor_client
        .connect_with_prefs(("example.net", 80), &innocent)
        .await?;
    send_request(&mut stream, "example.net").await?;

    let mut stream = tor_client
        .connect_with_prefs(("example.com", 80), &sensitive_1)
        .await?;
    send_request(&mut stream, "example.com").await?;

    let mut stream = tor_client
        .connect_with_prefs(("example.com", 80), &sensitive_2)
        .await?;
    send_request(&mut stream, "example.com").await?;

    let mut stream = tor_client
        .connect_with_prefs(("example.com", 80), &sensitive_1)
        .await?;
    send_request(&mut stream, "example.com").await?;

    // Each of these requests can share a circuit with at most 2 other usages (3 including itself).
    // As there are 4 different usages, there will be at least 2 circuits used. Also as
    // IsolateOverused and IsolateSensitive are not the same type, they won't share any circuits.
    let first_usage = {
        let mut pref = StreamPrefs::new();
        pref.set_isolation(IsolateOverused::<_, 3>::new_with_usage("first usage"));
        pref
    };
    let second_usage = {
        let mut pref = StreamPrefs::new();
        pref.set_isolation(IsolateOverused::<_, 3>::new_with_usage("second usage"));
        pref
    };
    let third_usage = {
        let mut pref = StreamPrefs::new();
        pref.set_isolation(IsolateOverused::<_, 3>::new_with_usage("third usage"));
        pref
    };
    let fourth_usage = {
        let mut pref = StreamPrefs::new();
        pref.set_isolation(IsolateOverused::<_, 3>::new_with_usage("fourth usage"));
        pref
    };

    let mut stream = tor_client
        .connect_with_prefs(("example.net", 80), &first_usage)
        .await?;
    send_request(&mut stream, "example.net").await?;
    let mut stream = tor_client
        .connect_with_prefs(("example.org", 80), &second_usage)
        .await?;
    send_request(&mut stream, "example.org").await?;
    let mut stream = tor_client
        .connect_with_prefs(("example.com", 80), &third_usage)
        .await?;
    send_request(&mut stream, "example.com").await?;
    let mut stream = tor_client
        .connect_with_prefs(("example.net", 80), &fourth_usage)
        .await?;
    send_request(&mut stream, "example.net").await?;

    Ok(())
}

async fn send_request(stream: &mut arti_client::DataStream, host: &str) -> Result<()> {
    stream
        .write_all(
            format!("GET / HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n\r\n").as_bytes(),
        )
        .await?;
    stream.flush().await?;

    let mut buf = Vec::new();
    stream.read_to_end(&mut buf).await?;
    println!("{}", String::from_utf8_lossy(&buf));
    Ok(())
}
