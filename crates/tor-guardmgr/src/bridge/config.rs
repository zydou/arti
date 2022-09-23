//! Configuration logic and types for bridges.
#![allow(dead_code)] // TODO pt-client: remove.

use tor_linkspec::ChannelMethod;
use tor_llcrypto::pk::{ed25519::Ed25519Identity, rsa::RsaIdentity};

/// A relay not listed on the main tor network, used for anticensorship.
///
/// This object represents a bridge as configured by the user or by software
/// running on the user's behalf.
#[derive(Debug, Clone)]
// TODO pt-client: Derive builder and associated config types.
pub struct Bridge {
    // TODO pt-client: I am not sold on this exact representation for Bridge; it
    // needs to be something like this, but not necessarily this exact set of
    // members.
    //
    /// Address and transport via which the bridge can be reached, and
    /// the parameters for those transports.
    addrs: ChannelMethod,

    /// The RSA identity of the bridge.
    rsa_id: RsaIdentity,

    /// The Ed25519 identity of the bridge.
    ed_id: Option<Ed25519Identity>,
}
// TODO pt-client: when implementing deserialization for this type, make sure
// that it can accommodate a large variety of possible configurations methods,
// and check that the toml looks okay.  For discussion see
// https://gitlab.torproject.org/tpo/core/arti/-/merge_requests/704/diffs#note_2835271

// TODO pt-client Additionally, make sure that Bridge can be deserialized from a string,
// when that string is a "bridge" line.

// TODO pt-client We want a "list of bridges'" configuration type
//
// TODO pt-client we want a "should we use bridges at this moment"
// configuration object.
//
// (These last two might be part of the same configuration type.)
