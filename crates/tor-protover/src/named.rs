//! Define protocol versions by name.
//!
//! Protocol versions obsolete at the time of this writing (Mar 2025)
//! are not included.
//!
//! For more details about specific versions,
//! see the [relevant section of the spec][spec].
//!
//! [spec]: https://spec.torproject.org/tor-spec/subprotocol-versioning.html

use super::{NamedSubver, ProtoKind};
use paste::paste;

/// Helper: define a set of named aliases for specific subprotocol versions
macro_rules! def_named {
    { $( $protocol:ident {
        $(
            $(#[$meta:meta])*
            $subver:ident = $num:expr;
        )*
      })*
    } => {paste!{
        $($(
            $(#[$meta])*
            pub const [<$protocol:upper _ $subver>] : NamedSubver = NamedSubver::new(ProtoKind::$protocol, $num);
        )*)*
    }}
}

def_named! {

    Link {
        /// Obsolete version 1 link protocol.
        ///
        /// This protocol used RSA-based TLS certificate chains with specific properties.
        V1 = 1;
        /// Obsolete version 2 link protocol.
        ///
        /// This protocol used TLS renegotiation.
        V2 = 2;
        /// Version 3 link protocol.
        ///
        /// This protocol uses a single server certificate in TLS,
        /// and then exchanges additional certificates and authentication
        /// within the protocol.
        V3 = 3;
        /// Version 4 link protocol.
        ///
        /// This protocol extends the version 3 link protocol
        /// by changing the length of Circuit IDs from 2 bytes to 4 bytes.
        V4 = 4;
        /// Version 5 link protocol.
        ///
        /// This protocol extends the version 4 link protocol
        /// by adding support for link padding.
        V5 = 5;
    }

    LinkAuth {
        /// TLS authentication based on signing key-exported material with an Ed25519 key.
        ///
        /// ([Specification](https://spec.torproject.org/tor-spec/negotiating-channels.html#Ed25519-SHA256-RFC5705))
        ED25519_SHA256_EXPORTER = 3;
    }

    Relay {
        /// Support for ntor key exchange, CREATE2, CREATED2, EXTEND2, EXTENDED2.
        NTOR = 2;

        /// Support for extending over IPv6 properly using EXTEND2 messages.
        EXTEND_IPv6 = 3;

        /// Support for ntor v3 key exchange, including "extra data" in circuit handshakes
        /// in the format described in
        /// [the "ntor-v3" handshake](https://spec.torproject.org/tor-spec/create-created-cells.md#ntor-v3).
        NTORV3 = 4;

        /// Support for the ntorv3 [protocol request extension][prop346].
        ///
        /// (Reserved.)
        ///
        /// [prop346]: https://spec.torproject.org/proposals/346-protovers-again.html
        NEGOTIATE_SUBPROTO = 5;

        /// Support for counter galois onion relay encryption.
        ///
        /// (Reserved.)
        ///
        /// [prop359]: https://spec.torproject.org/proposals/359-cgo-redux.html
        CRYPT_CGO = 6;
    }

    HSIntro {
        /// Version 3 hidden service introduction point support.
        V3 = 4;

        /// Support for rate-limiting anti-DOS extensions in the`ESTABLISH_INTRO` message.
        RATELIM = 5;
    }

    HSRend {
        /// Support for RENDEZVOUS2 messages of arbitrary length.
        V3 = 2;
    }

    HSDir {
        /// Support for version 3 hidden service descriptors,
        /// including blinded keys.
        V3 = 2;
    }

    DirCache {
        /// Support for consensus diffs.
        CONSDIFF = 2;
    }

    Desc {
        /// Support for signing with ed25519 keys,
        /// and cross-signing with onion keys.
        CROSSSIGN = 2;

        /// Support for parsing relay descriptors without TAP onion-keys (`KP_onion_tap`),
        /// and generating them without TAP onion keys when `publish-dummy-tap-key` is 0.
        NO_TAP = 3;

        /// Support for understanding and building paths according to
        /// the "happy families" design.
        FAMILY_IDS = 4;
    }

    Microdesc {
        /// Support for generating and parsing microdescriptors with Ed25159 identities
        /// (`KP_relayid_ed`)
        ED25519_KEY = 2;

        /// Support for parsing microdescriptors without TAP keys (`KP_onion_tap``).
        NO_TAP = 3;
    }

    Cons {
        /// Support for consensus method 21, which moved ed25519 identity keys (`KP_relayid_ed`)
        /// to microdescriptors.
        ED25519_MDS = 2;
    }

    Padding {
        /// Support for padding machines to hide HS circuit setup patterns.
        MACHINES_CIRC_SETUP = 2;
    }

    FlowCtrl {
        /// Support for authenticated circuit-level SENDME messages.
        AUTH_SENDME = 1;

        /// Support for congestion control.
        CC = 2;
    }

    Conflux {
        /// Support for the core conflux protocol.
        BASE = 1;
    }

}
