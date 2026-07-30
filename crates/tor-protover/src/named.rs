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

/// Define a restricted set of subprotocol versions.
///
/// This supports a set of named subprotocols as defined in [`tor_protover::named`](crate::named).
///
/// This is useful when you want to restrict what subprotocol versions are allowed,
/// and also want to be able to exhaustively handle each subprotocol version.
/// If you don't care about (or don't want) the exhaustive property,
/// you might be better off defining a wrapper around [`Protocols`]($crate::Protocols) instead.
///
/// Example:
///
/// ```
/// tor_protover::subprotocol_restricted_set! {
///     #[derive(Copy, Clone, Debug, Default, PartialEq, Eq)]
///     pub(crate) struct SupportedSubprotocols {
///         RELAY_CRYPT_CGO,
///         RELAY_NTORV3,
///     }
/// }
/// ```
///
/// generates a struct of the form:
///
/// ```
/// #[derive(Copy, Clone, Debug, Default, PartialEq, Eq)]
/// pub(crate) struct SupportedSubprotocols {
///     pub(crate) relay_crypt_cgo: bool,
///     pub(crate) relay_ntorv3: bool,
/// }
/// ```
#[macro_export]
macro_rules! subprotocol_restricted_set {
    {
        $(#[$meta:meta])*
        $v:vis struct $name:ident {
            $(
                $(#[$field_meta:meta])*
                $field:ident
            ),* $(,)?
        }
    } => {
        $crate::macro_export::paste::paste!{
            // We don't make this `non_exhaustive` because the goal of this type is to support
            // exhaustively handling all elements.
            $(#[$meta])*
            $v struct $name {
                $(
                    $(#[$field_meta])*
                    #[doc = concat!(
                        "The [`", stringify!($field), "`](",
                        stringify!($crate), "::named::", stringify!($field),
                        ") subprotocol version."
                    )]
                    $v [<$field:lower>]: bool,
                )*
            }

            impl $name {
                /// All subprotocol versions that are supported by this set.
                $v const ALL: Self = Self {$(
                    [<$field:lower>]: true,
                )*};
            }

            impl From<$name> for $crate::Protocols {
                fn from(set: $name) -> Self {
                    Self::from_iter(
                        [$(set.[<$field:lower>].then_some($crate::named::$field)),*]
                        .into_iter()
                        .filter_map(|x| x)
                    )
                }
            }
        }
    };
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
    #![allow(clippy::unchecked_time_subtraction)]
    #![allow(clippy::useless_vec)]
    #![allow(clippy::needless_pass_by_value)]
    #![allow(clippy::string_slice)] // See arti#2571
    //! <!-- @@ end test lint list maintained by maint/add_warning @@ -->

    use crate::Protocols;

    subprotocol_restricted_set! {
        #[derive(Copy, Clone, Debug, Default, PartialEq, Eq)]
        struct SupportedSubprotocols {
            RELAY_CRYPT_CGO,
            RELAY_NTORV3,
        }
    }

    #[test]
    fn restricted_set_constants() {
        assert_eq!(
            SupportedSubprotocols::ALL,
            SupportedSubprotocols {
                relay_crypt_cgo: true,
                relay_ntorv3: true,
            },
        );
    }

    #[test]
    fn restricted_set() {
        let protocols: Protocols = "Relay=4".parse().unwrap();

        assert_eq!(
            Protocols::from(SupportedSubprotocols {
                relay_crypt_cgo: false,
                relay_ntorv3: true,
            }),
            protocols,
        );
    }
}
