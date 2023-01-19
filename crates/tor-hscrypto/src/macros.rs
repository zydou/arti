//! Macros that we use to define other types in this crate.
//!
//! (These macros are not likely to work outside of the context used in this
//! crate without additional help.)

/// Define a public key type and a private key type to wrap a given inner key.
macro_rules! define_pk_keypair {
    {
        $(#[$meta:meta])* pub struct $pk:ident($pkt:ty) / $sk:ident($skt:ty);
    } => {
        paste::paste!{
            $(#[$meta])*
            #[derive(Clone,Debug)]
            pub struct $pk ($pkt);

            impl AsRef<$pkt> for $pk {
                fn as_ref(&self) -> &$pkt {
                    &self.0
                }
            }
            impl From<$pkt> for $pk {
                fn from(inp: $pkt) -> Self {
                    Self(inp)
                }
            }
            impl From<$pk> for $pkt {
                fn from(inp: $pk) -> Self {
                    inp.0
                }
            }

            #[doc = concat!("The private counterpart of a [`", stringify!($pk), "Key'].")]
            pub struct $sk ($skt);

            impl AsRef<$skt> for $sk {
                fn as_ref(&self) -> &$skt {
                    &self.0
                }
            }
            impl From<$skt> for $sk {
                fn from(inp: $skt) -> Self {
                    Self(inp)
                }
            }
            impl From<$sk> for $skt {
                fn from(inp: $sk) -> $skt {
                    inp.0
                }
            }
            impl std::fmt::Debug for $sk
            {
                fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                    f.write_str(concat!(stringify!($pk), "SecretKey(...)"))
                }
            }

        }
    };
}

/// Define a wrapper type around a byte array of fixed length.
///
/// (Internally, it uses a [`CtByteArray`](tor_llcrypto::util::ct::CtByteArray),
/// so it's safe to derive Ord, Eq, etc.)
macro_rules! define_bytes {
{ $(#[$meta:meta])* pub struct $name:ident([u8 ; $n:expr]); } =>
{
    $(#[$meta])*
    pub struct $name(tor_llcrypto::util::ct::CtByteArray<$n>);

    impl $name {
        fn new(inp: [u8;$n]) -> Self {
            Self(inp.into())
        }
    }
    impl AsRef<[u8;$n]> for $name {
        fn as_ref(&self) -> &[u8;$n] {
            self.0.as_ref()
        }
    }
    impl From<[u8;$n]> for $name {
        fn from(inp: [u8;$n]) -> Self {
            Self::new(inp)
        }
    }
    impl From<$name> for [u8;$n] {
        fn from(inp: $name) -> [u8;$n] {
            inp.0.into()
        }
    }
}
}

pub(crate) use {define_bytes, define_pk_keypair};
