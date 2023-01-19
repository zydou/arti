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

pub(crate) use define_pk_keypair;
