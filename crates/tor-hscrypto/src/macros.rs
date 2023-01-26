//! Macros that we use to define other types in this crate.
//!
//! (These macros are not likely to work outside of the context used in this
//! crate without additional help.)

/// Define a public key type and a private key type to wrap a given inner key.
macro_rules! define_pk_keypair {
    {
        $(#[$meta:meta])* pub struct $pk:ident($pkt:ty) / $(#[$sk_meta:meta])* $sk:ident($skt:ty);
    } => {
        paste::paste!{
            $(#[$meta])*
            #[derive(Clone,Debug,derive_more::From,derive_more::Deref,derive_more::Into,derive_more::AsRef)]
            pub struct $pk ($pkt);

            #[doc = concat!("The private counterpart of a [`", stringify!($pk), "Key'].")]
            $(#[$sk_meta])*
            #[derive(derive_more::From,derive_more::Into,derive_more::AsRef)]
            pub struct $sk ($skt);

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
