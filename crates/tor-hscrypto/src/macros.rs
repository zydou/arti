//! Macros that we use to define other types in this crate.
//!
//! (These macros are not likely to work outside of the context used in this
//! crate without additional help.)

/// Define a public key type and a private key type to wrap a given inner key.
//
// TODO This macro needs proper formal documentation of its its input syntax and semantics.
// (Possibly the input syntax ought to be revisited.)
macro_rules! define_pk_keypair {
    {
        $(#[$meta:meta])* pub struct $pk:ident($pkt:ty) / $(#[$sk_meta:meta])* $sk:ident($skt:ty);
        $($(#[$p_meta:meta])* curve25519_pair as $pair:ident;)?
    } => {
        paste::paste!{
            $(#[$meta])*
            #[derive(Clone,Debug,derive_more::From,derive_more::Deref,derive_more::Into,derive_more::AsRef)]
            pub struct $pk ($pkt);

            #[doc = concat!("The private counterpart of a [`", stringify!($pk), "Key'].")]
            $(#[$sk_meta])*
            #[derive(derive_more::From, derive_more::Into, derive_more::AsRef)]
            pub struct $sk ($skt);

            impl std::fmt::Debug for $sk
            {
                fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                    f.write_str(concat!(stringify!($pk), "SecretKey(...)"))
                }
            }

            // For curve25519 keys, we are willing to handle secret keys without
            // a corresponding public key, since there is not a cryptographic
            // risk inherent in our protocols to getting them mixed up.
            //
            // But that means that it sometimes _is_ worthwhile defining a
            // keypair type.
            $(
                #[doc = concat!("A pair of a public and private components for a [`", stringify!($pk), "`].")]
                $(#[$p_meta])*
                #[derive(Debug)]
                pub struct $pair {
                    public: $pk,
                    secret: $sk,
                }
                impl $pair {
                    /// Construct this keypair from a public key and a secret key.
                    pub fn new(public: $pk, secret: $sk) -> Self {
                        Self { public, secret }
                    }
                    /// Construct this keypair from a secret key.
                    pub fn from_secret_key(secret: $sk) -> Self {
                        let public:$pk = $pkt::from(&secret.0).into();
                        Self { public, secret }
                    }
                    /// Return the public part of this keypair.
                    pub fn public(&self) -> &$pk { &self.public }
                    /// Return the secret part of this keypair.
                    pub fn secret(&self) -> &$sk { &self.secret }
                    /// Generate a new keypair from a secure random number generator.
                    //
                    // TODO: this should be implemented in terms of
                    // `<curve25519::StaticSecret as tor_keymgr::Keygen>` and
                    // `<$pair as From<curve25519::StaticKeypair>>`
                    // See https://gitlab.torproject.org/tpo/core/arti/-/issues/1137#note_2969181
                    pub fn generate<R>(rng: &mut R) -> Self
                    where
                        R: rand::Rng + rand::CryptoRng,
                    {
                        let secret = curve25519::StaticSecret::random_from_rng(rng);
                        let public: curve25519::PublicKey = (&secret).into();
                        Self {
                            secret: secret.into(),
                            public: public.into(),
                        }
                    }
                }
                impl From<curve25519::StaticKeypair> for $pair {
                    fn from(input: curve25519::StaticKeypair) -> $pair {
                        $pair {
                            secret: input.secret.into(),
                            public: input.public.into(),
                        }
                    }
                }
                impl From<$pair> for curve25519::StaticKeypair {
                    fn from(input: $pair) -> curve25519::StaticKeypair {
                        curve25519::StaticKeypair {
                            secret: input.secret.into(),
                            public: input.public.into(),
                        }
                    }
                }
            )?
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
    impl tor_bytes::Readable for $name {
        fn take_from(r: &mut tor_bytes::Reader<'_>) -> tor_bytes::Result<Self> {
            Ok(Self::new(r.extract()?))
        }
    }
    impl tor_bytes::Writeable for $name {
        fn write_onto<B:tor_bytes::Writer+?Sized>(&self, w: &mut B) -> tor_bytes::EncodeResult<()> {
            w.write_all(&self.0.as_ref()[..]);
            Ok(())
        }
    }
}
}

pub(crate) use {define_bytes, define_pk_keypair};
