//! This module defines the key types that can be written to a [`Keystore`](crate::Keystore).

// @Diziet's notes regarding why we shouldn't be storing public keys in the key store:
//
// "Let me talk through, a bit, why we have public keys here.
//
// ISTM that primarily, a keystore is a store of secrets (ie, things we use to demonstrate to other
// people).  Ie it corresponds to our identities.  It's not a registry of public data (including
// instructions about who to trust for what).
//
// But we do need to store some ancillary data with some of our identities.  Where this data is
// small or convenient, we can put it into the keystore.  And when we do that we can use the same
// storage format as we use for private keys?  (That's not actually true: openssh private keys and
// openssh public keys are different formats.)
//
// Which public keys are you anticipating storing here?
//
// I would like to rule out, at this stage, using the Arti keystore to store the public keys of
// clients for our HS.  That is, the HS client authentication keys for a particular HS should be
// stored, for that HS, outside the keystore.  (IIRC C Tor does keep the client auth public keys
// for an HS in its keystore, so we need to be compatible with that, but that doesn't necessary
// have to be done in Arti via the keystore API.  Perhaps the "C Tor keystore" object could
// implement both the keystore trait and an "HS client public keys" trait.)
//
// I should explain why I have this opinion:
// Basically, (private) keystores are awkward.  They have to handle private key material, deal with
// privsep (possibly including offline hosts); they have to be transparent and manipulable, but
// also secure.  They might need to be implemented by or associated with HSMs.  All of these things
// make the keystore's APIs (both the caller API and the visible filesystem interface) compromises
// with nontrivial downsides.
//
// Whereas data about who we should trust is totally different.  It can live in normal
// configuration land; it doesn't need to be associated with HSMs.  It doesn't want or need (the
// possibility of) privsep.  And the user might want to override/supplement it in totally different
// ways.  For example, it should be possible for an HS server to look up client authentication keys
// in a database.  But we don't need or want to write a generic "look up stuff in a database" API;
// that can be (at least for now) a bespoke API just for HS client auth."

pub(crate) mod ssh;

/// A type of key stored in the key store.
#[derive(Copy, Clone, Debug, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum KeyType {
    /// An Ed25519 keypair.
    Ed25519Keypair,
    /// A Curve25519 secret key.
    X25519StaticSecret,
    // ...plus all the other key types we're interested in (TODO)
}

impl KeyType {
    /// The file extension for a key of this type.
    //
    // TODO HSS: this is subject to change (i.e. we might also need a `KeySpecifier` argument here
    // to decide the file extension should be).
    pub fn arti_extension(&self) -> &'static str {
        match self {
            KeyType::Ed25519Keypair => "ed25519_private",
            KeyType::X25519StaticSecret => "x25519_private",
        }
    }

    /// The file extension for a key of this type, for use in a C Tor key store.
    //
    // TODO HSS: this is subject to change (i.e. we might also need a `KeySpecifier` argument here
    // to decide the file extension should be).
    pub fn ctor_extension(&self) -> &'static str {
        todo!() // TODO HSS
    }
}
