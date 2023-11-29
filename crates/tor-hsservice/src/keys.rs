//! [`KeySpecifier`] implementations for hidden service keys.

use derive_adhoc::Adhoc;

use tor_error::into_internal;
use tor_hscrypto::time::TimePeriod;
use tor_keymgr::{derive_adhoc_template_KeySpecifierDefault, KeyPathPattern};
use tor_keymgr::{ArtiPath, ArtiPathUnavailableError, CTorPath, KeySpecifier};

use crate::HsNickname;
use crate::IptLocalId;

#[derive(Adhoc)]
#[derive_adhoc(KeySpecifierDefault)]
#[adhoc(prefix = "hs")]
#[adhoc(role = "KP_hs_id")]
#[adhoc(summary = "The public part of the identity key of the service.")]
/// The public part of the identity key of the service.
pub struct HsIdPublicKeySpecifier {
    /// The nickname of the  hidden service.
    nickname: HsNickname,
}

#[derive(Adhoc)]
#[derive_adhoc(KeySpecifierDefault)]
#[adhoc(prefix = "hs")]
#[adhoc(role = "KS_hs_id")]
#[adhoc(summary = "The long-term identity keypair of the service.")]
/// The long-term identity keypair of the service.
pub struct HsIdKeypairSpecifier {
    /// The nickname of the  hidden service.
    pub(crate) nickname: HsNickname,
}

#[derive(Adhoc)]
#[derive_adhoc(KeySpecifierDefault)]
#[adhoc(prefix = "hs")]
#[adhoc(role = "KS_hs_blind_id")]
#[adhoc(summary = "The blinded signing keypair.")]
/// The blinded signing keypair.
pub struct BlindIdKeypairSpecifier {
    /// The nickname of the  hidden service.
    pub(crate) nickname: HsNickname,
    #[adhoc(denotator)]
    /// The time period associated with this key.
    pub(crate) period: TimePeriod,
}

#[derive(Adhoc)]
#[derive_adhoc(KeySpecifierDefault)]
#[adhoc(prefix = "hs")]
#[adhoc(role = "KP_hs_blind_id")]
#[adhoc(summary = "The blinded public key.")]
/// The blinded public key.
pub struct BlindIdPublicKeySpecifier {
    /// The nickname of the  hidden service.
    pub(crate) nickname: HsNickname,
    #[adhoc(denotator)]
    /// The time period associated with this key.
    pub(crate) period: TimePeriod,
}

#[derive(Adhoc)]
#[derive_adhoc(KeySpecifierDefault)]
#[adhoc(prefix = "hs")]
#[adhoc(role = "KS_hs_desc_sign")]
#[adhoc(summary = "The descriptor signing key.")]
/// The descriptor signing key.
pub struct DescSigningKeypairSpecifier {
    /// The nickname of the  hidden service.
    pub(crate) nickname: HsNickname,
    #[adhoc(denotator)]
    /// The time period associated with this key.
    pub(crate) period: TimePeriod,
}

/// Denotates one of the keys, in the context of a particular HS and intro point
#[derive(Debug, strum::Display)]
#[strum(serialize_all = "snake_case")]
pub(crate) enum IptKeyRole {
    /// `k_hss_ntor`
    KHssNtor,
    /// `k_hss_ntor`
    KSid,
}

/// Specifies an intro point key
#[derive(Debug)]
pub(crate) struct IptKeySpecifier<'s> {
    /// nick
    pub(crate) nick: &'s HsNickname,
    /// lid
    pub(crate) lid: IptLocalId,
    /// which key
    pub(crate) role: IptKeyRole,
}

// TODO HSS soup up the `KeySpecifierDefault` macro to be able to generate this ArtiPath
// (the ArtiPath itself is right, so this ought to change impl but not tests)
impl KeySpecifier for IptKeySpecifier<'_> {
    fn arti_path(&self) -> Result<ArtiPath, ArtiPathUnavailableError> {
        let IptKeySpecifier { nick, lid, role } = self;
        let s = format!("hs/{nick}/ipts/{role}+{lid}");
        Ok(ArtiPath::new(s).map_err(into_internal!("made wrong ArtiPath"))?)
    }
    fn ctor_path(&self) -> Option<CTorPath> {
        None
    }
}

#[cfg(test)]
mod test {
    // @@ begin test lint list maintained by maint/add_warning @@
    #![allow(clippy::bool_assert_comparison)]
    #![allow(clippy::clone_on_copy)]
    #![allow(clippy::dbg_macro)]
    #![allow(clippy::print_stderr)]
    #![allow(clippy::print_stdout)]
    #![allow(clippy::single_char_pattern)]
    #![allow(clippy::unwrap_used)]
    #![allow(clippy::unchecked_duration_subtraction)]
    #![allow(clippy::useless_vec)]
    #![allow(clippy::needless_pass_by_value)]
    //! <!-- @@ end test lint list maintained by maint/add_warning @@ -->
    use super::*;
    use tor_keymgr::KeySpecifier;

    #[test]
    fn hsid_key_specifiers() {
        let nickname = HsNickname::try_from("shallot".to_string()).unwrap();
        let key_spec = HsIdPublicKeySpecifier::new(nickname.clone());
        assert_eq!(
            key_spec.arti_path().unwrap().as_str(),
            "hs/shallot/KP_hs_id"
        );

        let key_spec = HsIdKeypairSpecifier::new(nickname);
        assert_eq!(
            key_spec.arti_path().unwrap().as_str(),
            "hs/shallot/KS_hs_id"
        );
    }

    #[test]
    fn blind_id_key_specifiers() {
        let nickname = HsNickname::try_from("shallot".to_string()).unwrap();
        let period = TimePeriod::from_parts(1, 2, 3);
        let key_spec = BlindIdPublicKeySpecifier::new(nickname.clone(), period);
        assert_eq!(
            key_spec.arti_path().unwrap().as_str(),
            "hs/shallot/KP_hs_blind_id+2_1_3"
        );

        let key_spec = BlindIdKeypairSpecifier::new(nickname, period);
        assert_eq!(
            key_spec.arti_path().unwrap().as_str(),
            "hs/shallot/KS_hs_blind_id+2_1_3"
        );
    }

    #[test]
    fn desc_signing_key_specifiers() {
        let nickname = HsNickname::try_from("shallot".to_string()).unwrap();
        let period = TimePeriod::from_parts(1, 2, 3);
        let key_spec = DescSigningKeypairSpecifier::new(nickname, period);
        assert_eq!(
            key_spec.arti_path().unwrap().as_str(),
            "hs/shallot/KS_hs_desc_sign+2_1_3"
        );
    }

    #[test]
    fn ipt_key_specifiers() {
        let nick = HsNickname::try_from("shallot".to_string()).unwrap();
        let lid = IptLocalId::dummy(1);
        let spec = |role| IptKeySpecifier {
            nick: &nick,
            lid,
            role,
        };
        let lid_s = "0101010101010101010101010101010101010101010101010101010101010101";
        assert_eq!(
            spec(IptKeyRole::KHssNtor).arti_path().unwrap().as_str(),
            format!("hs/shallot/ipts/k_hss_ntor+{lid_s}"),
        );
        assert_eq!(
            spec(IptKeyRole::KSid).arti_path().unwrap().as_str(),
            format!("hs/shallot/ipts/k_sid+{lid_s}"),
        );
    }
}
