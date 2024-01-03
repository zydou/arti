//! [`KeySpecifier`](tor_keymgr::KeySpecifier) implementations for hidden service keys.
//!
//! Some of these `KeySpecifier`s represent time-bound keys (that are only valid
//! as long as their time period is relevant). Time-bound keys are expired (removed)
//! by the [`KeystoreSweeper`](crate::svc::keystore_sweeper::KeystoreSweeper) task.
//! If you add a new time-bound key, you also need to update
//! [`KeystoreSweeper`](crate::svc::keystore_sweeper::KeystoreSweeper::launch)
//! to expire the key when its time-period is no longer relevant.

use derive_adhoc::Adhoc;

use tor_hscrypto::time::TimePeriod;
use tor_keymgr::KeySpecifierComponentViaDisplayFromStr;
use tor_keymgr::{derive_adhoc_template_KeySpecifier};

use crate::HsNickname;
use crate::IptLocalId;

#[derive(Adhoc, PartialEq, Debug)]
#[derive_adhoc(KeySpecifier)]
#[adhoc(prefix = "hs")]
#[adhoc(role = "KP_hs_id")]
#[adhoc(summary = "Public part of the identity key")]
/// The public part of the identity key of the service.
pub struct HsIdPublicKeySpecifier {
    /// The nickname of the  hidden service.
    nickname: HsNickname,
}

#[derive(Adhoc, PartialEq, Debug)]
#[derive_adhoc(KeySpecifier)]
#[adhoc(prefix = "hs")]
#[adhoc(role = "KS_hs_id")]
#[adhoc(summary = "Long-term identity keypair")]
/// The long-term identity keypair of the service.
pub struct HsIdKeypairSpecifier {
    /// The nickname of the  hidden service.
    pub(crate) nickname: HsNickname,
}

#[derive(Adhoc, PartialEq, Debug)]
#[derive_adhoc(KeySpecifier)]
#[adhoc(prefix = "hs")]
#[adhoc(role = "KS_hs_blind_id")]
#[adhoc(summary = "Blinded signing keypair")]
/// The blinded signing keypair.
pub struct BlindIdKeypairSpecifier {
    /// The nickname of the  hidden service.
    pub(crate) nickname: HsNickname,
    #[adhoc(denotator)]
    /// The time period associated with this key.
    pub(crate) period: TimePeriod,
}

#[derive(Adhoc, PartialEq, Debug)]
#[derive_adhoc(KeySpecifier)]
#[adhoc(prefix = "hs")]
#[adhoc(role = "KP_hs_blind_id")]
#[adhoc(summary = "Blinded public key")]
/// The blinded public key.
pub struct BlindIdPublicKeySpecifier {
    /// The nickname of the  hidden service.
    pub(crate) nickname: HsNickname,
    #[adhoc(denotator)]
    /// The time period associated with this key.
    pub(crate) period: TimePeriod,
}

#[derive(Adhoc, PartialEq, Debug)]
#[derive_adhoc(KeySpecifier)]
#[adhoc(prefix = "hs")]
#[adhoc(role = "KS_hs_desc_sign")]
#[adhoc(summary = "Descriptor signing key")]
/// The descriptor signing key.
pub struct DescSigningKeypairSpecifier {
    /// The nickname of the  hidden service.
    pub(crate) nickname: HsNickname,
    #[adhoc(denotator)]
    /// The time period associated with this key.
    pub(crate) period: TimePeriod,
}

/// Denotates one of the keys, in the context of a particular HS and intro point
#[derive(Debug, Adhoc, Eq, PartialEq, strum::Display, strum::EnumString)]
#[strum(serialize_all = "snake_case")]
pub(crate) enum IptKeyRole {
    /// `k_hss_ntor`
    KHssNtor,
    /// `k_hss_ntor`
    KSid,
}

impl KeySpecifierComponentViaDisplayFromStr for IptKeyRole {}

/// Specifies an intro point key
#[derive(Debug, Adhoc, Eq, PartialEq)]
#[derive_adhoc(KeySpecifier)]
#[adhoc(prefix = "hs")]
#[adhoc(summary = "introduction point key")]
pub(crate) struct IptKeySpecifier {
    /// nick
    pub(crate) nick: HsNickname,
    /// which key
    #[adhoc(fixed_path_component = "ipts")]
    #[adhoc(role)]
    pub(crate) role: IptKeyRole,
    /// lid
    #[adhoc(denotator)]
    pub(crate) lid: IptLocalId,
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
    use tor_keymgr::test_utils::check_key_specifier;
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
        check_key_specifier(&key_spec, "hs/shallot/KS_hs_id");
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
        check_key_specifier(&key_spec, "hs/shallot/KS_hs_blind_id+2_1_3");
    }

    #[test]
    fn desc_signing_key_specifiers() {
        let nickname = HsNickname::try_from("shallot".to_string()).unwrap();
        let period = TimePeriod::from_parts(1, 2, 3);
        let key_spec = DescSigningKeypairSpecifier::new(nickname, period);
        check_key_specifier(&key_spec, "hs/shallot/KS_hs_desc_sign+2_1_3");
    }

    #[test]
    fn ipt_key_specifiers() {
        let nick = HsNickname::try_from("shallot".to_string()).unwrap();
        let lid = IptLocalId::dummy(1);
        let spec = |role| IptKeySpecifier {
            nick: nick.clone(),
            lid,
            role,
        };
        let lid_s = "0101010101010101010101010101010101010101010101010101010101010101";
        check_key_specifier(
            &spec(IptKeyRole::KHssNtor),
            &format!("hs/shallot/ipts/k_hss_ntor+{lid_s}"),
        );
        check_key_specifier(
            &spec(IptKeyRole::KSid),
            &format!("hs/shallot/ipts/k_sid+{lid_s}"),
        );
    }
}
