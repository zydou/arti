//! [`KeySpecifier`] implementations for hidden service keys.
//!
//! Some of these `KeySpecifier`s represent time-bound keys (that are only valid
//! as long as their time period is relevant). Time-bound keys are expired (removed)
//! by [`expire_publisher_keys`].
//!
//! If you add a new key that is not a per-service singleton, you also need to
//! make arrangements to delete old ones.
//! For TP-based keys, that involves deriving [`HsTimePeriodKeySpecifier`]
//! and adding a call to `remove_if_expired!` in [`expire_publisher_keys`].

use crate::internal_prelude::*;

/// Keys that are used by publisher, which relate to our HS and a TP
///
/// Derived using
/// the derive-deftly macro of the same name.
// We'd like to link to crate::derive_deftly_template_HsTimePeriodKeySpecifier
// but linking to a module-local macro doesn't work with rustdoc.
trait HsTimePeriodKeySpecifier: Debug {
    /// Inspect the nickname
    fn nickname(&self) -> &HsNickname;
    /// Inspect the period
    fn period(&self) -> &TimePeriod;
}

define_derive_deftly! {
    /// Implement `HsTimePeriodKeySpecifier` for a struct with `nickname` and `period`
    HsTimePeriodKeySpecifier:

    impl HsTimePeriodKeySpecifier for $ttype {
      $(
        ${when any(approx_equal($fname, nickname), approx_equal($fname, period))}
        fn $fname(&self) -> &$ftype {
            &self.$fname
        }
      )
    }
}

#[derive(Deftly, PartialEq, Debug, Constructor)]
#[derive_deftly(KeySpecifier)]
#[deftly(prefix = "hss")]
#[deftly(role = "KP_hs_id")]
#[deftly(summary = "Public part of the identity key")]
/// The public part of the identity key of the service.
pub struct HsIdPublicKeySpecifier {
    /// The nickname of the  hidden service.
    nickname: HsNickname,
}

#[derive(Deftly, PartialEq, Debug, Constructor)]
#[derive_deftly(KeySpecifier)]
#[deftly(prefix = "hss")]
#[deftly(role = "KS_hs_id")]
#[deftly(summary = "Long-term identity keypair")]
/// The long-term identity keypair of the service.
pub struct HsIdKeypairSpecifier {
    /// The nickname of the  hidden service.
    pub(crate) nickname: HsNickname,
}

impl From<&HsIdPublicKeySpecifier> for HsIdKeypairSpecifier {
    fn from(hs_id_public_key_specifier: &HsIdPublicKeySpecifier) -> HsIdKeypairSpecifier {
        HsIdKeypairSpecifier::new(hs_id_public_key_specifier.nickname.clone())
    }
}

#[derive(Deftly, PartialEq, Debug, Constructor)]
#[derive_deftly(KeySpecifier, HsTimePeriodKeySpecifier)]
#[deftly(prefix = "hss")]
#[deftly(role = "KS_hs_blind_id")]
#[deftly(summary = "Blinded signing keypair")]
/// The blinded signing keypair.
pub struct BlindIdKeypairSpecifier {
    /// The nickname of the  hidden service.
    pub(crate) nickname: HsNickname,
    #[deftly(denotator)]
    /// The time period associated with this key.
    pub(crate) period: TimePeriod,
}

#[derive(Deftly, PartialEq, Debug, Constructor)]
#[derive_deftly(KeySpecifier, HsTimePeriodKeySpecifier)]
#[deftly(prefix = "hss")]
#[deftly(role = "KP_hs_blind_id")]
#[deftly(summary = "Blinded public key")]
/// The blinded public key.
pub struct BlindIdPublicKeySpecifier {
    /// The nickname of the  hidden service.
    pub(crate) nickname: HsNickname,
    #[deftly(denotator)]
    /// The time period associated with this key.
    pub(crate) period: TimePeriod,
}

impl From<&BlindIdPublicKeySpecifier> for BlindIdKeypairSpecifier {
    fn from(
        hs_blind_id_public_key_specifier: &BlindIdPublicKeySpecifier,
    ) -> BlindIdKeypairSpecifier {
        BlindIdKeypairSpecifier::new(
            hs_blind_id_public_key_specifier.nickname.clone(),
            hs_blind_id_public_key_specifier.period,
        )
    }
}

#[derive(Deftly, PartialEq, Debug, Constructor)]
#[derive_deftly(KeySpecifier, HsTimePeriodKeySpecifier)]
#[deftly(prefix = "hss")]
#[deftly(role = "KS_hs_desc_sign")]
#[deftly(summary = "Descriptor signing key")]
/// The descriptor signing key.
pub struct DescSigningKeypairSpecifier {
    /// The nickname of the  hidden service.
    pub(crate) nickname: HsNickname,
    #[deftly(denotator)]
    /// The time period associated with this key.
    pub(crate) period: TimePeriod,
}

/// Denotates one of the keys, in the context of a particular HS and intro point
#[derive(Debug, Deftly, Eq, PartialEq, strum::Display, strum::EnumString)]
#[strum(serialize_all = "snake_case")]
pub(crate) enum IptKeyRole {
    /// `k_hss_ntor`
    KHssNtor,
    /// `k_hss_ntor`
    KSid,
}

impl KeySpecifierComponentViaDisplayFromStr for IptKeyRole {}

/// Specifies an intro point key
#[derive(Debug, Deftly, Eq, PartialEq)]
#[derive_deftly(KeySpecifier)]
#[deftly(prefix = "hss")]
#[deftly(summary = "introduction point key")]
pub(crate) struct IptKeySpecifier {
    /// nick
    pub(crate) nick: HsNickname,
    /// which key
    #[deftly(fixed_path_component = "ipts")]
    #[deftly(role)]
    pub(crate) role: IptKeyRole,
    /// lid
    #[deftly(denotator)]
    pub(crate) lid: IptLocalId,
}

/// Expire publisher keys for no-longer relevant TPs
pub(crate) fn expire_publisher_keys(
    keymgr: &KeyMgr,
    nickname: &HsNickname,
    relevant_periods: &[HsDirParams],
) -> tor_keymgr::Result<()> {
    // Only remove the keys of the hidden service
    // that concerns us
    let arti_pat = tor_keymgr::KeyPathPattern::Arti(format!("hss/{}/*", &nickname));
    let possibly_relevant_keys = keymgr.list_matching(&arti_pat)?;

    for entry in possibly_relevant_keys {
        let key_path = entry.key_path();
        // Remove the key identified by `spec` if it's no longer relevant
        let remove_if_expired = |spec: &dyn HsTimePeriodKeySpecifier| {
            if spec.nickname() != nickname {
                return Err(internal!(
                    "keymgr gave us key {spec:?} that doesn't match our pattern {arti_pat:?}"
                )
                .into());
            }
            let is_expired = relevant_periods
                .iter()
                .all(|p| &p.time_period() != spec.period());

            if is_expired {
                keymgr.remove_entry(&entry)?;
            }

            tor_keymgr::Result::Ok(())
        };

        /// Remove the specified key, if it's no longer relevant.
        macro_rules! remove_if_expired {
            ($K:ty) => {{
                if let Ok(spec) = <$K>::try_from(key_path) {
                    remove_if_expired(&spec)?;
                }
            }};
        }

        // TODO: any invalid/malformed keys are ignored (rather than
        // removed).
        remove_if_expired!(BlindIdPublicKeySpecifier);
        remove_if_expired!(BlindIdKeypairSpecifier);
        remove_if_expired!(DescSigningKeypairSpecifier);
    }

    Ok(())
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
            "hss/shallot/kp_hs_id"
        );

        let key_spec = HsIdKeypairSpecifier::new(nickname);
        check_key_specifier(&key_spec, "hss/shallot/ks_hs_id");
    }

    #[test]
    fn blind_id_key_specifiers() {
        let nickname = HsNickname::try_from("shallot".to_string()).unwrap();
        let period = TimePeriod::from_parts(1, 2, 3);
        let key_spec = BlindIdPublicKeySpecifier::new(nickname.clone(), period);
        assert_eq!(
            key_spec.arti_path().unwrap().as_str(),
            "hss/shallot/kp_hs_blind_id+2_1_3"
        );

        let key_spec = BlindIdKeypairSpecifier::new(nickname, period);
        check_key_specifier(&key_spec, "hss/shallot/ks_hs_blind_id+2_1_3");
    }

    #[test]
    fn desc_signing_key_specifiers() {
        let nickname = HsNickname::try_from("shallot".to_string()).unwrap();
        let period = TimePeriod::from_parts(1, 2, 3);
        let key_spec = DescSigningKeypairSpecifier::new(nickname, period);
        check_key_specifier(&key_spec, "hss/shallot/ks_hs_desc_sign+2_1_3");
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
            &format!("hss/shallot/ipts/k_hss_ntor+{lid_s}"),
        );
        check_key_specifier(
            &spec(IptKeyRole::KSid),
            &format!("hss/shallot/ipts/k_sid+{lid_s}"),
        );
    }
}
