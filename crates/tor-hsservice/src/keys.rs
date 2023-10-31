//! [`KeySpecifier`] implementations for hidden service keys.

use tor_hscrypto::time::TimePeriod;
use tor_keymgr::{define_key_specifier, KeyPathPattern};

use crate::HsNickname;

/// A helper for defining service [`KeySpecifier`]s.
///
/// This macro creates a `key_spec` struct that in addition to the specified fields and denotators,
/// also contains an `&HsNickname` field. The `prefix` value of the resulting `key_spec` is
/// set to `"hs"`.
///
/// The resulting `key_spec` implements [`KeySpecifier`](tor_keymgr::KeySpecifier).
///
/// This is essentially a convenience  wrapper around [`define_key_specifier`],
/// which inserts the `&HsNickname` field (which is common to all service key specifiers)
/// into the struct.
macro_rules! define_svc_key_specifier {
    {
        #[role = $role:expr]
        $( #[ $($attrs:meta)* ] )*
        $vis:vis struct $key_spec:ident $( [ $($gen:tt)+ ] )?
        $( where [ $($where_clauses:tt)* ] )?
        {
            #[denotator]
            $( #[ $($denotator_attrs:meta)* ] )*
            $denotator:ident : $denotator_ty:ty,

            $(
                $( #[ $($field_attrs:meta)* ] )*
                $field:ident : $field_ty:ty,
            )*
        }
    } => {
        define_key_specifier! {
            #[prefix = "hs"]
            #[role = $role]
            $(#[ $($attrs)* ])*
            $vis struct $key_spec [ 'a $(, $($gen)+ )? ]
            $( where $($where_clauses)* )?
            {
                #[denotator]
                $( #[ $($denotator_attrs)* ] )*
                $denotator: $denotator_ty,

                /// The nickname of the  hidden service.
                nickname: &'a HsNickname,

                $(
                    $( #[ $($field_attrs)* ] )*
                    $field: $field_ty,
                )*

            }
        }
    };

    {
        #[role = $role:expr]
        $( #[ $($attrs:meta)* ] )*
        $vis:vis struct $key_spec:ident $( [ $($gen:tt)+ ] )?
        $( where [ $($where_clauses:tt)* ] )?
        {
            $(
                $( #[ $($field_attrs:meta)* ] )*
                $field:ident : $field_ty:ty,
            )*
        }
    } => {
        define_key_specifier! {
            #[prefix = "hs"]
            #[role = $role]
            $(#[ $($attrs)* ])*
            $vis struct $key_spec [ 'a $(, $($gen)+ )? ]
            $( where $($where_clauses)* )?
            {
                /// The nickname of the  hidden service.
                nickname: &'a HsNickname,

                $(
                    $( #[ $($field_attrs)* ] )*
                    $field: $field_ty,
                )*
            }
        }
    };
}

define_svc_key_specifier! {
    #[role = "KP_hs_id"]
    /// The public part of the identity key of the service.
    pub struct HsIdPublicKeySpecifier  {}
}

define_svc_key_specifier! {
    #[role = "KS_hs_id"]
    /// The long-term identity keypair of the service.
    pub struct HsIdKeypairSpecifier  {}
}

define_svc_key_specifier! {
    #[role = "KS_hs_blind_id"]
    /// The blinded signing keypair.
    pub struct BlindIdKeypairSpecifier  {
        #[denotator]
        /// The time period associated with this key.
        period: TimePeriod,
    }
}

define_svc_key_specifier! {
    #[role = "KP_hs_blind_id"]
    /// The blinded public key.
    pub struct BlindIdPublicKeySpecifier  {
        #[denotator]
        /// The time period associated with this key.
        period: TimePeriod,
    }
}

define_svc_key_specifier! {
    #[role = "KS_hs_desc_sign"]
    /// The descriptor signing key.
    pub struct DescSigningKeypairSpecifier  {
        #[denotator]
        /// The time period associated with this key.
        period: TimePeriod,
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
        let key_spec = HsIdPublicKeySpecifier::new(&nickname);
        assert_eq!(
            key_spec.arti_path().unwrap().as_str(),
            "hs/shallot/KP_hs_id"
        );

        let key_spec = HsIdKeypairSpecifier::new(&nickname);
        assert_eq!(
            key_spec.arti_path().unwrap().as_str(),
            "hs/shallot/KS_hs_id"
        );
    }

    #[test]
    fn blind_id_key_specifiers() {
        let nickname = HsNickname::try_from("shallot".to_string()).unwrap();
        let period = TimePeriod::from_parts(1, 2, 3);
        let key_spec = BlindIdPublicKeySpecifier::new(&nickname, period);
        assert_eq!(
            key_spec.arti_path().unwrap().as_str(),
            "hs/shallot/KP_hs_blind_id_2_1_3"
        );

        let key_spec = BlindIdKeypairSpecifier::new(&nickname, period);
        assert_eq!(
            key_spec.arti_path().unwrap().as_str(),
            "hs/shallot/KS_hs_blind_id_2_1_3"
        );
    }

    #[test]
    fn desc_signing_key_specifiers() {
        let nickname = HsNickname::try_from("shallot".to_string()).unwrap();
        let period = TimePeriod::from_parts(1, 2, 3);
        let key_spec = DescSigningKeypairSpecifier::new(&nickname, period);
        assert_eq!(
            key_spec.arti_path().unwrap().as_str(),
            "hs/shallot/KS_hs_desc_sign_2_1_3"
        );
    }
}
