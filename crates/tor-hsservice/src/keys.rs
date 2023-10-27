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
