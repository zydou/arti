//! Serde support for [`TrustedUser`] and [`TrustedGroup`].

use super::{TrustedGroup, TrustedUser};
use serde::{Deserialize, Serialize};
use std::{convert::TryFrom, ffi::OsString};

/// Helper type: when encoding or decoding a group or user, we do so as one of
/// these.
///
/// It's an `untagged` enumeration, so every case must be uniquely identifiable
/// by type or by keywords.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(untagged)]
pub(super) enum Serde {
    /// A boolean value.
    ///
    /// "false" means "no user", and is the same as "none".
    ///
    /// "true" is not allowed.
    Bool(bool),
    /// A string given in quotes.
    ///
    /// If this starts with ":" it will be interpreted as a special entity (e.g.
    /// ":current" or ":username"). Otherwise, it will be interpreted as a name.
    ///  
    Str(String),
    /// An integer provided without any identification.
    ///
    /// This will be interpreted as a UID or GID.
    Num(u32),
    /// A name, explicitly qualified as such.
    Name {
        /// The name in question.
        ///
        /// Even if this begins with ":", it is still interpreted as a name.
        name: String,
    },
    /// A username that cannot be represented as a String.
    Raw {
        /// The username in question.
        raw_name: OsString,
    },
    /// A special entity.
    Special {
        /// The name of the special entity. Starts with ":".
        special: String,
    },
    /// A UID or GID, explicitly qualified as such.
    Id {
        /// The UID or GID.
        id: u32,
    },
}

impl Serde {
    /// Convert this [`Serde`] into a less ambiguous form.
    ///
    /// Removes all Num and Str cases from the output, replacing them with
    /// Special/Name/Id as appropriate.
    fn disambiguate(self) -> Self {
        match self {
            Serde::Str(s) if s.starts_with(':') => Self::Special { special: s },
            Serde::Str(s) => Self::Name { name: s },
            Serde::Num(id) => Self::Id { id },
            other => other,
        }
    }
}

/// Helper: declare
macro_rules! implement_serde {
   { $struct:ident { $( $case:ident => $str:expr, )* [ $errcase:ident ] } } => {

    impl $struct {
        /// Try to decode a "special-user" string from `s`, for serde.
        fn from_special_str(s: &str) -> Result<Self, crate::Error> {
            match s {
                $( $str => Ok($struct::$case), )*
                _ => Err(crate::Error::$errcase(s.to_owned())),
            }
        }
        fn from_boolean(b: bool) -> Result<Self, crate::Error> {
            if b {
                Err(crate::Error::$errcase("'true'".into()))
            } else {
                Self::from_special_str(":none")
            }
        }
    }

    impl From<$struct> for Serde {
        fn from(value: $struct) -> Self {
            match value {
                $struct::Id(id) => Self::Num(id),
                $struct::Name(name) => {
                    if let Some(name) = name.to_str() {
                        let name = name.to_string();
                        if name.starts_with(':') {
                            Self::Name { name }
                        } else {
                            Self::Str(name)
                        }
                    } else {
                        Self::Raw { raw_name: name }
                    }
                }
                $(
                    $struct::$case => Self::Str($str.to_owned())
                ),*
            }
        }
    }

    impl TryFrom<Serde> for $struct {
        type Error = crate::Error;
        fn try_from(ent: Serde) -> Result<Self, Self::Error> {
            Ok(match ent.disambiguate() {
                Serde::Str(_) | Serde::Num(_) => {
                    panic!("These should have been caught by disambiguate.")
                }
                Serde::Bool(b) => $struct::from_boolean(b)?,
                Serde::Name { name } => $struct::Name(name.into()),
                Serde::Raw { raw_name } => $struct::Name(raw_name),
                Serde::Special { special } => {
                    $struct::from_special_str(special.as_ref())?
                }
                Serde::Id { id } => $struct::Id(id),
            })
        }
    }
}}

implement_serde! { TrustedUser {
    None => ":none",
    Current => ":current",
    [NoSuchUser]
}}

implement_serde! { TrustedGroup {
    None => ":none",
    SelfNamed => ":username",
    [NoSuchGroup]
}}

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

    #[derive(Serialize, Deserialize, Debug, Clone, Eq, PartialEq)]
    struct Chum {
        handle: TrustedUser,
        team: TrustedGroup,
    }

    #[test]
    fn round_trips() {
        let examples: Vec<(&'static str, &'static str, Chum)> = vec![
            (
                r#"handle = "gardenGnostic"
                   team = 413
                  "#,
                r#"{ "handle": "gardenGnostic", "team": 413 }"#,
                Chum {
                    handle: TrustedUser::Name("gardenGnostic".into()),
                    team: TrustedGroup::Id(413),
                },
            ),
            (
                r#"handle = "413"
                   team = false
                  "#,
                r#"{ "handle": "413", "team": false }"#,
                Chum {
                    handle: TrustedUser::Name("413".into()),
                    team: TrustedGroup::None,
                },
            ),
            (
                r#"handle = { id = 8 }
                   team = { name = "flarp" }
                 "#,
                r#"{ "handle": { "id": 8 }, "team" : { "name" : "flarp" } }"#,
                Chum {
                    handle: TrustedUser::Id(8),
                    team: TrustedGroup::Name("flarp".into()),
                },
            ),
            (
                r#"handle = ":current"
                   team = ":username"
                 "#,
                r#"{ "handle": ":current", "team" : ":username" }"#,
                Chum {
                    handle: TrustedUser::Current,
                    team: TrustedGroup::SelfNamed,
                },
            ),
            (
                r#"handle = { special = ":none" }
                   team = { special = ":none" }
                 "#,
                r#"{ "handle": {"special" : ":none"}, "team" : { "special" : ":none"} }"#,
                Chum {
                    handle: TrustedUser::None,
                    team: TrustedGroup::None,
                },
            ),
            (
                r#"handle = { name = ":none" }
                   team = { name = ":none" }
                 "#,
                r#"{ "handle": {"name" : ":none"}, "team" : { "name" : ":none"} }"#,
                Chum {
                    handle: TrustedUser::Name(":none".into()),
                    team: TrustedGroup::Name(":none".into()),
                },
            ),
        ];

        for (toml_string, json_string, chum) in examples {
            let toml_obj: Chum = toml::from_str(toml_string).unwrap();
            let json_obj: Chum = serde_json::from_str(json_string).unwrap();
            assert_eq!(&toml_obj, &chum);
            assert_eq!(&json_obj, &chum);

            let s = toml::to_string(&chum).unwrap();
            let toml_obj2: Chum = toml::from_str(&s).unwrap();
            assert_eq!(&toml_obj2, &chum);

            let s = serde_json::to_string(&chum).unwrap();
            let json_obj2: Chum = serde_json::from_str(&s).unwrap();
            assert_eq!(&json_obj2, &chum);
        }
    }

    #[cfg(target_family = "unix")]
    #[test]
    fn os_string() {
        // Try round-tripping a username that isn't UTF8.
        use std::os::unix::ffi::OsStringExt as _;
        let not_utf8 = OsString::from_vec(vec![255, 254, 253, 252]);
        assert!(not_utf8.to_str().is_none());
        let chum = Chum {
            handle: TrustedUser::Name(not_utf8.clone()),
            team: TrustedGroup::Name(not_utf8),
        };

        // Alas, we cannot serialize an OsString in Toml. serde thinks that an
        // OsString should be represented using `serialize_newtype_variant`, and
        // the toml crate doesn't support that method.
        //
        //let toml_result = toml::to_string(&chum);
        //assert!(toml_result.is_err());

        let s = serde_json::to_string(&chum).unwrap();
        let toml_obj: Chum = serde_json::from_str(&s).unwrap();
        assert_eq!(&toml_obj, &chum);
    }

    #[test]
    fn bad_names() {
        let s = r#"handle = 413
            team = false"#;
        let r: Result<Chum, _> = toml::from_str(s);
        assert!(r.is_ok());

        let s = r#"handle = true
            team = false"#;
        let r: Result<Chum, _> = toml::from_str(s);
        assert!(r.is_err());

        let s = r#"handle = ":foo"
            team = false"#;
        let r: Result<Chum, _> = toml::from_str(s);
        assert!(r.is_err());
    }
}
