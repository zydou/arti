//! Declares macros to help implementing parsers.

// https://github.com/rust-lang/rust-clippy/issues/6860
#![allow(renamed_and_removed_lints, clippy::unknown_clippy_lints)]

/// Macro for declaring a keyword enumeration to help parse a document.
///
/// A keyword enumeration implements the Keyword trait.
///
/// These enums are a bit different from those made by `caret`, in a
/// few ways.  Notably, they are optimized for parsing, they are
/// required to be compact, and they allow multiple strings to be mapped to
/// a single index.
///
/// ```ignore
/// decl_keyword! {
///    Location {
//         "start" => START,
///        "middle" | "center" => MID,
///        "end" => END
///    }
/// }
///
/// assert_eq!(Location::from_str("start"), Location::START);
/// assert_eq!(Location::from_str("stfff"), Location::UNRECOGNIZED);
/// ```
#[allow(unused_macro_rules)]
macro_rules! decl_keyword {
    { $(#[$meta:meta])* $v:vis
      $name:ident { $( $($anno:ident)? $($s:literal)|+ => $i:ident),* $(,)? } } => {
        #[derive(Copy,Clone,Eq,PartialEq,Debug,std::hash::Hash)]
        #[allow(non_camel_case_types)]
        $(#[$meta])*
        #[allow(unknown_lints)]
        // https://github.com/rust-lang/rust-clippy/issues/6860
        #[allow(renamed_and_removed_lints, clippy::unknown_clippy_lints)]
        #[allow(clippy::upper_case_acronyms)]
        $v enum $name {
            $( $i , )*
            UNRECOGNIZED,
            ANN_UNRECOGNIZED
        }
        impl $crate::KeywordEncodable for $name {
            fn to_str(self) -> &'static str {
                use $name::*;
                match self {
                    $( $i => decl_keyword![@impl join $($s),+], )*
                    UNRECOGNIZED => "<unrecognized>",
                    ANN_UNRECOGNIZED => "<unrecognized annotation>"
                }
            }
        }
        impl $crate::parse::keyword::Keyword for $name {
            fn idx(self) -> usize { self as usize }
            fn n_vals() -> usize { ($name::ANN_UNRECOGNIZED as usize) + 1 }
            fn unrecognized() -> Self { $name::UNRECOGNIZED }
            fn ann_unrecognized() -> Self { $name::ANN_UNRECOGNIZED }
            fn from_str(s : &str) -> Self {
                // Note usage of phf crate to create a perfect hash over
                // the possible keywords.  It will be even better if someday
                // the phf crate can find hash functions that are better
                // than siphash.
                const KEYWORD: phf::Map<&'static str, $name> = phf::phf_map! {
                    $( $( $s => $name::$i , )+ )*
                };
                match KEYWORD.get(s) {
                    Some(k) => *k,
                    None => if s.starts_with('@') {
                        $name::ANN_UNRECOGNIZED
                    } else {
                        $name::UNRECOGNIZED
                    }
                }
            }
            fn from_idx(i : usize) -> Option<Self> {
                // Note looking up the value in a vec.  This may or may
                // not be faster than a case statement would be.
                static VALS: std::sync::LazyLock<Vec<$name>> =
                    std::sync::LazyLock::new(
                        || vec![ $($name::$i , )*
                              $name::UNRECOGNIZED,
                                 $name::ANN_UNRECOGNIZED ]);
                VALS.get(i).copied()
            }
            fn is_annotation(self) -> bool {
                use $name::*;
                match self {
                    $( $i => decl_keyword![@impl is_anno $($anno)? ], )*
                    UNRECOGNIZED => false,
                    ANN_UNRECOGNIZED => true,
                }
            }
        }
    };
    [ @impl is_anno annotation ] => ( true );
    [ @impl is_anno $x:ident ] => ( compile_error!("unrecognized keyword; not annotation") );
    [ @impl is_anno ] => ( false );
    [ @impl join $s:literal ] => ( $s );
    [ @impl join $s:literal , $($ss:literal),+ ] => (
        concat! { $s, "/", decl_keyword![@impl join $($ss),*] }
    );
}

#[cfg(test)]
pub(crate) mod test {
    #![allow(clippy::cognitive_complexity)]

    use crate::KeywordEncodable;

    decl_keyword! {
        pub(crate) Fruit {
            "apple" => APPLE,
            "orange" => ORANGE,
            "lemon" => LEMON,
            "guava" => GUAVA,
            "cherry" | "plum" => STONEFRUIT,
            "banana" => BANANA,
            annotation "@tasty" => ANN_TASTY,
        }
    }

    #[test]
    fn kwd() {
        use crate::parse::keyword::Keyword;
        use Fruit::*;
        assert_eq!(Fruit::from_str("lemon"), LEMON);
        assert_eq!(Fruit::from_str("cherry"), STONEFRUIT);
        assert_eq!(Fruit::from_str("plum"), STONEFRUIT);
        assert_eq!(Fruit::from_str("pear"), UNRECOGNIZED);
        assert_eq!(Fruit::from_str("@tasty"), ANN_TASTY);
        assert_eq!(Fruit::from_str("@tastier"), ANN_UNRECOGNIZED);

        assert_eq!(APPLE.idx(), 0);
        assert_eq!(ORANGE.idx(), 1);
        assert_eq!(ANN_UNRECOGNIZED.idx(), 8);
        assert_eq!(Fruit::n_vals(), 9);

        assert_eq!(Fruit::from_idx(0), Some(APPLE));
        assert_eq!(Fruit::from_idx(8), Some(ANN_UNRECOGNIZED));
        assert_eq!(Fruit::from_idx(9), None);

        assert_eq!(Fruit::idx_to_str(3), "guava");
        assert_eq!(Fruit::idx_to_str(999), "<out of range>");

        assert_eq!(APPLE.to_str(), "apple");
        assert_eq!(GUAVA.to_str(), "guava");
        assert_eq!(ANN_TASTY.to_str(), "@tasty");
        assert_eq!(STONEFRUIT.to_str(), "cherry/plum");
        assert_eq!(UNRECOGNIZED.to_str(), "<unrecognized>");
        assert_eq!(ANN_UNRECOGNIZED.to_str(), "<unrecognized annotation>");

        assert!(!GUAVA.is_annotation());
        assert!(!STONEFRUIT.is_annotation());
        assert!(!UNRECOGNIZED.is_annotation());
        assert!(ANN_TASTY.is_annotation());
        assert!(ANN_UNRECOGNIZED.is_annotation());
    }
}
