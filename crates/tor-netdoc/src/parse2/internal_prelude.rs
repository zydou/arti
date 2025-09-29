//! Prelude used internally for everything in `parse2`.
//!
//! This is also exported, but with `#[doc(hidden)]`, for the benefit of our public macros.

pub use std::collections::HashSet;
pub use std::fmt::Debug;
pub use std::io::Write as _;
pub use std::marker::PhantomData;
pub use std::mem;
pub use std::ops::RangeInclusive;
pub use std::result::Result;
pub use std::slice;
pub use std::str::FromStr;
pub use std::time::{Duration, SystemTime};

pub use derive_deftly::{Deftly, define_derive_deftly};
pub use digest::Digest;
pub use educe::Educe;
pub use itertools::Itertools;
pub use paste::paste;
pub use thiserror::Error;
pub use void::Void;

pub use tor_llcrypto::pk;

pub const PEM_HEADER_START: &str = crate::parse::tokenize::object::BEGIN_STR;
pub const PEM_FOOTER_START: &str = crate::parse::tokenize::object::END_STR;
pub const PEM_AFTER_LABEL: &str = crate::parse::tokenize::object::TAG_END;

pub use super::{
    error::{ErrorProblem, ParseError, VerifyFailed},
    keyword::KeywordRef,
    lex::{ArgumentStream, ItemStream, UnparsedItem, WS},
    lines::{Lines, StrExt as _},
    multiplicity::{ArgumentSetMethods, ArgumentSetSelector, ItemSetMethods, ItemSetSelector},
    signatures::{
        SignatureHashInputs, SignatureItemParseable, SignedDocumentBody, sig_hash_methods,
    },
    structural::{StopAt, StopPredicate},
    traits::{
        ItemArgumentParseable, ItemValueParseable, NetdocParseable, NetdocParseableFields,
        NetdocSigned,
    },
};
pub use crate::{netdoc_ordering_check, stop_at};

pub use ErrorProblem as EP;
pub use VerifyFailed as VF;
