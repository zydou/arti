//! Declare a restricted variant of our message types.

/// Re-export tor_bytes and paste here, so that the macro can use it.
pub use {paste, tor_bytes};

/// Declare a restricted version of
/// [`AnyRelayMsg`](crate::relaycell::msg::AnyRelayMsg) or
/// [`AnyChanMsg`](crate::chancell::msg::AnyChanMsg).
///
/// Frequently we only want to handle a subset of the possible channel or relay
/// commands that we might see.  In those situations, it makes sense to define a
/// a message types that will only try to parse the allowable commands.  That way,
/// we can avoid exposing any unnecessary parsers to a possible attacker.
///
/// The restricted message type is an enum, and is declared with a syntax as follows:
/// ```
/// use tor_cell::{restrict::restricted_msg, relaycell::RelayMsgOuter};
///
/// restricted_msg! {
///     enum OpenStreamMsg : RelayMsg {
///         Data,
///         Sendme,
///         End,
///         _ => Unrecognized,
///    }
/// }
///
/// type OpenStreamMsgOuter = RelayMsgOuter<OpenStreamMsg>;
/// ```
///
/// Instead of `RelayMsg`, you can say `ChanMsg` to get a restricted channel
/// message.
///
/// Only message variants exposed from the `tor_cell::{chan,relay}cell::msg` are
/// supported.
///
/// You can omit the `_ => Unrecognized` clause at the end.  If you do, then any
/// unexpected command types will be treated as a parse error.
#[macro_export]
macro_rules! restricted_msg {
    {
        $(#[$meta:meta])*
        $(@omit_from $omit_from:literal)?
        $v:vis enum $name:ident : RelayMsg {
            $($tt:tt)*
        }
    } => {
        $crate::restrict::restricted_msg!{
            [
            any_type: $crate::relaycell::msg::AnyRelayMsg,
            msg_mod: $crate::relaycell::msg,
            cmd_type: $crate::relaycell::RelayCmd,
            unrecognized: $crate::relaycell::msg::Unrecognized,
            body_trait: $crate::relaycell::msg::Body,
            msg_trait: $crate::relaycell::RelayMsg,
            omit_from: $($omit_from)?
            ]
            $(#[$meta])*
            $v enum $name { $($tt)*}
        }
    };
    {
        $(#[$meta:meta])*
        $(@omit_from $omit_from:literal)?
        $v:vis enum $name:ident : ChanMsg {
            $($tt:tt)*
        }
    } => {
        $crate::restrict::restricted_msg!{
            [
            any_type: $crate::chancell::msg::AnyChanMsg,
            msg_mod: $crate::chancell::msg,
            cmd_type: $crate::chancell::ChanCmd,
            unrecognized: $crate::chancell::msg::Unrecognized,
            body_trait: $crate::chancell::msg::Body,
            msg_trait: $crate::chancell::ChanMsg,
            omit_from: $($omit_from)?
            ]
            $(#[$meta])*
            $v enum $name { $($tt)*}
        }
    };
    {
        [
          any_type: $any_msg:ty,
          msg_mod: $msg_mod:path,
          cmd_type: $cmd_type:ty,
          unrecognized: $unrec_type:ty,
          body_trait: $body_type:ty,
          msg_trait: $msg_trait:ty,
          omit_from: $($omit_from:literal)?
        ]
        $(#[$meta:meta])*
        $v:vis enum $name:ident {
            $(
                $(#[$case_meta:meta])*
                $([feature=$feat:literal])?
                $case:ident
            ),*
            $(, _ =>
                $(#[$unrec_meta:meta])*
                $unrecognized:ident )?
            $(,)?
        }
    } => {
    $crate::restrict::paste::paste!{
        $(#[$meta])*
        $v enum $name {
            $(
                $(#[$case_meta])*
                $( #[cfg(feature=$feat)] )?
                $case($msg_mod :: $case),
            )*
            $(
                $(#[$unrec_meta])*
                $unrecognized($unrec_type)
            )?
        }

        impl $msg_trait for $name {
            fn cmd(&self) -> $cmd_type {
                match self {
                    $(
                        $( #[cfg(feature=$feat)] )?
                        Self::$case(_) => $cmd_type:: [<$case:snake:upper>] ,
                    )*
                    $(
                        Self::$unrecognized(u) => u.cmd(),
                    )?
                }
            }

             fn encode_onto<W:>(self, w: &mut W) -> $crate::restrict::tor_bytes::EncodeResult<()>
             where
                W: $crate::restrict::tor_bytes::Writer + ?Sized
             {
                match self {
                    $(
                        $( #[cfg(feature=$feat)] )?
                        Self::$case(m) => $body_type::encode_onto(m, w),
                    )*
                    $(
                        Self::$unrecognized(u) => $body_type::encode_onto(u, w),
                    )?
                }
            }

            fn decode_from_reader(cmd: $cmd_type, r: &mut $crate::restrict::tor_bytes::Reader<'_>) -> $crate::restrict::tor_bytes::Result<Self> {
                Ok(match cmd {
                    $(
                        $( #[cfg(feature=$feat)] )?
                        $cmd_type:: [<$case:snake:upper>] => Self::$case( <$msg_mod :: $case as $body_type> :: decode_from_reader(r)? ),
                    )*
                    $(
                        _ => Self::$unrecognized($unrec_type::decode_with_cmd(cmd, r)?),
                    )?
                    #[allow(unreachable_patterns)] // This is unreachable if we had an Unrecognized variant above.
                    _ => return Err($crate::restrict::tor_bytes::Error::InvalidMessage(
                        format!("Unexpected command {} in {}", cmd, stringify!($name)).into()
                    )),
                })
            }
        }

        $(
            #[cfg(feature = $omit_from)]
        )?
        impl From<$name> for $any_msg {
            fn from(msg: $name) -> $any_msg {
                match msg {
                    $(
                        $( #[cfg(feature=$feat)] )?
                        $name::$case(b) => Self::$case(b),
                    )*
                    $(
                        $name::$unrecognized(u) => $any_msg::Unrecognized(u),
                    )?
                }
            }
        }

        $(
            #[cfg(feature = $omit_from)]
        )?
        impl TryFrom<$any_msg> for $name {
            type Error = $any_msg;
            fn try_from(msg: $any_msg) -> std::result::Result<$name, $any_msg> {
                Ok(match msg {
                    $(
                        $( #[cfg(feature=$feat)] )?
                        $any_msg::$case(b) => $name::$case(b),
                    )*
                    $(
                        $any_msg::Unrecognized(u) => Self::$unrecognized(u),
                    )?
                    #[allow(unreachable_patterns)]
                    other => return Err(other),
                })
            }
        }
        $(
            $( #[cfg(feature=$feat)] )?
            impl From<$msg_mod :: $case> for $name {
                fn from(m: $msg_mod::$case) -> $name {
                    $name :: $case(m)
                }
            }
        )*
        $(
            impl From<$unrec_type> for $name {
                fn from (u: $unrec_type) -> $name {
                    $name::$unrecognized(u)
                }
            }
        )?
    }
    }
}

pub use restricted_msg;

#[cfg(test)]
mod test {
    use super::*;
    // Here we do a couple of other variations of the example in the doctest, to
    // make sure they work.

    // As in the doctest, but no "unrecognized" variant.
    restricted_msg! {
        enum StrictOpenStreamMsg : RelayMsg {
            Data,
            Sendme,
            End,
       }
    }

    // Try it with chanmsg.
    restricted_msg! {
        enum CircuitBuildReply : ChanMsg {
            Created,
            Created2,
            CreatedFast,
            Destroy,
            _ => Unrecognized,
       }
    }

    // As above, but no "unrecognized" variant.
    restricted_msg! {
        enum StrictCircuitBuildReply : ChanMsg {
            Created,
            Created2,
            CreatedFast,
            Destroy,
       }
    }
}
