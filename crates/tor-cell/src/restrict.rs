//! Declare a restricted variant of our message types.

/// Re-export tor_bytes here, so that the macro can use it.
pub use tor_bytes;

/// Declare a restricted version of
/// [`RelayMsg`](crate::relaycell::msg::RelayMsg) or
/// [`ChanMsg`](crate::chancell::msg::ChanMsg).
///
/// Frequently we only want to handle a subset of the possible channel or relay
/// commands that we might see.  In those situations, it makes sense to define a
/// a message types that will only try to parse the allowable commands.  That way,
/// we can avoid exposing any unnecessary parsers to a possible attacker.
///
/// The restricted message type is an enum, and is declared with a syntax as follows:
/// ```
/// use tor_cell::{restrict::restricted_msg, relaycell::RestrictedRelayCell};
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
/// type OpenStreamCell = RestrictedRelayCell<OpenStreamMsg>;
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
        $v:vis enum $name:ident : RelayMsg {
            $($tt:tt)*
        }
    } => {
        $crate::restrict::restricted_msg!{
            [
            base_type: $crate::relaycell::msg::RelayMsg,
            msg_mod: $crate::relaycell::msg,
            cmd_type: $crate::relaycell::RelayCmd,
            unrecognized: $crate::relaycell::msg::Unrecognized,
            body_trait: $crate::relaycell::msg::Body,
            msg_trait: $crate::relaycell::RelayMsgClass
            ]
            $(#[$meta])*
            $v enum $name { $($tt)*}
        }
    };
    {
        $(#[$meta:meta])*
        $v:vis enum $name:ident : ChanMsg {
            $($tt:tt)*
        }
    } => {
        $crate::restrict::restricted_msg!{
            [
            base_type: $crate::chancell::msg::ChanMsg,
            msg_mod: $crate::chancell::msg,
            cmd_type: $crate::chancell::ChanCmd,
            unrecognized: $crate::chancell::msg::Unrecognized,
            body_trait: $crate::chancell::msg::Body,
            msg_trait: $crate::chancell::ChanMsgClass
            ]
            $(#[$meta])*
            $v enum $name { $($tt)*}
        }
    };
    {
        [
          base_type: $base:ty,
          msg_mod: $msg_mod:path,
          cmd_type: $cmd_type:ty,
          unrecognized: $unrec_type:ty,
          body_trait: $body_type:ty,
          msg_trait: $msg_trait:ty
        ]
        $(#[$meta:meta])*
        $v:vis enum $name:ident {
            $(
                $(#[$case_meta:meta])*
                $case:ident
            ),*
            $(, _ =>
                $(#[$unrec_meta:meta])*
                $unrecognized:ident )?
            $(,)?
        }
    } => {
    paste::paste!{
        $(#[$meta])*
        $v enum $name {
            $(
                $(#[$case_meta])*
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
                use $body_type;
                match self {
                    $(
                        Self::$case(m) => m.encode_onto(w),
                    )*
                    $(
                        Self::$unrecognized(u) => u.encode_onto(w),
                    )?
                }
            }

            fn decode_from_reader(cmd: $cmd_type, r: &mut $crate::restrict::tor_bytes::Reader<'_>) -> $crate::restrict::tor_bytes::Result<Self> {
                use $body_type;
                Ok(match cmd {
                    $(
                        $cmd_type:: [<$case:snake:upper>] => Self::$case( $msg_mod :: $case :: decode_from_reader(r)? ),
                    )*
                    $(
                        _ => Self::$unrecognized($unrec_type::decode_with_cmd(cmd, r)?),
                    )?
                    // TODO: This message is too terse! This message type should maybe take a Cow?
                    #[allow(unreachable_patterns)] // This is unreachable if we had an Unrecognized variant above.
                    _ => return Err($crate::restrict::tor_bytes::Error::BadMessage("Unexpected command")),
                })
            }
        }
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
