//! Macros to define a restricted subset of RelayMsg.
//!
//! These restricted subsets are not just a matter of internal typesafety: they
//! provide _parsing support_ for only the relevant subset of messages, ensuring
//! that an attacker doesn't get easy access to our whole parsing surface.

// TODO hs: make a new macro that behaves something like this.  (This will need
// to change; it's just a sketch.)
//
// See arti#525 for more info.
//
// ```
// restricted_msg!( pub enum DataStreamMsg {
//    Data(Data),
//    End(End),
// }),
// ```
//
// It should define a new type that behaves like RelayMsg, except that it only
// tries to parse a message if the command is RELAY_CMD_DATA or RELAY_CMD_END.
//
// It would be neat if there were as little redundancy in the format as
// possible, and we didn't have to say "Data(Data) DATA" (meaning that the Data
// variant uses a Data object and should be used if the relay command is DATA).
//
// We'll need to define how the new type behaves on other commands.  In some
// cases, it should put them in a variant `Other`.  In most cases, it should
// just give an error.
//
// It might be neat if this could define restricted sets of ChanMsg too.  If so,
// we should move it.
//
// When only one relay message is valid, it might be neat to have a simpler way
// to parse that message specifically and reject everything else.
