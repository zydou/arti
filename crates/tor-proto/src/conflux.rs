//! Conflux-related functionality

pub(crate) mod msghandler;

use tor_cell::relaycell::RelayCmd;

/// Whether the specified `cmd` counts towards the conflux sequence numbers.
pub(crate) fn cmd_counts_towards_seqno(cmd: RelayCmd) -> bool {
    // Note: copy-pasted from c-tor
    match cmd {
        // These are all fine to multiplex, and must be so that ordering is preserved
        RelayCmd::BEGIN | RelayCmd::DATA | RelayCmd::END | RelayCmd::CONNECTED => true,

        // We can't multiplex these because they are circuit-specific
        RelayCmd::SENDME
        | RelayCmd::EXTEND
        | RelayCmd::EXTENDED
        | RelayCmd::TRUNCATE
        | RelayCmd::TRUNCATED
        | RelayCmd::DROP => false,

        //  We must multiplex RESOLVEs because their ordering impacts begin/end.
        RelayCmd::RESOLVE | RelayCmd::RESOLVED => true,

        // These are all circuit-specific
        RelayCmd::BEGIN_DIR
        | RelayCmd::EXTEND2
        | RelayCmd::EXTENDED2
        | RelayCmd::ESTABLISH_INTRO
        | RelayCmd::ESTABLISH_RENDEZVOUS
        | RelayCmd::INTRODUCE1
        | RelayCmd::INTRODUCE2
        | RelayCmd::RENDEZVOUS1
        | RelayCmd::RENDEZVOUS2
        | RelayCmd::INTRO_ESTABLISHED
        | RelayCmd::RENDEZVOUS_ESTABLISHED
        | RelayCmd::INTRODUCE_ACK
        | RelayCmd::PADDING_NEGOTIATE
        | RelayCmd::PADDING_NEGOTIATED => false,

        // Flow control cells must be ordered (see prop 329).
        RelayCmd::XOFF | RelayCmd::XON => true,

        // These two are not multiplexed, because they must be processed immediately
        // to update sequence numbers before any other cells are processed on the circuit
        RelayCmd::CONFLUX_SWITCH
        | RelayCmd::CONFLUX_LINK
        | RelayCmd::CONFLUX_LINKED
        | RelayCmd::CONFLUX_LINKED_ACK => false,

        _ => {
            tracing::warn!("Conflux asked to multiplex unknown relay command {cmd}");
            false
        }
    }
}
