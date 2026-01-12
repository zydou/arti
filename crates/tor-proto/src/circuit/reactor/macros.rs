//! Helper macros for the circuit reactors.

derive_deftly::define_derive_deftly! {
    /// Helper for deriving the boilerplate `run()` function of a circuit reactor.
    ///
    ///
    /// ### Custom attributes
    ///
    ///  * **`#[deftly(reactor_name = "...")]`** (toplevel):
    ///    The name of the reactor, for logging purposes.
    ///    Must be a literal string.
    ///
    ///  * **`#[deftly(run_inner_fn = "FUNCTION")]`** (toplevel):
    ///    The function to run from `run()`, possibly in a loop.
    ///    `FUNCTION` is a function with the signature
    ///    `async fn run_once(&mut Self) -> Result<(), ReactorError>`
    ///
    ///  * **`#[deftly(only_run_once)]`** (toplevel):
    ///    Whether the `run()` function should only run `run_inner_fn` once
    export CircuitReactor expect items:

    impl<$tgens> $ttype where
        $twheres
    {
        /// Launch the reactor, and run until the circuit closes or we
        /// encounter an error.
        ///
        /// Once this method returns, the circuit is dead and cannot be
        /// used again.
        pub(crate) async fn run(mut self) -> $crate::Result<()> {
            let unique_id = self.unique_id;

            tracing::debug!(
                circ_id = %unique_id,
                "Running {}", ${tmeta(reactor_name) as str}
            );

            let result: $crate::Result<()> = loop {

                match ${tmeta(run_inner_fn) as expr}(&mut self).await {

                    Ok(()) => {
                        ${if tmeta(only_run_once) {
                            break Ok(());
                        }}
                    },
                    Err(ReactorError::Shutdown) => break Ok(()),
                    Err(ReactorError::Err(e)) => break Err(e),
                }
            };

            // Log that the reactor stopped, possibly with the associated error as a report.
            // May log at a higher level depending on the error kind.
            let msg = format!("{} shut down", ${tmeta(reactor_name) as str});
            match &result {
                Ok(()) => tracing::trace!(circ_id = %unique_id, "{msg}"),
                Err(e) => tor_error::debug_report!(e, circ_id = %unique_id, "{msg}"),
            }

            result
        }
    }
}

pub(crate) use derive_deftly_template_CircuitReactor;
