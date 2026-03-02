//! Proof-of-concept for applied operation use.
//!
//! These functions should obviously be moved to [`super`] at one point.

use r2d2::Pool;
use r2d2_sqlite::SqliteConnectionManager;
use rand::{seq::SliceRandom, Rng};
use tor_basic_utils::retry::RetryDelay;
use tor_dircommon::{authority::AuthorityContacts, config::DirTolerance};
use tor_netdoc::doc::netstatus::ConsensusFlavor;
use tor_rtcompat::PreferredRuntime;

use crate::{
    database::Timestamp,
    err::IsFatal,
    mirror::operation::{ConsensusBoundData, StaticEngine},
};

/// Proof-of-concept main execution function for this module
///
/// Right now, this is a proof-of-concept that just panics in the case of a
/// fatal error, but does proper retry handling for non-fatal errors.
// TODO DIRMIRROR: Make this not a poc.
// TODO DIRMIRROR: Add logging.
async fn serve<R: Rng, F: Fn() -> Timestamp>(
    pool: &Pool<SqliteConnectionManager>,
    flavor: ConsensusFlavor,
    authorities: AuthorityContacts,
    tolerance: DirTolerance,
    rng: &mut R,
    now_fn: F,
) {
    let mut data = ConsensusBoundData::None;
    let engine = StaticEngine {
        flavor,
        authorities,
        tolerance,
        rt: PreferredRuntime::current().expect("unable to get runtime"),
    };

    // Shuffle the list of download endpoints.
    let mut downloads = engine.authorities.downloads().clone();
    downloads.shuffle(rng);
    // Keeps track of the authority we currently use, i.e. preferred authority.
    let mut current = 0;

    let mut retry = RetryDelay::default();
    loop {
        let endpoint = downloads.get(current).expect("attempted all authorities");

        // Perform the FSM execution.
        let res = engine
            .execute(pool, &mut data, endpoint, now_fn(), rng)
            .await;

        match res {
            Ok(()) => {
                retry.reset();

                // Swap the currently used authority with the front and reset
                // current to zero.
                //
                // With this design, we will loose track on which authorities
                // were successful and which were not on every successful
                // return.  At one point, we have to do this.  Probably after
                // every consensus, but not after every Ok.  However, for this
                // we would need a way to learn when we got a new consensus.
                // It would probably make most sense to modify the return type
                // of execute() to return something like the next state plus
                // previous state or maybe an even simpler bool that returns
                // true when the consensus got replaced.
                downloads.swap(0, current);
            }
            Err(e) => {
                // Check whether the error is fatal.
                if e.is_fatal() {
                    panic!("fatal error: {e}");
                }

                // Non-fatal error means we should wait and try again.
                current += 1;
                let delay = retry.next_delay(rng);
                tokio::time::sleep(delay).await;
            }
        }
    }
}
