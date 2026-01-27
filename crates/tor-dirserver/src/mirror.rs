//! The Tor directory mirror implementation.
//!
//! # Specifications
//!
//! * [Directory cache operation](https://spec.torproject.org/dir-spec/directory-cache-operation.html).
//!
//! # Rationale
//!
//! The network documents specified in the directory specification form a
//! fundamental part within the Tor protocol, namely the creation and distribution
//! of a canonical list, listing all relays present in the Tor network, thereby
//! giving all clients a unified view of the entire Tor network, a fact that
//! is very important for defending against partitioning attacks and other potential
//! attacks in the domain of distributed networks.
//!
//! These network documents are generated, signed, and served by so called
//! "directory authorities", a set of 10-ish highly trusted Tor relays more or
//! less governing the entirety of the Tor network.
//!
//! Now here comes the bottleneck: Tor has millions of active daily users but
//! only 10-ish relays responsible for these crucial documents.  Having all
//! clients download from those 10-ish relays would present an immense overload
//! to those, thereby potentially shutting the entire Tor network down, if the
//! amount of traffic to those relays is so high, that they are unable to
//! communicate and coordinate under themselves.
//!
//! Fortunately, all network documents are either directly or indirectly signed
//! by well-known keys of directory authorities, thereby making mirroring them
//! trivially possible, due the fact that authenticity can be established outside
//! the raw TLS connection thanks to cryptographic signatures.
//!
//! This is the place where directory mirrors come in hnady.  Directory mirrors
//! (previously known as "directory caches") are ordinary relays that mirror all
//! network documents from the authorities, by implementing the respective routes
//! for all HTTP GET endpoints from the relays.
//!
//! The network documents are usually served through ordinary Tor circuits,
//! by accepting incoming connections through `RELAY_BEGIN_DIR` cells.
//! In the past, this was done by some relays optionally enabling an additional
//! socket on the ordinary Internet through a dedicated SocketAddr, known as
//! "directory address".  Since about 2020, this is no longer done.  However,
//! the functionality continues to persist and this module is written fairly
//! agnostic on how it accepts such connections, as directory authorities continue
//! to advertise their directory address.

use std::{convert::Infallible, path::PathBuf};

use futures::Stream;
use tokio::io::{AsyncRead, AsyncWrite};
use tor_dircommon::{
    authority::AuthorityContacts,
    config::{DirTolerance, DownloadScheduleConfig},
};

mod operation;

/// Core data type of a directory mirror.
///
/// # External Notes
///
/// This structure serves as the entrence point to the [`mirror`](crate::mirror)
/// API.  It represents an instance that is launchable using [`DirMirror::serve`].
/// Calling this method consumes the instance, as this is the common behavior
/// for objects representing server-like things, in order to not imply that this
/// instance serves as a mere configuration template only.
///
/// # Internal Notes
///
/// For now, this data structure only holds configuration options as an ad-hoc
/// replacement for a yet missing hypothetical `DirMirrorConfig` structure.
///
/// I assume that in the future, regardless of the configuration, this might also
/// hold other fields such as access to the database pool, etc.  The question
/// is whether this structure will be passed around with locking mechanisms
/// or will just be used as a way to extract configuration options initially
/// in the consuming function, which then applies further wrapping or not.
#[derive(Debug)]
#[non_exhaustive]
pub struct DirMirror {
    /// The [`PathBuf`] where the [`database`](crate::database) is located.
    path: PathBuf,
    /// The [`AuthorityContacts`] data structure for contacting authorities.
    authorities: AuthorityContacts,
    /// The [`DownloadScheduleConfig`] used for properly retrying downloads.
    schedule: DownloadScheduleConfig,
    /// The [`DirTolerance`] to tolerate clock skews.
    tolerance: DirTolerance,
}

impl DirMirror {
    /// Creates a new [`DirMirror`] with a given set of configuration options.
    ///
    /// # Parameters
    ///
    /// * `path`: The [`PathBuf`] where the database is located.
    /// * `authorities`: The [`AuthorityContacts`] data structure for contacting authorities.
    /// * `schedule`: The [`DownloadScheduleConfig`] used for properly retrying downloads.
    /// * `tolerance`: The [`DirTolerance`] to tolerate clock skews.
    ///
    /// # Notes
    ///
    /// **Beware of [`DirTolerance::default()`]!**, as the default values are
    /// inteded for clients, not directory mirrors.  Tolerances of several days
    /// are not recommened for directory mirrors.  Consider using something in
    /// the minute range instead, such as `60s`, which is what ctor uses.[^1]
    ///
    /// TODO DIRMIRROR: This is unacceptable for the actual release.  We **NEED**
    /// a proper way to configure this, such as with a `DirMirrorConfig` struct
    /// that can properly serialize from configuration files and such.  However,
    /// this task is not a trivial one and maybe one of the hardest parts of this
    /// entire development, as it would involve a radical change to many higher
    /// level crates.  The reason for this being, that we need a clean way to
    /// share "global" settings such as the list of authorities into various
    /// sub-configurations, such as the configuration for the directory mirror.
    /// We must not offer different configurations for the list of authorities
    /// for those different components, that would result in lots of boilerplate
    /// and potentially wrong execution given that those resources are affecting
    /// so many parts of the Tor protocol that a consistent view must be assumed
    /// in order to avoid surprising behavior.
    ///
    /// [^1]: <https://gitlab.torproject.org/tpo/core/tor/-/blob/0b20710/src/feature/nodelist/networkstatus.c#L1890>.
    pub fn new(
        path: PathBuf,
        authorities: AuthorityContacts,
        schedule: DownloadScheduleConfig,
        tolerance: DirTolerance,
    ) -> Self {
        Self {
            path,
            authorities,
            schedule,
            tolerance,
        }
    }

    /// Consumes the [`DirMirror`] by running endlessly in the current task.
    ///
    /// This method accepts a `listener`, which is a [`Stream`] yielding a
    /// [`Result`] in order to model a generic way of accepting incoming
    /// connections.  Think of `S` as the file descriptor you would call
    /// `accept(2)` upon if you were in C.  The idea behind this generic is,
    /// as outlined in the module documentation, that a [`DirMirror`] can
    /// handle incoming connections in multiple ways, such as by serving
    /// through an ordinary TCP socket or through a Tor circuit in combination
    /// with a `RELAY_BEGIN_DIR` cell.  How this is concretely done, is outside
    /// the scope of this crate; instead we provide the primitives making such
    /// flexibility possible.
    #[allow(clippy::unused_async)] // TODO
    pub async fn serve<S, T, E>(self, _listener: S) -> Result<(), Infallible>
    where
        S: Stream<Item = Result<T, E>> + Unpin,
        T: AsyncRead + AsyncWrite + Unpin + Send + 'static,
        E: std::error::Error,
    {
        todo!()
    }
}
