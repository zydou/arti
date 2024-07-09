//! Declare tor client specific errors.

mod hint;

use std::fmt::{self, Display};
use std::sync::Arc;

use futures::task::SpawnError;

#[cfg(feature = "onion-service-client")]
use safelog::Redacted;
use safelog::Sensitive;
use thiserror::Error;
use tor_circmgr::TargetPorts;
use tor_error::{ErrorKind, HasKind};

use crate::TorAddrError;
#[cfg(feature = "onion-service-client")]
use tor_hscrypto::pk::HsId;

pub use hint::HintableError;

/// Main high-level error type for the Arti Tor client
///
/// If you need to handle different types of errors differently, use the
/// [`kind`](`tor_error::HasKind::kind`) trait method to check what kind of
/// error it is.
///
/// Note that although this type implements that standard
/// [`Error`](trait@std::error::Error) trait, the output of that trait's methods are
/// not covered by semantic versioning.  Specifically: you should not rely on
/// the specific output of `Display`, `Debug`, or `Error::source()` when run on
/// this type; it may change between patch versions without notification.
#[derive(Error, Clone, Debug)]
pub struct Error {
    /// The actual error.
    ///
    /// This field is exposed via the `detail()` method only if the
    /// `error_detail` feature is enabled. Using it will void your semver
    /// guarantee.
    #[source]
    detail: Box<ErrorDetail>,
}

impl From<ErrorDetail> for Error {
    fn from(detail: ErrorDetail) -> Error {
        Error {
            detail: detail.into(),
        }
    }
}

/// Declare an enum as `pub` if `error_details` is enabled, and as `pub(crate)` otherwise.
#[cfg(feature = "error_detail")]
macro_rules! pub_if_error_detail {
    {  $(#[$meta:meta])* enum $e:ident $tt:tt } => {
        $(#[$meta])* pub enum $e $tt
    }
}

/// Declare an enum as `pub` if `error_details` is enabled, and as `pub(crate)` otherwise.
#[cfg(not(feature = "error_detail"))]
macro_rules! pub_if_error_detail {
    {  $(#[$meta:meta])* enum $e:ident $tt:tt } => {
        $(#[$meta])* pub(crate) enum $e $tt }
}

// Hello, macro-fans!  There are some other solutions that we considered here
// but didn't use.
//
// 1. For one, `pub_if_error_detail!{} enum ErrorDetail { ... }` would be neat,
// but Rust doesn't allow macros to appear in that position.
//
// 2. We could also declare `ErrorDetail` here as `pub` unconditionally, and
// rely on `mod err` being private to keep it out of the user's hands.  Then we
// could conditionally re-export `ErrorDetail` in `lib`:
//
// ```
// mod err {
//    pub enum ErrorDetail { ... }
// }
//
// #[cfg(feature = "error_detail")]
// pub use err::ErrorDetail;
// ```
//
// But if we did that, the compiler would no longer warn us if we
// _unconditionally_ exposed the ErrorDetail type from somewhere else in this
// crate.  That doesn't seem too safe.
//
// 3. At one point we had a macro more like:
// ```
// macro_rules! declare_error_detail { { $vis: $vis } } =>
//  => { ... $vis enum ErrorDetail {...} }
// ```
// There's nothing wrong with that in principle, but it's no longer needed,
// since we used to use $vis in several places but now it's only used in one.
// Also, it's good to make macro declarations small, and rust-analyzer seems to
// handle understand format a little bit better.

pub_if_error_detail! {
// We cheat with the indentation, a bit.  Happily rustfmt doesn't seem to mind.

/// Represents errors that can occur while doing Tor operations.
///
/// This enumeration is the inner view of a
/// [`arti_client::Error`](crate::Error): we don't expose it unless the
/// `error_detail` feature is enabled.
///
/// The details of this enumeration are not stable: using the `error_detail`
/// feature will void your semver guarantee.
///
/// Instead of looking at the type, you try to should use the
/// [`kind`](`tor_error::HasKind::kind`) trait method to distinguish among
/// different kinds of [`Error`](struct@crate::Error).  If that doesn't provide enough information
/// for your use case, please let us know.
#[cfg_attr(docsrs, doc(cfg(feature = "error_detail")))]
#[cfg_attr(test, derive(strum::EnumDiscriminants))]
#[cfg_attr(test, strum_discriminants(vis(pub(crate))))]
#[derive(Error, Clone, Debug)]
#[non_exhaustive]
enum ErrorDetail {
    /// Error setting up the channel manager
    // TODO: should "chanmgr setup error" be its own type in tor-chanmgr
    #[error("Error setting up the channel manager")]
    ChanMgrSetup(#[source] tor_chanmgr::Error),

    /// Error setting up the guard manager
    // TODO: should "guardmgr setup error" be its own type in tor-guardmgr?
    #[error("Error setting up the guard manager")]
    GuardMgrSetup(#[source] tor_guardmgr::GuardMgrError),

    /// Error setting up the guard manager
    // TODO: should "vanguardmgr setup error" be its own type in tor-guardmgr?
    #[cfg(all(
        feature = "vanguards",
        any(feature = "onion-service-client", feature = "onion-service-service")
    ))]
    #[error("Error setting up the vanguard manager")]
    VanguardMgrSetup(#[source] tor_guardmgr::VanguardMgrError),

    /// Error setting up the circuit manager
    // TODO: should "circmgr setup error" be its own type in tor-circmgr?
    #[error("Error setting up the circuit manager")]
    CircMgrSetup(#[source] tor_circmgr::Error),

    /// Error setting up the bridge descriptor manager
    #[error("Error setting up the bridge descriptor manager")]
    #[cfg(feature = "bridge-client")]
    BridgeDescMgrSetup(#[from] tor_dirmgr::bridgedesc::StartupError),

    /// Error setting up the directory manager
    // TODO: should "dirmgr setup error" be its own type in tor-dirmgr?
    #[error("Error setting up the directory manager")]
    DirMgrSetup(#[source] tor_dirmgr::Error),

    /// Error setting up the state manager.
    #[error("Error setting up the persistent state manager")]
    StateMgrSetup(#[source] tor_persist::Error),

    /// Error setting up the hidden service client connector.
    #[error("Error setting up the hidden service client connector")]
    #[cfg(feature = "onion-service-client")]
    HsClientConnectorSetup(#[from] tor_hsclient::StartupError),

    /// Failed to obtain exit circuit
    #[error("Failed to obtain exit circuit for ports {exit_ports}")]
    ObtainExitCircuit {
        /// The ports that we wanted a circuit for.
        exit_ports: Sensitive<TargetPorts>,

        /// What went wrong
        #[source]
        cause: tor_circmgr::Error,
    },

    /// Failed to obtain hidden service circuit
    #[cfg(feature = "onion-service-client")]
    #[error("Failed to obtain hidden service circuit to {hsid}")]
    ObtainHsCircuit {
        /// The service we were trying to connect to
        hsid: Redacted<HsId>,

        /// What went wrong
        #[source]
        cause: tor_hsclient::ConnError,
    },

    /// Directory manager was unable to bootstrap a working directory.
    #[error("Unable to bootstrap a working directory")]
    DirMgrBootstrap(#[source] tor_dirmgr::Error),

    /// A protocol error while launching a stream
    #[error("Protocol error while launching a {kind} stream")]
    StreamFailed {
        /// What kind of stream we were trying to launch.
        kind: &'static str,

        /// The error that occurred.
        #[source]
        cause:  tor_proto::Error
    },

    /// An error while interfacing with the persistent data layer.
    #[error("Error while trying to access persistent state")]
    StateAccess(#[source] tor_persist::Error),

    /// We asked an exit to do something, and waited too long for an answer.
    #[error("Timed out while waiting for answer from exit")]
    ExitTimeout,

    /// Onion services are not compiled in, but we were asked to connect to one.
    #[error("Rejecting .onion address; feature onion-service-client not compiled in")]
    OnionAddressNotSupported,

    /// Onion services are not enabled, but we were asked to connect to one.
    ///
    /// This error occurs when Arti is built with onion service support, but
    /// onion services are disabled via our stream preferences.
    ///
    /// To enable onion services, set `allow_onion_addrs` to `true` in the
    /// `address_filter` configuration section.  Alternatively, set
    /// `connect_to_onion_services` in your `StreamPrefs` object.
    #[cfg(feature = "onion-service-client")]
    #[error("Rejecting .onion address; allow_onion_addrs disabled in stream preferences")]
    OnionAddressDisabled,

    /// Error when trying to find the IP address of a hidden service
    #[error("A .onion address cannot be resolved to an IP address")]
    OnionAddressResolveRequest,

    /// Unusable target address.
    ///
    /// `TorAddrError::InvalidHostname` should not appear here;
    /// use `ErrorDetail::InvalidHostname` instead.
    // TODO this is a violation of the "make invalid states unrepresentable" principle,
    // but maybe that doesn't matter too much here?
    #[error("Could not parse target address")]
    Address(crate::address::TorAddrError),

    /// Hostname not valid.
    #[error("Rejecting hostname as invalid")]
    InvalidHostname,

    /// Address was local, and we don't permit connecting to those over Tor.
    #[error("Cannot connect to a local-only address without enabling allow_local_addrs")]
    LocalAddress,

    /// Building configuration for the client failed.
    #[error("Problem with configuration")]
    Configuration(#[from] tor_config::ConfigBuildError),

    /// Unable to change configuration.
    #[error("Unable to change configuration")]
    Reconfigure(#[from] tor_config::ReconfigureError),

    /// Problem creating or launching a pluggable transport.
    #[cfg(feature="pt-client")]
    #[error("Problem with a pluggable transport")]
    PluggableTransport(#[from] tor_ptmgr::err::PtError),

    /// We encountered a problem while inspecting or creating a directory.
    #[error("Problem accessing filesystem")]
    FsMistrust(#[from] fs_mistrust::Error),

    /// Unable to spawn task
    #[error("Unable to spawn {spawning}")]
    Spawn {
        /// What we were trying to spawn.
        spawning: &'static str,
        /// What happened when we tried to spawn it.
        #[source]
        cause: Arc<SpawnError>
    },

    /// Attempted to use an unbootstrapped `TorClient` for something that
    /// requires bootstrapping to have completed.
    #[error("Cannot {action} with unbootstrapped client")]
    BootstrapRequired {
        /// What we were trying to do that required bootstrapping.
        action: &'static str
    },

    /// Attempted to use a `TorClient` for something when it did not
    /// have a valid directory.
    #[error("Tried to {action} without a valid directory")]
    NoDir {
        /// The underlying error.
        #[source]
        error: tor_netdir::Error,
        /// What we were trying to do that needed a directory.
        action: &'static str,
    },

    /// A key store access failed.
    #[error("Error while trying to access a key store")]
    Keystore(#[from] tor_keymgr::Error),

    /// Attempted to use a `TorClient` for something that
    /// requires the keystore to be enabled in the configuration.
    #[error("Cannot {action} without enabling storage.keystore")]
    KeystoreRequired {
        /// What we were trying to do that required the keystore to be enabled.
        action: &'static str
    },

    /// Encountered a malformed client specifier.
    #[error("Bad client specifier")]
    BadClientSpecifier(#[from] tor_keymgr::ArtiPathSyntaxError),

    /// We tried to parse an onion address, but we found that it was invalid.
    #[cfg(feature = "onion-service-client")]
    #[error("Invalid onion address")]
    BadOnionAddress(#[from] tor_hscrypto::pk::HsIdParseError),

    /// We were unable to launch an onion service, even though we
    /// we are configured to be able to do so.
    #[cfg(feature= "onion-service-service")]
    #[error("Unable to launch onion service")]
    LaunchOnionService(#[source] tor_hsservice::StartupError),

    /// A programming problem, either in our code or the code calling it.
    #[error("Programming problem")]
    Bug(#[from] tor_error::Bug),
}

// End of the use of $vis to refer to visibility according to `error_detail`
}

#[cfg(feature = "error_detail")]
impl Error {
    /// Return the underlying error detail object for this error.
    ///
    /// In general, it's not a good idea to use this function.  Our
    /// `arti_client::ErrorDetail` objects are unstable, and matching on them is
    /// probably not the best way to achieve whatever you're trying to do.
    /// Instead, we recommend using  the [`kind`](`tor_error::HasKind::kind`)
    /// trait method if your program needs to distinguish among different types
    /// of errors.
    ///
    /// (If the above function don't meet your needs, please let us know!)
    ///
    /// This function is only available when `arti-client` is built with the
    /// `error_detail` feature.  Using this function will void your semver
    /// guarantees.
    pub fn detail(&self) -> &ErrorDetail {
        &self.detail
    }
}

impl Error {
    /// Consume this error and return the underlying error detail object.
    pub(crate) fn into_detail(self) -> ErrorDetail {
        *self.detail
    }
}

impl ErrorDetail {
    /// Construct a new `Error` from a `SpawnError`.
    pub(crate) fn from_spawn(spawning: &'static str, err: SpawnError) -> ErrorDetail {
        ErrorDetail::Spawn {
            spawning,
            cause: Arc::new(err),
        }
    }
}

impl Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "tor: {}: {}", self.detail.kind(), &self.detail)
    }
}

impl tor_error::HasKind for Error {
    fn kind(&self) -> ErrorKind {
        self.detail.kind()
    }
}

impl tor_error::HasKind for ErrorDetail {
    fn kind(&self) -> ErrorKind {
        use ErrorDetail as E;
        use ErrorKind as EK;
        match self {
            E::ObtainExitCircuit { cause, .. } => cause.kind(),
            #[cfg(feature = "onion-service-client")]
            E::ObtainHsCircuit { cause, .. } => cause.kind(),
            E::ExitTimeout => EK::RemoteNetworkTimeout,
            E::BootstrapRequired { .. } => EK::BootstrapRequired,
            E::GuardMgrSetup(e) => e.kind(),
            #[cfg(all(
                feature = "vanguards",
                any(feature = "onion-service-client", feature = "onion-service-service")
            ))]
            E::VanguardMgrSetup(e) => e.kind(),
            #[cfg(feature = "bridge-client")]
            E::BridgeDescMgrSetup(e) => e.kind(),
            E::CircMgrSetup(e) => e.kind(),
            E::DirMgrSetup(e) => e.kind(),
            E::StateMgrSetup(e) => e.kind(),
            #[cfg(feature = "onion-service-client")]
            E::HsClientConnectorSetup(e) => e.kind(),
            E::DirMgrBootstrap(e) => e.kind(),
            #[cfg(feature = "pt-client")]
            E::PluggableTransport(e) => e.kind(),
            E::StreamFailed { cause, .. } => cause.kind(),
            E::StateAccess(e) => e.kind(),
            E::Configuration(e) => e.kind(),
            E::Reconfigure(e) => e.kind(),
            E::Spawn { cause, .. } => cause.kind(),
            E::OnionAddressNotSupported => EK::FeatureDisabled,
            E::OnionAddressResolveRequest => EK::NotImplemented,
            #[cfg(feature = "onion-service-client")]
            E::OnionAddressDisabled => EK::ForbiddenStreamTarget,
            #[cfg(feature = "onion-service-client")]
            E::BadOnionAddress(e) => e.kind(),
            #[cfg(feature = "onion-service-service")]
            E::LaunchOnionService(e) => e.kind(),
            // TODO Should delegate to TorAddrError EK
            E::Address(_) | E::InvalidHostname => EK::InvalidStreamTarget,
            E::LocalAddress => EK::ForbiddenStreamTarget,
            E::ChanMgrSetup(e) => e.kind(),
            E::NoDir { error, .. } => error.kind(),
            E::Keystore(e) => e.kind(),
            E::KeystoreRequired { .. } => EK::InvalidConfig,
            E::BadClientSpecifier(_) => EK::InvalidConfig,
            E::FsMistrust(_) => EK::FsPermissions,
            E::Bug(e) => e.kind(),
        }
    }
}

impl From<TorAddrError> for Error {
    fn from(e: TorAddrError) -> Error {
        ErrorDetail::from(e).into()
    }
}

impl From<tor_keymgr::Error> for Error {
    fn from(e: tor_keymgr::Error) -> Error {
        ErrorDetail::Keystore(e).into()
    }
}

impl From<TorAddrError> for ErrorDetail {
    fn from(e: TorAddrError) -> ErrorDetail {
        use ErrorDetail as E;
        use TorAddrError as TAE;
        match e {
            TAE::InvalidHostname => E::InvalidHostname,
            TAE::NoPort | TAE::BadPort => E::Address(e),
        }
    }
}

/// Verbose information about an error, meant to provide detail or justification
/// for user-facing errors, rather than the normal short message for
/// developer-facing errors.
///
/// User-facing code may attempt to produce this by calling [`Error::hint`].
/// Not all errors may wish to provide verbose messages. `Some(ErrorHint)` will be
/// returned if hinting is supported for the error. Err(()) will be returned otherwise.
/// Which errors support hinting, and the hint content, have no SemVer warranty and may
/// change in patch versions without warning. Callers should handle both cases,
/// falling back on the original error message in case of Err.
///
/// Since the internal machinery for constructing and displaying hints may change over time,
/// no data members are currently exposed. In the future we may wish to offer an unstable
/// API locked behind a feature, like we do with ErrorDetail.
#[derive(Clone, Debug)]
pub struct ErrorHint<'a> {
    /// The pieces of the message to display to the user
    inner: ErrorHintInner<'a>,
}

/// An inner enumeration, describing different kinds of error hint that we know how to give.
#[derive(Clone, Debug)]
enum ErrorHintInner<'a> {
    /// There is a misconfigured filesystem permission, reported by `fs-mistrust`.
    ///
    /// Tell the user to make their file more private, or to disable `fs-mistrust`.
    BadPermission {
        /// The location of the file.
        filename: &'a std::path::Path,
        /// The access bits set on the file.
        bits: u32,
        /// The access bits that, according to fs-mistrust, should not be set.
        badbits: u32,
    },
}

// TODO: Perhaps we want to lower this logic to fs_mistrust crate, and have a
// separate `ErrorHint` type for each crate that can originate a hint.  But I'd
// rather _not_ have that turn into something that forces us to give a Hint for
// every intermediate crate.
impl<'a> Display for ErrorHint<'a> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        use fs_mistrust::anon_home::PathExt as _;

        match self.inner {
            ErrorHintInner::BadPermission {
                filename,
                bits,
                badbits,
            } => {
                writeln!(
                    f,
                    "Permissions are set too permissively on {}: currently {}",
                    filename.anonymize_home(),
                    fs_mistrust::format_access_bits(bits, '=')
                )?;
                if 0 != badbits & 0o222 {
                    writeln!(
                        f,
                        "* Untrusted users could modify its contents and override our behavior.",
                    )?;
                }
                if 0 != badbits & 0o444 {
                    writeln!(f, "* Untrusted users could read its contents.")?;
                }
                writeln!(f,
                    "You can fix this by further restricting the permissions of your filesystem, using:\n\
                         chmod {} {}",
                        fs_mistrust::format_access_bits(badbits, '-'),
                        filename.anonymize_home())?;
                writeln!(f, "You can suppress this message by setting storage.permissions.dangerously_trust_everyone=true,\n\
                    or setting ARTI_FS_DISABLE_PERMISSION_CHECKS=yes in your environment.")?;
            }
        }
        Ok(())
    }
}

impl Error {
    /// Return a hint object explaining how to solve this error, if we have one.
    ///
    /// Most errors won't have obvious hints, but some do.  For the ones that
    /// do, we can return an [`ErrorHint`].
    ///
    /// Right now, `ErrorHint` is completely opaque: the only supported option
    /// is to format it for human consumption.
    pub fn hint(&self) -> Option<ErrorHint> {
        HintableError::hint(self)
    }
}

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

    /// This code makes sure that our errors implement all the traits we want.
    #[test]
    fn traits_ok() {
        // I had intended to use `assert_impl`, but that crate can't check whether
        // a type is 'static.
        fn assert<
            T: Send + Sync + Clone + std::fmt::Debug + Display + std::error::Error + 'static,
        >() {
        }
        fn check() {
            assert::<Error>();
            assert::<ErrorDetail>();
        }
        check(); // doesn't do anything, but avoids "unused function" warnings.
    }
}
