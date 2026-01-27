#![cfg_attr(docsrs, feature(doc_cfg))]
#![doc = include_str!("../README.md")]
// @@ begin lint list maintained by maint/add_warning @@
#![allow(renamed_and_removed_lints)] // @@REMOVE_WHEN(ci_arti_stable)
#![allow(unknown_lints)] // @@REMOVE_WHEN(ci_arti_nightly)
#![warn(missing_docs)]
#![warn(noop_method_call)]
#![warn(unreachable_pub)]
#![warn(clippy::all)]
#![deny(clippy::await_holding_lock)]
#![deny(clippy::cargo_common_metadata)]
#![deny(clippy::cast_lossless)]
#![deny(clippy::checked_conversions)]
#![warn(clippy::cognitive_complexity)]
#![deny(clippy::debug_assert_with_mut_call)]
#![deny(clippy::exhaustive_enums)]
#![deny(clippy::exhaustive_structs)]
#![deny(clippy::expl_impl_clone_on_copy)]
#![deny(clippy::fallible_impl_from)]
#![deny(clippy::implicit_clone)]
#![deny(clippy::large_stack_arrays)]
#![warn(clippy::manual_ok_or)]
#![deny(clippy::missing_docs_in_private_items)]
#![warn(clippy::needless_borrow)]
#![warn(clippy::needless_pass_by_value)]
#![warn(clippy::option_option)]
#![deny(clippy::print_stderr)]
#![deny(clippy::print_stdout)]
#![warn(clippy::rc_buffer)]
#![deny(clippy::ref_option_ref)]
#![warn(clippy::semicolon_if_nothing_returned)]
#![warn(clippy::trait_duplication_in_bounds)]
#![deny(clippy::unchecked_time_subtraction)]
#![deny(clippy::unnecessary_wraps)]
#![warn(clippy::unseparated_literal_suffix)]
#![deny(clippy::unwrap_used)]
#![deny(clippy::mod_module_files)]
#![allow(clippy::let_unit_value)] // This can reasonably be done for explicitness
#![allow(clippy::uninlined_format_args)]
#![allow(clippy::significant_drop_in_scrutinee)] // arti/-/merge_requests/588/#note_2812945
#![allow(clippy::result_large_err)] // temporary workaround for arti#587
#![allow(clippy::needless_raw_string_hashes)] // complained-about code is fine, often best
#![allow(clippy::needless_lifetimes)] // See arti#1765
#![allow(mismatched_lifetime_syntaxes)] // temporary workaround for arti#2060
#![deny(clippy::unused_async)]
//! <!-- @@ end lint list maintained by maint/add_warning @@ -->

use std::sync::{Arc, Mutex};

use arti_client::{IntoTorAddr, TorClient};
use ureq::{
    http::{Uri, uri::Scheme},
    tls::TlsProvider as UreqTlsProvider,
    unversioned::{
        resolver::{ArrayVec, ResolvedSocketAddrs, Resolver as UreqResolver},
        transport::{Buffers, Connector as UreqConnector, LazyBuffers, NextTimeout, Transport},
    },
};

use educe::Educe;
use thiserror::Error;
use tor_proto::client::stream::{DataReader, DataWriter};
use tor_rtcompat::{Runtime, ToplevelBlockOn};

#[cfg(feature = "rustls")]
use ureq::unversioned::transport::RustlsConnector;

#[cfg(feature = "native-tls")]
use ureq::unversioned::transport::NativeTlsConnector;

use futures::io::{AsyncReadExt, AsyncWriteExt};

/// High-level functionality for accessing the Tor network as a client.
pub use arti_client;

/// Compatibility between different async runtimes for Arti.
pub use tor_rtcompat;

/// Underlying HTTP/S client library.
pub use ureq;

/// **Default usage**: Returns an instance of [`ureq::Agent`] using the default [`Connector`].
///
/// Equivalent to `Connector::new()?.agent()`.
///
/// # Example
///
/// ```rust,no_run
/// arti_ureq::default_agent()
///     .expect("Failed to create default agent.")
///     .get("http://check.torproject.org/api/ip")
///     .call()
///     .expect("Failed to make request.");
/// ```
///
/// Warning: This method creates a default [`arti_client::TorClient`]. Using multiple concurrent
/// instances of `TorClient` is not recommended. Most programs should create a single `TorClient` centrally.
pub fn default_agent() -> Result<ureq::Agent, Error> {
    Ok(Connector::new()?.agent())
}

/// **Main entrypoint**: Object for making HTTP/S requests through Tor.
///
/// This type embodies an [`arti_client::TorClient`] and implements [`ureq::unversioned::transport::Connector`],
/// allowing HTTP/HTTPS requests to be made with `ureq` over Tor.
///
/// Also bridges between async I/O (in Arti and Tokio) and sync I/O (in `ureq`).
///
/// ## A `Connector` object can be constructed in different ways.
///
/// ### 1. Use [`Connector::new`] to create a `Connector` with a default `TorClient`.
/// ```rust,no_run
/// let connector = arti_ureq::Connector::new().expect("Failed to create Connector.");
/// ```
///
/// ### 2. Use [`Connector::with_tor_client`] to create a `Connector` with a specific `TorClient`.
/// ```rust,no_run
/// let tor_client = arti_client::TorClient::with_runtime(
///     tor_rtcompat::PreferredRuntime::create().expect("Failed to create runtime.")
/// )
/// .create_unbootstrapped()
/// .expect("Error creating Tor Client.");
///
/// let connector = arti_ureq::Connector::with_tor_client(tor_client);
/// ```
///
/// ### 3. Use [`Connector::builder`] to create a `ConnectorBuilder` and configure a `Connector` with it.
/// ```rust,no_run
/// let connector = arti_ureq::Connector::<tor_rtcompat::PreferredRuntime>::builder()
///    .expect("Failed to create ConnectorBuilder.")
///    .build()
///    .expect("Failed to create Connector.");
/// ```
///
///
/// ## Usage of `Connector`.
///
/// A `Connector` can be used to retrieve an [`ureq::Agent`] with [`Connector::agent`] or pass the `Connector`
/// to [`ureq::Agent::with_parts`] along with a custom [`ureq::config::Config`] and a resolver
/// obtained from [`Connector::resolver`] to retrieve a more configurable [`ureq::Agent`].
///
/// ### Retrieve an `ureq::Agent`.
/// ```rust,no_run
/// let connector = arti_ureq::Connector::new().expect("Failed to create Connector.");
/// let ureq_agent = connector.agent();
/// ```
///
/// ### Pass as argument to `ureq::Agent::with_parts`.
///
/// We highly advice only using `Resolver` instead of e.g `ureq`'s [`ureq::unversioned::resolver::DefaultResolver`] to avoid DNS leaks.
///
/// ```rust,no_run
/// let connector = arti_ureq::Connector::new().expect("Failed to create Connector.");
/// let resolver = connector.resolver();
///
/// let ureq_agent = ureq::Agent::with_parts(
///    ureq::config::Config::default(),
///    connector,
///    resolver,
/// );
/// ```
#[derive(Educe)]
#[educe(Debug)]
pub struct Connector<R: Runtime> {
    /// [`arti_client::TorClient`] used to make requests.
    #[educe(Debug(ignore))]
    client: TorClient<R>,

    /// Selected [`ureq::tls::TlsProvider`]. Possible options are `Rustls` or `NativeTls`. The default is `Rustls`.
    tls_provider: UreqTlsProvider,
}

/// Object for constructing a [`Connector`].
///
/// Returned by [`Connector::builder`].
///
/// # Example
///
/// ```rust,no_run
/// // `Connector` using `NativeTls` as Tls provider.
/// let arti_connector = arti_ureq::Connector::<tor_rtcompat::PreferredRuntime>::builder()
///    .expect("Failed to create ConnectorBuilder.")
///     .tls_provider(ureq::tls::TlsProvider::NativeTls)
///     .build()
///     .expect("Failed to create Connector.");
///
/// // Retrieve `ureq::Agent` from the `Connector`.
/// let ureq_agent = arti_connector.agent();
/// ```
pub struct ConnectorBuilder<R: Runtime> {
    /// Configured [`arti_client::TorClient`] to be used with [`Connector`].
    client: Option<TorClient<R>>,

    /// Runtime
    ///
    /// If `client` is `None`, is used to create one.
    /// If `client` is `Some`. we discard this in `.build()` in favour of `.client.runtime()`.
    //
    // (We could replace `client` and `runtime` with `Either<TorClient<R>, R>` or some such,
    // but that would probably be more confusing.)
    runtime: R,

    /// Custom selected TlsProvider. Default is `Rustls`. Possible options are `Rustls` or `NativeTls`.
    tls_provider: Option<UreqTlsProvider>,
}

/// Custom [`ureq::unversioned::transport::Transport`] enabling `ureq` to use
/// [`arti_client::TorClient`] for making requests over Tor.
#[derive(Educe)]
#[educe(Debug)]
struct HttpTransport<R: Runtime> {
    /// Reader handle to Arti's read stream.
    // TODO #1859
    r: Arc<Mutex<DataReader>>,

    /// Writer handle to Arti's write stream.
    w: Arc<Mutex<DataWriter>>, // TODO #1859

    /// Buffer to store data.
    #[educe(Debug(ignore))]
    buffer: LazyBuffers,

    /// Runtime used to bridge between sync (`ureq`) and async I/O (`arti`).
    rt: R,
}

/// Resolver implementing trait [`ureq::unversioned::resolver::Resolver`].
///
/// Resolves the host to an IP address using [`arti_client::TorClient::resolve`] avoiding DNS leaks.
///
/// An instance of [`Resolver`] can easily be retrieved using [`Connector::resolver()`].
///
/// This is needed when using `ureq::Agent::with_parts`,
/// to avoid leaking DNS queries to the public local network.
/// Usually, use [`Connector::agent`] instead,
/// in which case you don't need to deal explicitly with a `Resolver`.
///
/// # Example
///
/// ```rust,no_run
/// // Retrieve the resolver directly from your `Connector`.
/// let arti_connector = arti_ureq::Connector::new().expect("Failed to create Connector.");
/// let arti_resolver = arti_connector.resolver();
/// let ureq_agent = ureq::Agent::with_parts(
///     ureq::config::Config::default(),
///     arti_connector,
///     arti_resolver,
/// );
/// ```
#[derive(Educe)]
#[educe(Debug)]
pub struct Resolver<R: Runtime> {
    /// [`arti_client::TorClient`] which contains the method [`arti_client::TorClient::resolve`].
    ///
    /// Use [`Connector::resolver`] or pass the client from your `Connector` to create an instance of `Resolver`.
    #[educe(Debug(ignore))]
    client: TorClient<R>,
}

/// Error making or using http connection.
#[derive(Error, Debug)]
#[non_exhaustive]
pub enum Error {
    /// Unsupported URI scheme.
    #[error("unsupported URI scheme in {uri:?}")]
    UnsupportedUriScheme {
        /// URI.
        uri: Uri,
    },

    /// Missing hostname.
    #[error("Missing hostname in {uri:?}")]
    MissingHostname {
        /// URI.
        uri: Uri,
    },

    /// Tor connection failed.
    #[error("Tor connection failed")]
    Arti(#[from] arti_client::Error),

    /// General I/O error.
    #[error("General I/O error")]
    Io(#[from] std::io::Error),

    /// TLS configuration mismatch.
    #[error("TLS provider in config does not match the one in Connector.")]
    TlsConfigMismatch,
}

// Map our own error kinds to Arti's error classification.
impl tor_error::HasKind for Error {
    #[rustfmt::skip]
    fn kind(&self) -> tor_error::ErrorKind {
        use tor_error::ErrorKind as EK;
        match self {
            Error::UnsupportedUriScheme{..} => EK::NotImplemented,
            Error::MissingHostname{..}      => EK::BadApiUsage,
            Error::Arti(e)                  => e.kind(),
            Error::Io(..)                   => EK::Other,
            Error::TlsConfigMismatch        => EK::BadApiUsage,
        }
    }
}

// Convert our own error type to ureq's error type.
impl std::convert::From<Error> for ureq::Error {
    fn from(err: Error) -> Self {
        match err {
            Error::MissingHostname { uri } => {
                ureq::Error::BadUri(format!("Missing hostname in {uri:?}"))
            }
            Error::UnsupportedUriScheme { uri } => {
                ureq::Error::BadUri(format!("Unsupported URI scheme in {uri:?}"))
            }
            Error::Arti(e) => ureq::Error::Io(std::io::Error::other(e)), // TODO #1858
            Error::Io(e) => ureq::Error::Io(e),
            Error::TlsConfigMismatch => {
                ureq::Error::Tls("TLS provider in config does not match the one in Connector.")
            }
        }
    }
}

// Implementation of trait [`ureq::unversioned::transport::Transport`] for [`HttpTransport`].
//
// Due to this implementation [`Connector`] can have a valid transport to be used with `ureq`.
//
// In this implementation we map the `ureq` buffer to the `arti` stream. And map the
// methods to receive and transmit data between `ureq` and `arti`.
//
// Here we also bridge between the sync context `ureq` is usually called from and Arti's async I/O
// by blocking the provided runtime. Preferably a runtime only used for `arti` should be provided.
impl<R: Runtime + ToplevelBlockOn> Transport for HttpTransport<R> {
    // Obtain buffers used by ureq.
    fn buffers(&mut self) -> &mut dyn Buffers {
        &mut self.buffer
    }

    // Write received data from ureq request to arti stream.
    fn transmit_output(&mut self, amount: usize, _timeout: NextTimeout) -> Result<(), ureq::Error> {
        let mut writer = self.w.lock().expect("lock poisoned");

        let buffer = self.buffer.output();
        let data_to_write = &buffer[..amount];

        self.rt.block_on(async {
            writer.write_all(data_to_write).await?;
            writer.flush().await?;
            Ok(())
        })
    }

    // Read data from arti stream to ureq buffer.
    fn await_input(&mut self, _timeout: NextTimeout) -> Result<bool, ureq::Error> {
        let mut reader = self.r.lock().expect("lock poisoned");

        let buffers = self.buffer.input_append_buf();
        let size = self.rt.block_on(reader.read(buffers))?;
        self.buffer.input_appended(size);

        Ok(size > 0)
    }

    // Check if the connection is open.
    fn is_open(&mut self) -> bool {
        // We use `TorClient::connect` without `StreamPrefs::optimistic`,
        // so `.is_connected()` tells us whether the stream has *ceased to be* open;
        // i.e., we don't risk returning `false` because the stream isn't open *yet*.
        self.r.lock().is_ok_and(|guard| {
            guard
                .client_stream_ctrl()
                .is_some_and(|ctrl| ctrl.is_connected())
        })
    }
}

impl ConnectorBuilder<tor_rtcompat::PreferredRuntime> {
    /// Returns instance of [`ConnectorBuilder`] with default values.
    pub fn new() -> Result<Self, Error> {
        Ok(ConnectorBuilder {
            client: None,
            runtime: tor_rtcompat::PreferredRuntime::create()?,
            tls_provider: None,
        })
    }
}

impl<R: Runtime> ConnectorBuilder<R> {
    /// Creates instance of [`Connector`] from the builder.
    pub fn build(self) -> Result<Connector<R>, Error> {
        let client = match self.client {
            Some(client) => client,
            None => TorClient::with_runtime(self.runtime).create_unbootstrapped()?,
        };

        let tls_provider = self.tls_provider.unwrap_or(get_default_tls_provider());

        Ok(Connector {
            client,
            tls_provider,
        })
    }

    /// Creates new [`Connector`] with an explicitly specified [`tor_rtcompat::Runtime`].
    ///
    /// The value `runtime` is only used if no [`arti_client::TorClient`] is configured using [`ConnectorBuilder::tor_client`].
    pub fn with_runtime(runtime: R) -> Result<ConnectorBuilder<R>, Error> {
        Ok(ConnectorBuilder {
            client: None,
            runtime,
            tls_provider: None,
        })
    }

    /// Configure a custom Tor client to be used with [`Connector`].
    ///
    /// Will also cause `client`'s `Runtime` to be used (obtained via [`TorClient::runtime()`]).
    ///
    /// If the client isn't `TorClient<PreferredRuntime>`, use [`ConnectorBuilder::with_runtime()`]
    /// to create a suitable `ConnectorBuilder`.
    pub fn tor_client(mut self, client: TorClient<R>) -> ConnectorBuilder<R> {
        self.runtime = client.runtime().clone();
        self.client = Some(client);
        self
    }

    /// Configure the TLS provider to be used with [`Connector`].
    pub fn tls_provider(mut self, tls_provider: UreqTlsProvider) -> Self {
        self.tls_provider = Some(tls_provider);
        self
    }
}

// Implementation of trait [`ureq::unversioned::resolver::Resolver`] for [`Resolver`].
//
// `Resolver` can be used in [`ureq::Agent::with_parts`] to resolve the host to an IP address.
//
// Uses [`arti_client::TorClient::resolve`].
//
// We highly advice only using `Resolver` instead of e.g `ureq`'s [`ureq::unversioned::resolver::DefaultResolver`] to avoid DNS leaks.
impl<R: Runtime + ToplevelBlockOn> UreqResolver for Resolver<R> {
    /// Method to resolve the host to an IP address using `arti_client::TorClient::resolve`.
    fn resolve(
        &self,
        uri: &Uri,
        _config: &ureq::config::Config,
        _timeout: NextTimeout,
    ) -> Result<ResolvedSocketAddrs, ureq::Error> {
        // We just retrieve the IP addresses using `arti_client::TorClient::resolve` and output
        // it in a format that ureq can use.
        let (host, port) = uri_to_host_port(uri)?;
        let ips = self
            .client
            .runtime()
            .block_on(async { self.client.resolve(&host).await })
            .map_err(Error::from)?;

        let mut array_vec: ArrayVec<core::net::SocketAddr, 16> = ArrayVec::from_fn(|_| {
            core::net::SocketAddr::new(core::net::IpAddr::V4(core::net::Ipv4Addr::UNSPECIFIED), 0)
        });

        for ip in ips {
            let socket_addr = core::net::SocketAddr::new(ip, port);
            array_vec.push(socket_addr);
        }

        Ok(array_vec)
    }
}

impl<R: Runtime + ToplevelBlockOn> Connector<R> {
    /// Creates new instance with the provided [`arti_client::TorClient`].
    pub fn with_tor_client(client: TorClient<R>) -> Connector<R> {
        Connector {
            client,
            tls_provider: get_default_tls_provider(),
        }
    }
}

impl<R: Runtime + ToplevelBlockOn> UreqConnector<()> for Connector<R> {
    type Out = Box<dyn Transport>;

    /// Makes a connection using the Tor client.
    ///
    /// Returns a `HttpTransport` which implements trait [`ureq::unversioned::transport::Transport`].
    fn connect(
        &self,
        details: &ureq::unversioned::transport::ConnectionDetails,
        _chained: Option<()>,
    ) -> Result<Option<Self::Out>, ureq::Error> {
        // Retrieve host and port from the ConnectionDetails.
        let (host, port) = uri_to_host_port(details.uri)?;

        // Convert to an address we can use to connect over the Tor network.
        let addr = (host.as_str(), port)
            .into_tor_addr()
            .map_err(|e| Error::Arti(e.into()))?;

        // Retrieve stream from Tor connection.
        let stream = self
            .client
            .runtime()
            .block_on(async { self.client.connect(addr).await })
            .map_err(Error::from)?;

        // Return a HttpTransport with a reader and writer to the stream.
        let (r, w) = stream.split();
        Ok(Some(Box::new(HttpTransport {
            r: Arc::new(Mutex::new(r)),
            w: Arc::new(Mutex::new(w)),
            buffer: LazyBuffers::new(2048, 2048),
            rt: self.client.runtime().clone(),
        })))
    }
}

impl Connector<tor_rtcompat::PreferredRuntime> {
    /// Returns new `Connector` with default values.
    ///
    /// To configure a non-default `Connector`,
    /// use [`ConnectorBuilder`].
    ///
    /// Warning: This method creates a default [`arti_client::TorClient`]. Using multiple concurrent
    /// instances of `TorClient` is not recommended. Most programs should create a single `TorClient` centrally.
    pub fn new() -> Result<Self, Error> {
        Self::builder()?.build()
    }
}

impl<R: Runtime + ToplevelBlockOn> Connector<R> {
    /// Returns instance of [`Resolver`] implementing trait [`ureq::unversioned::resolver::Resolver`].
    pub fn resolver(&self) -> Resolver<R> {
        Resolver {
            client: self.client.clone(),
        }
    }

    /// Returns instance of [`ureq::Agent`].
    ///
    /// Equivalent to using [`ureq::Agent::with_parts`] with the default [`ureq::config::Config`]
    /// and this `Connector` and the resolver obtained from [`Connector::resolver()`].
    ///
    /// # Example
    ///
    /// ```rust,no_run
    /// let ureq_agent = arti_ureq::Connector::new()
    ///     .expect("Failed to create Connector")
    ///     .agent();
    ///
    /// // Use the agent to make a request.
    /// ureq_agent
    ///     .get("https://check.torproject.org/api/ip")
    ///     .call()
    ///     .expect("Failed to make request.");
    /// ```
    pub fn agent(self) -> ureq::Agent {
        let resolver = self.resolver();

        let ureq_config = ureq::config::Config::builder()
            .tls_config(
                ureq::tls::TlsConfig::builder()
                    .provider(self.tls_provider)
                    .build(),
            )
            .build();

        ureq::Agent::with_parts(ureq_config, self.connector_chain(), resolver)
    }

    /// Returns instance of [`ureq::Agent`] using the provided [`ureq::config::Config`].
    ///
    /// Equivalent to [`Connector::agent`] but allows the user to provide a custom [`ureq::config::Config`].
    pub fn agent_with_ureq_config(
        self,
        config: ureq::config::Config,
    ) -> Result<ureq::Agent, Error> {
        let resolver = self.resolver();

        if self.tls_provider != config.tls_config().provider() {
            return Err(Error::TlsConfigMismatch);
        }

        Ok(ureq::Agent::with_parts(
            config,
            self.connector_chain(),
            resolver,
        ))
    }

    /// Returns connector chain depending on features flag.
    fn connector_chain(self) -> impl UreqConnector {
        let chain = self;

        #[cfg(feature = "rustls")]
        let chain = chain.chain(RustlsConnector::default());

        #[cfg(feature = "native-tls")]
        let chain = chain.chain(NativeTlsConnector::default());

        chain
    }
}

/// Returns the default [`ureq::tls::TlsProvider`] based on the features flag.
pub fn get_default_tls_provider() -> UreqTlsProvider {
    if cfg!(feature = "native-tls") {
        UreqTlsProvider::NativeTls
    } else {
        UreqTlsProvider::Rustls
    }
}

/// Implementation to make [`ConnectorBuilder`] accessible from [`Connector`].
///
/// # Example
///
/// ```rust,no_run
/// let rt = tor_rtcompat::PreferredRuntime::create().expect("Failed to create runtime.");
/// let tls_provider = arti_ureq::get_default_tls_provider();
///
/// let client = arti_client::TorClient::with_runtime(rt.clone())
///     .create_unbootstrapped()
///     .expect("Error creating Tor Client.");
///
/// let builder = arti_ureq::ConnectorBuilder::<tor_rtcompat::PreferredRuntime>::new()
///     .expect("Failed to create ConnectorBuilder.")
///     .tor_client(client)
///     .tls_provider(tls_provider);
///
/// let arti_connector = builder.build();
/// ```
impl Connector<tor_rtcompat::PreferredRuntime> {
    /// Returns new [`ConnectorBuilder`] with default values.
    pub fn builder() -> Result<ConnectorBuilder<tor_rtcompat::PreferredRuntime>, Error> {
        ConnectorBuilder::new()
    }
}

/// Parse the URI.
///
/// Obtain the host and port.
fn uri_to_host_port(uri: &Uri) -> Result<(String, u16), Error> {
    let host = uri
        .host()
        .ok_or_else(|| Error::MissingHostname { uri: uri.clone() })?;

    let port = match uri.scheme() {
        Some(scheme) if scheme == &Scheme::HTTPS => Ok(443),
        Some(scheme) if scheme == &Scheme::HTTP => Ok(80),
        Some(_) => Err(Error::UnsupportedUriScheme { uri: uri.clone() }),
        None => Err(Error::UnsupportedUriScheme { uri: uri.clone() }),
    }?;

    Ok((host.to_owned(), port))
}

#[cfg(test)]
mod arti_ureq_test {
    // @@ begin test lint list maintained by maint/add_warning @@
    #![allow(clippy::bool_assert_comparison)]
    #![allow(clippy::clone_on_copy)]
    #![allow(clippy::dbg_macro)]
    #![allow(clippy::mixed_attributes_style)]
    #![allow(clippy::print_stderr)]
    #![allow(clippy::print_stdout)]
    #![allow(clippy::single_char_pattern)]
    #![allow(clippy::unwrap_used)]
    #![allow(clippy::unchecked_time_subtraction)]
    #![allow(clippy::useless_vec)]
    #![allow(clippy::needless_pass_by_value)]
    //! <!-- @@ end test lint list maintained by maint/add_warning @@ -->

    use super::*;
    use arti_client::config::TorClientConfigBuilder;
    use std::str::FromStr;
    use test_temp_dir::test_temp_dir;

    const ARTI_TEST_LIVE_NETWORK: &str = "ARTI_TEST_LIVE_NETWORK";
    const ARTI_TESTING_ON_LOCAL: &str = "ARTI_TESTING_ON_LOCAL";

    // Helper function to check if two types are equal. The types in this library are to
    // complex to use the `==` operator or (Partial)Eq. So we compare the types of the individual properties instead.
    fn assert_equal_types<T>(_: &T, _: &T) {}

    // Helper function to check if the environment variable ARTI_TEST_LIVE_NETWORK is set to 1.
    // We only want to run tests using the live network when the user explicitly wants to.
    fn test_live_network() -> bool {
        let run_test = std::env::var(ARTI_TEST_LIVE_NETWORK).is_ok_and(|v| v == "1");
        if !run_test {
            println!("Skipping test, set {}=1 to run.", ARTI_TEST_LIVE_NETWORK);
        }

        run_test
    }

    // Helper function to check if the environment variable ARTI_TESTING_ON_LOCAL is set to 1.
    // Some tests, especially those that create default `Connector` instances, or test the `ConnectorBuilder`,
    // are not reliable when run on CI.  We don't know why that is.  It's probably a bug.  TODO fix the tests!
    fn testing_on_local() -> bool {
        let run_test = std::env::var(ARTI_TESTING_ON_LOCAL).is_ok_and(|v| v == "1");
        if !run_test {
            println!("Skipping test, set {}=1 to run.", ARTI_TESTING_ON_LOCAL);
        }

        run_test
    }

    // Helper method to allow tests to be ran in a closure.
    fn test_with_tor_client<R: Runtime>(rt: R, f: impl FnOnce(TorClient<R>)) {
        let temp_dir = test_temp_dir!();
        temp_dir.used_by(move |temp_dir| {
            let arti_config = TorClientConfigBuilder::from_directories(
                temp_dir.join("state"),
                temp_dir.join("cache"),
            )
            .build()
            .expect("Failed to build TorClientConfig");

            let tor_client = arti_client::TorClient::with_runtime(rt)
                .config(arti_config)
                .create_unbootstrapped()
                .expect("Error creating Tor Client.");

            f(tor_client);
        });
    }

    // Helper function to make a request to check.torproject.org/api/ip and check if
    // it was done over Tor.
    fn request_is_tor(agent: ureq::Agent, https: bool) -> bool {
        let mut request = agent
            .get(format!(
                "http{}://check.torproject.org/api/ip",
                if https { "s" } else { "" }
            ))
            .call()
            .expect("Failed to make request.");
        let response = request
            .body_mut()
            .read_to_string()
            .expect("Failed to read body.");
        let json_response: serde_json::Value =
            serde_json::from_str(&response).expect("Failed to parse JSON.");
        json_response
            .get("IsTor")
            .expect("Failed to retrieve IsTor property from response")
            .as_bool()
            .expect("Failed to convert IsTor to bool")
    }

    // Quick internal test to check if our helper function `equal_types` works as expected.
    // Otherwise our other tests might not be reliable.
    #[test]
    fn test_equal_types() {
        assert_equal_types(&1, &i32::MIN);
        assert_equal_types(&1, &i64::MIN);
        assert_equal_types(&String::from("foo"), &String::with_capacity(1));
    }

    // `Connector::new` should return the default `Connector`.
    // This test is only ran when ARTI_TESTING_ON_LOCAL is set to 1.
    #[test]
    #[cfg(all(feature = "rustls", not(feature = "native-tls")))]
    fn articonnector_new_returns_default() {
        if !testing_on_local() {
            return;
        }

        let actual_connector = Connector::new().expect("Failed to create Connector.");
        let expected_connector = Connector {
            client: TorClient::with_runtime(
                tor_rtcompat::PreferredRuntime::create().expect("Failed to create runtime."),
            )
            .create_unbootstrapped()
            .expect("Error creating Tor Client."),
            tls_provider: UreqTlsProvider::Rustls,
        };

        assert_equal_types(&expected_connector, &actual_connector);
        assert_equal_types(
            &actual_connector.client.runtime().clone(),
            &tor_rtcompat::PreferredRuntime::create().expect("Failed to create runtime."),
        );
        assert_eq!(
            &actual_connector.tls_provider,
            &ureq::tls::TlsProvider::Rustls,
        );
    }

    // `Connector::with_tor_client` should return a `Connector` with specified Tor client set.
    // This test is only ran when ARTI_TESTING_ON_LOCAL is set to 1.
    #[test]
    #[cfg(all(feature = "rustls", not(feature = "native-tls")))]
    fn articonnector_with_tor_client() {
        if !testing_on_local() {
            return;
        }

        let tor_client = TorClient::with_runtime(
            tor_rtcompat::PreferredRuntime::create().expect("Failed to create runtime."),
        )
        .create_unbootstrapped()
        .expect("Error creating Tor Client.");

        let actual_connector = Connector::with_tor_client(tor_client);
        let expected_connector = Connector {
            client: TorClient::with_runtime(
                tor_rtcompat::PreferredRuntime::create().expect("Failed to create runtime."),
            )
            .create_unbootstrapped()
            .expect("Error creating Tor Client."),
            tls_provider: UreqTlsProvider::Rustls,
        };

        assert_equal_types(&expected_connector, &actual_connector);
        assert_equal_types(
            &actual_connector.client.runtime().clone(),
            &tor_rtcompat::PreferredRuntime::create().expect("Failed to create runtime."),
        );
        assert_eq!(
            &actual_connector.tls_provider,
            &ureq::tls::TlsProvider::Rustls,
        );
    }

    // The default instance returned by `Connector::builder` should equal to the default `Connector`.
    // This test is only ran when ARTI_TESTING_ON_LOCAL is set to 1.
    #[test]
    fn articonnectorbuilder_new_returns_default() {
        if !testing_on_local() {
            return;
        }

        let expected = Connector::new().expect("Failed to create Connector.");
        let actual = Connector::<tor_rtcompat::PreferredRuntime>::builder()
            .expect("Failed to create ConnectorBuilder.")
            .build()
            .expect("Failed to create Connector.");

        assert_equal_types(&expected, &actual);
        assert_equal_types(&expected.client.runtime(), &actual.client.runtime());
        assert_eq!(&expected.tls_provider, &actual.tls_provider);
    }

    // `ConnectorBuilder::with_runtime` should return a `ConnectorBuilder` with the specified runtime set.
    // This test is only ran when ARTI_TESTING_ON_LOCAL is set to 1.
    #[cfg(all(feature = "tokio", feature = "rustls"))]
    #[test]
    fn articonnectorbuilder_with_runtime() {
        if !testing_on_local() {
            return;
        }

        let arti_connector = ConnectorBuilder::with_runtime(
            tor_rtcompat::tokio::TokioRustlsRuntime::create().expect("Failed to create runtime."),
        )
        .expect("Failed to create ConnectorBuilder.")
        .build()
        .expect("Failed to create Connector.");

        assert_equal_types(
            &arti_connector.client.runtime().clone(),
            &tor_rtcompat::tokio::TokioRustlsRuntime::create().expect("Failed to create runtime."),
        );

        let arti_connector = ConnectorBuilder::with_runtime(
            tor_rtcompat::PreferredRuntime::create().expect("Failed to create runtime."),
        )
        .expect("Failed to create ConnectorBuilder.")
        .build()
        .expect("Failed to create Connector.");

        assert_equal_types(
            &arti_connector.client.runtime().clone(),
            &tor_rtcompat::PreferredRuntime::create().expect("Failed to create runtime."),
        );
    }

    // `ConnectorBuilder::tor_client` should return a `Connector` with the specified `TorClient` set.
    #[cfg(all(feature = "tokio", feature = "rustls"))]
    #[test]
    fn articonnectorbuilder_set_tor_client() {
        let rt =
            tor_rtcompat::tokio::TokioRustlsRuntime::create().expect("Failed to create runtime.");

        test_with_tor_client(rt.clone(), move |tor_client| {
            let arti_connector = ConnectorBuilder::with_runtime(rt)
                .expect("Failed to create ConnectorBuilder.")
                .tor_client(tor_client.clone().isolated_client())
                .build()
                .expect("Failed to create Connector.");

            assert_equal_types(
                &arti_connector.client.runtime().clone(),
                &tor_rtcompat::tokio::TokioRustlsRuntime::create()
                    .expect("Failed to create runtime."),
            );
        });
    }

    // Test if the method `uri_to_host_port` returns the correct parameters.
    #[test]
    fn test_uri_to_host_port() {
        let uri = Uri::from_str("http://torproject.org").expect("Error parsing uri.");
        let (host, port) = uri_to_host_port(&uri).expect("Error parsing uri.");

        assert_eq!(host, "torproject.org");
        assert_eq!(port, 80);

        let uri = Uri::from_str("https://torproject.org").expect("Error parsing uri.");
        let (host, port) = uri_to_host_port(&uri).expect("Error parsing uri.");

        assert_eq!(host, "torproject.org");
        assert_eq!(port, 443);

        let uri = Uri::from_str("https://www.torproject.org/test").expect("Error parsing uri.");
        let (host, port) = uri_to_host_port(&uri).expect("Error parsing uri.");

        assert_eq!(host, "www.torproject.org");
        assert_eq!(port, 443);
    }

    // Test if `arti-ureq` default agent uses Tor to make the request.
    // This test is only ran when ARTI_TEST_LIVE_NETWORK is set to 1.
    #[test]
    fn request_goes_over_tor() {
        if !test_live_network() {
            return;
        }

        let is_tor = request_is_tor(
            default_agent().expect("Failed to retrieve default agent."),
            true,
        );

        assert_eq!(is_tor, true);
    }

    // Test if `arti-ureq` default agent uses Tor to make the request.
    // This test also checks if the Tor API returns false when the request is made with an
    // `ureq` agent that is not configured to use Tor to ensure the test is reliable.
    // This test is only ran when ARTI_TEST_LIVE_NETWORK is set to 1.
    #[test]
    #[cfg(all(feature = "rustls", not(feature = "native-tls")))]
    fn request_goes_over_tor_with_unsafe_check() {
        if !test_live_network() {
            return;
        }

        let is_tor = request_is_tor(ureq::Agent::new_with_defaults(), true);
        assert_eq!(is_tor, false);

        let is_tor = request_is_tor(
            default_agent().expect("Failed to retrieve default agent."),
            true,
        );
        assert_eq!(is_tor, true);
    }

    // Test if the `ureq` client configured with `Connector` uses Tor tor make the request using bare HTTP.
    // This test is only ran when ARTI_TEST_LIVE_NETWORK is set to 1.
    #[test]
    fn request_with_bare_http() {
        if !test_live_network() {
            return;
        }

        let rt = tor_rtcompat::PreferredRuntime::create().expect("Failed to create runtime.");

        test_with_tor_client(rt, |tor_client| {
            let arti_connector = Connector::with_tor_client(tor_client);
            let is_tor = request_is_tor(arti_connector.agent(), false);

            assert_eq!(is_tor, true);
        });
    }

    // Test if `get_default_tls_provider` correctly derives the TLS provider from the feature flags.
    #[test]
    fn test_get_default_tls_provider() {
        #[cfg(feature = "native-tls")]
        assert_eq!(get_default_tls_provider(), UreqTlsProvider::NativeTls);

        #[cfg(not(feature = "native-tls"))]
        assert_eq!(get_default_tls_provider(), UreqTlsProvider::Rustls);
    }

    // Test if configuring the `Connector` using `get_default_tls_provider` correctly sets the TLS provider
    // based on the feature flags.
    // This test is only ran when ARTI_TESTING_ON_LOCAL is set to 1.
    #[test]
    fn test_tor_client_with_get_default_tls_provider() {
        if !testing_on_local() {
            return;
        }

        let tor_client = TorClient::with_runtime(
            tor_rtcompat::PreferredRuntime::create().expect("Failed to create runtime."),
        )
        .create_unbootstrapped()
        .expect("Error creating Tor Client.");

        let arti_connector = Connector::<tor_rtcompat::PreferredRuntime>::builder()
            .expect("Failed to create ConnectorBuilder.")
            .tor_client(tor_client.clone().isolated_client())
            .tls_provider(get_default_tls_provider())
            .build()
            .expect("Failed to create Connector.");

        #[cfg(feature = "native-tls")]
        assert_eq!(
            &arti_connector.tls_provider,
            &ureq::tls::TlsProvider::NativeTls,
        );

        #[cfg(not(feature = "native-tls"))]
        assert_eq!(
            &arti_connector.tls_provider,
            &ureq::tls::TlsProvider::Rustls,
        );
    }
}
