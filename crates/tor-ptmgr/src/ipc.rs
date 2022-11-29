//! Launching pluggable transport binaries and communicating with them.
//!
//! This module contains utilities to launch pluggable transports supporting pt-spec.txt
//! version 1, and communicate with them in order to specify configuration parameters and
//! receive updates as to the current state of the PT.

use crate::err;
use crate::err::PtError;
use futures::channel::mpsc;
use futures::channel::mpsc::Receiver;
use futures::StreamExt;
use std::borrow::Cow;
use std::collections::HashMap;
use std::ffi::OsString;
use std::io::{BufRead, BufReader};
use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr};
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::str::FromStr;
use std::sync::Arc;
use std::time::{Duration, Instant};
use std::{io, thread};
use tor_config::Itertools;
use tor_linkspec::PtTransportName;
use tor_rtcompat::{Runtime, SleepProviderExt};
use tor_socksproto::SocksVersion;
use tracing::{debug, error, info, trace, warn};

/// Amount of time we give a pluggable transport child process to exit gracefully.
const GRACEFUL_EXIT_TIME: Duration = Duration::from_secs(5);
/// Default timeout for PT binary startup.
const PT_START_TIMEOUT: Duration = Duration::from_secs(30);
/// Size for the buffer storing pluggable transport stdout lines.
const PT_STDIO_BUFFER: usize = 64;

/// An arbitrary key/value status update from a pluggable transport.
#[derive(PartialEq, Eq, Debug, Clone)]
pub struct PtStatus {
    /// The name of the pluggable transport.
    transport: PtTransportName,
    /// Arbitrary key-value data about the state of this transport, from the binary running
    /// said transport.
    // NOTE(eta): This is assumed to not have duplicate keys.
    data: HashMap<String, String>,
}

/// A message sent from a pluggable transport child process.
///
/// For more in-depth information about these messages, consult pt-spec.txt.
#[derive(PartialEq, Eq, Debug, Clone)]
#[non_exhaustive]
#[cfg_attr(feature = "experimental-api", visibility::make(pub))]
pub(crate) enum PtMessage {
    /// `VERSION-ERROR`: No compatible pluggable transport specification version was provided.
    VersionError(String),
    /// `VERSION`: Specifies the version the binary is using for the IPC protocol.
    Version(String),
    /// `ENV-ERROR`: Reports an error with the provided environment variables.
    EnvError(String),
    /// `PROXY DONE`: The configured proxy was correctly initialised.
    ProxyDone,
    /// `PROXY-ERROR`: An error was encountered setting up the configured proxy.
    ProxyError(String),
    /// `CMETHOD`: A client transport has been launched.
    ClientTransportLaunched {
        /// The name of the launched transport.
        transport: PtTransportName,
        /// The protocol used ('socks4' or 'socks5').
        protocol: String,
        /// An address to connect via this transport.
        endpoint: SocketAddr,
    },
    /// `CMETHOD-ERROR`: An error was encountered setting up a client transport.
    ClientTransportFailed {
        /// The name of the transport.
        transport: PtTransportName,
        /// The error message.
        message: String,
    },
    /// `CMETHODS DONE`: All client transports that are supported have been launched.
    ClientTransportsDone,
    /// `SMETHOD`: A server transport has been launched.
    ServerTransportLaunched {
        /// The name of the launched transport.
        transport: PtTransportName,
        /// The endpoint clients should use the reach the transport.
        endpoint: SocketAddr,
        /// Additional per-transport information.
        // NOTE(eta): This assumes it actually is k/v and repeated keys aren't allowed...
        options: HashMap<String, String>,
    },
    /// `SMETHOD-ERROR`: An error was encountered setting up a server transport.
    ServerTransportFailed {
        /// The name of the transport.
        transport: PtTransportName,
        /// The error message.
        message: String,
    },
    /// `SMETHODS DONE`: All server transports that are supported have been launched.
    ServerTransportsDone,
    /// `LOG`: A log message.
    Log {
        /// The severity (one of 'error', 'warning', 'notice', 'info', 'debug').
        severity: String,
        /// The log message.
        message: String,
    },
    /// `STATUS`: Arbitrary key/value status messages.
    Status(PtStatus),
    /// A line containing an unknown command.
    Unknown(String),
}

/// Parse a value (something on the RHS of an =), which could be a CString as defined by
/// control-spec.txt §2. Returns (value, unparsed rest of string).
fn parse_one_value(from: &str) -> Result<(String, &str), &'static str> {
    let first_char = from.chars().next();
    Ok(if first_char.is_none() {
        (String::new(), "")
    } else if let Some('"') = first_char {
        // This is a CString, so we're going to need to parse it char-by-char.
        // FIXME(eta): This currently doesn't parse octal escape codes, even though the spec says
        //             we should. That's finicky, though, and probably not used.
        let mut ret = String::new();
        let mut chars = from.chars();
        assert_eq!(chars.next(), Some('"')); // discard "
        loop {
            let ch = chars.next().ok_or("ran out of input parsing CString")?;
            match ch {
                '\\' => match chars
                    .next()
                    .ok_or("encountered trailing backslash in CString")?
                {
                    'n' => ret.push('\n'),
                    'r' => ret.push('\r'),
                    't' => ret.push('\t'),
                    '0'..='8' => return Err("attempted unsupported octal escape code"),
                    _ => ret.push(ch),
                },
                '"' => break,
                _ => ret.push(ch),
            }
        }
        (ret, chars.as_str())
    } else {
        // Simple: just find the space
        let space = from.find(' ').unwrap_or(from.len());
        (from[0..space].into(), &from[space..])
    })
}

/// Chomp one key/value pair off a list of smethod args.
/// Returns (k, v, unparsed rest of string).
/// Will also chomp the comma at the end, if there is one.
fn parse_one_smethod_arg(args: &str) -> Result<(String, String, &str), &'static str> {
    // NOTE(eta): Apologies for this looking a bit gnarly. Ideally, this is what you'd use
    //            something like `nom` for, but I didn't want to bring in a dep just for this.

    let mut key = String::new();
    let mut val = String::new();
    // If true, we're reading the value, not the key.
    let mut reading_val = false;
    let mut chars = args.chars();
    while let Some(c) = chars.next() {
        let target = if reading_val { &mut val } else { &mut key };
        match c {
            '\\' => {
                let c = chars
                    .next()
                    .ok_or("smethod arg terminates with backslash")?;
                target.push(c);
            }
            '=' => {
                if reading_val {
                    return Err("encountered = while parsing value");
                }
                reading_val = true;
            }
            ',' => break,
            c => target.push(c),
        }
    }
    if !reading_val {
        return Err("ran out of chars parsing smethod arg");
    }
    Ok((key, val, chars.as_str()))
}

impl FromStr for PtMessage {
    type Err = Cow<'static, str>;

    // NOTE(eta): This, of course, implies that the PT IPC communications are valid UTF-8.
    //            This assumption might turn out to be false.
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        // TODO(eta): Maybe tolerate additional whitespace (using `split_whitespace`)?.
        //            This requires modified words.join() logic, though.
        let mut words = s.split(' ');
        let first_word = words.next().ok_or_else(|| Cow::from("empty line"))?;
        Ok(match first_word {
            "VERSION-ERROR" => {
                let rest = words.join(" ");
                Self::VersionError(rest)
            }
            "VERSION" => {
                let vers = words.next().ok_or_else(|| Cow::from("no version"))?;
                Self::Version(vers.into())
            }
            "ENV-ERROR" => {
                let rest = words.join(" ");
                Self::EnvError(rest)
            }
            "PROXY" => match words.next() {
                Some("DONE") => Self::ProxyDone,
                _ => Self::Unknown(s.into()),
            },
            "PROXY-ERROR" => {
                let rest = words.join(" ");
                Self::ProxyError(rest)
            }
            "CMETHOD" => {
                let transport = words.next().ok_or_else(|| Cow::from("no transport"))?;
                let protocol = words.next().ok_or_else(|| Cow::from("no protocol"))?;
                let endpoint = words
                    .next()
                    .ok_or_else(|| Cow::from("no endpoint"))?
                    .parse::<SocketAddr>()
                    .map_err(|e| Cow::from(format!("failed to parse endpoint: {}", e)))?;
                Self::ClientTransportLaunched {
                    transport: transport
                        .parse()
                        .map_err(|_| Cow::from("bad transport ID"))?,
                    protocol: protocol.to_string(),
                    endpoint,
                }
            }
            "CMETHOD-ERROR" => {
                let transport = words.next().ok_or_else(|| Cow::from("no transport"))?;
                let rest = words.join(" ");
                Self::ClientTransportFailed {
                    transport: transport
                        .parse()
                        .map_err(|_| Cow::from("bad transport ID"))?,
                    message: rest,
                }
            }
            "CMETHODS" => match words.next() {
                Some("DONE") => Self::ClientTransportsDone,
                _ => Self::Unknown(s.into()),
            },
            "SMETHOD" => {
                let transport = words.next().ok_or_else(|| Cow::from("no transport"))?;
                let endpoint = words
                    .next()
                    .ok_or_else(|| Cow::from("no endpoint"))?
                    .parse::<SocketAddr>()
                    .map_err(|e| Cow::from(format!("failed to parse endpoint: {}", e)))?;
                let mut parsed_args = HashMap::new();

                // NOTE(eta): pt-spec.txt seems to imply these options can't contain spaces, so
                //            we work under that assumption.
                //            It also doesn't actually parse them out -- but seeing as the API to
                //            feed these back in will want them as separated k/v pairs, I think
                //            it makes sense to here.
                for option in words {
                    if let Some(mut args) = option.strip_prefix("ARGS:") {
                        while !args.is_empty() {
                            let (k, v, rest) = parse_one_smethod_arg(args).map_err(|e| {
                                Cow::from(format!("failed to parse SMETHOD ARGS: {}", e))
                            })?;
                            if parsed_args.contains_key(&k) {
                                // At least check our assumption that this is actually k/v
                                // and not Vec<(String, String)>.
                                warn!("PT SMETHOD arguments contain repeated key {}!", k);
                            }
                            parsed_args.insert(k, v);
                            args = rest;
                        }
                    }
                }
                Self::ServerTransportLaunched {
                    transport: transport
                        .parse()
                        .map_err(|_| Cow::from("bad transport ID"))?,
                    endpoint,
                    options: parsed_args,
                }
            }
            "SMETHOD-ERROR" => {
                let transport = words.next().ok_or_else(|| Cow::from("no transport"))?;
                let rest = words.join(" ");
                Self::ServerTransportFailed {
                    transport: transport
                        .parse()
                        .map_err(|_| Cow::from("bad transport ID"))?,
                    message: rest,
                }
            }
            "SMETHODS" => match words.next() {
                Some("DONE") => Self::ServerTransportsDone,
                _ => Self::Unknown(s.into()),
            },
            "LOG" => {
                let severity = words
                    .next()
                    .ok_or_else(|| Cow::from("no severity"))?
                    .strip_prefix("SEVERITY=")
                    .ok_or_else(|| Cow::from("badly formatted severity"))?;
                let message = words.join(" ");
                let message = parse_one_value(
                    message
                        .strip_prefix("MESSAGE=")
                        .ok_or_else(|| Cow::from("no or badly formatted message"))?,
                )
                .map_err(Cow::from)?
                .0;
                Self::Log {
                    severity: severity.into(),
                    message,
                }
            }
            "STATUS" => {
                let mut ret = HashMap::new();
                let message = words.join(" ");
                let mut message = &message as &str;
                while !message.is_empty() {
                    let equals = message
                        .find('=')
                        .ok_or_else(|| Cow::from(format!("failed to find = in '{}'", message)))?;
                    let k = &message[..equals];
                    if equals + 1 == message.len() {
                        return Err(Cow::from("key with no value"));
                    }
                    let (v, rest) = parse_one_value(&message[(equals + 1)..]).map_err(Cow::from)?;
                    if ret.contains_key(k) {
                        // At least check our assumption that this is actually k/v
                        // and not Vec<(String, String)>.
                        warn!("STATUS contains repeated key {}!", k);
                    }
                    ret.insert(k.to_owned(), v);
                    message = rest;
                    if message.starts_with(' ') {
                        message = &message[1..];
                    }
                }
                let transport = ret
                    .remove("TRANSPORT")
                    .ok_or_else(|| Cow::from("no TRANSPORT in STATUS"))?;
                Self::Status(PtStatus {
                    transport: transport
                        .parse()
                        .map_err(|_| Cow::from("bad transport ID"))?,
                    data: ret,
                })
            }
            _ => Self::Unknown(s.into()),
        })
    }
}

/// A handle to receive lines from a pluggable transport process' stdout asynchronously.
//
// FIXME(eta): This currently spawns an OS thread, since there's no other way to do this without
//             being async-runtime dependent (or adding process spawning to tor-rtcompat).
#[derive(Debug)]
struct AsyncPtChild {
    /// Channel to receive lines from the child process stdout.
    stdout: Receiver<io::Result<String>>,
    /// Identifier to put in logging messages.
    identifier: String,
}

impl AsyncPtChild {
    /// Wrap an OS child process by spawning a worker thread to forward output from the child
    /// to the asynchronous runtime via use of a channel.
    fn new(mut child: Child, identifier: String) -> Option<Self> {
        let (stdin, stdout) = (child.stdin.take()?, child.stdout.take()?);
        let (mut tx, rx) = mpsc::channel(PT_STDIO_BUFFER);
        thread::spawn(move || {
            let reader = BufReader::new(stdout);
            let _stdin = stdin;
            // Forward lines from the blocking reader to the async channel.
            for line in reader.lines() {
                let err = line.is_err();
                if let Ok(ref l) = line {
                    trace!("<-- PT: {}", l);
                }
                if let Err(e) = tx.try_send(line) {
                    if e.is_disconnected() {
                        // Channel dropped, so shut down the pluggable transport process.
                        break;
                    }
                    // The other kind of error is "full", which we can't do anything about
                    // (and logging would be spammy). Just throw the line away.
                }
                if err {
                    // Encountered an error reading, so ensure the process is shut down (it's
                    // probably "broken pipe" anyway, so this is slightly redundant, but the
                    // rest of the code assumes errors are nonrecoverable).
                    break;
                }
            }
            // Has it already quit? If so, just exit now.
            if let Ok(Some(_)) = child.try_wait() {
                // FIXME(eta): We currently throw away the exit code, which might be useful
                //             for debugging purposes!
                return;
            }
            // Otherwise, tell it to exit.
            // Dropping stdin should tell the PT to exit, since we set the correct environment
            // variable for that to happen.
            drop(_stdin);
            // Give it some time to exit.
            thread::sleep(GRACEFUL_EXIT_TIME);
            match child.try_wait() {
                Ok(None) => {
                    // Kill it.
                    if let Err(e) = child.kill() {
                        warn!("Failed to kill() spawned PT: {}", e);
                    }
                }
                Ok(Some(_)) => {} // It exited.
                Err(e) => {
                    warn!("Failed to call try_wait() on spawned PT: {}", e);
                }
            }
        });
        Some(AsyncPtChild {
            stdout: rx,
            identifier,
        })
    }

    /// Receive a message from the pluggable transport binary asynchronously.
    ///
    /// Note: This will convert `PtMessage::Log` into a tracing log call automatically.
    async fn recv(&mut self) -> err::Result<PtMessage> {
        loop {
            match self.stdout.next().await {
                None => return Err(PtError::ChildGone),
                Some(Ok(line)) => {
                    let line = line
                        .parse::<PtMessage>()
                        .map_err(|e| PtError::IpcParseFailed {
                            line,
                            error: e.into(),
                        })?;
                    if let PtMessage::Log { severity, message } = line {
                        // FIXME(eta): I wanted to make this integrate with `tracing` more nicely,
                        //             but gave up after 15 minutes of clicking through spaghetti.
                        match &severity as &str {
                            "error" => error!("[pt {}] {}", self.identifier, message),
                            "warning" => warn!("[pt {}] {}", self.identifier, message),
                            "notice" => info!("[pt {}] {}", self.identifier, message),
                            "info" => debug!("[pt {}] {}", self.identifier, message),
                            "debug" => trace!("[pt {}] {}", self.identifier, message),
                            x => warn!("[pt] {} {} {}", self.identifier, x, message),
                        }
                    } else {
                        return Ok(line);
                    }
                }
                Some(Err(e)) => {
                    return Err(PtError::ChildReadFailed(Arc::new(e)));
                }
            }
        }
    }
}

/// Parameters passed to a pluggable transport.
#[derive(PartialEq, Eq, Clone, Debug, derive_builder::Builder)]
pub struct PtParameters {
    /// A path where the launched PT can store state.
    state_location: PathBuf,
    /// An IPv4 address to bind outgoing connections to (if specified).
    ///
    /// Leaving this out will mean the PT uses a sane default.
    #[builder(default)]
    outbound_bind_v4: Option<Ipv4Addr>,
    /// An IPv6 address to bind outgoing connections to (if specified).
    ///
    /// Leaving this out will mean the PT uses a sane default.
    #[builder(default)]
    outbound_bind_v6: Option<Ipv6Addr>,
    /// A SOCKS URI specifying a proxy to use.
    #[builder(default)]
    proxy_uri: Option<String>,
    /// A list of transports to initialise.
    ///
    /// The PT launch will fail if all transports are not successfully initialised.
    transports: Vec<PtTransportName>,
    /// The maximum time we should wait for a pluggable transport binary to report successful
    /// initialization. If `None`, a default value is used.
    #[builder(default)]
    timeout: Option<Duration>,
}

impl PtParameters {
    /// Return a new `PtParametersBuilder` for constructing a set of parameters.
    pub fn builder() -> PtParametersBuilder {
        PtParametersBuilder::default()
    }

    /// Convert these parameters into a set of environment variables to be passed to the PT binary
    /// in accordance with the specification.
    fn environment_variables(&self) -> HashMap<OsString, OsString> {
        let mut ret = HashMap::new();
        ret.insert("TOR_PT_MANAGED_TRANSPORT_VER".into(), "1".into());
        ret.insert(
            "TOR_PT_STATE_LOCATION".into(),
            self.state_location.clone().into_os_string(),
        );
        ret.insert("TOR_PT_EXIT_ON_STDIN_CLOSE".into(), "1".into());
        if let Some(v4) = self.outbound_bind_v4 {
            ret.insert(
                "TOR_PT_OUTBOUND_BIND_ADDRESS_V4".into(),
                v4.to_string().into(),
            );
        }
        if let Some(v6) = self.outbound_bind_v6 {
            // pt-spec.txt: "IPv6 addresses MUST always be wrapped in square brackets."
            ret.insert(
                "TOR_PT_OUTBOUND_BIND_ADDRESS_V6".into(),
                format!("[{}]", v6).into(),
            );
        }
        if let Some(ref proxy_uri) = self.proxy_uri {
            ret.insert("TOR_PT_PROXY".into(), proxy_uri.clone().into());
        }
        ret.insert(
            "TOR_PT_CLIENT_TRANSPORTS".into(),
            self.transports.iter().join(",").into(),
        );
        ret
    }
}

/// A SOCKS endpoint to connect through a pluggable transport.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PtClientMethod {
    /// The SOCKS protocol version to use.
    pub(crate) kind: SocksVersion,
    /// The socket address to connect to.
    pub(crate) endpoint: SocketAddr,
}

impl PtClientMethod {
    /// Get the SOCKS protocol version to use.
    pub fn kind(&self) -> SocksVersion {
        self.kind
    }

    /// Get the socket address to connect to.
    pub fn endpoint(&self) -> SocketAddr {
        self.endpoint
    }
}

/// A pluggable transport binary in a child process.
///
/// These start out inert, and must be launched with [`PluggableTransport::launch`] in order
/// to be useful.
#[derive(Debug)]
pub struct PluggableTransport {
    /// The currently running child, if there is one.
    inner: Option<AsyncPtChild>,
    /// The path to the binary to run.
    pub(crate) binary_path: PathBuf,
    /// Arguments to pass to the binary.
    arguments: Vec<String>,
    /// Configured parameters.
    params: PtParameters,
    /// Information about client methods obtained from the PT.
    cmethods: HashMap<PtTransportName, PtClientMethod>,
}

impl PluggableTransport {
    /// Create a new pluggable transport wrapper, wrapping the binary at `binary_path` and passing
    /// the `params` to it.
    ///
    /// You must call [`PluggableTransport::launch`] to actually run the PT.
    pub fn new(binary_path: PathBuf, arguments: Vec<String>, params: PtParameters) -> Self {
        Self {
            params,
            arguments,
            binary_path,
            inner: None,
            cmethods: Default::default(),
        }
    }

    /// Get all client methods returned by the binary, if it has been launched.
    ///
    /// If it hasn't been launched, the returned map will be empty.
    // TODO(eta): Actually figure out a way to expose this more stably.
    #[allow(dead_code)] // TODO: remove unless this turns out to be useful.
    pub(crate) fn transport_methods(&self) -> &HashMap<PtTransportName, PtClientMethod> {
        &self.cmethods
    }

    /// Get the next [`PtMessage`] from the running transport. It is recommended to call this
    /// in a loop once a PT has been launched, in order to forward log messages and find out about
    /// status updates.
    //
    // FIXME(eta): This API will probably go away and get replaced with something better.
    //             In particular, we'd want to cache `Status` messages from before this method
    //             was called.
    #[cfg_attr(feature = "experimental-api", visibility::make(pub))]
    pub(crate) async fn next_message(&mut self) -> err::Result<PtMessage> {
        let inner = self.inner.as_mut().ok_or(PtError::ChildGone)?;
        let ret = inner.recv().await;
        if let Err(PtError::ChildGone) | Err(PtError::ChildReadFailed { .. }) = ret {
            // FIXME(eta): Currently this lets the caller still think the methods work by calling
            //             transport_methods.
            self.inner = None;
        }
        ret
    }
    /// Launch the pluggable transport, executing the binary.
    ///
    /// Will return an error if the launch fails, one of the transports fail, not all transports
    /// were launched, or the launch times out.
    pub async fn launch<R: Runtime>(&mut self, rt: R) -> err::Result<()> {
        if self.inner.is_some() {
            warn!(
                "Attempted to launch PT binary for {:?} twice.",
                self.params.transports
            );
            return Ok(());
        }
        info!(
            "Launching pluggable transport at {} for {:?}",
            self.binary_path.display(),
            self.params.transports
        );
        let child = Command::new(&self.binary_path)
            .args(self.arguments.iter())
            .envs(self.params.environment_variables())
            .stdout(Stdio::piped())
            .stdin(Stdio::piped())
            .spawn()
            .map_err(|e| PtError::ChildSpawnFailed {
                path: self.binary_path.clone(),
                error: Arc::new(e),
            })?;

        let identifier = self
            .binary_path
            .file_name()
            .map(|x| x.to_string_lossy().to_string())
            .unwrap_or_else(|| "unknown".to_string());

        // FIXME(eta): Arguably, this error should be a panic or bug. Not sure how frequent this
        //             failure case is.
        let mut async_child =
            AsyncPtChild::new(child, identifier).ok_or(PtError::StdioUnavailable)?;

        let deadline = Instant::now() + self.params.timeout.unwrap_or(PT_START_TIMEOUT);
        let mut cmethods = HashMap::new();
        let mut proxy_done = self.params.proxy_uri.is_none();

        loop {
            match rt
                .timeout(
                    // FIXME(eta): It'd be nice if SleepProviderExt took an `Instant` natively.
                    deadline.saturating_duration_since(Instant::now()),
                    async_child.recv(),
                )
                .await
                .map_err(|_| PtError::Timeout)??
            {
                PtMessage::VersionError(e) => {
                    if e != "no-version" {
                        warn!("weird VERSION-ERROR: {}", e);
                    }
                    return Err(PtError::UnsupportedVersion);
                }
                PtMessage::Version(vers) => {
                    if vers != "1" {
                        return Err(PtError::ProtocolViolation(format!(
                            "stated version is {}, asked for 1",
                            vers
                        )));
                    }
                }
                PtMessage::EnvError(e) => return Err(PtError::ChildProtocolViolation(e)),
                PtMessage::ProxyDone => {
                    if proxy_done {
                        return Err(PtError::ProtocolViolation(
                            "binary initiated proxy when not asked (or twice)".into(),
                        ));
                    }
                    info!("PT binary now proxying connections via supplied URI");
                    proxy_done = true;
                }
                PtMessage::ProxyError(e) => return Err(PtError::ProxyError(e)),
                PtMessage::ClientTransportLaunched {
                    transport,
                    protocol,
                    endpoint,
                } => {
                    if !self.params.transports.contains(&transport) {
                        return Err(PtError::ProtocolViolation(format!(
                            "binary launched unwanted transport '{}'",
                            transport
                        )));
                    }
                    let protocol = match &protocol as &str {
                        "socks4" => SocksVersion::V4,
                        "socks5" => SocksVersion::V5,
                        x => {
                            return Err(PtError::ProtocolViolation(format!(
                                "unknown CMETHOD protocol '{}'",
                                x
                            )))
                        }
                    };
                    let method = PtClientMethod {
                        kind: protocol,
                        endpoint,
                    };
                    info!("Transport '{}' uses method {:?}", transport, method);
                    cmethods.insert(transport, method);
                }
                PtMessage::ClientTransportFailed { transport, message } => {
                    return Err(PtError::ClientTransportFailed {
                        transport: transport.to_string(),
                        message,
                    })
                }
                PtMessage::ClientTransportsDone => {
                    let unsupported = self
                        .params
                        .transports
                        .iter()
                        .filter(|&x| !cmethods.contains_key(x))
                        .map(|x| x.to_string())
                        .collect::<Vec<_>>();
                    if !unsupported.is_empty() {
                        warn!(
                            "PT binary failed to initialise transports: {:?}",
                            unsupported
                        );
                        return Err(PtError::ClientTransportsUnsupported(unsupported));
                    }
                    info!("PT binary initialisation done");
                    break;
                }
                // TODO(eta): We don't do anything with these right now!
                PtMessage::Status(_) => {}
                PtMessage::Unknown(x) => {
                    warn!("unknown PT line: {}", x);
                }
                x => {
                    return Err(PtError::ProtocolViolation(format!(
                        "received unexpected {:?}",
                        x
                    )));
                }
            }
        }
        self.cmethods = cmethods;
        self.inner = Some(async_child);
        // TODO(eta): We need to expose the log and status messages after this function exits!
        Ok(())
    }
}

#[cfg(test)]
mod test {
    // @@ begin test lint list maintained by maint/add_warning @@
    #![allow(clippy::bool_assert_comparison)]
    #![allow(clippy::clone_on_copy)]
    #![allow(clippy::dbg_macro)]
    #![allow(clippy::print_stderr)]
    #![allow(clippy::print_stdout)]
    #![allow(clippy::single_char_pattern)]
    #![allow(clippy::unwrap_used)]
    //! <!-- @@ end test lint list maintained by maint/add_warning @@ -->

    use crate::ipc::{PtMessage, PtStatus};
    use std::collections::HashMap;
    use std::net::{IpAddr, Ipv4Addr, SocketAddr};

    #[test]
    fn it_parses_spec_examples() {
        assert_eq!(
            "VERSION-ERROR no-version".parse(),
            Ok(PtMessage::VersionError("no-version".into()))
        );
        assert_eq!("VERSION 1".parse(), Ok(PtMessage::Version("1".into())));
        assert_eq!(
            "ENV-ERROR No TOR_PT_AUTH_COOKIE_FILE when TOR_PT_EXTENDED_SERVER_PORT set".parse(),
            Ok(PtMessage::EnvError(
                "No TOR_PT_AUTH_COOKIE_FILE when TOR_PT_EXTENDED_SERVER_PORT set".into()
            ))
        );
        assert_eq!("PROXY DONE".parse(), Ok(PtMessage::ProxyDone));
        assert_eq!(
            "PROXY-ERROR SOCKS 4 upstream proxies unsupported".parse(),
            Ok(PtMessage::ProxyError(
                "SOCKS 4 upstream proxies unsupported".into()
            ))
        );
        assert_eq!(
            "CMETHOD trebuchet socks5 127.0.0.1:19999".parse(),
            Ok(PtMessage::ClientTransportLaunched {
                transport: "trebuchet".parse().unwrap(),
                protocol: "socks5".to_string(),
                endpoint: SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 19999)
            })
        );
        assert_eq!(
            "CMETHOD-ERROR trebuchet no rocks available".parse(),
            Ok(PtMessage::ClientTransportFailed {
                transport: "trebuchet".parse().unwrap(),
                message: "no rocks available".to_string()
            })
        );
        assert_eq!("CMETHODS DONE".parse(), Ok(PtMessage::ClientTransportsDone));
        assert_eq!(
            "SMETHOD trebuchet 198.51.100.1:19999".parse(),
            Ok(PtMessage::ServerTransportLaunched {
                transport: "trebuchet".parse().unwrap(),
                endpoint: SocketAddr::new(IpAddr::V4(Ipv4Addr::new(198, 51, 100, 1)), 19999),
                options: Default::default()
            })
        );
        let mut map = HashMap::new();
        map.insert("N".to_string(), "13".to_string());
        assert_eq!(
            "SMETHOD rot_by_N 198.51.100.1:2323 ARGS:N=13".parse(),
            Ok(PtMessage::ServerTransportLaunched {
                transport: "rot_by_N".parse().unwrap(),
                endpoint: SocketAddr::new(IpAddr::V4(Ipv4Addr::new(198, 51, 100, 1)), 2323),
                options: map
            })
        );
        let mut map = HashMap::new();
        map.insert(
            "cert".to_string(),
            "HszPy3vWfjsESCEOo9ZBkRv6zQ/1mGHzc8arF0y2SpwFr3WhsMu8rK0zyaoyERfbz3ddFw".to_string(),
        );
        map.insert("iat-mode".to_string(), "0".to_string());
        assert_eq!(
            "SMETHOD obfs4 198.51.100.1:43734 ARGS:cert=HszPy3vWfjsESCEOo9ZBkRv6zQ/1mGHzc8arF0y2SpwFr3WhsMu8rK0zyaoyERfbz3ddFw,iat-mode=0".parse(),
            Ok(PtMessage::ServerTransportLaunched {
                transport: "obfs4".parse().unwrap(),
                endpoint: SocketAddr::new(IpAddr::V4(Ipv4Addr::new(198, 51, 100, 1)), 43734),
                options: map
            })
        );
        assert_eq!(
            "SMETHOD-ERROR trebuchet no cows available".parse(),
            Ok(PtMessage::ServerTransportFailed {
                transport: "trebuchet".parse().unwrap(),
                message: "no cows available".to_string()
            })
        );
        assert_eq!(
            "LOG SEVERITY=debug MESSAGE=\"Connected to bridge A\"".parse(),
            Ok(PtMessage::Log {
                severity: "debug".to_string(),
                message: "Connected to bridge A".to_string()
            })
        );
        let mut map = HashMap::new();
        map.insert("ADDRESS".to_string(), "198.51.100.123:1234".to_string());
        map.insert("CONNECT".to_string(), "Success".to_string());
        assert_eq!(
            "STATUS TRANSPORT=obfs4 ADDRESS=198.51.100.123:1234 CONNECT=Success".parse(),
            Ok(PtMessage::Status(PtStatus {
                transport: "obfs4".parse().unwrap(),
                data: map
            }))
        );
        let mut map = HashMap::new();
        map.insert("ADDRESS".to_string(), "198.51.100.222:2222".to_string());
        map.insert("CONNECT".to_string(), "Failed".to_string());
        map.insert("FINGERPRINT".to_string(), "<Fingerprint>".to_string());
        map.insert("ERRSTR".to_string(), "Connection refused".to_string());
        assert_eq!(
            "STATUS TRANSPORT=obfs4 ADDRESS=198.51.100.222:2222 CONNECT=Failed FINGERPRINT=<Fingerprint> ERRSTR=\"Connection refused\"".parse(),
            Ok(PtMessage::Status(PtStatus {
                transport: "obfs4".parse().unwrap(),
                data: map
            }))
        );
    }
}
