# ERROR HANDLING IN TOR-* AND ARTI-*

## Plan

### In arti-client.

The arti-client crate is our primary point of entry.  It exposes a mostly-opaque Error type, and an ErrorKind type derived from its inner (hidden) data. 

The stable, supported ways to get information from arti_client::Error are:

 * display it.
 * if you must, access its source().
 * call its kind() method, and match on the ErrorKind.

The ErrorKind enum contains a number of possible error types.  Each is designed for high-level consumption: its documentation should explain why such an error might occur, and what the application might want to do about it.  (If we cannot write such documentation for an ErrorKind, it is probably wrong.)

There is additionally an unstable way to get more detailed information from an arti_client::Error.  If you have enabled the "error-details" feature, you can call a detail() method, to access an inner ErrorDetail enum with a more specific breakdown of where the error occurred, how, and why.

Using the "error-details" feature breaks your semver guarantees on the arti-client crate.  If you ever need to do so, then possibly one of us is mistaken: maybe we have made a mistake in designing Error or ErrorKind, or maybe there is a better way to do what you're trying to achieve.  Please get in touch so that we can help figure out the best solution.

We are making the arti_client::Error type opaque so that we have freedom to radically refactor ErrorDetail, as well as the Error types from other crates.  We are exposing it behind a feature because we recognize that we will inevitably make some mistakes in our designs, and it's important to allow escape hatches for users with tricky needs.


### In ErrorDetail, and in other crates' Error types.

Everywhere else besides arti_error::Error, we try to make our error types follow these general patterns:

 * All should implement Clone, Display, Error, Debug, Send, Sync, 'static.
 * When we wrap an inner error, we always include context information describing what was happening when the inner error occurred.  This means that we should usually not `impl From<TheirInner> for MyError`.
 * Whenever appropriate, we have a `pub fn kind(&self) -> ErrorKind` function.
 * When a public function can fail for a number of reasons that are much more limited than the crate's entire Error type, we should consider giving that function its own Error type.
 * We use `Box<>` as needed to keep the size of the enumeration fairly small.
 * We allow more instability in these types than we allow in arti_client: these types should be inaccessible from the arti_client when "error-details" is not enabled.


## SOME EXAMPLES

### In arti-client

We expose a mostly-type-erased error type with an API like:

```
/// A general error produced by a TorClient.
///
/// Specific functions may produce more specific error types.
///
/// In general, you should be able to interact with this function through
/// the `kind()` method and through the [`ErrorKind`] enumeration. 
///
/// If you absolutely need to dive inside of an error for more information,
/// you can use the "error-details" feature to expose a more specific
/// ErrorDetail type.  Doing so will void your semver warranty!  If you need to do
/// this, please let us know: it might be an indication that we should expose more
/// information in our stable API.
#[derive(Debug,Clone)]
pub struct Error {
    detail: ErrorDetail
}

impl std::error::Error for Error {
    /// Here is the type-erased cause.
    fn source(&self) -> Option<&(dyn Error + 'static)> { Some(&self.detail) }
}

impl Display for Error { ... }

impl Error {
    pub fn kind(&self) -> ErrorKind { self.detail.kind() }
    #[cfg(feature("error-details"))]
    pub fn detail(&self) -> &ErrorDetail { &self.detail }
}

/// The inner error type that we only expose when "error-details" is enabled.
///
/// This is not covered by semver guarantees in the arti-client crate!
///
/// If you need to use this type, we have probably failed to expose enough information
/// via Error and ErrorKind.
#[derive(Debug,Clone)]
enum ErrorDetail {
    // The variants here are designed similarly to the mid-level crate error types below.
    CircuitBuildFailed { ... }
    CouldntBootstrap { ... }
}

#[cfg(feature("error-details"))]
pub use ErrorDetail; // This becomes public only if we have

impl std::error::Error for ErrorDetail { ... }

impl ErrorDetail {
    pub fn kind(&self) -> ErrorKind { ... }
}
```

### In most mid-level crates

The error type looks like this:

```
/// A general error from the tor-foo crate.
///
/// 
#[derive(Debug,Clone, Display)]
#[non_exhaustive] // this is belt and braces, since we don't make much API stability guarantee
    ConnectionFailed {
        target: RelayId
        cause: Arc<io::Error>,
    },
    ConnectionDropped {
        partner: RelayId,
        cause: Arc<io::Error>,
    },
    ConnectionTimeout {
        target: RelayId,
    },
    ProtocolViolated {
        partner: RelayId,
        problem: tor_proto::Error,
    },
    ...
    
    // Here is what we try NOT to do:
    Io(Arc<io::Error>), // no context information!
}

// We can do this impl with thiserror, but we don't use thiserror's `#[from]`
impl std::err::Error for Error { ... }

impl Display for Error { ... }

impl Error {
    pub fn kind(&self) -> ErrorKind { ... }
}
```

We try to avoid having blanket implementations of `From<other::Error>` for crate::Error, unless we are _sure_ that they can't lose context.


For error types that are more specific to functions, we use more specific enumerations, as in:

```
impl FromStr for Id {
	type Err = ParseIdError; // GOOD!
	// type Err = crate::Error // BAD!
     ...
}
```

We _do_ expose the entire error enumeration from these crates.  That means we might need to break their compatibility more often; so be it.

**TODO**: should be documented somewhere! perhaps more generally ("tor-* crates are more unstable")

#### Who is responsible for putting calling parameters into the error?

Eg, tor-chanmgr has this:

    type BuildSpec = OwnedChanTarget;
    async fn build_channel(&self, target: &Self::BuildSpec) -> crate::Result<Self::Channel> {

If the build fails, then someone is responsible for putting the `OwnedChatTarget` (or some subset of the information in it) into the error structure.

This should be the *calling* crate.  Otherwise the same context information must be duplicated for every variant of the lower crate error.  In the upper crate, it can be in only one variant.

For example, when tor-circmgr calls `build_channel`, it is tor-circmgr which is responsible for putting the context in the outer error variant, ie

```
  enum tor_circmgr::Error {
      ...
      ChannelFailed {
          target: OwnedChanTarget,
          cause: tor_chanmgr::Error,
      }
```

#### Describing the error type

When a problem is reported, different error types should generally produce different messages.  Where should this be done?

Answer: the place where the type is embedded.  For example:

```
  enum tor_circmgr::Error {
      /// Problem with channel
      #[error("Problem with channel to {peer}")]
      ChanFailed {
          cause: tor_chanmgr::Error,

  enum tor_chanmgr::Error  {
      /// Network IO error or TLS error
      #[error("Network IO error, or TLS error, talking to {peer}")]
      Io {
          /// Who we were talking to
          peer: SocketAddr,
```

So the channel error does not say that it *is* a channel error, just as an `io::Error` doesn't say that it is an IO error.  `tor_chanmgr::Error::Io` says that it is an IO error; when that is found inside eg a `tor_circmgr::Error`, the circmgr error is responsible for saying it's about a channel (and describing relevant channel properties).

### In a new tor-errorkind crate


```
/// A categorization of error from Arti.
///
/// We try to make this a _useful_ categorization primarily.  Each kind's
/// documentation should say when we expect that kind of error to occur, what 
/// might cause it, and what you might decide to do about it.
#[derive(Debug,Clone,Copy,Display)]
#[non_exhaustive]
pub enum ErrorKind {
    // **Note from Diziet, disposition TBD**
    //
    //     I think many of these kinds are rather more detailed than a caller could usefully do
    //     much with.  ISTM that we probably want to distinguish "trouble making connections over
    //     the public internet near us" from "problem is definitely within the Tor network" from
    //     "problem is on the outer public internet on the far side of the tor network".  But not
    //     much more than that.  Or to put it another way, how to operationalise these: "use local
    //     network changes as a hint to try again", "other target hosts may work better", "you're
    //     stuffed unless you want to try doing thing non-anonymously" (or maybe try restarting tor
    //     or using different tor config??)
    //     
    //     They ought to be operationalisable by users too; categorising errors that way is useful.
    //     So "internal error" is a kind because it means "maybe try upgrading your tor"
    //
    //     I don't think at this high level we can usefully distinguish ENETUNREACH from a timeout,
    //     eg.
    //     
    //     Possibly "someone is *misbehaving* on the tor network and that is why this is going
    //     wrong" is operationally useful to a user, as distinguished from "the tor network is not
    //     functioning correctly but this is a plausible failure so doesn't necessarily mean peer
    //     is buggy or malicious"
    
    /// An operation found that it couldn't make connections on the internet.
    ///
    /// If these are persistent, then there's likely something wrong with the
    /// user's internet connection or configuration; the best option is to tell
    /// them so.  Possibly, you should check the bootstrapping status to see if
    /// it's been able to diagnose a particular problem.
    NetUnreachable,
    /// We encountered a bug which we didn't expect in our code.
    ///
    /// You should never see this case.  If you do, there's a mistake in our code:
    /// please report it on our friendly bugtracker.
    InternalBug,
    /// We were waiting for a response on the network from some relay, but that
    /// response never came.
    ///
    /// This might mean that the resource you wanted is unavailable for now, but 
    /// retrying later might help.
    RelayTimeout,
    /// We told an exit relay to open a stream on our behalf, but we waited too long 
    /// for the response.
    ///
    /// This might be a problem with the server we were trying to connect to, or it
    /// might be a problem with the exit.  It might work if you try again on a 
    /// different circuit, or after the server has come back online.
    ConnTimeout,

    // ... and so on.  Each error kind should tell the API user what
    // probably caused it, and what they're expected to do about it.
    
    MisbehavingRelay,
    IdMismatch,
     ...
}
```


## InternalError idea

We will have a single `InternalError` type which `Into<everything::Error>`.

Matching on internal errors (ie bugs) is not going to be useful for callers.  It might want to have a backtrace in it as well as something resembling an assertion message.

We'll have something like an `internal!` macro that works like `panic!` to generate this type
