# A few notes about onion services

## A higher level vs a lower level.

As I'm working through all of the design elements below, I'm realizing
that we have the possibility for both a high-level API and a low-level
API.  The low-level API wouldn't need to handle persistence or making
outbound connections; it would just provide `DataStreams` and let the
caller load and save things as needed.  The higher level API would
behave more like C tor, providing a 'reverse proxy' and opening
stream connections to local applications.


## What we need to save on disk

Right now C tor stores this information:

`DIR/hostname`: The hostname of the onion service, with trailing
.onion.  Tor writes this but does not read it.

`DIR/private_key`: The top level identity key (`KS_hs_id`) for the
onion service.

`DIR/client_keys`: A list of authorized clients; optional.  Tor reads
this but does not write it.

`DIR/onion_service_non_anonymous`: present if this is a non-anonymous
service.

`DIR/ob_config`: present if this is an onion balance input; contains a
"master onion address key" which is one level higher than the KP_hs_id
used for the onion address of this service.  We can defer this
until we add onionbalance support.


It's absolutely necessary to support making `KS_hs_id` persistent, or
we can't create the same onion service over time.  The other stuff can
be read or written in other ways, though maintaining the current interface
_would_ allow compatibility with C installations.


## Notes about configuration

Right now C tor has these options.  They're all prefixed with
`HiddenService` but let's just ignore that.

### High-level options.

Here we talk about the higher-level APIs.  These are all APIs that we
would or could implement _on top of_ the lower-level API I'm going to
be discussing below.

These are **must-have** **high-level** options.  (They are must-have
_in some form_, and the form can be quite different.)

`Dir`: Location on disk to store info for this onion service.

`Port`: mapping from virtual port received in begin cell
to local port where we should send streams. AF_UNIX addresses are supported


Client authorization file: Stored on disk. Is a directory full of files
with the contents: `<auth-type>:<key-type>:<base32-encoded-public-key>`.

> Note: the "client authorization" terminology is deprecated.
> "Client authorizatio" is now known as "restricted discovery".

These are **nice-to-have** **high-level** options:

`ExportCircuitId`: Special protocol to use in exposing a global
circuit ID for whatever circuit originated each stream. Right now
`haproxy` is supported.

`DirGroupReadable`: Allow the directory to be group-readable.

`OnionBalanceInstance`: Exposes extra data used by `OnionBalance`.
(TODO: find out what this does?)



I suggest that we do not provide these **high-level** options:

`AllowUnknownPorts`: Do not close the circuit when we get a request
for a port we don't recognize.  (This is 0 by default to avoid port-scanning)


### Low-level options

Here are the lower-level options.  We'd need to port these to work with
our lower-level APIs.

These are **should-have** **low-level** options:

`NumIntroductionPoints`: How many introduction points to
try to have.  (This turns out to be important for tuning, IIUC)

These are **nice-to-have** **low-level** options:

`SingleHopMode`, `NonAnonymousMode`: Makes services non-anonymous.  Global.

We should build these out as part of our anti-DoS mechanisms:

`EnableIntroDosDefense`, `IntroDosBurstPerSec`,
`IntroDosRatePerSec`: configure rate-limiting for how many
introduction requests to accept at each introduction point.
This is enforced jointly with the introduction point.

`PoWDefensesEnabled` `PoWQueueRate` `PoWQueueBurst`,
`CompiledProofOfWorkHash`: configuration for the proof-of-work
mechanism.

We can defer this indefinitely, until we need it:

`PublishHidServDescriptor`: Do not publish any
descriptors. Global. Only useful if you're having something else
publish for you.

I **do not know** whether this is high-level or low-level, or how
necessary it is:

`MaxStreams`: Limit simultaneous connections on a rendezvous circuit.

`MaxStreamsCloseCircuit`: Whether to close the circuit if the number of
streams tries to exceed the limit.

I suggest that we do not  build this** low-level** option:

`Version`: Always 3.


## Projected data structures and APIs

```
enum Anonymity {
    Anonymous,
    DangerouslyNonAnonymous,
}

struct ServiceConfig {
   /// An arbitrary identifier or "nickname" used to look up this service's
   /// keys, state, configuration, etc,
   /// and distinguish them from other services.  This is local-only.
   nickname: String,

   /// Whether we want this to be a non-anonymous "single onion service".
   /// We could skip this in v1.  We should make sure that our state
   /// is built to make it hard to accidentally set this.
   anonymity: Anonymity,

   /// Number of intro points; defaults to 3; max 20.
   num_intro_points: Option<u8>,

   /// Not sure if client encryption belongs as a configuration item, or
   /// as a directory like C tor does?
}

pub struct Service {
   inner: Mutex<Inner>
}

struct ServiceInner {
   /// Configuration of this service
   config: ServiceConfig,

   /// Used to look up our keys
   keymgr: Arc<KeyMgr>,

   /// Used to decide whom to encrypt descriptor to.
   desc_encryption_auth: Option<DescEncryptionAuth>,

   current_keys: {
       // Possibly we cache keys here that we've loaded?
       // Possibly we store keys here that don't go in the keymgr?
       // we probably want to keep certs around.
   },


   /// Possibly a generational arena , so we can make IntroPointId
   /// into a generational index?
   intro_point_state: Vec<IntroPointState>,

   desc_upload_history: DescUploadHistory,
}


struct DescUploadHistory {
   /// We can have multiple simultaneous variants of our
   /// descriptor of there are different time periods active now,
   /// I think?
   ///
   /// Possibly we should just have multiple instances of DescUploadHistory?
   ///
   /// Possibly we should (eventually, not v1) try to decorrelate uploads
   /// where the BlindIdKey is different
   descriptors_last_rebuilt: Instant,

   descriptors: HashMap<HsBlindIdKey, (String, HsDe)>,

   /// Status with uploading the latest version of each descriptor to
   /// each relevant hsdir.
   upload_targets: HashMap<RelayIds, (HsBlindIdKey, RetryState)>,
}

struct DescEncryptionAuth {
    Vec<x25519::PublicKey>,
 }


struct IntroPointState {
   /// TODO diziet is writing this, I think.
}


impl Service {
     /// At some point you can launch a service and get a stream
     /// of all the requests to rendezvous.
     pub fn launch(...) -> Result<mpsc::Receiver<RendRequest>>;
}

pub enum IntroAuth {
/// Deliberately empty; nothing is implemented here.
}

// TODO: Use Beth's api instead.
enum ProofOfWork {
     EquixV1 { effort_level: usize }
}

/// We create one of these whenever we get a well-formed INTRODUCE2
/// message, based on this, we the caller decides whether to send a
/// RENDEZVOUS2 message.
pub struct RendRequest {
    from_intro_point: IntroPointId,
    client_auth_provided: Option<ClientAuth>,
    proof_of_work_provided: Option<ProofOfWork>,
    rend_circuit: Arc<ClientCirc>,

    info_needed_to_send_rendezvous2 : (
       OwnedChanTarget,  // The location of the rendezvous point.
       x25519::PublicKey, // The ntor key for the rendezvous point.
       HandshakeState, // Not a real type; used to finish the handshake.
    ),
}

// TODO: Not sure that the functions here and below need to be
// async, or if they should send messages on one-shots.

impl RendRequest {
     pub async fn accept(self) -> Result<mpsc::Receiver<StreamRequest>>;
     pub async fn reject(self) -> Result<()>;
     // also various accessors
}

pub struct StreamRequest {
    stream: DataStream, // Or possibly some other type that can turn
    	                // into a DataStream.
    target: SocketAddr,

    // doesn't need to include a ClientCirc, since the DataStream
    // can give you its circuit.
}

pub struct ServiceDataStream {
    inner: DataStream,
}

impl StreamRequest
    pub async fn accept(self) -> Result<ServiceDataStream>;
    pub async fn reject(self) -> Result<()>;
    pub fn shutdown_circuit(self) -> Result<()>;
    // various accessors, including for circuit.
}
```

# Tickets to open

- API to inquire about number of current open streams on a circuit.

