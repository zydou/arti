
2023-08-23

Here are some notes about high level api/ui design for onion services,
and what it might look like.

2023-08-28

See [!1541](https://gitlab.torproject.org/tpo/core/arti/-/merge_requests/1541)
for comments on this note.

# Top CLI level: the `arti` CLI tool.

I'm imagining that the configuration looks something like this:

```toml
# I'm making this an array of 'onion_service' tables.
#
# One alternative would be to make it a set of named tables
# as in "[onion_service.example_name]".
[[onion_service]]

# This is the only required option.  It sets a nickname
# for the onion service that's used to identity it in the
# interface and key manager.
#
# Different onion services must have different names.
name = "example"

# If false, this onion service isn't actually enabled.
# We're providing this as a convenience to make it easier
# to turn services on and off.
enabled = true

# I had thought of calling this is_single_onion_service but I am
# frightened to make this too easy to set by accident.  Honestly
# I would prefer that its name be even scarier.
is_non_anonymous = false

####
# These options are about setting limits on concurrency and
# introduction rate.
####

# This option is a (rate,burst) tuple that we should send to
# the introduction point to configure how many introduction
# requests it accepts.  I'm open to a better way to
# specify these.
rate_limit_at_intro = [ 100, 500 ]

# How many streams will we allow to be open at once for this service?
max_concurrent_streams = 1000

# How many streams will we allow to be open at once for a single circuit
# on this service?
max_concurrent_streams_per_circuit = 10

# If true, will we require proof-of-work when we're under heavy load.
enable_proof_of_work = true

# Rate/burst for dispatching requests from rendezvous request queue when
# pow defense is enabled.  I don't know if we want to duplicate this
# mechanism, but tor does it.
pow_queue_rate = [ 100, 500 ]

# Disable the compiled hashx backend for proof-of-work.
disable_pow_compilation = false

# Descriptor-based client authentication.  If this is set
# to any array, even an empty one, then authentication is required.
encrypt_descriptor = [
    'curve25519:aaaaaaa', # A given public key can be put in the config.
    'dir:/path/to/dir', # A directory full of keys can be listed.
]
# Note that you can also give a singleton, as in:
# encrypt_descriptor = 'dir:/path/to/dir".

# Set the number of introduction points to try to use for the onion service.
num_intro_points = 3

# This option configures port relaying, which is the only option
# available at the CLI for actually implementing an onion service.
#
# The syntax for each port is:
#   [ SOURCE, DEST ]
#
# Allowable SOURCE values are:
#   integer:     a port.
#   'low-high':  a range of ports
#   '*':         matches all ports.
#
# Allowable destination values are:
#
#   'tcp:sockaddr' or 'sockaddr'
#        forward to a given socket address
#   'unix:/path'
#        forward to an AF_LOCAL address.
#   'reject'
#        close the stream.
#   'ignore'
#        ignore the request. (Q: Should this even exist?)
#   'destroy':
#        tear down the circuit.
#
# The patterns in `proxy_ports` match from first to last; we take
# the first one that matches.  If no pattern matches, we tear down
# the circuit.
#
proxy_ports = [
   [80, '127.0.0.1:9998'],
   [443, '127.0.0.1:9999'],
   ['1-1024', 'reject'],
   ['*', 'ignore']
]
```


# Top API level: the `arti-client` API.

I think we translate the above options into a set of configuration
structures something like this.

(In areas there this isn't a 100% match for the above we should probably
reconcile them to minimize needless divergence.)

```
pub struct OnionSvcConfig {
    // note that this is the only option that can't be changed.  Maybe
    // that means that instead of making it part of the OnionSvcConfig
    // it should be at a higher level?  IOW, instead of Vec<OnionSvcConfig>,
    // we would have HashMap<String,OnionSvcConfig>.

    name: String,
    enabled: bool,
    rate_limits: RateLimitConfig,
    pow: ProofOfWorkConfig,
    encrypt_descriptor: Option<DescEncryption>

    // Note that this doesn't include proxy configuration
    // at this level, since that's not part of the onion
    // service itself.
}

pub struct TokenBucketConfig {
    max_per_sec: u32,
    max_burst: u32,
}

pub struct RateLimitConfig {
    rate_limit_at_intro: Option<TokenBucketConfig>,
    max_concurrent_streams: u32, // or Option<NonZeroU32>
    max_concurrent_streams_per_circuit: u32, // or Option<NonZeroU32>
}

pub struct ProofOfWorkCOnfig {
    enable: bool,
    queue_rate: Option<TokenBucketConfig>,
    disable_compilation: bool
}

pub struct DescEncryption {
    authorized_client: Vec<AuthorizedClient>,
}

pub enum AuthorizedClient {
    DirectoryOfKeys(PathBuf),
    Curve25519Key(curve25519::PublicKey),
}

mod proxy {

    pub struct ProxyConfig {
        rules: Vec<ProxyRule>,
    }

    pub struct ProxyRule {
        source: ProxyPattern,
        target: ProxyTarget,
    }

    pub enum ProxyPattern {
        Port(u16),
	PortRange(u16,u16),
	All,
    }

    pub enum ProxyTarget {
        Tcp(SocketAddr),
	Unix(PathBuf),
	RejectStream,
	DropStream,
	DestroyCircuit
    }
}
```


On to the APIs.  I'm imagining that these methods goes into `TorClient`:

```
pub async fn launch_onion_service(&self, config: OnionSvcConfig) {
    -> Result<(Arc<OnionSvc>, impl Stream<Item=IncomingStream>)>
{
   ...
}
// ^ Note that if we move `name` out of the config, we should
// make it an argument here.

pub fn lookup_onion_service(&self, name: &str) -> Option<Arc<OnionSvc>>
{
   ...
}
```

There's an `OnionSvc` handle in the return value here so that we can
manage the service.  It's in an `Arc<>` so that it's visible to the RPC
system.

I think that the API for `OnionSvc` looks something like this:

```
impl OnionSvc {
   pub fn reconfigure(&self, new_config: OnionSvcConfig) -> Result<()> {..}
   pub fn shutdown(&self) -> Result<()> {..}
   pub fn detach(&self) -> Result<()> {..}
}
```

To implement proxies, I think we do something like this.  I think it goes
in a separate crate.

```
pub struct OnionSvcProxy {
  ..
}

impl OnionSvcProxy {
   pub fn new(
       config: ProxyConfig,
       streams: impl Stream<Item=IncomingStream>
   ) -> Result<Self>
   { .. }

   pub fn reconfigure(&self, new_config: ProxyConfig) -> Result<()> {..}

   // implementation function. Runs forever. Probably not public.
   fn handle_requests_loop(&self) -> Result<()> {..}

   // run forever in a new task.
   pub fn launch<R:Runtime>(&self) -> Result<()> {..}
}
```


# Missing APIs

For some purposes we'd like to have an "ephemeral" onion service: this
amounts to one where we don't store anything on disk and instead
the caller takes responsibility for key management and persistence.

Would this be as simple as providing an alternative API like this?

```
pub async fn launch_ephemeral_onion_service(
    &self,
    config: OnionSvcConfig
    persistence: OnionSvcPersist) {
    -> Result<(Arc<OnionSvc>, impl Stream<Item=IncomingStream>)>
{
   ...
}

pub struct OnionSvcPersist {
   my_state_handler: Box<dyn tor_persist::StorageHandle<serde_json::Object>>,

   my_key_mgr: Box<dyn AbstractKeyMgr>,
}
```

