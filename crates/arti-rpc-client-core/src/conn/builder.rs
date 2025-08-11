//! Functionality to connect to an RPC server.

use std::{
    collections::HashMap,
    io::{self},
    path::PathBuf,
    str::FromStr as _,
};

use fs_mistrust::Mistrust;
use tor_config_path::{CfgPath, CfgPathResolver};
use tor_rpc_connect::{
    ClientErrorAction, HasClientErrorAction, ParsedConnectPoint,
    auth::RpcAuth,
    load::{LoadError, LoadOptions},
};

use crate::{RpcConn, conn::ConnectError, llconn, msgs::response::UnparsedResponse};

use super::ConnectFailure;

/// An error occurred while trying to construct or manipulate an [`RpcConnBuilder`].
#[derive(Clone, Debug, thiserror::Error)]
#[non_exhaustive]
pub enum BuilderError {
    /// We couldn't decode a provided connect string.
    #[error("Invalid connect string.")]
    InvalidConnectString,
}

/// Information about how to construct a connection to an Arti instance.
//
// TODO RPC: Once we have our formats more settled, add a link to a piece of documentation
// explaining what a connect point is and how to make one.
#[derive(Default, Clone, Debug)]
pub struct RpcConnBuilder {
    /// Path entries provided programmatically.
    ///
    /// These are considered after entries in
    /// the `$ARTI_RPC_CONNECT_PATH_OVERRIDE` environment variable,
    /// but before any other entries.
    /// (See `RPCConnBuilder::new` for details.)
    ///
    /// These entries are stored in reverse order.
    prepend_path_reversed: Vec<SearchEntry>,
}

/// A single entry in the search path used to find connect points.
///
/// Includes information on where we got this entry
/// (environment variable, application, or default).
#[derive(Clone, Debug)]
struct SearchEntry {
    /// The source telling us this entry.
    source: ConnPtOrigin,
    /// The location to search.
    location: SearchLocation,
}

/// A single location in the search path used to find connect points.
#[derive(Clone, Debug)]
enum SearchLocation {
    /// A literal connect point entry to parse.
    Literal(String),
    /// A path to a connect file, or a directory full of connect files.
    Path {
        /// The path to load.
        path: CfgPath,

        /// If true, then this entry comes from a builtin default,
        /// and relative paths should cause the connect attempt to be declined.
        ///
        /// Otherwise, this entry comes from the user or application,
        /// and relative paths should cause the connect attempt to abort.
        is_default_entry: bool,
    },
}

/// Diagnostic: An explanation of where we found a connect point,
/// and why we looked there.
#[derive(Debug, Clone)]
pub struct ConnPtDescription {
    /// What told us to look in this location
    source: ConnPtOrigin,
    /// Where we found the connect point.
    location: ConnPtLocation,
}

impl std::fmt::Display for ConnPtDescription {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "connect point in {}, from {}",
            &self.location, &self.source
        )
    }
}

/// Diagnostic: a source telling us where to look for a connect point.
#[derive(Clone, Copy, Debug)]
enum ConnPtOrigin {
    /// Found the search entry from an environment variable.
    EnvVar(&'static str),
    /// Application manually inserted the search entry.
    Application,
    /// The search entry was a built-in default
    Default,
}

impl std::fmt::Display for ConnPtOrigin {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ConnPtOrigin::EnvVar(varname) => write!(f, "${}", varname),
            ConnPtOrigin::Application => write!(f, "application"),
            ConnPtOrigin::Default => write!(f, "default list"),
        }
    }
}

/// Diagnostic: Where we found a connect point.
#[derive(Clone, Debug)]
enum ConnPtLocation {
    /// The connect point was given as a literal string.
    Literal(String),
    /// We expanded a CfgPath to find the location of a connect file on disk.
    File {
        /// The path as configured
        path: CfgPath,
        /// The expanded path.
        expanded: Option<PathBuf>,
    },
    /// We expanded a CfgPath to find a directory, and found the connect file
    /// within that directory
    WithinDir {
        /// The path of the directory as configured.
        path: CfgPath,
        /// The location of the file.
        file: PathBuf,
    },
}

impl std::fmt::Display for ConnPtLocation {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Note: here we use Path::display(), which in other crates we forbid
        // and use tor_basic_utils::PathExt::display_lossy().
        //
        // Here we make an exception, since arti-rpc-client-core is meant to have
        // minimal dependencies on our other crates.
        #[allow(clippy::disallowed_methods)]
        match self {
            ConnPtLocation::Literal(s) => write!(f, "literal string {:?}", s),
            ConnPtLocation::File {
                path,
                expanded: Some(ex),
            } => {
                write!(f, "file {} [{}]", path, ex.display())
            }
            ConnPtLocation::File {
                path,
                expanded: None,
            } => {
                write!(f, "file {} [cannot expand]", path)
            }

            ConnPtLocation::WithinDir {
                path,
                file: expanded,
            } => {
                write!(f, "file {} in directory {}", expanded.display(), path)
            }
        }
    }
}

impl RpcConnBuilder {
    /// Create a new `RpcConnBuilder` to try connecting to an Arti instance.
    ///
    /// By default, we search:
    ///   - Any connect points listed in the environment variable `$ARTI_RPC_CONNECT_PATH_OVERRIDE`
    ///   - Any connect points passed to `RpcConnBuilder::prepend_*`
    ///     (Since these variables are _prepended_,
    ///     the ones that are prepended _last_ will be considered _first_.)
    ///   - Any connect points listed in the environment variable `$ARTI_RPC_CONNECT_PATH`
    ///   - Any connect files in `${ARTI_LOCAL_DATA}/rpc/connect.d`
    ///   - Any connect files in `/etc/arti-rpc/connect.d` (unix only)
    ///   - [`tor_rpc_connect::USER_DEFAULT_CONNECT_POINT`]
    ///   - [`tor_rpc_connect::SYSTEM_DEFAULT_CONNECT_POINT`] if present
    //
    // TODO RPC: Once we have our formats more settled, add a link to a piece of documentation
    // explaining what a connect point is and how to make one.
    pub fn new() -> Self {
        Self::default()
    }

    /// Prepend a single literal connect point to the search path in this RpcConnBuilder.
    ///
    /// This entry will be considered before any entries in
    /// the `$ARTI_RPC_CONNECT_PATH` environment variable
    /// but after any entry in
    /// the `$ARTI_RPC_CONNECT_PATH_OVERRIDE` environment variable.
    ///
    /// This entry must be a literal connect point, expressed as a TOML table.
    pub fn prepend_literal_entry(&mut self, s: String) {
        self.prepend_internal(SearchLocation::Literal(s));
    }

    /// Prepend a single path entry to the search path in this RpcConnBuilder.
    ///
    /// This entry will be considered before any entries in
    /// the `$ARTI_RPC_CONNECT_PATH` environment variable,
    /// but after any entry in
    /// the `$ARTI_RPC_CONNECT_PATH_OVERRIDE` environment variable.
    ///
    /// This entry must be a path to a file or directory.
    /// It may contain variables to expand;
    /// they will be expanded according to the rules of [`CfgPath`],
    /// using the variables of [`tor_config_path::arti_client_base_resolver`].
    pub fn prepend_path(&mut self, p: String) {
        self.prepend_internal(SearchLocation::Path {
            path: CfgPath::new(p),
            is_default_entry: false,
        });
    }

    /// Prepend a single literal path entry to the search path in this RpcConnBuilder.
    ///
    /// This entry will be considered before any entries in
    /// the `$ARTI_RPC_CONNECT_PATH` environment variable,
    /// but after any entry in
    /// the `$ARTI_RPC_CONNECT_PATH_OVERRIDE` environment variable.
    ///
    /// Variables in this entry will not be expanded.
    pub fn prepend_literal_path(&mut self, p: PathBuf) {
        self.prepend_internal(SearchLocation::Path {
            path: CfgPath::new_literal(p),
            is_default_entry: false,
        });
    }

    /// Prepend the application-provided [`SearchLocation`] to the path.
    fn prepend_internal(&mut self, location: SearchLocation) {
        self.prepend_path_reversed.push(SearchEntry {
            source: ConnPtOrigin::Application,
            location,
        });
    }

    /// Return the list of default path entries that we search _after_
    /// all user-provided entries.
    fn default_path_entries() -> Vec<SearchEntry> {
        use SearchLocation::*;
        let dflt = |location| SearchEntry {
            source: ConnPtOrigin::Default,
            location,
        };
        let mut result = vec![
            dflt(Path {
                path: CfgPath::new("${ARTI_LOCAL_DATA}/rpc/connect.d/".to_owned()),
                is_default_entry: true,
            }),
            #[cfg(unix)]
            dflt(Path {
                path: CfgPath::new_literal("/etc/arti-rpc/connect.d/"),
                is_default_entry: true,
            }),
            dflt(Literal(
                tor_rpc_connect::USER_DEFAULT_CONNECT_POINT.to_owned(),
            )),
        ];
        if let Some(p) = tor_rpc_connect::SYSTEM_DEFAULT_CONNECT_POINT {
            result.push(dflt(Literal(p.to_owned())));
        }
        result
    }

    /// Return a vector of every PathEntry that we should try to connect to.
    fn all_entries(&self) -> Result<Vec<SearchEntry>, ConnectError> {
        let mut entries = SearchEntry::from_env_var("ARTI_RPC_CONNECT_PATH_OVERRIDE")?;
        entries.extend(self.prepend_path_reversed.iter().rev().cloned());
        entries.extend(SearchEntry::from_env_var("ARTI_RPC_CONNECT_PATH")?);
        entries.extend(Self::default_path_entries());
        Ok(entries)
    }

    /// Try to connect to an Arti process as specified by this Builder.
    pub fn connect(&self) -> Result<RpcConn, ConnectFailure> {
        let resolver = tor_config_path::arti_client_base_resolver();
        // TODO RPC: Make this configurable.  (Currently, you can override it with
        // the environment variable FS_MISTRUST_DISABLE_PERMISSIONS_CHECKS.)
        let mistrust = Mistrust::default();
        let options = HashMap::new();
        let all_entries = self.all_entries().map_err(|e| ConnectFailure {
            declined: vec![],
            final_desc: None,
            final_error: e,
        })?;
        let mut declined = Vec::new();
        for (description, load_result) in all_entries
            .into_iter()
            .flat_map(|ent| ent.load(&resolver, &mistrust, &options))
        {
            match load_result.and_then(|e| try_connect(&e, &resolver, &mistrust)) {
                Ok(conn) => return Ok(conn),
                Err(e) => match e.client_action() {
                    ClientErrorAction::Abort => {
                        return Err(ConnectFailure {
                            declined,
                            final_desc: Some(description),
                            final_error: e,
                        });
                    }
                    ClientErrorAction::Decline => {
                        declined.push((description, e));
                    }
                },
            }
        }
        Err(ConnectFailure {
            declined,
            final_desc: None,
            final_error: ConnectError::AllAttemptsDeclined,
        })
    }
}

/// Helper: Try to resolve any variables in parsed,
/// and open and authenticate an RPC connection to it.
///
/// This is a separate function from `RpcConnBuilder::connect` to make error handling easier to read.
fn try_connect(
    parsed: &ParsedConnectPoint,
    resolver: &CfgPathResolver,
    mistrust: &Mistrust,
) -> Result<RpcConn, ConnectError> {
    let tor_rpc_connect::client::Connection {
        reader,
        writer,
        auth,
        ..
    } = parsed.resolve(resolver)?.connect(mistrust)?;
    let mut reader = llconn::Reader::new(io::BufReader::new(reader));
    let banner = reader
        .read_msg()
        .map_err(|e| ConnectError::CannotConnect(e.into()))?
        .ok_or(ConnectError::InvalidBanner)?;
    check_banner(&banner)?;

    let mut conn = RpcConn::new(reader, llconn::Writer::new(writer));

    // TODO RPC: remove this "scheme name" from the protocol?
    let session_id = match auth {
        RpcAuth::Inherent => conn.authenticate_inherent("auth:inherent")?,
        RpcAuth::Cookie {
            secret,
            server_address,
        } => conn.authenticate_cookie(secret.load()?.as_ref(), &server_address)?,
        _ => return Err(ConnectError::AuthenticationNotSupported),
    };
    conn.session = Some(session_id);

    Ok(conn)
}

/// Return Ok if `msg` is a banner indicating the correct protocol.
fn check_banner(msg: &UnparsedResponse) -> Result<(), ConnectError> {
    /// Structure to indicate that this is indeed an Arti RPC connection.
    #[derive(serde::Deserialize)]
    struct BannerMsg {
        /// Ignored value
        #[allow(dead_code)]
        arti_rpc: serde_json::Value,
    }
    let _: BannerMsg =
        serde_json::from_str(msg.as_str()).map_err(|_| ConnectError::InvalidBanner)?;
    Ok(())
}

impl SearchEntry {
    /// Return an iterator over ParsedConnPoints from this `SearchEntry`.
    fn load<'a>(
        &self,
        resolver: &CfgPathResolver,
        mistrust: &Mistrust,
        options: &'a HashMap<PathBuf, LoadOptions>,
    ) -> ConnPtIterator<'a> {
        // Create a ConnPtDescription given a connect point's location, so we can describe
        // an error origin.
        let descr = |location| ConnPtDescription {
            source: self.source,
            location,
        };

        match &self.location {
            SearchLocation::Literal(s) => ConnPtIterator::Singleton(
                descr(ConnPtLocation::Literal(s.clone())),
                // It's a literal entry, so we just try to parse it.
                ParsedConnectPoint::from_str(s).map_err(|e| ConnectError::from(LoadError::from(e))),
            ),
            SearchLocation::Path {
                path: cfgpath,
                is_default_entry,
            } => {
                // Create a ConnPtDescription given an optional expanded path.
                let descr_file = |expanded| {
                    descr(ConnPtLocation::File {
                        path: cfgpath.clone(),
                        expanded,
                    })
                };

                // It's a path, so we need to expand it...
                let path = match cfgpath.path(resolver) {
                    Ok(p) => p,
                    Err(e) => {
                        return ConnPtIterator::Singleton(
                            descr_file(None),
                            Err(ConnectError::CannotResolvePath(e)),
                        );
                    }
                };
                if !path.is_absolute() {
                    if *is_default_entry {
                        return ConnPtIterator::Done;
                    } else {
                        return ConnPtIterator::Singleton(
                            descr_file(Some(path)),
                            Err(ConnectError::RelativeConnectFile),
                        );
                    }
                }
                // ..then try to load it as a directory...
                match ParsedConnectPoint::load_dir(&path, mistrust, options) {
                    Ok(iter) => ConnPtIterator::Dir(self.source, cfgpath.clone(), iter),
                    Err(LoadError::NotADirectory) => {
                        // ... and if that fails, try to load it as a file.
                        let loaded =
                            ParsedConnectPoint::load_file(&path, mistrust).map_err(|e| e.into());
                        ConnPtIterator::Singleton(descr_file(Some(path)), loaded)
                    }
                    Err(other) => {
                        ConnPtIterator::Singleton(descr_file(Some(path)), Err(other.into()))
                    }
                }
            }
        }
    }

    /// Return a list of `SearchEntry` as specified in an environment variable with a given name.
    fn from_env_var(varname: &'static str) -> Result<Vec<Self>, ConnectError> {
        match std::env::var(varname) {
            Ok(s) if s.is_empty() => Ok(vec![]),
            Ok(s) => Self::from_env_string(varname, &s),
            Err(std::env::VarError::NotPresent) => Ok(vec![]),
            Err(_) => Err(ConnectError::BadEnvironment), // TODO RPC: Preserve more information?
        }
    }

    /// Return a list of `SearchEntry` as specified in the value `s` from an envvar called `varname`.
    fn from_env_string(varname: &'static str, s: &str) -> Result<Vec<Self>, ConnectError> {
        // TODO RPC: Possibly we should be using std::env::split_paths, if it behaves correctly
        // with our url-escaped entries.
        s.split(PATH_SEP_CHAR)
            .map(|s| {
                Ok(SearchEntry {
                    source: ConnPtOrigin::EnvVar(varname),
                    location: SearchLocation::from_env_string_elt(s)?,
                })
            })
            .collect()
    }
}

impl SearchLocation {
    /// Return a `SearchLocation` from a single entry within an environment variable.
    fn from_env_string_elt(s: &str) -> Result<SearchLocation, ConnectError> {
        match s.bytes().next() {
            Some(b'%') | Some(b'[') => Ok(Self::Literal(
                percent_encoding::percent_decode_str(s)
                    .decode_utf8()
                    .map_err(|_| ConnectError::BadEnvironment)?
                    .into_owned(),
            )),
            _ => Ok(Self::Path {
                path: CfgPath::new(s.to_owned()),
                is_default_entry: false,
            }),
        }
    }
}

/// Character used to separate path environment variables.
const PATH_SEP_CHAR: char = {
    cfg_if::cfg_if! {
         if #[cfg(windows)] { ';' } else { ':' }
    }
};

/// Iterator over connect points returned by PathEntry::load().
enum ConnPtIterator<'a> {
    /// Iterator over a directory
    Dir(
        /// Origin of the directory
        ConnPtOrigin,
        /// The directory as configured
        CfgPath,
        /// Iterator over the elements loaded from the directory
        tor_rpc_connect::load::ConnPointIterator<'a>,
    ),
    /// A single connect point or error
    Singleton(ConnPtDescription, Result<ParsedConnectPoint, ConnectError>),
    /// An exhausted iterator
    Done,
}

impl<'a> Iterator for ConnPtIterator<'a> {
    // TODO RPC yield the pathbuf too, for better errors.
    type Item = (ConnPtDescription, Result<ParsedConnectPoint, ConnectError>);

    fn next(&mut self) -> Option<Self::Item> {
        let mut t = ConnPtIterator::Done;
        std::mem::swap(self, &mut t);
        match t {
            ConnPtIterator::Dir(source, cfgpath, mut iter) => {
                let next = iter
                    .next()
                    .map(|(path, res)| (path, res.map_err(|e| e.into())));
                let Some((expanded, result)) = next else {
                    *self = ConnPtIterator::Done;
                    return None;
                };
                let description = ConnPtDescription {
                    source,
                    location: ConnPtLocation::WithinDir {
                        path: cfgpath.clone(),
                        file: expanded,
                    },
                };
                *self = ConnPtIterator::Dir(source, cfgpath, iter);
                Some((description, result))
            }
            ConnPtIterator::Singleton(desc, res) => Some((desc, res)),
            ConnPtIterator::Done => None,
        }
    }
}
