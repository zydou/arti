//! Functionality to connect to an RPC server.

use std::{collections::HashMap, io, path::PathBuf, str::FromStr as _};

use fs_mistrust::Mistrust;
use tor_config_path::{CfgPath, CfgPathResolver};
use tor_rpc_connect::{
    auth::RpcAuth,
    load::{LoadError, LoadOptions},
    ClientErrorAction, HasClientErrorAction, ParsedConnectPoint,
};

use crate::{conn::ConnectError, llconn, RpcConn};

/// An error occurred while trying to construct or manipulate an [`RpcConnBuilder`].
#[derive(Clone, Debug, thiserror::Error)]
#[non_exhaustive]
pub enum BuilderError {
    /// We couldn't decode a provided connect string.
    #[error("Invalid connect string.")]
    InvalidConnectString,
}

/// Information about how to construct a connection to an Arti instance.
#[derive(Default, Clone, Debug)]
pub struct RpcConnBuilder {
    /// Path entries provided programmatically.
    ///
    /// These are considered after entries in ARTI_RPC_CONNECT_PATH_OVERRIDE,
    /// but before any other entries.
    ///
    /// These entries are stored in reverse order.
    prepend_path_reversed: Vec<PathEntry>,
}

/// A single searchable entry in the connect path.
#[derive(Clone, Debug)]
enum PathEntry {
    /// A literal connect point entry to parse.
    Literal(String),
    /// A path to a connect file, or a directory full of connect files.
    Path(CfgPath),
}

impl RpcConnBuilder {
    /// Create a new `RpcConnBuilder` to try connecting to an Arti instance.
    ///
    /// By default, we search:
    ///   - Any connect points listed in the environment variable `$ARTI_RPC_CONNECT_PATH_OVERRIDE`
    ///   - Any connect points passed to `RpcConnBuilder::prepend_entry`
    ///   - Any connect points listed in the environment variable `$ARTI_RPC_CONNECT_PATH`
    ///   - Any connect files in `${ARTI_LOCAL_DATA/rpc/connect.d`
    ///   - Any connect files in `/etc/arti-rpc/connect/d` (unix only)
    ///   - [`tor_rpc_connect::USER_DEFAULT_CONNECT_POINT`]
    ///   - [`tor_rpc_connect::SYSTEM_DEFAULT_CONNECT_POINT`] if present
    pub fn new() -> Self {
        Self::default()
    }

    /// Prepend a single literal connect point to the search path in this RpcConnBuilder.
    ///
    /// This entry will be considered before any entries in `${ARTI_RPC_CONNECT_PATH}`,
    /// but after any entry in `$ARTI_RPC_CONNECT_PATH_OVERRIDE`.
    ///
    /// This entry must be a literal connect point, expressed as a TOML table.
    pub fn prepend_literal_entry(&mut self, s: String) {
        self.prepend_path_reversed.push(PathEntry::Literal(s));
    }

    /// Prepend a single path entry to the search path in this RpcConnBuilder.
    ///
    /// This entry will be considered before any entries in `${ARTI_RPC_CONNECT_PATH}`,
    /// but after any entry in `$ARTI_RPC_CONNECT_PATH_OVERRIDE`.
    ///
    /// This entry must be a path to a file or directory.
    /// It may contain variables to expand;
    /// they will be expanded according to the rules of [`CfgPath`],
    /// using the variables of [`tor_config_path::arti_client_base_resolver`].
    pub fn prepend_path(&mut self, p: String) {
        self.prepend_path_reversed
            .push(PathEntry::Path(CfgPath::new(p)));
    }

    /// Prepend a single literal path entry to the search path in this RpcConnBuilder.
    ///
    /// This entry will be considered before any entries in `${ARTI_RPC_CONNECT_PATH}`,
    /// but after any entry in `$ARTI_RPC_CONNECT_PATH_OVERRIDE`.
    ///
    /// Variables in this entry will not be expanded.
    pub fn prepend_literal_path(&mut self, p: PathBuf) {
        self.prepend_path_reversed
            .push(PathEntry::Path(CfgPath::new_literal(p)));
    }

    /// Return the list of default path entries that we search _after_
    /// all user-provided entries.
    fn default_path_entries() -> Vec<PathEntry> {
        use PathEntry::*;
        let mut result = vec![
            Path(CfgPath::new("${ARTI_LOCAL_DATA}/rpc/connect.d/".to_owned())),
            #[cfg(unix)]
            Path(CfgPath::new_literal("/etc/arti-rpc/connect.d/")),
            Literal(tor_rpc_connect::USER_DEFAULT_CONNECT_POINT.to_owned()),
        ];
        if let Some(p) = tor_rpc_connect::SYSTEM_DEFAULT_CONNECT_POINT {
            result.push(Literal(p.to_owned()));
        }
        result
    }

    /// Return a vector of every PathEntry that we should try to connect to.
    fn all_entries(&self) -> Result<Vec<PathEntry>, ConnectError> {
        let mut entries = PathEntry::from_env_var("ARTI_RPC_CONNECT_PATH_OVERRIDE")?;
        entries.extend(self.prepend_path_reversed.iter().rev().cloned());
        entries.extend(PathEntry::from_env_var("ARTI_RPC_CONNECT_PATH")?);
        entries.extend(Self::default_path_entries());
        Ok(entries)
    }

    /// Try to connect to an Arti process as specified by this Builder.
    pub fn connect(&self) -> Result<RpcConn, ConnectError> {
        let resolver = tor_config_path::arti_client_base_resolver();
        // TODO RPC: Make this configurable.  (Currently, you can override it with
        // the environment variable FS_MISTRUST_DISABLE_PERMISSIONS_CHECKS.)
        let mistrust = Mistrust::default();
        let options = HashMap::new();
        for entry in self
            .all_entries()?
            .into_iter()
            .flat_map(|ent| ent.load(&resolver, &mistrust, &options))
        {
            match entry.and_then(|e| try_connect(&e, &resolver, &mistrust)) {
                Ok(conn) => return Ok(conn),
                Err(e) => match e.client_action() {
                    ClientErrorAction::Abort => return Err(e),
                    ClientErrorAction::Decline => {
                        // TODO RPC Log the error.
                    }
                },
            }
        }
        Err(ConnectError::AllAttemptsDeclined)
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
    match auth {
        RpcAuth::None => {}
        // TODO RPC: Implement cookie auth.
        _ => return Err(ConnectError::AuthenticationNotSupported),
    }
    let mut conn = RpcConn::new(
        llconn::Reader::new(io::BufReader::new(reader)),
        llconn::Writer::new(writer),
    );

    // TODO RPC: remove this "scheme name" from the protocol?
    // This will get refactored when we do cookie auth.
    let session_id = conn.authenticate_inherent("inherent:unix_path")?;
    conn.session = Some(session_id);

    Ok(conn)
}

impl PathEntry {
    /// Return an iterator over ParsedConnPoints from this PathEntry.
    fn load<'a>(
        &self,
        resolver: &CfgPathResolver,
        mistrust: &Mistrust,
        options: &'a HashMap<PathBuf, LoadOptions>,
    ) -> ConnPtIterator<'a> {
        match self {
            PathEntry::Literal(s) => ConnPtIterator::Singleton(
                // It's a literal entry, so we just try to parse it.
                ParsedConnectPoint::from_str(s).map_err(|e| ConnectError::from(LoadError::from(e))),
            ),
            PathEntry::Path(cfg_path) => {
                // It's a path, so we need to expand it...
                let path = match cfg_path.path(resolver) {
                    Ok(p) => p,
                    Err(e) => {
                        return ConnPtIterator::Singleton(Err(ConnectError::CannotResolvePath(e)))
                    }
                };
                // ..then try to load it as a directory...
                match ParsedConnectPoint::load_dir(&path, mistrust, options) {
                    Ok(iter) => ConnPtIterator::Dir(iter),
                    Err(LoadError::NotADirectory) => {
                        // ... and if that fails, try to load it as a file.
                        ConnPtIterator::Singleton(
                            ParsedConnectPoint::load_file(&path, mistrust).map_err(|e| e.into()),
                        )
                    }
                    Err(other) => ConnPtIterator::Singleton(Err(other.into())),
                }
            }
        }
    }

    /// Return a list of PathEntry as specified in an environment variable with a given name.
    fn from_env_var(s: &str) -> Result<Vec<Self>, ConnectError> {
        match std::env::var(s) {
            Ok(s) if s.is_empty() => Ok(vec![]),
            Ok(s) => Self::from_env_string(&s),
            Err(std::env::VarError::NotPresent) => Ok(vec![]),
            Err(_) => Err(ConnectError::BadEnvironment), // TODO RPC: Preserve more information?
        }
    }

    /// Return a list of PathEntry as specified in an environment variable with a given name.
    fn from_env_string(s: &str) -> Result<Vec<Self>, ConnectError> {
        s.split(':').map(Self::from_env_string_elt).collect()
    }

    /// Return a PathEntry from a single entry within an environment variable.
    fn from_env_string_elt(s: &str) -> Result<Self, ConnectError> {
        match s.bytes().next() {
            Some(b'%') | Some(b'[') => Ok(Self::Literal(
                percent_encoding::percent_decode_str(s)
                    .decode_utf8()
                    .map_err(|_| ConnectError::BadEnvironment)?
                    .into_owned(),
            )),
            _ => Ok(Self::Path(CfgPath::new(s.to_owned()))),
        }
    }
}

/// Iterator over connect points returned by PathEntry::load().
enum ConnPtIterator<'a> {
    /// Iterator over a directory
    Dir(tor_rpc_connect::load::ConnPointIterator<'a>),
    /// A single connect point or error
    Singleton(Result<ParsedConnectPoint, ConnectError>),
    /// An exhausted iterator
    Done,
}

impl<'a> Iterator for ConnPtIterator<'a> {
    // TODO RPC yield the pathbuf too, for better errors.
    type Item = Result<ParsedConnectPoint, ConnectError>;

    fn next(&mut self) -> Option<Self::Item> {
        let mut t = ConnPtIterator::Done;
        std::mem::swap(self, &mut t);
        match t {
            ConnPtIterator::Dir(mut iter) => {
                let next = iter.next().map(|(_path, res)| res.map_err(|e| e.into()));
                *self = ConnPtIterator::Dir(iter);
                next
            }
            ConnPtIterator::Singleton(res) => Some(res),
            ConnPtIterator::Done => None,
        }
    }
}
