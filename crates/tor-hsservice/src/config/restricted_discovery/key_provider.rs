//! Service discovery client key providers.

use crate::config::restricted_discovery::HsClientNickname;
use crate::internal_prelude::*;

use std::collections::BTreeMap;

use derive_more::{AsRef, Into};
use fs_mistrust::{CheckedDir, Mistrust, MistrustBuilder};

use amplify::Getters;
use serde_with::DisplayFromStr;

use tor_config::mistrust::BuilderExt as _;
use tor_config::{define_list_builder_helper, CfgPath, CfgPathError};
use tor_error::warn_report;
use tor_hscrypto::pk::HsClientDescEncKeyParseError;
use tor_persist::slug::BadSlug;

/// A static mapping from [`HsClientNickname`] to client authorization keys.
#[serde_with::serde_as]
#[derive(Default, Debug, Clone, Eq, PartialEq)] //
#[derive(Into, From, AsRef, Serialize, Deserialize)]
pub struct StaticKeyProvider(
    #[serde_as(as = "BTreeMap<DisplayFromStr, DisplayFromStr>")]
    BTreeMap<HsClientNickname, HsClientDescEncKey>,
);

define_list_builder_helper! {
    #[derive(Eq, PartialEq)]
    pub struct StaticKeyProviderBuilder {
        keys : [(HsClientNickname, HsClientDescEncKey)],
    }
    built: StaticKeyProvider = build_static(keys)?;
    default = vec![];
    item_build: |value| Ok(value.clone());
    #[serde(try_from = "StaticKeyProvider", into = "StaticKeyProvider")]
}

impl TryFrom<StaticKeyProvider> for StaticKeyProviderBuilder {
    type Error = ConfigBuildError;

    fn try_from(value: StaticKeyProvider) -> Result<Self, Self::Error> {
        let mut list_builder = StaticKeyProviderBuilder::default();
        for (nickname, key) in value.0 {
            list_builder.access().push((nickname, key));
        }
        Ok(list_builder)
    }
}

impl From<StaticKeyProviderBuilder> for StaticKeyProvider {
    /// Convert our Builder representation of a set of static keys into the
    /// format that serde will serialize.
    ///
    /// Note: This is a potentially lossy conversion, since the serialized format
    /// can't represent a collection of keys with duplicate nicknames.
    fn from(value: StaticKeyProviderBuilder) -> Self {
        let mut map = BTreeMap::new();
        for (nickname, key) in value.keys.into_iter().flatten() {
            map.insert(nickname, key);
        }
        Self(map)
    }
}

/// Helper for building a [`StaticKeyProvider`] out of a list of client keys.
///
/// Returns an error if the list contains duplicate keys
fn build_static(
    keys: Vec<(HsClientNickname, HsClientDescEncKey)>,
) -> Result<StaticKeyProvider, ConfigBuildError> {
    let mut key_map = BTreeMap::new();

    for (nickname, key) in keys.into_iter() {
        if key_map.insert(nickname.clone(), key).is_some() {
            return Err(ConfigBuildError::Invalid {
                field: "keys".into(),
                problem: format!("Multiple client keys for nickname {nickname}"),
            });
        };
    }

    Ok(StaticKeyProvider(key_map))
}

/// A directory containing the client keys, each in the
/// `descriptor:x25519:<base32-encoded-x25519-public-key>` format.
///
/// Each file in this directory must have a file name of the form `<nickname>.auth`,
/// where `<nickname>` is a valid [`HsClientNickname`].
#[derive(Debug, Clone, Builder, Eq, PartialEq, Getters)]
#[builder(derive(Serialize, Deserialize, Debug))]
#[builder(build_fn(error = "ConfigBuildError"))]
pub struct DirectoryKeyProvider {
    /// The path.
    path: CfgPath,

    /// Configuration about which permissions we want to enforce on our files.
    #[builder(sub_builder(fn_name = "build_for_arti"))]
    #[builder_field_attr(serde(default))]
    permissions: Mistrust,
}

/// The serialized format of a [`DirectoryKeyProviderListBuilder`]:
pub type DirectoryKeyProviderList = Vec<DirectoryKeyProvider>;

define_list_builder_helper! {
    pub struct DirectoryKeyProviderListBuilder {
        key_dirs: [DirectoryKeyProviderBuilder],
    }
    built: DirectoryKeyProviderList = key_dirs;
    default = vec![];
}

impl DirectoryKeyProvider {
    /// Read the client service discovery keys from the specified directory.
    pub(super) fn read_keys(&self) -> Result<Vec<(HsClientNickname, HsClientDescEncKey)>, DirectoryKeyProviderError> {
        let dir_path =
            self.path
                .path()
                .map_err(|err| DirectoryKeyProviderError::PathExpansionFailed {
                    path: self.path.clone(),
                    err,
                })?;

        let checked_dir = self
            .permissions
            .verifier()
            .secure_dir(&dir_path)
            .map_err(|err| DirectoryKeyProviderError::FsMistrust {
                path: dir_path.clone(),
                err,
            })?;

        let make_err = |e| DirectoryKeyProviderError::IoError(Arc::new(e));

        // TODO: should this be a method on CheckedDir?
        let key_entries = fs::read_dir(checked_dir.as_path()).map_err(make_err)?;
        let mut keys = vec![];

        for entry in key_entries {
            let entry = entry.map_err(make_err)?;
            let path = entry.path();

            match read_key_file(&checked_dir, &path) {
                Ok((client_nickname, key)) => keys.push((client_nickname, key)),
                Err(e) => {
                    warn_report!(
                        e,
                        "Failed to read client discovery key at {}",
                        path.display_lossy()
                    );
                    continue;
                }
            };
        }

        Ok(keys)
    }
}

/// Read the client key at  `path`.
fn read_key_file(
    checked_dir: &CheckedDir,
    path: &Path,
) -> Result<(HsClientNickname, HsClientDescEncKey), DirectoryKeyProviderError> {
    /// The extension the client key files are expected to have.
    const KEY_EXTENSION: &str = "auth";

    if path.is_dir() {
        return Err(DirectoryKeyProviderError::InvalidKeyDirectoryEntry {
            path: path.into(),
            problem: "entry is a directory".into(),
        });
    }

    let extension = path.extension().and_then(|e| e.to_str());
    if extension != Some(KEY_EXTENSION) {
        return Err(DirectoryKeyProviderError::InvalidKeyDirectoryEntry {
            path: path.into(),
            problem: "invalid extension (file must end in .auth)".into(),
        });
    }

    // We unwrap_or_default() instead of returning an error if the file stem is None,
    // because empty slugs handled by HsClientNickname::from_str (they are rejected).
    let client_nickname = path
        .file_stem()
        .and_then(|e| e.to_str())
        .unwrap_or_default();
    let client_nickname = HsClientNickname::from_str(client_nickname)?;

    // CheckedDir::read_to_string needs a relative path
    let rel_path =
        path.file_name()
            .ok_or_else(|| DirectoryKeyProviderError::InvalidKeyDirectoryEntry {
                path: path.into(),
                problem: "invalid filename".into(),
            })?;
    let key = checked_dir.read_to_string(rel_path).map_err(|err| {
        DirectoryKeyProviderError::FsMistrust {
            path: checked_dir.as_path().join(rel_path),
            err,
        }
    })?;

    let parsed_key = HsClientDescEncKey::from_str(key.trim()).map_err(|err| {
        DirectoryKeyProviderError::KeyParse {
            path: rel_path.into(),
            err,
        }
    })?;

    Ok((client_nickname, parsed_key))
}

/// Error type representing an invalid [`DirectoryKeyProvider`].
#[derive(Debug, Clone, thiserror::Error)]
pub(super) enum DirectoryKeyProviderError {
    /// Encountered an inaccessible path or invalid permissions.
    #[error("Inaccessible path or bad permissions on {path}")]
    FsMistrust {
        /// The path of the key we were trying to read.
        path: PathBuf,
        /// The underlying error.
        #[source]
        err: fs_mistrust::Error,
    },

    /// Encountered an error while reading the keys from disk.
    #[error("IO error while reading discovery keys")]
    IoError(#[source] Arc<io::Error>),

    /// We couldn't expand a path.
    #[error("Failed to expand path {path}")]
    PathExpansionFailed {
        /// The offending path.
        path: CfgPath,
        /// The error encountered.
        #[source]
        err: CfgPathError,
    },

    /// Found an invalid key entry.
    #[error("{path} is not a valid key entry: {problem}")]
    InvalidKeyDirectoryEntry {
        /// The path of the key we were trying to read.
        path: PathBuf,
        /// The problem we encountered.
        problem: String,
    },

    /// Failed to parse a client nickname.
    #[error("Invalid client nickname")]
    ClientNicknameParse(#[from] BadSlug),

    /// Failed to parse a key.
    #[error("Failed to parse key at {path}")]
    KeyParse {
        /// The path of the key we were trying to parse.
        path: PathBuf,
        /// The underlying error.
        #[source]
        err: HsClientDescEncKeyParseError,
    },
}
