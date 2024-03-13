//! Code to inspect user db information on unix.

#[cfg(feature = "serde")]
mod serde_support;

use crate::Error;
use once_cell::sync::Lazy;
use std::{
    collections::HashMap,
    ffi::{OsStr, OsString},
    io,
    sync::Mutex,
};

use pwd_grp::{PwdGrp, PwdGrpProvider};

/// uids and gids, convenient type alias
type Id = u32;

/// Cache for the trusted uid/gid answers
#[derive(Default, Debug)]
struct TrustedUsersCache<U: PwdGrpProvider> {
    /// The passwd/group provider (possibly mocked)
    pwd_grp: U,
    /// Cached trusted uid determination
    trusted_uid: HashMap<TrustedUser, Option<Id>>,
    /// Cached trusted gid determination
    trusted_gid: HashMap<TrustedGroup, Option<Id>>,
}

/// Cached trusted id determinations
///
/// Caching here saves time - including passwd/group lookups, which can be slow enough
/// we don't want to do them often.
///
/// It isn't 100% correct since we don't track changes to the passwd/group databases.
/// That might not be OK everywhere, but it is OK in this application.
static CACHE: Lazy<Mutex<TrustedUsersCache<PwdGrp>>> =
    Lazy::new(|| Mutex::new(TrustedUsersCache::default()));

/// Convert an [`io::Error `] representing a user/group handling failure into an [`Error`]
fn handle_pwd_error(e: io::Error) -> Error {
    Error::PasswdGroupIoError(e.into())
}

/// Obtain the gid of a group named after the current user
fn get_self_named_gid_impl<U: PwdGrpProvider>(userdb: &U) -> io::Result<Option<u32>> {
    let Some(username) = get_own_username(userdb)? else {
        return Ok(None);
    };

    let Some(group) = userdb.getgrnam::<Vec<u8>>(username)? else {
        return Ok(None);
    };

    // TODO: Perhaps we should enforce a requirement that the group contains
    // _only_ the current users.  That's kinda tricky to do, though, without
    // walking the entire user db.

    Ok(if cur_groups()?.contains(&group.gid) {
        Some(group.gid)
    } else {
        None
    })
}

/// Find our username, if possible.
///
/// By default, we look for the USER environment variable, and see whether we an
/// find a user db entry for that username with a UID that matches our own.
///
/// Failing that, we look for a user entry for our current UID.
fn get_own_username<U: PwdGrpProvider>(userdb: &U) -> io::Result<Option<Vec<u8>>> {
    use std::os::unix::ffi::OsStringExt as _;

    let my_uid = userdb.getuid();

    if let Some(username) = std::env::var_os("USER") {
        let username = username.into_vec();
        if let Some(passwd) = userdb.getpwnam::<Vec<u8>>(&username)? {
            if passwd.uid == my_uid {
                return Ok(Some(username));
            }
        }
    }

    if let Some(passwd) = userdb.getpwuid(my_uid)? {
        // This check should always pass, but let's be extra careful.
        if passwd.uid == my_uid {
            return Ok(Some(passwd.name));
        }
    }

    Ok(None)
}

/// Return a vector of the group ID values for every group to which we belong.
fn cur_groups() -> io::Result<Vec<u32>> {
    PwdGrp.getgroups()
}

/// A user that we can be configured to trust.
///
/// # Serde support
///
/// If this crate is build with the `serde1` feature enabled, you can serialize
/// and deserialize this type from any of the following:
///
///  * `false` and the string `":none"` correspond to `TrustedUser::None`.
///  * The string `":current"` and the map `{ special = ":current" }` correspond
///    to `TrustedUser::Current`.
///  * A numeric value (e.g., `413`) and the map `{ id = 413 }` correspond to
///    `TrustedUser::Id(413)`.
///  * A string not starting with `:` (e.g., "jane") and the map `{ name = "jane" }`
///    correspond to `TrustedUser::Name("jane".into())`.
///
/// ## Limitations
///
/// Non-UTF8 usernames cannot currently be represented in all serde formats.
/// Notably, toml doesn't support them.
#[derive(Clone, Default, Debug, Eq, PartialEq, Hash)]
#[cfg_attr(
    feature = "serde",
    derive(serde::Serialize, serde::Deserialize),
    serde(try_from = "serde_support::Serde", into = "serde_support::Serde")
)]
#[non_exhaustive]
pub enum TrustedUser {
    /// We won't treat any user as trusted.
    None,
    /// Treat the current user as trusted.
    #[default]
    Current,
    /// Treat the user with a particular UID as trusted.
    Id(u32),
    /// Treat a user with a particular name as trusted.
    ///
    /// If there is no such user, we'll report an error.
    //
    // TODO change type of TrustedUser::Name.0 to Vec<u8> ? (also TrustedGroup)
    // This is a Unix-only module.  Arguably we shouldn't be using the OsString
    // type which is super-inconvenient and only really exists because on Windows
    // the environment, arguments, and filenames, are WTF-16.
    Name(OsString),
}

impl From<u32> for TrustedUser {
    fn from(val: u32) -> Self {
        TrustedUser::Id(val)
    }
}
impl From<OsString> for TrustedUser {
    fn from(val: OsString) -> Self {
        TrustedUser::Name(val)
    }
}
impl From<&OsStr> for TrustedUser {
    fn from(val: &OsStr) -> Self {
        val.to_owned().into()
    }
}
impl From<String> for TrustedUser {
    fn from(val: String) -> Self {
        OsString::from(val).into()
    }
}
impl From<&str> for TrustedUser {
    fn from(val: &str) -> Self {
        val.to_owned().into()
    }
}

impl TrustedUser {
    /// Try to convert this `User` into an optional UID.
    pub(crate) fn get_uid(&self) -> Result<Option<u32>, Error> {
        let mut cache = CACHE.lock().expect("poisoned lock");
        if let Some(got) = cache.trusted_uid.get(self) {
            return Ok(*got);
        }
        let calculated = self.get_uid_impl(&cache.pwd_grp)?;
        cache.trusted_uid.insert(self.clone(), calculated);
        Ok(calculated)
    }
    /// As `get_uid`, but take a userdb.
    fn get_uid_impl<U: PwdGrpProvider>(&self, userdb: &U) -> Result<Option<u32>, Error> {
        use std::os::unix::ffi::OsStrExt as _;

        match self {
            TrustedUser::None => Ok(None),
            TrustedUser::Current => Ok(Some(userdb.getuid())),
            TrustedUser::Id(id) => Ok(Some(*id)),
            TrustedUser::Name(name) => userdb
                .getpwnam(name.as_bytes())
                .map_err(handle_pwd_error)?
                .map(|u: pwd_grp::Passwd<Vec<u8>>| Some(u.uid))
                .ok_or_else(|| Error::NoSuchUser(name.to_string_lossy().into_owned())),
        }
    }
}

/// A group that we can be configured to trust.
///
/// # Serde support
///
/// See the `serde support` section in [`TrustedUser`].  Additionally,
/// you can represent `TrustedGroup::SelfNamed` with the string `":username"`
/// or the map `{ special = ":username" }`.
#[derive(Clone, Debug, Default, Eq, PartialEq, Hash)]
#[cfg_attr(
    feature = "serde",
    derive(serde::Serialize, serde::Deserialize),
    serde(try_from = "serde_support::Serde", into = "serde_support::Serde")
)]
#[non_exhaustive]
pub enum TrustedGroup {
    /// We won't treat any group as trusted
    None,
    /// We'll treat any group with same name as the current user as trusted.
    ///
    /// If there is no such group, we trust no group.
    ///
    /// (This is the default.)
    #[default]
    SelfNamed,
    /// We'll treat a specific group ID as trusted.
    Id(u32),
    /// We'll treat a group with a specific name as trusted.
    ///
    /// If there is no such group, we'll report an error.
    Name(OsString),
}

impl From<u32> for TrustedGroup {
    fn from(val: u32) -> Self {
        TrustedGroup::Id(val)
    }
}
impl From<OsString> for TrustedGroup {
    fn from(val: OsString) -> TrustedGroup {
        TrustedGroup::Name(val)
    }
}
impl From<&OsStr> for TrustedGroup {
    fn from(val: &OsStr) -> TrustedGroup {
        val.to_owned().into()
    }
}
impl From<String> for TrustedGroup {
    fn from(val: String) -> TrustedGroup {
        OsString::from(val).into()
    }
}
impl From<&str> for TrustedGroup {
    fn from(val: &str) -> TrustedGroup {
        val.to_owned().into()
    }
}

impl TrustedGroup {
    /// Try to convert this `Group` into an optional GID.
    pub(crate) fn get_gid(&self) -> Result<Option<u32>, Error> {
        let mut cache = CACHE.lock().expect("poisoned lock");
        if let Some(got) = cache.trusted_gid.get(self) {
            return Ok(*got);
        }
        let calculated = self.get_gid_impl(&cache.pwd_grp)?;
        cache.trusted_gid.insert(self.clone(), calculated);
        Ok(calculated)
    }
    /// Like `get_gid`, but take a user db as an argument.
    fn get_gid_impl<U: PwdGrpProvider>(&self, userdb: &U) -> Result<Option<u32>, Error> {
        use std::os::unix::ffi::OsStrExt as _;

        match self {
            TrustedGroup::None => Ok(None),
            TrustedGroup::SelfNamed => get_self_named_gid_impl(userdb).map_err(handle_pwd_error),
            TrustedGroup::Id(id) => Ok(Some(*id)),
            TrustedGroup::Name(name) => userdb
                .getgrnam(name.as_bytes())
                .map_err(handle_pwd_error)?
                .map(|g: pwd_grp::Group<Vec<u8>>| Some(g.gid))
                .ok_or_else(|| Error::NoSuchGroup(name.to_string_lossy().into_owned())),
        }
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
    use pwd_grp::mock::MockPwdGrpProvider;
    type Id = u32;

    fn mock_users() -> MockPwdGrpProvider {
        let mock = MockPwdGrpProvider::new();
        mock.set_uids(413.into());
        mock
    }
    fn add_user(mock: &MockPwdGrpProvider, uid: Id, name: &str, gid: Id) {
        mock.add_to_passwds([pwd_grp::Passwd::<String> {
            name: name.into(),
            uid,
            gid,
            ..pwd_grp::Passwd::blank()
        }]);
    }
    fn add_group(mock: &MockPwdGrpProvider, gid: Id, name: &str) {
        mock.add_to_groups([pwd_grp::Group::<String> {
            name: name.into(),
            gid,
            ..pwd_grp::Group::blank()
        }]);
    }

    #[test]
    fn groups() {
        let groups = cur_groups().unwrap();
        let cur_gid = pwd_grp::getgid();
        if groups.is_empty() {
            // Some container/VM setups forget to put the (root) user into any
            // groups at all.
            return;
        }
        assert!(groups.contains(&cur_gid));
    }

    #[test]
    fn username_real() {
        // Here we'll do tests with our real username.  THere's not much we can
        // actually test there, but we'll try anyway.
        let cache = CACHE.lock().expect("poisoned lock");
        let uname = get_own_username(&cache.pwd_grp)
            .unwrap()
            .expect("Running on a misconfigured host");
        let user = PwdGrp.getpwnam::<Vec<u8>>(&uname).unwrap().unwrap();
        assert_eq!(user.name, uname);
        assert_eq!(user.uid, PwdGrp.getuid());
    }

    #[test]
    fn username_from_env() {
        let Ok(username_s) = std::env::var("USER")
        // If USER isn't set, can't test this without setting the environment,
        // and we don't do that in tests.
        // Likewise if USER is not UTF-8, we can't make mock usernames.
        else {
            return;
        };
        let username = username_s.as_bytes().to_vec();

        let other_name = format!("{}2", &username_s);

        // Case 1: Current user in environment exists, though there are some distractions.
        let db = mock_users();
        add_user(&db, 413, &username_s, 413);
        add_user(&db, 999, &other_name, 999);
        // I'd like to add another user with the same UID and a different name,
        // but MockUsers doesn't support that.
        let found = get_own_username(&db).unwrap();
        assert_eq!(found.as_ref(), Some(&username));

        // Case 2: Current user in environment exists, but has the wrong uid.
        let db = mock_users();
        add_user(&db, 999, &username_s, 999);
        add_user(&db, 413, &other_name, 413);
        let found = get_own_username(&db).unwrap();
        assert_eq!(found, Some(other_name.clone().into_bytes()));

        // Case 3: Current user in environment does not exist; no user can be found.
        let db = mock_users();
        add_user(&db, 999413, &other_name, 999);
        let found = get_own_username(&db).unwrap();
        assert!(found.is_none());
    }

    #[test]
    fn username_ignoring_env() {
        // Case 1: uid is found.
        let db = mock_users();
        add_user(&db, 413, "aranea", 413413);
        add_user(&db, 415, "notyouru!sername", 413413);
        let found = get_own_username(&db).unwrap();
        assert_eq!(found, Some(b"aranea".to_vec()));

        // Case 2: uid not found.
        let db = mock_users();
        add_user(&db, 999413, "notyourn!ame", 999);
        let found = get_own_username(&db).unwrap();
        assert!(found.is_none());
    }

    #[test]
    fn selfnamed() {
        // check the real groups we're in, since this isn't mockable.
        let cur_groups = cur_groups().unwrap();
        if cur_groups.is_empty() {
            // Can't actually proceed with the test unless we're in a group.
            return;
        }
        let not_our_gid = (1..65536)
            .find(|n| !cur_groups.contains(n))
            .expect("We are somehow in all groups 1..65535!");

        // Case 1: we find our username but no group with the same name.
        let db = mock_users();
        add_user(&db, 413, "aranea", 413413);
        add_group(&db, 413413, "serket");
        let found = get_self_named_gid_impl(&db).unwrap();
        assert!(found.is_none());

        // Case 2: we find our username and a group with the same name, but we
        // are not a member of that group.
        let db = mock_users();
        add_user(&db, 413, "aranea", 413413);
        add_group(&db, not_our_gid, "aranea");
        let found = get_self_named_gid_impl(&db).unwrap();
        assert!(found.is_none());

        // Case 3: we find our username and a group with the same name, AND we
        // are indeed a member of that group.
        let db = mock_users();
        add_user(&db, 413, "aranea", 413413);
        add_group(&db, cur_groups[0], "aranea");
        let found = get_self_named_gid_impl(&db).unwrap();
        assert_eq!(found, Some(cur_groups[0]));
    }

    #[test]
    fn lookup_id() {
        let db = mock_users();
        add_user(&db, 413, "aranea", 413413);
        add_group(&db, 33, "nepeta");

        assert_eq!(TrustedUser::None.get_uid_impl(&db).unwrap(), None);
        assert_eq!(TrustedUser::Current.get_uid_impl(&db).unwrap(), Some(413));
        assert_eq!(TrustedUser::Id(413).get_uid_impl(&db).unwrap(), Some(413));
        assert_eq!(
            TrustedUser::Name("aranea".into())
                .get_uid_impl(&db)
                .unwrap(),
            Some(413)
        );
        assert!(TrustedUser::Name("ac".into()).get_uid_impl(&db).is_err());

        assert_eq!(TrustedGroup::None.get_gid_impl(&db).unwrap(), None);
        assert_eq!(TrustedGroup::Id(33).get_gid_impl(&db).unwrap(), Some(33));
        assert_eq!(
            TrustedGroup::Name("nepeta".into())
                .get_gid_impl(&db)
                .unwrap(),
            Some(33)
        );
        assert!(TrustedGroup::Name("ac".into()).get_gid_impl(&db).is_err());
    }
}
