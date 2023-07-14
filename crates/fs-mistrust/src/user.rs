//! Code to inspect user db information on unix.

#[cfg(feature = "serde")]
mod serde_support;

use crate::Error;
use once_cell::sync::Lazy;
use std::{
    ffi::{OsStr, OsString},
    io,
    sync::Mutex,
};

/// Cached values of user db entries we've looked up.
///
/// Caching here saves time, AND makes our code testable.
///
/// Though this type has interior mutability, it isn't Sync, so we need to add a mutex.
static CACHE: Lazy<Mutex<users::UsersCache>> = Lazy::new(|| Mutex::new(users::UsersCache::new()));

/// Convert an [`io::Error `] representing a user/group handling failure into an [`Error`]
fn handle_pwd_error(e: io::Error) -> Error {
    Error::PasswdGroupIoError(e.into())
}

/// Like get_self_named_gid(), but use a provided user database.
fn get_self_named_gid_impl<U: users::Groups + users::Users>(userdb: &U) -> io::Result<Option<u32>> {
    let Some(username) = get_own_username(userdb)? else { return Ok(None) };

    let Some(group) = userdb.get_group_by_name(username.as_os_str())
    else { return Ok(None) };

    // TODO: Perhaps we should enforce a requirement that the group contains
    // _only_ the current users.  That's kinda tricky to do, though, without
    // walking the entire user db.

    Ok(if cur_groups()?.contains(&group.gid()) {
        Some(group.gid())
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
#[allow(clippy::unnecessary_wraps)] // XXXX
fn get_own_username<U: users::Users>(userdb: &U) -> io::Result<Option<OsString>> {
    let my_uid = userdb.get_current_uid();

    if let Some(username) = std::env::var_os("USER") {
        if let Some(passwd) = userdb.get_user_by_name(username.as_os_str()) {
            if passwd.uid() == my_uid {
                return Ok(Some(username));
            }
        }
    }

    if let Some(passwd) = userdb.get_user_by_uid(my_uid) {
        // This check should always pass, but let's be extra careful.
        if passwd.uid() == my_uid {
            return Ok(Some(passwd.name().to_owned()));
        }
    }

    Ok(None)
}

/// Return a vector of the group ID values for every group to which we belong.
///
/// (We don't use `users::group_access_list()` here, since that function calls
/// `getgrnam_r` on every group we belong to, when in fact we don't care what
/// the groups are named.)
#[allow(clippy::unnecessary_wraps)] // XXXX
fn cur_groups() -> io::Result<Vec<u32>> {
    let n_groups = unsafe { libc::getgroups(0, std::ptr::null_mut()) };
    if n_groups <= 0 {
        return Ok(Vec::new());
    }
    let mut buf: Vec<users::gid_t> = vec![0; n_groups as usize];
    let n_groups2 = unsafe { libc::getgroups(buf.len() as i32, buf.as_mut_ptr()) };
    if n_groups2 <= 0 {
        return Ok(Vec::new());
    }
    if n_groups2 < n_groups {
        buf.resize(n_groups2 as usize, 0);
    }
    // It's not guaranteed that our current GID is necessarily one of our
    // current groups.  So, we add it.
    let cur_gid = users::get_current_gid();
    if !buf.contains(&cur_gid) {
        buf.push(cur_gid);
    }
    Ok(buf)
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
#[derive(Clone, Debug, educe::Educe, Eq, PartialEq)]
#[educe(Default)]
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
    #[educe(Default)]
    Current,
    /// Treat the user with a particular UID as trusted.
    Id(u32),
    /// Treat a user with a particular name as trusted.
    ///
    /// If there is no such user, we'll report an error.
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
        let userdb = CACHE.lock().expect("poisoned lock");
        self.get_uid_impl(&*userdb)
    }
    /// As `get_uid`, but take a userdb.
    fn get_uid_impl<U: users::Users>(&self, userdb: &U) -> Result<Option<u32>, Error> {
        match self {
            TrustedUser::None => Ok(None),
            TrustedUser::Current => Ok(Some(userdb.get_current_uid())),
            TrustedUser::Id(id) => Ok(Some(*id)),
            TrustedUser::Name(name) => userdb
                .get_user_by_name(&name)
                .map(|u| Some(u.uid()))
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
#[derive(Clone, Debug, educe::Educe, Eq, PartialEq)]
#[educe(Default)]
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
    #[educe(Default)]
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
        let userdb = CACHE.lock().expect("poisoned lock");
        self.get_gid_impl(&*userdb)
    }
    /// Like `get_gid`, but take a user db as an argument.
    fn get_gid_impl<U: users::Users + users::Groups>(
        &self,
        userdb: &U,
    ) -> Result<Option<u32>, Error> {
        match self {
            TrustedGroup::None => Ok(None),
            TrustedGroup::SelfNamed => get_self_named_gid_impl(userdb).map_err(handle_pwd_error),
            TrustedGroup::Id(id) => Ok(Some(*id)),
            TrustedGroup::Name(name) => userdb
                .get_group_by_name(&name)
                .map(|u| Some(u.gid()))
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
    #![allow(clippy::print_stderr)]
    #![allow(clippy::print_stdout)]
    #![allow(clippy::single_char_pattern)]
    #![allow(clippy::unwrap_used)]
    #![allow(clippy::unchecked_duration_subtraction)]
    #![allow(clippy::useless_vec)]
    //! <!-- @@ end test lint list maintained by maint/add_warning @@ -->
    use super::*;
    use users::mock::{Group, MockUsers, User};

    #[test]
    fn groups() {
        let groups = cur_groups().unwrap();
        let cur_gid = users::get_current_gid();
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
        let uname = get_own_username(&*cache).unwrap().expect("Running on a misconfigured host");
        let user = users::get_user_by_name(uname.as_os_str()).unwrap();
        assert_eq!(user.name(), uname);
        assert_eq!(user.uid(), users::get_current_uid());
    }

    #[test]
    fn username_from_env() {
        let username = if let Some(username) = std::env::var_os("USER") {
            username
        } else {
            // Can't test this without setting the environment, and we don't do that in tests.
            return;
        };
        let username_s = if let Some(u) = username.to_str() {
            u
        } else {
            // Can't mock usernames that aren't utf8.
            return;
        };

        let other_name = format!("{}2", username_s);

        // Case 1: Current user in environment exists, though there are some distractions.
        let mut db = MockUsers::with_current_uid(413);
        db.add_user(User::new(413, username_s, 413));
        db.add_user(User::new(999, &other_name, 999));
        // I'd like to add another user with the same UID and a different name,
        // but MockUsers doesn't support that.
        let found = get_own_username(&db).unwrap();
        assert_eq!(found.as_ref(), Some(&username));

        // Case 2: Current user in environment exists, but has the wrong uid.
        let mut db = MockUsers::with_current_uid(413);
        db.add_user(User::new(999, username_s, 999));
        db.add_user(User::new(413, &other_name, 413));
        let found = get_own_username(&db).unwrap();
        assert_eq!(found, Some(OsString::from(other_name.clone())));

        // Case 3: Current user in environment does not exist; no user can be found.
        let mut db = MockUsers::with_current_uid(413);
        db.add_user(User::new(999413, &other_name, 999));
        let found = get_own_username(&db).unwrap();
        assert!(found.is_none());
    }

    #[test]
    fn username_ignoring_env() {
        // Case 1: uid is found.
        let mut db = MockUsers::with_current_uid(413);
        db.add_user(User::new(413, "aranea", 413413));
        db.add_user(User::new(415, "notyouru!sername", 413413));
        let found = get_own_username(&db).unwrap();
        assert_eq!(found, Some(OsString::from("aranea")));

        // Case 2: uid not found.
        let mut db = MockUsers::with_current_uid(413);
        db.add_user(User::new(999413, "notyourn!ame", 999));
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
        let mut db = MockUsers::with_current_uid(413);
        db.add_user(User::new(413, "aranea", 413413));
        db.add_group(Group::new(413413, "serket"));
        let found = get_self_named_gid_impl(&db).unwrap();
        assert!(found.is_none());

        // Case 2: we find our username and a group with the same name, but we
        // are not a member of that group.
        let mut db = MockUsers::with_current_uid(413);
        db.add_user(User::new(413, "aranea", 413413));
        db.add_group(Group::new(not_our_gid, "aranea"));
        let found = get_self_named_gid_impl(&db).unwrap();
        assert!(found.is_none());

        // Case 3: we find our username and a group with the same name, AND we
        // are indeed a member of that group.
        let mut db = MockUsers::with_current_uid(413);
        db.add_user(User::new(413, "aranea", 413413));
        db.add_group(Group::new(cur_groups[0], "aranea"));
        let found = get_self_named_gid_impl(&db).unwrap();
        assert_eq!(found, Some(cur_groups[0]));
    }

    #[test]
    fn lookup_id() {
        let mut db = MockUsers::with_current_uid(413);
        db.add_user(User::new(413, "aranea", 413413));
        db.add_group(Group::new(33, "nepeta"));

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
