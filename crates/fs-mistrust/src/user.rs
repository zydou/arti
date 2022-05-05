//! Code to inspect user db information on unix.

use once_cell::sync::Lazy;
use std::{ffi::OsString, sync::Mutex};

/// Cached values of user db entries we've looked up.
///
/// Caching here saves time, AND makes our code testable.
///
/// Though this type has interior mutability, it isn't Sync, so we need to add a mutex.
static CACHE: Lazy<Mutex<users::UsersCache>> = Lazy::new(|| Mutex::new(users::UsersCache::new()));

/// Look for a group with the same name as our username.
///
/// If there is one, and we belong to it, return its gid.  Otherwise
/// return None.
pub(crate) fn get_self_named_gid() -> Option<u32> {
    let cache = CACHE.lock().expect("Poisoned lock");
    get_self_named_gid_impl(&*cache)
}

/// Like get_self_named_gid(), but use a provided user database.
fn get_self_named_gid_impl<U: users::Groups + users::Users>(userdb: &U) -> Option<u32> {
    let username = get_own_username(userdb)?;

    let group = userdb.get_group_by_name(username.as_os_str())?;

    // TODO: Perhaps we should enforce a requirement that the group contains
    // _only_ the current users.  That's kinda tricky to do, though, without
    // walking the entire user db.

    if cur_groups().contains(&group.gid()) {
        Some(group.gid())
    } else {
        None
    }
}

/// Find our username, if possible.
///
/// By default, we look for the USER environment variable, and see whether we an
/// find a user db entry for that username with a UID that matches our own.
///
/// Failing that, we look for a user entry for our current UID.
fn get_own_username<U: users::Users>(userdb: &U) -> Option<OsString> {
    let my_uid = userdb.get_current_uid();

    if let Some(username) = std::env::var_os("USER") {
        if let Some(passwd) = userdb.get_user_by_name(username.as_os_str()) {
            if passwd.uid() == my_uid {
                return Some(username);
            }
        }
    }

    if let Some(passwd) = userdb.get_user_by_uid(my_uid) {
        // This check should always pass, but let's be extra careful.
        if passwd.uid() == my_uid {
            return Some(passwd.name().to_owned());
        }
    }

    None
}

/// Return a vector of the group ID values for every group to which we belong.
///
/// (We don't use `users::group_access_list()` here, since that function calls
/// `getgrnam_r` on every group we belong to, when in fact we don't care what
/// the groups are named.)
fn cur_groups() -> Vec<u32> {
    let n_groups = unsafe { libc::getgroups(0, std::ptr::null_mut()) };
    if n_groups <= 0 {
        return Vec::new();
    }
    let mut buf: Vec<users::gid_t> = vec![0; n_groups as usize];
    let n_groups2 = unsafe { libc::getgroups(buf.len() as i32, buf.as_mut_ptr()) };
    if n_groups2 <= 0 {
        return Vec::new();
    }
    if n_groups2 < n_groups {
        buf.resize(n_groups2 as usize, 0);
    }
    buf
}

#[cfg(test)]
mod test {
    #![allow(clippy::unwrap_used)]
    use super::*;
    use users::mock::{Group, MockUsers, User};

    #[test]
    fn groups() {
        let groups = cur_groups();
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
        let uname = get_own_username(&*cache).expect("Running on a misconfigured host");
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
        let found = get_own_username(&db);
        assert_eq!(found.as_ref(), Some(&username));

        // Case 2: Current user in environment exists, but has the wrong uid.
        let mut db = MockUsers::with_current_uid(413);
        db.add_user(User::new(999, username_s, 999));
        db.add_user(User::new(413, &other_name, 413));
        let found = get_own_username(&db);
        assert_eq!(found, Some(OsString::from(other_name.clone())));

        // Case 3: Current user in environment does not exist; no user can be found.
        let mut db = MockUsers::with_current_uid(413);
        db.add_user(User::new(999413, &other_name, 999));
        let found = get_own_username(&db);
        assert!(found.is_none());
    }

    #[test]
    fn username_ignoring_env() {
        // Case 1: uid is found.
        let mut db = MockUsers::with_current_uid(413);
        db.add_user(User::new(413, "aranea", 413413));
        db.add_user(User::new(415, "notyouru!sername", 413413));
        let found = get_own_username(&db);
        assert_eq!(found, Some(OsString::from("aranea")));

        // Case 2: uid not found.
        let mut db = MockUsers::with_current_uid(413);
        db.add_user(User::new(999413, "notyourn!ame", 999));
        let found = get_own_username(&db);
        assert!(found.is_none());
    }

    #[test]
    fn selfnamed() {
        // check the real groups we're in, since this isn't mockable.
        let cur_groups = cur_groups();
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
        let found = get_self_named_gid_impl(&db);
        assert!(found.is_none());

        // Case 2: we find our username and a group with the same name, but we
        // are not a member of that group.
        let mut db = MockUsers::with_current_uid(413);
        db.add_user(User::new(413, "aranea", 413413));
        db.add_group(Group::new(not_our_gid, "aranea"));
        let found = get_self_named_gid_impl(&db);
        assert!(found.is_none());

        // Case 3: we find our username and a group with the same name, AND we
        // are indeed a member of that group.
        let mut db = MockUsers::with_current_uid(413);
        db.add_user(User::new(413, "aranea", 413413));
        db.add_group(Group::new(cur_groups[0], "aranea"));
        let found = get_self_named_gid_impl(&db);
        assert_eq!(found, Some(cur_groups[0]));
    }
}
