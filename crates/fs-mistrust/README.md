# fs-mistrust

Check whether file permissions are private.

This crate provides a set of functionality to check the permissions on files
and directories to ensure that they are effectively private—that is, that
they are only readable or writable by trusted[^1] users.

This kind of check can protect your users' data against misconfigurations,
such as cases where they've accidentally made their home directory
world-writable, or where they're using a symlink stored in a directory owned
by another user.

The checks in this crate try to guarantee that, after a path has been shown
to be private, no action by a _non-trusted user_ can make that path private.
It's still possible for a _trusted user_ to change a path after it has been
checked.  Because of that, you may want to use other mechanisms if you are
concerned about time-of-check/time-of-use issues caused by _trusted_ users
altering the filesystem.

Also see the [Limitations](#limitations) section below.

[^1]: we define "trust" here in the computer-security sense of the word: a
     user is "trusted" if they have the opportunity to break our security
     guarantees.  For example, `root` on a Unix environment is "trusted",
     whether you actually trust them or not.

### What's so hard about checking permissions?

Suppose that we want to know whether a given path can be read or modified by
an untrusted user. That's trickier than it sounds:

* Even if the permissions on the file itself are correct, we also need to
  check the permissions on the directory holding it, since they might allow
  an untrusted user to replace the file, or change its permissions.
* Similarly, we need to check the permissions on the parent of _that_
  directory, since they might let an untrusted user replace the directory or
  change _its_ permissions.  (And so on!)
* It can be tricky to define "a trusted user".  On Unix systems, we usually
  say that each user is trusted by themself, and that root (UID 0) is
  trusted.  But it's hard to say which _groups_ are trusted: even if a given
  group contains only trusted users today, there's no OS-level guarantee
  that untrusted users won't be added to that group in the future.
* Symbolic links add another layer of confusion.  If there are any symlinks
  in the path you're checking, then you need to check permissions on the
  directory containing the symlink, and then the permissions on the target
  path, _and all of its ancestors_ too.
* Many programs first canonicalize the path being checked, removing all
  `..`s and symlinks.  That's sufficient for telling whether the _final_
  file can be modified by an untrusted user, but not for whether the _path_
  can be modified by an untrusted user.  If there is a modifiable symlink in
  the middle of the path, or at any stage of the path resolution, somebody
  who can modify that symlink can change which file the path points to.
* Even if you have checked a directory as being writeable only by a trusted
  user, that doesn't mean that the objects _in_ that directory are only
  writeable by trusted users.  Those objects might be symlinks to some other
  (more writeable) place on the file system; or they might be accessible
  with hard links stored elsewhere on the file system.

Different programs try to solve this problem in different ways, often with
very little rationale.  This crate tries to give a reasonable implementation
for file privacy checking and enforcement, along with clear justifications
in its source for why it behaves that way.


### What we actually do

To make sure that every step in the file resolution process is checked, we
emulate that process on our own.  We inspect each component in the provided
path, to see whether it is modifiable by an untrusted user.  If we encounter
one or more symlinks, then we resolve every component of the path added by
those symlink, until we finally reach the target.

In effect, we are emulating `realpath` (or `fs::canonicalize` if you
prefer), and looking at the permissions on every part of the filesystem we
touch in doing so, to see who has permissions to change our target file or
the process that led us to it.

For groups, we use the following heuristic: If there is a group with the
same name as the current user, and the current user belongs to that group,
we assume that group is trusted.  Otherwise, we treat all groups as
untrusted.

### Examples

#### Simple cases

Make sure that a directory is only readable or writeable by us (simple
case):

```rust
use fs_mistrust::Mistrust;
match Mistrust::new().check_directory("/home/itchy/.local/hat-swap") {
    Ok(()) => println!("directory is good"),
    Err(e) => println!("problem with our hat-swap directory: {}", e),
}
```

As above, but create the directory, and its parents if they do not already
exist.

```rust
use fs_mistrust::Mistrust;
match Mistrust::new().make_directory("/home/itchy/.local/hat-swap") {
    Ok(()) => println!("directory exists (or was created without trouble"),
    Err(e) => println!("problem with our hat-swap directory: {}", e),
}
```

#### Configuring a [`Mistrust`]

You can adjust the [`Mistrust`] object to change what it permits:

```rust,no_run
# fn main() -> Result<(), fs_mistrust::Error> {
use fs_mistrust::Mistrust;

let my_mistrust = Mistrust::builder()
    // Assume that our home directory and its parents are all well-configured.
    .ignore_prefix("/home/doze/")
    // Assume that a given group will only contain trusted users (this feature is only
    // available on Unix-like platforms).
    // .trust_group(413)
    .build()?;
# Ok(())
# }
```

See [`Mistrust`] for more options.

#### Using [`Verifier`] for more fine-grained checks

For more fine-grained control over a specific check, you can use the
[`Verifier`] API.  Unlike [`Mistrust`], which generally you'll want to
configure for several requests, the changes in [`Verifier`] generally make
sense only for one request at a time.

```rust,no_run
# fn main() -> Result<(), fs_mistrust::Error> {
# #[cfg(feature = "walkdir")] {
use fs_mistrust::Mistrust;
let mistrust = Mistrust::new();

// Require that an object is a regular file; allow it to be world-
// readable.
mistrust
    .verifier()
    .permit_readable()
    .require_file()
    .check("/home/trace/.path_cfg")?;

// Make sure that a directory _and all of its contents_ are private.
// Create the directory if it does not exist.
// Return an error object containing _all_ of the problems discovered.
mistrust
    .verifier()
    .require_directory()
    .check_content()
    .all_errors()
    .make_directory("/home/trace/private_keys/");
# }
# Ok(())
# }
```

See [`Verifier`] for more options.

#### Using [`CheckedDir`] for safety.

You can use the [`CheckedDir`] API to ensure not only that a directory is
private, but that all of your accesses to its contents continue to verify
and enforce _their_ permissions.

```rust,no_run
# fn main() -> Result<(), fs_mistrust::Error> {
use fs_mistrust::{Mistrust, CheckedDir};
use std::fs::{File, OpenOptions};
let dir = Mistrust::new()
    .verifier()
    .secure_dir("/Users/clover/riddles")?;

// You can use the CheckedDir object to access files and directories.
// All of these must be relative paths within the path you used to
// build the CheckedDir.
dir.make_directory("timelines")?;
let file = dir.open("timelines/vault-destroyed.md",
    OpenOptions::new().write(true).create(true))?;
// (... use file...)
# Ok(())
# }
```

### Limitations

As noted above, this crate only checks whether a path can be changed by
_non-trusted_ users.  After the path has been checked, a _trusted_ user can
still change its permissions.  (For example, the user could make their home
directory world-writable.)  This crate does not try to defend against _that
kind_ of time-of-check/time-of-use issue.

We currently assume a fairly vanilla Unix environment: we'll tolerate other
systems, but we don't actually look at the details of any of these:
   * Windows security (ACLs, SecurityDescriptors, etc)
   * SELinux capabilities
   * POSIX (and other) ACLs.

We use a somewhat inaccurate heuristic when we're checking the permissions
of items _inside_ a target directory (using [`Verifier::check_content`] or
[`CheckedDir`]): we continue to forbid untrusted-writeable directories and
files, but we still allow readable ones, even if we insisted that the target
directory itself was required to to be unreadable.  This is too permissive
in the case of readable objects with hard links: if there is a hard link to
the file somewhere else, then an untrusted user can read it.  It is also too
restrictive in the case of writeable objects _without_ hard links: if
untrusted users have no path to those objects, they can't actually write
them.

On Windows, we accept all file permissions and owners.

We don't check for mount-points and the privacy of filesystem devices
themselves.  (For example, we don't distinguish between our local
administrator and the administrator of a remote filesystem. We also don't
distinguish between local filesystems and insecure networked filesystems.)

This code has not been audited for correct operation in a setuid
environment; there are almost certainly security holes in that case.

This is fairly new software, and hasn't been audited yet.

All of the above issues are considered "good to fix, if practical".

### Acknowledgements

The list of checks performed here was inspired by the lists from OpenSSH's
[safe_path], GnuPG's [check_permissions], and Tor's [check_private_dir]. All
errors are my own.

[safe_path]:
    https://github.com/openssh/openssh-portable/blob/master/misc.c#L2177
[check_permissions]:
    https://github.com/gpg/gnupg/blob/master/g10/gpg.c#L1551
[check_private_dir]:
    https://gitlab.torproject.org/tpo/core/tor/-/blob/main/src/lib/fs/dir.c#L70

License: MIT OR Apache-2.0
