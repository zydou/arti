# `fslock-guard` — A guard object to ensure we have an exclusive lock to a file

This crate is a thin wrapper around [`fslock`], which uses [`flock`(2)] or
[`LockFileEx`] to aquire an advisory lock on the filesystem. 

We add two features that `fslock` does not (currently) have:

 - We have a [`LockFileGuard`] type, which can be used to ensure that a lock is
   actually held until the guard is dropped.
 - We perform a post-lock check to make sure that the our lockfile has not been
   removed and re-created on disk by someone else.  This check makes it safe to
   remove lockfiles.

[`fslock`]: https://docs.rs/fslock/latest/fslock/index.html
[`flock`(2)]: https://man7.org/linux/man-pages/man2/flock.2.html
[`LockFileEx`]: https://learn.microsoft.com/en-us/windows/win32/api/fileapi/nf-fileapi-lockfileex
