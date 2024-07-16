# rust-maint-common - maintenance scripts for Rust projects

This repo contains a number of scripts and utilities
which are particularly useful for projects written in Rust,
especially if using (gitlab) CI.

## Functionality and configuration

Each script has its own documentation, typically in its head comment.

Scripts will typically be driven by normal in-tree metadata
such as `Cargo.toml`.

In some cases the scripts may
read files in `maint/` for configuration,
or execute scripts in `maint/`
(possibly scripts that also exist in this repo,
in which case you should make a suitable symlink - see below.)

## How to incorporate this into your project

The repo is designed to be merged into your history 
using `git subtree`.

It is good practice to merge it under its full name,
and to commit a symlink through which you make all references.
This will allow a downstream to replace the embedded copy,
with a reference to a shared copy.

```
git subtree add -P maint/rust-maint-common https://gitlab.torproject.org/tpo/core/rust-maint-common main
ln -s rust-maint-common main maint/common
```

Then, you can use scripts directly like this:

```
maint/common/check-blocking-todos
```

Or, you make another symlink like this
(which will make it easier to diverge, if you want to):

```
ln -s common/check-blocking-todos maint/
maint/common/check-blocking-todos
```

You can update to a new version of `rust-maint-common`
with `git subtree pull` or `git subtree merge`.

## Invocation

The script are designed to be invoked from your toplevel,
as `maint/name-of-script` or `maint/common/name-of-script`.

They will assume that `maint/common/` is this tree
(as recommended above).

## Security considerations

These scripts can be configured by files found
relative to the current directory,
and they can execute other scripts from this package,
hoping to find them via relative paths.

These scripts are not safe to run in an untrusted cwd.
They must not be put on `PATH`.

## Making changes

You should try to make only changes which would be
suitable for all users of these scripts.
But you may make them in the same commits
as you change other parts of your tree.

After you have made changes and are satisfied with them,
you should use `git subtree split` or `git subtree push`
to split off the changes you have made,
into a branch of (a fork of) this repo.
Then you can make a Merge Request for your changes.

## Copyright and licence

Copyright The Tor Project, Inc, and contributors.

This whole repository is Free Software.
You may share and modify under the terms of the MIT License
or the Apache License version 2.0.

SPDX-License-Identifier: MIT OR Apache-2.0
