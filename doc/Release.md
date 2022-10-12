# How to release Arti 0.0.x

1. For 0.0.x, we do a toplevel changelog only.

  I made the toplevel changelog for 0.0.1 by reading 'git shortlog
  arti-v0.0.0..' and summarizing the best stuff.

  There is a ./maint/thanks script to generate the acknowledgments.

2. Make sure we're up-to-date.  Try to run:
  * cargo update
  * cargo upgrade --dry-run --workspace --skip-compatible
  * ./maint/cargo_audit
  * ./maint/check_licenses

    (Note that not all of the above will make changes on their own; you'll
    need to understand the output and decide what to do.)

3. Then make sure that CI passes. *Also ensure we've run tests for all
  possible Cargo feature combinations, as per arti#303.*

4. Increase all appropriate version numbers.  This time we'll be moving to
   0.0.1 on all crates.

   We'll also need to update the versions in all our dependencies to 0.0.1.

   It seems that `cargo set-version -p ${CRATE} --bump patch` does the right
   thing here, but `cargo set-version --workspace --bump patch` doesn't
   update dependent crates correctly.

   To bump the patch version of _every_ crate, run:

   ; for crate in $(./maint/list_crates); do cargo set-version -p "$crate" --bump patch; done

   To find only the crates that changed since version 0.0.x, you can run:

   ; ./maint/changed_crates arti-v0.0.x

   But note that you can't just bump _only_ the crates that changed!  Any
   crate that depends on one of those might now count as changed, even if
   it wasn't changed before.

5. Then make sure that CI passes, again.

6. From lowest-level to highest-level, we have to run cargo publish.  For
   a list of crates from lowest- to highest-level, see the top-level
   Cargo.toml.

   ; for crate in $(./maint/list_crates); do cargo publish -p "$crate"; echo "Sleeping"; sleep 30; done

    (The "sleep 30" is probably too long, but some delay seems to be
    necessary to give crates.io time to publish each crate before the next
    crate tries to download it.)

7. We tag the repository with arti-v0.0.1

8. Remove all of the semver.md files.
