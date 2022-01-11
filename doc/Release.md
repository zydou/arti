# How to release Arti 0.0.x

1. For 0.0.x, we do a toplevel changelog only.

  I made the toplevel changelog for 0.0.1 by reading 'git shortlog
  arti-v0.0.0..' and summarizing the best stuff.

  There is a ./maint/thanks.sh script to generate the acknowledgments.

2. Make sure we're up-to-date.  Try to run:
  * cargo update
  * cargo upgrade --dry-run --workspace --skip-compatible
  * ./maint/cargo_audit.sh
  * ./maint/check_licenses.sh
  * ./maint/readmes.sh

3. Then make sure that CI passes.

4. Increase all appropriate version numbers.  This time we'll be moving to
   0.0.1 on all crates.

   We'll also need to update the versions in all our dependencies to 0.0.1.

   It seems that `cargo set-version -p ${CRATE} --bump patch` does the right
   thing here, but `cargo set-version --workspace --bump patch` doesn't
   update dependent crates correctly.

   ; for crate in $(./maint/list_crates.py); do cargo set-version -p "$crate" --bump patch; done

5. Then make sure that CI passes, again.

6. From lowest-level to highest-level, we have to run cargo publish.  For
   a list of crates from lowest- to highest-level, see the top-level
   Cargo.toml.

   ; for crate in $(./maint/list_crates.py); do cargo publish -p "$crate"; echo "Sleeping"; sleep 30; done

    (The "sleep 30" is probably too long, but some delay seems to be
    necessary to give crates.io time to publish each crate before the next
    crate tries to download it.)

7. We tag the repository with arti-v0.0.1
