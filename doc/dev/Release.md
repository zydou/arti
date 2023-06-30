# How to release Arti

## Are we ready to release?

## Preparing the release

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

## Actually releasing


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

## Post-release

8. Remove all of the semver.md files.

9. Update the origin/pages branch to refer to the new version.


# Making a patch release of a crate, eg to fix a semver breakage

If one crate needs to be updated urgently
(eg to fix a build breakage),
we can release it separately as follows.

(The underlying principle is to try to
make precisely the minimal intended change;
and avoid picking up other changes made to Arti crates
since the last release.)

0. File a ticket describing the problem.
   This will be referenced in MRs, release docs, etc.

1. Prepare the changes on a git branch
   starting from the most recent `arti-v...` tag, **not main**.

   (If this happens more than once per Arti release cycle,
   start the branch from the previous crate-specific tag;
   we should perhaps create a `patch-releases` branch
   if this is other than a very rare case.)

2. Changes on this branch should include:
   * The underlying desired change (whether to code or `Cargo.toml`s)
   * Version bump to the crate being released
   * Absolutely minimal necessary changes to `Cargo.lock`.
     (`Cargo.lock` is mostly for CI here.)
   * New stanza in `CHANGELOG.md` describing the point release
     (and cross-referencing to the ticket).

3. Make an MR of this branch.
   State in the MR that the branch is intended for a patch update.
   Obtain a review.

4. If the CI passes, and review is favourable,
   merge the MR and go on to step 5.

5. If the CI failed, you may want to proceed anyway.
   For example, `cargo audit`, or builds with Nightly,
   can rot, without us having done anything.
   If you think you wish to do this:

    1. Review the CI output for the failing command,
       and make a decision about it,
       in consultation with your reviewer.
       If you wish to tolerate this failure:

    2. Create a new git branch `bodge`
       off the patch release branch.

    3. In `.gitlab-ci.yml`,
       prepend the failing shell command with `true X X X`
       (only with the three Xs cuddled together).
       This will cause it to not run, but "succed".
       The `XXXs` will cause the blocking-todos CI job to fail,
       hindering accidental merge of this branch to main.

    4. Make a new MR of this `bodge` branch.
       Say "do not merge" in the title
       and mark it draft.

    5. Await CI on the bodge MR.
       If all that fails is the blocking todos,
       you're good to go.
       Otherwise, go back to sub-step 1
       and review the further failures.

    6. Double check which MR page you are looking at:
       you must be looking at the real patch MR,
       not the CI bodge MR, or some unrelated MR.
       Then, tell gitlab to merge the branch despite CI failure.

6. After the patch branch is merged,
   check it out locally and make releases:

    1. Check that you are on the patch branch, not `main`.

    2. `cargo publish -p the-affected-crate`.

    3. `git tag -s the-affected-crate-vX.Y.Z`
       and push the tag.

7. File any followup tickets and/or do any post-patch cleanup.

8. Consider whether to make a blog post about the patch release.
