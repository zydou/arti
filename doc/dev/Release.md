# How to release Arti

Note that many of these steps can be done in parallel.
It is worth reading through all the steps,
and considering what things it is possible to do while you are waiting for CI or reviews.

## Checklist

* [ ] Create the checklist ticket

Run `maint/release-prep-ticket-template` to generate a checklist.

Paste it into a new ticket, perhaps using
`maint/release-prep-ticket-template | xclip`.

Set the "Blocker" label on that ticket and assign it to yourself.

## Tools and notation

We're going to use the following.
Why not upgrade to the latest version before you start?

  * `cargo-semver-checks`
  * `cargo-edit`
  * `cargo-audit`
  * `cargo-license`
  * `cargo-sort` (note that we currently need version 2.0.1 specifically, see [#2156])

In the documentation below,
we sometimes use environment variables to indicate
particular versions of Arti.
For example, in the release I just did, I had:

```
LAST_VERSION=1.1.5
THIS_VERSION=1.1.6
```

## Are we ready to release?

Before we can finally release, we need to check a few things
to make sure we aren't going to break our users.

1. [ ] Make sure CI is passing.

2. After making sure that the pipeline as a whole has passed,
   look at every part of the pipeline that "passed with warnings".
   Are the warnings what we expect?
   If it's failing, is is it failing for the reasons we anticipated,
   or have new failures crept in?

3. [ ] Look at the current list of exceptions in our automated tooling.

   Are they still relevant?
   (There are exceptions in
   `cargo_audit`
   and
   `check_licenses`.)

4. [ ] Do we have any open [issues] or [merge requests] tagged "Blocker"?

[issues]: https://gitlab.torproject.org/tpo/core/arti/-/issues/?label_name%5B%5D=Blocker
[merge requests]: https://gitlab.torproject.org/tpo/core/arti/-/merge_requests/?label_name[]=Blocker

5. [ ] Ensure `maint/fixup-features` is happy

   Does `maint/fixup-features` produce any results?
   If so, fix them.

   Note: fixup-features should be run with the top-level Cargo.toml
   as an argument:
   ```
   cargo run -p fixup-features -- --exclude examples/ --exclude maint/ Cargo.toml
   ```

6. [ ] Does `maint/semver-checks "arti-v$LAST_VERSION" | tee ../semver.log` find any issues
   not noted in our semver.md files?
   If so, add them.

   (Note that not every issue reported by cargo-semver-checks
   is necessarily significant.  See issue [#1983].)

[#1983]: https://gitlab.torproject.org/tpo/core/arti/-/issues/1983

Note that you can do these steps _in parallel_ with "preparing for the
release" below.

## Preparing for the release

Note that you can do these steps _in parallel_ with "are we ready to
release?" above.

4. [ ] Write a changelog.

   I start by copying the [changelog template](./ChangelogTemplate.md),
   and filling in the version and date.

   Then I run
   `git log --topo-order --reverse arti-v${LAST_VERSION}..`,
   and writing a short summary of everything I find into
   new sections of the changelog.
   I try to copy the list of sections
   from previous changelogs, to keep them consistent.

   If I have to take a break in the middle,
   or if time will pass between now and the release,
   I add a note like
   `UP TO DATE WITH 726f666c2d2d6d61646520796f75206c6f6f6b21`
   to remind me where I need to start again.

   The script `maint/changelog-syntax-fiddle`
   can be helpful to write the cross-references more easily.

   See below for our current [changelog style guide](#changelog-style-guide).

5. [ ] Finish the changelog.

   When the changelog is done, run
   `maint/update-md-links CHANGELOG.md`
   to auto-generate markdown links
   to our gitlab repositories.
   (This script may need a Python venv, as it depends on
   a specific version of the `mistune` library.)
   Then, fill in the URLs for any links that the script couldn't find -
   they'll be marked with X X X todo markers.

   Run `maint/format_md_links CHANGELOG.md`
   to ensure that the lists of links on each entry
   are in the expected format.

   Run `maint/thanks arti-v${LAST_VERSION}`
   to generate our list of acknowledgments;
   insert this into the changelog.

   Add an acknowledgement for the current sponsor(s).

6. [ ] Determine what semver/version update to do to each crate.

   We need to sort our crates into the following tiers.
    * Unstable (0.x) `tor-*` and `arti-*` crates.
      (Bump minor version, to the same value for each crate.)
    * No changes were made.
      (No version bump needed)
    * Only non-functional changes were made.
      (Bump the version of the crate, but not the depended-on version.)
    * Functional changes were made, but no APIs were added or broken.
      (Bump patchlevel.)
    * APIs were added.
      (Bump patchlevel if major == 0; else bump minor.)
    * APIs were broken.
      (Bump minor if major == 0; else bump major.)
    * MSRV was increased.
      (Bump minor; see our [MSRV policy][msrv])
    * Crates that we do not publish (E.g. `maint/*`, `examples/*`).
      (Do not bump version)

   [msrv]: https://gitlab.torproject.org/tpo/core/arti#minimum-supported-rust-version

   For all `tor-*` and `arti-*` crates with 0.x version numbers
   (which, as of March 2024 includes all `tor-*` crates,
   and all `arti-*` crates apart from `arti` itself),
   we always bump the minor version and release,
   even if there have been no changes.
   For other crates, things are more complicated:

   You can identify crates that have no changes using `maint/changed_crates`:
   ```
   maint/changed_crates -v "arti-v$LAST_VERSION" 2>&1 >/dev/null | grep -i "no change"
   ```

   To see whether a crate has only non-functional changes,
   you have to use  `git diff`.  Sorry!
   Historically, trivial changes
   are small tweaks in the clippy lints,
   or documentation/comment improvements.

   To determine whether any APIs were added,
   look in the semver.md files.
   (We often forget to add these;
   but fortunately,
   most of our crates currently have major version 0,
   so we don't need to distinguish "functional changes"
   from "new APIs".)

   To determine whether any APIs were broken,
   look in the semver.md files.
   The `cargo semver-checks` tool
   can also identify some of these,
   but its false-negative rate is high.

   You may also want to look over the crate-by-crate diffs.
   This can be quite time-consuming.

## Final preparation for a release.

Wait! Go back and make sure
that you have done everything in the previous sections
before you continue!

0. [ ] Tell `network-team` (via email and IRC) that the tree is now frozen,
   and no MRs should be merged.

1. [ ] Finalize the changelog.

   Make sure that the date is correct.
   Make sure that the acknowledgments and links are correct,
   if they might have gotten stale.

2. [ ] Increase all appropriate version numbers.

   For unstable (0.x) `tor-*` and `arti-*` crates,
   determine the new minor number.
   `maint/list_crates --version  | grep -P '^tor|^arti'`
   will show you the existing versions,
   which should usually all be the same.
   Pick the next minor version, and, for each such crate:
   `cargo set-version -p ${CRATE} 0.${MINOR}.0`.

   For other crates:

    * For each crate with functional changes:
      `cargo set-version --bump {patch|minor|major} -p ${CRATE}`.

    * For crates with non-functional changes,
      you can use the `bump_nodep` script:
      `./maint/bump_nodep crate1 crate2 crate3` ...

   In all cases, make sure you commit `Cargo.lock` changes too.

   If `hashx` or `equix` have changed since the last release, you must also update
   `crates/{hashx,equix}/bench/Cargo.lock`,
   which aren't in the workspace for
   [Reasons](https://gitlab.torproject.org/tpo/core/arti/-/issues/1351):

```
		(cd crates/hashx/bench && cargo update)
		(cd crates/equix/bench && cargo update)
```

3. [ ] (Re)run `maint/semver-checks` (having addressed any expected problems)

   Check for side effects from bumping versions!

   As of March 2024, you can skip this section
   for `tor-*` and `arti-*`, since:
     * `arti` is the only non-0.x `arti-*` or `tor-*` crate;
	 * `arti` does not expose types from our lower-layer crates;
	 * None other of our crates depend on `tor-*` or `arti-*` crates.
   Therefore all necessary bumps have been done.

   You may need to perform these checks
   if there have been semver bumps
   to non-`arti-*` or `tor-*` crates,
   when other such crates expose their types.

   Does a previously unchanged crate
   depend on a crate that got a version bump?
   Now _that_ crate counts as changed,
   and needs a version bump of its own.

   You can list all crates that have changed
   since the last version,
   but not had their versions bumped,
   with the command
   `./maint/changed_crates -u ${LAST_VERSION}`.
   (Note the `-u`.)

   Run `maint/semver-checks` again:
   It should be quiet now that you bumped all the versions.

4. [ ] Run `maint/update-release-date`

   This makes sure that Arti has an accurate sense of when its version was bumped.

## The actual release itself.

1. [ ] Recheck for *Blocker* [issues] and [merge requests].

2. [ ] Make sure that CI passes, again, on `main`.

3. [ ] Run `maint/cargo-publish`.

   First, run `maint/cargo-publish --dry-run ${THIS_VERSION}`
   to see what it thinks.

   If all seems well, run it without the `--dry-run` option.

   If it fails, you may be able to rerun the script
   after fixing the cause.
   It is supposed to be idempotent.

4. [ ] Make the signed git tag `arti-v${THIS_VERSION}`

   To do this, run
   `maint/tag-arti-release ${THIS_VERSION}`
   (which will include the output of `maint/list_crates --version`).

   (Note to self: if you find that gpg can't find your yubikey,
   you'll need to run
   `sudo systemctl restart pcscd`
   to set things right.
   I hope that nobody else has this problem.)

## Post-release

3. [ ] Tell `network-team` (via email and IRC) that the tree is open
   for new MRs to be merged!

1. [ ] Remove all of the semver.md files:
   `git rm crates/*/semver.md`.

   (Note that we do this _after_ the release,
   so that the relevant `semver.md` entries
   are present in the tagged commit,
   and easy to find for reference.)

2. [ ] Write and publish a blog post.

3. [ ] If new crates published, add appropriate owners.

   Did you create any new crates?
   If so, you need to make sure that they are owned (on crates.io)
   by the right set of developers.
   If you aren't sure, run `maint/cargo-crate-owners`.
   You can then use `cargo owner --add <username> <crate-name>`
   to add them as owners for the new crates.

4. [ ] Run `cargo update`, to obtain non-breaking changes in our dependencies

   Check for non-breaking changes to our dependencies with
   `cargo update`.
   This will replace each of our dependencies in Cargo.lock
   with the latest version.

5. [ ] Consider dependency updates for breaking changes in our dependencies.

   Check for breaking changes to our dependencies with
   `cargo upgrade --dry-run --compatible=ignore --incompatible=allow`.
   This will tell us if any of our dependencies
   have new versions that will not upgrade automatically.

   Then, check the tickets with the label "[Upgrade Blocker]":
   they will tell you about things that we tried to upgrade in the past,
   but weren't able to upgrade.  (This might save you some headaches.)

   [Upgrade Blocker]: https://gitlab.torproject.org/tpo/core/arti/-/issues/?sort=created_date&state=opened&label_name%5B%5D=Upgrade%20Blocker

   Then, upgrade these dependencies.
   Note that in some cases, this will be nontrivial:
   APIs may have changed, or the upgraded versions may not be compatible
   with our current MSRV.
   You'll may need to either fix the call sites to the old APIs,
   skip the upgrade,
   or open a ticket to upgrade the crate later on.

   If there is a dependency you can't upgrade,
   open an Arti ticket for it, with the label "Upgrade Blocker".
   If the reason you can't upgrade is a bug in the dependency,
   or _accidental_ MSRV breakage, file a bug upstream.

6. [ ] Consider updating CI Docker images.

   Look in `.gitlab-ci.yml` for docker images that we specify a specific version for.
   These are the `image:` items within each job.

   Check [Docker Hub](https://hub.docker.com) for each image to see if there is a more recent version,
   and update to it if it is available. If the update causes a breakage,
   either fix the breakage or file a "[Upgrade Blocker]" ticket with details.

   Note that some images may intentionally specify older versions,
   such as our `minimal-versions` test which is currently used to test our MSRV as well.

7. [ ] Make MR(s) of any changes to `Release.md` and/or release tooling.

   If anything was janky or didn't go as planned, and you can see how
   to improve it, please fix it - here or in the relevant tooling.

[!2271]: https://gitlab.torproject.org/tpo/core/arti/-/merge_requests/2271

<!-- ================================================== -->

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
       This will cause it to not run, but "succeed".
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

# Changelog style guide

> This guide is fairly rough;
> it is mainly here to ensure that we get similar changelogs
> no matter who is writing them.
>
> If this guide produces bad results, we should change it.

## Goals and guidelines

The CHANGELOG is meant to be read by downstream users and developers;
try to describe things from their point of view,
and emphasize the entries that they care about.

Other people will read the CHANGELOG too:
do not assume that the audience has extensive Tor experience,
or knowledge of our inner workings.

When writing a CHANGELOG,
think about what users will most want to know,
and make sure to describe the
implications of things in terms of how the user experience will change,
what they should look out for,
what was the impact/risk from that bug you fixed,
what new features they should try in this new version,
and so on.

The CHANGELOG is partly an advertisement
for why users should want to upgrade,
and partly a historical document
so that people can go back to discover
what features/bugs were present in which past versions.

In times of excitement,
the CHANGELOG may even get attention from the press.
When possible, avoid phrases prone to misinterpretation or sensationalism.

## Format

Please use the [changelog template](ChangelogTemplate.md)
as a rough guide to what pieces of each changelog go where.

Every individual changelog entry should be a bullet-point,
looking more or less like this:

```
- Arti can now [brew a pleasant cup of tea]. ([#9090], [#9091], [!9998],
  [!9999])
```

Each entry should contain a terse description of what changed,
ending with a period.
After that description, there is a list of reference links.

Use the `maint/format_md_links` tool
to ensure that all of the reference links
are in brackets, comma-separated, and wrapped in parentheses.
Make sure to check its output:
As of 2025 Jan, it is fairly new.

## Reference links.

The reference links are surrounded by parentheses;
they are separated by commas.

Reference links can be to tickets (`[#1234]`),
merge requests (`[!1234]`),
proposals (`[prop123]`),
TROVE IDs (`[TROVE-2024-001]`),
git commits (`[1ce40b6e4a43bab4]`),
or other relevant references.
They are intended to answer the question
"where can I find out more?"

Reference links should be grouped by type,
then sorted by number.

Use commit links only when a relevant MR is not present,
or (rarely) when describing a particular commit individually.

One changelog entry per merge request can be a good starting point;
however, it is usually best to combine many merge requests into a single entry
when they are logically combining to the same kind of development.
The primary goal should be to structure the information for readability
(including skim-reading) and comprehensibility,
not to mirror the structure of the actual development work.
It is also okay to make a changelog entry for a single commit
when it does something interesting not covered by its MR.

It is okay to refer to the same ticket or MR at multiple places
in the changelog.

It is okay to omit entries for MRs that do completely trivial actions
(such as adjusting a single line of whitespace).

We should usually omit entries for actions that we take routinely
as part of the release process
(such as running "cargo update" or removing "semver.md" files).
As an exception, we _should_ document upgraded dependencies
(as occur when we run "cargo upgrade").

We should usually omit entries for actions that are nobody's business
and do not affect Arti itself.
(such as adjusting an entry in `.mailmap`).

We should usually omit entries
for fixing a bug or clean up a piece of code
that didn't appear in any released version of Arti.
Instead, we add the MR that fixes the code to the changelog entry
in which the code was introduced.

## Style (specific to Changelog)

**Be terse.**

Prefer grammatical structures
in the following _declining_ order of preference:

- Arti's new behavior, described in the present tense with "now".
  ("Arti now requires Rust 1.77";
  "`tor-bytes` now allows generic strings".)
- Something that _we_ did, in the past tense, with no subject.
  ("Removed support for Rust ≤1.76";
  "Added generic-string support to `tor-bytes`".)
- Something that Arti will now do,
  in the imperative:
  as if you were telling Arti to do it.
  ("Don't support Rust ≤1.76";
  "Support generic strings in `tor-bytes`".)
- Bare noun phrases with no main verb,
  if noun is something
  newly done, added, or instituted.
  ("New requirement for Rust 1.77";
  "Generic string support in `tor-bytes`".)

Try to avoid these grammatical structures:

- Something that _we_ did described
  with the present tense, imperative, or infinitive.
  \[Sorry, these are hard to distinguish in English.\]
  ("Add requirement for Rust 1.77",
  "Tweak `tor-bytes` to support generic strings.")
- Bare gerunds.
  ("Requiring Rust version 1.77";
  "Supporting generic strings in `tor-bytes`")
- Passive voice.
  ("Rust 1.77 now required";
  "Generic strings now supported by `tor-bytes`.")
- Something we did using the word "we".
  ("We have added a rust 1.77 requirement";
   "we made `tor-bytes` support generic strings").
- Something that Arti now does, using the word "we".
  ("We now require 1.77";
  "we now support generic strings in `tor-bytes`.")
- Bare noun phrases with no main verb,
  if noun is **not** something
  done, added, or instituted.
  ("Bug in Rust 1.77";
  "Performance in `tor-bytes`".)

<!-- NOTE:  C tor changelog style prefers present-tense for changes,
     and never past tense.  Our guidelines here reflect a change in that
     rule.
     TODO: Confirm that's what we want.
 -->

Avoid referring to the reader as "you";
instead prefer the imperative.  ("To find out more, consult..."
or "To enable this feature, use...")


Be descriptive.
Avoid bland entries like "general hacking on X" or "Work on Y".
If you can't tell what an MR actually did,
ask the author for help.

For new features that people will want to try, link to instructions.
(Alternatively, you can recapitulate the instructions
if they are short and simple.)

Prefer the section names from the template,
when they are applicable.

Mention configuration options by name in `monospace`.
If they're rare or unusual, remind people what they're for.

When fixing a bug, consider describing what the old undesired behavior was.
("Previously, Arti could catch fire if you left it plugged in overnight.";
"Fix a bug that made onion services slow.")
If the bug was introduced in an identifiable version of Arti,
use the parenthetical phrasing "(Bug first appeared in Arti 1.2.3)"

## Style (general)

Prefer US spelling ("behavior", "anonymize").

"Arti" is capitalized except when it refers to the crate or the binary.

Write the names of crates, functions, and classes
in `monospace`.

Prefer English ("for example/such as", "that is", "and so on")
over Latin ("e.g.", "i.e.", "etc.").

Try to use the "channel cell"/"relay message" terminology correctly.

Say "onion service" not "hidden service"
in user-facing documentation.

Begin sentences with a capital letter.
If a sentence would begin with an identifier
that starts with a lowercase letter,
make sure that the identifier is in `monospace`,
and consider describing it so it does not start the sentence.
(Not "tor-bytes is..." and not "Tor-bytes is...",
but "`tor-bytes` is..." or "The `tor-bytes` crate is...".)
It is not generally necessary necessary to linkify references to Rust APIs.

Be careful when saying "connection";
instead you might mean
"channel", "circuit", "stream",
"TCP connection", "TLS connection",
or something else entirely.
Use "connection" when you mean more than one kind of underlying thing,
or when it is clearer to avoid giving specific technical detail.

Say "relays", not "servers" or "nodes" or "tor relays".

> “Substitute 'damn' every time you're inclined to write 'very;' your editor
> will delete it and the writing will be just as it should be.” — Mark Twain

An [em dash] is written as &emdash; or — or ---; never as a hyphen (`-`).
It does not have spaces adjacent to it.
You can often substitute a colon.

[em dash]: https://en.wikipedia.org/wiki/Dash
[#2156]: https://gitlab.torproject.org/tpo/core/arti/-/issues/2156
