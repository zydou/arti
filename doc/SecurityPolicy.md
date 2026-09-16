# Arti security policy

This is an interim policy.  We'll probably make it more formal as Arti becomes more mature.

**NOTE:** This security policy is not up-to-date.


## To report a security vulnerability

Just open a ticket on gitlab.  If you think that the vulnerability is
especially severe, you can mark it as confidential.

We'll provide more secure vulnerability reporting once Arti is more secure.


## What counts as a vulnerability?  How severe is it?

We incorporate the definition of security vulnerabilities from the
network team [SecurityPolicy](https://gitlab.torproject.org/tpo/core/team/-/wikis/NetworkTeam/SecurityPolicy).

We do not distinguish whether bugs occur in our upstream libraries or in Arti: only their effect on Arti users. However, this guarantee is weakened when Arti is used with upstream library versions that are different from those specified in our `Cargo.lock`, such as when Arti is embedded as a library itself. In this configuration, we will attempt to mitigate the impact of upstream vulnerabilities on a best-effort basis only.

We consider network-induced panics as low- or medium- severity security issues,
depending on their impact.

Panics caused by the user or by an embedding application are low-severity or
"not a bug".

We treat API weaknesses that _promote_ insecure usage of Arti as security
vulnerabilities.  It is not a security bug if an API weakness only _permits_
insecure usage of Arti.


## When do we assign identifiers to security vulnerabilities?

### TROVEs:

We only publish TROVEs for "stable" artifacts that can be built
(or are bundled in releases) from the Arti repository.
This means that we only publish TROVEs for arti,
and arti-relay/arti-dirauth in the future once they are stable.
If a vulnerability in a lower-level crate is not exploitable in these artifacts,
then we do not publish a TROVE.
We do not publish TROVEs for issues that require enabling experimental
features.

Past examples: <https://gitlab.torproject.org/tpo/core/team/-/wikis/NetworkTeam/TROVE>

### RustSec advisories:

We publish RustSec advisories for issues in any published crate we deem
to have "high" or "critical" severity according to our
[TROVE guidelines](https://gitlab.torproject.org/tpo/core/team/-/wikis/NetworkTeam/SecurityPolicy#how-will-the-developers-handle-security-issues).
For consistency, we use these TROVE guidelines to determine the severity
even if we're not publishing a TROVE.
We do not publish RustSec advisories for issues that require enabling
experimental features.

This means that "medium" and lower severity security issues are not documented
or published anywhere outside of the issue tracker.

If third parties wish to publish RustSec advisories for our crates for less-serious issues,
we will review them for accuracy,
participating in the RustSec review process (currently, GitHub MR review).

Past examples: <https://rustsec.org/packages/tor-circmgr.html>

### CVEs:

We do not apply for CVEs for any Arti security issues.


## How will we track vulnerabilities?

Vulnerabilities are tracked in Tor's
[TROVE list](https://gitlab.torproject.org/tpo/core/team/-/wikis/NetworkTeam/TROVE).

## How will we respond to vulnerabilities?

Until Arti is at release 1.0.0, we will treat every vulnerability of severity
less than "high" as non-confidential, and solve it in the open.  We'll put
out releases around once a month.  We will do the same for "high"-severity
issues that we think aren't likely to cause immediate harm.

For any "high"-level severity issues that seem likely to cause immediate
harm if not fixed, and for all "critical"-level vulnerabilities, we will try
to fix them in private, and put out a release as soon as seems practical.

We do not plan to backport any security fixes.

We'll announce any such issues **TODO Where**?
