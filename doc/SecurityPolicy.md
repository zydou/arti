# Arti security policy

This is an interim policy.  We'll probably make it more formal as Arti becomes more mature.


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

## How will we track vulnerabilities?

*TBD whether we will use TROVE, or whether we will have a separate repository
for each tool.  But we will do something like that.*

## How will we respond to vulnerabilities?

Until Arti is at release 1.0.0, we will treat every vulnerability of severity
less than "high" as non-confidential, and solve it in the open.  We'll put
out releases around once a month.  We will do the same for "high"-severity
issues that we think aren't likely to cause immediate harm.

For any "high"-level severity issues that seem likely to cause immediate
harm if not fixed, and for all "critical"-level vulnerabilities, we will try
to fix them in private, and put out a release as soon as seems practical.

We do not plan to backport any security fixes until Arti 1.0.0 is out: only
the most recent API revision will get security fixes.

We'll announce any such issues **XXXX Where**?

## Issues so far

(We'll move this list once we have a better registry.)

 * The link handshake validation issue we fixed with 11cd138c7488a4660a75e932f9ebb992002e70de.  I believe it predates the actual use of an issue tracker for Arti.
 * The [environment-related bug](https://rustsec.org/advisories/RUSTSEC-2020-0159) in chrono that caused us to migrate to time.
 * The [string-slicing bug](https://github.com/acw/simple_asn1/pull/28) in `simple_asn1`.
 * Boolean inversion in `auth_sendme_optional` (#294).
