# Arti, Rust, LGPL section 4d compliance, and you

As of 2024 May, Arti can (but is not required to) link against
certain crates licenced under the
GNU Lesser General Public License version 3.0 ([LGPL]).
These crates are [`hashx`] and [`equix`].

This document explains some issues that you should be aware of
if you want to ship binaries that use these crates,
that come about due to the interactions
of the Rust build system with the LGPL.

If you are just a user of Arti,
and you aren't distributing software,
you don't need to worry about any of this.

## WARNING!

We are not lawyers and this is not legal advice.
Although this represents our current understanding
of the compliance issues at stake,
you should not take this document as a substitute
for actually reading and understanding
the relevant licenses and laws.

This is our attempt to make you aware
of some issues that you may face.
It is not a license,
or an amendment to any license.

Most of Arti is under licenses other than those discussed here;
this document does not free you of your obligation to follow those licenses.

## Your more difficult obligations, in summary

Briefly and approximately:

If you ship an application that includes an LGPL-licensed library,
you need to give your users the ability to replace that library
with a different or modified version.
This requirement is in section 4.d of the [LGPL].

But Rust builds applications and libraries as static binaries,
and does not make it easy to replaces their constituent crates once
they have been built.
So the option of section 4.d.1 of the [LGPL] is not typically available.

Therefore,
if you are shipping binaries that are based on Arti,
your easiest options are:

1. Do not include the LGPL-licensed code.
2. Conform with section 4.d.0 of the [LGPL] by giving
   your users all the source code necessary to build your
   application.
   Not just any way of making this code available is okay:
   you need to conform with section 6 of the [GPL].
   Free software developers will generally find
   section 6.d of the GPL easiest to follow.

(Note that if you're shipping LGPL-licensed code,
you also have other obligations
with respect to giving notice
and displaying the appropriate copyright statements.
See section 4 of the [LGPL].
Note also that the LGPL frees you from
some but not all of your obligations under the full [GPL];
make sure you are aware of the requirements that the [LGPL]
does not relax.)

## What if I want to ship arti with LGPL code in a closed-source binary?

With some engineering,
you could probably make it possible to link [`equix`]
into arti as a shared library.

We have no plans to work on this.


[`hashx`]: https://gitlab.torproject.org/tpo/core/arti/-/tree/main/crates/hashx?ref_type=heads
[`equix`]: https://gitlab.torproject.org/tpo/core/arti/-/tree/main/crates/equix?ref_type=heads
[GPL]: https://www.gnu.org/licenses/gpl-3.0.html
[LGPL]: https://www.gnu.org/licenses/lgpl-3.0.en.html
