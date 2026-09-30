# Officially supported third-party integrations

> [!NOTE] Arti was designed to integrate with other libraries and tools.
> Typically, this involves writing some glue code that bridges between Arti and the external library.
> The crate that holds this glue code is referred to as an "Arti integration"

Here are the officially supported Arti integrations:

  * [x] [`arti-ureq`], for using Arti in combination with the [`ureq`] HTTP client
  * [ ] `arti-hyper` ([#2168])

If the integration you are looking for is missing from this list,
please open a ticket to bring it up for consideration.
Note, however, that not all third-party integrations
are suitable for inclusion in the Arti project.
Eligibility will be decided on a case by case basis;
a non-exhaustive list of criteria can be found below:

  * The integration should save the user a significant amount of work/code,
    or be necessary to protect against easy-to-get-wrong security/privacy issues.
    We don't want to maintain an integration for something that could easily be done
    by the library user.
  * The third-party library that we're integrating with should be somewhat stable.
    We don't want Arti's integration to break often, requiring extensive work from
    us.
  * The third-party library should be a good fit for the Tor ecosystem, and should
    be designed in a way that fits well with Arti.

Integrations that don't meet these criteria,
or that we are otherwise unable to include in the Arti project,
are best maintained as third-party integrations.

## Adding a new third-party integration

If we (the Arti team) accept a new user-facing Arti integration,
we are making a long-term commitment to the development and support of this integration.
We should, among the team members, ensure there is a rough consensus that we all want
to become familiar with this library and contribute to its Arti integration.
A good way to propose this to the rest of the team is by following the
["proposing big changes"][proposing-big-changes] guide.


[`arti-ureq`]: https://crates.io/crates/arti-ureq
[`ureq`]: https://crates.io/crates/ureq
[proposing-big-changes]: https://gitlab.torproject.org/tpo/core/arti/-/blob/main/doc/dev/ProposingBigChanges.md?ref_type=heads
[#2168]: https://gitlab.torproject.org/tpo/core/arti/-/work_items/2168
