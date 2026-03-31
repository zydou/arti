# Policy: "Big changes" in arti

Some changes in arti are "big", and require a rough team consensus.
These include:

 - Removing or deprecating functionality
 - Adding a substantial maintenance burden
 - Making an experimental feature stable
 - Breaking user-visible backward compatibility on the `arti` crate.
 - _Large_ breaks of backward compatibility on the `arti-client` crate
 - Large refactorings or architectural changes
 - Breaking network compatibility with existing Tor clients or relays

> Protocol changes aren't listed here; they should go through the regular
> tor-spec proposal process.

These categories are somewhat fuzzy,
and it will often require a judgment call to decide whether something is a
"big" change.
We will probably refine them over time.
We should resist the urge to clarify every possible case,
and instead try to use our best judgment.

"Big" changes require rough team consensus.
To get it, you can take the following steps:

1. Open a ticket about the issue.
If the issue is complex, discuss the pros and cons about it.

Some _possible_ questions to answer in a ticket where you propose stabilizing a
feature are:

 - [ ] What are the benefits of using this feature?
 - [ ] How well-tested is it?
 - [ ] How well does it work?  (How do we know?)
 - [ ] What are the risks if all our users start using it?
 - [ ] Who knows the code in question?
 - [ ] What security problems (if any) might this introduce?
 - [ ] Are we likely to want to make breaking changes in the UI for this feature?
 - [ ] What could we do to make us more confident in stabilizing this?
 - [ ] Does it make sense for this stablilized Cargo feature to remain a
   feature? Or should it simply be always-on?
 - [ ] Will users have the ability to disable the feature?
   (And do we want them to have the ability?)
 - [ ] If removing or breaking functionality, do existing users rely on this?
 - [ ] What users does this affect? (Relay users, client users, rpc users,
   etc.)
 - [ ] What is the maintenance overhead?
 - [ ] Where and how is this feature/functionality/process documented?
 - [ ] Does the feature follow a specification/proposal?
   If so, which, and is it fully implemented?

> Note 1: Some of these questions will apply to proposed changes
> that are _not_ feature stabilizations.
>
> Note 2: You are not required to answer all of these questions!
> It's okay to skip ones that are obviously not relevant.

These questions are useful not just for convincing the Arti team
to adopt this "big" change,
but also to get everyone "up to speed"
who hasn't been following along with this particular development,
and to preempt some common questions.

2. Raise the issue with the team.
The usual way is to ask people on IRC to comment on the ticket,
and to add the issue to the meeting pad for discussion at the next weekly meeting.

3. If the team reaches a rough consensus, great!  If not, look for other ways forward.


