//! Traits and common types for for calculating consensuses from votes

use super::*;

/// Voter number
///
/// Valid only within a particular consensus calculation round.
/// Corresponds to the index in `ConsensusesContext.votes`.
#[derive(Debug, Clone, Copy, Eq, PartialEq, Ord, PartialOrd, Hash)] //
#[derive(derive_more::From, derive_more::Into)]
pub(super) struct VoterNum(pub usize);

/// A set of voters
pub(super) type VoterSet = HashSet<VoterNum>;

/// Components within a vote (trait alias)
///
/// Input to [`ConsensusesFromVotes::consensuses`] and [`Aggregate::aggregate`].
pub(super) trait ComponentInVotes<T>: Iterator<Item = (VoterNum, T)> + Clone {}
impl<I, T> ComponentInVotes<T> for I where I: Iterator<Item = (VoterNum, T)> + Clone {}

/// Actual context for computing a field: global context, plus already-computed values
///
/// Shared references, so `Copy`.
#[derive(Debug, Educe, derive_more::Deref)]
#[educe(Clone, Copy)]
pub(super) struct ConsensusContextRefs<'r, AlreadyComputed> {
    /// The `ConsensusContext`, the same for all parts of the computation
    ///
    /// This is usually the part of the context that's wanted, so
    /// for convenience, `ContextAndComputed` derefs to this.
    #[deref]
    pub context: &'r ConsensusCommonContext<'r>,

    /// Stuff we computed earlier
    ///
    /// This is needed because some parts of the consensus depend on other parts.
    /// For example, the `w` item in a routerstatus depends on network parameters
    /// (as found in the preamble of *this* consensus).
    ///
    /// impls that don't need any precomputed data should be blanket over `AlreadyComputed`.
    //
    // The alternatives to this would be:
    //  a. Build the consensus in mutable variables.  But there are a lot of required
    //     fields, so that is quite awkward.
    //  b. Have some separate mutable variables in the context, and pass them mutably
    //     through all the calculations.
    //
    // Both a and b would make it easy to write the kind of "didn't assign to
    // this variable yet" ordering bugs which are common in languages and
    // progrms with mutable globals.
    //
    //  c. Do some kind of ad-hoc calculation beforehand, and put the answers in
    //     `context`.  The ad-hoc calculation couldn't use any of our infrastructure
    //     since that requires a `ConsensusContext` which we wouldn't have yet.
    //
    //  d. Put dummy data in the awkward fields, and fix it up later
    //     after the systematic calculation has produced a whole consensus.
    //     This makes it easy to accidentally use or emit uninitialised data,
    //     and is really a form of (a)/(b).
    //
    pub computed: &'r AlreadyComputed,
}

/// Component of a vote, from which a corresponding consensus component can be calculated
///
/// Implemented on the *input*, ie the vote or part of a vote.
///
/// Implement this trait directly when the different flavours need different outputs.
///
/// Implement [`Aggregate`] instead, if the flavour doesn't matter.
/// There is a blanket implementation of `ConsensusesFromVotes` for any [`Aggregate`].
pub(super) trait ConsensusesFromVotes<AlreadyComputed> {
    /// The plain-flavourconsensus component
    type PlainOutput: Sized;
    /// The microdescriptor consensus component
    type MdOutput: Sized;

    /// Calculate the consensus components corresponding to the `Self` in the votes
    ///
    /// Takes as input the vote components (one per vote), and
    /// returns the consensus components, as a pair, one for each flavour.
    ///
    /// `inputs` is an iterator of references to the relevant parts of each vote.
    fn consensuses<'i>(
        context: ConsensusContextRefs<AlreadyComputed>,
        inputs: impl ComponentInVotes<&'i Self>,
    ) -> Result<(Self::PlainOutput, Self::MdOutput), ConsensusError>
    where
        Self: 'i;
}

/// Component of a vote from which a flavour-independent consensus component can be calculated
///
/// Implemented on the *input*, ie the vote or part of a vote.
///
/// Use `[ConsensusesFromVotes`] when flavour is relevant.
pub(super) trait Aggregate<AC>: Sized {
    /// The output (consensus) component type.  Often `Self`.
    type Output: Sized;

    /// Calculate the consensus component corresponding to the `Self` in the votes
    ///
    /// Takes as input the vote components (one per vote), and
    /// returns the corresponding consensus components.
    ///
    /// `inputs` is an iterator of references to the relevant parts of each vote.
    fn aggregate<'i>(
        context: ConsensusContextRefs<AC>,
        inputs: impl ComponentInVotes<&'i Self>,
    ) -> Result<Self::Output, ConsensusError>
    where
        Self: 'i;
}

impl<AC, V: Aggregate<AC>> ConsensusesFromVotes<AC> for V {
    type PlainOutput = V::Output;
    type MdOutput = V::Output;

    fn consensuses<'i>(
        context: ConsensusContextRefs<AC>,
        inputs: impl ComponentInVotes<&'i Self>,
    ) -> Result<(Self::PlainOutput, Self::MdOutput), ConsensusError>
    where
        Self: 'i,
    {
        Ok((
            V::aggregate(context, inputs.clone())?,
            V::aggregate(context, inputs)?,
        ))
    }
}

/// Error during calculation of a consensus
///
/// Normally errors at this stage should be avoided, because that would prevent
/// us from participating in the consensus.
#[derive(thiserror::Error, Clone, Debug)]
#[non_exhaustive]
pub enum ConsensusError {
    /// Tried to calculate a consensus from no votes!
    #[error("tried to calculate a consensus from no votes!")]
    NoVotes,

    /// Internal error in calculation algorithm
    #[error("bug calculating a consensus")]
    Internal(#[from] Bug),
}

#[ext(name = TiSliceExt)]
pub(super) impl<V> TiSlice<VoterNum, V> {
    /// Get the value from one of the votes
    ///
    /// Convenience method for `.get(vnum)` which avoids recapitulating the error handling.
    //
    // TODO DIRAUTH after !4463 use this in toplevel.rs in
    //  impl<AC> Aggregate<AC> for netstatus::VoteAuthoritySection
    fn vote(&self, vnum: VoterNum) -> Result<&V, Bug> {
        self.get(vnum)
            .ok_or_else(|| internal!("{vnum:?} out of range"))
    }
}

/// "Global" inputs for calculating consensus from votes
#[derive(Debug, Clone)]
pub(super) struct ConsensusCommonContext<'r> {
    /// The consensus method for which to generate a consensus
    pub method: SupportedConsensusMethod,

    /// The number of authorities (>= the number of votes)
    pub n_authorities: usize,

    /// The input votes (in their entirity)
    pub votes: TiVec<VoterNum, &'r tor_netdoc::doc::netstatus::vote::NetworkStatus>,
}

impl<'r> ConsensusCommonContext<'r> {
    /// Is `n_some_voters` strictly more than half of all the authorities?
    pub(super) fn is_more_than_half_all_auths(&self, n_some_voters: usize) -> bool {
        // This way of writing it avoids any possibility of over/under-flow
        n_some_voters > self.n_authorities / 2
    }
}

#[cfg(test)]
pub(crate) mod test {
    // @@ begin test lint list maintained by maint/add_warning @@
    #![allow(clippy::bool_assert_comparison)]
    #![allow(clippy::clone_on_copy)]
    #![allow(clippy::dbg_macro)]
    #![allow(clippy::mixed_attributes_style)]
    #![allow(clippy::print_stderr)]
    #![allow(clippy::print_stdout)]
    #![allow(clippy::single_char_pattern)]
    #![allow(clippy::unwrap_used)]
    #![allow(clippy::unchecked_time_subtraction)]
    #![allow(clippy::useless_vec)]
    #![allow(clippy::needless_pass_by_value)]
    #![allow(clippy::string_slice)] // See arti#2571
    //! <!-- @@ end test lint list maintained by maint/add_warning @@ -->
    use super::*;

    impl ConsensusCommonContext<'static> {
        pub(crate) fn new_for_test() -> Self {
            // TODO obtain (memoised?) from testdata2, using its constructor, when we have one
            ConsensusCommonContext {
                method: SupportedConsensusMethod::MAX,
                n_authorities: 0,
                votes: ti_vec![],
            }
        }
    }

    #[test]
    fn is_more_than_half_all_auths() {
        let mut context = ConsensusCommonContext::new_for_test();

        let mut check = |n_authorities, minimum_that_is_more_than_half| {
            context.n_authorities = n_authorities;
            for t in 0..=(n_authorities + 1) {
                assert_eq!(
                    context.is_more_than_half_all_auths(t),
                    t >= minimum_that_is_more_than_half,
                );
            }
        };

        check(0, 1);
        check(1, 1);
        check(2, 2);
        check(3, 2);
        check(4, 3);
        check(5, 3);
    }
}
