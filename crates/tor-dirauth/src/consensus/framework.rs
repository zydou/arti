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

/// Component of a vote, from which a corresponding consensus component can be calculated
///
/// Implemented on the *input*, ie the vote or part of a vote.
///
/// Implement this trait directly when the different flavours need different outputs.
///
/// Implement [`Aggregate`] instead, if the flavour doesn't matter.
/// There is a blanket implementation of `ConsensusesFromVotes` for any [`Aggregate`].
pub(super) trait ConsensusesFromVotes {
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
        context: &ConsensusContext,
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
pub(super) trait Aggregate: Sized {
    /// The output (consensus) component type.  Often `Self`.
    type Output: Sized;

    /// Calculate the consensus component corresponding to the `Self` in the votes
    ///
    /// Takes as input the vote components (one per vote), and
    /// returns the corresponding consensus components.
    ///
    /// `inputs` is an iterator of references to the relevant parts of each vote.
    fn aggregate<'i>(
        context: &ConsensusContext,
        inputs: impl ComponentInVotes<&'i Self>,
    ) -> Result<Self::Output, ConsensusError>
    where
        Self: 'i;
}

impl<V: Aggregate> ConsensusesFromVotes for V {
    type PlainOutput = V::Output;
    type MdOutput = V::Output;

    fn consensuses<'i>(
        context: &ConsensusContext,
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

/// "Global" inputs for calculating consensus from votes
pub(super) struct ConsensusContext {
    /// The consensus method for which to generate a consensus
    pub(super) method: SupportedConsensusMethod,

    /// The number of authorities (>= the number of votes)
    pub(super) n_authorities: usize,

    /// The input votes (in their entirity)
    pub(super) votes: TiVec<VoterNum, tor_netdoc::doc::netstatus::vote::NetworkStatus>,

    /// Which of the votes came from bandwidth authorities
    pub(super) bandwidth_authorities: VoterSet,
}

impl ConsensusContext {
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

    impl ConsensusContext {
        pub(crate) fn new_for_test() -> Self {
            // TODO obtain (memoised?) from testdata2, using its constructor, when we have one
            ConsensusContext {
                method: SupportedConsensusMethod::MAX,
                n_authorities: 0,
                votes: ti_vec![],
                bandwidth_authorities: VoterSet::default(),
            }
        }
    }

    #[test]
    fn is_more_than_half_all_auths() {
        let mut context = ConsensusContext::new_for_test();

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
