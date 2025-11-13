//! Types related to stream isolation
use downcast_rs::{Downcast, impl_downcast};
use dyn_clone::{DynClone, clone_trait_object};
use std::sync::atomic::{AtomicU64, Ordering};

/// A type that can make isolation decisions about streams it is attached to.
///
/// Types that implement `Isolation` contain properties about a stream that are
/// used to make decisions about whether that stream can share the same circuit
/// as other streams. You may pass in any type implementing `Isolation` when
/// creating a stream via `TorClient::connect_with_prefs`, or constructing a
/// circuit with [`CircMgr::get_or_launch_exit()`](crate::CircMgr::get_or_launch_exit).
///
/// You typically do not want to implement this trait directly.  Instead, most
/// users should implement [`IsolationHelper`].
pub trait Isolation:
    seal::Sealed + Downcast + DynClone + std::fmt::Debug + Send + Sync + 'static
{
    /// Return true if this Isolation is compatible with another.
    ///
    /// Two streams may share a circuit if and only if they have compatible
    /// `Isolation`s.
    ///
    /// # Requirements
    ///
    /// For correctness, this relation must be symmetrical and reflexive:
    /// `self.compatible(other)` must equal `other.compatible(self)`, and
    /// `self.compatible(self)` must be true.
    ///
    /// For correctness, this function must always give the same result as
    /// `self.join(other).is_some()`.
    ///
    /// This relationship does **not** have to be transitive: it's possible that
    /// stream A can share a circuit with either stream B or stream C, but not
    /// with both.
    fn compatible(&self, other: &dyn Isolation) -> bool;

    /// Join two [`Isolation`] into the intersection of what each allows.
    ///
    /// A circuit's isolation is the `join` of the isolation values of all of
    /// the streams that have _ever_ used that circuit.  A circuit's isolation
    /// can never be `None`: streams that would cause it to be `None` can't be
    /// attached to the circuit.
    ///
    /// When a stream is added to a circuit, `join` is used to calculate the
    /// circuit's new isolation.
    ///
    /// # Requirements
    ///
    /// For correctness, this function must be commutative: `self.join(other)`
    /// must equal `other.join(self)`.  Also, it must be idempotent:
    /// `self.join(self)` must equal self.
    //
    // TODO: (This function probably should be associative too, but we haven't done
    // all the math.)
    fn join(&self, other: &dyn Isolation) -> Option<Box<dyn Isolation>>;

    /// Return true if this `Isolation` object should be considered sufficiently strong
    /// as to enable long-lived circuits.
    ///
    /// By default, once a circuit has been in use for long enough,
    /// it is considered no longer usable for new circuits.
    /// But if the circuit's isolation is sufficiently strong
    /// (and this method returns true)
    /// then a circuit will keep being used for new streams indefinitely.
    ///
    /// The default implementation of this method returns false.
    fn enables_long_lived_circuits(&self) -> bool {
        false
    }
}

/// Seal preventing implementation of Isolation not relying on IsolationHelper
mod seal {
    /// Seal preventing implementation of Isolation not relying on IsolationHelper
    pub trait Sealed {}
    impl<T: super::IsolationHelper> Sealed for T {}
}

impl_downcast!(Isolation);
clone_trait_object!(Isolation);
impl<T: Isolation> From<T> for Box<dyn Isolation> {
    fn from(isolation: T) -> Self {
        Box::new(isolation)
    }
}

impl<T: IsolationHelper + Clone + std::fmt::Debug + Send + Sync + 'static> Isolation for T {
    fn compatible(&self, other: &dyn Isolation) -> bool {
        if let Some(other) = other.as_any().downcast_ref() {
            self.compatible_same_type(other)
        } else {
            false
        }
    }

    fn join(&self, other: &dyn Isolation) -> Option<Box<dyn Isolation>> {
        if let Some(other) = other.as_any().downcast_ref() {
            self.join_same_type(other)
                .map(|res| Box::new(res) as Box<dyn Isolation>)
        } else {
            None
        }
    }

    fn enables_long_lived_circuits(&self) -> bool {
        IsolationHelper::enables_long_lived_circuits(self)
    }
}

/// Trait to help implement [`Isolation`].
///
/// You should generally implement this trait whenever you need to implement a
/// new set of stream isolation rules: it takes care of down-casting and type
/// checking for you.
///
/// When you implement this trait for some type T, isolation objects of that
/// type will be incompatible (unable to share circuits) with objects of _any
/// other type_.  (That's usually what you want; if you're defining a new type
/// of Isolation rules, then you probably don't want streams using different
/// rules to share circuits with yours.)
pub trait IsolationHelper: Sized {
    /// Returns whether self and other are compatible.
    ///
    /// Two streams may share a circuit if and only if they have compatible
    /// `Isolation`s.
    ///
    /// (See [`Isolation::compatible`] for more information and requirements.)
    fn compatible_same_type(&self, other: &Self) -> bool;

    /// Join self and other into the intersection of what they allows.
    ///
    /// (See [`Isolation::join`] for more information and requirements.)
    fn join_same_type(&self, other: &Self) -> Option<Self>;

    /// Return true if this `Isolation` object should be considered sufficiently strong
    /// as to permit long-lived circuits.
    ///
    /// (See [`Isolation::enables_long_lived_circuits`] for more information.)
    fn enables_long_lived_circuits(&self) -> bool {
        false
    }
}

/// A token used to isolate unrelated streams on different circuits.
///
/// When two streams are associated with different isolation tokens, they
/// can never share the same circuit.
///
/// Tokens created with [`IsolationToken::new`] are all different from
/// one another, and different from tokens created with
/// [`IsolationToken::no_isolation`]. However, tokens created with
/// [`IsolationToken::no_isolation`] are all equal to one another.
///
/// # Examples
///
/// Creating distinct isolation tokens:
///
/// ```rust
/// # use tor_circmgr::IsolationToken;
/// let token_1 = IsolationToken::new();
/// let token_2 = IsolationToken::new();
///
/// assert_ne!(token_1, token_2);
///
/// // Demonstrating the behaviour of no_isolation() tokens:
/// assert_ne!(token_1, IsolationToken::no_isolation());
/// assert_eq!(IsolationToken::no_isolation(), IsolationToken::no_isolation());
/// ```
///
/// Using an isolation token to route streams differently over the Tor network:
///
/// ```ignore
/// use arti_client::StreamPrefs;
///
/// let token_1 = IsolationToken::new();
/// let token_2 = IsolationToken::new();
///
/// let mut prefs_1 = StreamPrefs::new();
/// prefs_1.set_isolation(token_1);
///
/// let mut prefs_2 = StreamPrefs::new();
/// prefs_2.set_isolation(token_2);
///
/// // These two connections will come from different source IP addresses.
/// tor_client.connect(("example.com", 80), Some(prefs_1)).await?;
/// tor_client.connect(("example.com", 80), Some(prefs_2)).await?;
/// ```
// # Semver note
//
// This type is re-exported by `arti-client`: any changes to it must be
// reflected in `arti-client`'s version.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct IsolationToken(u64);

#[allow(clippy::new_without_default)]
impl IsolationToken {
    /// Create a new IsolationToken, unequal to any other token this function
    /// has created.
    ///
    /// # Panics
    ///
    /// Panics if we have already allocated 2^64 isolation tokens: in that
    /// case, we have exhausted the space of possible tokens, and it is
    /// no longer possible to ensure isolation.
    pub fn new() -> Self {
        /// Internal counter used to generate different tokens each time
        static COUNTER: AtomicU64 = AtomicU64::new(1);
        // Ordering::Relaxed is fine because we don't care about causality, we just want a
        // different number each time
        let token = COUNTER.fetch_add(1, Ordering::Relaxed);
        assert!(token < u64::MAX);
        IsolationToken(token)
    }

    /// Create a new IsolationToken equal to every other token created
    /// with this function, but different from all tokens created with
    /// `new`.
    ///
    /// This can be used when no isolation is wanted for some streams.
    pub fn no_isolation() -> Self {
        IsolationToken(0)
    }
}

impl IsolationHelper for IsolationToken {
    fn compatible_same_type(&self, other: &Self) -> bool {
        self == other
    }
    fn join_same_type(&self, other: &Self) -> Option<Self> {
        if self.compatible_same_type(other) {
            Some(*self)
        } else {
            None
        }
    }

    fn enables_long_lived_circuits(&self) -> bool {
        false
    }
}

/// Helper macro to implement IsolationHelper for tuple of IsolationHelper
macro_rules! tuple_impls {
    ($(
        $Tuple:ident {
            $(($idx:tt) -> $T:ident)+
        }
    )+) => {
        $(
            impl<$($T:IsolationHelper),+> IsolationHelper for ($($T,)+) {
                fn compatible_same_type(&self, other: &Self) -> bool {
                    $(self.$idx.compatible_same_type(&other.$idx))&&+
                }

                fn join_same_type(&self, other: &Self) -> Option<Self> {
                    Some((
                    $(self.$idx.join_same_type(&other.$idx)?,)+
                    ))
                }

                fn enables_long_lived_circuits(&self) -> bool {
                    $(self.$idx.enables_long_lived_circuits() || )+ false
                }
            }
        )+
    }
}

tuple_impls! {
    Tuple1 {
        (0) -> A
    }
    Tuple2 {
        (0) -> A
        (1) -> B
    }
    Tuple3 {
        (0) -> A
        (1) -> B
        (2) -> C
    }
    Tuple4 {
        (0) -> A
        (1) -> B
        (2) -> C
        (3) -> D
    }
    Tuple5 {
        (0) -> A
        (1) -> B
        (2) -> C
        (3) -> D
        (4) -> E
    }
    Tuple6 {
        (0) -> A
        (1) -> B
        (2) -> C
        (3) -> D
        (4) -> E
        (5) -> F
    }
    Tuple7 {
        (0) -> A
        (1) -> B
        (2) -> C
        (3) -> D
        (4) -> E
        (5) -> F
        (6) -> G
    }
    Tuple8 {
        (0) -> A
        (1) -> B
        (2) -> C
        (3) -> D
        (4) -> E
        (5) -> F
        (6) -> G
        (7) -> H
    }
    Tuple9 {
        (0) -> A
        (1) -> B
        (2) -> C
        (3) -> D
        (4) -> E
        (5) -> F
        (6) -> G
        (7) -> H
        (8) -> I
    }
    Tuple10 {
        (0) -> A
        (1) -> B
        (2) -> C
        (3) -> D
        (4) -> E
        (5) -> F
        (6) -> G
        (7) -> H
        (8) -> I
        (9) -> J
    }
    Tuple11 {
        (0) -> A
        (1) -> B
        (2) -> C
        (3) -> D
        (4) -> E
        (5) -> F
        (6) -> G
        (7) -> H
        (8) -> I
        (9) -> J
        (10) -> K
    }
    Tuple12 {
        (0) -> A
        (1) -> B
        (2) -> C
        (3) -> D
        (4) -> E
        (5) -> F
        (6) -> G
        (7) -> H
        (8) -> I
        (9) -> J
        (10) -> K
        (11) -> L
    }
}

/// A set of information about how a stream should be isolated.
///
/// If two streams are isolated from one another, they may not share
/// a circuit.
#[derive(Clone, Debug, derive_builder::Builder)]
pub struct StreamIsolation {
    /// Any isolation set on the stream.
    #[builder(default = "Box::new(IsolationToken::no_isolation())")]
    stream_isolation: Box<dyn Isolation>,
    /// Any additional isolation token set on an object that "owns" this
    /// stream.  This is typically owned by a `TorClient`.
    #[builder(default = "IsolationToken::no_isolation()")]
    owner_token: IsolationToken,
}

impl StreamIsolation {
    /// Construct a new StreamIsolation with no isolation enabled.
    pub fn no_isolation() -> Self {
        StreamIsolationBuilder::new()
            .build()
            .expect("Bug constructing StreamIsolation")
    }

    /// Return a new StreamIsolationBuilder for constructing
    /// StreamIsolation objects.
    pub fn builder() -> StreamIsolationBuilder {
        StreamIsolationBuilder::new()
    }
}

impl IsolationHelper for StreamIsolation {
    fn compatible_same_type(&self, other: &StreamIsolation) -> bool {
        self.owner_token == other.owner_token
            && self
                .stream_isolation
                .compatible(other.stream_isolation.as_ref())
    }

    fn join_same_type(&self, other: &StreamIsolation) -> Option<StreamIsolation> {
        if self.owner_token != other.owner_token {
            return None;
        }
        self.stream_isolation
            .join(other.stream_isolation.as_ref())
            .map(|stream_isolation| StreamIsolation {
                stream_isolation,
                owner_token: self.owner_token,
            })
    }

    fn enables_long_lived_circuits(&self) -> bool {
        self.stream_isolation.enables_long_lived_circuits()
    }
}

impl StreamIsolationBuilder {
    /// Construct a builder with no items set.
    pub fn new() -> Self {
        StreamIsolationBuilder::default()
    }
}

#[cfg(test)]
pub(crate) mod test {
    #![allow(clippy::unwrap_used)]
    use super::*;

    /// Trait for testing use only. Much like PartialEq, but for type containing an dyn Isolation
    /// which is known to be an IsolationToken.
    pub(crate) trait IsolationTokenEq {
        /// Compare two values, returning true if they are equals and all dyn Isolation they contain
        /// are IsolationToken (which are equal too).
        fn isol_eq(&self, other: &Self) -> bool;
    }

    macro_rules! assert_isoleq {
        { $arg1:expr, $arg2:expr } => {
            assert!($arg1.isol_eq(&$arg2))
        }
    }
    pub(crate) use assert_isoleq;

    impl IsolationTokenEq for IsolationToken {
        fn isol_eq(&self, other: &Self) -> bool {
            self == other
        }
    }

    impl<T: IsolationTokenEq> IsolationTokenEq for Option<T> {
        fn isol_eq(&self, other: &Self) -> bool {
            match (self, other) {
                (Some(this), Some(other)) => this.isol_eq(other),
                (None, None) => true,
                _ => false,
            }
        }
    }

    impl<T: IsolationTokenEq + std::fmt::Debug> IsolationTokenEq for Vec<T> {
        fn isol_eq(&self, other: &Self) -> bool {
            if self.len() != other.len() {
                return false;
            }
            self.iter()
                .zip(other.iter())
                .all(|(this, other)| this.isol_eq(other))
        }
    }

    impl IsolationTokenEq for dyn Isolation {
        fn isol_eq(&self, other: &Self) -> bool {
            let this = self.as_any().downcast_ref::<IsolationToken>();
            let other = other.as_any().downcast_ref::<IsolationToken>();
            match (this, other) {
                (Some(this), Some(other)) => this == other,
                _ => false,
            }
        }
    }

    impl IsolationTokenEq for StreamIsolation {
        fn isol_eq(&self, other: &Self) -> bool {
            self.stream_isolation
                .isol_eq(other.stream_isolation.as_ref())
                && self.owner_token == other.owner_token
        }
    }

    #[derive(PartialEq, Clone, Copy, Debug, Eq)]
    struct OtherIsolation(usize);

    impl IsolationHelper for OtherIsolation {
        fn compatible_same_type(&self, other: &Self) -> bool {
            self == other
        }
        fn join_same_type(&self, other: &Self) -> Option<Self> {
            if self.compatible_same_type(other) {
                Some(*self)
            } else {
                None
            }
        }
    }

    #[test]
    fn isolation_token() {
        let token_1 = IsolationToken::new();
        let token_2 = IsolationToken::new();

        assert!(token_1.compatible_same_type(&token_1));
        assert!(token_2.compatible_same_type(&token_2));
        assert!(!token_1.compatible_same_type(&token_2));

        assert_eq!(token_1.join_same_type(&token_1), Some(token_1));
        assert_eq!(token_2.join_same_type(&token_2), Some(token_2));
        assert_eq!(token_1.join_same_type(&token_2), None);
    }

    #[test]
    fn isolation_trait() {
        let token_1: Box<dyn Isolation> = Box::new(IsolationToken::new());
        let token_2: Box<dyn Isolation> = Box::new(IsolationToken::new());
        let other_1: Box<dyn Isolation> = Box::new(OtherIsolation(0));
        let other_2: Box<dyn Isolation> = Box::new(OtherIsolation(1));

        assert!(token_1.compatible(token_1.as_ref()));
        assert!(token_2.compatible(token_2.as_ref()));
        assert!(!token_1.compatible(token_2.as_ref()));

        assert!(other_1.compatible(other_1.as_ref()));
        assert!(other_2.compatible(other_2.as_ref()));
        assert!(!other_1.compatible(other_2.as_ref()));

        assert!(!token_1.compatible(other_1.as_ref()));
        assert!(!other_1.compatible(token_1.as_ref()));

        assert!(token_1.join(token_1.as_ref()).is_some());
        assert!(token_1.join(token_2.as_ref()).is_none());

        assert!(other_1.join(other_1.as_ref()).is_some());
        assert!(other_1.join(other_2.as_ref()).is_none());

        assert!(token_1.join(other_1.as_ref()).is_none());
        assert!(other_1.join(token_1.as_ref()).is_none());
    }

    #[test]
    fn isolation_tuple() {
        let token_1 = IsolationToken::new();
        let token_2 = IsolationToken::new();
        let other_1 = OtherIsolation(0);
        let other_2 = OtherIsolation(1);

        let token_12: Box<dyn Isolation> = Box::new((token_1, token_2));
        let token_21: Box<dyn Isolation> = Box::new((token_2, token_1));
        let mix_11: Box<dyn Isolation> = Box::new((token_1, other_1));
        let mix_12: Box<dyn Isolation> = Box::new((token_1, other_2));
        let revmix_11: Box<dyn Isolation> = Box::new((other_1, token_1));

        let join_token = token_12.join(token_12.as_ref()).unwrap();
        assert!(join_token.compatible(token_12.as_ref()));
        let join_mix = mix_12.join(mix_12.as_ref()).unwrap();
        assert!(join_mix.compatible(mix_12.as_ref()));

        let isol_list = [token_12, token_21, mix_11, mix_12, revmix_11];

        for (i, isol1) in isol_list.iter().enumerate() {
            for (j, isol2) in isol_list.iter().enumerate() {
                assert_eq!(isol1.compatible(isol2.as_ref()), i == j);
            }
        }
    }

    #[test]
    fn build_isolation() {
        let no_isolation = StreamIsolation::no_isolation();
        let no_isolation2 = StreamIsolation::builder()
            .owner_token(IsolationToken::no_isolation())
            .stream_isolation(Box::new(IsolationToken::no_isolation()))
            .build()
            .unwrap();
        assert_eq!(no_isolation.owner_token, no_isolation2.owner_token);
        assert_eq!(
            no_isolation
                .stream_isolation
                .as_ref()
                .as_any()
                .downcast_ref::<IsolationToken>(),
            no_isolation2
                .stream_isolation
                .as_ref()
                .as_any()
                .downcast_ref::<IsolationToken>()
        );
        assert!(no_isolation.compatible(&no_isolation2));

        let tok = IsolationToken::new();
        let some_isolation = StreamIsolation::builder().owner_token(tok).build().unwrap();
        let some_isolation2 = StreamIsolation::builder()
            .stream_isolation(Box::new(tok))
            .build()
            .unwrap();
        assert!(!no_isolation.compatible(&some_isolation));
        assert!(!no_isolation.compatible(&some_isolation2));
        assert!(!some_isolation.compatible(&some_isolation2));
        assert!(some_isolation.compatible(&some_isolation));
    }
}
