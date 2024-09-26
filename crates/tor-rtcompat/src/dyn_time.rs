//! type-erased time provider

use std::future::Future;
use std::mem::{self, MaybeUninit};
use std::pin::Pin;
use std::time::{Duration, Instant, SystemTime};

use dyn_clone::DynClone;
use educe::Educe;
use paste::paste;

use crate::{CoarseInstant, CoarseTimeProvider, SleepProvider};

//-------------------- handle PreferredRuntime maybe not existing ----------

// TODO use this more widely, eg in tor-rtcompat/lib.rs

/// See the other implementation
#[allow(unused_macros)] // Will be redefined if there *is* a preferred runtime
macro_rules! if_preferred_runtime {{ [$($y:tt)*] [$($n:tt)*] } => { $($n)* }}
#[cfg(all(
    any(feature = "native-tls", feature = "rustls"),
    any(feature = "async-std", feature = "tokio")
))]
/// `if_preferred_runtime!{[ Y ] [ N ]}` expands to `Y` (if there's `PreferredRuntime`) or `N`
macro_rules! if_preferred_runtime {{ [$($y:tt)*] [$($n:tt)*] } => { $($y)* }}

if_preferred_runtime! {[
    use crate::PreferredRuntime;
] [
    /// Dummy value that makes the variant uninhabited
    #[derive(Clone, Debug)]
    enum PreferredRuntime {}
]}
/// `with_preferred_runtime!( R; EXPR )` expands to `EXPR`, or to `match *R {}`.
macro_rules! with_preferred_runtime {{ $p:ident; $($then:tt)* } => {
    if_preferred_runtime!([ $($then)* ] [ match *$p {} ])
}}

//---------- principal types ----------

/// Convenience alias for a boxed sleep future
type DynSleepFuture = Pin<Box<dyn Future<Output = ()> + Send + 'static>>;

/// Object-safe version of `SleepProvider` and `CoarseTimeProvider`
///
/// The methods mirror those in `SleepProvider` and `CoarseTimeProvider`
#[allow(clippy::missing_docs_in_private_items)]
trait DynProvider: DynClone + Send + Sync + 'static {
    // SleepProvider principal methods
    fn dyn_now(&self) -> Instant;
    fn dyn_wallclock(&self) -> SystemTime;
    fn dyn_sleep(&self, duration: Duration) -> DynSleepFuture;

    // SleepProvider testing stuff
    fn dyn_block_advance(&self, reason: String);
    fn dyn_release_advance(&self, _reason: String);
    fn dyn_allow_one_advance(&self, duration: Duration);

    // CoarseTimeProvider
    fn dyn_now_coarse(&self) -> CoarseInstant;
}

dyn_clone::clone_trait_object!(DynProvider);

/// Type-erased `SleepProvider` and `CoarseTimeProvider`
///
/// Useful where time is needed, but we don't want a runtime type parameter.
#[derive(Clone, Debug)]
pub struct DynTimeProvider(Impl);

/// Actual contents of a `DynTimeProvider`
///
/// We optimise the `PreferredRuntime` case
#[derive(Clone, Educe)]
#[educe(Debug)]
enum Impl {
    /// Just (a handle to) the preferred runtime
    Preferred(PreferredRuntime),
    /// Some other runtime
    Dyn(#[educe(Debug(ignore))] Box<dyn DynProvider>),
}

impl DynTimeProvider {
    /// Create a new `DynTimeProvider` from a concrete runtime type
    pub fn new<R: SleepProvider + CoarseTimeProvider>(runtime: R) -> Self {
        let imp = match downcast_value(runtime) {
            Ok(preferred) => Impl::Preferred(preferred),
            Err(other) => Impl::Dyn(Box::new(other) as _),
        };
        DynTimeProvider(imp)
    }
}

//---------- impl DynProvider for any SleepProvider + CoarseTimeProvider ----------

/// Define ordinary methods in `impl DynProvider`
///
/// This macro exists mostly to avoid copypaste mistakes where we (for example)
/// implement `block_advance` by calling `release_advance`.
macro_rules! dyn_impl_methods { { $(
    fn $name:ident(
        ,
        $( $param:ident: $ptype:ty ),*
    ) -> $ret:ty;
)* } => { paste! { $(
    fn [<dyn_ $name>](
        &self,
        $( $param: $ptype, )*
    )-> $ret {
        self.$name( $($param,)* )
    }
)* } } }

impl<R: SleepProvider + CoarseTimeProvider> DynProvider for R {
    dyn_impl_methods! {
        fn now(,) -> Instant;
        fn wallclock(,) -> SystemTime;

        fn block_advance(, reason: String) -> ();
        fn release_advance(, reason: String) -> ();
        fn allow_one_advance(, duration: Duration) -> ();

        fn now_coarse(,) -> CoarseInstant;
    }

    fn dyn_sleep(&self, duration: Duration) -> DynSleepFuture {
        Box::pin(self.sleep(duration))
    }
}

//---------- impl SleepProvider and CoarseTimeProvider for DynTimeProvider ----------

/// Define ordinary methods in `impl .. for DynTimeProvider`
///
/// This macro exists mostly to avoid copypaste mistakes where we (for example)
/// implement `block_advance` by calling `release_advance`.
macro_rules! pub_impl_methods { { $(
    fn $name:ident $( [ $($generics:tt)* ] )? (
        ,
        $( $param:ident: $ptype:ty ),*
    ) -> $ret:ty;
)* } => { paste! { $(
    fn $name $( < $($generics)* > )?(
        &self,
        $( $param: $ptype, )*
    )-> $ret {
        match &self.0 {
            Impl::Preferred(p) => with_preferred_runtime!(p; p.$name( $($param,)* )),
            Impl::Dyn(p) => p.[<dyn_ $name>]( $($param .into() ,)? ),
        }
    }
)* } } }

impl SleepProvider for DynTimeProvider {
    pub_impl_methods! {
        fn now(,) -> Instant;
        fn wallclock(,) -> SystemTime;

        fn block_advance[R: Into<String>](, reason: R) -> ();
        fn release_advance[R: Into<String>](, reason: R) -> ();
        fn allow_one_advance(, duration: Duration) -> ();
    }

    type SleepFuture = DynSleepFuture;

    fn sleep(&self, duration: Duration) -> DynSleepFuture {
        match &self.0 {
            Impl::Preferred(p) => with_preferred_runtime!(p; Box::pin(p.sleep(duration))),
            Impl::Dyn(p) => p.dyn_sleep(duration),
        }
    }
}

impl CoarseTimeProvider for DynTimeProvider {
    pub_impl_methods! {
        fn now_coarse(,) -> CoarseInstant;
    }
}

//---------- downcast_value ----------

// TODO expose this, maybe in tor-basic-utils ?

/// Try to cast `I` (which is presumably a TAIT) to `O` (presumably a concrete type)
///
/// We use runtime casting, but typically the answer is known at compile time.
///
/// Astonishingly, this isn't in any of the following:
///  * `std`
///  * `match-downcast`
///  * `better_any` (`downcast:move` comes close but doesn't give you your `self` back)
///  * `castaway`
///  * `mopa`
///  * `as_any`
fn downcast_value<I: std::any::Any, O: Sized + 'static>(input: I) -> Result<O, I> {
    let mut input = MaybeUninit::new(input);
    // SAFETY: the MaybeUninit is initialised just above
    let mut_ref: &mut I = unsafe { input.assume_init_mut() };
    match <dyn std::any::Any>::downcast_mut(mut_ref) {
        Some::<&mut O>(output) => {
            let output = output as *mut O;
            // SAFETY:
            //  output is properly aligned and points to a properly initialised
            //    O, because it came from a mut reference
            //  Reading this *invalidates* the MaybeUninit, since the value isn't Copy.
            //  It also invalidates mut_ref, which we therefore mustn't use again.
            let output: O = unsafe { output.read() };
            // Prove that the MaybeUninit is live up to here, and then isn't used any more
            #[allow(clippy::drop_non_drop)] // Yes, we know
            mem::drop::<MaybeUninit<I>>(input);
            Ok(output)
        }
        None => Err(
            // SAFETY: Indeed, it was just initialised, and downcast_mut didn't change that
            unsafe { input.assume_init() },
        ),
    }
}

#[test]
#[allow(clippy::unwrap_used, clippy::useless_format)]
fn check_downcast_value() {
    use std::fmt::{Debug, Display};
    use std::hint::black_box;

    fn chk(x: impl Display + Debug + 'static) -> Result<String, impl Display + Debug + 'static> {
        black_box(downcast_value(black_box(x)))
    }

    assert_eq!(chk(format!("hi")).unwrap(), format!("hi"));
    assert_eq!(chk("hi").unwrap_err().to_string(), "hi");
}
