//! Declaration for an n-keyed list type, allowing access to each of its members by each of N
//! different keys.

// Re-export dependencies that we use to make this macro work.
#[doc(hidden)]
pub mod deps {
    pub use paste::paste;
    pub use slab::Slab;
    pub use smallvec::SmallVec;
}

/// Declare a structure that can hold elements with multiple unique keys.
///
/// Each element can be looked up by any of its keys. The keys themselves can be any type that
/// supports `Hash`, `Eq`, and `Clone`. Elements can have multiple keys of the same type: for
/// example, a person can have a username `String` and an irc_handle `String`.
///
/// Multiple values can be stored for a given key: a lookup of one key returns all elements with
/// that key.
///
/// Keys may be accessed from elements either by field access or by an accessor function.
///
/// Keys may be optional. If all keys are optional, then we require additionally that every element
/// must have at least one key.
///
/// # Examples
///
/// ```
/// use tor_basic_utils::n_key_list;
///
/// // We declare a person struct with several different fields.
/// pub struct Person {
///     username: String,
///     irc_handle: String,
///     student_id: Option<u64>,
///     favorite_joke: Option<String>,
/// }
///
/// n_key_list! {
///     pub struct PersonList for Person {
///         // See note on "Key syntax" below.  The ".foo" syntax
///         // here means that the value for the key is returned
///         // by accessing a given field.
///         username: String { .username },
///         irc_handle: String { .irc_handle },
///         (Option) student_id: u64 { .student_id }
///     }
/// }
///
/// let mut people = PersonList::new();
/// people.insert(Person {
///     username: "mina".into(),
///     irc_handle: "pashMina".into(),
///     student_id: None,
///     favorite_joke: None,
/// });
/// assert_eq!(people.by_username("mina").len(), 1);
/// assert_eq!(people.by_irc_handle("pashMina").len(), 1);
/// ```
///
/// # Key syntax
///
/// You can tell the map to access the keys of an element in any of several ways.
///
/// * `name : type { func() }` - A key whose name is `name` and type is `type`, that can be accessed
///   from a given element by calling `element.func()`.
/// * `name : type { .field }` - A key whose name is `name` and type is `type`, that can be accessed
///   from a given element by calling `&element.field`.
/// * `name : type` - Short for as `name : type { name() }`.
///
/// If a key declaration is preceded with `(Option)`, then the key is treated as optional, and
/// accessor functions are expected to return `Option<&Type>`.
///
/// # Additional features
///
/// You can put generic parameters and `where` constraints on your structure. The `where` clause (if
/// present) must be wrapped in square brackets.
///
/// If you need to use const generics or lifetimes in your structure, you need to use square
/// brackets instead of angle brackets, and specify both the generic parameters *and* the type that
/// you are implementing. (This is due to limitations in the Rust macro system.)  For example:
///
/// ```
/// # use tor_basic_utils::n_key_list;
/// n_key_list!{
///     struct['a, T, const N: usize] ArrayMap2['a, T, N] for (String, [&'a T;N])
///         [ where T: Clone + 'a ]
///     {
///          name: String { .0 }
///     }
/// }
/// ```
#[macro_export]
macro_rules! n_key_list {
{
    $(#[$meta:meta])*
    $vis:vis struct $mapname:ident $(<$($P:ident),*>)? for $V:ty
    $( where [ $($constr:tt)+ ] )?
    {
        $($body:tt)+
    }
} => {
n_key_list!{
    $(#[$meta])*
    $vis struct [$($($P),*)?] $mapname [$($($P),*)?] for $V
    $( [ where $($constr)+ ] )?
    {
        $( $body )+
    }
}
};
{
    $(#[$meta:meta])*
    $vis:vis struct [$($($G:tt)+)?] $mapname:ident [$($($P:tt)+)?] for $V:ty
    $( [ where $($constr:tt)+ ])?
    {
        $( $(( $($flag:ident)+ ))? $key:ident : $KEY:ty $({ $($source:tt)+ })? ),+
        $(,)?
    }
} => {
$crate::n_key_list::deps::paste!{
    $( #[$meta] )*
    /// # General information
    ///
    #[doc = concat!(
        "A list of elements of type `", stringify!($V), "` whose members can be accessed by multiple keys."
    )]
    ///
    /// The keys are:
    ///
    #[doc = $( "- `" $key "` (`" $KEY "`)" $(" (" $($flag)+ ")\n" )? )+]
    ///
    /// Each element has a value for *each* required key, and up to one value for *each* optional
    /// key. There can be many elements for a given key value.
    ///
    /// ## Requirements
    ///
    /// Key types must have consistent `Hash` and `Eq` implementations, as they will be used as keys
    /// in a `HashMap`.
    ///
    /// If all keys are optional, then every element inserted must have at least one non-`None` key.
    ///
    /// An element must not change its keys over time through interior mutability.
    ///
    /// <div class='warning'>
    ///
    /// If *any* of these rules is violated, the consequences are unspecified, and could include
    /// panics or wrong answers (but not memory-unsafety).
    ///
    /// </div>
    $vis struct $mapname $(<$($G)*>)?
    where
        $( $KEY : std::hash::Hash + Eq + Clone , )+
        $($($constr)+, )?
    {
        /// The $key fields here are a set of maps from each of the key values to the lists of the
        /// positions of values with the same key within the Slab.
        ///
        /// Invariants:
        ///   - There is an entry K=>idx in the map `$key` if and only if values[idx].$accessor() ==
        ///     K.
        ///   - Every value in `values` has at least one key.
        ///   - A list should never be empty.
        ///
        /// The map values (the lists) are effectively a set, but using an inline vec should have
        /// better cache performance than something like HashSet.
        ///
        /// The SmallVec size of 4 was chosen arbitrarily under the assumption that a given key will
        /// have a small number of values on average. The exact constant probably won't matter, but
        /// inlining most of the lists should be good even if some spill into separate memory
        /// allocations. It's not worth exposing this level of internal detail to the macro caller
        /// unless there's a reason we need to.
        $([<$key _map>]: std::collections::HashMap<$KEY, $crate::n_key_list::deps::SmallVec<[usize; 4]>> , )+

        /// A map from the indices to the values.
        values: $crate::n_key_list::deps::Slab<$V>,
    }

    #[allow(dead_code)] // may be needed if this is not public
    impl $(<$($G)*>)? $mapname $(<$($P)*>)?
    where
        $( $KEY : std::hash::Hash + Eq + Clone , )+
        $($($constr)+)?
    {
        #[doc = "Construct a new [`" $mapname "`](Self)."]
        $vis fn new() -> Self {
            Self::with_capacity(0)
        }

        #[doc = "Construct a new [`" $mapname "`](Self) with a given capacity."]
        $vis fn with_capacity(n: usize) -> Self {
            Self {
                $([<$key _map>]: std::collections::HashMap::with_capacity(n),)*
                values: $crate::n_key_list::deps::Slab::with_capacity(n),
            }
        }

        // for each key type
        $(
        #[doc = "Return an iterator of the elements whose `" $key "` is `key`."]
        ///
        /// The iteration order is arbitrary.
        $vis fn [<by_ $key>] <BorrowAsKey_>(&self, key: &BorrowAsKey_) -> [<$mapname Iter>] <'_, $V>
        where
            $KEY : std::borrow::Borrow<BorrowAsKey_>,
            BorrowAsKey_: std::hash::Hash + Eq + ?Sized,
        {
            [<$mapname Iter>] {
                iter: self.[<$key _map>].get(key).map(|set| set.iter()).unwrap_or([].iter()),
                values: &self.values,
            }
        }

        #[doc = "Return `true` if this list contains an element whose `" $key "` is `key`."]
        $vis fn [<contains_ $key>] <BorrowAsKey_>(&mut self, key: &BorrowAsKey_) -> bool
        where
            $KEY : std::borrow::Borrow<BorrowAsKey_>,
            BorrowAsKey_: std::hash::Hash + Eq + ?Sized,
        {
            let Some(list) = self.[<$key _map>].get(key) else {
                return false;
            };

            if list.is_empty() {
                // we're not supposed to let this happen, so panic in debug builds
                #[cfg(debug_assertions)]
                panic!("Should not have an empty list");
                #[cfg(not(debug_assertions))]
                return false;
            }

            true
        }

        #[doc = "Remove and return the elements whose `" $key "` is `key`"]
        /// and where `filter` returns `true`.
        $vis fn [<remove_by_ $key>] <BorrowAsKey_>(
            &mut self,
            key: &BorrowAsKey_,
            mut filter: impl FnMut(&$V) -> bool,
        ) -> Vec<$V>
        where
            $KEY : std::borrow::Borrow<BorrowAsKey_>,
            BorrowAsKey_: std::hash::Hash + Eq + ?Sized,
        {
            let idx_list: Vec<usize> = {
                let Some(set) = self.[<$key _map>].get(key) else {
                    return Vec::new();
                };

                set
                    .iter()
                    .filter(|&&idx| filter(self.values.get(idx).expect("inconsistent state")))
                    .copied()
                    .collect()
            };

            let mut removed = Vec::with_capacity(idx_list.len());
            for idx in idx_list {
                removed.push(self.remove_at(idx).expect("inconsistent state"));
            }

            removed
        }
        )+

        fn remove_at(&mut self, idx: usize) -> Option<$V> {
            if let Some(removed) = self.values.try_remove(idx) {
                $(
                let $key = $crate::n_key_list!( @access(removed, ($($($flag)+)?) $key : $KEY $({$($source)+})?) );
                if let Some($key) = $key {
                    let set = self.[<$key _map>].get_mut($key).expect("inconsistent state");

                    #[cfg(debug_assertions)]
                    let size_before_remove = set.len();

                    // a `swap_retain` if it existed might be nice here, but the set should be small
                    // so shifting all later elements should be fine
                    set.retain(|x| *x != idx);

                    #[cfg(debug_assertions)]
                    assert_ne!(set.len(), size_before_remove, "should have removed at least one element");

                    // don't leave entries around with empty lists
                    if set.is_empty() {
                        self.[<$key _map>].remove($key);
                    }
                }
                )*
                Some(removed)
            } else {
                None
            }
        }

        /// Return an iterator over the elements in this container.
        $vis fn values(&self) -> impl Iterator<Item=&$V> + '_ {
            self.values.iter().map(|(_, v)| v)
        }

        /// Consume this container and return an iterator of its values.
        $vis fn into_values(self) -> impl Iterator<Item=$V> {
            self.values.into_iter().map(|(_, v)| v)
        }

        /// Try to insert `value`.
        ///
        /// Return `Error::NoKeys` if all the keys are optional, and `value` has no keys at all.
        $vis fn try_insert(&mut self, value: $V) -> Result<(), $crate::n_key_list::Error> {
            if self.capacity() > 32 && self.len() < self.capacity() / 4 {
                // we have the opportunity to free up a fair amount of space; let's take it
                self.compact()
            }

            let mut some_key_found = false;

            $(
            let $key = $crate::n_key_list!( @access(value, ($($($flag)+)?) $key : $KEY $({$($source)+})?) );
            some_key_found |= $key.is_some();
            )*

            if !some_key_found {
                // exit early before we add it to `values`
                return Err($crate::n_key_list::Error::NoKeys);
            }

            let idx = self.values.insert(value);
            let value = self.values.get(idx).expect("inconsistent state");

            $(
            let $key = $crate::n_key_list!( @access(value, ($($($flag)+)?) $key : $KEY $({$($source)+})?) );
            if let Some($key) = $key {
                let set = self.[<$key _map>].entry($key.to_owned()).or_default();
                set.push(idx);

                // we don't want the list's capacity to grow unbounded, so in the (hopefully) rare
                // case that the list grows large and then small again, try to free some of the
                // memory
                if set.capacity() > 64 && set.len() < set.capacity() / 4 {
                    set.shrink_to_fit();
                }

                // TODO: would it be beneficial to aggressively shrink the list if `len()` is
                // smaller than `inline_size()`?
            }
            )*

            Ok(())
        }

        /// See [`try_insert`](Self::try_insert). Panicks on errors.
        $vis fn insert(&mut self, value: $V) {
            self.try_insert(value)
                .expect("tried to add a value with no key")
        }

        /// Return the number of elements in this container.
        $vis fn len(&self) -> usize {
            self.values.len()
        }

        /// Return `true` if there are no elements in this container.
        $vis fn is_empty(&self) -> bool {
            let is_empty = self.len() == 0;

            #[cfg(debug_assertions)]
            if is_empty {
                $(assert!(self.[<$key _map>].is_empty());)*
            }

            is_empty
        }

        /// Return the number of elements for which this container has allocated storage.
        $vis fn capacity(&self) -> usize {
            self.values.capacity()
        }

        /// Remove every element that does not satisfy the predicate `pred`.
        $vis fn retain<F>(&mut self, mut pred: F)
        where
            F: FnMut(&$V) -> bool,
        {
            for idx in 0..self.values.capacity() {
                if self.values.get(idx).map(&mut pred) == Some(false) {
                    self.remove_at(idx);
                }
            }
        }

        /// An empty iterator.
        ///
        /// **NOTE:** This function is weird and will be removed in the future. We can fix this once
        /// we support a minimum rust version of 1.79.
        // TODO: The problem is that we need to assign `values` some value. In rust 1.79 we can just
        // use a constant expression, but without constant expressions, there's no way to get a
        // reference to a `Slab` with the generic types of `$V`. Once we support a minimum rust
        // version of 1.79, remove this function and uncomment the `Default` impl for the iterator
        // below.
        #[deprecated]
        $vis fn empty_iterator(&self) -> [<$mapname Iter>] <'_, $V> {
            [<$mapname Iter>] {
                iter: [].iter(),
                values: &self.values,
            }
        }

        /// Re-index all the values in this map, so that the map can use a more compact
        /// representation.
        ///
        /// This should be done infrequently; it's expensive.
        fn compact(&mut self) {
            let old_value = std::mem::replace(self, Self::with_capacity(self.len()));
            for item in old_value.into_values() {
                self.insert(item);
            }
        }

        /// Assert that this list appears to be in an internally consistent state.
        ///
        /// This method can be very expensive, and it should never fail unless your code has a bug.
        ///
        /// # Panics
        ///
        /// Panics if it finds bugs in this object, or constraint violations in its elements. See
        /// the (type documentation)[Self#Requirements] for a list of constraints.
        // it would be nice to run this after every operation that mutates internal state in debug
        // builds, but this function is way too slow for that
        fn check_consistency(&self) {
            // ensure each value is in exactly the correct maps
            for (idx, value) in &self.values {
                $(
                    let $key = $crate::n_key_list!( @access(value, ($($($flag)+)?) $key : $KEY $({$($source)+})?) );
                    if let Some($key) = $key {
                        // check that it exists in the set that it should be in
                        let set = self.[<$key _map>].get($key).expect("inconsistent state");
                        assert!(set.contains(&idx));
                        // check that it does not exist in any set that it should not be in
                        for (_key, set) in self.[<$key _map>].iter().filter(|(key, _)| *key != $key) {
                            assert!(!set.contains(&idx));
                        }
                    } else {
                        // check that it does not exist in any set
                        for set in self.[<$key _map>].values() {
                            assert!(!set.contains(&idx));
                        }
                    }
                )*
            }

            $(
                for set in self.[<$key _map>].values() {
                    // ensure no sets have dangling idxs
                    for idx in set {
                        assert!(self.values.contains(*idx));
                    }

                    // ensure no sets have duplicate idxs
                    let mut set_iter = set.iter();
                    while let Some(idx) = set_iter.next() {
                        assert!(!set_iter.clone().any(|x| x == idx));
                    }

                    // ensure no sets are empty
                    assert!(!set.is_empty());
                }
            )*

            // ensure that if a value is in a key's map, then the value really has that key
            $(
                for (key, set) in &self.[<$key _map>] {
                    for idx in set {
                        let value = self.values.get(*idx).expect("inconsistent state");
                        let $key = $crate::n_key_list!( @access(value, ($($($flag)+)?) $key : $KEY $({$($source)+})?) );
                        let $key = $key.expect("inconsistent state");
                        assert!(key == $key);
                    }
                }
            )*
        }
    }

    impl $(<$($G)*>)? Default for $mapname $(<$($P)*>)?
    where
        $( $KEY : std::hash::Hash + Eq + Clone , )+
        $($($constr)+)?
    {
        fn default() -> Self {
            $mapname::new()
        }
    }

    impl $(<$($G)*>)? std::iter::FromIterator<$V> for $mapname $(<$($P)*>)?
    where
        $( $KEY : std::hash::Hash + Eq + Clone , )*
        $($($constr)+)?
    {
        fn from_iter<IntoIter_>(iter: IntoIter_) -> Self
        where
            IntoIter_: std::iter::IntoIterator<Item = $V>,
        {
            let iter = iter.into_iter();
            let mut list = Self::with_capacity(iter.size_hint().0);
            for value in iter {
                list.insert(value);
            }
            list
        }
    }

    #[doc = "An iterator for [`" $mapname "`](" $mapname ")."]
    $vis struct [<$mapname Iter>] <'a, T> {
        iter: std::slice::Iter<'a, usize>,
        values: &'a $crate::n_key_list::deps::Slab<T>,
    }

    impl<'a, T> std::iter::Iterator for [<$mapname Iter>] <'a, T> {
        type Item = &'a T;

        fn next(&mut self) -> std::option::Option<Self::Item> {
            self.iter.next().map(|idx| self.values.get(*idx).expect("inconsistent state"))
        }

        #[inline]
        fn size_hint(&self) -> (usize, std::option::Option<usize>) {
            self.iter.size_hint()
        }
    }

    impl<'a, T> std::iter::ExactSizeIterator for [<$mapname Iter>] <'a, T>
    where
        // no harm in specifying it here, even though it should always be true
        std::slice::Iter<'a, usize>: std::iter::ExactSizeIterator,
    {
        #[inline]
        fn len(&self) -> usize {
            self.iter.len()
        }
    }

    // TODO: see comments on 'empty_iterator' above
    /*
    impl<'a, T> std::default::Default for [<$mapname Iter>] <'a, T> {
        fn default() -> Self {
            [<$mapname Iter>] {
                iter: [].iter(),
                values: const { &$crate::n_key_list::deps::Slab::new() },
            }
        }
    }
    */
}
};

// Helper: Generate an expression to access a specific key and return an `Option<&TYPE>` for that
// key. This is the part of the macro that parses key descriptions.

{ @access($ex:expr, (Option) $key:ident : $t:ty ) } => {
    $ex.key()
};
{ @access($ex:expr, () $key:ident : $t:ty) } => {
    Some($ex.key())
};
{ @access($ex:expr, (Option) $key:ident : $t:ty { . $field:tt } ) } => {
    $ex.$field.as_ref()
};
{ @access($ex:expr, () $key:ident : $t:ty { . $field:tt } ) } => {
   Some(&$ex.$field)
};
{ @access($ex:expr, (Option) $key:ident : $t:ty { $func:ident () } ) } => {
    $ex.$func()
};
{ @access($ex:expr, () $key:ident : $t:ty { $func:ident () } ) } => {
    Some($ex.$func())
};
}

/// An error returned from an operation on an [`n_key_list`].
#[derive(Clone, Debug, thiserror::Error)]
#[non_exhaustive]
pub enum Error {
    /// We tried to insert a value into a set where all keys were optional, but every key on that
    /// value was `None`.
    #[error("Tried to insert a value with no keys")]
    NoKeys,
}

#[cfg(test)]
mod test {
    // @@ begin test lint list maintained by maint/add_warning @@
    #![allow(clippy::bool_assert_comparison)]
    #![allow(clippy::clone_on_copy)]
    #![allow(clippy::dbg_macro)]
    #![allow(clippy::mixed_attributes_style)]
    #![allow(clippy::print_stderr)]
    #![allow(clippy::print_stdout)]
    #![allow(clippy::single_char_pattern)]
    #![allow(clippy::unwrap_used)]
    #![allow(clippy::unchecked_duration_subtraction)]
    #![allow(clippy::useless_vec)]
    #![allow(clippy::needless_pass_by_value)]
    //! <!-- @@ end test lint list maintained by maint/add_warning @@ -->

    fn sort<T: std::cmp::Ord>(i: impl Iterator<Item = T>) -> Vec<T> {
        let mut v: Vec<_> = i.collect();
        v.sort();
        v
    }

    n_key_list! {
        #[derive(Clone, Debug)]
        struct Tuple2List<A,B> for (A,B) {
            first: A { .0 },
            second: B { .1 },
        }
    }

    #[test]
    #[allow(clippy::cognitive_complexity)]
    fn basic() {
        let mut list = Tuple2List::new();
        assert!(list.is_empty());

        // add a single element and do some sanity checks
        list.insert((0_u32, 99_u16));
        assert_eq!(list.len(), 1);
        assert_eq!(list.contains_first(&0), true);
        assert_eq!(list.contains_second(&99), true);
        assert_eq!(list.contains_first(&99), false);
        assert_eq!(list.contains_second(&0), false);
        assert_eq!(sort(list.by_first(&0)), [&(0, 99)]);
        assert_eq!(sort(list.by_second(&99)), [&(0, 99)]);
        assert_eq!(list.by_first(&99).len(), 0);
        assert_eq!(list.by_second(&0).len(), 0);
        list.check_consistency();

        // lookup by a key that has never existed in the map
        assert_eq!(list.by_first(&1000000).len(), 0);

        // inserting the same element again should add it to the list
        assert_eq!(list.len(), 1);
        list.insert((0_u32, 99_u16));
        assert_eq!(list.len(), 2);
        list.check_consistency();

        // add two new entries
        list.insert((12, 34));
        list.insert((0, 34));
        assert_eq!(list.len(), 4);
        assert!(list.capacity() >= 4);
        assert_eq!(sort(list.by_first(&0)), [&(0, 34), &(0, 99), &(0, 99)]);
        assert_eq!(sort(list.by_first(&12)), [&(12, 34)]);
        list.check_consistency();

        // remove some elements
        assert_eq!(
            list.remove_by_first(&0, |(_, b)| *b == 99),
            vec![(0, 99), (0, 99)]
        );
        assert_eq!(list.remove_by_first(&0, |_| true), vec![(0, 34)]);
        assert_eq!(list.len(), 1);
        list.check_consistency();

        // test adding an element again
        assert_eq!(sort(list.by_first(&12)), [&(12, 34)]);
        list.insert((12, 123));
        assert_eq!(list.len(), 2);
        assert_eq!(sort(list.by_first(&12)), [&(12, 34), &(12, 123)]);
        assert_eq!(sort(list.by_second(&34)), [&(12, 34)]);
        assert_eq!(sort(list.by_second(&123)), [&(12, 123)]);
        list.check_consistency();

        // test iterators
        list.insert((56, 78));
        assert_eq!(sort(list.values()), [&(12, 34), &(12, 123), &(56, 78)]);
        assert_eq!(sort(list.into_values()), [(12, 34), (12, 123), (56, 78)]);
    }

    #[test]
    fn retain_and_compact() {
        let mut list: Tuple2List<String, String> = (1..=1000)
            .map(|idx| (format!("A={}", idx), format!("B={}", idx)))
            .collect();

        assert_eq!(list.len(), 1000);
        let cap_orig = list.capacity();
        assert!(cap_orig >= list.len());
        list.check_consistency();

        // retain only the values whose first key is 3 characters long; that's 9 values out of 1000
        list.retain(|(a, _)| a.len() <= 3);
        assert_eq!(list.len(), 9);
        // we don't shrink till we next insert
        assert_eq!(list.capacity(), cap_orig);
        list.check_consistency();

        // insert should cause the list to shrink
        list.insert(("A=0".to_string(), "B=0".to_string()));
        assert!(list.capacity() < cap_orig);
        assert_eq!(list.len(), 10);
        for idx in 0..=9 {
            assert!(list.contains_first(&format!("A={}", idx)));
        }
        list.check_consistency();
    }

    n_key_list! {
        #[derive(Clone, Debug)]
        struct AllOptional<A,B> for (Option<A>,Option<B>) {
            (Option) first: A { .0 },
            (Option) second: B { .1 },
        }
    }

    #[test]
    fn optional() {
        let mut list = AllOptional::<u8, u8>::new();

        // should be able to insert values with at least one key
        list.insert((Some(1), Some(2)));
        list.insert((None, Some(2)));
        list.insert((Some(1), None));
        list.check_consistency();

        assert_eq!(
            sort(list.by_first(&1)),
            [&(Some(1), None), &(Some(1), Some(2))],
        );

        // check that inserting a value with no keys results in an error
        assert!(matches!(
            list.try_insert((None, None)),
            Err(super::Error::NoKeys),
        ));
    }

    #[allow(dead_code)]
    struct Weekday {
        dow: u8,
        name: &'static str,
        lucky_number: Option<u16>,
    }
    #[allow(dead_code)]
    impl Weekday {
        fn dow(&self) -> &u8 {
            &self.dow
        }
        fn name(&self) -> &str {
            self.name
        }
        fn lucky_number(&self) -> Option<&u16> {
            self.lucky_number.as_ref()
        }
    }
    n_key_list! {
        struct WeekdaySet for Weekday {
            idx: u8 { dow() },
            (Option) lucky: u16 { lucky_number() },
            name: String { name() }
        }
    }

    n_key_list! {
        struct['a] ArrayMap['a] for (String, [&'a u32;10]) {
            name: String { .0 }
        }
    }

    n_key_list! {
        struct['a, const N:usize] ArrayMap2['a, N] for (String, [&'a u32;N]) {
            name: String { .0 }
        }
    }
}
