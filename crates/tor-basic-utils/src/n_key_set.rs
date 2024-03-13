//! Declaration for an n-keyed set type, allowing access to each of its members by each of N different keys.

// Re-export dependencies that we use to make this macro work.
#[doc(hidden)]
pub mod deps {
    pub use paste::paste;
    pub use slab::Slab;
}

/// Declare a structure that can hold elements with multiple unique keys.
///
/// Each element can be looked up or removed by any of its keys. The keys
/// themselves can be any type that supports `Hash`, `Eq`, and `Clone`. Elements
/// can have multiple keys of the same type: for example, a person can have a
/// username `String` and an irc_handle `String`.
///
/// All keys in the set must be unique: if a new element is inserted that has
/// the same value for any key as a previous element, the old element is
/// removed.
///
/// Keys may be accessed from elements either by field access or by an accessor
/// function.
///
/// Keys may be optional.  If all keys are optional, then we require
/// additionally that every element must have at least one key.
///
/// # Examples
///
/// ```
/// use tor_basic_utils::n_key_set;
///
/// // We declare a person struct with several different fields.
/// pub struct Person {
///     username: String,
///     irc_handle: String,
///     student_id: Option<u64>,
///     favorite_joke: Option<String>,
/// }
///
/// n_key_set! {
///     pub struct PersonSet for Person {
///         // See note on "Key syntax" below.  The ".foo" syntax
///         // here means that the value for the key is returned
///         // by accessing a given field.
///         username: String { .username },
///         irc_handle: String { .irc_handle },
///         (Option) student_id: u64 { .student_id }
///     }
/// }
///
/// let mut people = PersonSet::new();
/// people.insert(Person {
///     username: "mina".into(),
///     irc_handle: "pashMina".into(),
///     student_id: None,
///     favorite_joke: None
/// });
/// assert!(people.by_username("mina").is_some());
/// assert!(people.by_irc_handle("pashMina").is_some());
/// ```
///
/// # Key syntax
///
/// You can tell the map to access the keys of an element in any of several ways.
///
/// * `name : type { func() }` - A key whose name is `name` and type is `type`,
///   that can be accessed from a given element by calling `element.func()`.
/// * `name : type { .field }` - A key whose name is `name` and type is `type`,
///   that can be accessed from a given element by calling `&element.field`.
/// * `name : type` - Short for as `name : type { name() }`.
///
/// If a key declaration is preceded with `(Option)`, then the
/// key is treated as optional, and accessor functions are expected to return
/// `Option<&Type>`.
///
/// # Additional features
///
/// You can put generic parameters and `where` constraints on your structure.
/// The `where` clause (if present) must be wrapped in square brackets.
///
/// If you need to use const generics or lifetimes in your structure, you
/// need to use square brackets instead of angle brackets, and specify both the
/// generic parameters *and* the type that you are implementing. (This is due to
/// limitations in the Rust macro system.)  For example:
///
/// ```
/// # use tor_basic_utils::n_key_set;
/// n_key_set!{
///     struct['a, T, const N: usize] ArrayMap2['a, T, N] for (String, [&'a T;N])
///         [ where T: Clone + 'a ]
///     {
///          name: String { .0 }
///     }
/// }
/// ```
#[macro_export]
macro_rules! n_key_set {
{
    $(#[$meta:meta])*
    $vis:vis struct $mapname:ident $(<$($P:ident),*>)? for $V:ty
    $( where [ $($constr:tt)+ ] )?
    {
        $($body:tt)+
    }
} => {
n_key_set!{
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
$crate::n_key_set::deps::paste!{
   $( #[$meta] )*
    #[doc = concat!(
        "A set of elements of type ", stringify!($V), " whose members can be accessed by multiple keys.",
        "\n\nThe keys are:",
        $( " * `", stringify!($key), "` (`",stringify!($KEY),"`)\n" ,
           $(" (", stringify!($($flag)+), ")", )?
         )+
        "\
Each member has a value for *each* required key, and up to one value
for *each* optional key.
The set contains at most one member for any value of a given key.

# Requirements

Key types must have consistent `Hash` and `Eq` implementations, as
they will be used as keys in a `HashMap`.

If all keys are optional, then every element in this set
must have at least one non-None key.

An element must not change its keys over time through interior
mutability.

⚠️ If *any* of these rules is violated, the consequences are unspecified,
and could include panics or wrong answers (but not memory-unsafety).
        
# Limitations

This could be more efficient in space and time.
        ",
    )]
    $vis struct $mapname $(<$($G)*>)?
        where $( $KEY : std::hash::Hash + Eq + Clone , )+  $($($constr)+)?
    {
        // The $key fields here are a set of maps from each of the key values to
        // the position of that value within the Slab.
        //
        // Invariants:
        //    * There is an entry K=>idx in the map `$key` if and only if
        //      values[idx].$accessor() == K.
        //    * Every value in `values` has at least one key.
        //
        // TODO: Dare we have these HashMaps key based on a reference to V
        // instead? That would create a self-referential structure and require
        // unsafety.  Probably best to avoid that for now.
        $([<$key _map>]: std::collections::HashMap<$KEY, usize> , )+

        // A map from the indices to the values.
        values: $crate::n_key_set::deps::Slab<$V>,
    }

    #[allow(dead_code)] // May be needed if this is not public.
    impl $(<$($G)*>)? $mapname $(<$($P)*>)?
        where $( $KEY : std::hash::Hash + Eq + Clone , )+  $($($constr)+)?
    {
        #[doc = concat!("Construct a new ", stringify!($mapname))]
        $vis fn new() -> Self {
            Self::with_capacity(0)
        }
        #[doc = concat!("Construct a new ", stringify!($mapname), " with a given capacity.")]

        $vis fn with_capacity(n: usize) -> Self {
            Self {
                $([<$key _map>]: std::collections::HashMap::with_capacity(n),)*
                values: $crate::n_key_set::deps::Slab::with_capacity(n),
            }
        }
        $(
        #[doc = concat!("Return a reference to the element whose `", stringify!($key), "` is `key`.")]
        ///
        /// Return None if there is no such element.
        $vis fn [<by_ $key>] <BorrowAsKey_>(&self, key: &BorrowAsKey_) -> Option<&$V>
            where $KEY : std::borrow::Borrow<BorrowAsKey_>,
                  BorrowAsKey_: std::hash::Hash + Eq + ?Sized
        {
            self.[<$key _map>].get(key).map(|idx| self.values.get(*idx).expect("inconsistent state"))
        }

        #[doc = concat!("Return a mutable reference to the element whose `", stringify!($key),
                        "` is `key`.")]
        ///
        /// Return None if there is no such element.
        ///
        /// # Safety
        ///
        /// This function can put this set into an inconsistent state if the
        /// mutable reference is used to change any of the keys. Doing this does
        /// not risk Rust safety violations (such as undefined behavior), but it
        /// may nonetheless make your program incorrect by causing other
        /// functions on this object to panic or give incorrect results.
        ///
        /// If you cannot prove to yourself that this won't happen, then you
        /// should use `modify_by_*` instead.
        $vis unsafe fn [<by_ $key _mut>] <BorrowAsKey_>(
            &mut self,
            key: &BorrowAsKey_
        ) -> Option<&mut $V>
            where $KEY : std::borrow::Borrow<BorrowAsKey_>,
                  BorrowAsKey_: std::hash::Hash + Eq + ?Sized
        {
            self.[<$key _map>]
                .get(key)
                .map(|idx| self.values.get_mut(*idx).expect("inconsistent state"))
        }

        #[doc = concat!("Return true if this set contains an element whose `", stringify!($key),
                        "` is `key`.")]
        $vis fn [<contains_ $key>] <BorrowAsKey_>(&mut self, $key: &BorrowAsKey_) -> bool
        where $KEY : std::borrow::Borrow<BorrowAsKey_>,
              BorrowAsKey_: std::hash::Hash + Eq + ?Sized
        {
            self.[<$key _map>].get($key).is_some()
        }

        #[doc = concat!("Remove the element whose `", stringify!($key), "` is `key`")]
        ///
        /// Return that element on success, and None if there is no such element.")]
        #[doc=stringify!($key)]
        $vis fn [<remove_by_ $key>] <BorrowAsKey_>(&mut self, $key: &BorrowAsKey_) -> Option<$V>
            where $KEY : std::borrow::Borrow<BorrowAsKey_>,
                  BorrowAsKey_: std::hash::Hash + Eq + ?Sized
        {
            self.[<$key _map>]
                .get($key)
                .copied()
                .map(|old_idx| self.remove_at(old_idx).expect("inconsistent state"))
        }


        #[doc = concat!("Modify the element with the given value for `", stringify!($key),
                        " by applying `func` to it.")]
        ///
        /// `func` is allowed to change the keys for this value.  All indices
        /// are updated to refer to the new keys.  If the new keys conflict with
        /// any previous values, those values are replaced and returned in a
        /// vector.
        ///
        /// If `func` causes the value to have no keys at all, then the value
        /// itself is also removed and returned in the result vector.
        ///
        /// Note that because this function needs to copy all key values and check whether
        /// they have changed, it is not terribly efficient.
        $vis fn [<modify_by_$key>] <BorrowAsKey_, F_>(
            &mut self,
            $key: &BorrowAsKey_,
            func: F_) -> Vec<$V>
        where
            $KEY : std::borrow::Borrow<BorrowAsKey_>,
            BorrowAsKey_: std::hash::Hash + Eq + ?Sized,
            F_: FnOnce(&mut $V)
        {
            if let Some(idx) = self.[<$key _map>].get($key) {
                self.modify_at(*idx, func)
            } else {
                Vec::new()
            }
        }
        )+

        /// Return an iterator over the elements in this container.
        $vis fn values(&self) -> impl Iterator<Item=&$V> + '_ {
            self.values.iter().map(|(_, v)| v)
        }

        /// Consumer this container and return an iterator of its values.
        $vis fn into_values(self) -> impl Iterator<Item=$V> {
            self.values.into_iter().map(|(_, v)| v)
        }

        /// Try to insert the value `value`.
        ///
        /// Remove any previous values that shared any keys with `value`, and
        /// return them in a vector on success.
        ///
        /// Return `Err(Error::NoKeys)` if all the keys are optional,
        /// and `value` has no keys at all.
        $vis fn try_insert(&mut self, value: $V) -> Result<Vec<$V>, $crate::n_key_set::Error> {
            if self.capacity() > 32 && self.len() < self.capacity() / 4 {
                // We're have the opportunity to free up a fair amount of space; let's take it.
                self.compact()
            }

            // First, remove all the elements that have at least one key in common with `value`.
            let mut replaced = Vec::new();
            $(
                replaced.extend(
                    $crate::n_key_set!( @access(value, ($($($flag)+)?) $key : $KEY $({$($source)+})?) )
                    .and_then(|key| self.[<remove_by_$key>](key))
                );
            )*

            // Now insert the new value, and add it to all of the maps.
            let new_idx = self.values.insert(value);
            let value_ref = self.values.get(new_idx).expect("we just inserted this");
            let mut some_key_found = false;
            $(
                $crate::n_key_set!( @access(value_ref, ($($($flag)+)?) $key : $KEY $({$($source)+})?) )
                    .map(|key| {
                        self.[<$key _map>].insert(key.to_owned(), new_idx);
                        some_key_found = true;
                    });
            )*
            // If we didn't find any key on the newly added value, that's
            // an invariant violation.
            if ! some_key_found {
                self.values.remove(new_idx); // Restore the set to a correct state.
                return Err($crate::n_key_set::Error::NoKeys);
            }

            Ok(replaced)
        }

        /// Try to insert the value `value`.
        ///
        /// Remove any previous values that shared any keys with `value`, and
        /// return them in a vector.
        ///
        /// # Panics
        ///
        /// Panics if all the keys are optional, and `value` has no keys at all.
        $vis fn insert(&mut self, value: $V) -> Vec<$V> {
            self.try_insert(value)
                .expect("Tried to add a value with no key!")
        }

        /// Return the number of elements in this container.
        $vis fn len(&self) -> usize {
            self.values.len()
        }

        /// Return true if there are no elements in this container.
        $vis fn is_empty(&self) -> bool {
            self.values.len() == 0
        }

        /// Return the number of elements for which this container has allocated
        /// storage.
        $vis fn capacity(&self) -> usize {
            self.values.capacity()
        }

        /// Remove every element that does not satisfy the predicate `pred`.
        $vis fn retain<F>(&mut self, mut pred: F)
            where F: FnMut(&$V) -> bool,
        {
            for idx in 0..self.values.capacity() {
                if self.values.get(idx).map(&mut pred) == Some(false) {
                    self.remove_at(idx);
                }
            }
        }

        /// Helper: remove the item stored at index `idx`, and remove it from
        /// every key map.
        ///
        /// If there was no element at `idx`, do nothing.
        ///
        /// Return the element removed (if any).
        fn remove_at(&mut self, idx: usize) -> Option<$V> {
            if let Some(removed) = self.values.try_remove(idx) {
                $(
                let $key = $crate::n_key_set!( @access(removed, ($($($flag)+)?) $key : $KEY $({$($source)+})?) );
                if let Some($key) = $key {
                    let old_idx = self.[<$key _map>].remove($key);
                    assert_eq!(old_idx, Some(idx));
                }
                )*
                Some(removed)
            } else {
                None
            }
        }

        /// Change the value at `idx` by applying `func` to it.
        ///
        /// `func` is allowed to change the keys for this value.  All indices
        /// are updated to refer to the new keys.  If the new keys conflict with
        /// any previous values, those values are replaced and returned in a
        /// vector.
        ///
        /// If `func` causes the value to have no keys at all, then the value
        /// itself is also removed and returned in the result vector.
        ///
        /// # Panics
        ///
        /// Panics if `idx` is not present in this set.
        fn modify_at<F_>(&mut self, idx: usize, func: F_) -> Vec<$V>
        where
            F_: FnOnce(&mut $V)
        {
            let value = self.values.get_mut(idx).expect("invalid index");
            $(
            let [<orig_$key>] = $crate::n_key_set!( @access(value, ($($($flag)+)?) $key : $KEY $({$($source)+})?) )
                .map(|elt| elt.to_owned()) ;
            )+

            func(value);

            // Check whether any keys have changed, and whether there still are
            // any keys.
            $(
                let [<new_$key>] = $crate::n_key_set!( @access( value, ($($($flag)+)?) $key : $KEY $({$($source)+})?) ) ;
            )+
            let keys_changed = $(
                 [<orig_$key>].as_ref().map(std::borrow::Borrow::borrow) != [<new_$key>]
            )||+ ;

            if keys_changed {
                let found_any_keys = $( [<new_$key>].is_some() )||+ ;

                // Remove this value from every place that it was before.
                //
                // We can't use remove_at, since we have changed the keys in the
                // value: we have to remove them manually from each index
                // instead.
                $(
                    if let Some(orig) = [<orig_ $key>] {
                        let removed = self.[<$key _map>].remove(&orig);
                        assert_eq!(removed, Some(idx));
                    }
                )+
                // Remove the value from its previous place in the index.  (This
                // results in an extra copy when we call insert(), but if we
                // didn't do it, we'd need to reimplement `insert()`.)
                let removed = self.values.remove(idx);
                if found_any_keys {
                    // This item belongs: put it back and return the vector of
                    // whatever was replaced.j
                    self.insert(removed)
                } else {
                    // This item does not belong any longer, since all its keys
                    // were removed.
                    vec![removed]
                }
            } else {
                // We did not change any keys, so we know we have not replaced
                // any items.
                vec![]
            }
        }

        /// Re-index all the values in this map, so that the map can use a more
        /// compact representation.
        ///
        /// This should be done infrequently; it's expensive.
        fn compact(&mut self) {
            let old_value = std::mem::replace(self, Self::with_capacity(self.len()));
            for item in old_value.into_values() {
                self.insert(item);
            }
        }

        /// Assert that this set appears to be in an internally consistent state.
        ///
        /// This method can be somewhat expensive, and it should never fail unless
        /// your code has a bug.
        ///
        /// # Panics
        ///
        /// Panics if it finds bugs in this object, or constraint violations in
        /// its elements.  See the (type documentation)[Self#Requirements] for a
        /// list of constraints.
        $vis fn check_invariants(&self) {
            #![allow(noop_method_call)] // permit borrow when it does nothing.
            use std::borrow::Borrow;
            // Make sure that every entry in the $key map points to a
            // value with the right value for that $key.
            $(
                for (k,idx) in self.[<$key _map>].iter() {
                    let val = self.values.get(*idx).expect("Dangling entry in hashmap.");
                    // Can't use assert_eq!; k might not implement Debug.
                    assert!(
                        Some((k).borrow()) ==
                        $crate::n_key_set!( @access(val, ($($($flag)+)?) $key : $KEY $({$($source)+})?) ),
                        "Inconsistent key between hashmap and value."
                    )
                }
            )+

            // Make sure that every value has an entry in the $key map that
            // points to it, for each of its keys.
            //
            // This is slightly redundant, but we don't care too much about
            // efficiency here.
            for (idx, val) in self.values.iter() {
                let mut found_any_key = false;
                $(
                if let Some(k) = $crate::n_key_set!( @access(val, ($($($flag)+)?) $key : $KEY $({$($source)+})?) ) {
                    found_any_key = true;
                    assert!(
                        self.[<$key _map>].get(k) == Some(&idx),
                        "Value not found at correct index"
                    )
                }
                stringify!($key);
                )+
                assert!(found_any_key, "Found a value with no keys.");
            }
        }
    }

    impl $(<$($G)*>)? Default for $mapname $(<$($P)*>)?
        where $( $KEY : std::hash::Hash + Eq + Clone , )*  $($($constr)+)?
    {
        fn default() -> Self {
            $mapname::new()
        }
    }

    impl $(<$($G)*>)? FromIterator<$V> for $mapname $(<$($P)*>)?
        where $( $KEY : std::hash::Hash + Eq + Clone , )*  $($($constr)+)?
    {
        fn from_iter<IntoIter_>(iter: IntoIter_) -> Self
        where
            IntoIter_: IntoIterator<Item = $V>
        {
            let iter = iter.into_iter();
            let mut set = Self::with_capacity(iter.size_hint().0);
            for value in iter {
                set.insert(value);
            }
            set
        }
    }
}
};

// Helper: Generate an expression to access a specific key and return
// an Option<&TYPE> for that key.  This is the part of the macro
// that parses key descriptions.

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

/// An error returned from an operation on an `n_key_set`.
#[derive(Clone, Debug, thiserror::Error)]
#[non_exhaustive]
pub enum Error {
    /// We tried to insert a value into a set where all keys were optional, but
    /// every key on that value was `None`.
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

    n_key_set! {
        #[derive(Clone, Debug)]
        struct Tuple2Set<A,B> for (A,B) {
            first: A { .0 },
            second: B { .1 },
        }
    }

    #[test]
    fn basic() {
        let mut set = Tuple2Set::new();
        assert!(set.is_empty());

        set.insert((0_u32, 99_u16));
        assert_eq!(set.contains_first(&0), true);
        assert_eq!(set.contains_second(&99), true);
        assert_eq!(set.contains_first(&99), false);
        assert_eq!(set.contains_second(&0), false);
        assert_eq!(set.by_first(&0), Some(&(0, 99)));
        assert_eq!(set.by_second(&99), Some(&(0, 99)));
        assert_eq!(set.by_first(&99), None);
        assert_eq!(set.by_second(&0), None);

        assert_eq!(set.insert((12, 34)), vec![]);
        assert_eq!(set.len(), 2);
        assert!(set.capacity() >= 2);
        assert_eq!(set.by_first(&0), Some(&(0, 99)));
        assert_eq!(set.by_first(&12), Some(&(12, 34)));
        assert_eq!(set.remove_by_second(&99), Some((0, 99)));
        assert_eq!(set.len(), 1);

        // no overlap in these next few inserts.
        set.insert((34, 56));
        set.insert((56, 78));
        set.insert((78, 90));
        assert_eq!(set.len(), 4);
        // This insert replaces (12, 34)
        assert_eq!(set.insert((12, 123)), vec![(12, 34)]);
        // This one replaces (12,123) and (34,56).
        let mut replaced = set.insert((12, 56));
        replaced.sort();
        assert_eq!(replaced, vec![(12, 123), (34, 56)]);
        assert_eq!(set.len(), 3);
        assert_eq!(set.is_empty(), false);
        set.check_invariants();

        // Test our iterators
        let mut all_members: Vec<_> = set.values().collect();
        all_members.sort();
        assert_eq!(all_members, vec![&(12, 56), &(56, 78), &(78, 90)]);

        let mut drained_members: Vec<_> = set.into_values().collect();
        drained_members.sort();
        assert_eq!(drained_members, vec![(12, 56), (56, 78), (78, 90)]);
    }

    #[test]
    fn retain_and_compact() {
        let mut set: Tuple2Set<String, String> = (1..=1000)
            .map(|idx| (format!("A={}", idx), format!("B={}", idx)))
            .collect();

        assert_eq!(set.len(), 1000);
        let cap_orig = set.capacity();
        assert!(cap_orig >= set.len());

        // Retain only the values whose first key is 3 characters long.
        // That's 9 values out of 1000.
        set.retain(|(a, _)| a.len() <= 3);
        assert_eq!(set.len(), 9);
        // We don't shrink till we next insert.
        assert_eq!(set.capacity(), cap_orig);
        set.check_invariants();

        assert!(set
            .insert(("A=0".to_string(), "B=0".to_string()))
            .is_empty());
        assert!(set.capacity() < cap_orig);
        assert_eq!(set.len(), 10);
        for idx in 0..=9 {
            assert!(set.contains_first(&format!("A={}", idx)));
        }
        set.check_invariants();
    }

    #[test]
    fn modify_value() {
        let mut set: Tuple2Set<i32, i32> = (1..=100).map(|idx| (idx, idx * idx)).collect();
        set.check_invariants();

        let v = set.modify_by_first(&30, |elt| elt.1 = 256);
        set.check_invariants();
        // one element was replaced.
        assert_eq!(v.len(), 1);
        assert_eq!(v[0], (16, 256));
        assert_eq!(set.by_second(&256).unwrap(), &(30, 256));
        assert_eq!(set.by_first(&30).unwrap(), &(30, 256));

        let v = set.modify_by_first(&30, |elt| *elt = (-100, -100));
        set.check_invariants();
        // no elements were replaced.
        assert_eq!(v.len(), 0);
        assert_eq!(set.by_first(&30), None);
        assert_eq!(set.by_second(&256), None);
        assert_eq!(set.by_first(&-100).unwrap(), &(-100, -100));
        assert_eq!(set.by_second(&-100).unwrap(), &(-100, -100));

        set.check_invariants();
    }

    #[allow(dead_code)]
    struct Weekday {
        dow: u8,
        name: &'static str,
        lucky_number: Option<u16>,
    }
    #[allow(dead_code)]
    impl Weekday {
        // TODO: I wish this could return u8
        fn dow(&self) -> &u8 {
            &self.dow
        }
        fn name(&self) -> &str {
            self.name
        }
        // TODO: I wish this could return Option<u16>
        fn lucky_number(&self) -> Option<&u16> {
            self.lucky_number.as_ref()
        }
    }
    n_key_set! {
        struct WeekdaySet for Weekday {
            idx: u8 { dow() },
            (Option) lucky: u16 { lucky_number() },
            name: String { name() }
        }
    }

    n_key_set! {
        struct['a] ArrayMap['a] for (String, [&'a u32;10]) {
            name: String { .0 }
        }
    }

    n_key_set! {
        struct['a, const N:usize] ArrayMap2['a, N] for (String, [&'a u32;N]) {
            name: String { .0 }
        }
    }
}
