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
/// firstname `String` and a lastname `String`.
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
///     given_name: String,
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
///         given_name: String { .given_name },
///         student_id: Option<u64> { .student_id }
///     }
/// }
///
/// let mut people = PersonSet::new();
/// people.insert(Person {
///     username: "mina".into(),
///     given_name: "Mina Harker".into(),
///     student_id: None,
///     favorite_joke: None
/// });
/// assert!(people.by_username("mina").is_some());
/// assert!(people.by_given_name("Mina Harker").is_some());
/// ```
///
/// # Key syntax
///
/// You can access the keys of an element in any of several ways.
///
/// * `name : type { func() }` - A key whose name is `name` and type is `type`,
///   that can be accessed from a given element by calling `element.func()`.
/// * name : type { .field }` - A key whose name is `name` and type is `type`,
///   that can be accessed from a given element by calling `&element.field`.
/// * `name : type` - Short for as `name : type { name() }`.
///
/// If the type of a key is given as `Option<type2>`, then the inner `type2` is
/// treated as the real key type, and the key is treated as optional.
///
/// # Additional features
///
/// You can put generic parameters and `where` constraints on your structure.
#[macro_export]
macro_rules! n_key_set {
{
    $(#[$meta:meta])*
    $vis:vis struct $mapname:ident $(<$($P:ident),*>)? for $V:ty
    $( where $($constr:tt)+ )?
    {
        $( $key:ident : $KEY:ty $({ $($source:tt)+ })? ),+
        $(,)?
    }
} => {
$crate::n_key_set::deps::paste!{
   $( #[$meta] )*
    #[doc = concat!("
        A set of elements of type ", stringify!($V), " whose members can be 
        accessed by multiple keys.

        The keys are:
        ",
        $( " * `", stringify!($key), "` (`",stringify!($ty),"`)\n" , )+
        "

        The set contains at most one member for any value of a given key.

        # Requirements

        Key types must have consistent `Hash` and `Eq` implementations, as
        they will be used as keys in a `HashSet`.

        If all keys are of type `Option<T>`, then every element in this set
        must have at least one non-None key.

        An element must not change its keys over time through interior
        mutability.
        
        # Limitations

        This could be more efficient in space and time.
        "
    )]
    $vis struct $mapname $(<$($P),*>)?
        where $( $KEY : std::hash::Hash + Eq + Clone , )+  $($($constr)+)?
    {
        // The $key fields here are a set of maps from each of the key values to
        // the position of that value within the Slab..
        //
        // Invariants:
        //    * There is an entry K=>idx in the map `$key` if and only if
        //      values[idx].$accessor() == K.
        //
        // TODO: Dare we have these HashMaps key based on a reference to V
        // instead? That would create a self-referential structure and require
        // unsafety.  Probably best to avoid that for now.
        $($key: std::collections::HashMap<$KEY, usize> , )+

        // A map from the indices to the values.
        values: $crate::n_key_set::deps::Slab<$V>,
    }

    #[allow(dead_code)] // May be needed if this is not public.
    impl $(<$($P),*>)? $mapname $(<$($P),*>)?
        where $( $KEY : std::hash::Hash + Eq + Clone , )+  $($($constr)+)?
    {
        #[doc = concat!("Construct a new ", stringify!($mapname))]
        $vis fn new() -> Self {
            Self::with_capacity(0)
        }
        #[doc = concat!("Construct a new ", stringify!($mapname), " with a given capacity.")]

        $vis fn with_capacity(n: usize) -> Self {
            Self {
                $($key: std::collections::HashMap::with_capacity(n),)*
                values: $crate::n_key_set::deps::Slab::with_capacity(n),
            }
        }
        $(
        #[doc = concat!("Return a reference to the element whose `", stringify!($key), "` is `key`.
        
        Return None if there is no such element.")]
        $vis fn [<by_ $key>] <T>(&self, key: &T) -> Option<&$V>
            where $KEY : std::borrow::Borrow<T>,
                  T: std::hash::Hash + Eq + ?Sized
        {
            self.$key.get(key).and_then(|idx| self.values.get(*idx))
        }

        /*  Removed: This seems too risky for real life.

        #[doc = concat!("Return a mutable reference to the element whose `", stringify!($key), "` is `key`.

        Return None if there is no such element.

        # Correctness

        This reference must not be used to change the value of any of the resulting
        element's keys: doing so can invalidate this set.
        ")]
        $vis fn [<by_ $key _mut>] <T>(&mut self, $key: &T) -> Option<&mut $V>
            where $KEY : std::borrow::Borrow<T>,
                  T: std::hash::Hash + Eq + ?Sized
        {
            self.$key.get($key).and_then(|idx| self.values.get_mut(*idx))
        }

        */

        #[doc = concat!("Return true if this set contains an element whose `", stringify!($key), "` is `key`.")]
        $vis fn [<contains_ $key>] <T>(&mut self, $key: &T) -> bool
        where $KEY : std::borrow::Borrow<T>,
              T: std::hash::Hash + Eq + ?Sized
        {
            self.$key.get($key).is_some()
        }

        #[doc = concat!("Remove the element whose `", stringify!($key), "` is `key`.
        
        Return that element on success, and None if there is no such element.")]
        #[doc=stringify!($key)]
        $vis fn [<remove_by_ $key>] <T>(&mut self, $key: &T) -> Option<$V>
            where $KEY : std::borrow::Borrow<T>,
                  T: std::hash::Hash + Eq + ?Sized
        {
            self.$key.get($key).copied().and_then(|old_idx| self.remove_at(old_idx))
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

        /// Insert the value `value`.
        ///
        /// Remove any previous values that shared any keys with `value`, and
        /// return them in a vector.
        $vis fn insert(&mut self, value: $V) -> Vec<$V> {
            if self.capacity() > 32 && self.len() < self.capacity() / 4 {
                // We're have the opportunity to free up a fair amount of space; let's take it.
                self.compact()
            }

            // First, remove all the elements that have at least one key in common with `value`.
            let mut replaced = Vec::new();
            $(
                $crate::n_key_set!( @access(value, $key : $KEY $({$($source)+})?) )
                    .and_then(|key| self.$key.get(key))
                    .and_then(|idx| self.values.try_remove(*idx))
                    .map(|val| replaced.push(val));
            )*

            // Now insert the new value, and add it to all of the maps.
            let new_idx = self.values.insert(value);
            let value_ref = self.values.get(new_idx).expect("we just inserted this");
            let mut some_key_found = false;
            $(
                $crate::n_key_set!( @access(value_ref, $key : $KEY $({$($source)+})?) )
                    .map(|key| {
                        self.$key.insert(key.clone(), new_idx);
                        some_key_found = true;
                    });
            )*
            // If we didn't find any key on the newly added value, that's
            // an invariant violation.
            debug_assert!(some_key_found);

            replaced
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
                    if let Some($key) = $crate::n_key_set!( @access(removed, $key : $KEY $({$($source)+})?) ) {
                        let old_idx = self.$key.remove($key);
                        debug_assert_eq!(old_idx, Some(idx));
                    }
                )*
                Some(removed)
            } else {
                None
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
    }

    impl $(<$($P),*>)? Default for $mapname $(<$($P),*>)?
        where $( $KEY : std::hash::Hash + Eq + Clone , )*  $($($constr)+)?
    {
        fn default() -> Self {
            $mapname::new()
        }
    }

    impl $(<$($P),*>)? FromIterator<$V> for $mapname $(<$($P),*>)?
        where $( $KEY : std::hash::Hash + Eq + Clone , )*  $($($constr)+)?
    {
        fn from_iter<T>(iter: T) -> Self
        where
            T: IntoIterator<Item = $V>
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

{ @access($ex:expr, $key:ident : Option<$t:ty> ) } => {
    $ex.key()
};
{ @access($ex:expr, $key:ident : $t:ty) } => {
    Some($ex.key())
};
{ @access($ex:expr, $key:ident : Option<$t:ty> { . $field:tt } ) } => {
    $ex.$field.as_ref()
};
{ @access($ex:expr, $key:ident : $t:ty { . $field:tt } ) } => {
   Some(&$ex.$field)
};
{ @access($ex:expr, $key:ident : Option<$t:ty> { $func:ident () } ) } => {
    $ex.$func()
};
{ @access($ex:expr, $key:ident : $t:ty { $func:ident () } ) } => {
    Some($ex.$func())
};
}

#[cfg(test)]
mod test {

    n_key_set! {
        struct Tuple2Set<A,B> for (A,B) {
            first: A { .0 },
            second: B { .1 },
        }
    }

    #[test]
    fn basic() {
        let mut set = Tuple2Set::new();
        set.insert((0_u32, 99_u16));
        assert!(set.contains_first(&0));
        assert!(set.contains_second(&99));
        assert!(!set.contains_first(&99));
        assert!(!set.contains_second(&0));
    }
}
