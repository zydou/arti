//! A data structure for the solver's bucket sort layers
//!
//! This module implements the [`KeyValueBucketArray`] and related types,
//! forming the basis of our solver's temporary storage. The basic key/value
//! bucket array is a hash table customized with a fixed capacity and minimal
//! data types. The overall key/value array is organized in a struct-of-arrays
//! fashion, keeping bucket counts in state memory alongside mutable references
//! to external key and value memories.
//!
//! The implementation is split into a higher level which knows about the hash
//! table semantics and a lower level that's responsible for memory safety.

pub(crate) mod hash;
pub(crate) mod mem;
