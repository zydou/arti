//! A data structure for the solver's bucket sort layers
//!
//! This module implements the [`hash::KeyValueBucketArray`] and related types,
//! forming the basis of our solver's temporary storage. The basic key/value
//! bucket array is a hash table customized with a fixed capacity and minimal
//! data types. It's organized in a struct-of-arrays fashion, keeping bucket
//! counts in state memory alongside mutable references to external key and
//! value memories.
//!
//! For performance and memory efficiency, the hash table layer is built on
//! a manual memory management layer. Individual bucket arrays are backed
//! by [`mem::BucketArrayMemory`]. Layouts defined at compile time can be
//! marked using the [`mem::Uninit`] trait and constructed from a single large
//! buffer of uninitialized reusable memory.

pub(crate) mod hash;
pub(crate) mod mem;
