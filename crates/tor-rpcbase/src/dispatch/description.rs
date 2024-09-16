//! Types and code for describing our type-based dispatch system.

use std::collections::{BTreeMap, BTreeSet};

use serde::Serialize;

use crate::{method::method_info_by_typeid, MethodInfo_, NoUpdates};

/// A table describing, for a single RPC method,
/// which types it expects and returns, and which objects it applies to.
///
/// This is, for now, a serialize-only type; it does nothing else.
///
/// See [`RpcDispatchInformation`] for caveats about type names.
#[derive(Serialize, Debug, Clone)]
struct MethodDescription {
    /// The type representing an invocation of this method.
    ///
    /// Its fields are the method's parameters.
    method_type: String,
    /// The type that this method returns on successful completion.
    output_type: String,
    /// The type (if any) that this method delivers as an incremental status update.
    update_type: Option<String>,
    /// A list of the types of Objects that this method can be applied to.
    applies_to_object_types: BTreeSet<String>,
}

/// A table describing the the set of RPC methods available,
/// which types they expect and return, and which objects they apply to.
///
/// This is, for now, a serialize-only type; it does nothing else.
///
/// All "type names" in this object refer to a Rust type in Arti.
/// These Rust types are mainly useful for finding the relevant types
/// in the generated Arti documentation.
/// They are not guaranteed to be stable across Arti versions:
/// for example, we might rename a type, or put it in a different module or crate.
/// They are not guaranteed to be stable across Rust versions:
/// see the caveats in [`std::any::type_name`].
#[derive(Serialize, Debug, Clone)]
pub struct RpcDispatchInformation {
    /// A map from RPC method name (such as "arti:foo") to a description of that method.
    methods: BTreeMap<String, MethodDescription>,

    /// A map from an object type to a list of the types that object can delegate to.
    delegations: BTreeMap<String, BTreeSet<String>>,
}

impl super::DispatchTable {
    /// Return a description for all of the RPC methods available,
    /// which types they expect and return, and which objects they apply to.
    ///
    /// Currently, the resulting object is good for nothing but serialization.
    pub fn dispatch_information(&self) -> RpcDispatchInformation {
        let mut methods = BTreeMap::new();
        for invoker_ent in self.map.values() {
            let Some(method_info) = method_info_by_typeid(invoker_ent.invoker.method_type()) else {
                continue; // This isn't an RpcMethod.
            };

            let rpc_method_name = method_info.method_name.to_owned();
            let (object_type_name, method_type_name) =
                invoker_ent.invoker.object_and_method_type_names();
            let description = methods
                .entry(rpc_method_name)
                .or_insert_with(|| MethodDescription::new(method_type_name, method_info));
            description.push_object_type(object_type_name);
        }

        let mut delegations = BTreeMap::new();
        for note in inventory::iter::<DelegationNote>() {
            let set = delegations
                .entry((note.from_type_name)().to_string())
                .or_insert_with(BTreeSet::new);
            set.insert((note.to_type_name)().to_string());
        }

        RpcDispatchInformation {
            methods,
            delegations,
        }
    }
}

impl MethodDescription {
    /// Construct a new `MethodDescription`.
    fn new(method_type_name: &str, info: &MethodInfo_) -> Self {
        let method_type_name = method_type_name.to_owned();
        let output_type_name = (info.output_name)().to_owned();
        let update_type_name = {
            let name = (info.update_name)();
            if name == std::any::type_name::<NoUpdates>() {
                None
            } else {
                Some(name.to_owned())
            }
        };

        MethodDescription {
            method_type: method_type_name,
            output_type: output_type_name,
            update_type: update_type_name,
            applies_to_object_types: Default::default(),
        }
    }

    /// Add `object_type_name` to the list of object types this method applies to.
    fn push_object_type(&mut self, object_type_name: &str) {
        self.applies_to_object_types
            .insert(object_type_name.to_owned());
    }
}

/// Helper to implement RpcDispatchInformation.
#[derive(Debug)]
#[doc(hidden)]
#[allow(clippy::exhaustive_structs)]
pub struct DelegationNote {
    /// Name of the type we're delegating from.
    ///
    /// (We use a fn() here since std::any::type_name isn't yet const.)
    pub from_type_name: fn() -> &'static str,
    /// Name of the type we're delegating to.
    pub to_type_name: fn() -> &'static str,
}
inventory::collect!(DelegationNote);

/// Helper: Declare that `$from_type` (which must implement `Object`)
/// can delegate to `$to_type` (which also must implement `Object`).
///
/// This declaration is used only to help implement `RpcDispatchInformation`.
#[macro_export]
#[doc(hidden)]
macro_rules! register_delegation_note {
    { $from_type:ty, $to_type:ty } => {
        $crate::inventory::submit!{$crate::DelegationNote {
            from_type_name: std::any::type_name::<$from_type>,
            to_type_name: std::any::type_name::<$to_type>,
        }}
    }
}
