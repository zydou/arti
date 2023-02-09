//! Manage a set of private keys for a client to authenticate to one or more
//! onion services.

use std::{collections::HashMap, sync::Mutex};

use tor_hscrypto::pk::{ClientSecretKeys, HsId};

pub(crate) struct Keys {
    /// The
    keys: Mutex<HashMap<HsId, ClientSecretKeys>>,
}
