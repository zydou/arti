//! Shared imports for this crate

pub(crate) use std::cell::Cell;
pub(crate) use std::cmp::{self, Ordering};
pub(crate) use std::fmt::{self, Debug};
pub(crate) use std::net::Ipv4Addr;
pub(crate) use std::ops::{RangeBounds, RangeInclusive};

pub(crate) use ipnet::{IpNet, Ipv4Net};
pub(crate) use itertools::{Itertools, chain};
pub(crate) use paste::paste;
pub(crate) use rangemap::RangeInclusiveMap;

pub(crate) use tor_error::{Bug, internal, into_internal};
pub(crate) use tor_netdoc::{
    //
    doc::netstatus::ConsensusMethod,
    rangemap_mutate_range,
};

pub(crate) use crate::utils::*;
