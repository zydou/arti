//! Shared imports for this crate

pub(crate) use std::cmp;
pub(crate) use std::net::Ipv4Addr;
pub(crate) use std::ops::RangeInclusive;

pub(crate) use ipnet::{IpNet, Ipv4Net};
pub(crate) use itertools::Itertools;
pub(crate) use rangemap::RangeInclusiveMap;

pub(crate) use tor_error::{Bug, internal, into_internal};
pub(crate) use tor_netdoc::{
    //
    doc::netstatus::ConsensusMethod,
    rangemap_mutate_range,
};

pub(crate) use crate::utils::*;
