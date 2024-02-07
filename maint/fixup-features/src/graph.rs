//! Graph manipulation code
//!
//! I had hoped to use petgraph, but it is optimized for efficiency over
//! usability, and I got lost in a maze of indices.

use anyhow::{anyhow, Result};
use std::collections::{HashMap, HashSet};
use std::hash::Hash;

/// Given a hashmap representing a binary relationship, compute its transitive closure.
fn transitive_closure<K: Hash + Eq + PartialEq + Clone>(
    inp: &HashMap<K, HashSet<K>>,
) -> HashMap<K, HashSet<K>> {
    let mut out = inp.clone();
    let max_iters = inp.len();
    for _ in 0..max_iters {
        let mut new_out = out.clone();
        for (k, vs) in out.iter() {
            let new_vs = new_out
                .get_mut(k)
                .expect("That key should have been there when I cloned it...");
            for v in vs.iter() {
                if let Some(vv) = out.get(v) {
                    new_vs.extend(vv.iter().cloned());
                }
            }
        }
        if out == new_out {
            break;
        } else {
            out = new_out;
        }
    }
    out
}

/// Given a hashmap representing a binary relationship, invert it.
fn invert<K: Hash + Eq + PartialEq + Clone>(
    inp: &HashMap<K, HashSet<K>>,
) -> HashMap<K, HashSet<K>> {
    let mut out: HashMap<K, HashSet<K>> = HashMap::new();
    for (k, vs) in inp.iter() {
        for v in vs {
            out.entry(v.clone()).or_default().insert(k.clone());
        }
    }
    out
}

/// A representation of which features depend on what.
#[derive(Clone, Debug, Default)]
pub struct FeatureGraph {
    /// List of all features.
    all_features: HashSet<String>,
    /// Adjacency map: for each feature F, `depends_on[F]` includes G if F
    /// directly depends on G.
    depends_on: HashMap<String, HashSet<String>>,
    /// Inverse adjacency map.
    depended_on_by: HashMap<String, HashSet<String>>,
    /// Transitive closure of the adjacency map.
    reachable_from: HashMap<String, HashSet<String>>,
}

impl FeatureGraph {
    /// Convert a toml `[features]` section into a [`FeatureGraph`].
    pub fn from_features_table(features: &toml_edit::Table) -> Result<Self> {
        let mut depends_on = HashMap::new();
        for (k, vs) in features.iter() {
            let mut d = HashSet::new();
            for v in vs
                .as_array()
                .ok_or_else(|| anyhow!("features.{} was not an array", k))?
            {
                let v = v
                    .as_str()
                    .ok_or_else(|| anyhow!("features.{} contained a non-string", k))?;
                d.insert(v.to_string());
            }
            depends_on.insert(k.to_string(), d);
        }
        let all_features = depends_on.keys().cloned().collect();
        let reachable_from = transitive_closure(&depends_on);
        let depended_on_by = invert(&depends_on);
        Ok(Self {
            all_features,
            depends_on,
            depended_on_by,
            reachable_from,
        })
    }

    pub fn all_features(&self) -> impl Iterator<Item = String> + '_ {
        self.depends_on.keys().cloned()
    }

    pub fn contains_feature(&self, feature: &str) -> bool {
        self.all_features.contains(feature)
    }

    pub fn contains_edge(&self, from: &str, to: &str) -> bool {
        match self.depends_on.get(from) {
            Some(fs) => fs.contains(to),
            None => false,
        }
    }

    pub fn all_reachable_from(&self, feature: &str) -> impl Iterator<Item = String> + '_ {
        match self.reachable_from.get(feature) {
            Some(set) => itertools::Either::Left(set.iter().cloned()),
            None => itertools::Either::Right(std::iter::empty()),
        }
    }

    /// Return all the features that `feature` depends on.  Return an empty iterator if
    /// it has no dependencies, or is not in this map.
    pub fn edges_from(&self, feature: &str) -> impl Iterator<Item = String> + '_ {
        match self.depends_on.get(feature) {
            Some(set) => itertools::Either::Left(set.iter().cloned()),
            None => itertools::Either::Right(std::iter::empty()),
        }
    }

    /// Return all the features that depend on `feature` directly.  Return an empty iterator if
    /// it has no dependencies, or is not in this map.
    pub fn edges_to(&self, feature: &str) -> impl Iterator<Item = String> + '_ {
        match self.depended_on_by.get(feature) {
            Some(set) => itertools::Either::Left(set.iter().cloned()),
            None => itertools::Either::Right(std::iter::empty()),
        }
    }
}
