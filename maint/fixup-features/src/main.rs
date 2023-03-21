//! A quick and dirty command-line tool to enforce certain properties about
//! Arti's Cargo.toml files.
//!
//! The properties that we want to enforce are:
//!
//! 1. Every crate has a "full" feature.
//! 2. For every crate within Arti, if we depend on that crate, our "full"
//!    includes that crate's "full".
//! 3. Every feature we declare is reachable from "full", "experimental", or
//!    "__nonadditive"--except for "full", "experimental", "__nonadditive", and
//!    "default". property automatically.)
//! 4. No feature we declare is reachable from more than one of "full",
//!    "experimental", or "__nonadditive".
//!
//! This tool can edit Cargo.toml files to enforce the rules 1 and 2
//! automatically.  For rule 3, it can annotate any offending features with
//! comments complaining about how they need to be included in one of the
//! top-level features.
//!
//! # To use:
//!
//! Run this tool with the top-level Cargo.toml as an argument.
//!
//! # Limitations
//!
//! This is not very efficient, and is not trying to be.

use anyhow::{anyhow, Context, Result};
use std::collections::{HashMap, HashSet};
use std::hash::Hash;
use std::path::{Path, PathBuf};
use toml_edit::{Array, Document, Item, Table, Value};

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

/// A warning we return from our linter.
///
/// It's a newtype so I don't confuse it with other strings.
#[derive(Debug, Clone)]
struct Warning(String);

/// A dependency from a crate.  
///
/// All we care about is the dependency's name, and whether it is optional.
#[derive(Debug, Clone)]
struct Dependency {
    name: String,
    optional: bool,
}

/// Stored information about a crate.
#[derive(Debug, Clone)]
struct Crate {
    /// name of the crate
    name: String,
    /// path to the crate's Cargo.toml
    toml_file: PathBuf,
    /// Parsed and manipulated copy of Cargo.toml
    toml_doc: Document,
    /// Pared and unmanipulated copy of Cargo.toml.
    toml_doc_orig: Document,
}

/// Given a `[dependencies]` table from a Cargo.toml, find all of the
/// dependencies that are also part of arti.
///
/// We do this by looking for ones that have `path` set.
fn arti_dependencies(dependencies: &Table) -> Vec<Dependency> {
    let mut deps = Vec::new();

    for (depname, info) in dependencies {
        let table = match info {
            // Cloning is "inefficient", but we don't care.
            Item::Value(Value::InlineTable(info)) => info.clone().into_table(),
            Item::Table(info) => info.clone(),
            _ => continue, // Not part of arti.
        };
        if !table.contains_key("path") {
            continue; // Not part of arti.
        }
        let optional = table
            .get("optional")
            .and_then(Item::as_value)
            .and_then(Value::as_bool)
            .unwrap_or(false);

        deps.push(Dependency {
            name: depname.to_string(),
            optional,
        });
    }

    deps
}

/// A complaint that we add to features which are not reachable according to
/// rule 3.
const COMPLAINT: &str = "# XX\x58X Add this to a top-level feature!\n";

impl Crate {
    /// Try to read a crate's Cargo.toml from a given filename.
    fn load(p: impl AsRef<Path>) -> Result<Self> {
        let toml_file = p.as_ref().to_owned();
        let s = std::fs::read_to_string(&toml_file)?;
        let toml_doc = s.parse::<Document>()?;
        let toml_doc_orig = toml_doc.clone();
        let name = toml_doc["package"]["name"]
            .as_str()
            .ok_or_else(|| anyhow!("package.name was not a string"))?
            .to_string();
        Ok(Crate {
            name,
            toml_file,
            toml_doc,
            toml_doc_orig,
        })
    }

    /// Try to fix all the issues we find with a Cargo.toml.  Return a list of warnings.
    fn fix(&mut self) -> Result<Vec<Warning>> {
        let mut warnings = Vec::new();
        let mut w = |s| warnings.push(Warning(s));
        let dependencies = self
            .toml_doc
            .entry("dependencies")
            .or_insert_with(|| Item::Table(Table::new()));
        let dependencies = arti_dependencies(
            dependencies
                .as_table()
                .ok_or_else(|| anyhow!("dependencies was not a table"))?,
        );
        let features = self
            .toml_doc
            .entry("features")
            .or_insert_with(|| Item::Table(Table::new()))
            .as_table_mut()
            .ok_or_else(|| anyhow!("Features was not table"))?;
        let _ = features
            .entry("full")
            .or_insert_with(|| Item::Value(Value::Array(Array::new())));

        let features_map: Result<HashMap<String, HashSet<String>>> = features
            .iter()
            .map(|(k, v)| {
                Ok((
                    k.to_string(),
                    v.as_array()
                        .ok_or_else(|| anyhow!("features.{} was not an array!", k))?
                        .iter()
                        .filter_map(|v| v.as_str())
                        .map(|s| s.to_string())
                        .collect(),
                ))
            })
            .collect();
        let features_map = features_map?;

        let all_features: HashSet<String> = features_map.keys().cloned().collect();

        let reachable = transitive_closure(&features_map);
        // Enforce rule 1.  (There is a "Full" feature.)
        if !reachable.contains_key("full") {
            w("full feature does not exist. Adding.".to_string());
            // Actually, we fixed it already, by adding it to `features` above.
        }

        let empty = HashSet::new();
        let full = reachable.get("full").unwrap_or(&empty);
        let experimental = reachable.get("experimental").unwrap_or(&empty);
        let nonadditive = reachable.get("__nonadditive").unwrap_or(&empty);
        let reachable_from_toplevel: HashSet<_> = [full, experimental, nonadditive]
            .iter()
            .flat_map(|s| s.iter())
            .cloned()
            .collect();

        // Enforce rule 4: No feature we declare may be reachable from two of full,
        // experimental, and __nonadditive.
        for item in experimental.intersection(full) {
            w(format!("{item} reachable from both full and experimental"));
        }
        for item in nonadditive.intersection(full) {
            w(format!("{item} reachable from both full and nonadditive"));
        }
        for item in nonadditive.intersection(experimental) {
            w(format!(
                "{item} reachable from both experimental and nonadditive"
            ));
        }

        // Enforce rule 3: Every feature we declare must be reachable from full,
        // experimental, or __nonadditive, except for those
        // top-level features, and "default".
        for feat in all_features.difference(&reachable_from_toplevel) {
            if ["full", "default", "experimental", "__nonaddtive"].contains(&feat.as_str()) {
                continue;
            }
            w(format!(
                "{feat} not reachable from full, experimental, or __nonadditive. Marking."
            ));

            let decor = features
                .key_decor_mut(feat.as_str())
                .expect("No decor on key!"); // (There should always be decor afaict.)
            let prefix = match decor.prefix() {
                Some(r) => r.as_str().expect("prefix not a string"), // (We can't proceed if the prefix decor is not a string.)
                None => "",
            };
            if !prefix.contains(COMPLAINT) {
                let mut new_prefix: String = prefix.to_string();
                new_prefix.push('\n');
                new_prefix.push_str(COMPLAINT);
                decor.set_prefix(new_prefix);
            }
        }

        // Enforce rule 3: for every arti crate that we depend on, our 'full' should include that crate's full.
        let mut add_to_full = HashSet::new();
        for dep in dependencies.iter() {
            let wanted = if dep.optional {
                format!("{}?/full", dep.name)
            } else {
                format!("{}/full", dep.name)
            };

            if !full.contains(wanted.as_str()) {
                w(format!("full should contain {}. Fixing.", wanted));
                add_to_full.insert(wanted);
            }
        }
        features
            .get_mut("full")
            .expect("We checked for the `full` feature, but now it isn't there!")
            .as_array_mut()
            .expect("Somehow `full` is not an array any more!")
            .extend(add_to_full);

        Ok(warnings)
    }

    /// If we made changes to this crate's cargo.toml, flush it to disk.
    fn save_if_changed(&self) -> Result<()> {
        let old_text = self.toml_doc_orig.to_string();
        let new_text = self.toml_doc.to_string();
        if new_text != old_text {
            println!("{} changed. Replacing.", self.name);
            let tmpname = self.toml_file.with_extension("toml.tmp");
            std::fs::write(&tmpname, new_text.as_str())?;
            std::fs::rename(&tmpname, &self.toml_file)?;
        }
        Ok(())
    }
}

/// Look at a toplevel Cargo.toml and find all of the paths in workplace.members
fn list_crate_paths(toplevel: impl AsRef<Path>) -> Result<Vec<String>> {
    let s = std::fs::read_to_string(toplevel.as_ref())?;
    let toml_doc = s.parse::<Document>()?;
    Ok(toml_doc["workspace"]["members"]
        .as_array()
        .ok_or_else(|| anyhow!("workplace.members is not an array!?"))?
        .iter()
        .map(|v| {
            v.as_str()
                .expect("Some member of workplace.members is not a string!?")
                .to_owned()
        })
        .collect())
}

fn main() -> Result<()> {
    let args: Vec<_> = std::env::args().collect();
    if args.len() != 1 {
        println!("We expect a single argument: The top-level Cargo.toml file.");
        return Ok(());
    }
    let toplevel_toml_file = PathBuf::from(&args[1]);
    let toplevel_dir = toplevel_toml_file
        .parent()
        .expect("How is your Cargo.toml file `/`?")
        .to_path_buf();
    let mut crates = Vec::new();
    for p in list_crate_paths(&toplevel_toml_file)? {
        let mut crate_toml_path = toplevel_dir.clone();
        crate_toml_path.push(p);
        crate_toml_path.push("Cargo.toml");
        crates.push(
            Crate::load(&crate_toml_path).with_context(|| format!("In {crate_toml_path:?}"))?,
        );
    }

    for cr in crates.iter_mut() {
        for w in cr.fix().with_context(|| format!("In {}", cr.name))? {
            println!("{}: {}", cr.name, w.0);
        }
        cr.save_if_changed()?;
    }

    Ok(())
}
