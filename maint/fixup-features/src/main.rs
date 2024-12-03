//! A quick and dirty command-line tool to enforce certain properties about
//! Arti's Cargo.toml files.
//!
//!
//! Definitions.
//!
//! - An **experimental** feature is one for which we do not provide semver guarantees.
//! - A **non-additive** feature is one whose behavior does something other than
//!   add functionality to its crate.  (For example, building statically or
//!   switching out a default is non-additive.)
//! - The **meta** features are `default`, `full`, `experimental`,
//!   `__is_nonadditive`, and `__is_experimental`.
//! - The **toplevel** features are `default`, `full`, and `experimental`.
//! - A feature A "is reachable from" some feature B if there is a nonempty path from A
//!   to B in the feature graph.
//! - A feature A "directly depends on" some feature B if there is an edge from
//!   A to B in the feature graph.  We also say that feature B "is listed in"
//!   feature A.
//!
//! The properties that we want to enforce are:
//!
//! 1. Every crate has a "full" feature.
//! 2. For every crate within Arti, if we depend on that crate, our "full"
//!    includes that crate's "full".
//! 3. Every feature listed in `experimental` depends on `__is_experimental`.
//!    Every feature that depends on `__is_experimental` is reachable from `experimental`.
//!    Call such features "experimental" features.
//! 4. Call a feature "non-additive" if and only if it depends directly on `__is_nonadditive`.
//!    Every non-meta feature we declare is reachable from "full" or "experimental",
//!    or it is non-additive.
//! 5. Every feature reachable from `default` is reachable from `full`.
//! 6. No non-additive feature is reachable from `full` or `experimental`.
//! 7. No experimental is reachable from `full`.
//! 8. No in-workspace dependency uses the `*` wildcard version.
//! 9. Only unpublished crates may depend on unpublished crates.
//!
//! This tool can edit Cargo.toml files to enforce the rules 1-3
//! automatically.  For rules 4-7, it can annotate any offending features with
//! comments complaining about how they need to be fixed. For rules 8 and 9,
//! it generates warnings.
//!
//! # To use:
//!
//! Run this tool with the top-level Cargo.toml as an argument.
//! Run with `--no-annotate` if you don't want any comments added.
//!
//! # Limitations
//!
//! This is not very efficient, and is not trying to be.

mod changes;
mod graph;

use anyhow::{anyhow, Context, Result};
use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};
use toml_edit::{DocumentMut, Item, Table, Value};

use changes::{Change, Changes};

/// A warning we return from our linter.
///
/// It's a newtype so I don't confuse it with other strings.
#[derive(Debug, Clone)]
struct Warning(String);

/// A dependency from a crate.
///
/// All we care about is the dependency's name, its version,
/// and whether it is optional.
#[derive(Debug, Clone)]
struct Dependency {
    name: String,
    optional: bool,
    version: Option<String>,
}

/// Stored information about a crate.
#[derive(Debug, Clone)]
struct Crate {
    /// name of the crate
    name: String,
    /// path to the crate's Cargo.toml
    toml_file: PathBuf,
    /// Parsed and manipulated copy of Cargo.toml
    toml_doc: DocumentMut,
    /// Parsed and un-manipulated copy of Cargo.toml.
    toml_doc_orig: DocumentMut,
}

/// Information about a crate that we use in other crates.
#[derive(Debug, Clone)]
struct CrateInfo {
    published: bool,
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
        let version = table
            .get("version")
            .and_then(Item::as_value)
            .and_then(Value::as_str)
            .map(str::to_string);

        deps.push(Dependency {
            name: depname.to_string(),
            optional,
            version,
        });
    }

    deps
}

impl Crate {
    /// Try to read a crate's Cargo.toml from a given filename.
    fn load(p: impl AsRef<Path>) -> Result<Self> {
        let toml_file = p.as_ref().to_owned();
        let s = std::fs::read_to_string(&toml_file)?;
        let toml_doc = s.parse::<DocumentMut>()?;
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

    /// Extract information about this crate that other crates will need.
    fn info(&self) -> CrateInfo {
        let package = self
            .toml_doc
            .get("package")
            .expect("no package table!")
            .as_table()
            .expect("[package] was not a table");
        let publish_option = package
            .get("publish")
            .and_then(Item::as_value)
            .and_then(Value::as_bool);
        let published = publish_option != Some(false);
        CrateInfo { published }
    }

    /// Try to fix all the issues we find with a Cargo.toml.  Return a list of warnings.
    fn fix(
        &mut self,
        no_annotate: bool,
        other_crates: &HashMap<String, CrateInfo>,
    ) -> Result<Vec<Warning>> {
        let mut warnings = Vec::new();
        let my_info = self.info();
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
        let graph = graph::FeatureGraph::from_features_table(features)?;
        let mut changes = Changes::default();

        // Build a few sets that will be useful a few times below.
        let all_features: HashSet<_> = graph.all_features().collect();
        let reachable_from_experimental: HashSet<_> =
            graph.all_reachable_from("experimental").collect();
        let nonadditive: HashSet<_> = graph.edges_to("__is_nonadditive").collect();
        let reachable_from_full: HashSet<_> = graph.all_reachable_from("full").collect();

        // Enforce rule 1.  (There is a "Full" feature.)
        if !graph.contains_feature("full") {
            w("full feature does not exist. Adding.".to_string());
            changes.push(Change::AddFeature("full".to_string()));
        }

        // Enforce rule 2. (for every arti crate that we depend on, our 'full' should include that crate's full.
        for dep in dependencies.iter() {
            let wanted = if dep.optional {
                format!("{}?/full", dep.name)
            } else {
                format!("{}/full", dep.name)
            };

            if !graph.contains_edge("full", wanted.as_str()) {
                w(format!("full should contain {}. Fixing.", wanted));
                changes.push(Change::AddExternalEdge("full".to_string(), wanted));
            }
        }

        // Enforce rule 3 (relationship between "experimental" and
        // "__is_experimental")
        let defined_experimental: HashSet<_> = {
            let in_experimental: HashSet<_> = graph.edges_from("experimental").collect();
            let is_experimental: HashSet<_> = graph.edges_to("__is_experimental").collect();

            // Every feature listed in `experimental` depends on `__is_experimental`.
            for f in in_experimental.difference(&is_experimental) {
                if all_features.contains(f) {
                    w(format!("{f} should depend on __is_experimental. Fixing."));
                    changes.push(Change::AddEdge(f.clone(), "__is_experimental".into()));
                }
            }
            // Every feature that depends on `__is_experimental` is reachable from `experimental`.
            for f in is_experimental.difference(&reachable_from_experimental) {
                w(format!("{f} is marked as __is_experimental, but is not reachable from experimental. Fixing."));
                changes.push(Change::AddEdge("experimental".into(), f.clone()))
            }

            &in_experimental | &is_experimental
        };

        // Enforce rule 4: Every non-meta feature is reachable from full, or
        // from experimental, or is nonadditive.
        {
            let complaint: &str = "# XX\x58X Mark as full, experimental, or non-additive!\n";

            let all_features: HashSet<_> = graph.all_features().collect();
            let meta: HashSet<_> = [
                "__is_nonadditive",
                "__is_experimental",
                "full",
                "default",
                "experimental",
            ]
            .into_iter()
            .map(String::from)
            .collect();

            let mut not_found = all_features;
            for set in [
                &reachable_from_full,
                &meta,
                &reachable_from_experimental,
                &nonadditive,
            ] {
                not_found = &not_found - set;
            }

            for f in not_found {
                w(format!(
                    "{f} is not experimental, reachable from full, or nonadditive."
                ));
                changes.push(Change::Annotate(f.clone(), complaint.to_string()));
            }
        }

        // 5. Every feature reachable from `default` is reachable from `full`.
        {
            let complaint = "# XX\x58X This is reachable from 'default', but from 'full'.\n";
            let default: HashSet<_> = graph.edges_from("default").collect();
            for f in default.difference(&reachable_from_full) {
                if all_features.contains(f) {
                    w(format!("{f} is reachable from default, but not from full."));
                    changes.push(Change::Annotate(f.clone(), complaint.to_string()));
                }
            }
        }

        // 6. No non-additive feature is reachable from `full` or
        //    `experimental`.
        {
            let complaint = "# XX\x58X This is non-additive, but reachable from 'full'.\n";
            for f in nonadditive.intersection(&reachable_from_full) {
                w(format!("nonadditive feature {f} is reachable from full."));
                changes.push(Change::Annotate(f.clone(), complaint.to_string()));
            }
            let complaint = "# XX\x58X This is non-additive, but reachable from 'experimental'.\n";
            for f in nonadditive.intersection(&reachable_from_experimental) {
                w(format!(
                    "nonadditive feature {f} is reachable from experimental."
                ));
                changes.push(Change::Annotate(f.clone(), complaint.to_string()));
            }
        }

        // 7. No experimental is reachable from `full`.
        {
            let complaint = "# XX\x58X This is experimental, but reachable from 'full'.\n";
            for f in reachable_from_full.intersection(&defined_experimental) {
                w(format!("experimental feature {f} is reachable from full!"));
                changes.push(Change::Annotate(f.clone(), complaint.to_string()));
            }
        }

        // 8. Every dependency is a real version.
        for dep in &dependencies {
            match dep.version.as_deref() {
                Some("*") => w(format!(
                    "Dependency for {:?} is given as version='*'",
                    &dep.name
                )),
                None => w(format!(
                    "No version found for dependency on {:?}",
                    &dep.name
                )),
                _ => {}
            }
        }

        // Enforce rule 9. (every arti crate we depend on is published if
        // we are published.)
        if my_info.published {
            println!("in {}", self.name);
            for dep in &dependencies {
                match other_crates.get(&dep.name) {
                    None => w(format!(
                        "Dependency on crate {:?}, which I could not find.",
                        &dep.name
                    )),
                    Some(info) if !info.published => w(format!(
                        "Dependency on crate {:?}, which has `publish = false`",
                        &dep.name
                    )),
                    _ => {}
                }
            }
        }

        if no_annotate {
            changes.drop_annotations();
        }
        // We have to look this up again, or else it isn't &mut.
        let features = self
            .toml_doc
            .get_mut("features")
            .ok_or_else(|| anyhow!("I thought we added 'features' earlier!"))?
            .as_table_mut()
            .ok_or_else(|| anyhow!("Features was not table"))?;
        changes.apply(features)?;

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
fn list_crate_paths(
    toplevel: impl AsRef<Path>,
    exclusion_prefixes: &[String],
) -> Result<Vec<String>> {
    let s = std::fs::read_to_string(toplevel.as_ref())?;
    let toml_doc = s.parse::<DocumentMut>()?;
    Ok(toml_doc["workspace"]["members"]
        .as_array()
        .ok_or_else(|| anyhow!("workplace.members is not an array!?"))?
        .iter()
        .map(|v| {
            v.as_str()
                .expect("Some member of workplace.members is not a string!?")
                .to_owned()
        })
        .filter(|s| {
            // Iterate through all exclusion prefixes and check if there isn't one that `s` starts with.
            !exclusion_prefixes
                .iter()
                .any(|prefix| s.starts_with(prefix))
        })
        .collect())
}

fn main() -> Result<()> {
    let mut pargs = pico_args::Arguments::from_env();
    const HELP: &str =
        "fixup-features [--no-annotate] [--exclude <PREFIX1> --exclude <PREFIX2> ...] <toplevel Cargo.toml>";

    if pargs.contains(["-h", "--help"]) {
        println!("{}", HELP);
        return Ok(());
    }
    let no_annotate = pargs.contains("--no-annotate");
    let exclusion_prefixes: Vec<String> = pargs.values_from_str("--exclude").unwrap();
    let toplevel_toml_file: PathBuf = pargs.free_from_str()?;
    if !pargs.finish().is_empty() {
        println!("{}", HELP);
        return Ok(());
    }

    let toplevel_dir = toplevel_toml_file
        .parent()
        .expect("How is your Cargo.toml file `/`?")
        .to_path_buf();
    let mut crates = Vec::new();
    let mut crate_info = HashMap::new();
    for p in list_crate_paths(&toplevel_toml_file, &exclusion_prefixes)? {
        let mut crate_toml_path = toplevel_dir.clone();
        crate_toml_path.push(p);
        crate_toml_path.push("Cargo.toml");
        let cr =
            Crate::load(&crate_toml_path).with_context(|| format!("In {crate_toml_path:?}"))?;
        crate_info.insert(cr.name.clone(), cr.info());
        crates.push(cr);
    }

    for cr in crates.iter_mut() {
        for w in cr
            .fix(no_annotate, &crate_info)
            .with_context(|| format!("In {}", cr.name))?
        {
            println!("{}: {}", cr.name, w.0);
        }
        cr.save_if_changed()?;
    }

    Ok(())
}
