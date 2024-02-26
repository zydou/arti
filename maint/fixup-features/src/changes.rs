//! Remember a list of changes to a Cargo.toml file

use anyhow::{anyhow, Result};
use toml_edit::{Array, Item, Table, Value};

#[derive(Debug, Clone, Default)]
pub struct Changes {
    changes: Vec<Change>,
}

#[derive(Debug, Clone)]
pub enum Change {
    AddFeature(String),
    AddEdge(String, String),
    AddExternalEdge(String, String),
    Annotate(String, String),
}

fn value_is_str(value: &Value, string: &str) -> bool {
    matches! {
        value, Value::String(s) if s.value() == string
    }
}

impl Change {
    fn apply(&self, features: &mut Table) -> Result<()> {
        match self {
            Change::AddFeature(feature_name) => match features.get(feature_name) {
                Some(_) => {} // nothing to do.
                None => {
                    assert!(!feature_name.contains('/'), "/ in {feature_name}");
                    features.insert(feature_name, Item::Value(Value::Array(Array::new())));
                }
            },
            Change::AddEdge(from, to) => {
                // Make sure "to" is there.
                Change::AddFeature(to.to_string()).apply(features)?;
                Change::AddExternalEdge(from.to_string(), to.to_string()).apply(features)?;
            }
            Change::AddExternalEdge(from, to) => {
                // Make sure "from" is there.
                Change::AddFeature(from.to_string()).apply(features)?;
                assert!(!from.contains('/'), "/ in {from}");
                let array = features
                    .get_mut(from)
                    .expect("but we just tried to add {from}!")
                    .as_array_mut()
                    .ok_or_else(|| anyhow!("features.{from} wasn't an array!"))?;
                if !array.iter().any(|val| value_is_str(val, to)) {
                    array.push(to);
                }
            }
            Change::Annotate(feature_name, annotation) => {
                if features.get(feature_name).is_none() {
                    return Err(anyhow!(
                        "no such feature as {feature_name} to annotate with {annotation}"
                    ));
                }
                let mut key = features.key_mut(feature_name).expect("key not found!?");
                let decor = key.leaf_decor_mut();
                let prefix = match decor.prefix() {
                    Some(r) => r.as_str().expect("prefix not a string"), // (We can't proceed if the prefix decor is not a string.)
                    None => "",
                };
                if !prefix.contains(annotation) {
                    let mut new_prefix: String = prefix.to_string();
                    new_prefix.push('\n');
                    new_prefix.push_str(annotation);
                    decor.set_prefix(new_prefix);
                }
            }
        }
        Ok(())
    }
}

impl Changes {
    pub fn push(&mut self, change: Change) {
        self.changes.push(change);
    }
    pub fn drop_annotations(&mut self) {
        self.changes
            .retain(|change| !matches!(change, Change::Annotate(_, _)));
    }
    pub fn apply(&self, features: &mut Table) -> Result<()> {
        self.changes
            .iter()
            .try_for_each(|change| change.apply(features))
    }
}
