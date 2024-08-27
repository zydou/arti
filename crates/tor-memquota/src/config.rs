//! Configuration (private module)

use crate::internal_prelude::*;

/// We want to support at least this many participants with a cache each
///
/// This is not a recommended value; it's probably too lax
const MIN_MAX_PARTICIPANTS: usize = 10;

/// Minimum hysteresis
///
/// This is not a recommended value; it's probably far too lax for sensible performance!
const MAX_LOW_WATER_RATIO: f32 = 0.98;

define_derive_deftly! {
    /// Define setters on the builder for every field of type `Qty`
    ///
    /// The field type must be spelled precisely that way:
    /// we use `approx_equal(...)`.
    QtySetters:

    impl ConfigBuilder {
      $(
        ${when approx_equal($ftype, { Option::<Qty> })}

        ${fattrs doc}
        ///
        /// (Setter method.)
        pub fn $fname(&mut self, value: usize) -> &mut Self {
            self.$fname = Some(Qty(value));
            self
        }
      )
    }
}

/// Configuration for a memory data tracker
///
/// This is where the quota is specified.
///
/// This type can also represent
/// "memory quota tracking is not supposed to be enabled".
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct Config(pub(crate) IfEnabled<ConfigInner>);

/// Configuration for a memory data tracker (builder)
//
// We could perhaps generate this with `#[derive(Builder)]` on `CnfigInner`,
// but derive-builder would need a *lot* of overriding attributes;
// and, doing it this way lets us write separate docs about
// the invariants on our fields, which are not the same as those in the builder.
#[derive(Serialize, Deserialize, Debug, Clone, Eq, PartialEq, Default, Deftly)]
#[derive_deftly(tor_config::Flattenable, QtySetters)]
pub struct ConfigBuilder {
    /// Maximum memory usage tolerated before reclamation starts
    ///
    /// Setting this to `usize::MAX` disables the memory quota
    /// (and that's the default).
    ///
    /// Note that this is not a hard limit.
    /// See Approximate in [the overview](crate).
    max: Option<Qty>,

    /// Reclamation will stop when memory use is reduced to below this value
    ///
    /// Default is 75% of the maximum.
    low_water: Option<Qty>,
}

/// Configuration, if enabled
#[derive(Debug, Clone, Eq, PartialEq, Deftly)]
pub(crate) struct ConfigInner {
    /// Maximum memory usage
    ///
    /// Guaranteed not to be `MAX`, since we're anbled
    pub(crate) max: Qty,

    /// Low water
    ///
    /// Guaranteed to be enough lower than `max`
    pub(crate) low_water: Qty,
}

impl Config {
    /// Start building a [`Config`]
    ///
    /// Returns a fresh default [`ConfigBuilder`].
    pub fn builder() -> ConfigBuilder {
        ConfigBuilder::default()
    }
}

impl ConfigBuilder {
    /// Builds a new `Config` from a builder
    ///
    /// Returns an error unless at least `max` has been specified,
    /// or if the fields values are invalid or inconsistent.
    pub fn build(&self) -> Result<Config, ConfigBuildError> {
        let max = self.max.unwrap_or(Qty::MAX);

        if max == Qty::MAX {
            if self.low_water.is_some() {
                return Err(ConfigBuildError::Inconsistent {
                    fields: vec!["max".into(), "low_water".into()],
                    problem: "low_water supplied, but max omitted".into(),
                });
            };
            return Ok(Config(IfEnabled::Noop));
        }

        let enabled = EnabledToken::new_if_compiled_in()
            //
            .ok_or_else(|| ConfigBuildError::NoCompileTimeSupport {
                field: "max".into(),
                problem: "cargo feature `memquota` disabled (in tor-memquota crate)".into(),
            })?;

        let low_water = self.low_water.unwrap_or_else(
            //
            || Qty((*max as f32 * 0.75) as _),
        );

        let config = ConfigInner { max, low_water };

        let min_low_water = crate::mtracker::MAX_CACHE.as_usize() * MIN_MAX_PARTICIPANTS;
        if *config.low_water < min_low_water {
            return Err(ConfigBuildError::Invalid {
                field: "low_water".into(),
                problem: format!("must be at least {min_low_water}"),
            });
        }

        let ratio: f32 = *config.low_water as f32 / *config.max as f32;
        if ratio > MAX_LOW_WATER_RATIO {
            return Err(ConfigBuildError::Inconsistent {
                fields: vec!["low_water".into(), "max".into()],
                problem: format!(
 "low_water / max = {ratio}; must be <= {MAX_LOW_WATER_RATIO}, ideally considerably lower"
                ),
            });
        }

        Ok(Config(IfEnabled::Enabled(config, enabled)))
    }
}

#[cfg(test)]
mod test {
    // @@ begin test lint list maintained by maint/add_warning @@
    #![allow(clippy::bool_assert_comparison)]
    #![allow(clippy::clone_on_copy)]
    #![allow(clippy::dbg_macro)]
    #![allow(clippy::mixed_attributes_style)]
    #![allow(clippy::print_stderr)]
    #![allow(clippy::print_stdout)]
    #![allow(clippy::single_char_pattern)]
    #![allow(clippy::unwrap_used)]
    #![allow(clippy::unchecked_duration_subtraction)]
    #![allow(clippy::useless_vec)]
    #![allow(clippy::needless_pass_by_value)]
    //! <!-- @@ end test lint list maintained by maint/add_warning @@ -->

    use super::*;
    use serde_json::json;

    #[test]
    fn configs() {
        let chk_ok_raw = |j, c| {
            let b: ConfigBuilder = serde_json::from_value(j).unwrap();
            assert_eq!(b.build().unwrap(), c);
        };
        #[cfg(feature = "memquota")]
        let chk_ok = |j, max, low_water| {
            const M: usize = 1024 * 1024;

            let exp = IfEnabled::Enabled(
                ConfigInner {
                    max: Qty(max * M),
                    low_water: Qty(low_water * M),
                },
                EnabledToken::new(),
            );

            chk_ok_raw(j, Config(exp));
        };
        let chk_err = |j, exp| {
            let b: ConfigBuilder = serde_json::from_value(j).unwrap();
            let got = b.build().unwrap_err().to_string();

            #[cfg(not(feature = "memquota"))]
            if got.contains("cargo feature `memquota` disabled") {
                return;
            }

            assert!(got.contains(exp), "in {exp:?} in {got:?}");
        };
        #[cfg(not(feature = "memquota"))]
        let chk_ok = |j, max, low_water| {
            chk_err(j, "UNSUPPORTED");
        };

        chk_ok(json! {{ "max": "8 MiB" }}, 8, 6);
        chk_ok(json! {{ "max": "8 MiB", "low_water": "4 MiB" }}, 8, 4);
        chk_ok_raw(json! {{ }}, Config(IfEnabled::Noop));

        chk_err(
            json! {{ "low_water": "4 MiB" }},
            "low_water supplied, but max omitted",
        );
        chk_err(
            json! {{ "max": "8 MiB", "low_water": "8 MiB" }},
            "inconsistent: low_water / max",
        );
    }
}
