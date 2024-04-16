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
    QtySetters =

    impl $< $ttype Builder > {
      $(
        ${when approx_equal($ftype, Qty)}

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
#[derive(Debug, Clone, Builder, Eq, PartialEq, Deftly)]
#[derive_deftly(QtySetters)]
#[builder(build_fn(private, name = "build_unvalidated", error = "ConfigBuildError"))]
#[builder(derive(Serialize, Deserialize, Debug, Deftly, Eq, PartialEq))]
#[builder_struct_attr(derive_deftly(tor_config::Flattenable))]
pub struct Config {
    /// Maximum memory usage tolerated before reclamation starts
    ///
    /// Note that this is not a hard limit.
    /// See Approximate in [the overview](crate).
    ///
    ///
    #[builder(setter(custom))]
    pub(crate) max: Qty,

    /// Reclamation will stop when memory use is reduced to below this value
    ///
    /// Default is 75% of the maximum.
    #[builder(setter(custom))]
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
        let mut builder = self.clone();
        if let (Some(max), None) = (builder.max, builder.low_water) {
            builder.low_water = Some(Qty((*max as f32 * 0.75) as _));
        }
        let config = builder.build_unvalidated()?;

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
 "low_water / max = {ratio}; must be < {MAX_LOW_WATER_RATIO}, and should be lower than that"
                ),
            });
        }

        Ok(config)
    }
}
