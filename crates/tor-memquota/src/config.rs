//! Configuration (private module)

use std::sync::LazyLock;

use sysinfo::{MemoryRefreshKind, System};
use tracing::warn;

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
        ${when approx_equal($ftype, { Option::<ExplicitOrAuto<Qty>> })}

        ${fattrs doc}
        ///
        /// (Setter method.)
        // We use `value: impl Into<ExplicitOrAuto<usize>>` to avoid breaking users who used the
        // previous `value: usize`. But this isn't 100% foolproof, for example if a user used
        // `$fname(foo.into())`, which will fail type inference.
        pub fn $fname(&mut self, value: impl Into<ExplicitOrAuto<usize>>) -> &mut Self {
            self.$fname = Some(value.into().map(Qty));
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
// We could perhaps generate this with `#[derive(Builder)]` on `ConfigInner`,
// but derive-builder would need a *lot* of overriding attributes;
// and, doing it this way lets us write separate docs about
// the invariants on our fields, which are not the same as those in the builder.
#[derive(Serialize, Deserialize, Debug, Clone, Eq, PartialEq, Default, Deftly)]
#[derive_deftly(tor_config::Flattenable, QtySetters)]
pub struct ConfigBuilder {
    /// Maximum memory usage tolerated before reclamation starts
    ///
    /// Setting this to `usize::MAX` disables the memory quota.
    ///
    /// The default is "auto",
    /// which uses a value derived from the total system memory.
    /// It should not be assumed that the value used for "auto"
    /// will remain stable across different versions of this library.
    ///
    /// Note that this is not a hard limit.
    /// See Approximate in [the overview](crate).
    max: Option<ExplicitOrAuto<Qty>>,

    /// Reclamation will stop when memory use is reduced to below this value
    ///
    /// Default is "auto", which uses 75% of the maximum.
    /// It should not be assumed that the value used for "auto"
    /// will remain stable across different versions of this library.
    ///
    /// If set to an explicit value,
    /// then `max` must be set to an explicit value as well.
    low_water: Option<ExplicitOrAuto<Qty>>,
}

/// Configuration, if enabled
#[derive(Debug, Clone, Eq, PartialEq, Deftly)]
#[cfg_attr(
    feature = "testing",
    visibility::make(pub),
    allow(clippy::exhaustive_structs)
)]
pub(crate) struct ConfigInner {
    /// Maximum memory usage
    ///
    /// Guaranteed not to be `MAX`, since we're enabled
    pub max: Qty,

    /// Low water
    ///
    /// Guaranteed to be enough lower than `max`
    pub low_water: Qty,
}

impl Config {
    /// Start building a [`Config`]
    ///
    /// Returns a fresh default [`ConfigBuilder`].
    pub fn builder() -> ConfigBuilder {
        ConfigBuilder::default()
    }

    /// Obtain the actual configuration, if we're enabled, or `None` if not
    ///
    /// Ad-hoc accessor for testing purposes.
    /// (ideally we'd use `visibility` to make fields `pub`, but that doesn't work.)
    #[cfg(any(test, feature = "testing"))]
    #[cfg_attr(feature = "testing", visibility::make(pub))]
    fn inner(&self) -> Option<&ConfigInner> {
        self.0.as_ref().into_enabled()
    }
}

impl ConfigBuilder {
    /// Builds a new `Config` from a builder
    ///
    /// Returns an error if the fields values are invalid or inconsistent.
    pub fn build(&self) -> Result<Config, ConfigBuildError> {
        // both options default to "auto"
        let max = self.max.unwrap_or(ExplicitOrAuto::Auto);
        let low_water = self.low_water.unwrap_or(ExplicitOrAuto::Auto);

        // `MAX` indicates "disabled".
        // TODO: Should we add a new "enabled" config option instead of using a sentinel value?
        // But this would be a breaking change. Or maybe we should always enable the memquota
        // machinery even if the user chooses an unreasonably large value, and not give users a way
        // to disable it.
        if max == ExplicitOrAuto::Explicit(Qty::MAX) {
            // If it should be disabled, but the user provided an explicit value for `low_water`.
            if matches!(low_water, ExplicitOrAuto::Explicit(_)) {
                return Err(ConfigBuildError::Inconsistent {
                    fields: vec!["max".into(), "low_water".into()],
                    problem: "low_water supplied, but max indicates that we should disable the memory quota".into(),
                });
            };
            return Ok(Config(IfEnabled::Noop));
        }

        // We don't want the user to set "auto" for `max`, but an explicit value for `low_water`.
        // Otherwise this config is prone to breaking since a `max` of "auto" may change as system
        // memory is removed (either physically or if running in a VM/container).
        if matches!(max, ExplicitOrAuto::Auto) && matches!(low_water, ExplicitOrAuto::Explicit(_)) {
            return Err(ConfigBuildError::Inconsistent {
                fields: vec!["max".into(), "low_water".into()],
                problem: "max is \"auto\", but low_water is set to an explicit quantity".into(),
            });
        }

        let enabled = EnabledToken::new_if_compiled_in()
            //
            .ok_or_else(|| ConfigBuildError::NoCompileTimeSupport {
                field: "max".into(),
                problem: "cargo feature `memquota` disabled (in tor-memquota crate)".into(),
            })?;

        // The general logic is taken from c-tor (see `compute_real_max_mem_in_queues`).
        // NOTE: Relays have an additional lower bound for explicitly given values (64 MiB),
        // but we have no way of knowing whether we are a relay or not here.
        let max = match max {
            ExplicitOrAuto::Explicit(x) => x,
            ExplicitOrAuto::Auto => compute_max_from_total_system_mem(total_available_memory()),
        };

        let low_water = match low_water {
            ExplicitOrAuto::Explicit(x) => x,
            ExplicitOrAuto::Auto => Qty((*max as f32 * 0.75) as _),
        };

        let config = ConfigInner { max, low_water };

        /// Minimum low water.  `const` so that overflows are compile-time.
        const MIN_LOW_WATER: usize = crate::mtracker::MAX_CACHE.as_usize() * MIN_MAX_PARTICIPANTS;
        let min_low_water = MIN_LOW_WATER;
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

/// Determine a max given the system's total available memory.
///
/// This is used when `max` is configured as "auto".
/// It takes a `Result` so that we can handle the case where the total memory isn't available.
fn compute_max_from_total_system_mem(mem: Result<usize, MemQueryError>) -> Qty {
    const MIB: usize = 1024 * 1024;
    const GIB: usize = 1024 * 1024 * 1024;

    let mem = match mem {
        Ok(x) => x,
        Err(e) => {
            warn!("Unable to get the total available memory. Using a constant max instead: {e}");

            // Can't get the total available memory,
            // so we return a max depending on whether the architecture is 32-bit or 64-bit.
            return Qty({
                cfg_if::cfg_if! {
                    if #[cfg(target_pointer_width = "64")] {
                        8 * GIB
                    } else {
                        1 * GIB
                    }
                }
            });
        }
    };

    let mem = {
        // From c-tor:
        //
        // > The idea behind this value is that the amount of RAM is more than enough
        // > for a single relay and should allow the relay operator to run two relays
        // > if they have additional bandwidth available.
        let mut factor = 0.75;
        // Multiplying 8 * GIB overflows the usize limit (4 GIB - 1) on 32-bit
        // platforms. So handle this properly for 32-bit platforms. Memory on 32-bit
        // targets cannot exceed 4 GIB anyways.
        #[cfg(target_pointer_width = "64")]
        if mem >= 8 * GIB {
            factor = 0.40;
        }
        (mem as f64 * factor) as usize
    };

    // The (min, max) range to clamp `mem` to.
    let clamp = {
        cfg_if::cfg_if! {
            if #[cfg(target_pointer_width = "64")] {
                (256 * MIB, 8 * GIB)
            } else {
                (256 * MIB, 2 * GIB)
            }
        }
    };

    let mem = mem.clamp(clamp.0, clamp.1);

    Qty(mem)
}

/// The total available memory in bytes.
///
/// This is generally the amount of system RAM,
/// but we may also take into account other OS-specific limits such as cgroups.
///
/// Returns `None` if we were unable to get the total available memory.
/// But see internal comments for details.
fn total_available_memory() -> Result<usize, MemQueryError> {
    // The sysinfo crate says we should use only one `System` per application.
    // But we're a library, so it's probably best to just make this global and reuse it.
    // In reality getting the system memory probably shouldn't require persistent state,
    // but since the internals of the sysinfo crate are opaque to us,
    // we'll just follow their documentation and cache the `System`.
    //
    // NOTE: The sysinfo crate in practice gets more information than we ask for.
    // For example `System::new()` will always query the `_SC_PAGESIZE` and `_SC_CLK_TCK`
    // on Linux even though we only refresh the memory info below
    // (see https://github.com/GuillaumeGomez/sysinfo/blob/fc31b411eea7b9983176399dc5be162786dec95b/src/unix/linux/system.rs#L152).
    // This means that miri will fail to run on tests that build the config, even if the config uses
    // explicit values.
    static SYSTEM: LazyLock<Mutex<System>> = LazyLock::new(|| Mutex::new(System::new()));
    let mut system = SYSTEM.lock().unwrap_or_else(|mut e| {
        // The sysinfo crate has some internal panics which would poison this mutex.
        // But we can easily reset it, rather than panicking ourselves if it's poisoned.
        **e.get_mut() = System::new();
        SYSTEM.clear_poison();
        e.into_inner()
    });

    system.refresh_memory_specifics(MemoryRefreshKind::nothing().with_ram());

    // It might be possible for 32-bit systems to return >usize::MAX due to PAE (I haven't looked
    // into this), so we just saturate the value and don't consider this an error.
    let mem = to_usize_saturating(system.total_memory());

    // The sysinfo crate doesn't report errors, so the best we can do is guess that a value of 0
    // implies that it was unable to get the total memory.
    //
    // We also need to return early to prevent a panic below.
    if mem == 0 {
        return Err(MemQueryError::Unavailable);
    }

    // Note: The docs for the sysinfo crate say:
    //
    // > You need to have run refresh_memory at least once before calling this method.
    //
    // But as implemented, it also panics if `sys.mem_total == 0` (for example if the refresh
    // silently failed).
    let Some(cgroups) = system.cgroup_limits() else {
        // There is no cgroup (or we're a non-Linux platform).
        return Ok(mem);
    };

    // The `cgroup_limits()` surprisingly doesn't actually return the unaltered cgroups limits.
    // It also adjusts them depending on the total memory.
    // Since this is all undocumented, we'll also do the same calculation here.
    let mem = std::cmp::min(mem, to_usize_saturating(cgroups.total_memory));

    Ok(mem)
}

/// An error when we are unable to obtain the system's total available memory.
#[derive(Clone, Debug, thiserror::Error)]
enum MemQueryError {
    /// The total available memory is unavailable.
    #[error("total available memory is unavailable")]
    Unavailable,
}

/// Convert a `u64` to a `usize`, saturating if the value would overflow.
fn to_usize_saturating(x: u64) -> usize {
    // this will be optimized to a no-op on 64-bit systems
    x.try_into().unwrap_or(usize::MAX)
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
    #![allow(clippy::unchecked_time_subtraction)]
    #![allow(clippy::useless_vec)]
    #![allow(clippy::needless_pass_by_value)]
    //! <!-- @@ end test lint list maintained by maint/add_warning @@ -->

    use super::*;
    use serde_json::json;

    #[test]
    // A value of "auto" depends on the system memory,
    // which typically results in libc calls or syscall that aren't supported by miri.
    #[cfg_attr(miri, ignore)]
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

        let chk_builds = |j| {
            cfg_if::cfg_if! {
                if #[cfg(feature = "memquota")] {
                    let b: ConfigBuilder = serde_json::from_value(j).unwrap();
                    b.build().unwrap();
                } else {
                    chk_err(j, "UNSUPPORTED");
                }
            }
        };

        chk_ok(json! {{ "max": "8 MiB" }}, 8, 6);
        chk_ok(json! {{ "max": "8 MiB", "low_water": "auto" }}, 8, 6);
        chk_ok(json! {{ "max": "8 MiB", "low_water": "4 MiB" }}, 8, 4);

        // We don't know what the exact values will be since they are derived from the system
        // memory.
        chk_builds(json! {{ }});
        chk_builds(json! {{ "max": "auto" }});
        chk_builds(json! {{ "low_water": "auto" }});
        chk_builds(json! {{ "max": "auto", "low_water": "auto" }});

        chk_err(
            json! {{ "low_water": "4 MiB" }},
            "max is \"auto\", but low_water is set to an explicit quantity",
        );
        chk_err(
            json! {{ "max": "8 MiB", "low_water": "8 MiB" }},
            "inconsistent: low_water / max",
        );

        // `usize::MAX` is a special value.
        chk_err(
            json! {{ "max": usize::MAX.to_string(), "low_water": "8 MiB" }},
            "low_water supplied, but max indicates that we should disable the memory quota",
        );
        chk_builds(json! {{ "max": (usize::MAX - 1).to_string(), "low_water": "8 MiB" }});

        // check that the builder works as expected
        #[cfg(feature = "memquota")]
        {
            let mut b = Config::builder();
            b.max(ExplicitOrAuto::Explicit(100_000_000));
            if let Some(inner) = b.build().unwrap().inner() {
                assert_eq!(inner.max, Qty(100_000_000));
            }

            let mut b = Config::builder();
            b.max(100_000_000);
            if let Some(inner) = b.build().unwrap().inner() {
                assert_eq!(inner.max, Qty(100_000_000));
            }

            let mut b = ConfigBuilder::default();
            b.max(ExplicitOrAuto::Auto);
            b.build().unwrap();
        }
    }

    /// Test the logic that computes the `max` when configured as "auto".
    #[test]
    // We do some `1 * X` operations below for readability.
    #[allow(clippy::identity_op)]
    fn auto_max() {
        #[allow(unused)]
        fn check_helper(val: Qty, expected_32: Qty, expected_64: Qty) {
            assert_eq!(val, {
                cfg_if::cfg_if! {
                    if #[cfg(target_pointer_width = "64")] {
                        expected_64
                    } else if #[cfg(target_pointer_width = "32")] {
                        expected_32
                    } else {
                        panic!("Unsupported architecture :(");
                    }
                }
            });
        }

        check_helper(
            compute_max_from_total_system_mem(Err(MemQueryError::Unavailable)),
            /* 32-bit */ Qty(1 * 1024 * 1024 * 1024),
            /* 64-bit */ Qty(8 * 1024 * 1024 * 1024),
        );
        check_helper(
            compute_max_from_total_system_mem(Ok(8 * 1024 * 1024 * 1024)),
            /* 32-bit */ Qty(2 * 1024 * 1024 * 1024),
            /* 64-bit */ Qty(3435973836),
        );
        check_helper(
            compute_max_from_total_system_mem(Ok(7 * 1024 * 1024 * 1024)),
            /* 32-bit */ Qty(2 * 1024 * 1024 * 1024),
            /* 64-bit */ Qty(5637144576),
        );
        check_helper(
            compute_max_from_total_system_mem(Ok(1 * 1024 * 1024 * 1024)),
            /* 32-bit */ Qty(805306368),
            /* 64-bit */ Qty(805306368),
        );
        check_helper(
            compute_max_from_total_system_mem(Ok(7 * 1024)),
            /* 32-bit */ Qty(256 * 1024 * 1024),
            /* 64-bit */ Qty(256 * 1024 * 1024),
        );
        check_helper(
            compute_max_from_total_system_mem(Ok(0)),
            /* 32-bit */ Qty(256 * 1024 * 1024),
            /* 64-bit */ Qty(256 * 1024 * 1024),
        );
        check_helper(
            compute_max_from_total_system_mem(Ok(usize::MAX)),
            /* 32-bit */ Qty(2 * 1024 * 1024 * 1024),
            /* 64-bit */ Qty(8 * 1024 * 1024 * 1024),
        );
    }
}
