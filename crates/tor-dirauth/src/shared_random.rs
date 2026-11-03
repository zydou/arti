//! Shared random - support for calculating votes and consensuses
#![allow(unused)] // XXXX

use crate::internal_prelude::*;

/// Number of nominal hours in a nominal day
const PHASES: u8 = 24;

/// Phase within the 24-phase shared random protocol
///
/// This is the "nominal hour" from the spec, which in the live network is the UTC hour.
///
/// <https://spec.torproject.org/srv-spec/overview.html#times-and-the-voting-interval>
#[derive(Copy, Clone, Eq, PartialEq, derive_more::Debug, derive_more::From)]
#[debug("SrvPhase({nominal_hour:02}:00)")]
pub(crate) struct Phase {
    /// Nominal hour
    nominal_hour: u8,
}

/// Error thrown by `Phase::try_from_hour`
#[derive(Debug, Clone, Eq, PartialEq, thiserror::Error)]
#[error("SRV phase out of range")]
pub(crate) struct PhaseOutOfRange;

/// Bad times means we couldn't calculate the phase
#[derive(Clone, Debug, Eq, PartialEq, thiserror::Error)]
pub(crate) enum UnreasonableTime {
    /// bad valid after
    #[error("bad valid_after (must be after the unix epoch)")]
    ValidAfter,
    /// bad voting period
    #[error("bad voting period (must be nonzero)")]
    VotingPeriod,
}

impl Phase {
    /// Phase in which we declare a new SRV.  Midnight.
    pub(crate) const NEW_SRV: Phase = Phase::from_hour_const(0);

    /// Construct a `Phase` from a nominal hour value
    pub(crate) const fn try_from_hour(nominal_hour: u8) -> Result<Self, PhaseOutOfRange> {
        if nominal_hour >= PHASES {
            Err(PhaseOutOfRange)
        } else {
            Ok(Phase { nominal_hour })
        }
    }

    /// Construct a `Phase` from a nominal hour value
    ///
    /// # Panics
    ///
    /// Panics if the value is out of range (`>24`),
    /// with a rather poor error message.
    pub(crate) const fn from_hour_const(nominal_hour: u8) -> Self {
        match Phase::try_from_hour(nominal_hour) {
            Ok(y) => y,
            Err(_) => panic!(),
        }
    }

    /// Return the nominal hour for a particular voting period
    pub(crate) fn for_voting_period(
        valid_after: SystemTime,
        voting_period: Duration,
    ) -> Result<Phase, UnreasonableTime> {
        let unix_time = valid_after
            .duration_since(SystemTime::UNIX_EPOCH)
            .map_err(|_| UnreasonableTime::ValidAfter)?
            .as_secs();
        let interval_number = unix_time
            .checked_div(voting_period.as_secs())
            .ok_or(UnreasonableTime::VotingPeriod)?;
        let hour = interval_number
            .checked_rem(const { PHASES as u64 })
            .expect("PHASES is nonzero");
        let hour = u8::try_from(hour).expect("just reduced");
        let phase = Phase::try_from_hour(hour).expect("just reduced");
        Ok(phase)
    }
}

#[cfg(test)]
pub(crate) mod test {
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
    #![allow(clippy::string_slice)] // See arti#2571
    //! <!-- @@ end test lint list maintained by maint/add_warning @@ -->
    use super::*;
    use humantime::parse_rfc3339;

    #[test]
    fn phase_basic() {
        let ok = |h| assert_eq!(Phase::try_from_hour(h), Ok(Phase { nominal_hour: h }));
        let err = |h| Phase::try_from_hour(h).unwrap_err();
        ok(0);
        ok(1);
        ok(23);
        err(24);
        err(255);
    }

    #[test]
    fn phase_for_period() {
        let chk = |vp, t, exp| {
            assert_eq!(
                Phase::for_voting_period(parse_rfc3339(t).expect(t), Duration::from_secs(vp),),
                Ok(Phase::try_from_hour(exp).unwrap()),
                "{vp} {t:?} {exp}",
            );
        };

        let chk_h = |t, exp| chk(3600, t, exp);

        chk_h("2026-10-01T23:59:59Z", 23);
        chk_h("2026-10-02T00:00:00Z", 0);
        chk_h("2026-10-02T00:00:01Z", 0);
        chk_h("2026-10-02T00:00:59Z", 0);
        chk_h("2026-10-02T01:00:00Z", 1);
        chk_h("2026-10-02T02:00:00Z", 2);
        chk_h("2026-10-02T23:59:59Z", 23);
        chk(60, "1970-01-01T00:00:00Z", 0);
        chk(60, "1970-01-01T00:00:59Z", 0);
        chk(60, "1970-01-01T00:01:00Z", 1);
        chk(60, "1970-01-01T00:23:59Z", 23);
        chk(60, "1970-01-01T00:24:00Z", 0);
    }
}
