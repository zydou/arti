//! Computing microdescriptors

use super::*;

/// Error creating a microdescriptor
#[derive(Debug, Clone, thiserror::Error)]
#[non_exhaustive]
pub enum MicrodescError {
    /// Internal error
    #[error("internal error")]
    Internal(#[from] Bug),
}

/// Compute a microdescriptor from a routerdesc
///
/// <https://spec.torproject.org/dir-spec/computing-microdescriptors.html>
pub fn compute_microdesc(
    rd: &RouterDesc,
    meth: &TrackedConsensusMethod,
) -> Result<Microdesc, MicrodescError> {
    let mut family = RelayFamily::clone(&rd.family); // avoids Arc::Clone
    if !family.is_empty() {
        family.push(rd.signing_key.to_rsa_identity());
    }
    let family = family.intern(); // also normalises

    let family_ids: RelayFamilyIds = rd
        .family_cert
        .iter()
        .map(|cert| {
            let id = cert.get()?.family_ed25519;
            Ok::<_, Bug>(RelayFamilyId::Ed25519(id))
        })
        .try_collect()?;

    let ipv4_policy =
        ip_summary::summarise_policy_v4_approximate(&rd.ipv4_policy, meth)?.into_intern();

    let m = Microdesc {
        family,
        family_ids,
        ipv4_policy,
        ipv6_policy: rd.ipv6_policy.clone(),
        ..MicrodescConstructor {
            ntor_onion_key: rd.ntor_onion_key.clone(),
            ed25519_id: rd.identity_ed25519.get()?.id_ed25519.into(),
        }
        .construct()
    };
    Ok(m)
}

/// Microdescriptors computed from one routerdesc, for various supported consensus methods
pub type MicrodescsForRouterDesc = BTreeMap<tor_netdoc::doc::netstatus::ConsensusMethods, String>;

/// Errors calculating one or more microdescriptors
pub type MicrodescsErrors = Vec<(SupportedConsensusMethod, MicrodescError)>;

/// Computes the microdescriptor for this descriptor, for each supported consensus method
///
/// If all goes well returns `MicrodescsForRouterDesc`, a map from methods to strings.
/// The map is guaranteed not to have the same *value* for different keys:
/// if different emthods yield the same microdesc, thy will be represented as
/// a single `ConsensusMethods` set mapping to a single `String`.
///
/// Hashing (calculating and collating document digests) is done by the caller of this function.
///
/// If any microdesc couldn't be computed (currently, only possible due to internal errors)
/// returns an `Err` containing both the failed consensus method(s) and the corresponding errors,
/// and the successful results (if any).
///
/// This unusual error handling is so that a handful of strange routerdescs,
/// that trigger bugs in our code, do not cause the whole algorithm to collapse.
/// See torspec!522  TODO DIRAUTH turn this into a proper spec ref when that's merged.
pub fn compute_supported_microdescs(
    rd: &RouterDesc,
) -> Result<MicrodescsForRouterDesc, (MicrodescsErrors, MicrodescsForRouterDesc)> {
    compute_supported_generic(
        //
        SupportedConsensusMethod::iter_all(),
        |tracker| {
            let md = compute_microdesc(rd, tracker)?;
            let md = encode_netdoc_unsigned([&md])?;
            Ok(md)
        },
    )
}

/// "Good" output from [`compute_supported_generic`]
type Outputs<O> = BTreeMap<tor_netdoc::doc::netstatus::ConsensusMethods, O>;

/// Compute `O` for all supported consensus methods
///
/// This is the core of `compute_supported_microdescs`,
/// but made generic so that we can pass an interesting calculation function, for testing.
#[allow(clippy::type_complexity)] // return type is sadly rather complex
fn compute_supported_generic<O: Clone + Eq + Hash, E: From<Bug>>(
    all_methods: impl Iterator<Item = SupportedConsensusMethod>,
    computor: impl Fn(&TrackedConsensusMethod) -> Result<O, E>,
) -> Result<Outputs<O>, (Vec<(SupportedConsensusMethod, E)>, Outputs<O>)> {
    let mut results = HashMap::<O, tor_netdoc::doc::netstatus::ConsensusMethods>::new();
    let mut errors = vec![];

    let mut last = None::<(ConsensusMethodRange, O)>;
    for method in all_methods {
        (|| {
            let entry = if let Some((range, prev)) = &last
                && range.contains(&method)
            {
                results
                    .get_mut(prev)
                    .ok_or_else(|| internal!("prev not inserted!"))?
            } else {
                let tracker = TrackedConsensusMethod::new(method);
                let output = computor(&tracker)?;
                last = Some((tracker.finish_get_equivalent(), output.clone()));
                results.entry(output).or_default()
            };
            entry.methods.insert(method.into());
            Ok(())
        })()
        .unwrap_or_else(|e| {
            errors.push((method, e));
        });
    }

    let results = results
        .into_iter()
        .map(|(output, meths)| (meths, output))
        .collect();
    if errors.is_empty() {
        Ok(results)
    } else {
        Err((errors, results))
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
    #![allow(clippy::unchecked_time_subtraction)]
    #![allow(clippy::useless_vec)]
    #![allow(clippy::needless_pass_by_value)]
    #![allow(clippy::string_slice)] // See arti#2571
    //! <!-- @@ end test lint list maintained by maint/add_warning @@ -->
    use super::*;
    use tor_checkable::TimeBound as _;
    use tor_netdoc::{
        assert_eq_or_diff,
        doc::routerdesc::RouterDescUnverified,
        parse2::{ParseInput, parse_netdoc},
        test_support::regsub,
        testdata_live,
    };

    fn get_router_desc(relay: &testdata_live::PerRelay) -> anyhow::Result<RouterDesc> {
        let rd_txt = relay.data.plain;
        let rd: RouterDescUnverified = parse_netdoc(&ParseInput::new(rd_txt, relay.nick))?;
        let rd = rd.verify()?.dangerously_assume_timely();
        Ok(rd)
    }

    #[test]
    fn microdescs() -> anyhow::Result<()> {
        let method = TrackedConsensusMethod::new(
            // Test with method 100; will need to bump this occasionally,
            // and/or add more regsub fixups, if this test fails.
            ConsensusMethod(100).try_into()?,
        );

        for relay in testdata_live::RELAY_DESCRIPTORS {
            let rd = get_router_desc(relay)?;
            let md = compute_microdesc(&rd, &method)?;
            let md_txt = encode_netdoc_unsigned([&md])?;

            let mut exp_md = relay.data.md.to_owned();
            regsub(
                &mut exp_md,
                r#"(?x) ^ onion-key \n
                          -----BEGIN\ .*----- \n
                          [^-]+
                          -----END\ .*----- \n
                "#,
                "onion-key\n",
            );

            assert_eq_or_diff!(md_txt, exp_md, "for relay {}", relay.nick);
        }

        Ok(())
    }
}
