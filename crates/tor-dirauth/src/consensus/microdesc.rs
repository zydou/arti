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
