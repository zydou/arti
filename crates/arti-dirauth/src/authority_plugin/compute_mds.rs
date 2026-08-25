//! Implementation of `compute-mds` method

use super::*;

/// routerdesc to microdesc processor
#[derive(Deftly)]
#[derive_deftly(New)]
pub(crate) struct Processor<'o> {
    /// Nominal time, at which to check routerdesc validity
    #[deftly(new(arg))]
    nominal_time: SystemTime,

    /// Where to write generated microdescs
    #[deftly(new(arg))]
    mds_out: &'o mut Writing,

    /// Where to write the metadata
    #[deftly(new(arg))]
    meta_out: &'o mut Writing,

    /// Input descriptors that we've already processed
    dedup_inputs: HashSet<RdDigest>,

    /// Output descriptors that we've already written
    dedup_outputs: HashSet<MdDigest>,

    /// Consensus methods that triggered `Bug` (for logging deduplication)
    bugs_occurred: HashSet<ConsensusMethod>,
}

/// One entry in the metadata file
///
/// This is, in fact, a whole network document, which has only an intro item.
#[derive(Deftly)]
#[derive_deftly(tor_netdoc::NetdocEncodable)]
struct MetaFileEntry {
    /// The item
    m: MetaItem,
}

/// Values in a metadata item
#[derive(Deftly)]
#[derive_deftly(tor_netdoc::ItemValueEncodable)]
struct MetaItem {
    /// `CONSENSUS_VERSION`
    method: ConsensusMethod,

    /// `RSAID
    hk_relayid_rsa: Base64Fingerprint,

    /// `DID`
    hk_relayid_ed: Ed25519Public,

    /// `DD`
    h_routerdesc: RdDigest,

    /// `MD`
    h_md: MdDigest,
}

/// Router descriptor hash
type RdDigest = FixedB64<{ tor_netdoc::doc::routerdesc::DOC_DIGEST_LEN }>;
/// Microdescriptor hash
type MdDigest = FixedB64<{ tor_netdoc::doc::microdesc::DOC_DIGEST_LEN }>;

/// Routerdesc, parsed, with its location in the file
struct InputDescriptor {
    /// Start byte position
    start: usize,

    /// End byte position
    end: usize,

    /// SHA-1 (as required for the metadata file)
    h_routerdesc: RdDigest,

    /// The parsed routerdesc
    rd: RouterDesc,
}

impl<'o> Processor<'o> {
    /// Process one input file
    pub(crate) fn process_input(
        &mut self,
        mut input: parse2::ParseInput<'_>,
    ) -> Result<(), CliError> {
        input.retain_unknown_values();

        let router_descs = parse2::parse_netdoc_multiple_sophisticated::<
            CTorAnnotated<RouterDescUnverified>,
        >(&input)?;

        for (rd, start, end) in router_descs {
            let rd = rd.map(|CTorAnnotated(rd)| rd);

            let rd = match self.parse_verify_descriptor(rd, start, end) {
                Ok(y) => y,
                Err(e) => {
                    eprintln!("bad routerdesc at bytes {start}..{end}: {}", e.report(),);
                    continue;
                }
            };

            self.process_descriptor(&rd)?;
        }
        Ok(())
    }

    /// Resolve a parsed descriptor (or parse error) to a `InputDescriptor`
    ///
    /// Mostly, this function exists to provide an error handling context:
    /// errors which occur here are (always) logged,
    /// with the byte positions but not the routerdesc hash.
    fn parse_verify_descriptor(
        &self,
        rd: Result<RouterDescUnverified, parse2::ParseError>,
        start: usize,
        end: usize,
    ) -> Result<InputDescriptor, anyhow::Error> {
        // According to the plugin spec, the final routerdesc might be truncated.
        // That is be handled here, and so generates the log message, above.
        // That seems OK.
        let rd = rd.context("parse")?;

        let h_routerdesc = FixedB64(
            rd.sigs
                .hashes
                .sha1
                .ok_or_else(|| anyhow!("not hashed with SHAH-1, wrong kind of signature?"))?,
        );

        let rd = rd
            .verify()
            .context("verify")?
            .if_valid_at(&self.nominal_time)
            .context("check timeliness")?;

        Ok(InputDescriptor {
            h_routerdesc,
            rd,
            start,
            end,
        })
    }

    /// Process a descriptor into its microdescriptor(s) and write them out
    fn process_descriptor(&mut self, rd: &InputDescriptor) -> Result<(), CliError> {
        use tor_error::ErrorKind as EK;

        if !self.dedup_inputs.insert(rd.h_routerdesc.clone()) {
            return Ok(());
        }

        let (errs, mds) = match tor_dirauth::consensus::compute_supported_microdescs(&rd.rd) {
            Ok(y) => (vec![], y),
            Err(r) => r,
        };

        for (method, err) in errs.into_iter().rev() {
            macro_rules! log_error { { $fmt:literal } => {
                eprintln!(
                    concat!($fmt, ": {}"),
                    format_args!(
                        "rd at bytes {}..{} with hash {}",
                        rd.start,
                        rd.end,
                        rd.h_routerdesc,
                    ),
                    err.report(),
                    method=method,
                )
            } }

            match err.kind() {
                EK::RemoteProtocolViolation => {
                    // ie, bad routerdesc.  ignore it then, presumably.
                }
                EK::BadApiUsage | EK::Internal => {
                    if self.bugs_occurred.insert(method.into()) {
                        log_error!("bug in method {method} triggered by {}");
                    }
                }
                _other_kind => {
                    log_error!("problem due to {}, method {method}");
                    // Report only one error per md.
                    break;
                }
            }
        }

        for (methods, md) in mds {
            let h_md = FixedB64(Sha256::digest(&md).into());

            if self.dedup_outputs.insert(h_md.clone()) {
                self.mds_out.append_with(|w| write!(w, "{md}"))?;
            }

            for method in methods.methods {
                let meta = encode_netdoc_unsigned(&[MetaFileEntry {
                    m: MetaItem {
                        method,
                        h_md: h_md.clone(),
                        h_routerdesc: rd.h_routerdesc.clone(),
                        hk_relayid_ed: rd.rd.identity_ed25519.get()?.id_ed25519.into(),
                        hk_relayid_rsa: rd.rd.signing_key.to_rsa_identity().into(),
                    },
                }])?;

                self.meta_out.append_with(|w| write!(w, "{meta}"))?;
            }
        }

        Ok(())
    }
}
