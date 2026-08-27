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
                .ok_or_else(|| anyhow!("not hashed with SHA-1, wrong kind of signature?"))?,
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
    use std::fs;
    use test_temp_dir::test_temp_dir;
    use tor_dirauth::consensus::SupportedConsensusMethod;
    use tor_netdoc::{
        doc::microdesc::Microdesc,
        parse2::{ParseInput, parse_netdoc_multiple_with_offsets},
        testdata_live::{self, relay_document_by_nick},
        types::B64,
    };

    #[test]
    fn test_compute_mds() -> anyhow::Result<()> {
        let consensus = testdata_live::netstatus_plain();
        let nominal_time = consensus.preamble.lifetime.valid_after();
        let tmp = test_temp_dir!();

        tmp.used_by(|tmp| {
            let tmp: String = tmp
                .as_os_str()
                .to_str()
                .expect("tmp must be utf-8")
                .to_owned();
            let mds_f = format!("{tmp}/mds");
            let meta_f = format!("{tmp}/meta");
            let mk_out = |f: &str| FilenameOrStdio::Path(f.to_owned()).start_writing();
            let mut mds_out = mk_out(&mds_f)?;
            let mut meta_out = mk_out(&meta_f)?;

            let mut processor = Processor::new(nominal_time, &mut mds_out, &mut meta_out);

            let concatenated_descs = testdata_live::RELAY_DESCRIPTORS
                .iter()
                .map(|desc| format!("@ nick={}\n{}", desc.nick, desc.data.plain))
                .collect::<String>();

            processor.process_input(ParseInput::new(&concatenated_descs, "<input descriptors>"))?;

            mds_out.finish()?;
            meta_out.finish()?;

            let meta_made = fs::read_to_string(&meta_f)?;
            let mds_made = fs::read_to_string(&mds_f)?;

            eprintln!("@@ EMTA_OUT:\n{meta_made}");
            eprintln!("@@ MDS_OUT:\n{mds_made}");

            let mds = parse_netdoc_multiple_with_offsets::<Microdesc>(&ParseInput::new(
                &mds_made,
                "<out mds>",
            ))?;

            let md_hashes = mds
                .iter()
                .map(|&(_, start, end)| Sha256::digest(&mds_made[start..end]).into())
                .collect::<HashSet<[u8; 32]>>();

            let n_expected = testdata_live::RELAY_DESCRIPTORS.len();
            eprintln!("expecting at least {n_expected} mds");

            assert!(
                mds.len() >= n_expected,
                "{} is too few mds;\n{mds:?}",
                mds.len(),
            );

            let meta_made = meta_made.split_terminator('\n');

            for method in SupportedConsensusMethod::iter_all() {
                eprintln!("checking method {method}");

                let n_got = meta_made
                    .clone()
                    .filter(|l| {
                        // ad-hoc parsing, so we have an independent Cross-check

                        let mut l = l.split_ascii_whitespace();
                        let mut next = || l.next().unwrap();
                        macro_rules! next { {} => { next().parse().unwrap() } }

                        assert_eq!(next(), "m");

                        let m: ConsensusMethod = next!();
                        let m: SupportedConsensusMethod = m.try_into().unwrap();

                        let rsaid: Base64Fingerprint = next!();
                        let edid: B64 = next!();
                        let rd_hash: B64 = next!();
                        let md_hash: B64 = next!();

                        let rs_plain = consensus
                            .routers
                            .iter()
                            .find(|rs| rs.r.doc_digest[..] == **rd_hash)
                            .expect("missing doc digest");

                        let rs_md = relay_document_by_nick(
                            rs_plain.r.nickname.as_ref(),
                            &testdata_live::relay_microdescs(),
                        );

                        assert_eq!(rsaid, rs_plain.r.identity);
                        assert_eq!(*edid, rs_md.ed25519_id.pk.as_bytes());
                        assert!(md_hashes.contains(&**md_hash));

                        m == method
                    })
                    .count();
                assert!(n_got >= n_expected, "{} is too few", n_got);
            }

            Ok(())
        })
        .into_untracked()
    }
}
