// @@ begin lint list maintained by maint/add_warning @@
#![allow(renamed_and_removed_lints)] // @@REMOVE_WHEN(ci_arti_stable)
#![allow(unknown_lints)] // @@REMOVE_WHEN(ci_arti_nightly)
#![warn(missing_docs)]
#![warn(noop_method_call)]
#![warn(unreachable_pub)]
#![warn(clippy::all)]
#![deny(clippy::await_holding_lock)]
#![deny(clippy::cargo_common_metadata)]
#![deny(clippy::cast_lossless)]
#![deny(clippy::checked_conversions)]
#![allow(clippy::cognitive_complexity)] // See arti#2556
#![deny(clippy::debug_assert_with_mut_call)]
#![deny(clippy::exhaustive_enums)]
#![deny(clippy::exhaustive_structs)]
#![deny(clippy::expl_impl_clone_on_copy)]
#![deny(clippy::fallible_impl_from)]
#![deny(clippy::implicit_clone)]
#![deny(clippy::large_stack_arrays)]
#![warn(clippy::manual_ok_or)]
#![deny(clippy::missing_docs_in_private_items)]
#![warn(clippy::needless_borrow)]
#![warn(clippy::needless_pass_by_value)]
#![warn(clippy::option_option)]
#![deny(clippy::print_stderr)]
#![deny(clippy::print_stdout)]
#![warn(clippy::rc_buffer)]
#![deny(clippy::ref_option_ref)]
#![warn(clippy::semicolon_if_nothing_returned)]
#![warn(clippy::trait_duplication_in_bounds)]
#![deny(clippy::unchecked_time_subtraction)]
#![deny(clippy::unnecessary_wraps)]
#![warn(clippy::unseparated_literal_suffix)]
#![deny(clippy::unwrap_used)]
#![deny(clippy::mod_module_files)]
#![allow(clippy::let_unit_value)] // This can reasonably be done for explicitness
#![allow(clippy::uninlined_format_args)]
#![allow(clippy::significant_drop_in_scrutinee)] // arti/-/merge_requests/588/#note_2812945
#![allow(clippy::result_large_err)] // temporary workaround for arti#587
#![allow(clippy::needless_raw_string_hashes)] // complained-about code is fine, often best
#![allow(clippy::needless_lifetimes)] // See arti#1765
#![allow(mismatched_lifetime_syntaxes)] // temporary workaround for arti#2060
#![allow(clippy::collapsible_if)] // See arti#2342
#![deny(clippy::unused_async)]
#![deny(clippy::string_slice)] // See arti#2571
//! <!-- @@ end lint list maintained by maint/add_warning @@ -->

//! Tracing exporter to write spans to a file in the OTLP JSON format.

// TODO: If https://github.com/open-telemetry/opentelemetry-rust/issues/2602 gets fixed, we can
// replace this entire file with whatever upstream has for doing this.

use opentelemetry_proto::transform::common::tonic::ResourceAttributesWithSchema;
use opentelemetry_proto::transform::trace::tonic::group_spans_by_resource_and_scope;
use opentelemetry_sdk::{
    Resource,
    error::{OTelSdkError, OTelSdkResult},
    trace::SpanExporter,
};
use std::{
    fmt::Debug,
    io::{LineWriter, Write},
    sync::{Arc, Mutex},
};

/// Tracing exporter to write OTLP JSON to a file (or anything else that implements [`LineWriter`].
#[derive(Debug)]
pub struct FileExporter<W: Write + Send + Debug> {
    /// The [`LineWriter`] to write to.
    writer: Arc<Mutex<LineWriter<W>>>,
    /// The [`Resource`] to associate spans with.
    resource: Resource,
}

impl<W: Write + Send + Debug> FileExporter<W> {
    /// Create a new [`FileExporter`]
    pub fn new(writer: W, resource: Resource) -> Self {
        Self {
            writer: Arc::new(Mutex::new(LineWriter::new(writer))),
            resource,
        }
    }
}

// Note that OpenTelemetry can only represent events as children of spans, so this exporter only
// works on spans. If you want a event to be exported, you need to make sure it exists within some
// span.
impl<W: Write + Send + Debug> SpanExporter for FileExporter<W> {
    fn export(
        &self,
        batch: Vec<opentelemetry_sdk::trace::SpanData>,
    ) -> impl futures::Future<
        Output = std::result::Result<(), opentelemetry_sdk::error::OTelSdkError>,
    > + std::marker::Send {
        let resource = ResourceAttributesWithSchema::from(&self.resource);
        let data = group_spans_by_resource_and_scope(batch, &resource);
        let mut writer = self.writer.lock().expect("Lock poisoned");
        Box::pin(std::future::ready('write: {
            // See https://opentelemetry.io/docs/specs/otel/protocol/file-exporter/ for format

            if let Err(err) = serde_json::to_writer(
                writer.get_mut(),
                &serde_json::json!({"resourceSpans": data}),
            ) {
                break 'write Err(OTelSdkError::InternalFailure(err.to_string()));
            }

            if let Err(err) = writer.write(b"\n") {
                break 'write Err(OTelSdkError::InternalFailure(err.to_string()));
            }

            Ok(())
        }))
    }

    fn force_flush(&self) -> OTelSdkResult {
        let mut writer = self
            .writer
            .lock()
            .map_err(|e| OTelSdkError::InternalFailure(e.to_string()))?;

        writer
            .flush()
            .map_err(|e| OTelSdkError::InternalFailure(e.to_string()))
    }

    fn set_resource(&mut self, res: &opentelemetry_sdk::Resource) {
        self.resource = res.clone();
    }
}
