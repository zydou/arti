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
pub(crate) struct FileExporter<W: Write + Send + Debug> {
    /// The [`LineWriter`] to write to.
    writer: Arc<Mutex<LineWriter<W>>>,
    /// The [`Resource`] to associate spans with.
    resource: Resource,
}

impl<W: Write + Send + Debug> FileExporter<W> {
    /// Create a new [`FileExporter`]
    pub(crate) fn new(writer: W, resource: Resource) -> Self {
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

    fn force_flush(&mut self) -> OTelSdkResult {
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
