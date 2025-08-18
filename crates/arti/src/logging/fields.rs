//! Field formatters for [`tracing_subscriber`].

use std::error::Error;
use std::fmt::Debug;

use tracing::field::Field;
use tracing_subscriber::field::{RecordFields, Visit, VisitOutput};
use tracing_subscriber::fmt::format::{DefaultVisitor, FormatFields, Writer};

/// Visits only `dyn Error`.
struct ErrorVisitor<'a>(&'a mut dyn Visit);

// this just wraps an existing visitor, so if the trait methods gain a return type in the future,
// we want to just pass it through
#[allow(clippy::semicolon_if_nothing_returned)]
impl<'a> Visit for ErrorVisitor<'a> {
    // do nothing
    fn record_debug(&mut self, _field: &Field, _value: &dyn Debug) {}
    fn record_f64(&mut self, _field: &Field, _value: f64) {}
    fn record_i64(&mut self, _field: &Field, _value: i64) {}
    fn record_u64(&mut self, _field: &Field, _value: u64) {}
    fn record_i128(&mut self, _field: &Field, _value: i128) {}
    fn record_u128(&mut self, _field: &Field, _value: u128) {}
    fn record_bool(&mut self, _field: &Field, _value: bool) {}
    fn record_str(&mut self, _field: &Field, _value: &str) {}
    fn record_bytes(&mut self, _field: &Field, _value: &[u8]) {}

    // format the error and use the inner visitor
    fn record_error(&mut self, field: &Field, value: &(dyn Error + 'static)) {
        use std::fmt;
        use tor_error::ErrorReport as _;

        /// Wrapper to add a `Debug` impl to something that implements `Display`.
        struct DisplayToDebug<T: fmt::Display>(T);

        impl<T: fmt::Display> fmt::Debug for DisplayToDebug<T> {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                fmt::Display::fmt(&self.0, f)
            }
        }

        // use `ErrorReport` to format the error
        self.0.record_debug(field, &DisplayToDebug(value.report()))
    }
}

/// Visits everything but `dyn Error`.
struct NonErrorVisitor<'a>(&'a mut dyn Visit);

// this just wraps an existing visitor, so if the trait methods gain a return type in the future,
// we want to just pass it through
#[allow(clippy::semicolon_if_nothing_returned)]
impl<'a> Visit for NonErrorVisitor<'a> {
    // use the inner visitor
    fn record_debug(&mut self, field: &Field, value: &dyn Debug) {
        self.0.record_debug(field, value)
    }
    fn record_f64(&mut self, field: &Field, value: f64) {
        self.0.record_f64(field, value)
    }
    fn record_i64(&mut self, field: &Field, value: i64) {
        self.0.record_i64(field, value)
    }
    fn record_u64(&mut self, field: &Field, value: u64) {
        self.0.record_u64(field, value)
    }
    fn record_i128(&mut self, field: &Field, value: i128) {
        self.0.record_i128(field, value)
    }
    fn record_u128(&mut self, field: &Field, value: u128) {
        self.0.record_u128(field, value)
    }
    fn record_bool(&mut self, field: &Field, value: bool) {
        self.0.record_bool(field, value)
    }
    fn record_str(&mut self, field: &Field, value: &str) {
        self.0.record_str(field, value)
    }
    fn record_bytes(&mut self, field: &Field, value: &[u8]) {
        self.0.record_bytes(field, value)
    }

    // do nothing
    fn record_error(&mut self, _field: &Field, _value: &(dyn Error + 'static)) {}
}

/// Log error fields after other fields.
pub(crate) struct ErrorsLastFieldFormatter;

impl<'writer> FormatFields<'writer> for ErrorsLastFieldFormatter {
    fn format_fields<R: RecordFields>(
        &self,
        mut writer: Writer<'writer>,
        fields: R,
    ) -> std::fmt::Result {
        // we use a visitor from `tracing_subscriber` for formatting fields
        let mut visitor = DefaultVisitor::new(writer.by_ref(), /* is_empty= */ true);

        // record non-error fields first, then record error fields
        fields.record(&mut NonErrorVisitor(&mut visitor));
        fields.record(&mut ErrorVisitor(&mut visitor));

        visitor.finish()?;

        Ok(())
    }
}
