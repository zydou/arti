use cpu_time::ProcessTime;
use criterion::measurement::Measurement;
use criterion::measurement::ValueFormatter;
use criterion::Throughput;
use std::time::Duration;

const NANOS_PER_SEC: u64 = 1_000_000_000;

/// Custom measurement to use CPU time in Criterion benchmarks.
///
/// This measurement is based on the example in the Criterion documentation
/// for custom measurements:
/// https://bheisler.github.io/criterion.rs/book/user_guide/custom_measurements.html
pub struct CPUTime;

impl Measurement for CPUTime {
    type Intermediate = ProcessTime;
    type Value = Duration;

    fn start(&self) -> Self::Intermediate {
        ProcessTime::now()
    }

    fn end(&self, i: Self::Intermediate) -> Self::Value {
        i.elapsed()
    }

    fn add(&self, v1: &Self::Value, v2: &Self::Value) -> Self::Value {
        *v1 + *v2
    }

    fn zero(&self) -> Self::Value {
        Duration::from_secs(0)
    }

    fn to_f64(&self, val: &Self::Value) -> f64 {
        let nanos = val.as_secs() * NANOS_PER_SEC + u64::from(val.subsec_nanos());
        nanos as f64
    }

    fn formatter(&self) -> &dyn ValueFormatter {
        &DurationFormatter
    }
}

/// Custom value formatter for CPU time measurements.
///
/// This formatter is exactly the same as the one in the example in the Criterion
/// documentation for custom measurements since it is already a good fit for
/// the CPU time measurements.
pub struct DurationFormatter;

impl DurationFormatter {
    fn bytes_per_second(&self, bytes: f64, typical: f64, values: &mut [f64]) -> &'static str {
        let bytes_per_second = bytes * (1e9 / typical);
        let (denominator, unit) = if bytes_per_second < 1024.0 {
            (1.0, "  B/s")
        } else if bytes_per_second < 1024.0 * 1024.0 {
            (1024.0, "KiB/s")
        } else if bytes_per_second < 1024.0 * 1024.0 * 1024.0 {
            (1024.0 * 1024.0, "MiB/s")
        } else {
            (1024.0 * 1024.0 * 1024.0, "GiB/s")
        };

        for val in values {
            let bytes_per_second = bytes * (1e9 / *val);
            *val = bytes_per_second / denominator;
        }

        unit
    }

    fn elements_per_second(&self, elems: f64, typical: f64, values: &mut [f64]) -> &'static str {
        let elems_per_second = elems * (1e9 / typical);
        let (denominator, unit) = if elems_per_second < 1000.0 {
            (1.0, " elem/s")
        } else if elems_per_second < 1000.0 * 1000.0 {
            (1000.0, "Kelem/s")
        } else if elems_per_second < 1000.0 * 1000.0 * 1000.0 {
            (1000.0 * 1000.0, "Melem/s")
        } else {
            (1000.0 * 1000.0 * 1000.0, "Gelem/s")
        };

        for val in values {
            let elems_per_second = elems * (1e9 / *val);
            *val = elems_per_second / denominator;
        }

        unit
    }
}

impl ValueFormatter for DurationFormatter {
    fn scale_values(&self, ns: f64, values: &mut [f64]) -> &'static str {
        let (factor, unit) = if ns < 10f64.powi(0) {
            (10f64.powi(3), "ps")
        } else if ns < 10f64.powi(3) {
            (10f64.powi(0), "ns")
        } else if ns < 10f64.powi(6) {
            (10f64.powi(-3), "us")
        } else if ns < 10f64.powi(9) {
            (10f64.powi(-6), "ms")
        } else {
            (10f64.powi(-9), "s")
        };

        for val in values {
            *val *= factor;
        }

        unit
    }

    fn scale_throughputs(
        &self,
        typical: f64,
        throughput: &Throughput,
        values: &mut [f64],
    ) -> &'static str {
        match *throughput {
            Throughput::Bytes(bytes) => self.bytes_per_second(bytes as f64, typical, values),
            Throughput::Elements(elems) => self.elements_per_second(elems as f64, typical, values),
            Throughput::BytesDecimal(_) => todo!(),
        }
    }

    fn scale_for_machines(&self, _values: &mut [f64]) -> &'static str {
        // No scaling is needed
        "ns"
    }
}
