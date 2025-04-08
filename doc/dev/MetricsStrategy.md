# Metrics (observability) in Arti

Some parts of Arti have support for collecting and reporting metrics,
like counts of connections, etc.,
via the `metrics.prometheus.listen` config option.

Metrics collection and reporting has privacy implications.

## Metrics collection within the codebase

We use the `metrics` facade crate.

## Ensuring metrics aren't collected needlessly

The overall goal is to prevent metrics collection in purely-client applications,
and to ensure that it is only enabled intentionally
in clients that offer hidden services.

We would like the code to be compiled out.

Therefore:

 * Core crates (`tor-config`, `tor-dirmgr`, `tor-proto`)
   may not unconditionally depend on `metrics`.
   If they do depend on it, the dependency must be feature-gated
   on features relating to relay/dirauth/etc. support.
   Clients should not have metrics code compiled in in these crates.

 * Higher-level crates relating to HSS eg (`tor-hsservice`, `tor-hsrproxy`)
   should have `metrics` enabled as an optional feature,
   ultimately controlled by the `metrics` feature in `arti`.

 * Higher-level crates implementing relay functionality may
   have `metrics` as an unconditional dependency.

## Feature-gated use of `metrics`, in the codebase

Use of `metrics` involves creating metrics objects during setup
(eg `Counter`) with macros like `counter!` and updating them
during operation (eg with `.increment(1)`).

Feature-gating means that all uses of `metrics` and its types
must be decorated with `#[cfg(feature = "metrics")]` in most places.

This is arguably clumsy.  We may consider introducing some kind of
indirection layer, which could use uninhabited types rather than `cfg`
to compile the code out when it's not wanted.

## Stability of metrics schema

Currently the whole metrics system is behind `experimental` feature flags.

We need to decide what our stability policy is for the metrics schema.

## Reporting and configuration

Actual reporting of metrics is done by much higher level crates.
There should be one global metrics exporter per process.

`arti` can use `metrics-exporter-prometheus` to offer a Prometheus
HTTP scrape endpoint.  This is disabled in the default configuration.
