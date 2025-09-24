# Using OpenTelemetry with Arti

Arti has experimental support for exporting span data via OpenTelemetry. This allows us to see detailed information about the call stack and timing. This can have serious security implications, and is something you should only do if you're a developer, or have thought through and analyzed the security implications carefully as they relate to your particular usecase.

To use this feature, arti must be compiled with the `opentelemetry` feature.

This feature can be used in one of two ways:

* Exporting data via HTTP to software designed to ingest it, such as [Jaeger](https://www.jaegertracing.io)
* Exporting data to a JSON file, which can then be imported into compatible software (again, Jaeger, but there may be others as well)

## Exporting via HTTP

Add the following to the Arti configuration file
(if you plan on running Jaeger on a different port, or are using some OTEL collector other than Jaeger, you will need to adjust the `endpoint` accordingly):

```toml
[logging]
opentelemetry.http = { endpoint = "http://localhost:4318/v1/traces" }
```

Run Jaeger. It is easy to do this via Docker, if you have it installed:

```
docker run --rm --name jaeger \
  -p 16686:16686 \
  -p 4317:4317 \
  -p 4318:4318 \
  -p 5778:5778 \
  -p 9411:9411 \
  cr.jaegertracing.io/jaegertracing/jaeger:2.10.0
```

Run arti:

```
cargo run -p arti --features opentelemetry -- proxy -c /path/to/arti/config.toml
```

Navigate to [http://localhost:16686](http://localhost:16686) in a web browser. This should show the Jaeger UI. It should have a "Service" dropdown — select "arti" if it is not already selected, and click "Find Traces". This should show a timeline of various spans — click on a span to get detailed information about the call stack.

## Exporting via JSON file

This can be useful to get data when running Arti under Shadow/Chutney. Note that you cannot export to a file and to HTTP at the same time, due to underlying limitations in the design of the tracing system.

Add the following to the Arti configuration file:

```toml
[logging]
opentelemetry.file = { path = "~/logs/otel.json" }
```

Ensure that the path that you've specified exists.

Run Arti. It should generate a log file at the given location.

Run Jaeger. Click on "Search" in the Jaeger UI, then "Upload", and upload the created JSON file. You will then be able to view spans in the same way as you would if they'd been uploaded via HTTP.

## Adding instrumentation

Function calls are not instrumented by default. If you want to see something, you will need to add instrumentation to capture it. This can be easily done by applying the `#[instrument]` macro from the `tracing` crate to the functions you are interested in.

It is worthwhile to familiarize yourself with [the options available](https://docs.rs/tracing/latest/tracing/attr.instrument.html). I typically use `level = "trace"` and often use `skip_all` to avoid logging function arguments where I don't want to. You can also use `skip` to avoid logging specific fields, if you want to capture some fields but not others. In general, you should add `skip_all` to everything that you don't have a good reason to, and if you omit `skip_all`, you should think through the security implications carefully.

So far, we've just added instrumentation for a few things that have been useful for specific debugging, but we would like more instrumentation — if you add instrumentation to something, please be sure to submit a MR for it!
