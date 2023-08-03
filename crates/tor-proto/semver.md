BREAKING: `IncomingStream::request` returns an `&IncomingStreamRequest` instead
of `IncomingStreamRequest`
BREAKING: `IncomingStreamRequest::accept_data` is now async, takes `mut self`,
and returns a `Result`
BREAKING: `IncomingStreamRequest::reject` is now async, takes `&mut self`,
and returns a `Result`
BREAKING: `ClientCirc::allow_stream_requests` now expects `self` to be
`&Arc<ClientCirc>`
