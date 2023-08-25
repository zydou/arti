BREAKING: `IncomingStream::request` returns an `&IncomingStreamRequest` instead
of `IncomingStreamRequest`
BREAKING: `IncomingStreamRequest::accept_data` is now async, takes `mut self`,
and returns a `Result`
BREAKING: `IncomingStreamRequest::reject` is now async, takes `&mut self`,
and returns a `Result`
BREAKING: `ClientCirc::allow_stream_requests` now expects `self` to be
`&Arc<ClientCirc>`
ADDED: `HopNum` is now public
ADDED: `ClientCirc::last_hop_num`
DEPRECATED: `ClientCirc::start_conversation_last_hop()`
ADDED: `ClientCirc::start_conversation()` to eventually replace
`ClientCirc::start_conversation_last_hop()`
BREAKING: `ClientCirc::allow_stream_requests` is now async
BREAKING: `IncomingStream::discard` now takes `mut self` instead of `self` and
returns a `Result<(), Bug>`
ADDED: `ClientCirc::binding_key`
BREAKING: `ClientCirc::allow_stream_requests` now also takes a `HopNum` argument
ADDED: ClientCirc::send_raw_msg
ADDED: `HopNumDisplay`
