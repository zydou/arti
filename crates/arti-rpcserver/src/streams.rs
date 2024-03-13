//! Helper types for framing Json objects into async read/writes

use std::marker::PhantomData;

use asynchronous_codec::JsonCodec;
use bytes::BytesMut;
use serde::Serialize;

use crate::msgs::BoxedResponse;
use crate::msgs::FlexibleRequest;

/// A stream of [`Request`](crate::msgs::Request)
/// taken from `T` (an `AsyncRead`) and deserialized from Json.
#[allow(dead_code)] // TODO RPC
pub(crate) type RequestStream<T> =
    asynchronous_codec::FramedRead<T, JsonCodec<(), FlexibleRequest>>;

/// As JsonCodec, but only supports encoding, and places a newline after every
/// object.
#[derive(Clone)]
pub(crate) struct JsonLinesEncoder<T> {
    /// We consume objects of type T.
    _phantom: PhantomData<fn(T) -> ()>,
}

impl<T> Default for JsonLinesEncoder<T> {
    fn default() -> Self {
        Self {
            _phantom: PhantomData,
        }
    }
}

impl<T> asynchronous_codec::Encoder for JsonLinesEncoder<T>
where
    T: Serialize + 'static,
{
    type Item<'a> = T;

    type Error = asynchronous_codec::JsonCodecError;

    fn encode(&mut self, item: Self::Item<'_>, dst: &mut BytesMut) -> Result<(), Self::Error> {
        use std::fmt::Write as _;
        let j = serde_json::to_string(&item)?;
        // The jsonlines format won't work if serde_json starts adding newlines in the middle.
        debug_assert!(!j.contains('\n'));
        writeln!(dst, "{}", j).expect("write! of string on BytesMut failed");
        Ok(())
    }
}

/// A stream of [`BoxedResponse`] serialized as newline-terminated json objects
/// onto an `AsyncWrite.`
#[allow(dead_code)] // TODO RPC
pub(crate) type ResponseSink<T> =
    asynchronous_codec::FramedWrite<T, JsonLinesEncoder<BoxedResponse>>;

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
    #![allow(clippy::unchecked_duration_subtraction)]
    #![allow(clippy::useless_vec)]
    #![allow(clippy::needless_pass_by_value)]
    //! <!-- @@ end test lint list maintained by maint/add_warning @@ -->

    use super::*;
    use crate::msgs::*;
    use futures::sink::SinkExt as _;
    use futures_await_test::async_test;
    use tor_rpcbase as rpc;

    #[derive(serde::Serialize)]
    struct Empty {}

    #[async_test]
    async fn check_sink_basics() {
        // Sanity-checking for our sink type.
        let mut buf = Vec::new();
        let r1 = BoxedResponse {
            id: Some(RequestId::Int(7)),
            body: ResponseBody::Update(Box::new(Empty {})),
        };
        let r2 = BoxedResponse {
            id: Some(RequestId::Int(8)),
            body: ResponseBody::Error(Box::new(rpc::RpcError::from(
                crate::connection::RequestCancelled,
            ))),
        };
        let r3 = BoxedResponse {
            id: Some(RequestId::Int(9)),
            body: ResponseBody::Success(Box::new(Empty {})),
        };

        // These should get serialized as follows.
        let mut expect = String::new();
        expect.extend(serde_json::to_string(&r1));
        expect.push('\n');
        expect.extend(serde_json::to_string(&r2));
        expect.push('\n');
        expect.extend(serde_json::to_string(&r3));
        expect.push('\n');

        {
            let mut sink = ResponseSink::new(&mut buf, JsonLinesEncoder::default());
            sink.send(r1).await.unwrap();
            sink.send(r2).await.unwrap();
            sink.send(r3).await.unwrap();
        }
        // Exactly 3 messages means exactly 3 newlines.
        assert_eq!(buf.iter().filter(|c| **c == b'\n').count(), 3);
        // Make sure that the output is what we expected.
        assert_eq!(std::str::from_utf8(&buf).unwrap(), &expect);
    }
}
