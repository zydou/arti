use std::marker::PhantomData;

use asynchronous_codec::JsonCodec;
use bytes::BytesMut;
use serde::Serialize;

use crate::msgs::BoxedResponse;
use crate::msgs::Request;

/// A stream of [`Request`] taken from an `AsyncRead` and deserialized from Json.
pub(crate) type RequestStream<T> = asynchronous_codec::FramedRead<T, JsonCodec<(), Request>>;

/// As JsonCodec, but only supports encoding, and places a newline after every
/// object.
#[derive(Clone)]
pub(crate) struct JsonLinesEncoder<T> {
    /// We consume objects of type T.
    _phantom: PhantomData<fn(T) -> ()>,
}

impl<T> JsonLinesEncoder<T> {
    /// Return a new JsonLinesEncoder.
    pub(crate) fn new() -> Self {
        JsonLinesEncoder {
            _phantom: PhantomData,
        }
    }
}

impl<T> asynchronous_codec::Encoder for JsonLinesEncoder<T>
where
    T: Serialize + 'static,
{
    type Item = T;

    type Error = asynchronous_codec::JsonCodecError;

    fn encode(&mut self, item: Self::Item, dst: &mut BytesMut) -> Result<(), Self::Error> {
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
pub(crate) type ResponseSink<T> =
    asynchronous_codec::FramedWrite<T, JsonLinesEncoder<BoxedResponse>>;

#[cfg(test)]
mod test {
    use super::*;
    use crate::msgs::*;
    use futures::sink::SinkExt as _;
    use futures_await_test::async_test;

    #[derive(serde::Serialize)]
    struct Empty {}

    #[async_test]
    async fn check_sink_basics() {
        // Sanity-checking for our sink type.
        let mut buf = Vec::new();
        let r1 = BoxedResponse {
            id: RequestId::Int(7),
            body: BoxedResponseBody::Update(Box::new(Empty {})),
        };
        let r2 = BoxedResponse {
            id: RequestId::Int(8),
            body: BoxedResponseBody::Error(Box::new(Empty {})),
        };
        let r3 = BoxedResponse {
            id: RequestId::Int(9),
            body: BoxedResponseBody::Result(Box::new(Empty {})),
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
            let mut sink = ResponseSink::new(&mut buf, JsonLinesEncoder::new());
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
