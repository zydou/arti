CHANGED: `Begin::new()` takes a non-zero port.
CHANGED: `Begin::port()` returns a non-zero port.
         NOTE: This change will break `TorClient` hs service users,
         since we pass the `Begin` message through the `IncomingStreamRequest`.
CHANGED: `Begin::new()` takes an `EncodedBeginAddr` rather than a `&str`.
CHANGED: `Begin::addr()` returns an `EncodedBeginAddr` rather than a `&[u8]`.
