from arti_rpc_tests import arti_test
from arti_rpc import ArtiRpcError, ArtiRpcErrorStatus

import socket


# TODO: Have a way to annotate this test as "requires a live network",
# and "can't work offline."
@arti_test
def connect_simple(context):
    connection = context.open_rpc_connection()

    # Try a simple connection.
    # TODO: Pick another address?
    stream, stream_obj = connection.open_stream(
        "www.torproject.org", 80, want_stream_id=True
    )
    assert stream_obj is not None
    assert isinstance(stream, socket.socket)

    # Inspect the path we got.
    path_via_stream = stream_obj.invoke("arti:describe_path")
    tunnel = stream_obj.invoke("arti:get_tunnel")
    tunnel = connection.make_object(tunnel["id"])
    path_via_tunnel = tunnel.invoke("arti:describe_path")
    assert path_via_stream == path_via_tunnel
    assert len(path_via_stream["path"]) > 0
    ident, p = path_via_stream["path"].popitem()
    assert isinstance(ident, str)  # this is all we are guaranteed.

    # TODO: Assumption about path length holds true for now...
    assert len(p) == 3

    for hop in p:
        # make sure it isn't virtual, and get the fields.
        hop = hop["known_relay"]

        assert hop["ids"].get("ed25519") is not None
        # We didn't ask for rsa, so we won't get it.
        assert hop["ids"].get("rsa") is None
        assert len(hop["addrs"]) > 0

    del stream_obj
    del tunnel
    # TODO: Once we have another address, try doing something with this socket.
    stream.close()

    # Try a connection to a nonexistent address.
    try:
        stream, ident = connection.open_stream("does-not-exist.torproject.org", 443)
        assert False
    except ArtiRpcError as e:
        assert str(e).startswith("Data stream failed")
        assert e.status_code() == ArtiRpcErrorStatus.STREAM_FAILED

    # TODO: Isolation, once we can test it.

    # TODO: Getting a stream object ID, once we can test it.

    # TODO: Opening the stream on something other than the Session,
    # once we can test it.
