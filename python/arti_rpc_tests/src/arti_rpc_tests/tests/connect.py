from arti_rpc_tests import arti_test
from arti_rpc import ArtiRpcError, ArtiRpcResponseKind, ArtiRpcErrorStatus

import socket


# TODO: Have a way to annotate this test as "requires a live network",
# and "can't work offline."
@arti_test
def connect_simple(context):
    connection = context.open_rpc_connection()

    # Try a simple connection.
    # TODO: Pick another address?
    (stream, ident) = connection.open_stream("www.torproject.org", 80)
    assert ident is None
    assert isinstance(stream, socket.socket)
    # TODO: Once we have another address, try doing something with this socket.
    stream.close()

    # Try a connection to a nonexistent address.
    try:
        (stream, ident) = connection.open_stream("does-not-exist.torproject.org", 443)
        assert False
    except ArtiRpcError as e:
        assert str(e).startswith("Data stream failed")
        assert e.status_code() == ArtiRpcErrorStatus.STREAM_FAILED

    # TODO: Isolation, once we can test it.

    # TODO: Getting a stream object ID, once we can test it.

    # TODO: Opening the stream on something other than the Session,
    # once we can test it.
