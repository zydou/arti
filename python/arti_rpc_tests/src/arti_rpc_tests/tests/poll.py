from arti_rpc_tests import arti_test

import arti_rpc
import selectors
from arti_rpc.rpc import WOULD_BLOCK

R = selectors.EVENT_READ
RW = selectors.EVENT_WRITE | selectors.EVENT_READ


@arti_test
def polling(context):
    sel = selectors.DefaultSelector()

    bld = arti_rpc.ArtiRpcConnBuilder()
    bld.prepend_literal_path(str(context.tcp_connpt_path))
    connection, poll = bld.connect_polling(
        start_writing=lambda f: sel.modify(f, RW),
        stop_writing=lambda f: sel.modify(f, R),
    )
    sel.register(poll, R)

    # Launch three requests.
    connection.session().submit("CL1", "arti:new_isolated_client")
    connection.session().submit("CL2", "arti:new_isolated_client")
    connection.session().submit("CL3", "arti:new_isolated_client")

    # Wait for the responses.
    m = {}
    while len(m) < 3:
        # Ignore return value; we only have one event.
        sel.select()
        while True:
            r = poll.poll()
            if r is WOULD_BLOCK:
                break
            m[r.user_tag()] = r

    assert len(m) == 3
    assert len(set(m.values())) == 3
    assert set(m.keys()) == set(["CL1", "CL2", "CL3"])
