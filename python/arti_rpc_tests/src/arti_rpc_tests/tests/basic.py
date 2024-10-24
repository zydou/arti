from arti_rpc_tests import arti_test
from arti_rpc import ArtiRpcError, ArtiRpcResponseKind, ArtiRpcErrorStatus

import json


@arti_test
def test_trivial(context):
    connection = context.open_rpc_connection()

    # Run a method that doesn't actually require anything major to be working.
    #
    # TODO: Pick a better method once we have more of the RPC system
    # working.
    result = connection.session().invoke("arti:get_rpc_proxy_info")
    assert len(result["proxies"]) > 0


@arti_test
def test_execute(context):
    connection = context.open_rpc_connection()

    req = {
        "obj": connection.session().id(),
        "method": "arti:get_rpc_proxy_info",
        "params": {},
    }
    result = connection.execute(req)
    assert len(result["proxies"]) > 0

    result = connection.execute(json.dumps(req))
    assert len(result["proxies"]) > 0


@arti_test
def test_execute_with_handle(context):
    connection = context.open_rpc_connection()
    handle = connection.execute_with_handle(
        {
            "obj": connection.session().id(),
            "method": "arti:get_rpc_proxy_info",
            "params": {},
        }
    )

    response = handle.wait()
    assert response.kind() == ArtiRpcResponseKind.RESULT
    assert len(response.result()["proxies"]) > 1
    assert len(response["result"]["proxies"]) > 1

    try:
        response = handle.wait()
        assert False
    except ArtiRpcError as e:
        assert e.status_code() == ArtiRpcErrorStatus.REQUEST_COMPLETED
        assert str(e) == "Request has already completed (or failed)"
