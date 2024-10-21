from arti_rpc_tests import arti_test
from arti_rpc import ArtiRpcError

import json


@arti_test
def test_trivial(context):
    connection = context.open_rpc_connection()

    # Run a method that doesn't actually require anything major to be working.
    result = connection.session().invoke("arti:get_rpc_proxy_info")
    assert len(result["proxies"]) > 0


@arti_test
def missing_features(context):
    connection = context.open_rpc_connection()
    # TODO : having to encode this is unpleasant.
    request = {
        "obj": connection.session()._id,
        "method": "arti:get_rpc_proxy_info",
        "params": {},
        "meta": {
            "require": ["arti:does_not_exist"],
        },
    }
    try:
        out = connection.execute(json.dumps(request))
        assert False
    except ArtiRpcError as e:
        # TODO : having to decode this is unpleasant.
        x = json.loads(e.response())
        assert x["error"]["data"]["rpc:unsupported_features"] == ["arti:does_not_exist"]


@arti_test
def empty_features_list(context):
    connection = context.open_rpc_connection()
    # TODO : having to encode this is unpleasant.
    request = {
        "obj": connection.session()._id,
        "method": "arti:get_rpc_proxy_info",
        "params": {},
        "meta": {
            "require": [],
        },
    }

    out = connection.execute(json.dumps(request))
    # No exception raised; we're fine.
