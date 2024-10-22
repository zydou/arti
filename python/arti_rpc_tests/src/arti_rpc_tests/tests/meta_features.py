from arti_rpc_tests import arti_test
from arti_rpc import ArtiRpcError, ArtiRpcErrorStatus

@arti_test
def missing_features(context):
    connection = context.open_rpc_connection()
    request = {
        "obj": connection.session()._id,
        "method": "arti:get_rpc_proxy_info",
        "params": {},
        "meta": {
            "require": ["arti:does_not_exist"],
        },
    }
    try:
        out = connection.execute(request)
        assert False
    except ArtiRpcError as e:
        assert e.status_code() == ArtiRpcErrorStatus.REQUEST_FAILED
        err = e.response_obj()
        assert err["data"]["rpc:unsupported_features"] == ["arti:does_not_exist"]

@arti_test
def missing_features_2(context):
    """As missing_features, but uses with_meta."""
    connection = context.open_rpc_connection()

    try:
        out = (connection.session()
               .with_meta(require=["arti:does_not_exist"])
               .invoke("arti:get_rpc_proxy_info"))
        assert False
    except ArtiRpcError as e:
        assert e.status_code() == ArtiRpcErrorStatus.REQUEST_FAILED
        err = e.response_obj()
        assert err["data"]["rpc:unsupported_features"] == ["arti:does_not_exist"]

@arti_test
def empty_features_list(context):
    connection = context.open_rpc_connection()
    request = {
        "obj": connection.session()._id,
        "method": "arti:get_rpc_proxy_info",
        "params": {},
        "meta": {
            "require": [],
        },
    }

    out = connection.execute(request)
    # No exception raised; we're fine.
