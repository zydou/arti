from arti_rpc_tests import arti_test
from arti_rpc import ArtiRpcError


@arti_test
def obj_not_avail_after_drop(context):
    connection = context.open_rpc_connection()

    client_1 = connection.session().invoke("arti:new_isolated_client")
    client_1 = connection.make_object(client_1["id"])

    client_2 = client_1.invoke("arti:new_isolated_client")
    client_2 = connection.make_object(client_2["id"])
    assert client_1.id() != client_2.id()

    client_1.release_ownership()
    client_1.invoke("rpc:release")

    try:
        # Should no longer be usable.
        client_1.invoke("arti:new_isolated_client")
        assert False
    except ArtiRpcError as e:
        assert "rpc:ObjectNotFound" in e.response_obj()["kinds"]

    try:
        # Can't drop twice.
        client_1.invoke("rpc:release")
        assert False
    except ArtiRpcError as e:
        assert "rpc:ObjectNotFound" in e.response_obj()["kinds"]

    # Should still be usable
    _ = client_2.invoke("arti:new_isolated_client")


@arti_test
def drop_misformed_id(context):
    connection = context.open_rpc_connection()

    try:
        connection.execute(
            {"obj": "zaphodbeeblebrox", "method": "rpc:release", "params": {}}
        )
        assert False
    except ArtiRpcError as e:
        assert "rpc:ObjectNotFound" in e.response_obj()["kinds"]


@arti_test
def drop_connection(context):
    connection = context.open_rpc_connection()

    # Make sure we can drop the "connection" object ID itself!
    connection.execute({"obj": "connection", "method": "rpc:release", "params": {}})

    try:
        connection.execute({"obj": "connection", "method": "rpc:release", "params": {}})
        assert False
    except ArtiRpcError as e:
        assert "rpc:ObjectNotFound" in e.response_obj()["kinds"]

    # Make sure we can't drop it again!
    try:
        connection.execute({"obj": "connection", "method": "rpc:release", "params": {}})
    except ArtiRpcError as e:
        assert "rpc:ObjectNotFound" in e.response_obj()["kinds"]


@arti_test
def drop_session(context):
    connection = context.open_rpc_connection()

    _ = connection.session().invoke("arti:new_isolated_client")

    connection.session().release_ownership()
    connection.session().invoke("rpc:release")

    try:
        _ = connection.session().invoke("arti:new_isolated_client")
        assert False
    except ArtiRpcError as e:
        assert "rpc:ObjectNotFound" in e.response_obj()["kinds"]
