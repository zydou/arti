from arti_rpc_tests import arti_test
from arti_rpc import ArtiRpcError


@arti_test
def clone_id_strong(context):
    connection = context.open_rpc_connection()

    client_1 = connection.session().invoke("arti:new_isolated_client")
    client_1 = connection.make_object(client_1["id"])

    client_2 = client_1.invoke("rpc:clone_id")
    client_2 = connection.make_object(client_2["id"])

    # client1 should still work.
    _ = client_1.invoke("arti:new_isolated_client")

    # client2 should work too.
    _ = client_2.invoke("arti:new_isolated_client")


@arti_test
def clone_id_weak(context):
    connection = context.open_rpc_connection()

    client_1 = connection.session().invoke("arti:new_isolated_client")
    client_1 = connection.make_object(client_1["id"])

    client_2 = client_1.invoke("rpc:clone_id", weak=True)
    client_2 = connection.make_object(client_2["id"])

    # client1 should still work.
    _ = client_1.invoke("arti:new_isolated_client")

    # client2 should work too.
    _ = client_2.invoke("arti:new_isolated_client")

    # This causes client1 to get released...
    del client_1

    # Which should make client2 nonfunctional.
    try:
        _ = client_2.invoke("arti:new_isolated_client")
        assert False
    except ArtiRpcError as e:
        assert "rpc:WeakReferenceExpired" in e.response_obj()["kinds"]
