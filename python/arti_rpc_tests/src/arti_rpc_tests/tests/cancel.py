from arti_rpc_tests import arti_test
from arti_rpc import ArtiRpcError


@arti_test
def cancel_nonexistent(context):
    conn = context.open_rpc_connection()

    try:
        conn.connection().invoke("rpc:cancel", request_id="123")
        assert False
    except ArtiRpcError as e:
        assert "rpc:ObjectNotFound" in e.response_obj()["kinds"]


@arti_test
def cancel_pending(context):
    conn = context.open_rpc_connection()

    client_id = conn.session().invoke("arti:get_client")["id"]
    client = conn.make_object(client_id)

    # This request provides updates, and runs forever, so we can be certain
    # that cancelling it will work.
    hnd = client.with_meta(updates=True).invoke_with_handle("arti:watch_client_status")

    hnd.cancel()

    while True:
        resp = hnd.wait()
        if err := resp.error():
            assert "rpc:RequestCancelled" in err["kinds"]
            break
