from arti_rpc_tests import arti_test
from arti_rpc import ArtiRpcError


@arti_test
def test_su_fail(context):
    conn = context.open_rpc_connection(require_superuser=False)

    try:
        conn.session().invoke("arti:get_superuser_capability")
        assert False  # should not be reached
    except ArtiRpcError as e:
        assert "Superuser access not permitted" in str(e)

    # It's okay to drop superuser permission on a session that never
    # had it.
    r = conn.session().invoke("arti:remove_superuser_permission")
    assert r == {}


@arti_test
def test_su_and_drop(context):
    conn = context.open_rpc_connection(require_superuser=True)

    # We can invoke su on this session...
    su = conn.session().invoke("arti:get_superuser_capability")
    su = conn.make_object(su["id"])

    # Now try dropping su permissions on the session object.
    r = conn.session().invoke("arti:remove_superuser_permission")
    assert r == {}

    # At this point, su on the session should fail...
    try:
        conn.session().invoke("arti:get_superuser_capability")
        assert False  # should not be reached
    except ArtiRpcError as e:
        assert "Superuser access not permitted" in str(e)

    # But we should still be able to use the su capability we got before.
    r = su.invoke("arti:enter_dormant_mode")
    assert r == {}
