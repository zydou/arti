from arti_rpc_tests import arti_test
from arti_rpc import ArtiRpcError


@arti_test
def test_get_config(context):
    conn = context.open_rpc_connection(require_superuser=True)

    su = conn.session().invoke("arti:get_superuser_capability")
    su = conn.make_object(su["id"])

    # Look at a set of defaults that we're unlikely to change much.
    cfg = su.invoke("arti:get_config", key="address_filter")["value"]

    # Look at a single value
    v = su.invoke("arti:get_config", key="address_filter.allow_local_addrs")["value"]

    # Look at the whole tree
    tree = su.invoke("arti:get_config", key="")["value"]

    assert not cfg["allow_local_addrs"]
    assert v == cfg["allow_local_addrs"]
    assert cfg == tree["address_filter"]


@arti_test
def test_set_config(context):
    conn = context.open_rpc_connection(require_superuser=True)

    su = conn.session().invoke("arti:get_superuser_capability")
    su = conn.make_object(su["id"])

    # Try changing a single value in a way that works.
    su.invoke("arti:set_config", key="address_filter.allow_local_addrs", value=True)

    # Now try a way that doesn't work. (This value can't be an integer).
    try:
        su.invoke("arti:set_config", key="address_filter.allow_local_addrs", value=7)
        assert False
    except ArtiRpcError:
        pass

    # Now restore the config settings.
    su.invoke("arti:set_config", key="", value={})
