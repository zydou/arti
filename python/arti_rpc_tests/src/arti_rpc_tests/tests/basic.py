from arti_rpc_tests import arti_test
from arti_rpc import ArtiRpcError

import json


@arti_test
def test_trivial(context):
    connection = context.open_rpc_connection()

    # Run a method that doesn't actually require anything major to be working.
    result = connection.session().invoke("arti:get_rpc_proxy_info")
    assert len(result["proxies"]) > 0

