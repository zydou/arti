def test_trivial(context):
    connection = context.open_rpc_connection()

    # Run a method that doesn't actually require anything major to be working.
    result = connection.session().invoke("arti:get_rpc_proxy_info")
    assert len(result["proxies"]) > 0
