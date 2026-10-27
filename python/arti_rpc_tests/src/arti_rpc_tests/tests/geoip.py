from arti_rpc_tests import arti_test


@arti_test
def test_get_config(context):
    conn = context.open_rpc_connection()

    db = conn.session().invoke("arti:get_geoip_db")
    db = conn.make_object(db["id"])

    addrs = [
        "8.8.8.8",  # google's public dns.
        "95.216.163.36",  # one of the current torproject.org webservers
        "2001:500:2d::d",  # one of the .us nameservers
    ]
    results = db.invoke("arti:geoip_lookup_countries", addresses=addrs)

    # We can't actually guarantee what countries the above addrs are in...
    c = results["countries"]
    assert isinstance(c, dict)
    # but we can make sure that we got at least 2...
    assert len(c) >= 2
    for k, v in c.items():
        # and that we didn't get an answer for anything we didn't ask for...
        assert k in addrs
        # and that every answer is a CC.
        assert len(v) == 2
