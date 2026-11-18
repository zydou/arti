from arti_rpc_tests import arti_test


@arti_test
def test_rpc_lookup(context):
    conn = context.open_rpc_connection()

    db = conn.session().invoke("arti:get_geoip_db")
    db = conn.make_object(db["id"])

    addrs = {
        # google's public dns.
        "8.8.8.8": "US",
        # one of the current torproject.org webservers
        "95.216.163.36": "FI",
        # one of the .us nameservers, denormalized.
        "2001:500:2d::000d": "US",
    }
    results = db.invoke("arti:geoip_lookup_countries", addresses=list(addrs.keys()))

    # We can't actually guarantee what countries the above addrs are in;
    # but since tor-geoip-db is static, we know that this won't break
    # except when we change it.
    #
    # If this breaks frequently, we should choose a different set of test
    # addresses, or a different strategy.
    c = results["countries"]
    assert c == addrs
