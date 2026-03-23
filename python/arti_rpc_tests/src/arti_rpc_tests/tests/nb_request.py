from arti_rpc_tests import arti_test


@arti_test
def nonblocking_requests(context):
    connection = context.open_rpc_connection()

    # Launch three requests.
    connection.session().submit("CL1", "arti:new_isolated_client")
    connection.session().submit("CL2", "arti:new_isolated_client")
    connection.session().submit("CL3", "arti:new_isolated_client")

    m = {}
    for _ in range(3):
        r = connection.wait()
        m[r.user_tag()] = r

    assert len(m) == 3
    assert len(set(m.values())) == 3
    assert set(m.keys()) == set(["CL1", "CL2", "CL3"])
