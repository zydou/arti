"""
Tests for client connect-point functionality.
"""

from arti_rpc_tests import arti_test
from arti_rpc import (
    ArtiRpcError,
    ArtiRpcErrorStatus,
    ArtiRpcConn,
    ArtiRpcConnBuilder,
)

import sys
import tempfile
import os
import urllib.parse


def connpt_abort():
    """
    Return a connect point that fails with an explicit abort.
    """
    return """\
[builtin]
builtin = "abort"
"""


def connpt_unix(context):
    """
    Return a connect point that uses an AF_UNIX connection
    to connect to arti.
    """
    return f"""
[connect]
socket = "unix:{context.socket_path}"
auth = "none"
"""


def connpt_tcp(context):
    """
    Return a connect point that uses a TCP connection
    and cookie authentication to connect to arti.
    """
    return f"""
[connect]
socket = "inet:127.0.0.1:{context.rpc_port}"
auth = {{ cookie = {{ path = "{context.cookie_path}" }} }}
"""


def connpt_working(context):
    """
    Return a connect point that should work for connecting to the
    arti instance in `context`.

    (Prefer this function to `connpt_unix()`, so that once we have
    something that works on windows, we can make our tests pass there too.)
    """
    return connpt_tcp(context)


class Tempdir:
    """
    Helper for creating files within a temporary directory.

    When this object is destroyed, the directory and its contents are deleted.
    """

    def __init__(self):
        self.tmpdir = tempfile.TemporaryDirectory()

    def dirname(self):
        """
        Return the name of the temporary directory
        """
        return self.tmpdir.name

    def fname(self, name):
        """
        Return the name of a file within the temporary directory
        """
        return os.path.join(self.tmpdir.name, name)

    def write(self, fname, text):
        """
        Store `text` into the file called `fname` within the temporary directory.
        """
        with open(self.fname(fname), "w") as f:
            f.write(text)


class SavedEnviron:
    """
    Context manager to preserve os.environ while a test is changing it.
    """

    def __init__(self):
        pass

    def __enter__(self):
        self.env = dict(os.environ)

    def __exit__(self, _et, _ev, _tb):
        os.environ.update(self.env)
        for k in os.environ.keys() - self.env.keys():
            del os.environ[k]


def assert_builder_aborts(bld: ArtiRpcConnBuilder):
    """
    Try to open a RPC connection with `bld`, and assert that the attempt aborts.
    """
    try:
        _ = bld.connect()
        assert False  # shouldn't be reached.
    except ArtiRpcError as e:
        assert e.status_code() == ArtiRpcErrorStatus.ALL_CONNECT_ATTEMPTS_FAILED
        assert 'Encountered an explicit "abort"' in str(e)


def assert_builder_connects(bld):
    """
    Try to open a RPC connection with `bld`, and assert that the attempt succeeds.
    """
    c = bld.connect()
    assert c is not None


@arti_test
def ordering_literal_manual(context):
    # Assert that prepend_literal_connect_point respects ordering.
    bld = ArtiRpcConnBuilder()
    bld.prepend_literal_connect_point(connpt_working(context))
    bld.prepend_literal_connect_point(connpt_abort())
    assert_builder_aborts(bld)

    bld = ArtiRpcConnBuilder()
    bld.prepend_literal_connect_point(connpt_abort())
    bld.prepend_literal_connect_point(connpt_working(context))
    assert_builder_connects(bld)


@arti_test
def ordering_paths_manual(context):
    # Assert that prepend_literal_path respects ordering.
    tmp = Tempdir()
    tmp.write("abort.toml", connpt_abort())
    tmp.write("working.toml", connpt_working(context))

    bld = ArtiRpcConnBuilder()
    bld.prepend_literal_path(tmp.fname("working.toml"))
    bld.prepend_literal_path(tmp.fname("abort.toml"))
    assert_builder_aborts(bld)

    bld = ArtiRpcConnBuilder()
    bld.prepend_literal_path(tmp.fname("abort.toml"))
    bld.prepend_literal_path(tmp.fname("working.toml"))
    assert_builder_connects(bld)


@arti_test
def ordering_env_path(context):
    # Assert that paths within our envvars respect ordering.
    tmp = Tempdir()
    tmp.write("abort.toml", connpt_abort())
    tmp.write("working.toml", connpt_working(context))

    fn_a = tmp.fname("abort.toml")
    fn_w = tmp.fname("working.toml")
    assert ":" not in fn_a
    assert ":" not in fn_w

    for varname in ["ARTI_RPC_CONNECT_PATH", "ARTI_RPC_CONNECT_PATH_OVERRIDE"]:
        assert varname not in os.environ
        with SavedEnviron():
            bld = ArtiRpcConnBuilder()
            os.environ[varname] = f"{fn_a}:{fn_w}"
            assert_builder_aborts(bld)

            bld = ArtiRpcConnBuilder()
            os.environ[varname] = f"{fn_w}:{fn_a}"
            assert_builder_connects(bld)
        assert varname not in os.environ


@arti_test
def ordering_env_literal(context):
    # Assert that literal connect points within our envvars respect ordering.
    q_a = urllib.parse.quote(connpt_abort())
    q_w = urllib.parse.quote(connpt_working(context))

    for varname in ["ARTI_RPC_CONNECT_PATH", "ARTI_RPC_CONNECT_PATH_OVERRIDE"]:
        assert varname not in os.environ
        with SavedEnviron():
            bld = ArtiRpcConnBuilder()
            os.environ[varname] = f"{q_a}:{q_w}"
            assert_builder_aborts(bld)

            bld = ArtiRpcConnBuilder()
            os.environ[varname] = f"{q_w}:{q_a}"
            assert_builder_connects(bld)
        assert varname not in os.environ


@arti_test
def ordering_dir(context):
    # Assert that files within a directory respect ordering.
    tmp = Tempdir()
    tmp.write("00_name_ignored", connpt_abort())  # no ".toml" suffix
    tmp.write("01_abort.toml", connpt_abort())
    tmp.write("02_connect.toml", connpt_working(context))
    tmp.write("03_abort.toml", connpt_abort())

    bld = ArtiRpcConnBuilder()
    bld.prepend_literal_path(tmp.dirname())
    assert_builder_aborts(bld)

    os.unlink(tmp.fname("01_abort.toml"))
    assert_builder_connects(bld)


@arti_test
def ordering_multi(context):
    # Assert that our envvars and manually inserted items respect ordering
    # wrt one another.
    tmp = Tempdir()
    tmp.write("abort.toml", connpt_abort())
    tmp.write("working.toml", connpt_working(context))

    fn_a = tmp.fname("abort.toml")
    fn_w = tmp.fname("working.toml")

    with SavedEnviron():
        bld = ArtiRpcConnBuilder()
        os.environ["ARTI_RPC_CONNECT_PATH"] = fn_a
        assert_builder_aborts(bld)

        bld.prepend_literal_path(fn_w)
        assert_builder_connects(bld)

        os.environ["ARTI_RPC_CONNECT_PATH_OVERRIDE"] = fn_a
        assert_builder_aborts(bld)


@arti_test
def connect_nobuilder(context):
    # Assert that we can use ArtiRpcConn constructor
    # without a builder.
    tmp = Tempdir()
    tmp.write("abort.toml", connpt_abort())
    tmp.write("working.toml", connpt_working(context))

    fn_a = tmp.fname("abort.toml")
    fn_w = tmp.fname("working.toml")

    with SavedEnviron():
        os.environ["ARTI_RPC_CONNECT_PATH"] = fn_a
        try:
            _ = ArtiRpcConn()
            assert False  # Shouldn't be reached.
        except ArtiRpcError as e:
            assert e.status_code() == ArtiRpcErrorStatus.ALL_CONNECT_ATTEMPTS_FAILED
            assert 'Encountered an explicit "abort"' in str(e)

        os.environ["ARTI_RPC_CONNECT_PATH"] = fn_w
        c = ArtiRpcConn()
        assert c is not None


@arti_test
def connect_unix(context):
    # Make sure that if we're on unix, unix connect points work.

    if sys.platform in ["win32", "cygwin"]:
        return  # Skipped.

    bld = ArtiRpcConnBuilder()
    bld.prepend_literal_connect_point(connpt_abort())
    bld.prepend_literal_connect_point(connpt_unix(context))
    assert_builder_connects(bld)
