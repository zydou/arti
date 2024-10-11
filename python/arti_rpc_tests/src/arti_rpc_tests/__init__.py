class RpcTestException(Exception):
    """Superclass for an exception generated from the RPC test code."""


class FatalException(Exception):
    """An exception indicating that we need to stop the unit tests immediately."""


def arti_test(func):
    """
    Decorator: Marks a function as a test.
    """
    # TODO: Later, expand this to take arguments to list specific requirements
    # or attributes for the test.
    func.arti_rpc_test = True
    return func
