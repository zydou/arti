"""
Entry point for `arti_rpc_tests`.

LIMITATIONS: (TODO RPC)
- Only one instance of this process can run at once,
  since it tries to bind to a hardwired SOCKS tcp port.

BEHAVIOR:
- Launches arti
- Waits for it to be reachable via RPC.
- Runs a series of tests against arti or its RPC connection
- Tries to shut down Arti cleanly.

ENVIRONMENT VARIABLES:

- ARTI: Path to the arti binary to use.
- LIBARTI_RPC_CLIENT_CORE: Path to the Arti RPC library to use.
  (Consumed by `arti_rpc` package.)
- ARTI_RPC_TEST_DIR: Location at which Arti will store files
  and look for cache.  (This is reused across runs unless
  explicitly deleted.)

ARGUMENTS: None yet.
"""

from arti_rpc_tests import setup, runner

import arti_rpc

import os
import sys
import time

######
# Find arguments and environment.

arti_binary = os.environ["ARTI"]
test_dir = os.environ["ARTI_RPC_TEST_DIR"]

# TODO: Take this from the command line once it has arguments
testfilter = runner.TestFilter()

#####
# Build a test process
context = setup.TestContext.initialize(arti_binary, test_dir)
context.launch_arti()

#####
# Run the selected tests.

okay = runner.run_tests(testfilter, runner.all_modules(), context)

#####
# Wait a bit, then shut down arti.
#
# (We'll remove the delay once we have a few more tests.)

if context.arti_process is not None:
    SHUTDOWN_DELAY = 3
    print(f"Waiting {SHUTDOWN_DELAY} seconds...")
    time.sleep(SHUTDOWN_DELAY)  # TODO: remove this once the tests are nontrivial.
    print("Shutting down...")
    context.arti_process.close(gently=True)

if not okay:
    sys.exit(1)
