import pprint
import os
from arti_rpc import *

# TODO RPC: This won't work unless you've configured it in arti too.
socket_path = os.path.expanduser("~/.local/run/arti/SOCKET")
# TODO RPC: This isn't how connection strings will work in production
connect_string = f"unix:{socket_path}"

# Connect to arti RPC.
conn = ArtiRpcConn(connect_string)

# Demo 1: print out a complete list of supported RPC methods.
methods = conn.session().invoke("arti:x_list_all_rpc_methods")

pprint.pprint(methods)

# Demo 2: Open a socket to www.torproject.org port 80 over the tor network.

# TODO RPC: This stalls (as of 24 Sep 2024); it used to work.
# I have patches in other branches to fix it.
#
sock = conn.connect("www.torproject.org", 80, isolation="rpc_demo")
print(sock)
