# pt-proxy

This is a project that provides an interface to run the obfs4 pluggable transport
in a standalone manner, ie, instead of using obfs4 to connect to the Tor network,
we can use it to connect to the Internet directly.

Just like Tor, pt-proxy exposes a SOCKS5 proxy that other programs can be configured
to utilize, at which point their communications go through the Internet in an obfuscated
manner, reach the obfs4 server that has been configured ahead of time, and then connect
to the final destination from there on.

## Usage

First make sure you have [lyrebird](https://gitlab.torproject.org/tpo/anti-censorship/pluggable-transports/lyrebird/) installed.

Then, clone this repo and compile this project using `cargo`

### Server side

To run this program in server mode (that is, the program will listen on a specified address and route connections
wherever they need to go), we run

`cargo r -- <path-to-lyrebird> server <public-address-to-listen-to>`

Eg. `cargo r -- /usr/bin/lyrebird server 0.0.0.0:5555` will use the binary at `/usr/bin/lyrebird`
and listen on all interfaces on port 5555 for incoming connections to route.

If all goes well, you should see a string like this printed to the console:

`Authentication info is: cert=pAAsEKxisM4YDO0Qn1UqoN1hv+jA/7uTp2ZfAB152loVTGQy9oaGAqTTO+GtkRqKeL0bVg;iat-mode=0`

Copy and note down the `cert=pAAsEKxisM4YDO0Qn1UqoN1hv+jA/7uTp2ZfAB152loVTGQy9oaGAqTTO+GtkRqKeL0bVg;iat-mode=0` part.

Without this long string, we can't authenticate to the obfs4 server and we won't be able
to use the server!

### Client side

On the client side, we also need to run a local server, this local server
will be what your programs will connect to in order to be obfuscated using obfs4.

To do this, we run

`cargo r -- <path-to-lyrebird> client <remote-obfs4-server-ip> <remote-obfs4-server-port> <authentication-info>`

The authentication info is the long string that we created in the previous section and has to be enclosed in quotation marks.

Eg. an example usage of this program could be:

`cargo r -- lyrebird client 12.34.56.78 5555 "cert=pAAsEKxisM4YDO0Qn1UqoN1hv+jA/7uTp2ZfAB152loVTGQy9oaGAqTTO+GtkRqKeL0bVg;iat-mode=0"``

in order to connect to the server we initialized previously.

By default, to use this proxy, route all connections through `socks5://127.0.0.1:9050`.
If you wish to use a different port for the local SOCKS5 server, pass an additional argument to the above command, like this:

`cargo r -- lyrebird client <custom-socks5-proxy-port> 12.34.56.78 5555 "cert=pAAsEKxisM4YDO0Qn1UqoN1hv+jA/7uTp2ZfAB152loVTGQy9oaGAqTTO+GtkRqKeL0bVg;iat-mode=0"``
