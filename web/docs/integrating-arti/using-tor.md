---
title: Using Arti with Tor Browser
---

# Using Arti with Tor Browser

To hook up Arti with [Tor Browser](https://www.torproject.org/download/), you can launch Arti independently from Tor Browser. After compiling Arti,  start it with the basic configuration parameters to ensure that Arti sets its SOCKS port on `9150`:

```bash
$ ./target/release/arti proxy -l debug -p 9150
```

Once Arti is running on the specified port, run the following commands to launch and instruct the Tor Browser to use that SOCKS port, replacing the file path with the actual path of your Tor browser.

### Linux

```bash
$ TOR_PROVIDER=none TOR_SOCKS_PORT=9150 ./start-tor-browser.desktop
```

### OS X

```bash
$ TOR_PROVIDER=none TOR_SOCKS_PORT=9150 /path/to/Tor\ Browser/Contents/MacOS/firefox
```

### Windows

Create a shortcut with the `Target` set to:

```bash
C:\Windows\System32\cmd.exe /c "SET TOR_PROVIDER=none&& SET TOR_SOCKS_PORT=9150&& START /D ^"C:\path\to\Tor Browser\Browser^" firefox.exe"
```

and `Start in` set to:

```bash
"C:\path\to\Tor Browser\Browser"
```

The resulting Tor Browser should be using arti. 

**Note:** 

Any features depending on Tor’s control-port protocol will not work because Arti does not support them yet. However, features such as the “New circuit for this site” button should work as it does not depend on the control-port.

