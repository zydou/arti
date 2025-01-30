---
title: Configuring Applications
---

# Configuring applications to use Arti

Once Arti has been [compiled](/guides/compiling-arti) and [started as a proxy](/guides/starting-arti), it becomes possible to configure applications to utilize the `localhost:9150` SOCKS proxy. By sending your network traffic through the Tor network, Arti anonymizes your IP address and provides enhanced [privacy and security measures](https://support.torproject.org/#about_protections).

Before attempting to configure an application to use Arti, ensure that the program supports using the Tor nerwork and SOCKS proxies. Using the SOCKS proxy, your connection is directed through the Tor network, offering a certain level of anonymity. However, not all applications support SOCKS proxies, and there is the potential risk of IP address leaks, disclosure of other identifiable information, or applications forgetting to use the SOCKS proxy.

To configure an application to use Arti as a proxy, confirm that Arti is actively running on your local setup before taking the following steps:

1. Access the application's proxy settings to initiate the configuration for the SOCKS proxy.
2. Specify the SOCKS proxy server as `127.0.0.1` and set the port to `9150`. This ensures that Arti is recognized as the proxy, as Arti operates on port `9150` .
3. Verify the functionality of the SOCKS proxy within the application by using any features for testing purposes. 

It is advised not to configure Arti for an application without a thorough understanding of the data transmitted by that application and the potential for de-anonymization. Additionally, using Arti with a standard, unmodified browser is not recommended due to the substantial information leakage inherent in regular browsers. Instead, we strongly recommend [using Arti with Tor Browser](/integrating-arti/using-tor) for secure web browsing.

We ask that you use Arti responsibly when configuring it for Tor-supporting applications, as misuse can result in Tor access being blocked for others.
