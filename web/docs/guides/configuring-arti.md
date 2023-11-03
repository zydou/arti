---
title: Configuring Applications
---

# Configuring applications to use Arti

Once Arti has been [compiled](/guides/compiling-arti) and [started as a proxy](/guides/starting-arti), it becomes possible to configure applications to utilize the `localhost:9150` SOCKS proxy. By sending your network traffic through the Tor network, Arti anonymizes your IP address and provides enhanced privacy and security measures.

To configure your applications, such as browsers, to use Arti as a proxy, confirm that Arti is actively running on your local setup before taking the following steps:

1. Access your computer’s proxy settings to initiate the configuration for the SOCKS proxy.
2. Specify the SOCKS proxy server as `127.0.0.1` and set the port to `9150`. This ensures that Arti is recognized as the proxy, as Arti operates on port `9150` .
3. Verify the functionality of the SOCKS proxy by navigating to a website that displays your public IP address, such as [whatismyip.com](https://whatismyip.com). If the proxy is configured correctly, the IP address displayed should differ from your actual IP address.

It's crucial to acknowledge that when using a SOCKS proxy, your connection is directed through the Tor network, offering a certain level of anonymity. However, it's important to note that not all applications support SOCKS proxies, and there is a risk of potential IP address leaks or disclosure of other identifiable information.

Additionally, it's essential to understand the legal and ethical implications of using proxies and to ensure that your activities comply with the terms of service of the websites you visit, promoting responsible and lawful use of proxy services.

