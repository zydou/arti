---
title: Creating configuration options
---

# Arti Configuration Options

## Configuration File Location

The default location of Arti's configuration file is platform-dependent.

| OS | Header 2 |
|----------|----------|
| Unix | `~/.config/arti/arti.toml` |
| macOS | `~/Library/Application Support/org.torproject.arti/arti.toml` |
| Windows | `\Users\<USERNAME>\AppData\Roaming\arti\arti.toml` |

You can change the default configuration file location from the command line, using the `--config` option.

## Configuration File Format and Example

The configuration file is TOML. For an example, see `arti-example-config.toml` in the [Arti repository](https://gitlab.torproject.org/tpo/core/arti/-/blob/main/crates/arti/src/arti-example-config.toml). There is also a copy in the source tree. That example config file documents the configuration options. Below is an explanation of the different configuration options.


## Configuration File Structure

The Arti configuration file follows the standard [TOML format](https://toml.io/en/). We have organized the config file into several sections, each representing different aspects of Arti's configuration.

Each section starts with a header in square brackets (e.g., `[application]`). It includes various settings underneath it, formatted as key-value pairs. The settings can be uncommented (by removing the `#`) and modified to change the behavior of the Arti application. The comments guide the purpose and usage of each setting.

Here's a high-level overview of its structure:

### Comments

The file begins with comments, indicated by `#`. Arti ignores these comments. Comments provide explanations or instructions to the user.

### Application Behavior Settings `[application]`:

This section contains settings related to how Arti behaves as an application, such as watching configuration files for changes, permitting debugging, and allowing the program to run as root.

#### Options

-   `watch_configuration`: 
    -   **Purpose:** Determines whether Arti should watch its configuration files for changes.
    -   **Behavior:** When set to `true`, Arti actively monitors its configuration files and applies any changes made while running. This can be useful for dynamically updating the configuration without restarting Arti.
    -   **Note:** This feature may not behave as expected if there are changes to the symlinks in the directory path of the configuration files or if those directories are removed and recreated.

-   `permit_debugging`:
    -   **Purpose:** Controls whether other processes run by the same user are allowed to inspect the memory of the Arti process.
    -   **Behavior:** If set to `true`, it allows debugging operations such as inspecting memory, which can be helpful for development or troubleshooting. By default, and especially when built with the `harden` feature, Arti keeps its memory and state secret, including disabling core dumps.

-   `allow_running_as_root`:
    -   **Purpose:** Specifies whether Arti is permitted to start when the current user is root
    -   **Behavior:** Arti will not run as the root user by default, as this is generally considered a security risk or a configuration error. You can set this to `true` to override this behavior, allowing Arti to run as root.

### Proxy Configuration `[proxy]`:

The `[proxy]` section lets you activate Arti's proxy functionality. You can specify proxy settings, including default ports for SOCKS connections and DNS requests.

#### Options

-   `socks_listen`:
    -   **Purpose:** Specifies the default port for listening to SOCKS connections.
    -   **Behavior:** This setting determines the port on which Arti listens for incoming SOCKS protocol connections. Arti, by default, listens on the local interface (`localhost`).

-   `dns_listen`:
    -   **Purpose:** Defines the port used to listen for DNS requests.
    -   **Behavior:** This setting allows listening for DNS queries, which Art will resolve over the Tor network. Setting this to a port number (other than 0) enables the DNS listening functionality.
    -   **Note:** A value of 0 means this feature is disabled. Enabling this feature will anonymize your DNS requests over the Tor network, but it requires careful configuration to avoid DNS leaks.

### Logging Configuration `[logging]`:

The segment titled `[logging]` lets you specify how logging should be handled, including console logging, journald integration, file logging with rotation, and the handling of sensitive information. This segment also contains settings for time granularity in logs.

#### Options

-   `console`:
    -   **Purpose:** Specifies the filtering directives for sending trace messages to the console (standard output).
    -   **Behavior:** This setting allows you to define what level of logging information (e.g., `info``, `debug``, `trace``) should be output to the console. It can be a single log level or a more complex configuration with per-module settings.
    -   **Note:** This setting can be overridden with command-line options (`-l`, `--log-level`). The configuration can range from general log levels to more granular, module-specific levels.

-   [`journald`](https://sematext.com/blog/journald-logging-tutorial/):
    -   **Purpose:** Sets up filtering directives for sending trace messages to the journald logging system.
    -   **Behavior:** Similar to the `console` setting but specifically for sending log output to the journald system, a centralized logging solution commonly used in Linux environments.
    -   **Note:** An empty string as a value indicates that Arti shouldn't use journald logging.

-   `files`:
    -   **Purpose:** Allows configuration of one or more log files, each with different filters and optional rotation settings.
    -   **Behavior:** This setting specifies log files where Arti should write log messages and their respective filter levels and rotation policies. For example, you can have separate log files for debugging and trace-level logs, each with its rotation policy, such as daily or size-based rotation.
    -   **Note:** This is an array of configurations where each item specifies a `path` for the log file, a `filter` for the log level, and an optional `rotate` policy.

-   `log_sensitive_information`:
    -   **Purpose:** Controls whether to log sensitive information like target hostnames and IP addresses.
    -   **Behavior:** When set to false (the default), sensitive information is not logged in level `info` or higher messages. This setting is crucial for privacy and security, as it prevents potentially sensitive data from being stored in logs.

-   `time_granularity`:
    -   **Purpose:** Determines the granularity with which to display times in logs.
    -   **Behavior:** This setting is used to round the times in logs and display them less precisely. It's a security feature to lower the risk of aiding traffic analysis attacks through precise timing logs.
    -   **Note:** This setting won't affect the granularity of times recorded by external logging systems like journald.

### Storage Paths `[storage]`:

With `[storage]`, you can define locations for storing cache and state data on disk, with support for using environment variables and user home directories in path definitions.

Under the `[storage]` section, you can nest a `[storage.keystore]` section for keystore configuration, in addition to a `[storage.permissions]` sub-section for filesystem permission rules.

#### Options

-   `cache_dir`:
    -   **Purpose:** Defines the directory for storing cached data.
    -   **Behavior:** This setting determines where Arti will store cached information, such as downloaded directory information from the Tor network. This cache stores data that Arti may reuse across restarts to improve performance and reduce network load.
    -   **Note:** The path can include variables like `${ARTI_CACHE}`, which Arti will expand to a platform-specific default location, or you can set it to a custom path.

-   `state_dir`:
    -   **Purpose:** Specifies the directory for storing stateful data.
    -   **Behavior:** The `state_dir` setting indicates where Arti should keep its state data, which includes long-term information that Arti needs to maintain its operations, such as keys or long-term statistics.
    -   **Note:** Similar to `cache_dir`, the path for `state_dir` can include variables like `${ARTI_LOCAL_DATA}` for default locations or be set to a custom path.

##### Subsection `[storage.keystore]`

This subsection, when present, would handle configurations related to Arti's keystore, which Arti uses for managing cryptographic keys.

-   `enabled`:
    -   **Purpose:** enabled
    -   **Behavior:** Determines whether the keystore feature is enabled.

-   `path`:
    -   **Purpose:** Specifies the directory where the keystore is located.

##### Subsection `[storage.permissions]`

This subsection configures how Arti enforces filesystem permissions when accessing its cache and state directories.

-   `dangerously_trust_everyone`:
    -   **Behavior:** If set to `true`, Arti ignores filesystem permissions, which can be a security risk.

-   `trust_user`:
    -   **Purpose:** Specifies which user is trusted to own files and directories.
    -   **Behavior:** The value `":current"` means trusting the current user.

-   `trust_group`:
    -   **Purpose:** Indicates which group is trusted to have read/write access to files and directories.
    -   **Behavior:** The value `":selfnamed"` implies trusting the group with the same name as the current user.

-   `ignore_prefix`:
    -   **Behavior:** If set, gives a path prefix that will always be trusted. For example, setting it to `"/home/"` means Arti will trust the permissions on `/` and `/home` but check permissions on subdirectories.

### Bridges Configuration `[bridges]`:

This allows you to configure anti-censorship features through bridges, including settings for enabling bridges, specifying bridge lines, and configuring pluggable transports.

#### Options

-   `enabled`:
    -   **Purpose:** Controls whether Arti should use configured bridges.
    -   **Behavior:** The setting can have three values:
        -   `false`: Arti will not use any bridges, even if you have configured them.
        -   `auto`: Arti will use bridges if you have configured them.
        -   `true`: Arti **requires** the configuration of bridges and will use them.
    -   **Note:** This is useful for users in environments where access to the Tor network is blocked or heavily monitored, as bridges can help circumvent such restrictions.

-   `bridges`:
    -   **Purpose:** Specifies the bridges (including pluggable transports) Arti should use.
    -   **Behavior:** This setting is an array where each entry describes a bridge. The description includes the bridge's IP address, ORPort, fingerprint, and, if applicable, additional parameters for pluggable transports (like obfs4).
    -   **Examples:**
        -   For a basic bridge, a typical line might look like `"192.0.2.83:80 $0bac39417268b96b9f514ef763fa6fba1a788956"`.
        -   For a pluggable transport, it might be more complex, like `"obfs4 bridge.example.net:80 $0bac39417268b69b9f514e7f63fa6fba1a788958 ed25519:dGhpcyBpcyBbpmNyZWRpYmx5IHNpbGx5ISEhISEhISA iat-mode=1"`.
    -   **Note:** Bridges are beneficial for circumventing network censorship and can be essential for users in restrictive environments. Listing a bridge will have no effect unless `bridges.enabled` is true, and unless that bridge's pluggable transport (if any) is provided.

##### Subsection `[[bridges.transports]]`

This subsection configures pluggable transport binaries, which you can use to circumvent censorship targeting Tor traffic.

-   `protocols`:
    -   **Purpose:** Specifies which pluggable transports the binary provides (e.g., `["obfs4", "obfs5"]`).

-   `path`:
    -   **Purpose:** The path to the transport binary.

-   `arguments`:
    -   **Purpose:** Specifies any command-line arguments to pass to the binary.

-   `run_on_startup`:
    -   **Purpose:** Determines whether Arti will run the binary on startup.
    -   **Behavior:** If set to `false`, Arti will launch the binary upon first using the transport provided.

### Consensus Parameters Overrides `[override_net_params]`:

This section allows you to customize specific network parameters usually defined in the Tor network consensus. This section allows advanced users to fine-tune Arti's behavior by overriding default parameters.

This advanced feature should be used only by users who deeply understand the Tor network and its operational parameters.

#### Options

The consensus parameters can include a wide range of network settings. Some examples might be:

-   `circwindow`: This parameter might control the size of the circuit window (the number of cells that can be in flight on a circuit before acknowledgments are needed).
-   `min_paths_for_circs_pct`: This specifies the minimum percentage of path lengths Arti considers for building circuits.

The actual parameters available for override depend on the Arti version and the [Tor network's current consensus parameters.](https://spec.torproject.org/param-spec.html)

> **Warning:** Incorrect settings can lead to undesirable behavior, reduced anonymity, or performance issues. Therefore, you should change these parameters with extreme caution.

### Download Schedule `[download_schedule]`:

This section is important for managing how and when Arti downloads various directory information from the Tor network. This directory information is essential for understanding the state of the network, such as available relays and services.

Configures the timing and retry strategies for downloading various types of directory information.

#### Options

-   `retry_bootstrap`:
    -   **Purpose:** Configures how Arti retries the initial bootstrapping process when trying to start up and connect to the Tor network.
    -   **Parameters:**
        -   `attempts`: The number of attempts Arti will make to bootstrap.
        -   `initial_delay`: The initial delay before retrying the bootstrap process.
        -   `parallelism`: The level of parallelism allowed in the bootstrap attempts.
    -   **Behavior:** This setting is crucial for ensuring that Arti can successfully connect to the Tor network, especially in environments where the first attempt might fail due to network issues or censorship.

-   `retry_consensus`:
    -   **Purpose:** Controls the retry behavior for downloading the consensus document, which is a critical component containing information about the current state of the Tor network.
    -   **Parameters:**
        -   `attempts`: The number of attempts to download the consensus document.
        -   `initial_delay`: The initial delay before reattempting to download the consensus.
        -   `parallelism`: The number of parallel download attempts.
    -   **Behavior:** This ensures Arti continues to attempt to download the consensus document, which is essential for its operation, in case of initial failures.

-   `retry_certs`:
    -   **Purpose:** Sets the retry strategy for downloading authority certificates, which Arti uses to authenticate the consensus document.
    -   **Parameters:**
        -   `attempts`: Number of retry attempts for the certificates.
        -   `initial_delay`: Initial delay before retrying certificate downloads.
        -   `parallelism`: The number of parallel download attempts.
    -   **Behavior:** This configuration is essential for the security of Arti, ensuring it obtains the necessary certificates to validate the information it relies on.

-   `retry_microdescs`:
    -   **Purpose:** Configures how Arti retries downloading microdescriptors.
    -   **Parameters:**
        -   `attempts`: The number of attempts for downloading microdescriptors.
        -   `initial_delay`: Initial delay before retrying.
        -   `parallelism`: The number of parallel download attempts.
    -   **Behavior:** Microdescriptors provide more detailed information about Tor relays. This setting ensures that Arti persistently attempts to acquire up-to-date microdescriptors, critical for building efficient and secure circuits.

These settings ensure that Arti can reliably download and update the directory information to operate within the Tor network. They allow Arti to handle network variability and potential censorship by retrying failed download attempts with configurable parameters. Proper configuration is essential for maintaining the robustness and reliability of the Arti client.

### Directory Tolerance `[directory_tolerance]`:

The directory tolerance settings help Arti manage situations where there might be discrepancies in time or delays in receiving updated directory information from the Tor network. These discrepancies can arise for various reasons, such as clock skew (differences in time settings between different computers) or temporary issues in consensus among directory authorities. This information is critical for Arti to understand the current state of the Tor network.

#### Options

-   `pre_valid_tolerance`: 
    -   **Purpose:** Sets the duration for which Arti will accept directory documents before they are officially valid.
    -   **Behavior:** This parameter allows Arti to accept and use directory information it receives slightly before its scheduled validity period.
    -   **Note:** The setting helps deal with clock skews and minor synchronization issues between different nodes in the Tor network. It ensures that Arti can function smoothly even if its clock is slightly ahead or receives data early.

-   `post_valid_tolerance`: 
    -   **Purpose:** Specifies how long Arti will continue to consider directory documents usable after their official validity period has ended.
    -   **Behavior:** This setting allows Arti to use directory information for a certain period even after it has technically expired.
    -   **Note:** The tolerance for using slightly outdated directory information is important for maintaining connectivity when new directory information is delayed or when there are minor discrepancies in clock settings across the network. It helps Arti remain operational despite a temporary disruption in receiving updated directory data.

These settings provide a buffer for timing inaccuracies and delays in the distribution of directory information within the Tor network. By configuring these tolerances, you can enhance Arti's robustness and ability to cope with real-world network conditions, ensuring more consistent and reliable operation. However, setting these tolerances too high might risk using outdated information.

### Circuit Path Rules `[path_rules]`:

The configuration's `[path_rules]` govern how Arti selects and constructs paths through the Tor network for its circuits. A circuit in the Tor network is a path through multiple relays, providing anonymity and privacy for the user.

The path rules enhance privacy and security by dictating how Arti chooses relays for building circuits. These rules aim to avoid patterns or potential vulnerabilities that could compromise anonymity, such as selecting relays that are too close in terms of network topology or operated by the same entity.

#### Options

-   `ipv4_subnet_family_prefix`: 
    -   **Purpose:** Specifies how far apart two relays must be in IPv4 address space to be used in the same circuit.
    -   **Behavior:** This setting dictates the minimum difference in the IPv4 addresses of relays that Arti will consider when building a circuit. For example, a value of `16` means that two relays in the same circuit cannot have the first 16 bits of their IPv4 addresses be the same.
    -   **Note:** This rule helps you avoid choosing relays that are too close in network topology or possibly under the same administrative control, thereby enhancing security and anonymity.

-   `ipv6_subnet_family_prefix`: 
    -   **Purpose:** Similar to `ipv4_subnet_family_prefix`, but for IPv6 addresses.
    -   **Behavior:** Determines the minimum difference in the IPv6 addresses of relays for circuit construction. A typical value might be 32, ensuring that the relays chosen in a circuit are sufficiently far apart in their IPv6 address space.
    -   **Note:** This setting helps to prevent the selection of relays that are geographically or organizationally close in the IPv6 network, which is important for maintaining the anonymity properties of the Tor network.

-   `reachable_addrs`: 
    -   **Purpose:** This optional setting specifies a list of addresses or ports that Arti is allowed to contact directly.
    -   **Behavior:** It restricts which relays Arti can connect to based on their addresses or the ports they are listening on. This can be useful in environments with firewall restrictions or specific network policies.
    -   **Note:** Proper configuration of this setting can ensure compliance with local network policies while maintaining the effectiveness of the Tor connection.

These settings play a critical role in how Arti selects relays for its circuits, directly impacting the privacy and effectiveness of the Tor connections it establishes. Proper configuration of these path rules is key to maintaining the anonymity and security properties of the Tor network.

### Address Filters `[address_filter]`:

With the `[address_filter]` section, you can specify rules for what network addresses Arti is allowed or forbidden to connect to **over the Tor network**. This is important for various reasons, including compliance with network policies, avoiding specific traffic, or enhancing privacy and security.

#### Options

-   `allow_local_addrs`: 
    -   **Purpose:** Determines whether Arti can try to make anonymous connections to network-local addresses.
    -   **Behavior:** When set to `true`, Arti can connect to addresses considered local to the machine's network, such as private IP ranges (e.g., 192.168.x.x, 10.x.x.x).  Exit relays typically refuse these addresses.
    -   **Note:** Allowing connections to local addresses can be helpful in specific network configurations but may pose security risks or reveal information about the local network. In most cases, especially for privacy-focused usage, this is set to `false` to prevent such connections.

-   `allow_onion_addrs`: 
    -   **Purpose:** Specifies whether Arti should connect to onion services within the Tor network.
    -   **Behavior:** If set to `true`, Arti can establish connections to `.onion` addresses, allowing access to services hosted within the Tor network.
    -   **Note:** This setting is important for users who wish to access [onion services](docs/guides/connecting-to-onion.md). Enabling this feature should be carefully considered based on the user's privacy needs and the state of Arti's implementation of onion services. However, enabling this option alone won't work unless the **onion service client feature is enabled at compile time**. 

These settings allow users to fine-tune Arti's behavior in terms of network connections, ensuring that it adheres to desired security policies and operational requirements. Proper configuration of address filters is critical to aligning Arti's behavior with its operating environment's specific needs and constraints.

### Stream Timeouts `[stream_timeouts]`:

`[stream_timeouts]` is dedicated to defining how Arti manages timeouts for different stages of stream connections. Streams in Arti are individual connections routed over the Tor network, and managing their timeouts is essential for balancing performance with reliability. These settings are crucial for determining how long Arti waits for certain network activities to complete before considering them a failure.

#### Options

-   `connect_timeout`: 
    -   **Purpose:** Sets the maximum time Arti will wait for a connection to a host to be established.
    -   **Behavior:** This timeout value is used when Arti tries to establish a connection to a server or host through the Tor network. If the connection attempt exceeds this time limit, Arti will consider it a failure.
    -   **Note:** A properly set `connect_timeout` is essential for a responsive user experience. Too short a timeout might lead to unnecessary connection failures in slower networks. At the same time, too long a timeout could cause delays and a slow response in case of unresponsive hosts.

-   `resolve_timeout`: 
    -   **Purpose:** Determines how long Arti will wait for a DNS lookup to complete.
    -   **Behavior:** This setting controls the timeout for resolving a domain name to an IP address. If the DNS resolution process takes longer than this duration, the attempt will fail.
    -   **Note:** Timely DNS resolution is crucial for accessing web services. Setting an appropriate `resolve_timeout` is essential for balancing quick failure detection and accommodating slower DNS resolvers.

-   `resolve_ptr_timeout`: 
    -   **Purpose:** Specifies the timeout for reverse DNS lookups (PTR record queries).
    -   **Behavior:** This timeout applies to translating an IP address back to a domain name. Like `resolve_timeout`, if the reverse lookup exceeds this time limit, it's marked as failed.
    -   **Note:** Reverse DNS lookups are less common but can be important for certain applications. Setting a suitable `resolve_ptr_timeout` helps efficiently handle these lookups without unnecessary delays.

These timeout settings are vital to optimizing Arti's network responsiveness and reliability. They help manage the trade-off between waiting for slow network responses and aborting attempts that are unlikely to succeed, thereby enhancing the overall user experience. Proper configuration of these timeouts is crucial for the efficient operation of Arti in varied network conditions.

### System Resource Settings `[system]`:

As for `[system]`, it involves optimizing Arti's performance and ensuring that it operates within the constraints of the hosting system's resources. You can specify limits and preferences for how Arti interacts with the system's resources. This includes managing things like the number of file descriptors available to Arti.

#### Options

-   `max_files`: 
    -   **Purpose:** Specifies the maximum number of file descriptors available to Arti upon launch.
    -   **Behavior:** This setting defines the upper limit on the number of file descriptors that Arti can open. File descriptors are a limited resource in a system. Arti uses them to manage open files, network connections, and other I/O operations.
    -   **Note:** Setting an appropriate limit for file descriptors is crucial. If the limit is set too low, Arti might be unable to open enough connections or files, hindering its functionality. Conversely, setting it too high could risk exhausting the system's available file descriptors, especially if other demanding processes are running on the same system. This balance ensures that Arti runs efficiently without negatively impacting the overall system performance.

### Onion Services `[onion_services]`:

The `[onion_services]` configuration section deals with managing the settings for onion services, also known as hidden services. These services allow you to host websites and other services within the Tor network, making them accessible only through the Tor network for enhanced privacy and security.

You can configure multiple onion services. To do this, each onion service must have its own section. For example, you would configure an onion service named "documentation" at `[onion_services.documentation]`. Note that this feature is a work in progress. It is not yet secure and is not enabled by default. For guidance, see [running an onion service](https://gitlab.torproject.org/tpo/core/arti/-/blob/main/doc/OnionService.md?ref_type=heads).

#### Options

-   `proxy_ports`: 
    -   **Purpose:** Specifies rules for what to do with incoming connections to different ports of the onion service.
    -   **Behavior:** This setting is a list of rules, where each rule defines a port and what Arti should do with an incoming connection on that port. For example, `["80", "127.0.0.1:8080"]` will forward port 80 on the onion service to port 8080 on the local machine. `["22", "reject"]` will reject any connections attempted on port 22 (commonly used for SSH).
    -   **Note:** This is essential for setting up an onion service and directing traffic to the correct local services.

-   `anonymity`: 
    -   **Purpose:** Determines whether the onion service should be anonymous or non-anonymous (also known as a "single onion service").
    -   **Behavior:** Setting this to `"anonymous"` provides stronger anonymity, while `"non_anonymous"` offers improved performance. If you omit this setting, Arti will default to `"anonymous"`.
    -   **Note:** This setting affects the privacy level of the onion service. A non-anonymous service provides **_no privacy at all_**, and is only suitable in cases where you want Tor's non-privacy-related properties, like availability or censorship circumvention.

-   `num_intro_points`: 
    -   **Purpose:** Sets the number of introduction points to establish and advertise the onion service.
    -   **Behavior:** Introduction points are part of the mechanism that allows clients to connect to an onion service. This setting controls how many such points Arti uses.
    -   **Note:** More introduction points can increase the service's availability and redundancy but might also increase its exposure.

-   `max_concurrent_streams_per_circuit`: 
    -   **Purpose:** Specifies the maximum number of concurrent streams (individual connections) allowed for each circuit connected to the onion service.
    -   **Behavior:** This setting limits the number of simultaneous connections a single circuit can handle.
    -   **Note:** It balances resource usage and the ability to handle multiple simultaneous requests.

These settings provide control over the behavior of onion services. Setting up these parameters is crucial for anyone looking to host services on the Tor network, ensuring the right balance between privacy, performance, and accessibility.
