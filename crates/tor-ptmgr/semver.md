ADDED: `ipc::PtServerParameters`
ADDED: `trait ipc::PluggableTransport` providing `.transport_methods()` and `.next_message()`
ADDED: `ipc::PtMessage`
ADDED: `ipc::PluggableServerTransport`
BREAKING: Split `ipc::PtParameters` into `ipc::PtCommonParameters` and `ipc::PtClientParameters`
BREAKING: Renamed `ipc::PluggableTransport` struct into `ipc::PluggableClientTransport`; `ipc::PluggableTransport` is a trait now.
