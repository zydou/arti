import chutney.TorNet
from chutney.TorNet import NodeBackend, NodeConfig

import config as config_module


def make_network(config: config_module.Config) -> chutney.TorNet.Network:
    """Create a chutney Network object for use with these integration tests"""
    # Bring up directory authorities first. Everything else depends on these.
    # There will be a bit of chaos in the logs as these come up due to:
    # * auths trying to contact other auths before they're up.
    # * auths trying to create exit circuits before exit relays are created or up.
    LAUNCH_PHASE_DIR_AUTHS = 1
    # Need dirauths.
    LAUNCH_PHASE_RELAYS = 2
    # Needs dirauths, and to a lesser extent some exit relay.
    LAUNCH_PHASE_BRIDGE_AUTH = 3
    # Needs bridge authority.
    LAUNCH_PHASE_BRIDGES = 4
    # Clients need everything else up (including bridges, for bridge-clients) to
    # bootstrap cleanly.
    LAUNCH_PHASE_CLIENTS = 5

    # arti bins we're testing, keyed by tag-fragment.
    artis = dict(
        # "arti vanilla"
        av=config.arti,
        # "arti extra"
        ae=config.arti_extra,
    )

    configs = []
    # Authorities
    configs += NodeConfig(
        tag="a", authority=True, relay=True, launch_phase=LAUNCH_PHASE_DIR_AUTHS
    ).getN(4)
    # Exits. We don't need many since authorities also function as exits,
    # but let's have at least 1 non-authority exit relay.
    configs += NodeConfig(
        tag="r", relay=True, exit=True, launch_phase=LAUNCH_PHASE_RELAYS
    ).getN(2)
    # Simple tor client. Useful as a baseline check for "chutney verify",
    # and used in arti-bench for comparison.
    configs += NodeConfig(
        tag="ct",
        client=True,
        backend=NodeBackend.TOR,
        launch_phase=LAUNCH_PHASE_CLIENTS,
    ).getN(1)

    # Simple arti clients. DNS port enabled for DNS test.
    for tag, path in artis.items():
        configs += NodeConfig(
            tag="c" + tag,
            arti=path,
            client=True,
            enable_dnsport=True,
            backend=NodeBackend.ARTI,
            launch_phase=LAUNCH_PHASE_CLIENTS,
        ).getN(1)
    # bridge authority
    configs += NodeConfig(
        tag="ba",
        authority=True,
        bridgeauthority=True,
        relay=True,
        launch_phase=LAUNCH_PHASE_BRIDGE_AUTH,
    ).getN(1)
    # Bridge
    configs += NodeConfig(
        tag="br", bridge=True, relay=True, launch_phase=LAUNCH_PHASE_BRIDGES
    ).getN(2)
    # arti bridge clients
    for tag, path in artis.items():
        configs += NodeConfig(
            tag="bc" + tag,
            arti=path,
            client=True,
            backend=NodeBackend.ARTI,
            bridgeclient=True,
            launch_phase=LAUNCH_PHASE_CLIENTS,
        ).getN(1)

    network = chutney.TorNet.Network()
    network.addNodes(configs)
    return network
