#!/usr/bin/env bash

set -xeuo pipefail

# Remove output of previous run
rm -rf shadow.data

export RUST_BACKTRACE=1

# Run the simulation
shadow \
  --model-unblocked-syscall-latency=true \
  --log-level=debug \
  --strace-logging-mode=standard \
  --template-directory=./shadow.data.template \
  --progress=true \
  --use-memory-manager=false \
  shadow.yaml \
  > shadow.log

# Check whether file transfers via arti inside the simulation succeeded
for HOST in articlient articlient-bridge; do
  successes="$(grep -c stream-success shadow.data/hosts/$HOST/tgen.*.stdout || true)"
  if [ "$successes" = 10 ]
  then
    echo "Simulation successful"
  else
    echo "Failed. Only got $successes successful streams."
  fi
done

pushd shadow.data/hosts/articlient-bridge/
for PCAP in *.pcap; do
	# verify all connection are either from/to the bridge, or local.
	LEAK=$(tshark -r "$PCAP" 'ip.src != 100.0.0.2 && ip.dst != 100.0.0.2 && ip.dst != 127.0.0.0/8')
	if [ "$LEAK" ]; then
		echo "Found tcp leaks in PCAP: $PCAP"
	        echo "$LEAK"
		exit 1
	fi
done

DNS_LEAK=$(grep -l shadow_hostname_to_addr_ipv4 arti.*.strace || true)
if [ "$DNS_LEAK" ]; then
	echo "Found DNS leaks in $DNS_LEAK"
	exit 1
fi
popd
