#!/bin/bash

set -euo pipefail

# Remove output of previous run
rm -rf shadow.data

# Run the simulation
shadow \
  --model-unblocked-syscall-latency=true \
  --log-level=debug \
  --strace-logging-mode=standard \
  --parallelism="$(nproc)" \
  --template-directory=./shadow.data.template \
  --progress=true \
  shadow.yaml \
  > shadow.log

# Check whether file transfers via arti inside the simulation succeeded
successes="$(grep -c stream-success shadow.data/hosts/articlient/articlient.tgen.1001.stdout || true)"
if [ "$successes" = 10 ]
then
  echo "Passed"
  exit 0
else
  echo "Failed. Only got $successes successful streams."
fi
