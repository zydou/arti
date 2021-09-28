#!/bin/bash
set -xe

cd "$(git rev-parse --show-toplevel)"

source tests/chutney/arti.run

kill -s INT "$pid"; 
# wait $pid, but $pid was started by a different process
tail --pid="$pid" -f /dev/null


./chutney/chutney stop "$target"

source tests/chutney/arti.run
exit "$result"
