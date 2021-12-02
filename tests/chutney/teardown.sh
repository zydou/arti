#!/bin/bash
set -xe

cd "$(git rev-parse --show-toplevel)"

source tests/chutney/arti.run

if [ -z "${CHUTNEY_PATH}" ]; then
    # Use the default chutney path we set up before.
    export CHUTNEY_PATH="$(pwd)/chutney"
else
    # CHUTNEY_PATH is set; tell the user about that.
    echo "CHUTNEY_PATH is ${CHUTNEY_PATH}; using your local copy of chutney."
fi


kill -s INT "$pid";
# wait $pid, but $pid was started by a different process
tail --pid="$pid" -f /dev/null

"${CHUTNEY_PATH}/chutney" stop "$target"

source tests/chutney/arti.run
exit "$result"
