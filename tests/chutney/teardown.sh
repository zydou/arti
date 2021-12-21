#!/bin/bash
set -xe

cd "$(git rev-parse --show-toplevel)"

source tests/chutney/arti.run

if [ -z "${CHUTNEY_PATH}" ]; then
    # Use the default chutney path we set up before.
    CHUTNEY_PATH="$(pwd)/chutney"
    export CHUTNEY_PATH
else
    # CHUTNEY_PATH is set; tell the user about that.
    echo "CHUTNEY_PATH is ${CHUTNEY_PATH}; using your local copy of chutney."
fi


# Tolerate a failure here: even in case the arti process already died
# for some reason, we still want to shut down the chutney network.
kill -s INT "$pid" || true
# wait $pid, but $pid was started by a different process
tail --pid="$pid" -f /dev/null

"${CHUTNEY_PATH}/chutney" stop "${CHUTNEY_PATH}/$target"

source tests/chutney/arti.run
exit "$result"
