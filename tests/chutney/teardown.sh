#!/bin/bash
set -xe

cd "$(git rev-parse --show-toplevel)"

# Tell shellcheck that yes, we know that we're sourcing a file.
# shellcheck disable=SC1091
source tests/chutney/arti.run

# Tells shellcheck that these variables are set; exits early if they
# are not.
pid="${pid:?}"
target="${target:?}"

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

# Tell shellcheck that yes, we know that we're sourcing a file.
# shellcheck disable=SC1091
source tests/chutney/arti.run

# As above, make sure this is defined.  (It won't be defined until
# this point, so we can't check it earlier.)
result="${result:?}"

exit "$result"
