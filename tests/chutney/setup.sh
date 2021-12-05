#!/bin/bash
set -xe

target="${1:-networks/basic}"
cd "$(git rev-parse --show-toplevel)"

if [ -z "${CHUTNEY_PATH}" ]; then
    # CHUTNEY_PATH isn't set; try cloning a local chutney.
    if [ -d chutney ]; then
	(cd ./chutney && git pull)
    else
	git clone https://gitlab.torproject.org/tpo/core/chutney
    fi
    export CHUTNEY_PATH="$(pwd)/chutney"
else
    # CHUTNEY_PATH is set; tell the user about that.
    echo "CHUTNEY_PATH is ${CHUTNEY_PATH}; using your local copy of chutney."
fi

if [ ! -e "${CHUTNEY_PATH}/${target}" ]; then
    echo "Target network description ${CHUTNEY_PATH}/${target} not found."
    exit 1
fi

"${CHUTNEY_PATH}/chutney" configure "${CHUTNEY_PATH}/$target"
"${CHUTNEY_PATH}"/chutney start "${CHUTNEY_PATH}/$target"
CHUTNEY_START_TIME=180 "${CHUTNEY_PATH}"/chutney wait_for_bootstrap "${CHUTNEY_PATH}/$target"
"${CHUTNEY_PATH}"/chutney verify "${CHUTNEY_PATH}/$target"

if [ -x ./target/x86_64-unknown-linux-gnu/debug/arti ]; then
	cmd=./target/x86_64-unknown-linux-gnu/debug/arti
else
	cargo build
	cmd=./target/debug/arti
fi

(
	set +e
	"$cmd" proxy -c "${CHUTNEY_PATH}/net/nodes/arti.toml" &
	pid=$!
	echo "target=$target" > tests/chutney/arti.run
	echo "pid=$pid" >> tests/chutney/arti.run
	wait "$pid"
	echo "result=$?" >> tests/chutney/arti.run
) & disown
sleep 5
