#!/bin/bash
set -xe

target="${1:-chutney/networks/basic}"
cd "$(git rev-parse --show-toplevel)"
[ -d chutney ] || git clone https://gitlab.torproject.org/tpo/core/chutney
./chutney/chutney configure "$target"
./chutney/chutney start "$target"
CHUTNEY_START_TIME=180 ./chutney/chutney wait_for_bootstrap "$target"
./chutney/chutney verify "$target"


if [ -x ./target/x86_64-unknown-linux-gnu/debug/arti ]; then
	cmd=./target/x86_64-unknown-linux-gnu/debug/arti
else
	cargo build
	cmd=./target/debug/arti
fi

(
	set +e
	"$cmd" proxy -c chutney/net/nodes/arti.toml &
	pid=$!
	echo "target=$target" > tests/chutney/arti.run
	echo "pid=$pid" >> tests/chutney/arti.run
	wait "$pid"
	echo "result=$?" >> tests/chutney/arti.run
) & disown
sleep 5
