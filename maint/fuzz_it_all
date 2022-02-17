#!/bin/bash

set -e

trap 'kill $(jobs -p)' EXIT

for d in ./crates/*/fuzz; do
    pushd "$(dirname "$d")"
    for fuzzer in $(cargo +nightly fuzz list); do
	echo "$fuzzer"
	cargo +nightly fuzz build "$fuzzer"
    done
    popd
done


#JOBS=4

while true; do
    for d in ./crates/*/fuzz; do
	pushd "$(dirname "$d")"
	for fuzzer in $(cargo +nightly fuzz list); do
	    set +e
	    timeout 20m cargo +nightly fuzz run "$fuzzer"
	    status="$?"
	    set -e
	    case "$status" in
		0)
  		    # Successful exit?
		    ;;
		124)
		    # This is a timeout
		    ;;
		*)
		    exit 1
		    ;;
	    esac
	done
	popd
    done
done


# wait -n

