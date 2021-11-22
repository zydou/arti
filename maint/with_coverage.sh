#!/bin/bash

set -e

COVERAGE_BASEDIR=$(git rev-parse --show-toplevel)
export RUSTFLAGS="-Z instrument-coverage"
export LLVM_PROFILE_FILE=$COVERAGE_BASEDIR/coverage_meta/%p-%m.profraw
export RUSTUP_TOOLCHAIN=nightly

rm -r "$COVERAGE_BASEDIR/coverage" || true
mkdir -p "$COVERAGE_BASEDIR/coverage"

if [ $# -eq 0 ]; then
	# when run interactivelly, don't die on error
	bash || true
else
	"$@"
fi

grcov "$COVERAGE_BASEDIR/coverage_meta" --binary-path "$COVERAGE_BASEDIR/target/debug/" \
	-s "$COVERAGE_BASEDIR/crates/" -o "$COVERAGE_BASEDIR/coverage" -t html --branch \
	--ignore-not-existing --excl-start '^mod test' --excl-stop '^}' \
	--ignore="*/tests/*" --ignore="*/examples/*"

awk '{if (match($0, /<p class="heading">([^<]*)<\/p>/, groups)) {
		last_match=groups[1]
	} else if (match($0, /<abbr title="[0-9]* \/ [0-9]*">([^<]*)<\/abbr>/, groups)) {
	    print last_match " " groups[1]
	}}' "$COVERAGE_BASEDIR/coverage/index.html"
echo "Full report: $COVERAGE_BASEDIR/coverage/index.html"
