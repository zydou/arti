#!/bin/bash

set -e

SCRIPT_NAME=$(basename "$0")

function usage()
{
    cat <<EOF
${SCRIPT_NAME}: Generate coverage using grcov.

Usage:
  with_coverage [opts] <command> [args...] : Run <command> with [args].
  with_coverage -i [opts]                  : Run bash interactively.

Options:
  -h: Print this message.
  -i: Run an interactive shell after the command (if any)
  -c: Continue using data from previous runs. (By default, data is deleted.)
  -s: Skip generating a final report.

Notes:
  You need to have grcov, rust-nightly, and llvm-tools-preview installed.
EOF
}

interactive=no
remove_data=yes
skip_report=no

while getopts "chis" opt ; do
    case "$opt" in
	c) remove_data=no
	   ;;
	h) usage
	   exit 0
	   ;;
	i) interactive=yes
	   ;;
	s) skip_report=yes
	   ;;
	*) echo "Unknown option."
	   exit 1
	   ;;
    esac
done

# Remove the flags we parsed.
shift $((OPTIND-1))

# Make sure that we'll be doing _something_.
if [ $# -eq 0 ] && [ $interactive = "no" ]; then
    echo "No command specified: Use the -i flag if you want a shell."
    echo
    echo "Run ${SCRIPT_NAME} -h for help."
    exit 1
fi

# Validate that +nightly is installed.  This will log a message to stderr
# if it isn't.
cargo +nightly -h >/dev/null

# Validate that grcov is installed.
if [ "$(which grcov 2>/dev/null)" = "" ]; then
    echo "grcov appears not to be installed.  Try 'cargo install grcov'." >&2
    exit 1
fi

# Validate that llvm-tools-preview is installed.
if [ "$(rustup +nightly component list --installed | grep llvm-tools-preview)" = "" ]; then
   echo "llvm-tools-preview appears not to be installed. Try 'rustup +nightly component add llvm-tools-preview'." >&2
   exit 1
fi

COVERAGE_BASEDIR=$(git rev-parse --show-toplevel)
export RUSTFLAGS="-Z instrument-coverage"
export LLVM_PROFILE_FILE=$COVERAGE_BASEDIR/coverage_meta/%p-%m.profraw
export RUSTUP_TOOLCHAIN=nightly

if [ -d "$COVERAGE_BASEDIR/coverage" ]; then
    rm -r "$COVERAGE_BASEDIR/coverage" || true
fi
if [ -d "$COVERAGE_BASEDIR/coverage_meta" ] && [ "$remove_data" = "yes" ]; then
    echo "Removing data from previous runs. (Use -c to suppress this behavior.)"
    rm -r "$COVERAGE_BASEDIR/coverage_meta" || true
fi

mkdir -p "$COVERAGE_BASEDIR/coverage"
mkdir -p "$COVERAGE_BASEDIR/coverage_meta"

if [ ! -e "$COVERAGE_BASEDIR/coverage_meta/commands" ] ; then
    echo "REVISION: $(git rev-parse HEAD) $(git diff --quiet || echo "[dirty]")" >  "$COVERAGE_BASEDIR/coverage_meta/commands"
fi


if [ $# -ne 0 ]; then
    echo "$@" >> "$COVERAGE_BASEDIR/coverage_meta/commands"
    "$@"
fi

if [ $interactive = "yes" ] ; then
    echo "Launching a bash shell."
    echo "Exit this shell when you are ready to genate a coverage report."
    echo "# BASH SHELL" >> "$COVERAGE_BASEDIR/coverage_meta/commands"
    # when run interactivelly, don't die on error
    bash || true
fi

if [ "$skip_report" = "yes" ]; then
    exit 0
fi

echo "Generating report..."

grcov "$COVERAGE_BASEDIR/coverage_meta" --binary-path "$COVERAGE_BASEDIR/target/debug/" \
	-s "$COVERAGE_BASEDIR/crates/" -o "$COVERAGE_BASEDIR/coverage" -t html --branch \
	--ignore-not-existing --excl-start '^mod test' --excl-stop '^}' \
	--ignore="*/tests/*" --ignore="*/examples/*"

cp "$COVERAGE_BASEDIR/coverage/index.html" "$COVERAGE_BASEDIR/coverage/index_orig.html"

if [ "$(which python3 2>/dev/null)" = "" ]; then
    echo "python3 not installed; not post-processing the index file."
else
    echo "Postprocessing..."
    python3 "$COVERAGE_BASEDIR/maint/postprocess_coverage.py" "$COVERAGE_BASEDIR/coverage_meta/commands" "$COVERAGE_BASEDIR/coverage/index.html" "$COVERAGE_BASEDIR/coverage/index.html"
fi

echo "Full report: $COVERAGE_BASEDIR/coverage/index.html"
