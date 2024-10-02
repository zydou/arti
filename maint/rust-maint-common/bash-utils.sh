# -*- bash -*-
#
# utilities for maint/ scripts.

# Shellcheck is confused.
# It thinks it ought to be checking this as a standalone script, and prints
#   -- SC2148 (error): Tips depend on target shell and yours is unknown.
#             Add a shebang or a 'shell' directive.
# shellcheck shell=bash

unalias -a
shopt -s expand_aliases

fail () {
    echo >&2 "error: $*"
    exit 12
}

x () {
    echo >&2 "x $*"
    "$@"
}

alias reject_all_arguments='
    if [ $# != 0 ]; then
	fail "bad usage: no arguments allowed"
    fi
'

# shellcheck disable=SC2142
alias reject_options='
case "${1-}" in
    --) shift ;;
    -*) echo >&2 "$0: No options allowed"; exit 12 ;;
esac
'

# Prints a list of the files in git, with a #! that looks like (ba)sh
git_grep_for_shell_script_shebangs () {
    git grep -P --line-number '^#! ?(/usr/bin/env |/bin/)(:?ba)?sh\b' \
	| sed -n 's/:1:[^:]*$//p'
}
