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

alias reject_all_arguments='
    if [ $# != 0 ]; then
	fail "bad usage: no arguments allowed"
    fi
'
