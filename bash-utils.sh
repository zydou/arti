# -*- bash -*-
#
# utilities for maint/ scripts.

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
