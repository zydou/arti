#!/bin/bash
#
# Run "cargo audit" with an appropriate set of flags.

FLAGS=(
)

cargo audit -D warnings "${FLAGS[@]}"
