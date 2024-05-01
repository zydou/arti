#!/usr/bin/env bash

# The script that was used to generate the OpenSSH keys from this directory.

set -eou pipefail

GENERATE_PATH="./generate-custom"
MANIFEST_PATH="$GENERATE_PATH/Cargo.toml"
BIN_PATH="$GENERATE_PATH/target/debug/generate-custom"
EXPANDED_ED25519="ed25519_expanded_openssh"
X25519="x25519_openssh"

mangle_ed25519_private() (
    sed -i '2ahello' "$1"
)

mangle_ed25519_public() (
    sed -i 's/ssh-ed25519 /\0garbage/' "$1"
)

ssh-keygen -t dsa -N "" -f dsa_openssh -C foo@example.com > /dev/null
mv dsa_openssh dsa_openssh.private

# Generate an ed25519 key
ssh-keygen -t ed25519 -N "" -f ed25519_openssh -C armadillo@example.com > /dev/null
mv ed25519_openssh ed25519_openssh.private
mv ed25519_openssh.pub ed25519_openssh.public

# Generate an invalid ed25519 key
ssh-keygen -t ed25519 -N "" -f ed25519_openssh_bad -C armadillo@example.com > /dev/null
mv ed25519_openssh_bad ed25519_openssh_bad.private
mv ed25519_openssh_bad.pub ed25519_openssh_bad.public
mangle_ed25519_private ed25519_openssh_bad.private
mangle_ed25519_public ed25519_openssh_bad.public

cargo build --manifest-path "$MANIFEST_PATH"

"$BIN_PATH" --key-type expanded-ed25519 \
   --private \
   --name "${EXPANDED_ED25519}"

ssh-keygen -t ed25519 -N "" -f "${EXPANDED_ED25519}" -C armadillo@example.com > /dev/null
# We actually only need the public part of this key
rm "${EXPANDED_ED25519}"
mv "${EXPANDED_ED25519}.pub" "${EXPANDED_ED25519}.public"
# Pretend the key type is expanded-ed
sed -i 's/ssh-ed25519/ed25519-expanded@spec.torproject.org/' "${EXPANDED_ED25519}.public"

"$BIN_PATH" --key-type expanded-ed25519 \
   --private \
   --public \
   --algorithm armadillo@spec.torproject.org \
   --name "${EXPANDED_ED25519}_unknown_algorithm"

"$BIN_PATH" --key-type expanded-ed25519 \
   --private \
   --name "${EXPANDED_ED25519}_bad"

mangle_ed25519_private "${EXPANDED_ED25519}_bad.private"

"$BIN_PATH" --key-type x25519 \
   --private \
   --public \
   --name "$X25519"

"$BIN_PATH" --key-type x25519 \
   --private \
   --algorithm pangolin@torproject.org \
   --name "${X25519}_unknown_algorithm"

"$BIN_PATH" --key-type x25519 \
   --public \
   --algorithm armadillo@torproject.org \
   --name "${X25519}_unknown_algorithm"
