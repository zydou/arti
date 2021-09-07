#!/bin/sh
#
# This script is run inside a docker container as part of our
# reporoducible build process.
#
set -xeu
if [ ! -f /.dockerenv ]; then
    echo Not running inside Docker, build will probably not be reproducible
    echo Use docker_reproducible_build.sh instead to get the right environment
fi
here=$(pwd)

## fix the target architecture to get reproducible builds
## the architecture was choosen as old enought that it should cover most usage
## while still supporting usefull features like AES-NI. Older architectures
## won't be able to execute the resulting binary.
export CFLAGS="-march=westmere"
export RUSTFLAGS="-C target-cpu=westmere"

## force build to run in a fixed location. Ncessesary because the build path
## is somehow captured when compiling.
cp -a "$here" /arti
cd /arti

## use tmpfs to store dependancies sources. It has been observed that what
## filesystem these files reside on has an impact on the resulting binary.
## We put these in a tmpfs as a way to stabilize the result.
mkdir -p /dev/shm/registry /usr/local/cargo/registry
ln -s /dev/shm/registry /usr/local/cargo/registry/src

## add missing dependancies
apk add --no-cache musl-dev perl make git mingw-w64-gcc
rustup target add x86_64-pc-windows-gnu

## bring back the Cargo.lock where dependancies version are strictly defined
mv misc/Cargo.lock Cargo.lock

## Build targeting x86_64-unknown-linux-musl to get a static binary
## feature "static" enable compiling some C dependancies instead of linking
## to system libraries. It is required to get a well behaving result.
cargo build -p arti --target x86_64-unknown-linux-musl --release --features static
mv /arti/target/x86_64-unknown-linux-musl/release/arti "$here"/arti-linux

## PE contains a timestamp of when they were built. Don't insert this value
export RUSTFLAGS="$RUSTFLAGS -C link-arg=-Wl,--no-insert-timestamp"
cargo build -p arti --target x86_64-pc-windows-gnu --release --features static
mv /arti/target/x86_64-pc-windows-gnu/release/arti.exe "$here"/arti-windows.exe

set +x
echo "branch       :" "$(git rev-parse --abbrev-ref HEAD)"
echo "commit       :" "$(git rev-parse HEAD)"
echo "Linux hash   :" "$(sha256sum "$here"/arti-linux       | cut -d " " -f 1)"
echo "Windows hash :" "$(sha256sum "$here"/arti-windows.exe | cut -d " " -f 1)"
