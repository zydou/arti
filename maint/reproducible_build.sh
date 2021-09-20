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
if [ $# -eq 0 ]; then
	echo usage : "$0" '<linux|windows|macos...>'
	exit 1
fi
linux=""
windows=""
macos=""
while [ "$#" -ne 0 ]; do
	case "$1" in
	linux)   linux=1;;
	windows) windows=1;;
	macos)   macos=1;;
	*)
		echo "unknown target : $1" >&2
		exit 1;;
	esac
	shift
done

here=$(pwd)

## fix the target architecture to get reproducible builds
## the architecture was chosen as old enough that it should cover most usage
## while still supporting usefull features like AES-NI. Older architectures
## won't be able to execute the resulting binary.
export CFLAGS="-march=westmere"
export RUSTFLAGS="-C target-cpu=westmere"

## force build to run in a fixed location. Ncessesary because the build path
## is somehow captured when compiling.
cp -a "$here" /arti
cd /arti

## use tmpfs to store dependencies sources. It has been observed that what
## filesystem these files reside on has an impact on the resulting binary.
## We put these in a tmpfs as a way to stabilize the result.
mkdir -p /dev/shm/registry /usr/local/cargo/registry
ln -s /dev/shm/registry /usr/local/cargo/registry/src

## add missing dependencies
apk add perl make git musl-dev
if [ -n "$linux" ]; then
	## no additional dependancies specifically for linux

	## Build targeting x86_64-unknown-linux-musl to get a static binary
	## feature "static" enable compiling some C dependencies instead of linking
	## to system libraries. It is required to get a well behaving result.
	cargo build -p arti --target x86_64-unknown-linux-musl --release --features static
	mv /arti/target/x86_64-unknown-linux-musl/release/arti "$here"/arti-linux
fi
if [ -n "$windows" ]; then
	apk add mingw-w64-gcc
	rustup target add x86_64-pc-windows-gnu

	## Same tweaks as for Linux, plus don't insert compilation timestamp into PE headers
	RUSTFLAGS="$RUSTFLAGS -C link-arg=-Wl,--no-insert-timestamp" \
		cargo build -p arti --target x86_64-pc-windows-gnu --release --features static
	mv /arti/target/x86_64-pc-windows-gnu/release/arti.exe "$here"/arti-windows.exe
fi
if [ -n "$macos" ]; then
	apk add bash cmake patch clang libc-dev libxml2-dev openssl-dev fts-dev build-base python3 bsd-compat-headers xz
	rustup target add x86_64-apple-darwin

	mkdir -p .cargo
	cat > .cargo/config << EOF
[target.x86_64-apple-darwin]
linker = "x86_64-apple-darwin15-clang"
ar = "x86_64-apple-darwin15-ar"
EOF

	## don't compile clang if it's already here (CI cache?)
	if [ ! -x "/arti/osxcross/target/bin/o64-clang" ]; then
		git clone https://github.com/tpoechtrager/osxcross
		cd osxcross
		wget -nc https://s3.dockerproject.org/darwin/v2/MacOSX10.11.sdk.tar.xz -O tarballs/MacOSX10.11.sdk.tar.xz
		UNATTENDED=yes OSX_VERSION_MIN=10.7 ./build.sh
		# copy it to gitlab build-dir so it may get cached
		cp -r /arti/osxcross "$here"
	fi

	PATH="/arti/osxcross/target/bin:$PATH" \
		CC=o64-clang \
		CXX=o64-clang++ \
		cargo build -p arti --target x86_64-apple-darwin --release --features static
	mv /arti/target/x86_64-apple-darwin/release/arti "$here"/arti-macos
fi

set +x
echo "branch       :" "$(git rev-parse --abbrev-ref HEAD)"
echo "commit       :" "$(git rev-parse HEAD)"
[ -z "$linux" ]   || echo "Linux hash   :" "$(sha256sum "$here"/arti-linux       | cut -d " " -f 1)"
[ -z "$windows" ] || echo "Windows hash :" "$(sha256sum "$here"/arti-windows.exe | cut -d " " -f 1)"
[ -z "$macos" ]   || echo "MacOS hash   :" "$(sha256sum "$here"/arti-macos       | cut -d " " -f 1)"
