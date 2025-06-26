FROM rust:1.86.0-bullseye

RUN set -eux; \
	apt-get update; \
	apt-get install -y --no-install-recommends \
		bash \
		wget curl \
        locales \
        openjdk-17-jdk \
        build-essential \
        perl make git musl-dev \
	; \
	echo "en_US.UTF-8 UTF-8" >> /etc/locale.gen; \
	locale-gen en_US.UTF-8; \
	rm -rf /var/lib/apt/lists/*;

ENV SDK_URL="https://dl.google.com/android/repository/commandlinetools-linux-13114758_latest.zip" \
    ANDROID_HOME="/usr/local/android-sdk" \
    ANDROID_SDK=$ANDROID_HOME \
    ANDROID_VERSION=35 \
    ANDROID_BUILD_TOOLS_VERSION=35.0.1 \
    JAVA_HOME=/usr/lib/jvm/java-17-openjdk-amd64

## Download Android SDK
RUN mkdir -p "$ANDROID_HOME" .android \
    && cd "$ANDROID_HOME" \
    && curl -o sdk.zip $SDK_URL \
    && unzip sdk.zip \
    && rm sdk.zip \
    && mv $ANDROID_HOME/cmdline-tools $ANDROID_HOME/latest \
    && mkdir $ANDROID_HOME/cmdline-tools \
    && mv $ANDROID_HOME/latest $ANDROID_HOME/cmdline-tools \
    && yes | $ANDROID_HOME/cmdline-tools/latest/bin/sdkmanager --licenses

## Install Android Build Tool and Libraries
RUN $ANDROID_HOME/cmdline-tools/latest/bin/sdkmanager --update
RUN $ANDROID_HOME/cmdline-tools/latest/bin/sdkmanager "build-tools;${ANDROID_BUILD_TOOLS_VERSION}" \
    "platforms;android-${ANDROID_VERSION}" \
    "platform-tools"

# Install NDK
ENV NDK_VER="25.2.9519653"
RUN $ANDROID_HOME/cmdline-tools/latest/bin/sdkmanager "ndk;$NDK_VER"
RUN ln -sf $ANDROID_HOME/ndk/$NDK_VER $ANDROID_HOME/ndk-bundle

ENV ANDROID_NDK_ROOT=$ANDROID_HOME/ndk/25.2.9519653

ENV TARGETS="armv7-linux-androideabi aarch64-linux-android i686-linux-android x86_64-linux-android"
RUN rustup target add $TARGETS

RUN cargo install bindgen-cli --version 0.71.1 # from onionmasq install-toolchains.sh
RUN cargo install cargo-ndk

# handle docker_reproducible_build's call to alpine's apk to add bash with a NOP
RUN echo "#!/bin/sh" > /usr/bin/apk \
    && chmod a+x /usr/bin/apk
