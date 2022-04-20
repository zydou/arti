# Compilation Arti for Android

## Limitations
At the moment of writing this guide, Arti does not have a stable Rust API yet. For that reason, no proper bindings are provided.
You'll need to write these bindings yourself using the Java Native Interface.
(If this doesn't sound like something you can do, you might be better off
waiting until Arti is more stable.)

There are also rough edges, which will hopefully get polished over time. Most of these should be explained below.

This guide assumes you already have installed Cargo and Android Studio (but not that you used both together).

Finally: These guidelines are correct as far as we know, but they haven't
been tested by many people. If you find any problems in them, please let us
know!

## Installing the requirements

First you'll need to install targets so Rust knows how to compile to Android.
```sh
$ rustup target install armv7-linux-androideabi \
	aarch64-linux-android \
	i686-linux-android \
	x86_64-linux-android
```

You'll also need to get a NDK (you can skip this step if you already have one installed). As of now, NDK 23 is not supported yet.
You can download the NDK 22 [here](https://github.com/android/ndk/wiki/Unsupported-Downloads).
Choose the right NDK for your platform, unzip the archive and set the environment variable `NDK_HOME` to point to your newly installed NDK (you'll need to adjust the path to match your setup).
```sh
$ export NDK_HOME=/<path/to/where/you/unzipped>/android-ndk-r22b/
```

Install cargo-ndk. It's not technically required, but does make it easier.
```sh
$ cargo install cargo-ndk
```

## Configuring a Rust project

To create a new project in the directory you're in. You can do:
```sh
$ cargo init <project-name> --lib
```

You'll then need to add some content to the Cargo.toml.

First add the subcrates of arti you want to use to the `[dependencies]` section. You'll have to add `features=["static"]` to crates that support this feature
(at the moment tor-rtcompat, tor-dirmgr and arti-client): otherwise they will fail either to compile or to run.

You'll also need to add `jni`, to allow Rust and the Java in your app to work together.
```toml
jni = { version = "0.19", default-features = false }
```

You'll probably want to add some other dependencies, like futures, but these are not technically requirements.

You'll also need to specify what kind of lib this is. By default, it's a Rust lib that can only be used in the rust ecosystem.
We want it to be a dynamic library:
```toml
[lib]
crate-type = ["dylib"]
```

You are good to start programming in `src/lib.rs`.
To make your functions available to Java, you need to set certain modifiers on them, and to name them with a special convention.
You should be familiar with this if you used the JNI before.  If not, it's probably time to learn how to use it.
```rust
// defined the method "myMethod" on class "MyClass" in package "net.example"
#[no_mangle]
pub extern "C" fn Java_net_example_MyClass_myMethod( /* parameters omitted */ ) {..}
```

Once you are satisfied with your code, you can compile it by running this command. (This is a good time to take a coffee break)
```sh
 ## build for 32bit and 64bit, x86 (emulator) and arm (most devices).
$ cargo ndk -t armeabi-v7a -t arm64-v8a -t x86 -t x86_64 -o ./jniLibs build
 ## build for 64bit arm only (recent devices).
$ cargo ndk -t arm64-v8a -o ./jniLibs build
```

## The Java part

Note: you can use kotlin if you prefer.  The syntax is obviously slightly different, but it should work either way.

I'll assume you already have a project setup. This can be a brand new project, or an already existing one.

First you'll need to copy your native library inside the Android project (or use a symlink).
```sh
$ cp -r path/to/rust/project/jniLibs path/to/android/project/app/src/main
```

Next, if your application does not already require it, you have to request the permission to access Internet in your AndroidManifest.xml
```xml
    <uses-permission android:name="android.permission.INTERNET" />
```

Finally, you have to create the class referenced in your Rust code, and the method it overrides. This method must be marked "native".
You also have to put a static block loading the native library:
```java
package org.example

class MyClass {
    native void myMethod();
    static {
        System.loadLibrary("<name of the rust project>");
    }
}
```

You can now build your application, and test it in an emulator or on your device. Hopefully it should work.

## Tips and caveats

You can find a sample project to build a very basic app using Arti [here](https://gitlab.torproject.org/trinity-1686a/arti-mobile-example/).
It does not respect most good practices ("don't run long tasks on the UI thread" for instance), but should otherwise be a good starting point.
It's also implementing most of the tips below.


### Platform support
By default, Arti runs only on Android 7.0 and above. Versions under Android 7.0 will get a runtime exception due to a missing symbol.
If you want to support Android 5.0 and above, it is possible to implement `lockf` yourself, as it is a rather simple libc function.
It might be possible to support even lower Android version by implementing more of these methods (at least create\_epoll1). This has
not been explored, as it seems to be harder, and with less possible gain.
An implementation of `lockf` is part of the sample project linked above. (It's a Rust translation of Musl implementation of this function.)

### Debugging and stability
Arti logs events to help debugging. By default these logs are not available on Android.
You can make Arti export its logs to logcat by adding a couple dependencies and writing a bit of code:

```toml
# in [dependencies] in Cargo.toml
tracing-subscriber = "0.2.20"
tracing-android = "0.1.3"
```

```rust
use tracing_subscriber::fmt::Subscriber;
use tracing_subscriber::prelude::*;

Subscriber::new()
  .with(tracing_android::layer("rust.arti")?)
  .init(); // this must be called only once, otherwise your app will probably crash
```

You should take great care about your rust code not unwinding into Java Runtime: If it does, it will crash your app with no error message to help you.
If your code can panic, you should use `catch_unwind` to capture it before it reaches the Java Runtime.

### Async and Java
Arti relies a lot on Rust futures. There is no easy way to use these futures from Java. The easiest ways is probably to block on futures
if you are okay with it. Otherwise you have to pass callbacks from Java to Rust, and make so they are called when the future completes.

Eventually, Arti will provide a set of blocking APIs for use for embedding;
please get in touch if you want to help design them.
