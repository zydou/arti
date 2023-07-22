# Configuration of tor-* and arti (API)

*Discussion proposal*

## Overall philosophy

There should be one coherent schema/data model for our configuration.  It should be extensible enough that the arti executable can reuse the machinery used in arti-client, and that other embedders can also use it.

The schema should be reified in serde implementations, our config reader, and builder pattern methods etc. - i.e., all these methods should be equivalent.  There shouldn't be different names or semantics depending how the config is fed into our code.

We should make client construction using default config file locations easy (at least as easy as construction with hardcoded defaults).  That will make it easy for embedders to provide user-tweakable config.

We should add some warnings to the docs for configuration settings which have the potential to deanonymize users.  (Or possibly blanket warnings.)  This should aim to discourage not only users but also embedders from making poor choices.

## Validation (startup API simplification)

### Discussion

Few callers will want to validate the configuration separately from using it to make a Tor client (or running copy of the arti executable).  The separation between `FooConfigBuilder` (partially-validated[1] configuration read from file(s) and/or set up with builder pattern methods) and `FooConfig` (validated configuration for Foo) doubles the number of config structs in our API.  ([1] I say "partially" because the types of individual fields are right, although their values may be inappropriate.)

This distinction prevents (typestate-style) a programmer from writing code which directly constructs a client from an only-partially-validated config, but a program which does this is not buggy (if we make the validation happen at construction time) - and actually providing that API is easier for the caller.  And because the `FooConfig` is already *partially* validated, it just provides clutter in the caller's code.

### Proposal

We rename `FooConfigBuilder` to `FooConfig`.  The current `FooConfig` type will become a private `foo::ValidatedConfig` type.  (The two types will usually still need to be separate because defaulting means the builder ought usually to contain many `Option`, whereas the operational code doesn't want to see those.)

Config validation errors will be reported during client construction.

If desired we could provide a `validate()` method for callers that want to double check a config without trying to instantiate it.  Or maybe the "create without bootstrapping" entrypoint will be good for this.

The `Deserialize` impl on configs will be applied to the builder struct (now `FooConfig`) rather than the "built" struct, via `#[builder(derive(Deserialize))]`.  (Defaults will not need to be specified to serde, since the fields of the builder are `Option`.)

Since the "built" config is now private, the builder-generated `build` method becomes private.  If we want to do complicated defaulting (eg, defaulting that depends on other options) or the like, we may need to hand-roll that (or parts of it).

## Visibility of `FooConfig` structs

We have decided that `tor-*` crates have much more unstable APIs than `arti-*`.  Configuration is exposed via the config file format, and therefore a semantically equivalent view should be available via the APIs.

So each `FooConfig` needs to be re-exported by `arti-client`, and semver-breaking changes to those are semver breaks for arti.

## Division between sources and configs; Loading, embedding, etc.

### Discussion

To make our config loading code reusable, in everything from a slightly extended version of `arti`, to some entirely different embedding of our Tor, code, we need to separate out:

 * Code that knows about configuration sources (how to read a file, default locations of files, how to access the command line)

 * Code that knows about configuration *settings*

(Separate in the sense that most entrypoints should be one of these or the other, and they should be brought together only in convenience methods.)

### Proposal

All of the `FooConfig` structs should be made directly `Deserialize` and `Serialize` (subject to serde cargo feature of course).  (See above re abolition of `FooConfigBuilder` as a separate public type.)  This means that much of the boilerplate field-copying (and conversions) in arti-config can be deleted.

The knowledge of the default config file location(s) and sources should be (exposed) in `arti-client` (not `arti`), with the implication that we hope that most embedders will use it.
(`tor-config` can continue to be the actual implementation of env vars, default path lookup, etc.)

Individual `tor-*` crates will retain their knowledge of their own configuration.  arti-config will retain the knowledge of executable-specific config settings (notably logging), and can be reused by shallow embedders if they like.

### API suggestions

The most simple ones that just read a Tor config should look like this:

```
impl TorClientCfg {
     #[throws] pub fn from_files() -> Self;
     #[throws] pub fn builtin_defaults() -> Self;
}
```
(borrowing notation from `fehler` for clarity; actual code will be `-> Result`)

For embedders, `arti-client` should provide a method a bit like this
(name TBD)
```
    #]throws]
    pub fn tor_and_caller_config_from_usual_files<T>() -> (TorClientCfg, T)
        where T: Deserialize
    {
        #[derive(Deserialize)]
        struct CombinedConfig {
            #[flatten] tor: TorConfig,
            #[flatten] rest: T,
        }
        ... load a CombinedConfig from the usual Tor config files ...
```

On the principle of not having important knowledge only entangled in some more complicated machinery, there should probably be a ```fn usual_config_files() -> Vec<PathBuf>``` (or something).

## Transparency of `TorClientCfg`

I suggest that `TorClientCfg` should be a non-exhaustive but otherwise transparent struct (i.e. with `pub` fields).

The "sections" in it (ie, the sub-struct names and types) are already public, since they are part of the config file format.   Restructuring this would be a breaking change regardless of the Rust API.  So the current scheme does not add any additional API abstraction - it merely demands boilerplate code.

### `config` vs `figment`

Currently we use `config`.  I looked at others briefly and rather more closely at `figment`.  Certainly `figment` is a lot richer.  I think it might be able to produce better errors.  I have to say though that when ended up using a library that used `figment` I found it a bit awkward and confusing.

For now I suggest retaining `config`.  At least, the code that knows we're using it will be fairly self-contained.

## Miscellaneous

 * `TorClientCfg`.  Suggest renaming to `TorClientConfig`.  If we do things right, users won't normally need to type this name.

 * Default config file location is currently `./arti-config.toml`.  This should 
be changed (to XDG dirs probably)

 * `arti_defaults.toml`: this duplicates the default settings baked into the code.  This is kind of inevitable if we want to supply an example, but there is a big risk of divergence.  Either (a) there should be a test case that the defaults match the baked-in ones or (b) there should be no baked-in ones and instead things should be read from this file.  Also, it is in danger of being taken as an example config file, which is not great if we ever want to change the defaults.  Suggest we comment out every setting.  (The test case or run-time defaulting will now need to use a mechanically-uncommented versions.)

 * Configuration errors will continue to be mapped to `tor_config::ConfigBuildError`; in line with our new error handling proposal, at the top level these will turn into a kind on the portmanteau error returned from `bootstrap`.

 * IMO we should (generally) enable the `setter(into)` and `try_setter` features of `config`.

## Ideas I considered and rejected

### Make `FooConfig` transparent rather than providing a builder

Future API evolution will probably mean replacing occasional fields.  When this happens we will need to combine new values with old ways of doing the same thing.  This gets a lot harder when you can't see which fields have been set.

Also this involves constructing the default values for every field first, and then overwriting them all.
