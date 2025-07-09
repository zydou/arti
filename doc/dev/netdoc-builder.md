Building and signing netdocs
============================

We need to be able to create HS descriptors.  These are a kind of netdoc
(dir-spec.txt s1.2, 1.3).

Our tor-netdoc crate has code for parsing these.  Internally, in
`tor_netdoc::parse`, there are `SectionRules` which are used for
dismembering an incoming document.)  This is not done with types
structs with fields; rather, parsing into a dynamic data structure
indexed by values of a C-like enum, controlled by `SectionRules`.
I propose to not reuse `SectionRules`.

(In this design sketch lifetimes, generic bounds, etc., are often omitted.)

## Proposed internal API

(Now moved to `crates/tor-netdoc/src/build.rs`.)

## Proposed public API

```rust
// maybe derived with derive_builder? but the "built" struct is private
pub struct HsDescriptorBuilder<'b> {
    // Crypto keys we need to use
    k_desc_sign: Option<&'b ed25519::ExpandedSecretKey>,

    // fields to go in outer wrapper
    descriptor_lifetime: Option<LifetimeMinutes>, // err, type TBD
    ...
    ...
    // fields to go in layer 2 plaintext
    single_onion_service: bool,
    ...
}

impl HsDescriptorBuilder {
    // setters for everything, maybe taking borrowed values where relevant
    /// setter
    pub fn single_onion_service(&mut self, single_onion_service: bool);
}

impl NetdocBuilder for HsDescriptorBuilder;
```

## Proposed generic API for documents

```rust
pub trait NetdocBuilder {
    fn build_sign(self) -> Result<NetdocText<Self>, >;
}

```

## Imagined implementation

```rust
impl NetdocBuilder for HsDescriptorBuilder {
    fn build_sign(self /* or &self? */) -> Result<NetdocText<Self>, > {
        construct the L2 plaintext with NetdocBuilder
        construct the encryption key (using fields from swlf)
        encrypt
        construct the L1 plaintext with NetdocBuilder
        encrypt
        Construct the L0 plaintext.
        sign it with the provided key.
        eventually return the final NetdocText from NetdocBuilder.finish()
    }
}
```
