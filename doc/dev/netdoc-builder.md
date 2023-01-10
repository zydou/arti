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

```rust
pub(crate) struct NetdocBuilder<K> {
    items: Vec<Item<K>>,
}

impl NetdocBuilder<K> {
    pub fn push(&mut self, item: Item<K>);
    // do we need this to be generic over the key type?
    pub fn sign(&mut self, k: &ed25519::ExpandedSecretKey);
}
impl Extend<Item<K>> for NetdocBuilder<K> { ... }
```

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
    // fields to go in layer 2 plaintest
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

/// network document text according to dir-spec.txt s1.2 and maybe s1.3
///
/// contains just the text, but marked with the type of the builder
/// for clarity in function signatures etc.
pub struct NetdocText<Builder> {
    text: String,
    // variance: this somehow came from a T (not that we expect this to matter)
    kind: PhantomData<Builder>,
}

impl NetdocBuilder {
    pub(crate) fn finish() -> NetdocText<Self>;
}

impl Deref<Target=str> for NetdocText<_> { ... }
```

## Imagined implementation

```rust
impl NetdocBuilder for HsDescriptorBuilder {
    fn build_sign(self /* or &self? */) -> Result<NetdocText<Self>, > {
        construct the L2 plaintext with NetdocBuilder
        sign it with NetdocBuilder::sign
        construct the encryption key (using fields from swlf)
        encrypt
        construct the L1 plaintext with NetdocBuilder
        etc. etc.
        eventually return the final NetdocText from NetdocBuilder.finish()
    }
}
```

## `Item` type

Currently there is an `Item<'borrowed, K: Keyword>`.

The scheme abouve needs something similar.

The required contents of the builder's `Item` is a little different to
the parser's, but similar enough that we problably want to reuse it.

I propose:

 * Change `Item` and `Object` to contain `Cow`
 * Move them out of `tor_netdoc::parse` into a private module at the toplevel
 * Change the contents of `Item` so that it can contain at least one of `args`
   and `split_args` and maybe both.  `args` will go into the `RefCell`.
   Thus args can be built up.

 * Provide an `ItemBuilder` with the appropriate setters and a build method.

An alternative design would be to have completely separate `Item` for
netdoc construction as for parsing.  But we will probably in the
future want to be able to (for example) add our own signatures to
someone else's netdoc.
