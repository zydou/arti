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
pub(crate) struct NetdocEncoder<K> {
    // Err means bad values passed to some builder function
    built: Result<String, Bug>,
}

// we need to accumulate these in pieces, and put them in doc later,
// because otherwise args and objects can't be specified in any order
// and we'd need a typestate, and also there's the newline after the
// args
struct ItemEncoder<'n, K> {
    keyword: K,
    /// `None` after `drop`, or if an error occurred
    doc: Option<&'mut NetdocEncoder<K>>,
    args: Vec<String>,
    objects: String,
}

impl Drop for ItemEncoder<'_> {
    fn drop(&mut self) {
        // actually add any not-yet-flushed parts of the item
        // to self.doc.built.
    }
}

struct Cursor<K> {
    offset: usize,
    // Variance: notionally refers to a keyword K
    marker: PhantomData<*const K>,
}

impl NetdocEncoder<K> {
    /// Adds an item to the being-build document
    ///
    /// The item can be further extended with arguments or objects,
    /// using the returned `ItemEncoder`.
    //
    // Actually, we defer adding the item until `ItemEncoder` is dropped.
    pub fn item(&mut self, keyword: K) -> &mut ItemEncoder<K>;

    pub fn cursor(&self) -> Cursor<K>;

    // useful for making a signature
    //
    // Q. Should this return `&str` or `NetdocText<'self>` ?
    // (`NetdocText would have to then contain `Cow`, which is fine.)
    pub fn slice(&self, begin: Cursor<K>, end: Cursor<K>)
        -> Result<&str, Bug>;

    pub(crate) fn finish() -> Result<NetdocText<Self>, Bug>;
}

impl ItemEncoder<'n, K> {
    // This is not a hot path.  `dyn` for smaller code size.
    //
    // If arg is not in the correct syntax, a `Bug` is stored in self.doc.
    fn arg(&mut self, arg: &dyn Display) -> &mut self;

    // If keyword is not in the correct syntax,
    // or data fails to be written, a `Bug` is stored in self.doc.
    fn object(&mut self, keyword: &str,
               // Writeable isn't dyn-compatible
               data: impl tor_bytes::WriteableOnce) -> &mut self;
}

// Alternative to the `Bug` above.
// I think all of these are programming errors.
//
// If we don't have `Bug` in `NetdocEncoder`, we may want to have
// `.arg()` and `.object()` return `Result` but deferring the errors
// seems more ergonomic.
enum BuildError {
    /// Argument contained other than printing ASCII
    BadArgument { item_keyword: String, argument: String }

    /// Object keyword had bad syntax
    BadObjectKeyword { item_keyword: String, object_keyword: String }

    /// Object's `Writeable` implementation failed
    Encode { item_keyword: String, object_keyword: String,
             #[fsource] error: tor_bytes::Err::EncodeError, },
}
```

### Example of use:
```
use OnionServiceKeyword as K;

    let mut document = NetDocEncoder::new();
    let beginning = document.marker();
    document.item(K::HsDescriptor).arg(3);
    document.item(K::DescriptorLifetime).arg(&self.lifetime);
    document.item(K::DescriptorSigningKeyCert).object("ED25519 CERT", &self.cert[..])
    document.item(K::RevisionCounter).arg(&self.counter);
    document.item(K::Superencrypted).object("MESSAGE", inner_text);
    let end = document.marker();
    let signature = key.sign(document.slice(begining, end));
    document.item(K::Signature).arg(B64(signature));

    let text = document.finish()?;
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

impl Deref<Target=str> for NetdocText<_> { ... }
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
