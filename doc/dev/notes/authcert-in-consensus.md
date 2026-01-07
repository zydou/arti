# directory authority key certificates in network status documents

## Requirements

Network status documents (netstatuses) can contain "authority key
certificates" (authcerts).

Unlike most sub-documents found within netdocs, an authcert is a
signed document.  We expect to be able to copy an authcert into a
nestatus, encode, convey and parse the netstatus, and extract the
authcert, and verify the authcert's signature.

Additionally, the fact that authcerts have their own signatures means
that they need to be constructed separately from the surrounding
document, and then embedded in it later.

When parsing a netstatus, we need to be able to see *which parts* are
the netstatus, and we need to be able to extract the specific document
text, but we maybe don't want to parse the netstatus.

## Representation must include a document string

The requirement to convey the signed authcert without breaking the
signature means that the representation of an authcert within a netstatus needs
include its encoded form, with all its signatures.

## Representation containing the parsed authcert is not very useful

Conversely, signature verification of authcerts during decoding of a
netstatus is fairly complex.  We don't want to do signature
verification during parsing, because signature verification involves
the time, and we don't want parsing to need to know the time.

We don't want to make the Rust type of the authcert field within a
netstatus struct different before and after verification.  That would
involve adding generics to the netstatus.

Therefore the existence of a parsed netstatus struct does not imply
that the authcerts within have had their signature validity checked.

So *if* the parsed netstatus contains parsed data fields from the
authcert, access to the authcert fields needs to be gated by
`.inspect_unverified()` or some such.

## Basic conclusion

Each authcert within a netstatus will be represented as a newtype
around a `String`, which is the authcert document (iincluding its
intro item, all signatures, and trailing newline).

This newtype will be transparently accessible - `.as_str()` will be
available.  Maybe it will `Deref` to `str`.

Its type (so existence within the struct) will imply something about
the keywords within, but not anything about the signatures.

## Structural confusion hazard

Consider the following program:

 * We obtain an authcert from somewhere
 * We parse the authcert and verify its signature and we think it's OK
 * We copy the authcert into a netstatus
 * We encode the netstatus

The authcert might contain items that are structural for a netstatus,
so that when we embed it into the netstatus, we get an unintended framing.
This would perhaps be a vulnerability.

What keywords are structural depends on the surrounding document.
And we must ignore unknown keywords when parsing.
So parsing an authcert in isolation doesn't assure us that there is no
such problem!

When constructing and encoding, we want to be able to tell when this
problem is happening.  We want to be able to tell *which* authcert was
involved, and we don't want to entangle this with the encoder,
probably.

So we want the type of an authcert within a netstatus
struct to imply that this structural keyword property has been
checked.
I.e. the type of the authcert *within a netstatus* must have the
invariant that the string doesn't contain any keywords that are
structural *within a netstatus*.

## Proposal

```
/// Invariant:
///
///  * Can be lexed as a netdoc
///  * First item is `Y:is_intro_item`
///  * No other item is any `N::is_structual_item_keyword`
///
pub struct EncodedNetdoc<Y, (N0, N1 ..)>(String);

pub type EncodedAuthCert = EncodedNetdoc<
    AuthCert,
	(NetStatusConsensus, NetStatusVote, NetStatusAuthoritySection, etc.)
>;
```

When we encode a `NetStatus`, we end up encoding a
`NetStatusAuthoritySection` sub-document.  Within the
`NetStatusAuthoritySection` we find an `EncodedAuthCert`.

The derived encoder impl for `NetStatusAuthoritySection` consults its
own type `TypeId` and that for `NetStatus` (which was passed in via
its arguments) and checks that they are all included in the `N`s.
That demonstrates that there are no keywords in the document that
would mess up the parsing of the surrounding documents.

If any `TypeId` in the dynamic context are missing, it's a `Bug`: this
shows that the wrong type was provided.  (Sadly we can detect this
only at runtime, unless we want to make the encode method generic -
but this error would be detected every time this type was encoded, not
only when encoding erroneous documents, so the bug couldn't easily
survive testing.)

We should probably also do a runtime check during encoding where we
pass the structural keywords callback down to the next encoder and
report a `Bug` if we get something untoward.

We should also have some tests that try to smuggle so as to produce
miframed documents.

```
pub trait NetdocSomething {
    /// New function, exposing `is_subdoc_kw` from the middle of `from_items`
	///
	/// Returns true for this type's intro item keyword,
	/// and for the intro items for any of its sub-documents and sections
	/// `#[deftly(netdoc(subdoc))]`
	///
	/// But it adds up the number of true's
    fn is_structural_keyword(kw: KeywordRef<'_>) -> bool;
}
```
