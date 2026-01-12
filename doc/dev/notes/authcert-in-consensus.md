# directory authority key certificates in network status documents

## Requirements

Votes can contain "authority key certificates" (authcerts).

Unlike most sub-documents found within netdocs, an authcert is a
signed document.  We expect to be able to copy an authcert into a
vote, encode, convey and parse the vote, and extract the
authcert, and verify the authcert's signature.

Additionally, the fact that authcerts have their own signatures means
that they need to be constructed separately from the surrounding
document, and then embedded in it later.

When parsing a vote, we need to be able to see *which parts* are
the authcert, and we need to be able to extract the specific document
text, but we maybe don't want to parse the authcert.

## Representation must include a document string

The requirement to convey the signed authcert without breaking the
signature means that the representation of an authcert within a vote needs
include its encoded form, with all its signatures.

## Representation containing the parsed authcert is not very useful

Conversely, signature verification of authcerts during decoding of a
vote is fairly complex.  We don't want to do signature
verification during parsing, because signature verification involves
the time, and we don't want parsing to need to know the time.

We don't want to make the Rust type of the authcert field within a
vote struct different before and after verification.  That would
involve adding generics to the vote.

Therefore the existence of a parsed vote struct does not imply
that the authcerts within have had their signature validity checked.

So *if* the parsed vote contains parsed data fields from the
authcert, access to the authcert fields needs to be gated by
`.inspect_unverified()` or some such.

## Basic conclusion

Each authcert within a vote will be represented as a newtype
around a `String`, which is the authcert document (including its
intro item, all signatures, and trailing newline).

This newtype will be transparently accessible - `.as_str()` will be
available.  Maybe it will `Deref` to `str`.

Its type (so existence within the struct) will imply something about
the keywords within, but not anything about the signatures.

## Structural confusion hazard

See
<https://spec.torproject.org/dir-spec/creating-key-certificates.html#nesting>.

We need to be able to prevent the authcert author from
smuggling confusing keywords through us.
Specifically, consider the following program:

 * We obtain an authcert from somewhere
 * We parse the authcert and verify its signature and we think it's OK
 * We copy the authcert into a netstatus
 * We encode the netstatus

When constructing and encoding, we want to be able to tell when
forbidden items appear.  We want to be able to tell *which* authcert
was involved, and we don't want to entangle this with the encoder,
probably.

Therefore the type of an authcert within a netstatus should have an invariant
that the contents are suitable according to the rules in the spec.
The conditions in the spec are:

 * The lack of items that are structural for a netstatus
 * That every item keyword starts `dir-`
 * That it is properly framed with one `dir-key-certificate-version`
   and one `dir-key-certification`.

## Proposal

We make an ad-hoc type specially for an encoded authcert.

```
/// Entire authority key certificate, encoded and signed
///
/// (Invariants as above)
///
/// Non-invariant: signature and timeliness has not been checked.
///
/// Implements `NetdocParseable`:
/// parser matches `dir-key-certificate-version` and `dir-key-certification`,
/// but also calls `Bug` if the caller's `stop_at`
/// reports that this keyword is structural for its container.
/// (This could happen if an `EncodedAuthCert` existedd in some other
/// document but a vote.  We do not check this property during encoding.)
///
/// Implements `TryFrom<String>` and `FromStr`.
pub struct EncodedAuthCert(String);
```

The handwritten implementation of `EncodedAuthCert`'s parser
needs a list of the structural keywords for votes.
We enhance the `NetdocParseable` trait:

```
pub trait NetdocParseable {
    // extend this existing trait with this new function:

	/// Is `Keyword` a structural keyword for this kind of document?
	///
	/// Returns true for:
	///   - this type's intro item keyword (`is_intro_item_keyword`)
	///   - the intro items or structural items for any of its sub-documents and sections
	///     `#[deftly(netdoc(subdoc))]`
	///
	/// (This means it returns true for *any* item in a signatures subdocument
	/// ie any field in a struct decorated `#[deftly(netdoc(signatures))]`
	/// since those are considered intro items.)
	//
	// `EncodedAuthCert`s item checker contains calls to
	// `NetworkStatusVote::is_structural_keyword` and
	// `NetworkStatusSignaturesVote::is_structural_keyword`.
	//
    fn is_structural_keyword(kw: KeywordRef<'_>) -> bool;
}
```

We should also have some tests that try to smuggle so as to produce
misframed documents.

## Generics (possible future expansion)

If we discover other similar document nestings we could genericise things:

```
/// Invariant:
///
///  * Can be lexed as a netdoc
///  * First item is `Y:is_intro_item_keyword`
///  * Last item is (one) `YS:is_intro_item_keyword`
///  * No other item is any `N::is_structual_item_keyword`
///
pub struct EncodedNetdoc<Y, YS, (N0, N1 ..)>(String);

pub type EncodedAuthCert = EncodedNetdoc<
    AuthCert, AuthCertSignatures,
	(NetworkStatusVote, NetworkStatusSignaturesVote)
>;
```

Details TBD.
