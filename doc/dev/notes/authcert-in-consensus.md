# directory authority key certificates in network status documents

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
 * That every item keyword starts `dir-` (or is `fingerprint`)
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
