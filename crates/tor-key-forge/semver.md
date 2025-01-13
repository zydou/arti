BREAKING: `ErasedKey` is now `Box<dyn ItemType>`
BREAKING: `EncodableItem::item_type()` moved to `ItemType::item_type()`
BREAKING: `ToEncodableCert::Cert` replaced with `ToEncodableCert::ParsedCert` and `ToEncodableCert::EncodableCert`
BREAKING: `ToEncodableCert::validate` now takes a `Self::ParsedCert` and returns `Self`
REMOVED: `ToEncodableCert::From_encodableCert`
