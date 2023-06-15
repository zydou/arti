//! HS service key specifiers.

/// KP_hs_id, KS_hs_id.
#[allow(unused)] // TODO hs: remove
struct HsServiceIdentityKeySpecifier {
    // TODO hs: fill out the implementation.
    //
    // NOTE: this is just a sketch and might not be the right way of representing HS service
    // specifiers (i.e. maybe we shouldn't have a separate *Specifier struct for each type of key).
    // Instead, might want to have a single HsServiceSecretKeySpecifier, similarly to how we have a
    // single HsClientSecretKeySpecifier which can have one of several possible roles.
}

/// KP_hs_blind_id, KS_hs_blind_id.
#[allow(unused)] // TODO hs: remove
struct HsServiceBlindedKeySpecifier {
    // TODO hs: fill out the implementation.
    //
    // NOTE: this is just a sketch and might not be the right way of representing HS service
    // specifiers (i.e. maybe we shouldn't have a separate *Specifier struct for each type of key).
    // Instead, might want to have a single HsServiceSecretKeySpecifier, similarly to how we have a
    // single HsClientSecretKeySpecifier which can have one of several possible roles.
}

/// KP_hs_desc_sign, KS_hs_desc_sign.
#[allow(unused)] // TODO hs: remove
struct HsServiceDescriptorSigningKeySpecifier {
    // TODO hs: fill out the implementation.
    //
    // NOTE: this is just a sketch and might not be the right way of representing HS service
    // specifiers (i.e. maybe we shouldn't have a separate *Specifier struct for each type of key).
    // Instead, might want to have a single HsServiceSecretKeySpecifier, similarly to how we have a
    // single HsClientSecretKeySpecifier which can have one of several possible roles.
}
