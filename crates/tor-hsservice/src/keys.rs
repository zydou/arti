//! HS service key specifiers.

/// KP_hs_id, KS_hs_id.
#[allow(unused)] // TODO hss: remove
struct HsServiceIdentityKeySpecifier {
    // TODO hss: fill out the implementation.
    //
    // NOTE: this is just a sketch and might not be the right way of representing HS service
    // specifiers (i.e. maybe we shouldn't have a separate *Specifier struct for each type of key).
    // Instead, might want to have a single HsServiceSecretKeySpecifier, similarly to how we have a
    // single HsClientSecretKeySpecifier which can have one of several possible roles.
}

/// KP_hs_blind_id, KS_hs_blind_id.
#[allow(unused)] // TODO hss: remove
struct HsServiceBlindedKeySpecifier {
    // TODO hss: fill out the implementation.
    //
    // NOTE: this is just a sketch and might not be the right way of representing HS service
    // specifiers (i.e. maybe we shouldn't have a separate *Specifier struct for each type of key).
    // Instead, might want to have a single HsServiceSecretKeySpecifier, similarly to how we have a
    // single HsClientSecretKeySpecifier which can have one of several possible roles.
}

/// KP_hs_desc_sign, KS_hs_desc_sign.
#[allow(unused)] // TODO hss: remove
struct HsServiceDescriptorSigningKeySpecifier {
    // TODO hss: fill out the implementation.
    //
    // NOTE: this is just a sketch and might not be the right way of representing HS service
    // specifiers (i.e. maybe we shouldn't have a separate *Specifier struct for each type of key).
    // Instead, might want to have a single HsServiceSecretKeySpecifier, similarly to how we have a
    // single HsClientSecretKeySpecifier which can have one of several possible roles.
}
