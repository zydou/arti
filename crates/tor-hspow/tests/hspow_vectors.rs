//! Test vectors from the C tor implementation
//!
//! Includes short-running 'verify' tests and longer-running 'solve' tests,
//! with vectors from C tor.
//!
//! The solve tests are still optimized to complete without wasting too much
//! time, by artificially choosing a `first_nonce` only slightly lower than the
//! `expected_nonce` we want to find.

use equix::SolutionByteArray;
use hex_literal::hex;
use tor_hscrypto::pk::HsBlindId;
use tor_hspow::v1::{
    Effort, Instance, Nonce, Seed, Solution, SolutionErrorV1, SolverInput, Verifier,
};
use tor_hspow::{Error, SolutionError};

#[test]
fn verify_seed0_effort1_hash_err() {
    // All zero, but only claims an effort of 1.
    // Expect it will last until hash sum checks before failing.
    assert!(matches!(
        Verifier::new(Instance::new(
            hex!("1111111111111111111111111111111111111111111111111111111111111111").into(),
            hex!("0000000000000000000000000000000000000000000000000000000000000000").into(),
        ))
        .check(
            &Solution::try_from_bytes(
                hex!("00000000000000000000000000000000").into(),
                1_u32.into(),
                hex!("00000000").into(),
                &hex!("00000000000000000000000000000000"),
            )
            .unwrap(),
        ),
        Err(Error::BadSolution(SolutionError::V1(
            SolutionErrorV1::HashSum
        )))
    ));
}

#[test]
fn verify_seed0_effort10_effort_err() {
    // All zero, but a higher effort claim. Should fail the effort check.
    assert!(matches!(
        Verifier::new(Instance::new(
            hex!("1111111111111111111111111111111111111111111111111111111111111111").into(),
            hex!("0000000000000000000000000000000000000000000000000000000000000000").into(),
        ))
        .check(
            &Solution::try_from_bytes(
                hex!("00000000000000000000000000000000").into(),
                10_u32.into(),
                hex!("00000000").into(),
                &hex!("00000000000000000000000000000000"),
            )
            .unwrap(),
        ),
        Err(Error::BadSolution(SolutionError::V1(
            SolutionErrorV1::Effort
        )))
    ));
}

#[test]
fn verify_seed0_effort0_seed_err() {
    // Seed head mismatch
    assert!(matches!(
        Verifier::new(Instance::new(
            hex!("1111111111111111111111111111111111111111111111111111111111111111").into(),
            hex!("0000000000000000000000000000000000000000000000000000000000000000").into(),
        ))
        .check(
            &Solution::try_from_bytes(
                hex!("00000000000000000000000000000000").into(),
                0_u32.into(),
                hex!("00000001").into(),
                &hex!("00000000000000000000000000000000"),
            )
            .unwrap(),
        ),
        Err(Error::BadSolution(SolutionError::V1(SolutionErrorV1::Seed)))
    ));
}

#[test]
fn verify_effort0_ok() {
    // Valid zero-effort solution
    assert!(Verifier::new(Instance::new(
        hex!("1111111111111111111111111111111111111111111111111111111111111111").into(),
        hex!("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa").into()
    ))
    .check(
        &Solution::try_from_bytes(
            hex!("55555555555555555555555555555555").into(),
            0_u32.into(),
            hex!("aaaaaaaa").into(),
            &hex!("4312f87ceab844c78e1c793a913812d7")
        )
        .unwrap()
    )
    .is_ok());
}

#[test]
fn verify_effort1m_ok() {
    // Valid high-effort solution
    assert!(Verifier::new(Instance::new(
        hex!("1111111111111111111111111111111111111111111111111111111111111111").into(),
        hex!("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa").into()
    ))
    .check(
        &Solution::try_from_bytes(
            hex!("59217255555555555555555555555555").into(),
            1_000_000_u32.into(),
            hex!("aaaaaaaa").into(),
            &hex!("0f3db97b9cac20c1771680a1a34848d3")
        )
        .unwrap()
    )
    .is_ok());
}

#[test]
fn verify_effort100k_effort_err() {
    // The claimed effort must exactly match what's was in the challenge
    // when the Equi-X proof was created, or it will fail either the
    // Effort or HashSum checks.
    assert!(matches!(
        Verifier::new(Instance::new(
            hex!("bfd298428562e530c52bdb36d81a0e293ef4a0e94d787f0f8c0c611f4f9e78ed").into(),
            hex!("86fb0acf4932cda44dbb451282f415479462dd10cb97ff5e7e8e2a53c3767a7f").into()
        ))
        .check(
            &Solution::try_from_bytes(
                hex!("2eff9fdbc34326d9d2f18ed277469c63").into(),
                99_999_u32.into(),
                hex!("86fb0acf").into(),
                &hex!("400cb091139f86b352119f6e131802d6")
            )
            .unwrap()
        ),
        Err(Error::BadSolution(SolutionError::V1(
            SolutionErrorV1::Effort
        )))
    ));
}

#[test]
fn verify_seed86_effort100k_effort_err() {
    // Otherwise good solution but with a corrupted nonce. This may fail
    // either the Effort or HashSum checks.
    assert!(matches!(
        Verifier::new(Instance::new(
            hex!("bfd298428562e530c52bdb36d81a0e293ef4a0e94d787f0f8c0c611f4f9e78ed").into(),
            hex!("86fb0acf4932cda44dbb451282f415479462dd10cb97ff5e7e8e2a53c3767a7f").into()
        ))
        .check(
            &Solution::try_from_bytes(
                hex!("2eff9fdbc34326d9a2f18ed277469c63").into(),
                100_000_u32.into(),
                hex!("86fb0acf").into(),
                &hex!("400cb091139f86b352119f6e131802d6")
            )
            .unwrap()
        ),
        Err(Error::BadSolution(SolutionError::V1(
            SolutionErrorV1::Effort
        )))
    ));
}

#[test]
fn verify_seed86_effort100k_ok() {
    assert!(Verifier::new(Instance::new(
        hex!("bfd298428562e530c52bdb36d81a0e293ef4a0e94d787f0f8c0c611f4f9e78ed").into(),
        hex!("86fb0acf4932cda44dbb451282f415479462dd10cb97ff5e7e8e2a53c3767a7f").into()
    ))
    .check(
        &Solution::try_from_bytes(
            hex!("2eff9fdbc34326d9d2f18ed277469c63").into(),
            100_000_u32.into(),
            hex!("86fb0acf").into(),
            &hex!("400cb091139f86b352119f6e131802d6")
        )
        .unwrap()
    )
    .is_ok());
}

/// Utility to solve and verify one puzzle
fn solve_and_verify(
    effort: Effort,
    first_nonce: Nonce,
    seed: Seed,
    service: HsBlindId,
    expected_nonce: Nonce,
    expected_proof: SolutionByteArray,
) {
    let instance = Instance::new(service, seed);
    let solution = SolverInput::new(instance.clone(), effort)
        .solve_with_nonce(&first_nonce)
        .run()
        .unwrap();
    assert_eq!(solution.seed_head(), instance.seed().head());
    assert_eq!(solution.effort(), effort);
    assert_eq!(solution.nonce(), &expected_nonce);
    assert_eq!(solution.proof_to_bytes(), expected_proof);
    assert!(Solution::try_from_bytes(
        expected_nonce,
        effort,
        instance.seed().head(),
        &expected_proof
    )
    .is_ok());
    assert!(Verifier::new(instance).check(&solution).is_ok());
}

#[test]
fn solve_effort0_aa_11_55() {
    solve_and_verify(
        0_u32.into(),
        hex!("55555555555555555555555555555555").into(),
        hex!("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa").into(),
        hex!("1111111111111111111111111111111111111111111111111111111111111111").into(),
        hex!("55555555555555555555555555555555").into(),
        hex!("4312f87ceab844c78e1c793a913812d7"),
    );
}

#[test]
fn solve_effort1_aa_11_55() {
    solve_and_verify(
        1_u32.into(),
        hex!("55555555555555555555555555555555").into(),
        hex!("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa").into(),
        hex!("1111111111111111111111111111111111111111111111111111111111111111").into(),
        hex!("55555555555555555555555555555555").into(),
        hex!("84355542ab2b3f79532ef055144ac5ab"),
    );
}

#[test]
fn solve_effort1_aa_10_55() {
    solve_and_verify(
        1_u32.into(),
        hex!("55555555555555555555555555555555").into(),
        hex!("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa").into(),
        hex!("1111111111111111111111111111111111111111111111111111111111111110").into(),
        hex!("55555555555555555555555555555555").into(),
        hex!("115e4b70da858792fc205030b8c83af9"),
    );
}

#[test]
fn solve_effort2_aa_11_55() {
    solve_and_verify(
        2_u32.into(),
        hex!("55555555555555555555555555555555").into(),
        hex!("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa").into(),
        hex!("1111111111111111111111111111111111111111111111111111111111111111").into(),
        hex!("55555555555555555555555555555555").into(),
        hex!("4600a93a535ed76dc746c99942ab7de2"),
    );
}

#[test]
fn solve_effort10_aa_11_56() {
    solve_and_verify(
        10_u32.into(),
        hex!("55555555555555555555555555555555").into(),
        hex!("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa").into(),
        hex!("1111111111111111111111111111111111111111111111111111111111111111").into(),
        hex!("56555555555555555555555555555555").into(),
        hex!("128bbda5df2929c3be086de2aad34aed"),
    );
}

#[test]
fn solve_effort10_aa_11_01() {
    solve_and_verify(
        10_u32.into(),
        hex!("ffffffffffffffffffffffffffffffff").into(),
        hex!("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa").into(),
        hex!("1111111111111111111111111111111111111111111111111111111111111111").into(),
        hex!("01000000000000000000000000000000").into(),
        hex!("203af985537fadb23f3ed5873b4c81ce"),
    );
}

#[test]
fn solve_effort1k_aa_41_01() {
    solve_and_verify(
        1337_u32.into(),
        hex!("feffffffffffffffffffffffffffffff").into(),
        hex!("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa").into(),
        hex!("4111111111111111111111111111111111111111111111111111111111111111").into(),
        hex!("01000000000000000000000000000000").into(),
        hex!("31c377cb72796ed80ae77df6ac1d6bfd"),
    );
}

#[test]
fn solve_effort30k_aa_11_36() {
    solve_and_verify(
        31337_u32.into(),
        hex!("34a20000000000000000000000000000").into(),
        hex!("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa").into(),
        hex!("1111111111111111111111111111111111111111111111111111111111111111").into(),
        hex!("36a20000000000000000000000000000").into(),
        hex!("ca6899b91113aaf7536f28db42526bff"),
    );
}

#[test]
fn solve_effort100_aa_11_56() {
    solve_and_verify(
        100_u32.into(),
        hex!("55555555555555555555555555555555").into(),
        hex!("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa").into(),
        hex!("1111111111111111111111111111111111111111111111111111111111111111").into(),
        hex!("56555555555555555555555555555555").into(),
        hex!("3a4122a240bd7abfc922ab3cbb9479ed"),
    );
}

#[test]
fn solve_effort1k_aa_11_d4() {
    solve_and_verify(
        1000_u32.into(),
        hex!("d3555555555555555555555555555555").into(),
        hex!("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa").into(),
        hex!("1111111111111111111111111111111111111111111111111111111111111111").into(),
        hex!("d4555555555555555555555555555555").into(),
        hex!("338cc08f57697ce8ac2e4b453057d6e9"),
    );
}

#[test]
fn solve_effort10k_aa_11_c8() {
    solve_and_verify(
        10_000_u32.into(),
        hex!("c5715555555555555555555555555555").into(),
        hex!("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa").into(),
        hex!("1111111111111111111111111111111111111111111111111111111111111111").into(),
        hex!("c8715555555555555555555555555555").into(),
        hex!("9f2d3d4ed831ac96ad34c25fb59ff3e2"),
    );
}

#[test]
fn solve_effort100k_aa_11_42() {
    solve_and_verify(
        100_000_u32.into(),
        hex!("418d5655555555555555555555555555").into(),
        hex!("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa").into(),
        hex!("1111111111111111111111111111111111111111111111111111111111111111").into(),
        hex!("428d5655555555555555555555555555").into(),
        hex!("9863f3acd2d15adfd244a7ca61d4c6ff"),
    );
}

#[test]
fn solve_effort1m_aa_11_59() {
    solve_and_verify(
        1_000_000_u32.into(),
        hex!("58217255555555555555555555555555").into(),
        hex!("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa").into(),
        hex!("1111111111111111111111111111111111111111111111111111111111111111").into(),
        hex!("59217255555555555555555555555555").into(),
        hex!("0f3db97b9cac20c1771680a1a34848d3"),
    );
}

#[test]
fn solve_effort1_c5_bf_d1() {
    solve_and_verify(
        1_u32.into(),
        hex!("d0aec1669384bfe5ed39cd724d6c7954").into(),
        hex!("c52be1f8a5e6cc3b8fb71cfdbe272cbc91d4d035400f2f94fb0d0074794e0a07").into(),
        hex!("bfd298428562e530c52bdb36d81a0e293ef4a0e94d787f0f8c0c611f4f9e78ed").into(),
        hex!("d1aec1669384bfe5ed39cd724d6c7954").into(),
        hex!("462606e5f8c2f3f844127b8bfdd6b4ff"),
    );
}

#[test]
fn solve_effort1_86_bf_b4() {
    solve_and_verify(
        1_u32.into(),
        hex!("b4d0e611e6935750fcf9406aae131f62").into(),
        hex!("86fb0acf4932cda44dbb451282f415479462dd10cb97ff5e7e8e2a53c3767a7f").into(),
        hex!("bfd298428562e530c52bdb36d81a0e293ef4a0e94d787f0f8c0c611f4f9e78ed").into(),
        hex!("b4d0e611e6935750fcf9406aae131f62").into(),
        hex!("9f3fbd50b1a83fb63284bde44318c0fd"),
    );
}

#[test]
fn solve_effort1_9d_be_b4() {
    solve_and_verify(
        1_u32.into(),
        hex!("b4d0e611e6935750fcf9406aae131f62").into(),
        hex!("9dfbd06d86fed8e12de3ab214e1a63ea61f46253fe08346a20378da70c4a327d").into(),
        hex!("bec632eb76123956f99a06d394fcbee8f135b8ed01f2e90aabe404cb0346744a").into(),
        hex!("b4d0e611e6935750fcf9406aae131f62").into(),
        hex!("161baa7490356292d020065fdbe55ffc"),
    );
}

#[test]
fn solve_effort1_86_bf_40() {
    solve_and_verify(
        1_u32.into(),
        hex!("40559fdbc34326d9d2f18ed277469c63").into(),
        hex!("86fb0acf4932cda44dbb451282f415479462dd10cb97ff5e7e8e2a53c3767a7f").into(),
        hex!("bfd298428562e530c52bdb36d81a0e293ef4a0e94d787f0f8c0c611f4f9e78ed").into(),
        hex!("40559fdbc34326d9d2f18ed277469c63").into(),
        hex!("fa649c6a2c5c0bb6a3511b9ea4b448d1"),
    );
}

#[test]
fn solve_effort10k_86_bf_36() {
    solve_and_verify(
        10_000_u32.into(),
        hex!("34569fdbc34326d9d2f18ed277469c63").into(),
        hex!("86fb0acf4932cda44dbb451282f415479462dd10cb97ff5e7e8e2a53c3767a7f").into(),
        hex!("bfd298428562e530c52bdb36d81a0e293ef4a0e94d787f0f8c0c611f4f9e78ed").into(),
        hex!("36569fdbc34326d9d2f18ed277469c63").into(),
        hex!("2802951e623c74adc443ab93e99633ee"),
    );
}

#[test]
fn solve_effort100k_86_bf_2e() {
    solve_and_verify(
        100_000_u32.into(),
        hex!("2cff9fdbc34326d9d2f18ed277469c63").into(),
        hex!("86fb0acf4932cda44dbb451282f415479462dd10cb97ff5e7e8e2a53c3767a7f").into(),
        hex!("bfd298428562e530c52bdb36d81a0e293ef4a0e94d787f0f8c0c611f4f9e78ed").into(),
        hex!("2eff9fdbc34326d9d2f18ed277469c63").into(),
        hex!("400cb091139f86b352119f6e131802d6"),
    );
}

#[test]
fn solve_effort1m_86_bf_55() {
    solve_and_verify(
        1_000_000_u32.into(),
        hex!("5243b3dbc34326d9d2f18ed277469c63").into(),
        hex!("86fb0acf4932cda44dbb451282f415479462dd10cb97ff5e7e8e2a53c3767a7f").into(),
        hex!("bfd298428562e530c52bdb36d81a0e293ef4a0e94d787f0f8c0c611f4f9e78ed").into(),
        hex!("5543b3dbc34326d9d2f18ed277469c63").into(),
        hex!("b47c718b56315e9697173a6bac1feaa4"),
    );
}
