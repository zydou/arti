//! The original Equi-X unit tests don't contain full test vectors.
//! These are from the C tor implementation's test_crypto_equix().

use equix::{EquiX, Error, HashError, Solution, SolutionItemArray};
use std::iter;

#[test]
fn verify_only() {
    // Quick verify test that doesn't use the solver at all

    assert!(matches!(
        equix::verify_array(
            b"a",
            &[
                0x2227, 0xa173, 0x365a, 0xb47d, 0x1bb2, 0xa077, 0x0d5e, 0xf25f
            ]
        ),
        Ok(())
    ));
    assert!(matches!(
        equix::verify_array(
            b"a",
            &[
                0x1bb2, 0xa077, 0x0d5e, 0xf25f, 0x2220, 0xa173, 0x365a, 0xb47d
            ]
        ),
        Err(Error::Order)
    ));
    assert!(matches!(
        equix::verify_array(
            b"a",
            &[
                0x2220, 0xa173, 0x365a, 0xb47d, 0x1bb2, 0xa077, 0x0d5e, 0xf25f
            ]
        ),
        Err(Error::HashSum)
    ));
}

#[test]
fn tor_equix_vectors() {
    // Solve and verify test with permutations

    solve_and_verify(b"bsipdp", None);
    solve_and_verify(b"espceob", None);
    solve_and_verify(
        b"zzz",
        Some(&[[
            0xae21, 0xd392, 0x3215, 0xdd9c, 0x2f08, 0x93df, 0x232c, 0xe5dc,
        ]]),
    );
    solve_and_verify(
        b"rrr",
        Some(&[[
            0x0873, 0x57a8, 0x73e0, 0x912e, 0x1ca8, 0xad96, 0x9abd, 0xd7de,
        ]]),
    );
    solve_and_verify(b"qqq", Some(&[]));
    solve_and_verify(b"0123456789", Some(&[]));
    solve_and_verify(b"zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz", Some(&[]));
    solve_and_verify(
        b"",
        Some(&[
            [
                0x0098, 0x3a4d, 0xc489, 0xcfba, 0x7ef3, 0xa498, 0xa00f, 0xec20,
            ],
            [
                0x78d8, 0x8611, 0xa4df, 0xec19, 0x0927, 0xa729, 0x842f, 0xf771,
            ],
            [
                0x54b5, 0xcc11, 0x1593, 0xe624, 0x9357, 0xb339, 0xb138, 0xed99,
            ],
        ]),
    );
    solve_and_verify(
        b"a",
        Some(&[
            [
                0x4b38, 0x8c81, 0x9255, 0xad99, 0x5ce7, 0xeb3e, 0xc635, 0xee38,
            ],
            [
                0x3f9e, 0x659b, 0x9ae6, 0xb891, 0x63ae, 0x777c, 0x06ca, 0xc593,
            ],
            [
                0x2227, 0xa173, 0x365a, 0xb47d, 0x1bb2, 0xa077, 0x0d5e, 0xf25f,
            ],
        ]),
    );
    solve_and_verify(
        b"abc",
        Some(&[
            [
                0x371f, 0x8865, 0x8189, 0xfbc3, 0x26df, 0xe4c0, 0xab39, 0xfe5a,
            ],
            [
                0x2101, 0xb88f, 0xc525, 0xccb3, 0x5785, 0xa41e, 0x4fba, 0xed18,
            ],
        ]),
    );
    solve_and_verify(
        b"abce",
        Some(&[
            [
                0x4fca, 0x72eb, 0x101f, 0xafab, 0x1add, 0x2d71, 0x75a3, 0xc978,
            ],
            [
                0x17f1, 0x7aa6, 0x23e3, 0xab00, 0x7e2f, 0x917e, 0x16da, 0xda9e,
            ],
            [
                0x70ee, 0x7757, 0x8a54, 0xbd2b, 0x90e4, 0xe31e, 0x2085, 0xe47e,
            ],
            [
                0x62c5, 0x86d1, 0x5752, 0xe1f0, 0x12da, 0x8f33, 0x7336, 0xf161,
            ],
        ]),
    );
    solve_and_verify(
        b"01234567890123456789",
        Some(&[
            [
                0x4803, 0x6775, 0xc5c9, 0xd1b0, 0x1bc3, 0xe4f6, 0x4027, 0xf5ad,
            ],
            [
                0x5a8a, 0x9542, 0xef99, 0xf0b9, 0x4905, 0x4e29, 0x2da5, 0xfbd5,
            ],
            [
                0x4c79, 0xc935, 0x2bcb, 0xcd0f, 0x0362, 0x9fa9, 0xa62e, 0xf83a,
            ],
            [
                0x5878, 0x6edf, 0x1e00, 0xf5e3, 0x43de, 0x9212, 0xd01e, 0xfd11,
            ],
            [
                0x0b69, 0x2d17, 0x01be, 0x6cb4, 0x0fba, 0x4a9e, 0x8d75, 0xa50f,
            ],
        ]),
    );
}

fn solve_and_verify(challenge: &[u8], expected: Option<&[[u16; 8]]>) {
    match EquiX::new(challenge) {
        // Some constructions are expected to fail
        Err(Error::Hash(HashError::ProgramConstraints)) => assert_eq!(expected, None),
        Err(_) => unreachable!(),

        // Check each solution itself and a few variations, when the solve succeeds
        Ok(equix) => {
            let expected = expected.unwrap();
            let solutions = equix.solve();
            assert_eq!(solutions.len(), expected.len());

            for (solution, expected) in iter::zip(solutions, expected) {
                let solution = solution.into();

                assert_eq!(&solution, expected);
                verify_expect_success(&equix, &solution);
                verify_with_order_error(&solution);
                verify_with_hash_error(&equix, &solution);
            }
        }
    }
}

fn verify_expect_success(equix: &EquiX, solution: &SolutionItemArray) {
    let solution = Solution::try_from_array(solution).unwrap();
    assert!(equix.verify(&solution).is_ok());
}

fn verify_with_hash_error(equix: &EquiX, solution: &SolutionItemArray) {
    let mut solution = *solution;
    solution[0] += 1;
    let solution = Solution::try_from_array(&solution).unwrap();
    assert!(matches!(equix.verify(&solution), Err(Error::HashSum)));
}

fn verify_with_order_error(solution: &SolutionItemArray) {
    let mut solution = *solution;
    solution.swap(0, 1);
    assert!(matches!(
        Solution::try_from_array(&solution),
        Err(Error::Order)
    ));
}
