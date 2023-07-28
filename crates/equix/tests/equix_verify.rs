//! Round trip and constraint tests inspired by the original Equi-X implementation

use equix::{EquiX, Error, Solution, SolutionItemArray};
use std::collections::HashSet;

#[test]
fn solve_verify_1() {
    let challenge = 0u32.to_le_bytes();
    let instance = EquiX::new(&challenge).unwrap();
    let solutions = instance.solve();
    assert_eq!(solutions.len(), 1);
    assert!(instance.verify(&solutions[0]).is_ok());
    equix::verify_array(&challenge, solutions[0].as_ref()).unwrap();
}

/// Test that we find the same number of solutions as the original
/// implementation, and none of them are duplicates.
#[test]
fn expected_solution_count() {
    let mut solution_set = HashSet::<SolutionItemArray>::new();
    for seed in 0u32..20u32 {
        let instance = EquiX::new(&seed.to_le_bytes()).unwrap();
        for solution in instance.solve() {
            assert!(!solution_set.contains(solution.as_ref()));
            solution_set.insert(solution.into());
        }
    }
    assert_eq!(solution_set.len(), 38);
}

#[test]
fn incorrect_order() {
    // Test all permutations of an otherwise valid solution. Most should
    // be rejected early by the tree ordering constraints, and only one
    // will be ultimately accepted as valid.

    let challenge = EquiX::new(&0u32.to_le_bytes()).unwrap();
    let solutions = challenge.solve();
    assert_eq!(solutions.len(), 1);
    assert!(challenge.verify(&solutions[0]).is_ok());

    let mut allowed = 0usize;
    let mut err_order = 0usize;
    let mut err_sum = 0usize;
    let mut items: SolutionItemArray = solutions.into_iter().next().unwrap().into();

    let heap = permutohedron::Heap::new(&mut items);
    for permutation in heap {
        match Solution::try_from_array(&permutation) {
            Ok(solution) => match challenge.verify(&solution) {
                Ok(()) => {
                    allowed += 1;
                }
                Err(Error::HashSum) => {
                    err_sum += 1;
                }
                Err(_) => unreachable!(),
            },
            Err(Error::Order) => {
                err_order += 1;
            }
            Err(_) => unreachable!(),
        }
    }

    let total_permutations = 8 * 7 * 6 * 5 * 4 * 3 * 2;
    assert_eq!(allowed + err_order + err_sum, total_permutations);
    assert_eq!(allowed, 1);
    assert_eq!(err_sum, 314);
}
