//! Find Equi-X solutions.
//!
//! This is a particular instance of Equihash, a tree-structured search for
//! partial hash collisions using temporary memory. Equi-X modifies it to use
//! sums instead of XOR, and chooses specific parameters.

use crate::bucket_array::{
    hash::Insert, hash::KeyValueBucketArray, mem::BucketArrayMemory, mem::Uninit,
};
use crate::collision::{self, PackedCollision};
use crate::solution::{self, EQUIHASH_N, HashValue, Solution, SolutionArray, SolutionItem};
use arrayvec::ArrayVec;
use hashx::HashX;

// The hash table bucket counts here are mostly constrained by the shape of
// the Equihash tree, but the bucket capacities are somewhat arbitrary. Larger
// buckets use more memory, smaller buckets may discard solutions if there are
// sufficient collisions during the earlier layers. This uses the same bucket
// counts as the original Equi-X implementation, in order to exactly match
// its solution discarding behavior and thus its output.

/// First layer hash table, needs room for the full set of [`HashValue`]s and
/// [`SolutionItem`]s. Key remainder is `(EQUIHASH_N - 8 == 52)` bits here.
type Layer0<'k, 'v> =
    KeyValueBucketArray<'k, 'v, 256, 336, u16, HashValue, HashValue, SolutionItem>;
/// Key backing storage for [`Layer0`]
type Layer0KeyMem = BucketArrayMemory<256, 336, HashValue>;
/// Value backing storage for [`Layer0`]
type Layer0ValueMem = BucketArrayMemory<256, 336, SolutionItem>;
/// Packed collision type for [`Layer0`]
type Layer0Collision = PackedCollision<u32, 8, 9>;

/// Next layer maps residual hash (3/4 full width == 45 bits) to packed
/// [`Layer0Collision`]. Key remainder is 37 bits after this.
type Layer1<'k, 'v> = KeyValueBucketArray<'k, 'v, 256, 336, u16, u64, u64, u32>;
/// Key backing storage for [`Layer1`]
type Layer1KeyMem = BucketArrayMemory<256, 336, u64>;
/// Value backing storage for [`Layer1`]
type Layer1ValueMem = BucketArrayMemory<256, 336, u32>;
/// Packed collision type for [`Layer1`]
type Layer1Collision = PackedCollision<u32, 8, 9>;

/// Final layer maps the (N/2 == 30 bits) residual hash sum to packed
/// [`Layer1Collision`]. Key remainder is 22 bits.
type Layer2<'k, 'v> = KeyValueBucketArray<'k, 'v, 256, 336, u16, u32, u32, u32>;
/// Key backing storage for [`Layer2`]
type Layer2KeyMem = BucketArrayMemory<256, 336, u32>;
/// Value backing storage for [`Layer2`]
type Layer2ValueMem = BucketArrayMemory<256, 336, u32>;

/// Temporary value hash for resolving collisions between buckets.
/// This removes 7 bits of key between each of the other layers.
/// Value type may hold a [`SolutionItem`] or a temporary item-in-bucket index.
type TempMem = BucketArrayMemory<128, 12, u16>;

/// Internal solver memory, inside the heap allocation
///
/// Contains exclusively [`std::mem::MaybeUninit`] members. Other than the
/// temporary memory used between each pair of tree layers, the memory regions
/// are organized by which layer of the solution tree they form starting
/// from leaf `(hash, index)` items and moving toward the root of the tree.
#[derive(Copy, Clone)]
struct SolverMemoryInner {
    /// Temporary memory for each [`collision::search()`]
    temp: TempMem,
    /// Memory overlay union, access controlled with mutable references
    overlay: Overlay,
    /// Temporary value memory for [`Layer0`]
    layer0_values: Layer0ValueMem,
    /// Temporary value memory for [`Layer1`]
    layer1_values: Layer1ValueMem,
    /// Temporary key storage memory for [`Layer1`]
    layer1_keys: Layer1KeyMem,
}

/// SAFETY: We are proimising that [`SolverMemoryInner`] is
///         made only from [`Uninit`] types like [`BucketArrayMemory`].
unsafe impl Uninit for SolverMemoryInner {}

/// Union of overlay layouts used in solver memory
///
/// As a memory optimization, some of the allocations in [`SolverMemoryInner`]
/// are overlapped. We only use one of these at a time, checked statically
/// using a mutable borrow.
#[derive(Copy, Clone)]
union Overlay {
    /// Initial memory overlay layout
    first: OverlayFirst,
    /// Layout which replaces the first once we can drop `layer0_keys`
    second: OverlaySecond,
}

impl Overlay {
    /// Access the first overlay layout, via a mutable reference
    fn first(&mut self) -> &mut OverlayFirst {
        // SAFETY: This union and its members implement [`Uninit`], promising
        //         that we can soundly create an instance out of uninitialized
        //         or reused memory. Initialized state is controlled via a
        //         mutable reference, and by reborrowing a union field we ensure
        //         exclusive access using the borrow checker.
        unsafe { &mut self.first }
    }

    /// Access the second overlay layout, via a mutable reference
    fn second(&mut self) -> &mut OverlaySecond {
        // SAFETY: As above, we implement [`Uninit`] and use &mut to control access
        unsafe { &mut self.second }
    }
}

/// First memory overlay, contains the key portion of [`Layer0`]
#[derive(Copy, Clone)]
struct OverlayFirst {
    /// Key remainder table for [`Layer0`], which we can drop
    /// after running [`collision::search()`] on that layer.
    layer0_keys: Layer0KeyMem,
}

/// Second overlay, with both parts of Layer2
#[derive(Copy, Clone)]
struct OverlaySecond {
    /// Temporary key storage memory for [`Layer2`]
    layer2_keys: Layer2KeyMem,
    /// Temporary value memory for [`Layer2`]
    layer2_values: Layer2ValueMem,
}

/// Search for solutions, iterating the entire [`SolutionItem`] space and using
/// temporary memory to locate partial sum collisions at each tree layer.
pub(crate) fn find_solutions(func: &HashX, mem: &mut SolverMemory, results: &mut SolutionArray) {
    // Use the first memory overlay layout.
    let overlay = mem.heap.overlay.first();

    // Enumerate all hash values into the first layer
    let mut layer0 = Layer0::new(&mut overlay.layer0_keys, &mut mem.heap.layer0_values);
    for item in SolutionItem::MIN..=SolutionItem::MAX {
        let hash = solution::item_hash(func, item);
        let _ = layer0.insert(hash, item);
    }

    // Now form the first layer of the Equihash tree,
    // with collisions in the low N/4 (15) bits
    let layer1_n = EQUIHASH_N / 4;
    let mut layer1 = Layer1::new(&mut mem.heap.layer1_keys, &mut mem.heap.layer1_values);
    collision::search(&layer0, &mut mem.heap.temp, layer1_n, |sum, loc| {
        let _ = layer1.insert(sum, Layer0Collision::pack(&loc).into_inner());
    });

    // Once we finish searching a layer for collisions,
    // we can drop the key data and make the rest immutable.
    // This drops the last mutable reference into the first overlay.
    let layer0 = layer0.drop_key_storage();

    // Now switch to the second memory overlay layout.
    let overlay = mem.heap.overlay.second();

    // Next Equihash layer, collisions in the low N/2 (30) bits
    let layer2_n = EQUIHASH_N / 2;
    let mut layer2 = Layer2::new(&mut overlay.layer2_keys, &mut overlay.layer2_values);
    collision::search(
        &layer1,
        &mut mem.heap.temp,
        layer2_n - layer1_n,
        |sum, loc| {
            let _ = layer2.insert(sum as u32, Layer1Collision::pack(&loc).into_inner());
        },
    );

    // Final layer, match the entire N bits and assemble complete solutions
    let layer3_n = EQUIHASH_N;
    collision::search(
        &layer2,
        &mut mem.heap.temp,
        layer3_n - layer2_n,
        |_sum, loc| {
            let mut items = ArrayVec::<SolutionItem, { Solution::NUM_ITEMS }>::new();

            // Walk the binary tree of collision locations, in order.
            // The leaf layer will have our SolutionItems.
            loc.pair(&layer2).into_iter().for_each(|loc| {
                Layer1Collision::new(loc)
                    .unpack()
                    .pair(&layer1)
                    .into_iter()
                    .for_each(|loc| {
                        Layer0Collision::new(loc)
                            .unpack()
                            .pair(&layer0)
                            .into_iter()
                            .for_each(|item| items.push(item));
                    });
            });

            // Apply the ordering constraints and check for duplicates
            let solution = Solution::sort_from_array(
                items
                    .into_inner()
                    .expect("always collected a full SolutionItem tree"),
            );
            if results.last() != Some(&solution) {
                let _ = results.try_push(solution);
            }
        },
    );
}

/// Temporary memory used by the Equi-X solver
///
/// This space is needed temporarily during a solver run. It will be
/// allocated on the heap by [`SolverMemory::new()`], and the solver
/// provides a [`crate::EquiX::solve_with_memory()`] interface for reusing
/// this memory between runs.
pub struct SolverMemory {
    /// Inner heap allocation which holds the actual solver memory
    heap: Box<SolverMemoryInner>,
}

impl SolverMemory {
    /// Size of the solver memory region, in bytes
    pub const SIZE: usize = std::mem::size_of::<SolverMemoryInner>();

    /// New uninitialized memory, usable as solver temporary space.
    pub fn new() -> Self {
        Self {
            heap: SolverMemoryInner::alloc(),
        }
    }
}

impl Default for SolverMemory {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod test {
    #[test]
    fn solver_memory_size() {
        // Regression test for memory usage. Our actual memory size is very
        // similar to the original C implementation, the only difference that
        // our bucket counters are stored outside this structure.
        let size = super::SolverMemory::SIZE;
        assert_eq!(size, 1_895_424);
    }
}
