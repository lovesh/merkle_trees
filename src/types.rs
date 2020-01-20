use arrayvec::ArrayVec;
use num_bigint::BigUint;
use num_traits::identities::Zero;

/// Type for indexing leaves of a sparse merkle tree
pub trait LeafIndex {
    /// Path from root to leaf
    // TODO: Return type can be arrayvec?
    fn to_leaf_path(&self, arity: u8, tree_depth: usize) -> Vec<u8>;
}

/// When sparse merkle tree can have 2^64 leaves at max
impl LeafIndex for u64 {
    /// Returns the representation of the `u64` as a byte array in MSB form
    fn to_leaf_path(&self, arity: u8, tree_depth: usize) -> Vec<u8> {
        assert!(arity.is_power_of_two());
        let shift = (arity as f32).log2() as u64;
        let arity_minus_1 = (arity - 1) as u64;
        let mut path = vec![];
        let mut leaf_index = self.clone();
        while (path.len() != tree_depth) && (leaf_index != 0) {
            // Get last `shift` bytes
            path.push((leaf_index & arity_minus_1) as u8);
            // Remove last `shift` bytes
            leaf_index >>= shift;
        }

        while path.len() != tree_depth {
            path.push(0);
        }

        path.reverse();
        path
    }
}

/// When sparse merkle tree can have arbitrary number (usually > 2^128) of leaves
impl LeafIndex for BigUint {
    /// Returns the representation of the `BigUint` as a byte array in MSB form
    fn to_leaf_path(&self, arity: u8, tree_depth: usize) -> Vec<u8> {
        assert!(arity.is_power_of_two());
        let mut path = vec![];
        for d in self.to_radix_le(arity as u32) {
            if path.len() >= tree_depth {
                break;
            }
            path.push(d);
        }

        while path.len() != tree_depth {
            path.push(0);
        }

        path.reverse();
        path
    }
}

#[allow(non_snake_case)]
#[cfg(test)]
mod tests {
    use super::*;
    extern crate rand;
    use self::rand::{thread_rng, Rng};

    macro_rules! check_path_for_u64 {
        ( $idx:expr, $arity: tt, $depth: tt, $path: expr ) => {{
            assert_eq!($idx.to_leaf_path($arity, $depth), $path);
            let i = BigUint::from($idx);
            assert_eq!(i.to_leaf_path($arity, $depth), $path);
        }};
    }
    #[test]
    fn test_leaf_path() {
        // Test some hardcoded values for both u64 and BigUint
        let idx = 2u64;
        check_path_for_u64!(idx, 2, 2, vec![1, 0]);
        check_path_for_u64!(idx, 2, 3, vec![0, 1, 0]);

        let idx = 3u64;
        check_path_for_u64!(idx, 2, 2, vec![1, 1]);
        check_path_for_u64!(idx, 2, 3, vec![0, 1, 1]);

        let idx = 8u64;
        check_path_for_u64!(idx, 2, 2, vec![0, 0]);
        check_path_for_u64!(idx, 2, 3, vec![0, 0, 0]);
        check_path_for_u64!(idx, 2, 4, vec![1, 0, 0, 0]);

        let idx = 15u64;
        check_path_for_u64!(idx, 2, 2, vec![1, 1]);
        check_path_for_u64!(idx, 2, 3, vec![1, 1, 1]);
        check_path_for_u64!(idx, 2, 4, vec![1, 1, 1, 1]);
        check_path_for_u64!(idx, 2, 5, vec![0, 1, 1, 1, 1]);

        let idx = 108u64;
        check_path_for_u64!(idx, 2, 6, vec![1, 0, 1, 1, 0, 0]);
        check_path_for_u64!(idx, 2, 7, vec![1, 1, 0, 1, 1, 0, 0]);
        check_path_for_u64!(idx, 2, 8, vec![0, 1, 1, 0, 1, 1, 0, 0]);
    }

    #[test]
    fn test_leaf_path_1() {
        // Test some hardcoded values for u64
        for idx in vec![10503u64, 21522u64, 598162u64] {
            let p1 = idx.to_leaf_path(16, 30);
            assert_eq!(p1.len(), 30);
            assert!(p1.iter().all(|&x| x < 16));

            let p2 = idx.to_leaf_path(32, 30);
            assert_eq!(p2.len(), 30);
            assert!(p2.iter().all(|&x| x < 32));

            let p3 = idx.to_leaf_path(64, 30);
            assert_eq!(p3.len(), 30);
            assert!(p3.iter().all(|&x| x < 64));
        }
    }

    #[test]
    fn test_equivalence_of_u64_and_BigUint() {
        let test_cases = 100;
        let mut rng = thread_rng();
        for _ in 0..test_cases {
            let i = rng.gen_range(0, std::u64::MAX);
            let depth = rng.gen_range(2, 60);
            let p1 = i.to_leaf_path(2, depth);
            let p2 = BigUint::from(i).to_leaf_path(2, depth);
            assert_eq!(p1, p2);

            let p1 = i.to_leaf_path(4, depth);
            let p2 = BigUint::from(i).to_leaf_path(4, depth);
            assert_eq!(p1, p2);
        }
    }
}
