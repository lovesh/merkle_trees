use crate::errors::MerkleTreeError;
use crate::sha2::{Digest, Sha256};

/// To be used with a binary tree
/// `D` is the type of data the leaf has, like a string or a big number, etc.
/// `H` is the type for the hash
pub trait Arity2Hasher<D, H> {
    /// Hash the given leaf data to get the leaf hash
    fn hash_leaf_data(&self, leaf: D) -> Result<H, MerkleTreeError>;

    /// Hash 2 adjacent nodes (leaves or inner nodes) to get their root hash
    fn hash_tree_nodes(&self, left_node: H, right_node: H) -> Result<H, MerkleTreeError>;
}

/// To be used with a 4-ary tree
/// `D` is the type of data the leaf has, like a string or a big number, etc.
/// `H` is the type for the hash
pub trait Arity4Hasher<D, H> {
    /// Hash the given leaf data to get the leaf hash
    fn hash_leaf_data(&self, leaf: D) -> Result<H, MerkleTreeError>;

    /// Hash 4 adjacent nodes (leaves or inner nodes) to get their root hash
    fn hash_tree_nodes(
        &self,
        node_0: H,
        node_1: H,
        node_2: H,
        node_3: H,
    ) -> Result<H, MerkleTreeError>;
}

/// When SHA-256 is used for hashing in a merkle tree. Since SHA-256 is used for hashing leaf data and
/// nodes, a domain separator is used to differentiate
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Sha256Hasher {
    pub leaf_data_domain_separator: u8,
    pub node_domain_separator: u8,
}

impl Sha256Hasher {
    pub fn hash_leaf<D: AsRef<[u8]>>(&self, leaf: D) -> Result<Vec<u8>, MerkleTreeError> {
        let mut hasher = Sha256::new();
        hasher.input(&[self.leaf_data_domain_separator]);
        hasher.input(leaf);
        Ok(hasher.result().to_vec())
    }
}

/// When SHA-256 is used for hashing in a binary merkle tree
impl Arity2Hasher<&str, Vec<u8>> for Sha256Hasher {
    fn hash_leaf_data(&self, leaf: &str) -> Result<Vec<u8>, MerkleTreeError> {
        self.hash_leaf(leaf)
    }

    fn hash_tree_nodes(
        &self,
        left_node: Vec<u8>,
        right_node: Vec<u8>,
    ) -> Result<Vec<u8>, MerkleTreeError> {
        let mut hasher = Sha256::new();
        hasher.input(&[self.node_domain_separator]);
        hasher.input(left_node);
        hasher.input(right_node);
        Ok(hasher.result().to_vec())
    }
}

/// When SHA-256 is used for hashing in a 4-merkle tree
impl Arity4Hasher<&str, Vec<u8>> for Sha256Hasher {
    fn hash_leaf_data(&self, leaf: &str) -> Result<Vec<u8>, MerkleTreeError> {
        self.hash_leaf(leaf)
    }

    fn hash_tree_nodes(
        &self,
        node_0: Vec<u8>,
        node_1: Vec<u8>,
        node_2: Vec<u8>,
        node_3: Vec<u8>,
    ) -> Result<Vec<u8>, MerkleTreeError> {
        let mut hasher = Sha256::new();
        hasher.input(&[self.node_domain_separator]);
        hasher.input(node_0);
        hasher.input(node_1);
        hasher.input(node_2);
        hasher.input(node_3);
        Ok(hasher.result().to_vec())
    }
}

#[cfg(test)]
pub mod mimc_hash {
    // This MiMC hash is only for demonstrating that merkle trees in this crate can be used with MiMC hasher.
    // In production, the hash implementation will be more sophisticated but the interface should not be different
    extern crate mimc_rs;
    use self::mimc_rs::Mimc7;
    use super::Arity2Hasher;
    use crate::errors::MerkleTreeError;
    use num_bigint::{BigInt, BigUint, ToBigInt};

    /// When MiMC is used for hashing in a merkle tree
    pub struct MiMCHasher {
        leaf_data_domain_separator: BigUint,
        node_domain_separator: BigUint,
        leaf_pad: BigUint,
        mimc_hash: Mimc7,
    }

    impl Clone for MiMCHasher {
        fn clone(&self) -> MiMCHasher {
            MiMCHasher::new(
                self.leaf_data_domain_separator.clone(),
                self.node_domain_separator.clone(),
                self.leaf_pad.clone(),
            )
        }
    }

    impl MiMCHasher {
        pub fn new(
            leaf_data_domain_separator: BigUint,
            node_domain_separator: BigUint,
            leaf_pad: BigUint,
        ) -> Self {
            Self {
                leaf_data_domain_separator,
                node_domain_separator,
                leaf_pad,
                mimc_hash: Mimc7::new(),
            }
        }
    }

    /// When MiMC is used for hashing in a binary merkle tree
    impl Arity2Hasher<BigUint, BigUint> for MiMCHasher {
        fn hash_leaf_data(&self, leaf: BigUint) -> Result<BigUint, MerkleTreeError> {
            // Leaf hash = leaf_data_domain_separator || leaf || leaf_pad
            let mut input = vec![];
            input.push(self.leaf_data_domain_separator.to_bigint().unwrap());
            input.push(leaf.to_bigint().unwrap());
            input.push(self.leaf_pad.to_bigint().unwrap());
            let r = self.mimc_hash.hash(input).unwrap();
            Ok(r.to_biguint().unwrap())
        }

        fn hash_tree_nodes(
            &self,
            left_node: BigUint,
            right_node: BigUint,
        ) -> Result<BigUint, MerkleTreeError> {
            let mut input = vec![];
            input.push(self.node_domain_separator.to_bigint().unwrap());
            input.push(left_node.to_bigint().unwrap());
            input.push(right_node.to_bigint().unwrap());
            let r = self.mimc_hash.hash(input).unwrap();
            Ok(r.to_biguint().unwrap())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::mimc_hash::MiMCHasher;
    use super::*;
    use num_bigint::BigUint;

    #[test]
    fn test_sha256_arity_2_hasher() {
        // Choice of domain separators is arbitrary
        let hasher = Sha256Hasher {
            leaf_data_domain_separator: 0,
            node_domain_separator: 1,
        };

        let left_leaf = Arity2Hasher::hash_leaf_data(&hasher, "hi").unwrap();
        let right_leaf = Arity2Hasher::hash_leaf_data(&hasher, "there").unwrap();
        Arity2Hasher::hash_tree_nodes(&hasher, left_leaf, right_leaf).unwrap();
    }

    #[test]
    fn test_sha256_arity_4_hasher() {
        // Choice of domain separators is arbitrary
        let hasher = Sha256Hasher {
            leaf_data_domain_separator: 0,
            node_domain_separator: 1,
        };

        let leaf_0 = Arity4Hasher::hash_leaf_data(&hasher, "hi").unwrap();
        let leaf_1 = Arity4Hasher::hash_leaf_data(&hasher, "there").unwrap();
        let leaf_2 = Arity4Hasher::hash_leaf_data(&hasher, "how").unwrap();
        let leaf_3 = Arity4Hasher::hash_leaf_data(&hasher, "are you").unwrap();
        Arity4Hasher::hash_tree_nodes(&hasher, leaf_0, leaf_1, leaf_2, leaf_3).unwrap();
    }

    #[test]
    fn test_mimc_arity_2_hasher() {
        // Choice of domain separators and pad is arbitrary
        let hasher = MiMCHasher::new(
            BigUint::from(0u64),
            BigUint::from(1u64),
            BigUint::from(2u64),
        );

        let left_leaf = Arity2Hasher::hash_leaf_data(&hasher, BigUint::from(100u64)).unwrap();
        let right_leaf = Arity2Hasher::hash_leaf_data(&hasher, BigUint::from(200u64)).unwrap();
        Arity2Hasher::hash_tree_nodes(&hasher, left_leaf, right_leaf).unwrap();
    }
}
