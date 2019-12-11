use db::HashValueDb;
use errors::MerkleTreeError;
use hasher::Arity2Hasher;
use std::marker::PhantomData;
use types::LeafIndex;

// Following idea described here https://ethresear.ch/t/optimizing-sparse-merkle-trees/3751

#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum NodeType<H> {
    Path(Vec<u8>),
    SubtreeHash(H),
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct BinarySparseMerkleTree<D: Clone, H: Clone, MTH>
where
    MTH: Arity2Hasher<D, H>,
{
    pub depth: usize,
    pub root: H,
    pub hasher: MTH,
    /// `empty_tree_hashes` contains the hashes of empty subtrees at each level.
    /// The 1st element is the root hash when all subtrees are empty and last element is the hash
    /// of the empty leaf
    pub empty_subtree_hashes: Vec<H>,
    pub phantom: PhantomData<D>,
}

impl<D: Clone, H: Clone + PartialEq, MTH> BinarySparseMerkleTree<D, H, MTH>
where
    MTH: Arity2Hasher<D, H>,
{
    pub fn new(
        empty_leaf_val: D,
        hasher: MTH,
        depth: usize,
    ) -> Result<BinarySparseMerkleTree<D, H, MTH>, MerkleTreeError> {
        assert!(depth > 0);
        let mut cur_hash = hasher.hash_leaf_data(empty_leaf_val)?;
        let mut empty_subtree_hashes = vec![];
        empty_subtree_hashes.insert(0, cur_hash);
        for i in 0..depth {
            cur_hash = hasher.hash_tree_nodes(
                empty_subtree_hashes[i].clone(),
                empty_subtree_hashes[i].clone(),
            )?;
            empty_subtree_hashes.insert(0, cur_hash.clone());
        }
        Ok(BinarySparseMerkleTree {
            depth,
            root: empty_subtree_hashes[0].clone(),
            hasher,
            empty_subtree_hashes,
            phantom: PhantomData,
        })
    }

    pub fn update(
        &mut self,
        idx: &dyn LeafIndex,
        val: D,
        hash_db: &mut dyn HashValueDb<H, (NodeType<H>, H)>,
    ) -> Result<(), MerkleTreeError> {
        let path = idx.to_leaf_path(2, self.depth);
        let hash = self.hasher.hash_leaf_data(val)?;
        let new_root = self._update(path, hash, self.root.clone(), 0, hash_db)?;
        self.root = new_root;
        Ok(())
    }

    pub fn get(
        &self,
        idx: &dyn LeafIndex,
        proof: &mut Option<Vec<(NodeType<H>, H)>>,
        hash_db: &dyn HashValueDb<H, (NodeType<H>, H)>,
    ) -> Result<H, MerkleTreeError> {
        let mut path = idx.to_leaf_path(2, self.depth);
        let mut cur_node = self.root.clone();

        let need_proof = proof.is_some();
        let mut proof_vec = Vec::<(NodeType<H>, H)>::new();

        for i in 0..self.depth {
            if cur_node == self.empty_subtree_hashes[i] {
                // Subtree under `cur_node` is empty, so return hash of the empty leaf which is
                // the last element of `empty_subtree_hashes`
                cur_node = self.empty_subtree_hashes[self.depth].clone();
                break;
            }

            let children = hash_db.get(&cur_node)?;
            if need_proof {
                proof_vec.push(children.clone());
            }

            let (left_child, right_child) = children;
            match left_child {
                NodeType::Path(right_child_path) => {
                    if path == right_child_path {
                        cur_node = right_child;
                        break;
                    } else {
                        // No non empty leaf in the tree with this `path`, so return hash of the
                        // empty leaf which is the last element of `empty_subtree_hashes`
                        cur_node = self.empty_subtree_hashes[self.depth].clone();
                        break;
                    }
                }
                NodeType::SubtreeHash(left_subtree_hash) => {
                    if path[0] == 1 {
                        // Check right subtree
                        cur_node = right_child;
                    } else {
                        // Check left subtree
                        cur_node = left_subtree_hash;
                    }
                }
            }

            path.remove(0);
        }

        match proof {
            Some(v) => {
                v.append(&mut proof_vec);
            }
            None => (),
        }

        Ok(cur_node)
    }

    pub fn verify_proof(
        &self,
        idx: &dyn LeafIndex,
        val: D,
        proof: Vec<(NodeType<H>, H)>,
    ) -> Result<bool, MerkleTreeError> {
        if self.root == self.empty_subtree_hashes[0] {
            return Ok(proof.len() == 0);
        }

        let leaf_hash = self.hasher.hash_leaf_data(val)?;
        let mut path = idx.to_leaf_path(2, self.depth);
        let proof_len = proof.len();

        let mut subtree_root_hash = self.root.clone();

        for (left_child, right_child) in proof {
            match left_child {
                NodeType::Path(right_child_path) => {
                    if path == right_child_path {
                        return Ok(right_child == leaf_hash);
                    } else {
                        // No non empty leaf with this path, the leaf hash should be the hash of the empty leaf
                        return Ok(self.empty_subtree_hashes[0] == leaf_hash);
                    }
                }
                NodeType::SubtreeHash(left_subtree_hash) => {
                    let expected_hash = self
                        .hasher
                        .hash_tree_nodes(left_subtree_hash.clone(), right_child.clone())?;
                    if expected_hash != subtree_root_hash {
                        return Ok(false);
                    }

                    if path[0] == 1 {
                        // Check right subtree
                        subtree_root_hash = right_child
                    } else {
                        // Check left subtree
                        subtree_root_hash = left_subtree_hash;
                    }
                }
            }
            path.remove(0);
        }

        if proof_len == self.depth {
            Ok(subtree_root_hash == leaf_hash)
        } else {
            Ok(self.empty_subtree_hashes[0] == leaf_hash)
        }
    }

    fn _update(
        &mut self,
        mut path: Vec<u8>,
        val: H,
        root: H,
        depth: usize,
        hash_db: &mut dyn HashValueDb<H, (NodeType<H>, H)>,
    ) -> Result<H, MerkleTreeError> {
        if depth == self.depth {
            return Ok(val);
        }
        if root == self.empty_subtree_hashes[depth] {
            // Update an empty subtree: make a single-val subtree
            let new_root = self.update_empty_subtree(path.clone(), val.clone(), depth)?;
            hash_db.put(new_root.clone(), (NodeType::Path(path), val))?;
            Ok(new_root)
        } else {
            let (left_child, right_child) = hash_db.get(&root)?;
            match left_child {
                NodeType::Path(right_child_path) => self.update_one_val_subtree(
                    path,
                    val,
                    right_child_path,
                    right_child,
                    depth,
                    hash_db,
                ),
                NodeType::SubtreeHash(left_subtree_hash) => {
                    if path[0] == 1 {
                        // New value lies in right subtree so update right subtree
                        path.remove(0);
                        let new_right = self._update(path, val, right_child, depth + 1, hash_db)?;
                        let root = self
                            .hasher
                            .hash_tree_nodes(left_subtree_hash.clone(), new_right.clone())?;
                        hash_db.put(
                            root.clone(),
                            (NodeType::SubtreeHash(left_subtree_hash), new_right),
                        )?;
                        Ok(root)
                    } else {
                        // New value lies in left subtree so update left subtree
                        path.remove(0);
                        let new_left =
                            self._update(path, val, left_subtree_hash, depth + 1, hash_db)?;
                        let root = self
                            .hasher
                            .hash_tree_nodes(new_left.clone(), right_child.clone())?;
                        hash_db
                            .put(root.clone(), (NodeType::SubtreeHash(new_left), right_child))?;
                        Ok(root)
                    }
                }
            }
        }
    }

    /// Update subtree with 1 non-empty leaf, result will be creation of 2 subtrees, each with 1
    /// non-empty leaf unless the same non empty leaf is being updated. Save intermediate nodes in the DB
    fn update_one_val_subtree(
        &mut self,
        mut path_for_new_key: Vec<u8>,
        val_for_new_key: H,
        mut path_for_old_key: Vec<u8>,
        val_for_old_key: H,
        depth: usize,
        hash_db: &mut dyn HashValueDb<H, (NodeType<H>, H)>,
    ) -> Result<H, MerkleTreeError> {
        if path_for_new_key == path_for_old_key {
            // The path being updated is same as the existing path, this is the case of updating value
            // of an existing key so the resulting subtree has size a single non empty leaf.
            let new_root = self.update_empty_subtree(
                path_for_new_key.clone(),
                val_for_new_key.clone(),
                depth,
            )?;
            hash_db.put(
                new_root.clone(),
                (NodeType::Path(path_for_new_key), val_for_new_key),
            )?;
            return Ok(new_root);
        }
        let (left, right) = {
            if path_for_new_key[0] == 1 {
                // MSB is set, new value lies in right subtree
                if path_for_old_key[0] == 1 {
                    // Existing value is in right subtree, hence left subtree is empty
                    path_for_new_key.remove(0);
                    path_for_old_key.remove(0);
                    (
                        self.empty_subtree_hashes[depth + 1].clone(),
                        self.update_one_val_subtree(
                            path_for_new_key,
                            val_for_new_key,
                            path_for_old_key,
                            val_for_old_key,
                            depth + 1,
                            hash_db,
                        )?,
                    )
                } else {
                    // Existing value is in left subtree, create 2 subtrees with 1 value each
                    path_for_new_key.remove(0);
                    path_for_old_key.remove(0);
                    let left_subtree_hash = self.update_empty_subtree(
                        path_for_old_key.clone(),
                        val_for_old_key.clone(),
                        depth + 1,
                    )?;
                    let right_subtree_hash = self.update_empty_subtree(
                        path_for_new_key.clone(),
                        val_for_new_key.clone(),
                        depth + 1,
                    )?;
                    hash_db.put(
                        left_subtree_hash.clone(),
                        (NodeType::Path(path_for_old_key), val_for_old_key),
                    )?;
                    hash_db.put(
                        right_subtree_hash.clone(),
                        (NodeType::Path(path_for_new_key), val_for_new_key),
                    )?;
                    (left_subtree_hash, right_subtree_hash)
                }
            } else {
                // MSB is unset, new value lies in left subtree
                if path_for_old_key[0] == 1 {
                    // Existing value is in right subtree, create 2 subtrees with 1 value each
                    path_for_new_key.remove(0);
                    path_for_old_key.remove(0);
                    let left_subtree_hash = self.update_empty_subtree(
                        path_for_new_key.clone(),
                        val_for_new_key.clone(),
                        depth + 1,
                    )?;
                    let right_subtree_hash = self.update_empty_subtree(
                        path_for_old_key.clone(),
                        val_for_old_key.clone(),
                        depth + 1,
                    )?;
                    hash_db.put(
                        right_subtree_hash.clone(),
                        (NodeType::Path(path_for_old_key), val_for_old_key),
                    )?;
                    hash_db.put(
                        left_subtree_hash.clone(),
                        (NodeType::Path(path_for_new_key), val_for_new_key),
                    )?;
                    (left_subtree_hash, right_subtree_hash)
                } else {
                    // Existing value is in left subtree, hence right subtree is empty
                    path_for_new_key.remove(0);
                    path_for_old_key.remove(0);
                    (
                        self.update_one_val_subtree(
                            path_for_new_key,
                            val_for_new_key,
                            path_for_old_key,
                            val_for_old_key,
                            depth + 1,
                            hash_db,
                        )?,
                        self.empty_subtree_hashes[depth + 1].clone(),
                    )
                }
            }
        };
        let root = self.hasher.hash_tree_nodes(left.clone(), right.clone())?;
        hash_db.put(root.clone(), (NodeType::SubtreeHash(left), right))?;
        Ok(root)
    }

    /// Make a root hash of a (sub)tree with a single key/value pair from empty tree
    fn update_empty_subtree(
        &self,
        mut path: Vec<u8>,
        val: H,
        depth: usize,
    ) -> Result<H, MerkleTreeError> {
        if depth == self.depth {
            return Ok(val);
        }

        let (l, r) = {
            if path[0] == 1 {
                // MSB is set, descend in right subtree and hash the result with empty left subtree
                path.remove(0);
                (
                    self.empty_subtree_hashes[depth + 1].clone(),
                    self.update_empty_subtree(path, val, depth + 1)?,
                )
            } else {
                // MSB is unset, descend in left subtree and hash the result with empty right subtree
                path.remove(0);
                (
                    self.update_empty_subtree(path, val, depth + 1)?,
                    self.empty_subtree_hashes[depth + 1].clone(),
                )
            }
        };
        self.hasher.hash_tree_nodes(l, r)
    }
}

#[allow(non_snake_case)]
#[cfg(test)]
mod tests {
    use super::*;
    use crate::sha2::Sha256;
    extern crate mimc_rs;
    extern crate rand;
    use self::rand::{thread_rng, Rng};

    use db::{InMemoryBigUintHashDb, InMemoryHashValueDb};
    use hasher::mimc_hash::MiMCHasher;
    use hasher::Sha256Hasher;
    use num_bigint::{BigUint, RandBigInt};
    use num_traits::Pow;
    use std::collections::HashSet;

    #[test]
    fn test_binary_tree_sha256_string_repeat_vals() {
        let mut db = InMemoryHashValueDb::<(NodeType<Vec<u8>>, Vec<u8>)>::new();
        let tree_depth = 3;
        let max_leaves = 2u64.pow(tree_depth as u32);
        // Choice of `empty_leaf_val` is arbitrary
        let empty_leaf_val = "";
        let hasher = Sha256Hasher {
            leaf_data_domain_separator: 0,
            node_domain_separator: 1,
        };

        let mut tree =
            BinarySparseMerkleTree::new(empty_leaf_val.clone(), hasher.clone(), tree_depth)
                .unwrap();

        let empty_leaf_hash = Arity2Hasher::hash_leaf_data(&hasher, empty_leaf_val).unwrap();
        for i in 0..max_leaves {
            assert_eq!(tree.get(&i, &mut None, &db).unwrap(), empty_leaf_hash);
        }

        let mut data = vec![];
        for i in 0..max_leaves {
            let val = [String::from("val_"), i.to_string()].concat();
            let hash = Arity2Hasher::hash_leaf_data(&hasher, &val).unwrap();
            data.push((i, val, hash));
        }

        tree.update(&data[0].0, &data[0].1, &mut db).unwrap();
        // Update subtree with 1 value
        tree.update(&data[0].0, &data[1].1, &mut db).unwrap();
        assert_eq!(tree.get(&0, &mut None, &db).unwrap(), data[1].2);

        tree.update(&data[2].0, &data[2].1, &mut db).unwrap();
        // Update subtree with 1 value
        tree.update(&data[0].0, &data[3].1, &mut db).unwrap();
        assert_eq!(tree.get(&0, &mut None, &db).unwrap(), data[3].2);
    }

    #[test]
    fn test_binary_tree_sha256_string() {
        let mut db = InMemoryHashValueDb::<(NodeType<Vec<u8>>, Vec<u8>)>::new();
        let tree_depth = 10;
        let max_leaves = 2u64.pow(tree_depth as u32);
        let empty_leaf_val = "";
        let hasher = Sha256Hasher {
            leaf_data_domain_separator: 0,
            node_domain_separator: 1,
        };

        let mut tree =
            BinarySparseMerkleTree::new(empty_leaf_val.clone(), hasher.clone(), tree_depth)
                .unwrap();

        let empty_leaf_hash = Arity2Hasher::hash_leaf_data(&hasher, empty_leaf_val).unwrap();
        for i in 0..max_leaves {
            assert_eq!(tree.get(&i, &mut None, &db).unwrap(), empty_leaf_hash);
        }

        let test_cases = 300;
        let mut rng = thread_rng();
        let mut data = vec![];
        let mut set = HashSet::new();
        while data.len() < test_cases {
            let i: u64 = rng.gen_range(0, max_leaves);
            if set.contains(&i) {
                continue;
            } else {
                set.insert(i);
            }
            let val = [String::from("val_"), i.to_string()].concat();
            let hash = Arity2Hasher::hash_leaf_data(&hasher, &val).unwrap();
            data.push((i, val, hash));
        }

        for i in 0..test_cases {
            let idx = &data[i as usize].0;
            tree.update(idx, &data[i as usize].1, &mut db).unwrap();

            let mut proof_vec = Vec::<(NodeType<Vec<u8>>, Vec<u8>)>::new();
            let mut proof = Some(proof_vec);
            assert_eq!(tree.get(idx, &mut proof, &db).unwrap(), data[i as usize].2);

            proof_vec = proof.unwrap();
            assert!(tree
                .verify_proof(idx, &data[i as usize].1, proof_vec.clone())
                .unwrap());
        }

        for i in 0..test_cases {
            let idx = &data[i as usize].0;
            assert_eq!(tree.get(idx, &mut None, &db).unwrap(), data[i as usize].2);
        }
    }

    #[test]
    fn test_binary_tree_sha256_string_repeated() {
        let mut db = InMemoryHashValueDb::<(NodeType<Vec<u8>>, Vec<u8>)>::new();
        let tree_depth = 10;
        let max_leaves = 2u64.pow(tree_depth as u32);
        let empty_leaf_val = "";
        let hasher = Sha256Hasher {
            leaf_data_domain_separator: 0,
            node_domain_separator: 1,
        };

        let mut tree =
            BinarySparseMerkleTree::new(empty_leaf_val.clone(), hasher.clone(), tree_depth)
                .unwrap();

        let empty_leaf_hash = Arity2Hasher::hash_leaf_data(&hasher, empty_leaf_val).unwrap();
        for i in 0..max_leaves {
            assert_eq!(tree.get(&i, &mut None, &db).unwrap(), empty_leaf_hash);
        }

        let test_cases = 300;
        let mut rng = thread_rng();
        let mut data = vec![];

        for _ in 0..test_cases {
            let i: u64 = rng.gen_range(0, max_leaves);
            let val = [String::from("val_"), i.to_string()].concat();
            let hash = Arity2Hasher::hash_leaf_data(&hasher, &val).unwrap();
            data.push((i, val, hash));
        }

        for i in 0..test_cases {
            let idx = &data[i as usize].0;
            tree.update(idx, &data[i as usize].1, &mut db).unwrap();

            let mut proof_vec = Vec::<(NodeType<Vec<u8>>, Vec<u8>)>::new();
            let mut proof = Some(proof_vec);
            assert_eq!(tree.get(idx, &mut proof, &db).unwrap(), data[i as usize].2);

            proof_vec = proof.unwrap();
            assert!(tree
                .verify_proof(idx, &data[i as usize].1, proof_vec.clone())
                .unwrap());
        }

        for i in 0..test_cases {
            let idx = &data[i as usize].0;
            assert_eq!(tree.get(idx, &mut None, &db).unwrap(), data[i as usize].2);
        }
    }

    #[test]
    fn test_binary_tree_sha256_string_BigUint_index() {
        let mut db = InMemoryHashValueDb::<(NodeType<Vec<u8>>, Vec<u8>)>::new();
        let tree_depth = 100;
        let empty_leaf_val = "";
        let hasher = Sha256Hasher {
            leaf_data_domain_separator: 0,
            node_domain_separator: 1,
        };

        let mut tree =
            BinarySparseMerkleTree::new(empty_leaf_val.clone(), hasher.clone(), tree_depth)
                .unwrap();

        let mut data = vec![];
        let test_cases = 1000;
        let mut rng = thread_rng();
        let mut set = HashSet::new();

        while data.len() < test_cases {
            let i: BigUint = rng.gen_biguint(160);
            if set.contains(&i) {
                continue;
            } else {
                set.insert(i.clone());
            }
            let val = [String::from("val_"), i.clone().to_string()].concat();
            let hash = Arity2Hasher::hash_leaf_data(&hasher, &val).unwrap();
            data.push((i.clone(), val, hash));
        }

        for i in 0..test_cases {
            let idx = &data[i as usize].0;
            tree.update(idx, &data[i as usize].1, &mut db).unwrap();
            assert_eq!(tree.get(idx, &mut None, &db).unwrap(), data[i as usize].2);

            let mut proof_vec = Vec::<(NodeType<Vec<u8>>, Vec<u8>)>::new();
            let mut proof = Some(proof_vec);
            assert_eq!(tree.get(idx, &mut proof, &db).unwrap(), data[i as usize].2);

            proof_vec = proof.unwrap();
            assert!(tree
                .verify_proof(idx, &data[i as usize].1, proof_vec.clone())
                .unwrap());
        }
    }

    #[test]
    fn test_binary_tree_mimc_BigUint() {
        let mut db = InMemoryBigUintHashDb::<(NodeType<BigUint>, BigUint)>::new();
        let tree_depth = 10;
        let empty_leaf_val = BigUint::from(0u64);
        let hasher = MiMCHasher::new(
            BigUint::from(1u64),
            BigUint::from(2u64),
            BigUint::from(3u64),
        );
        let mut tree =
            BinarySparseMerkleTree::new(empty_leaf_val.clone(), hasher.clone(), tree_depth)
                .unwrap();

        let mut data = vec![];
        let test_cases = 100;
        let mut rng = thread_rng();
        let mut set = HashSet::new();

        while data.len() < test_cases {
            let i: BigUint = rng.gen_biguint(160);
            if set.contains(&i) {
                continue;
            } else {
                set.insert(i.clone());
            }
            let val: BigUint = rng.gen_biguint(200);
            let hash = Arity2Hasher::hash_leaf_data(&hasher, val.clone()).unwrap();
            data.push((i.clone(), val, hash));
        }

        for i in 0..test_cases {
            let idx = &data[i as usize].0;
            tree.update(idx, data[i as usize].1.clone(), &mut db)
                .unwrap();
            assert_eq!(tree.get(idx, &mut None, &db).unwrap(), data[i as usize].2);

            let mut proof_vec = Vec::<(NodeType<BigUint>, BigUint)>::new();
            let mut proof = Some(proof_vec);
            assert_eq!(tree.get(idx, &mut proof, &db).unwrap(), data[i as usize].2);

            proof_vec = proof.unwrap();
            assert!(tree
                .verify_proof(idx, data[i as usize].1.clone(), proof_vec.clone())
                .unwrap());
        }
    }
}
