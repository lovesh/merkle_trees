use crate::db::HashValueDb;
use crate::errors::MerkleTreeError;
use crate::hasher::{Arity2Hasher, Arity4Hasher};
use crate::types::LeafIndex;
use std::marker::PhantomData;

// TODO: Have prehashed versions of the methods below that do not call `hash_leaf_data` but assume
// that leaf data being passed is already hashed.

/// The types `D`, `H` and `MTH` correspond to the types of data, hash and merkle tree hasher
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct VanillaBinarySparseMerkleTree<D: Clone, H: Clone, MTH>
where
    MTH: Arity2Hasher<D, H>,
{
    pub depth: usize,
    pub root: H,
    pub hasher: MTH,
    pub phantom: PhantomData<D>,
}

impl<D: Clone, H: Clone + PartialEq, MTH> VanillaBinarySparseMerkleTree<D, H, MTH>
where
    MTH: Arity2Hasher<D, H>,
{
    /// Create a new tree. `empty_leaf_val` is the default value for leaf of empty tree. It could be zero.
    /// Requires a database to hold leaves and nodes. The db should implement the `HashValueDb` trait
    pub fn new(
        empty_leaf_val: D,
        hasher: MTH,
        depth: usize,
        hash_db: &mut dyn HashValueDb<H, (H, H)>,
    ) -> Result<VanillaBinarySparseMerkleTree<D, H, MTH>, MerkleTreeError> {
        assert!(depth > 0);
        let mut cur_hash = hasher.hash_leaf_data(empty_leaf_val)?;
        for _ in 0..depth {
            let val = (cur_hash.clone(), cur_hash.clone());
            cur_hash = hasher.hash_tree_nodes(cur_hash.clone(), cur_hash.clone())?;
            hash_db.put(cur_hash.clone(), val)?;
        }
        Ok(Self {
            depth,
            root: cur_hash,
            hasher,
            phantom: PhantomData,
        })
    }

    /// Create a new tree with a given root hash
    pub fn initialize_with_root_hash(hasher: MTH, depth: usize, root: H) -> Self {
        Self {
            depth,
            root,
            hasher,
            phantom: PhantomData,
        }
    }

    /// Set the given `val` at the given leaf index `idx`
    pub fn update(
        &mut self,
        idx: &dyn LeafIndex,
        val: D,
        hash_db: &mut dyn HashValueDb<H, (H, H)>,
    ) -> Result<(), MerkleTreeError> {
        // Find path to insert the new key
        let mut siblings_wrap = Some(Vec::<H>::new());
        self.get(idx, &mut siblings_wrap, hash_db)?;
        let mut siblings = siblings_wrap.unwrap();

        let mut path = idx.to_leaf_path(2, self.depth);
        // Reverse since path was from root to leaf but i am going leaf to root
        path.reverse();
        let mut cur_hash = self.hasher.hash_leaf_data(val)?;

        // Iterate over the bits
        for d in path {
            let sibling = siblings.pop().unwrap();
            let (l, r) = if d == 0 {
                // leaf falls on the left side
                (cur_hash, sibling)
            } else {
                // leaf falls on the right side
                (sibling, cur_hash)
            };
            let val = (l.clone(), r.clone());
            cur_hash = self.hasher.hash_tree_nodes(l, r)?;
            hash_db.put(cur_hash.clone(), val)?;
        }

        self.root = cur_hash;

        Ok(())
    }

    /// Get value for a leaf. `proof` when not set to None will be set to the inclusion proof for that leaf.
    pub fn get(
        &self,
        idx: &dyn LeafIndex,
        proof: &mut Option<Vec<H>>,
        hash_db: &dyn HashValueDb<H, (H, H)>,
    ) -> Result<H, MerkleTreeError> {
        let path = idx.to_leaf_path(2, self.depth);
        let mut cur_node = &self.root;
        let need_proof = proof.is_some();
        let mut proof_vec = Vec::<H>::new();

        let mut children;
        for d in path {
            children = hash_db.get(cur_node)?;
            if d == 0 {
                // leaf falls on the left side
                cur_node = &children.0;
                if need_proof {
                    proof_vec.push(children.1);
                }
            } else {
                // leaf falls on the right side
                cur_node = &children.1;
                if need_proof {
                    proof_vec.push(children.0);
                }
            }
        }
        match proof {
            Some(v) => {
                v.append(&mut proof_vec);
            }
            None => (),
        }
        Ok(cur_node.clone())
    }

    /// Verify a leaf inclusion proof, if `root` is None, use the current root else use given root
    pub fn verify_proof(
        &self,
        idx: &dyn LeafIndex,
        val: D,
        proof: Vec<H>,
        root: Option<&H>,
    ) -> Result<bool, MerkleTreeError> {
        let mut path = idx.to_leaf_path(2, self.depth);
        if path.len() != proof.len() {
            return Ok(false);
        }
        path.reverse();

        let mut cur_hash = self.hasher.hash_leaf_data(val)?;

        for (i, sibling) in proof.into_iter().rev().enumerate() {
            let (l, r) = if path[i] == 0 {
                // leaf falls on the left side
                (cur_hash, sibling)
            } else {
                // leaf falls on the right side
                (sibling, cur_hash)
            };
            cur_hash = self.hasher.hash_tree_nodes(l, r)?;
        }

        // Check if root is equal to cur_hash
        match root {
            Some(r) => Ok(cur_hash == *r),
            None => Ok(cur_hash == self.root),
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct VanillaArity4SparseMerkleTree<D: Clone, H: Clone, MTH>
where
    MTH: Arity4Hasher<D, H>,
{
    pub depth: usize,
    pub root: H,
    hasher: MTH,
    phantom: PhantomData<D>,
}

impl<D: Clone, H: Clone + PartialEq + Default, MTH> VanillaArity4SparseMerkleTree<D, H, MTH>
where
    MTH: Arity4Hasher<D, H>,
{
    /// Create a new tree. `empty_leaf_val` is the default value for leaf of empty tree. It could be zero.
    /// Requires a database to hold leaves and nodes. The db should implement the `HashValueDb` trait
    pub fn new(
        empty_leaf_val: D,
        hasher: MTH,
        depth: usize,
        hash_db: &mut dyn HashValueDb<H, [H; 4]>,
    ) -> Result<VanillaArity4SparseMerkleTree<D, H, MTH>, MerkleTreeError> {
        assert!(depth > 0);
        let mut cur_hash = hasher.hash_leaf_data(empty_leaf_val)?;
        for _ in 0..depth {
            let val = [
                cur_hash.clone(),
                cur_hash.clone(),
                cur_hash.clone(),
                cur_hash.clone(),
            ];
            cur_hash = hasher.hash_tree_nodes(
                cur_hash.clone(),
                cur_hash.clone(),
                cur_hash.clone(),
                cur_hash.clone(),
            )?;
            hash_db.put(cur_hash.clone(), val)?;
        }
        Ok(Self {
            depth,
            root: cur_hash,
            hasher,
            phantom: PhantomData,
        })
    }

    /// Create a new tree with a given root hash
    pub fn initialize_with_root_hash(hasher: MTH, depth: usize, root: H) -> Self {
        Self {
            depth,
            root,
            hasher,
            phantom: PhantomData,
        }
    }

    /// Set the given `val` at the given leaf index `idx`
    pub fn update(
        &mut self,
        idx: &dyn LeafIndex,
        val: D,
        hash_db: &mut dyn HashValueDb<H, [H; 4]>,
    ) -> Result<(), MerkleTreeError> {
        // Find path to insert the new key
        let mut siblings_wrap = Some(Vec::<[H; 3]>::new());
        self.get(idx, &mut siblings_wrap, hash_db)?;
        let mut siblings = siblings_wrap.unwrap();

        let mut path = idx.to_leaf_path(4, self.depth);
        // Reverse since path was from root to leaf but i am going leaf to root
        path.reverse();
        let mut cur_hash = self.hasher.hash_leaf_data(val)?;

        // Iterate over the base 4 digits
        for d in path {
            let (n_0, n_1, n_2, n_3) =
                Self::extract_from_siblings(d, siblings.pop().unwrap(), cur_hash);
            let val = [n_0.clone(), n_1.clone(), n_2.clone(), n_3.clone()];
            cur_hash = self.hasher.hash_tree_nodes(n_0, n_1, n_2, n_3)?;
            hash_db.put(cur_hash.clone(), val)?;
        }

        self.root = cur_hash;

        Ok(())
    }

    /// Get value for a leaf. `proof` when not set to None will be set to the inclusion proof for that leaf.
    pub fn get(
        &self,
        idx: &dyn LeafIndex,
        proof: &mut Option<Vec<[H; 3]>>,
        hash_db: &dyn HashValueDb<H, [H; 4]>,
    ) -> Result<H, MerkleTreeError> {
        let path = idx.to_leaf_path(4, self.depth);
        let mut cur_node = &self.root;
        let need_proof = proof.is_some();
        let mut proof_vec = Vec::<[H; 3]>::new();

        let mut children;
        for d in path {
            children = hash_db.get(cur_node)?;
            cur_node = &children[d as usize];
            if need_proof {
                let mut proof_node: [H; 3] = [H::default(), H::default(), H::default()];
                let mut j = 0;
                // XXX: to_vec will lead to copying the slice, can it be prevented without using unsafe?
                for (i, c) in children.to_vec().into_iter().enumerate() {
                    if i != (d as usize) {
                        proof_node[j] = c;
                        j += 1;
                    }
                }
                proof_vec.push(proof_node);
            }
        }
        match proof {
            Some(v) => {
                v.append(&mut proof_vec);
            }
            None => (),
        }
        Ok(cur_node.clone())
    }

    /// Verify a merkle proof, if `root` is None, use the current root else use given root
    pub fn verify_proof(
        &self,
        idx: &dyn LeafIndex,
        val: D,
        proof: Vec<[H; 3]>,
        root: Option<&H>,
    ) -> Result<bool, MerkleTreeError> {
        let mut path = idx.to_leaf_path(4, self.depth);
        if path.len() != proof.len() {
            return Ok(false);
        }
        path.reverse();

        let mut cur_hash = self.hasher.hash_leaf_data(val)?;

        for (i, sibling) in proof.into_iter().rev().enumerate() {
            let (n_0, n_1, n_2, n_3) = Self::extract_from_siblings(path[i], sibling, cur_hash);
            cur_hash = self.hasher.hash_tree_nodes(n_0, n_1, n_2, n_3)?;
        }

        // Check if root is equal to cur_hash
        match root {
            Some(r) => Ok(cur_hash == *r),
            None => Ok(cur_hash == self.root),
        }
    }

    /// Destructure the sibling array and return the cur_hash and siblings in the correct order.
    /// `d` is the index of `cur_hash` in the returned array
    fn extract_from_siblings(d: u8, sibling: [H; 3], cur_hash: H) -> (H, H, H, H) {
        let [s_0, s_1, s_2] = sibling;
        if d == 0 {
            (cur_hash, s_0, s_1, s_2)
        } else if d == 1 {
            (s_0, cur_hash, s_1, s_2)
        } else if d == 2 {
            (s_0, s_1, cur_hash, s_2)
        } else {
            (s_0, s_1, s_2, cur_hash)
        }
    }
}

#[allow(non_snake_case)]
#[cfg(test)]
mod tests {
    use super::*;
    extern crate rand;
    use self::rand::{thread_rng, Rng};

    use crate::db::InMemoryHashValueDb;
    use crate::hasher::Sha256Hasher;
    use num_bigint::{BigUint, RandBigInt};
    use std::collections::HashSet;

    use crate::db::rusqlite_db;
    use crate::errors::MerkleTreeErrorKind;
    use std::fs;
    extern crate rusqlite;
    use rusqlite::{params, Connection, NO_PARAMS};

    fn check_binary_tree_update_get_and_proof<'a, T, I>(
        tree: &'a mut VanillaBinarySparseMerkleTree<&'a str, Vec<u8>, Sha256Hasher>,
        tree_depth: usize,
        hasher: Sha256Hasher,
        data: &'a Vec<(I, String, Vec<u8>)>,
        db: &mut T,
    ) where
        T: HashValueDb<Vec<u8>, (Vec<u8>, Vec<u8>)>,
    {
        for i in 0..(data.len() as u64) {
            // Update and check
            tree.update(&i, &data[i as usize].1, db).unwrap();

            let mut proof_vec = Vec::<Vec<u8>>::new();
            let mut proof = Some(proof_vec);
            assert_eq!(tree.get(&i, &mut proof, db).unwrap(), data[i as usize].2);

            proof_vec = proof.unwrap();

            let verifier_tree = VanillaBinarySparseMerkleTree::initialize_with_root_hash(
                hasher.clone(),
                tree_depth,
                tree.root.clone(),
            );
            assert!(verifier_tree
                .verify_proof(&i, &data[i as usize].1, proof_vec.clone(), None)
                .unwrap());
            assert!(verifier_tree
                .verify_proof(&i, &data[i as usize].1, proof_vec.clone(), Some(&tree.root))
                .unwrap());
        }

        for i in 0..(data.len() as u64) {
            // Check after all updates done
            let mut proof_vec = Vec::<Vec<u8>>::new();
            let mut proof = Some(proof_vec);
            assert_eq!(tree.get(&i, &mut proof, db).unwrap(), data[i as usize].2);

            proof_vec = proof.unwrap();

            let verifier_tree = VanillaBinarySparseMerkleTree::initialize_with_root_hash(
                hasher.clone(),
                tree_depth,
                tree.root.clone(),
            );
            assert!(verifier_tree
                .verify_proof(&i, &data[i as usize].1, proof_vec.clone(), None)
                .unwrap());
        }
    }

    fn check_binary_tree_create_update_get_and_proof<T>(
        tree_depth: usize,
        empty_leaf_val: &str,
        db: &mut T,
    ) where
        T: HashValueDb<Vec<u8>, (Vec<u8>, Vec<u8>)>,
    {
        let max_leaves = 2u64.pow(tree_depth as u32);
        let hasher = Sha256Hasher {
            leaf_data_domain_separator: 0,
            node_domain_separator: 1,
        };
        let mut tree = VanillaBinarySparseMerkleTree::new(
            empty_leaf_val.clone(),
            hasher.clone(),
            tree_depth,
            db,
        )
        .unwrap();

        let empty_leaf_hash = Arity2Hasher::hash_leaf_data(&hasher, empty_leaf_val).unwrap();
        for i in 0..max_leaves {
            assert_eq!(tree.get(&i, &mut None, db).unwrap(), empty_leaf_hash);
        }

        let mut data = vec![];
        for i in 0..max_leaves {
            let val = [String::from("val_"), i.to_string()].concat();
            let hash = Arity2Hasher::hash_leaf_data(&hasher, &val).unwrap();
            data.push((i, val, hash));
        }

        check_binary_tree_update_get_and_proof(&mut tree, tree_depth, hasher, &data, db);
    }

    #[test]
    fn test_vanilla_binary_sparse_tree_sha256_string() {
        let mut db = InMemoryHashValueDb::<(Vec<u8>, Vec<u8>)>::new();
        let tree_depth = 7;
        // Choice of `empty_leaf_val` is arbitrary
        let empty_leaf_val = "";

        check_binary_tree_create_update_get_and_proof(tree_depth, empty_leaf_val, &mut db)
    }

    #[test]
    fn test_vanilla_sparse_4_ary_tree_sha256_string() {
        let mut db = InMemoryHashValueDb::<[Vec<u8>; 4]>::new();
        let tree_depth = 5;
        let max_leaves = 4u64.pow(tree_depth as u32);
        let empty_leaf_val = "";
        let hasher = Sha256Hasher {
            leaf_data_domain_separator: 0,
            node_domain_separator: 1,
        };
        let mut tree = VanillaArity4SparseMerkleTree::new(
            empty_leaf_val.clone(),
            hasher.clone(),
            tree_depth,
            &mut db,
        )
        .unwrap();

        let empty_leaf_hash = Arity4Hasher::hash_leaf_data(&hasher, empty_leaf_val).unwrap();
        for i in 0..max_leaves {
            assert_eq!(tree.get(&i, &mut None, &db).unwrap(), empty_leaf_hash);
        }

        let mut data = vec![];
        for i in 0..max_leaves {
            let val = [String::from("val_"), i.to_string()].concat();
            let hash = Arity2Hasher::hash_leaf_data(&hasher, &val).unwrap();
            data.push((i, val, hash));
        }

        for i in 0..max_leaves {
            // Update and check
            tree.update(&i, &data[i as usize].1, &mut db).unwrap();

            let mut proof_vec = Vec::<[Vec<u8>; 3]>::new();
            let mut proof = Some(proof_vec);
            assert_eq!(tree.get(&i, &mut proof, &db).unwrap(), data[i as usize].2);

            proof_vec = proof.unwrap();

            let verifier_tree = VanillaArity4SparseMerkleTree::initialize_with_root_hash(
                hasher.clone(),
                tree_depth,
                tree.root.clone(),
            );
            assert!(verifier_tree
                .verify_proof(&i, &data[i as usize].1, proof_vec.clone(), None)
                .unwrap());
            assert!(verifier_tree
                .verify_proof(&i, &data[i as usize].1, proof_vec.clone(), Some(&tree.root))
                .unwrap());
        }

        for i in 0..max_leaves {
            // Check after all updates done
            assert_eq!(tree.get(&i, &mut None, &db).unwrap(), data[i as usize].2);
            let mut proof_vec = Vec::<[Vec<u8>; 3]>::new();
            let mut proof = Some(proof_vec);
            assert_eq!(tree.get(&i, &mut proof, &db).unwrap(), data[i as usize].2);
            proof_vec = proof.unwrap();

            let verifier_tree = VanillaArity4SparseMerkleTree::initialize_with_root_hash(
                hasher.clone(),
                tree_depth,
                tree.root.clone(),
            );
            assert!(verifier_tree
                .verify_proof(&i, &data[i as usize].1, proof_vec.clone(), None)
                .unwrap());
        }
    }

    #[test]
    fn test_vanilla_binary_sparse_tree_sha256_string_BigUint_index() {
        let mut db = InMemoryHashValueDb::<(Vec<u8>, Vec<u8>)>::new();
        let tree_depth = 65;
        let empty_leaf_val = "";
        let hasher = Sha256Hasher {
            leaf_data_domain_separator: 0,
            node_domain_separator: 1,
        };
        let mut tree = VanillaBinarySparseMerkleTree::new(
            empty_leaf_val.clone(),
            hasher.clone(),
            tree_depth,
            &mut db,
        )
        .unwrap();

        let mut data = vec![];
        let test_cases = 300;
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

        check_binary_tree_update_get_and_proof(&mut tree, tree_depth, hasher, &data, &mut db);
    }

    /// Testing implementation for using sqlite for storing tree data. No error handling. Purpose is
    /// to demonstrate how a persistent database can be used

    pub struct RusqliteSMTHashValueDb {
        db_path: String,
        pub table_name: String,
        pub db_conn: Connection,
    }

    impl RusqliteSMTHashValueDb {
        pub fn new(db_path: String, table_name: String) -> Self {
            let db_conn = Connection::open(&db_path).unwrap();
            let sql = format!("create table if not exists {} (key string primary key, value1 blob not null, value2 blob not null)", table_name);
            db_conn.execute(&sql, NO_PARAMS).unwrap();
            Self {
                db_path,
                table_name,
                db_conn,
            }
        }
    }

    impl HashValueDb<Vec<u8>, (Vec<u8>, Vec<u8>)> for RusqliteSMTHashValueDb {
        fn put(&mut self, hash: Vec<u8>, value: (Vec<u8>, Vec<u8>)) -> Result<(), MerkleTreeError> {
            let hash_hex = rusqlite_db::RusqliteHashValueDb::hash_to_hex(&hash);
            let sql = format!(
                "insert into {} (key, value1, value2) values (?1, ?2, ?3)",
                self.table_name
            );
            let (v1, v2) = value;
            // XXX: A real implementation will have error handling here
            self.db_conn
                .execute(&sql, params![hash_hex, v1, v2])
                .unwrap();
            Ok(())
        }

        fn get(&self, hash: &Vec<u8>) -> Result<(Vec<u8>, Vec<u8>), MerkleTreeError> {
            let sql = format!(
                "select value1, value2 from {} where key='{}'",
                self.table_name,
                rusqlite_db::RusqliteHashValueDb::hash_to_hex(hash)
            );
            // XXX: A real implementation will have error handling here
            self.db_conn
                .query_row(&sql, NO_PARAMS, |row| {
                    let v1 = row.get(0).unwrap();
                    let v2 = row.get(1).unwrap();
                    Ok((v1, v2))
                })
                .map_err(|_| {
                    MerkleTreeError::from_kind(MerkleTreeErrorKind::HashNotFoundInDB {
                        hash: hash.to_vec(),
                    })
                })
        }
    }

    #[test]
    fn test_binary_tree_sha256_hash_sqlite_db() {
        // Test demonstrating the use of sqlite db for tree data

        let db_path = "./rusqlite_tree.db";
        fs::remove_file(db_path);

        let mut db = RusqliteSMTHashValueDb::new(String::from(db_path), String::from("kv_table"));
        let tree_depth = 3;
        let empty_leaf_val = "";

        check_binary_tree_create_update_get_and_proof(tree_depth, empty_leaf_val, &mut db)
    }
}
