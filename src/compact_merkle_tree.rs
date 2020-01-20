use crate::errors::{MerkleTreeError, MerkleTreeErrorKind};
use crate::hasher::Arity2Hasher;
use std::marker::PhantomData;

// Code inspired from Google's certificate-transparency https://github.com/google/certificate-transparency/blob/master/python/ct/crypto/merkle.py
// , Evernym's enhancements and Google's trillian

// TODO: Make it changable by a feature
// Tree with size 2^64 should be good for most purposes.
type TreeSizeType = u64;

/// Returns the number of bits set in `n`
fn count_set_bits(mut n: TreeSizeType) -> u8 {
    // Brian Kernighan's was https://graphics.stanford.edu/~seander/bithacks.html#CountBitsSetKernighan
    let mut count = 0;
    while n != 0 {
        n &= n - 1;
        count += 1
    }
    count
}

/// Number of bits required to represent `n`
fn num_bits(mut n: TreeSizeType) -> u8 {
    if n == 0 {
        return 0;
    }
    let mut index = 0;
    while n != 0 {
        index += 1;
        n >>= 1;
    }
    index
}

/// Least significant bit set in `n`,
fn least_significant_set_bit(n: TreeSizeType) -> u8 {
    if n == 0 {
        return 0;
    }
    n.trailing_zeros() as u8
}

/// Largest power of 2 less than `n`, 2^k < n <= 2^{k+1}, return 2^k
fn largest_power_of_2_less_than(n: TreeSizeType) -> TreeSizeType {
    if n < 2 {
        return 0;
    }
    let mut cur = 1u64;
    let mut largest = 1u64;
    while cur < n {
        largest = cur;
        let r = cur.wrapping_shl(1);
        if r < cur {
            // `cur` has wrapped around
            break;
        } else {
            cur = r;
        }
    }
    largest
}

/// Break a number on decreasing powers of 2, eg 4 -> 4, 5 -> [4, 1], 6 -> [4, 2], 7 -> [4, 2, 1], 8 -> [8]
fn powers_of_2(mut n: TreeSizeType) -> Vec<TreeSizeType> {
    if n == 0 {
        return vec![];
    }
    let mut powers = vec![];
    loop {
        if n.is_power_of_two() {
            powers.push(n);
            break;
        } else {
            let p = largest_power_of_2_less_than(n);
            n = n - p;
            powers.push(p);
        }
    }
    powers
}

/// Interface for the database used to store the leaf and node hashes
pub trait HashDb<H> {
    /// The database stores all leaves
    fn add_leaf(&mut self, leaf_hash: H) -> Result<(), MerkleTreeError>;

    /// The database stores roots of all full subtrees of the datbase
    fn add_full_subtree_root(&mut self, node_hash: H) -> Result<(), MerkleTreeError>;

    fn get_leaf(&self, leaf_index: TreeSizeType) -> Result<H, MerkleTreeError>;

    fn get_full_subtree_root(&self, node_index: TreeSizeType) -> Result<H, MerkleTreeError>;
}

/// Uses an in-memory vectors for storing leaf and node hashes. Used for testing.
#[derive(Clone, Debug)]
pub struct InMemoryHashDb<H> {
    leaves: Vec<H>,
    nodes: Vec<H>,
}

impl<H: Clone> HashDb<H> for InMemoryHashDb<H> {
    fn add_leaf(&mut self, leaf_hash: H) -> Result<(), MerkleTreeError> {
        self.leaves.push(leaf_hash);
        Ok(())
    }

    fn add_full_subtree_root(&mut self, node_hash: H) -> Result<(), MerkleTreeError> {
        self.nodes.push(node_hash);
        Ok(())
    }

    fn get_leaf(&self, leaf_index: TreeSizeType) -> Result<H, MerkleTreeError> {
        let i = leaf_index as usize;
        if i >= self.leaves.len() {
            Err(MerkleTreeError::from_kind(
                MerkleTreeErrorKind::LeafIndexNotFoundInDB { index: i as u64 },
            ))
        } else {
            Ok(self.leaves[i].clone())
        }
    }

    fn get_full_subtree_root(&self, node_index: TreeSizeType) -> Result<H, MerkleTreeError> {
        let i = node_index as usize;
        if i >= self.nodes.len() {
            Err(MerkleTreeError::from_kind(
                MerkleTreeErrorKind::NodeIndexNotFoundInDB { index: i as u64 },
            ))
        } else {
            Ok(self.nodes[i].clone())
        }
    }
}

impl<H> InMemoryHashDb<H> {
    pub fn new() -> Self {
        Self {
            leaves: vec![],
            nodes: vec![],
        }
    }

    pub fn leaf_count(&self) -> TreeSizeType {
        self.leaves.len() as TreeSizeType
    }

    pub fn node_count(&self) -> TreeSizeType {
        self.nodes.len() as TreeSizeType
    }
}

/// Compact merkle tree can be seen as a list of trees. A leaf is added to a tree until its full (it has 2^k leaves)
/// Once a tree is full, start adding to a new tree until that is full. Once the current full tree has the same height
/// as the previous full tree, combine both full trees to form a new full tree such that the previous and current form
/// the left and right subtrees of the new full tree respectively. When the various trees don't form a full tree, they
/// can be seen as subtrees of a big n-ary tree. The root of this n-ary tree at any time is the hash of the
/// concatenated roots of all full trees. eg, if there are 4 leaves in total, the n-ary tree is a full binary tree. When
/// there are 5 leaves, the n-ary tree contains 2 subtrees of size 4 and 1. With 6 leaves, the n-ary tree contains 2
/// subtrees of size 4 and 2. With 7 leaves, the n-ary tree contains 3 subtrees of size 4, 3 and 1. With 8 leaves, the
/// the n-ary tree is a full binary tree of size 8. Lets say we want to insert a few leaves l_0, l_1, l_2,..l_n in
/// an empty tree. Inserting l_0 makes the tree full (with 2^0=1 leaf) with root T_0 so l_1 will be inserted
/// in a new tree with root T_1, making it full as well. Note that since roots T_0 and T_1 have only 1 element
/// so the root hash is same as the leaf hash, i.e. T_0 = hash(l_0) and T_1 = hash(l_1). Now we have 2 full
/// trees of same height (1 in this case) so we combine them to make a new full tree of height 1 more than
/// their height (new tree has height 2 in this case). The root of this new tree is T_2 and T_2 = hash(T_0, T_1).
/// Since T_2 is full, l_2 will be inserted into a new tree T_3 and T_3 = hash(l_2). Also, T_3 is full so l_3
/// will be inserted in a new tree with root T_4 and T_4 = hash(l_3). We again have 2 tree of same height (1 here)
/// T3, T_4 so we combine them to form a tree of bigger height and root T_5 = hash(T_3, T_4). Now we have 2 more
/// trees of same height, T_2 and T_5. We combine them to form a bigger full tree with root T_6 = hash(T_2, T_5).
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CompactMerkleTree<D: Clone, H: Clone, MTH>
where
    MTH: Arity2Hasher<D, H>,
{
    /// Number of leaves in the tree
    pub size: TreeSizeType,
    /// Contains root of all the full subtrees, from largest subtree to smallest
    pub full_subtree_roots: Vec<H>,
    pub hasher: MTH,
    pub phantom: PhantomData<D>,
}

impl<D: Clone, H: Clone + PartialEq, MTH> CompactMerkleTree<D, H, MTH>
where
    MTH: Arity2Hasher<D, H>,
{
    pub fn new(hasher: MTH) -> Self {
        Self {
            size: 0,
            full_subtree_roots: vec![],
            hasher,
            phantom: PhantomData,
        }
    }

    /// Takes a hash db and returns a new tree of the size `tree_size` based on the leaves and nodes
    /// present in hash db.
    pub fn new_from_hash_db(
        hasher: MTH,
        tree_size: TreeSizeType,
        hash_db: &dyn HashDb<H>,
    ) -> Result<Self, MerkleTreeError> {
        // The full subtree roots will form the inclusion path of the next leaf that will be inserted
        // making the new tree's size `tree_size+1`
        let mut full_subtree_roots = Self::get_leaf_inclusion_proof_for_tree_size(
            &hasher,
            tree_size,
            tree_size + 1,
            hash_db,
        )?;
        full_subtree_roots.reverse();

        let mut new_tree = Self::new(hasher);
        new_tree.size = tree_size;
        new_tree.full_subtree_roots = full_subtree_roots;
        Ok(new_tree)
    }

    /// Append a leaf and return the inclusion proof of the leaf, path goes from leaf to root
    pub fn append(
        &mut self,
        leaf_data: D,
        hash_db: &mut dyn HashDb<H>,
    ) -> Result<Vec<H>, MerkleTreeError> {
        // Inclusion proof (audit path in RFC 6982) of a leaf contains the nodes that when hashed
        // together with the leaf result in the root hash. Thus the inclusion proof would be the roots
        // of all the subtrees from larger to smaller trees.
        let mut inclusion_proof = self.full_subtree_roots.clone();
        // We need the path from smaller to larger.
        inclusion_proof.reverse();
        // A single leaf forms a full subtree with 2^0 = 1 leaf
        self.push_full_subtree(vec![leaf_data], hash_db)?;
        Ok(inclusion_proof)
    }

    /// Append multiple leaves
    pub fn extend(
        &mut self,
        mut leaves: Vec<D>,
        hash_db: &mut dyn HashDb<H>,
    ) -> Result<(), MerkleTreeError> {
        if leaves.is_empty() {
            return Err(MerkleTreeErrorKind::NoLeafProvided.into());
        }
        let mut num_leaves_remaining = leaves.len() as TreeSizeType;

        if self.size > 0 {
            // The existing tree is non empty
            loop {
                // Try to create full tree from leaves, of the same size as the smallest full subtree
                // of the current tree
                let max_leaves_to_insert = 1 << self.smallest_subtree_height() as TreeSizeType;
                if max_leaves_to_insert <= num_leaves_remaining {
                    let to_insert = leaves.drain(0..max_leaves_to_insert as usize).collect();
                    self.push_full_subtree(to_insert, hash_db)?;
                    num_leaves_remaining -= max_leaves_to_insert;
                } else {
                    // The leaves cannot form a full tree of the size of the smallest full subtree
                    // of the current tree
                    break;
                }
            }
        }

        if num_leaves_remaining > 0 {
            // No subtree exists in the current tree smaller or of same size as the number of remaining leaves so
            // create full trees from the remaining leaves and add store their roots.

            let (leaf_hashes, node_hashes) =
                Self::hash_leaves(&self.hasher, leaves.drain(0..).collect())?;

            // `full_subtree_roots` should contain the roots of the full subtrees
            let mut idx = 0;
            for p in powers_of_2(num_leaves_remaining) {
                // `p` would be the size of the full tree
                if p == 1 {
                    // Hash of the subtree of size 1 is the leaf hash in it
                    self.added_subtree(1, leaf_hashes[(num_leaves_remaining - 1) as usize].clone());
                } else {
                    // pick root from `node_hashes` by calculating the index of the root; the root
                    // of tree of size p will be at index p-1 since there are p-1 inner nodes in a tree
                    // of p leaves
                    idx += (p - 1);
                    self.added_subtree(p, node_hashes[(idx - 1) as usize].clone());
                }
            }

            for l in leaf_hashes {
                hash_db.add_leaf(l)?;
            }
            for n in node_hashes {
                hash_db.add_full_subtree_root(n)?;
            }
        }
        Ok(())
    }

    pub fn get_root_hash(&self) -> Result<H, MerkleTreeError> {
        if self.size == 0 {
            return Err(MerkleTreeErrorKind::CannotQueryEmptyTree.into());
        }
        // Hash the roots of subtrees, starting from the root of the lower subtree.
        // In case of a single subtree (a full tree), the root of the subtree will be the root of
        // the full tree
        let mut cur_root = self.full_subtree_roots[self.full_subtree_roots.len() - 1].clone();
        for i in (0..self.full_subtree_roots.len() - 1).rev() {
            cur_root = self
                .hasher
                .hash_tree_nodes(self.full_subtree_roots[i].clone(), cur_root)?;
        }
        Ok(cur_root)
    }

    /// Get a proof that the leaf at index `leaf_index` is present in the current tree. Called `audit path` in RFC 6982
    pub fn get_leaf_inclusion_proof(
        &self,
        leaf_index: TreeSizeType,
        hash_db: &dyn HashDb<H>,
    ) -> Result<Vec<H>, MerkleTreeError> {
        Self::get_leaf_inclusion_proof_for_tree_size(&self.hasher, leaf_index, self.size, hash_db)
    }

    /// Get a proof that the leaf at index `leaf_index` is present in the tree of size `tree_size`. Called `audit path` in RFC 6982
    pub fn get_leaf_inclusion_proof_for_tree_size(
        hasher: &MTH,
        leaf_index: TreeSizeType,
        tree_size: TreeSizeType,
        hash_db: &dyn HashDb<H>,
    ) -> Result<Vec<H>, MerkleTreeError> {
        if leaf_index >= tree_size {
            return Err(MerkleTreeErrorKind::TreeSmallerThanExpected {
                expected: leaf_index + 1,
                given: tree_size,
            }
            .into());
        }
        Self::path(hasher, leaf_index, 0, tree_size, hash_db)
    }

    /// Get a proof that the a shorter tree with size `old_tree_size` is consistent with the current
    /// tree, i.e. the shorter tree is contained in the new tree
    pub fn get_consistency_proof(
        &self,
        old_tree_size: TreeSizeType,
        hash_db: &dyn HashDb<H>,
    ) -> Result<Vec<H>, MerkleTreeError> {
        Self::get_consistency_proof_for_tree_size(&self.hasher, old_tree_size, self.size, hash_db)
    }

    /// Get a proof that the a shorter tree with size `old_tree_size` is consistent with tree of size
    /// `new_tree_size`, i.e. the shorter tree is contained in the new tree
    pub fn get_consistency_proof_for_tree_size(
        hasher: &MTH,
        old_tree_size: TreeSizeType,
        new_tree_size: TreeSizeType,
        hash_db: &dyn HashDb<H>,
    ) -> Result<Vec<H>, MerkleTreeError> {
        if old_tree_size > new_tree_size {
            return Err(MerkleTreeErrorKind::TreeSmallerThanExpected {
                expected: old_tree_size,
                given: new_tree_size,
            }
            .into());
        }
        if old_tree_size == new_tree_size {
            Ok(vec![])
        } else {
            let proof = Self::subproof(hasher, old_tree_size, 0, new_tree_size, true, hash_db)?;
            Ok(proof)
        }
    }

    /// Verify the proof generated by `Self::get_leaf_inclusion_proof_*`
    pub fn verify_leaf_inclusion_proof(
        hasher: &MTH,
        leaf_index: TreeSizeType,
        leaf_val: D,
        tree_size: TreeSizeType,
        root: &H,
        proof: Vec<H>,
    ) -> Result<bool, MerkleTreeError> {
        if leaf_index >= tree_size {
            return Err(MerkleTreeErrorKind::TreeSmallerThanExpected {
                expected: leaf_index + 1,
                given: tree_size,
            }
            .into());
        }
        // start from the leaf hash
        let cur_hash = hasher.hash_leaf_data(leaf_val)?;

        let (right_border_len, inner_path_len) =
            Self::get_right_border_and_inner_node_count(leaf_index, tree_size);
        if (right_border_len + inner_path_len) != proof.len() as u8 {
            return Err(MerkleTreeErrorKind::ShorterInclusionProof {
                expected: right_border_len + inner_path_len,
                given: proof.len() as u8,
            }
            .into());
        }

        Self::_verify_leaf_inclusion_proof(
            hasher,
            leaf_index,
            inner_path_len,
            cur_hash,
            proof,
            root,
        )
    }

    /// Verify the proof generated by `Self::get_consistency_proof_*`
    pub fn verify_consistency_proof(
        hasher: &MTH,
        old_tree_size: TreeSizeType,
        new_tree_size: TreeSizeType,
        old_root: &H,
        new_root: &H,
        mut proof: Vec<H>,
    ) -> Result<bool, MerkleTreeError> {
        if old_tree_size > new_tree_size {
            return Err(MerkleTreeErrorKind::ConsistencyProofIncorrectTreeSize {
                new: new_tree_size,
                old: old_tree_size,
            }
            .into());
        }
        if old_tree_size == 0 || new_tree_size == 0 {
            return Err(MerkleTreeErrorKind::ConsistencyProofWithEmptyTree.into());
        }
        if old_tree_size == new_tree_size {
            return Ok(old_root == new_root);
        }

        // Start hashing from the node with hash `start_hash`
        let start_hash = if old_tree_size.is_power_of_two() {
            // If the old tree was a full tree, then its root hash will not be part of the proof
            old_root.clone()
        } else {
            proof.remove(0)
        };

        let (right_border_len, mut inner_path_len) =
            Self::get_right_border_and_inner_node_count(old_tree_size - 1, new_tree_size);

        // height of the smallest full subtree of the old tree
        let shift = least_significant_set_bit(old_tree_size);

        inner_path_len -= shift;

        if (right_border_len + inner_path_len) != proof.len() as u8 {
            return Err(MerkleTreeErrorKind::ShorterConsistencyProof {
                expected: right_border_len + inner_path_len,
                given: proof.len() as u8,
            }
            .into());
        }

        // A consistency proof is a leaf inclusion proof for the node with index `old_tree_size - 1` in
        // the new tree that also proves inclusion in the old tree.

        let node_index = (old_tree_size - 1) >> shift as TreeSizeType;

        // verify inclusion in the old tree
        let mut index_for_old = node_index.clone();
        let mut expected_old_root = start_hash.clone();
        for p in proof.iter().take(inner_path_len as usize) {
            if index_for_old % 2 == 1 {
                // the proof contains only left nodes, i.e. nodes present in the old tree
                expected_old_root = hasher.hash_tree_nodes(p.clone(), expected_old_root)?;
            }
            index_for_old >>= 1;
        }

        for p in proof.iter().skip(inner_path_len as usize) {
            expected_old_root = hasher.hash_tree_nodes(p.clone(), expected_old_root)?;
        }

        if expected_old_root != *old_root {
            return Err(MerkleTreeErrorKind::InconsistentOldRoot.into());
        }

        // verify inclusion in the new tree
        Self::_verify_leaf_inclusion_proof(
            hasher,
            node_index,
            inner_path_len,
            start_hash,
            proof,
            new_root,
        )
    }

    /// Helper for `Self::verify_leaf_inclusion_proof`
    fn _verify_leaf_inclusion_proof(
        hasher: &MTH,
        mut leaf_index: TreeSizeType,
        inner_path_len: u8,
        mut cur_hash: H,
        mut proof: Vec<H>,
        expected_root: &H,
    ) -> Result<bool, MerkleTreeError> {
        for p in proof.drain(0..inner_path_len as usize) {
            if leaf_index % 2 == 1 {
                cur_hash = hasher.hash_tree_nodes(p, cur_hash)?;
            } else {
                cur_hash = hasher.hash_tree_nodes(cur_hash, p)?;
            }
            leaf_index >>= 1;
        }
        // the nodes on the right border will always be roots of the right subtree and hence on the right
        // side while hashing
        for p in proof.drain(0..) {
            cur_hash = hasher.hash_tree_nodes(p, cur_hash)?;
        }
        Ok(cur_hash == *expected_root)
    }

    /// Add a full subtree formed from the given leaves. The number of leaves should be a power of 2.
    fn push_full_subtree(
        &mut self,
        leaves: Vec<D>,
        hash_db: &mut dyn HashDb<H>,
    ) -> Result<(), MerkleTreeError> {
        if !leaves.len().is_power_of_two() {
            return Err(MerkleTreeErrorKind::ErrorInsertingSubtree {
                msg: format!(
                    "Leaves should form a full subtree but only {} leaves given",
                    leaves.len()
                ),
            }
            .into());
        }
        // leaves form a full subtree.
        let new_subtree_height = leaves.len().trailing_zeros() as u8;
        let min_subtree_height = self.smallest_subtree_height();
        if (self.size != 0) && (new_subtree_height > min_subtree_height) {
            return Err(MerkleTreeErrorKind::ErrorInsertingSubtree {msg: format!("Leaves should form full subtree of height at most {} but form subtree of height {}", min_subtree_height, new_subtree_height)}.into());
        }

        let (leaf_hashes, node_hashes) = Self::hash_leaves(&self.hasher, leaves)?;

        // Root of a subtree with a single leaf is the leaf itself.
        let subtree_root = if node_hashes.is_empty() {
            leaf_hashes.last().unwrap().clone()
        } else {
            node_hashes.last().unwrap().clone()
        };

        for l in leaf_hashes {
            hash_db.add_leaf(l)?;
        }
        for n in node_hashes {
            hash_db.add_full_subtree_root(n)?;
        }

        // roots of all the new subtrees created from merging
        let new_roots = self.push_full_subtree_hash(new_subtree_height, subtree_root)?;

        for n in new_roots {
            hash_db.add_full_subtree_root(n)?;
        }

        Ok(())
    }

    /// Take a subtree hash and add it to the tree. This might lead to merging of existing subtrees
    /// since the given subtree can be of the same size as the smallest subtree in the tree which will
    /// result in merging of those together forming a larger subtree. That larger subtree might turn out
    /// to be of the same size as another existing subtree again resulting in a merge.
    /// Return the roots of all the new subtrees created from merging.
    fn push_full_subtree_hash(
        &mut self,
        subtree_height: u8,
        subtree_hash: H,
    ) -> Result<Vec<H>, MerkleTreeError> {
        let min_subtree_height = self.smallest_subtree_height();
        let subtree_size = 1 << (subtree_height as TreeSizeType);
        if (self.size != 0) && (subtree_height > min_subtree_height) {
            return Err(MerkleTreeErrorKind::ErrorInsertingSubtree {msg: format!("Leaves should form full subtree of height at most {} but form subtree of height {}", min_subtree_height, subtree_height)}.into());
        }
        if self.size == 0 || subtree_height < min_subtree_height {
            // Either the tree is empty or given subtree is smaller than the smallest subtree in the tree
            self.added_subtree(subtree_size, subtree_hash);
            Ok(vec![])
        } else {
            // The given subtree is of the size as the smallest subtree in the tree, hence merge them.

            // Take the smallest subtree hash.
            let removed_subtree_hash = self.removed_subtree(subtree_size)?;

            // Hash both subtree roots to create root of the new bigger subtree
            let next_root = self
                .hasher
                .hash_tree_nodes(removed_subtree_hash, subtree_hash)?;

            // Check if any more merges need to happen
            let mut remain_roots =
                self.push_full_subtree_hash(subtree_height + 1, next_root.clone())?;

            remain_roots.insert(0, next_root);
            Ok(remain_roots)
        }
    }

    /// A single full subtree was added.
    fn added_subtree(&mut self, subtree_size: TreeSizeType, subtree_root: H) {
        self.size += subtree_size;
        self.full_subtree_roots.push(subtree_root);
    }

    /// A single full subtree was removed.
    fn removed_subtree(&mut self, subtree_size: TreeSizeType) -> Result<H, MerkleTreeError> {
        if self.size < subtree_size {
            return Err(MerkleTreeErrorKind::TreeSmallerThanExpected {
                expected: subtree_size,
                given: self.size,
            }
            .into());
        }
        self.size -= subtree_size;
        Ok(self.full_subtree_roots.pop().unwrap())
    }

    /// Arrange leaves in a merkle tree and return hashes of all leaves and hash of all full subtrees
    /// with size > 1. The first return value is the list of hashes, one for each leaf. The second return
    /// value is the list of root hashes of all full subtrees.
    fn hash_leaves(hasher: &MTH, mut leaves: Vec<D>) -> Result<(Vec<H>, Vec<H>), MerkleTreeError> {
        if leaves.is_empty() {
            return Err(MerkleTreeErrorKind::NoLeafProvided.into());
        }

        if leaves.len() == 1 {
            Ok((vec![hasher.hash_leaf_data(leaves.remove(0))?], vec![]))
        } else {
            // left subtree will be a full subtree
            let left_subtree_size = largest_power_of_2_less_than(leaves.len() as TreeSizeType);
            // right subtree might be a full subtree
            let right_subtree_size = leaves.len() as TreeSizeType - left_subtree_size;

            let right_subtree_leaves = leaves.split_off(left_subtree_size as usize);

            let (mut left_leaf_hashes, mut left_node_hashes) = Self::hash_leaves(hasher, leaves)?;
            let (mut right_leaf_hashes, mut right_node_hashes) =
                Self::hash_leaves(hasher, right_subtree_leaves)?;

            // If the left and right subtree have same size then the root of the subtree needs to be returned
            let root = if left_subtree_size == right_subtree_size {
                // When there is only 1 leaf, the root hash is the leaf hash.
                let left_root = if left_node_hashes.is_empty() {
                    left_leaf_hashes.last().unwrap().clone()
                } else {
                    left_node_hashes.last().unwrap().clone()
                };
                let right_root = if right_node_hashes.is_empty() {
                    right_leaf_hashes.last().unwrap().clone()
                } else {
                    right_node_hashes.last().unwrap().clone()
                };

                let root = hasher.hash_tree_nodes(left_root, right_root)?;
                Some(root)
            } else {
                None
            };

            let mut all_leaf_hashes = vec![];
            all_leaf_hashes.append(&mut left_leaf_hashes);
            all_leaf_hashes.append(&mut right_leaf_hashes);

            let mut all_node_hashes = vec![];
            all_node_hashes.append(&mut left_node_hashes);
            all_node_hashes.append(&mut right_node_hashes);

            if left_subtree_size == right_subtree_size {
                all_node_hashes.push(root.unwrap());
            }

            Ok((all_leaf_hashes, all_node_hashes))
        }
    }

    /// Given an ordered list of n inputs to the tree, D[n] = {d(0), ..., d(n-1)}, the Merkle audit
    /// path PATH(m, D[n]) for the (m+1)th input d(m), 0 <= m < n, is defined as follows:
    /// For n = 1, path is empty. D[1] = {d(0)}, PATH(0, {d(0)}) = {}
    /// For n > 1 and m < n, let k be the largest power of two smaller than n:
    /// PATH(m, D[n]) = PATH(m, D[0:k]) : MTH(D[k:n]) for m < k; and
    /// PATH(m, D[n]) = PATH(m - k, D[k:n]) : MTH(D[0:k]) for m >= k,
    /// where ":" means concatenation and MTH is the merkle tree hash of the sublist
    /// Path goes from leaf to root
    fn path(
        hasher: &MTH,
        leaf_index: TreeSizeType,
        from: TreeSizeType,
        to: TreeSizeType,
        hash_db: &dyn HashDb<H>,
    ) -> Result<Vec<H>, MerkleTreeError> {
        // size of the subtree being processed
        let subtree_size = to - from;
        if subtree_size == 1 {
            return Ok(vec![]);
        }
        // Split the subtree into 2 smaller subtrees of sizes [from, k) and [k, to)
        let k = largest_power_of_2_less_than(subtree_size);
        let (mut path, mth) = if leaf_index < k {
            // leaf_index is in the left half of the subtree, find path in the left half
            let path = Self::path(hasher, leaf_index, from, from + k, hash_db)?;
            // take root of the right half
            let mth = Self::subtree_root_hash_from_db(hasher, from + k, to, hash_db)?;
            (path, mth)
        } else {
            // leaf_index is in the right half of the subtree, find path in the right half
            let path = Self::path(hasher, leaf_index - k, from + k, to, hash_db)?;
            // take root of the left half
            let mth = Self::subtree_root_hash_from_db(hasher, from, from + k, hash_db)?;
            (path, mth)
        };
        path.push(mth);
        Ok(path)
    }

    /// a consistency proof must contain a set of intermediate nodes sufficient to verify
    /// MTH(D[n]), such that (a subset of) the same nodes can be used to verify MTH(D[0:m]).
    /// PROOF(m, D[n]) = SUBPROOF(m, D[n], true), the boolean indicates whether the root at m is part of the old tree
    /// SUBPROOF(m, D[m], true) = {} if root of m was part of old tree
    /// SUBPROOF(m, D[m], false) = {MTH(D[m])} if root of m was not part of old tree
    /// For m < n, let k be the largest power of two smaller than n.  The subproof is then defined recursively.
    /// SUBPROOF(m, D[n], b) = SUBPROOF(m, D[0:k], b) : MTH(D[k:n]) for m <= k
    /// SUBPROOF(m, D[n], b) = SUBPROOF(m - k, D[k:n], false) : MTH(D[0:k]) for m > k
    /// /// where ":" means concatenation and MTH is the merkle tree hash of the sublist
    fn subproof(
        hasher: &MTH,
        old_tree_size: TreeSizeType,
        from: TreeSizeType,
        to: TreeSizeType,
        root_present_in_old_tree: bool,
        hash_db: &dyn HashDb<H>,
    ) -> Result<Vec<H>, MerkleTreeError> {
        // size of the subtree being processed
        let subtree_size = to - from;
        if subtree_size == old_tree_size && root_present_in_old_tree {
            Ok(vec![])
        } else if subtree_size == old_tree_size && !root_present_in_old_tree {
            Ok(vec![Self::subtree_root_hash_from_db(
                hasher, from, to, hash_db,
            )?])
        } else {
            // Split the subtree into 2 smaller subtrees of sizes [from, k) and [k, to)
            let k = largest_power_of_2_less_than(subtree_size);
            let (mut subproof, mth) = if old_tree_size <= k {
                // the right subtree is only present in the new tree so take root of the right
                // subtree and get subproof in the left subtree
                let subproof = Self::subproof(
                    hasher,
                    old_tree_size,
                    from,
                    from + k,
                    root_present_in_old_tree,
                    hash_db,
                )?;
                let mth = Self::subtree_root_hash_from_db(hasher, from + k, to, hash_db)?;
                (subproof, mth)
            } else {
                // left subtree is completely present in the old tree and some of the right subtree
                // so take root of the left subtree and get subproof in the right subtree ignoring
                // the part already present in the old tree.
                let subproof =
                    Self::subproof(hasher, old_tree_size - k, from + k, to, false, hash_db)?;
                let mth = Self::subtree_root_hash_from_db(hasher, from, from + k, hash_db)?;
                (subproof, mth)
            };
            subproof.push(mth);
            Ok(subproof)
        }
    }

    /// Reads leaves and nodes from database to create a root hash over leaves [`from`, `to`)
    fn subtree_root_hash_from_db(
        hasher: &MTH,
        from: TreeSizeType,
        to: TreeSizeType,
        hash_db: &dyn HashDb<H>,
    ) -> Result<H, MerkleTreeError> {
        if from >= to {
            return Err(MerkleTreeErrorKind::IncorrectSpan { from, to }.into());
        }
        let subtree_size = to - from;
        if subtree_size == 1 {
            hash_db.get_leaf(from)
        } else if subtree_size.is_power_of_two() {
            let node_index = Self::get_subtree_root_index(from, to);
            hash_db.get_full_subtree_root(node_index)
        } else {
            // Divide the subtree into 2 subtrees and hash their roots
            // left subtree will be a full subtree
            let left_subtree_size = largest_power_of_2_less_than(subtree_size);
            let left_root =
                Self::subtree_root_hash_from_db(hasher, from, from + left_subtree_size, hash_db)?;
            let right_root =
                Self::subtree_root_hash_from_db(hasher, from + left_subtree_size, to, hash_db)?;
            hasher.hash_tree_nodes(left_root, right_root)
        }
    }

    /// Get subtree root index where subtree is over leaves [`from`, `to`). Assumes `from` and `to` form
    /// a full subtree and `to` > `from`
    fn get_subtree_root_index(from: TreeSizeType, to: TreeSizeType) -> TreeSizeType {
        fn root_index(m: TreeSizeType, from: TreeSizeType, to: TreeSizeType) -> TreeSizeType {
            if from == m {
                // take all nodes between from and to which in a full subtree is always `no. of leaves - 1`
                // last -1 because nodes are indexed from 0
                to - from - 1 - 1
            } else {
                let d = to - from;
                let k = largest_power_of_2_less_than(d);
                (k - 1) + root_index(m, from + k, to)
            }
        }
        root_index(from, 0, to)
    }

    /// Height of the smallest subtree in the current tree
    fn smallest_subtree_height(&self) -> u8 {
        least_significant_set_bit(self.size)
    }

    /// For a tree size and a given leaf index, compare the paths from root to the leaf at index `leaf_index`
    /// and the last leaf and split the path of `leaf_index` where it diverges from path to last leaf.
    fn get_right_border_and_inner_node_count(
        leaf_index: TreeSizeType,
        size: TreeSizeType,
    ) -> (u8, u8) {
        let last_leaf_idx = (size - 1);
        // The bit representation of `leaf_index` and `leaf_index` represent which subtrees they lie in
        // and their paths from root to leaf. XOR will set those bits 1 where `leaf_index` and `leaf_index`
        // are different with the MSB being the first node where they diverge.
        // Taking `num_bits` will return the number of nodes on the path from the diversion (including the diverging node).
        let inner_path_len = num_bits(leaf_index ^ last_leaf_idx);
        // `leaf_index >> inner_path_len` will have those nodes . The nodes on the right border
        let right_border_path_len = count_set_bits(leaf_index >> inner_path_len as u64);
        (right_border_path_len, inner_path_len)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::hasher::Sha256Hasher;

    #[test]
    fn test_largest_power_of_2_less_than() {
        assert_eq!(largest_power_of_2_less_than(0), 0);
        assert_eq!(largest_power_of_2_less_than(1), 0);
        assert_eq!(largest_power_of_2_less_than(2), 1);
        assert_eq!(largest_power_of_2_less_than(3), 2);
        assert_eq!(largest_power_of_2_less_than(4), 2);
        assert_eq!(largest_power_of_2_less_than(5), 4);
        assert_eq!(largest_power_of_2_less_than(6), 4);
        assert_eq!(largest_power_of_2_less_than(7), 4);
        assert_eq!(largest_power_of_2_less_than(8), 4);
        // 2^63 = 9223372036854775808, 2^62 = 4611686018427387904
        assert_eq!(
            largest_power_of_2_less_than(u64::max_value()),
            9223372036854775808
        );
        assert_eq!(
            largest_power_of_2_less_than(u64::max_value() - 1),
            9223372036854775808
        );
        assert_eq!(
            largest_power_of_2_less_than(9223372036854775808u64),
            4611686018427387904u64
        );
        assert_eq!(
            largest_power_of_2_less_than(9223372036854775808u64 - 1),
            4611686018427387904u64
        );
        assert_eq!(
            largest_power_of_2_less_than(9223372036854775808u64 + 1),
            9223372036854775808u64
        );
    }

    #[test]
    fn test_count_set_bits() {
        assert_eq!(count_set_bits(0), 0);
        assert_eq!(count_set_bits(1), 1);
        assert_eq!(count_set_bits(2), 1);
        assert_eq!(count_set_bits(3), 2);
        assert_eq!(count_set_bits(4), 1);
        assert_eq!(count_set_bits(u64::max_value()), 64);
        // 2^63 = 9223372036854775808
        assert_eq!(count_set_bits(9223372036854775808), 1);
        assert_eq!(count_set_bits(9223372036854775808 - 1), 63);
    }

    #[test]
    fn test_least_significant_set_bit() {
        assert_eq!(least_significant_set_bit(0), 0);
        assert_eq!(least_significant_set_bit(1), 0);
        assert_eq!(least_significant_set_bit(2), 1);
        assert_eq!(least_significant_set_bit(3), 0);
        assert_eq!(least_significant_set_bit(4), 2);
        assert_eq!(least_significant_set_bit(u64::max_value()), 0);
        // 2^63 = 9223372036854775808
        assert_eq!(least_significant_set_bit(9223372036854775808), 63);
        assert_eq!(least_significant_set_bit(9223372036854775808 - 1), 0);
    }

    #[test]
    fn test_num_bits() {
        assert_eq!(num_bits(0), 0);
        assert_eq!(num_bits(1), 1);
        assert_eq!(num_bits(2), 2);
        assert_eq!(num_bits(3), 2);
        assert_eq!(num_bits(4), 3);
        assert_eq!(num_bits(5), 3);
        assert_eq!(num_bits(6), 3);
        assert_eq!(num_bits(7), 3);
        assert_eq!(num_bits(8), 4);
        assert_eq!(num_bits(u64::max_value()), 64);
        // 2^63 = 9223372036854775808
        assert_eq!(num_bits(9223372036854775808), 64);
        assert_eq!(num_bits(9223372036854775808 - 1), 63);
    }

    #[test]
    fn test_break_in_powers_of_2() {
        //assert_eq!(break_in_powers_of_2(0), vec![]);
        assert_eq!(powers_of_2(1), vec![1]);
        assert_eq!(powers_of_2(2), vec![2]);
        assert_eq!(powers_of_2(3), vec![2, 1]);
        assert_eq!(powers_of_2(4), vec![4]);
        assert_eq!(powers_of_2(5), vec![4, 1]);
        assert_eq!(powers_of_2(6), vec![4, 2]);
        assert_eq!(powers_of_2(7), vec![4, 2, 1]);
        assert_eq!(powers_of_2(8), vec![8]);
        assert_eq!(powers_of_2(9), vec![8, 1]);
        assert_eq!(powers_of_2(10), vec![8, 2]);
        assert_eq!(powers_of_2(11), vec![8, 2, 1]);
        assert_eq!(powers_of_2(12), vec![8, 4]);
        assert_eq!(powers_of_2(13), vec![8, 4, 1]);
        assert_eq!(powers_of_2(14), vec![8, 4, 2]);
        assert_eq!(powers_of_2(15), vec![8, 4, 2, 1]);
        assert_eq!(powers_of_2(16), vec![16]);
    }

    #[test]
    fn test_get_subtree_root_index() {
        // For tree of 8 leaves
        assert_eq!(
            CompactMerkleTree::<&str, Vec<u8>, Sha256Hasher>::get_subtree_root_index(0, 2),
            0
        );
        assert_eq!(
            CompactMerkleTree::<&str, Vec<u8>, Sha256Hasher>::get_subtree_root_index(2, 4),
            1
        );
        assert_eq!(
            CompactMerkleTree::<&str, Vec<u8>, Sha256Hasher>::get_subtree_root_index(0, 4),
            2
        );
        assert_eq!(
            CompactMerkleTree::<&str, Vec<u8>, Sha256Hasher>::get_subtree_root_index(4, 6),
            3
        );
        assert_eq!(
            CompactMerkleTree::<&str, Vec<u8>, Sha256Hasher>::get_subtree_root_index(6, 8),
            4
        );
        assert_eq!(
            CompactMerkleTree::<&str, Vec<u8>, Sha256Hasher>::get_subtree_root_index(4, 8),
            5
        );
        assert_eq!(
            CompactMerkleTree::<&str, Vec<u8>, Sha256Hasher>::get_subtree_root_index(0, 8),
            6
        );

        // For tree of 16 leaves
        assert_eq!(
            CompactMerkleTree::<&str, Vec<u8>, Sha256Hasher>::get_subtree_root_index(8, 10),
            7
        );
        assert_eq!(
            CompactMerkleTree::<&str, Vec<u8>, Sha256Hasher>::get_subtree_root_index(10, 12),
            8
        );
        assert_eq!(
            CompactMerkleTree::<&str, Vec<u8>, Sha256Hasher>::get_subtree_root_index(8, 12),
            9
        );
        assert_eq!(
            CompactMerkleTree::<&str, Vec<u8>, Sha256Hasher>::get_subtree_root_index(12, 14),
            10
        );
        assert_eq!(
            CompactMerkleTree::<&str, Vec<u8>, Sha256Hasher>::get_subtree_root_index(14, 16),
            11
        );
        assert_eq!(
            CompactMerkleTree::<&str, Vec<u8>, Sha256Hasher>::get_subtree_root_index(12, 16),
            12
        );
        assert_eq!(
            CompactMerkleTree::<&str, Vec<u8>, Sha256Hasher>::get_subtree_root_index(8, 16),
            13
        );
        assert_eq!(
            CompactMerkleTree::<&str, Vec<u8>, Sha256Hasher>::get_subtree_root_index(0, 16),
            14
        );
    }

    #[test]
    fn test_hash_db() {
        let mut db = InMemoryHashDb::<Vec<u8>>::new();
        let hasher = Sha256Hasher {
            leaf_data_domain_separator: 0,
            node_domain_separator: 1,
        };
        let l_0 = "leaf_0";
        let l_1 = "leaf_1";
        let l_2 = "leaf_2";
        let l_3 = "leaf_3";

        let h_l_0 = hasher.hash_leaf(l_0).unwrap();
        let h_l_1 = hasher.hash_leaf(l_1).unwrap();
        let h_l_2 = hasher.hash_leaf(l_2).unwrap();
        let h_l_3 = hasher.hash_leaf(l_3).unwrap();

        db.add_leaf(h_l_0.clone()).unwrap();
        db.add_leaf(h_l_1.clone()).unwrap();
        db.add_leaf(h_l_2.clone()).unwrap();
        db.add_leaf(h_l_3.clone()).unwrap();

        let n_0_1 = hasher
            .hash_tree_nodes(h_l_0.clone(), h_l_1.clone())
            .unwrap();
        let n_2_3 = hasher
            .hash_tree_nodes(h_l_2.clone(), h_l_3.clone())
            .unwrap();

        db.add_full_subtree_root(n_0_1.clone()).unwrap();
        db.add_full_subtree_root(n_2_3.clone()).unwrap();

        assert_eq!(db.get_leaf(0).unwrap(), h_l_0);
        assert_eq!(db.get_leaf(1).unwrap(), h_l_1);
        assert_eq!(db.get_leaf(2).unwrap(), h_l_2);
        assert_eq!(db.get_leaf(3).unwrap(), h_l_3);

        assert_eq!(db.get_full_subtree_root(0).unwrap(), n_0_1);
        assert_eq!(db.get_full_subtree_root(1).unwrap(), n_2_3);
    }

    #[test]
    fn test_hash_leaves() {
        let hasher = Sha256Hasher {
            leaf_data_domain_separator: 0,
            node_domain_separator: 1,
        };
        let tree = CompactMerkleTree::new(hasher.clone());
        let l_0 = "leaf_0";
        let l_1 = "leaf_1";
        let l_2 = "leaf_2";
        let l_3 = "leaf_3";
        let l_4 = "leaf_4";
        let l_5 = "leaf_5";
        let l_6 = "leaf_6";

        let (h_l_0_0, h_n_0_0) = CompactMerkleTree::hash_leaves(&hasher, vec![l_0]).unwrap();
        assert_eq!(h_l_0_0.len(), 1);
        assert!(h_n_0_0.is_empty());

        let h_l_0 = hasher.hash_leaf(l_0).unwrap();
        let h_l_1 = hasher.hash_leaf(l_1).unwrap();
        // hash(h_l_0, h_l_1)
        let expected_h_l_0_1 = hasher.hash_tree_nodes(h_l_0, h_l_1).unwrap();
        let (h_l_0_1, h_n_0_1) = CompactMerkleTree::hash_leaves(&hasher, vec![l_0, l_1]).unwrap();
        assert_eq!(h_l_0_1.len(), 2);
        assert_eq!(h_n_0_1.len(), 1);
        assert_eq!(h_n_0_1[0], expected_h_l_0_1);

        let h_l_2 = hasher.hash_leaf(l_2).unwrap();
        let (h_l_0_2, h_n_0_2) =
            CompactMerkleTree::hash_leaves(&hasher, vec![l_0, l_1, l_2]).unwrap();
        assert_eq!(h_l_0_2.len(), 3);
        assert_eq!(h_n_0_2.len(), 1);
        assert_eq!(h_n_0_2[0], expected_h_l_0_1);

        let h_l_3 = hasher.hash_leaf(l_3).unwrap();
        // hash(h_l_2, h_l_3)
        let expected_h_l_2_3 = hasher.hash_tree_nodes(h_l_2, h_l_3).unwrap();
        // hash(hash(h_l_0, h_l_1), hash(h_l_2, h_l_3))
        let expected_h_l_0_3 = hasher
            .hash_tree_nodes(expected_h_l_0_1.clone(), expected_h_l_2_3.clone())
            .unwrap();
        let (h_l_0_3, h_n_0_3) =
            CompactMerkleTree::hash_leaves(&hasher, vec![l_0, l_1, l_2, l_3]).unwrap();
        assert_eq!(h_l_0_3.len(), 4);
        assert_eq!(h_n_0_3.len(), 3);
        assert_eq!(h_n_0_3[0], expected_h_l_0_1);
        assert_eq!(h_n_0_3[1], expected_h_l_2_3);
        assert_eq!(h_n_0_3[2], expected_h_l_0_3);

        let h_l_4 = hasher.hash_leaf(l_4).unwrap();
        let (h_l_0_4, h_n_0_4) =
            CompactMerkleTree::hash_leaves(&hasher, vec![l_0, l_1, l_2, l_3, l_4]).unwrap();
        assert_eq!(h_l_0_4.len(), 5);
        assert_eq!(h_n_0_4.len(), 3);
        assert_eq!(h_n_0_4[0], expected_h_l_0_1);
        assert_eq!(h_n_0_4[1], expected_h_l_2_3);
        assert_eq!(h_n_0_4[2], expected_h_l_0_3);

        let h_l_5 = hasher.hash_leaf(l_5).unwrap();
        // hash(h_l_4, h_l_5)
        let expected_h_l_4_5 = hasher.hash_tree_nodes(h_l_4, h_l_5).unwrap();
        let (h_l_0_5, h_n_0_5) =
            CompactMerkleTree::hash_leaves(&hasher, vec![l_0, l_1, l_2, l_3, l_4, l_5]).unwrap();
        assert_eq!(h_l_0_5.len(), 6);
        assert_eq!(h_n_0_5.len(), 4);
        assert_eq!(h_n_0_5[0], expected_h_l_0_1);
        assert_eq!(h_n_0_5[1], expected_h_l_2_3);
        assert_eq!(h_n_0_5[2], expected_h_l_0_3);
        assert_eq!(h_n_0_5[3], expected_h_l_4_5);

        let h_l_6 = hasher.hash_leaf(l_6).unwrap();
        let (h_l_0_6, h_n_0_6) =
            CompactMerkleTree::hash_leaves(&hasher, vec![l_0, l_1, l_2, l_3, l_4, l_5, l_6])
                .unwrap();
        assert_eq!(h_l_0_6.len(), 7);
        assert_eq!(h_n_0_6.len(), 4);
        assert_eq!(h_n_0_6[0], expected_h_l_0_1);
        assert_eq!(h_n_0_6[1], expected_h_l_2_3);
        assert_eq!(h_n_0_6[2], expected_h_l_0_3);
        assert_eq!(h_n_0_6[3], expected_h_l_4_5);
    }

    #[test]
    fn test_append() {
        let mut db = InMemoryHashDb::<Vec<u8>>::new();
        let hasher = Sha256Hasher {
            leaf_data_domain_separator: 0,
            node_domain_separator: 1,
        };
        let mut tree = CompactMerkleTree::new(hasher.clone());
        let l_0 = "leaf_0";
        let l_1 = "leaf_1";
        let l_2 = "leaf_2";
        let l_3 = "leaf_3";
        let l_4 = "leaf_4";
        let l_5 = "leaf_5";

        let path_0 = tree.append(l_0, &mut db).unwrap();
        assert_eq!(tree.size, 1);
        assert_eq!(tree.full_subtree_roots.len(), 1);
        assert_eq!(
            hasher.hash_leaf(l_0).unwrap(),
            tree.get_root_hash().unwrap()
        );
        assert_eq!(path_0.len(), 0);

        let path_1 = tree.append(l_1, &mut db).unwrap();
        assert_eq!(tree.size, 2);
        assert_eq!(tree.full_subtree_roots.len(), 1);
        let rh_2 = tree.get_root_hash().unwrap();
        let h_l_1 = hasher.hash_leaf(l_1).unwrap();
        assert_eq!(
            tree.hasher
                .hash_tree_nodes(hasher.hash_leaf(l_0).unwrap(), h_l_1.clone())
                .unwrap(),
            rh_2
        );
        assert_eq!(path_1.len(), 1);
        assert_eq!(
            tree.hasher
                .hash_tree_nodes(path_1[0].clone(), h_l_1)
                .unwrap(),
            rh_2
        );

        let path_2 = tree.append(l_2, &mut db).unwrap();
        assert_eq!(tree.size, 3);
        assert_eq!(tree.full_subtree_roots.len(), 2);
        let rh_3 = tree.get_root_hash().unwrap();
        let h_l_2 = hasher.hash_leaf(l_2).unwrap();
        assert_eq!(
            tree.hasher
                .hash_tree_nodes(rh_2.clone(), h_l_2.clone())
                .unwrap(),
            rh_3
        );
        assert_eq!(path_2.len(), 1);
        assert_eq!(
            tree.hasher
                .hash_tree_nodes(path_2[0].clone(), h_l_2.clone())
                .unwrap(),
            rh_3
        );

        let path_3 = tree.append(l_3, &mut db).unwrap();
        assert_eq!(tree.size, 4);
        assert_eq!(tree.full_subtree_roots.len(), 1);
        let rh_4 = tree.get_root_hash().unwrap();
        assert_eq!(
            tree.hasher
                .hash_tree_nodes(
                    rh_2.clone(),
                    tree.hasher
                        .hash_tree_nodes(
                            hasher.hash_leaf(l_2).unwrap(),
                            hasher.hash_leaf(l_3).unwrap()
                        )
                        .unwrap()
                )
                .unwrap(),
            rh_4
        );
        assert_eq!(path_3.len(), 2);
        assert_eq!(path_3[0], h_l_2);
        assert_eq!(path_3[1], rh_2);

        let path_4 = tree.append(l_4, &mut db).unwrap();
        assert_eq!(tree.size, 5);
        assert_eq!(tree.full_subtree_roots.len(), 2);
        let rh_5 = tree.get_root_hash().unwrap();
        assert_eq!(
            tree.hasher
                .hash_tree_nodes(rh_4.clone(), hasher.hash_leaf(l_4).unwrap())
                .unwrap(),
            rh_5
        );

        let path_5 = tree.append(l_5, &mut db).unwrap();
        assert_eq!(tree.size, 6);
        assert_eq!(tree.full_subtree_roots.len(), 2);
        let rh_6 = tree.get_root_hash().unwrap();
        assert_eq!(
            tree.hasher
                .hash_tree_nodes(
                    rh_4,
                    tree.hasher
                        .hash_tree_nodes(
                            hasher.hash_leaf(l_4).unwrap(),
                            hasher.hash_leaf(l_5).unwrap()
                        )
                        .unwrap()
                )
                .unwrap(),
            rh_6
        );
    }

    #[test]
    fn test_inner_border_split() {
        assert_eq!(
            CompactMerkleTree::<&str, Vec<u8>, Sha256Hasher>::get_right_border_and_inner_node_count(
                0, 4
            ),
            (0, 2)
        );
        assert_eq!(
            CompactMerkleTree::<&str, Vec<u8>, Sha256Hasher>::get_right_border_and_inner_node_count(
                1, 4
            ),
            (0, 2)
        );
        assert_eq!(
            CompactMerkleTree::<&str, Vec<u8>, Sha256Hasher>::get_right_border_and_inner_node_count(
                2, 4
            ),
            (1, 1)
        );
        assert_eq!(
            CompactMerkleTree::<&str, Vec<u8>, Sha256Hasher>::get_right_border_and_inner_node_count(
                3, 4
            ),
            (2, 0)
        );

        assert_eq!(
            CompactMerkleTree::<&str, Vec<u8>, Sha256Hasher>::get_right_border_and_inner_node_count(
                0, 5
            ),
            (0, 3)
        );
        assert_eq!(
            CompactMerkleTree::<&str, Vec<u8>, Sha256Hasher>::get_right_border_and_inner_node_count(
                1, 5
            ),
            (0, 3)
        );
        assert_eq!(
            CompactMerkleTree::<&str, Vec<u8>, Sha256Hasher>::get_right_border_and_inner_node_count(
                2, 5
            ),
            (0, 3)
        );
        assert_eq!(
            CompactMerkleTree::<&str, Vec<u8>, Sha256Hasher>::get_right_border_and_inner_node_count(
                3, 5
            ),
            (0, 3)
        );
        assert_eq!(
            CompactMerkleTree::<&str, Vec<u8>, Sha256Hasher>::get_right_border_and_inner_node_count(
                4, 5
            ),
            (1, 0)
        );
    }

    #[test]
    fn test_verify_leaf_inclusion_path() {
        let mut db = InMemoryHashDb::<Vec<u8>>::new();
        let hasher = Sha256Hasher {
            leaf_data_domain_separator: 0,
            node_domain_separator: 1,
        };
        let mut tree = CompactMerkleTree::new(hasher.clone());
        let l_0 = "leaf_0";
        let l_1 = "leaf_1";
        let l_2 = "leaf_2";
        let l_3 = "leaf_3";
        let l_4 = "leaf_4";
        let l_5 = "leaf_5";
        let l_6 = "leaf_6";
        let l_7 = "leaf_7";

        let path_0 = tree.append(l_0, &mut db).unwrap();
        let rh_1 = tree.get_root_hash().unwrap();
        assert!(CompactMerkleTree::verify_leaf_inclusion_proof(
            &hasher, 0, l_0, tree.size, &rh_1, path_0
        )
        .unwrap());

        let path_1 = tree.append(l_1, &mut db).unwrap();
        let rh_2 = tree.get_root_hash().unwrap();
        assert!(CompactMerkleTree::verify_leaf_inclusion_proof(
            &hasher, 1, l_1, tree.size, &rh_2, path_1
        )
        .unwrap());

        let path_2 = tree.append(l_2, &mut db).unwrap();
        let rh_3 = tree.get_root_hash().unwrap();
        assert!(CompactMerkleTree::verify_leaf_inclusion_proof(
            &hasher, 2, l_2, tree.size, &rh_3, path_2
        )
        .unwrap());

        let path_3 = tree.append(l_3, &mut db).unwrap();
        let rh_4 = tree.get_root_hash().unwrap();
        assert!(CompactMerkleTree::verify_leaf_inclusion_proof(
            &hasher, 3, l_3, tree.size, &rh_4, path_3
        )
        .unwrap());

        let path_4 = tree.append(l_4, &mut db).unwrap();
        let rh_5 = tree.get_root_hash().unwrap();
        assert!(CompactMerkleTree::verify_leaf_inclusion_proof(
            &hasher, 4, l_4, tree.size, &rh_5, path_4
        )
        .unwrap());

        let path_5 = tree.append(l_5, &mut db).unwrap();
        let rh_6 = tree.get_root_hash().unwrap();
        assert!(CompactMerkleTree::verify_leaf_inclusion_proof(
            &hasher, 5, l_5, tree.size, &rh_6, path_5
        )
        .unwrap());

        let path_6 = tree.append(l_6, &mut db).unwrap();
        let rh_7 = tree.get_root_hash().unwrap();
        assert!(CompactMerkleTree::verify_leaf_inclusion_proof(
            &hasher, 6, l_6, tree.size, &rh_7, path_6
        )
        .unwrap());

        let path_7 = tree.append(l_7, &mut db).unwrap();
        let rh_8 = tree.get_root_hash().unwrap();
        assert!(CompactMerkleTree::verify_leaf_inclusion_proof(
            &hasher, 7, l_7, tree.size, &rh_8, path_7
        )
        .unwrap());
    }

    fn verify_inclusion_proof_for_all(
        test_cases: usize,
        hasher: &Sha256Hasher,
        tree: &CompactMerkleTree<&str, Vec<u8>, Sha256Hasher>,
        leaf_data: &Vec<String>,
        db: &InMemoryHashDb<Vec<u8>>,
    ) {
        let rh = tree.get_root_hash().unwrap();
        for i in 0..test_cases {
            let path = CompactMerkleTree::get_leaf_inclusion_proof_for_tree_size(
                hasher,
                i as TreeSizeType,
                tree.size,
                db,
            )
            .unwrap();
            assert!(CompactMerkleTree::verify_leaf_inclusion_proof(
                hasher,
                i as TreeSizeType,
                &leaf_data[i],
                tree.size,
                &rh,
                path
            )
            .unwrap());
        }
    }

    #[test]
    fn test_append_and_verify_proof() {
        let mut db = InMemoryHashDb::<Vec<u8>>::new();
        let hasher = Sha256Hasher {
            leaf_data_domain_separator: 0,
            node_domain_separator: 1,
        };
        let mut tree = CompactMerkleTree::new(hasher.clone());

        let test_cases = 100;
        let mut leaf_data = vec![];
        for i in 0..test_cases {
            leaf_data.push(i.to_string())
        }

        for i in 0..test_cases {
            let path = tree.append(&leaf_data[i], &mut db).unwrap();
            let rh = tree.get_root_hash().unwrap();
            assert!(CompactMerkleTree::verify_leaf_inclusion_proof(
                &hasher,
                i as TreeSizeType,
                &leaf_data[i],
                tree.size,
                &rh,
                path
            )
            .unwrap());
            verify_inclusion_proof_for_all(i, &hasher, &tree, &leaf_data, &db)
        }

        let rh = tree.get_root_hash().unwrap();
        for i in 0..test_cases {
            let path = CompactMerkleTree::get_leaf_inclusion_proof_for_tree_size(
                &hasher,
                i as TreeSizeType,
                tree.size,
                &db,
            )
            .unwrap();
            assert!(CompactMerkleTree::verify_leaf_inclusion_proof(
                &hasher,
                i as TreeSizeType,
                &leaf_data[i],
                tree.size,
                &rh,
                path
            )
            .unwrap());
        }
    }

    #[test]
    fn test_extend_and_verify_proof() {
        let mut db = InMemoryHashDb::<Vec<u8>>::new();
        let hasher = Sha256Hasher {
            leaf_data_domain_separator: 0,
            node_domain_separator: 1,
        };
        let mut tree = CompactMerkleTree::new(hasher.clone());

        let test_cases = 100;
        let mut leaf_data = vec![];
        for i in 0..test_cases {
            leaf_data.push(i.to_string())
        }

        tree.extend(vec![&leaf_data[0], &leaf_data[1]], &mut db)
            .unwrap();
        assert_eq!(tree.size, 2);
        verify_inclusion_proof_for_all(tree.size as usize, &hasher, &tree, &leaf_data, &db);

        tree.extend(vec![&leaf_data[2]], &mut db).unwrap();
        assert_eq!(tree.size, 3);
        verify_inclusion_proof_for_all(tree.size as usize, &hasher, &tree, &leaf_data, &db);

        tree.extend(vec![&leaf_data[3]], &mut db).unwrap();
        assert_eq!(tree.size, 4);
        verify_inclusion_proof_for_all(tree.size as usize, &hasher, &tree, &leaf_data, &db);

        tree.extend(vec![&leaf_data[4], &leaf_data[5], &leaf_data[6]], &mut db)
            .unwrap();
        assert_eq!(tree.size, 7);
        verify_inclusion_proof_for_all(tree.size as usize, &hasher, &tree, &leaf_data, &db);

        tree.extend(
            leaf_data[7..15].iter().map(|s| s.as_str()).collect(),
            &mut db,
        )
        .unwrap();
        assert_eq!(tree.size, 15);
        verify_inclusion_proof_for_all(tree.size as usize, &hasher, &tree, &leaf_data, &db);

        tree.extend(
            leaf_data[15..32].iter().map(|s| s.as_str()).collect(),
            &mut db,
        )
        .unwrap();
        assert_eq!(tree.size, 32);
        verify_inclusion_proof_for_all(tree.size as usize, &hasher, &tree, &leaf_data, &db);

        tree.extend(
            leaf_data[32..64].iter().map(|s| s.as_str()).collect(),
            &mut db,
        )
        .unwrap();
        assert_eq!(tree.size, 64);
        verify_inclusion_proof_for_all(tree.size as usize, &hasher, &tree, &leaf_data, &db);

        tree.extend(
            leaf_data[64..70].iter().map(|s| s.as_str()).collect(),
            &mut db,
        )
        .unwrap();
        assert_eq!(tree.size, 70);
        verify_inclusion_proof_for_all(tree.size as usize, &hasher, &tree, &leaf_data, &db);

        tree.extend(
            leaf_data[70..80].iter().map(|s| s.as_str()).collect(),
            &mut db,
        )
        .unwrap();
        assert_eq!(tree.size, 80);
        verify_inclusion_proof_for_all(tree.size as usize, &hasher, &tree, &leaf_data, &db);

        tree.extend(
            leaf_data[80..100].iter().map(|s| s.as_str()).collect(),
            &mut db,
        )
        .unwrap();
        assert_eq!(tree.size, 100);
        verify_inclusion_proof_for_all(tree.size as usize, &hasher, &tree, &leaf_data, &db);
    }

    #[test]
    fn test_consistency_proof() {
        let mut db = InMemoryHashDb::<Vec<u8>>::new();
        let hasher = Sha256Hasher {
            leaf_data_domain_separator: 0,
            node_domain_separator: 1,
        };
        let mut tree = CompactMerkleTree::new(hasher.clone());

        let test_cases = 100;
        let mut leaf_data = vec![];
        for i in 0..test_cases {
            leaf_data.push(i.to_string())
        }

        let mut roots = vec![];
        for i in 0..test_cases {
            tree.append(&leaf_data[i], &mut db).unwrap();
            roots.push(tree.get_root_hash().unwrap());
            if i > 0 {
                for j in 0..i {
                    let consistency_proof = tree
                        .get_consistency_proof((j + 1) as TreeSizeType, &db)
                        .unwrap();
                    assert!(CompactMerkleTree::verify_consistency_proof(
                        &hasher,
                        (j + 1) as TreeSizeType,
                        (i + 1) as TreeSizeType,
                        &roots[j],
                        &roots[i],
                        consistency_proof
                    )
                    .unwrap());
                }
            }
        }
    }

    #[test]
    fn test_create_tree_from_hash_db() {
        let mut db = InMemoryHashDb::<Vec<u8>>::new();
        let hasher = Sha256Hasher {
            leaf_data_domain_separator: 0,
            node_domain_separator: 1,
        };
        let mut tree = CompactMerkleTree::new(hasher.clone());

        let test_cases = 100;
        let mut leaf_data = vec![];
        for i in 0..test_cases {
            leaf_data.push(i.to_string())
        }
        for i in 0..test_cases {
            tree.append(&leaf_data[i], &mut db).unwrap();

            /*if i != 2 {
                continue
            }*/
            let new_tree =
                CompactMerkleTree::new_from_hash_db(hasher.clone(), tree.size, &db).unwrap();
            assert_eq!(new_tree.size, tree.size);
            assert_eq!(new_tree.full_subtree_roots, tree.full_subtree_roots);
        }
    }
}
