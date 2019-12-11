extern crate rlp;
extern crate sha3;

use self::rlp::RlpStream;
use self::sha3::{Digest, Sha3_256};
use db::HashValueDb;
use errors::{MerkleTreeError, MerkleTreeErrorKind};
use failure::_core::cmp::min;
use hasher::Arity2Hasher;
use std::marker::PhantomData;
use types::LeafIndex;

// IMPLEMENTATION AS USED BY ETHEREUM. https://github.com/ethereum/wiki/wiki/Patricia-Tree
// Code borrowed from ethereum implementation and this repo https://github.com/lovesh/Merkle-Patricia-Trie

pub trait Key {
    fn to_nibbles(&self) -> Vec<u8>;
}

impl Key for Vec<u8> {
    fn to_nibbles(&self) -> Vec<u8> {
        bytes_to_nibbles(self)
    }
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub enum NodeType<H, V> {
    Empty,
    Leaf(Leaf<V>),
    Extension(Extension<H, V>),
    Branch(Branch<H, V>),
}

impl<H, V> NodeType<H, V> {
    fn is_empty(&self) -> bool {
        match self {
            NodeType::Empty => true,
            _ => false,
        }
    }

    fn is_leaf(&self) -> bool {
        match self {
            NodeType::Leaf(_) => true,
            _ => false,
        }
    }

    fn is_extension(&self) -> bool {
        match self {
            NodeType::Extension(_) => true,
            _ => false,
        }
    }

    fn is_branch(&self) -> bool {
        match self {
            NodeType::Branch(_) => true,
            _ => false,
        }
    }
}

impl<H, V> Default for NodeType<H, V> {
    fn default() -> Self {
        NodeType::Empty
    }
}

pub enum KeyValueNodeType<H, V> {
    Leaf(Leaf<V>),
    Extension(Extension<H, V>),
}

/// Either a hash (which would be a hash of a serialized branch node) or a branch node
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub enum HashOrBranch<H, V> {
    /// hash of a serialized branch node
    Hash(H),
    Branch(Branch<H, V>),
}

/// Either hash of a serialized node or a node
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub enum HashOrNode<H, V> {
    Hash(H),
    Node(NodeType<H, V>),
}

impl<H, V> Default for HashOrNode<H, V> {
    fn default() -> Self {
        HashOrNode::Node(NodeType::Empty)
    }
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct Leaf<V> {
    /// path in nibbles, does not contain nibbles for flag
    path: Vec<u8>,
    value: V,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct Extension<H, V> {
    /// path in nibbles, does not contain nibbles for flag
    path: Vec<u8>,
    key: HashOrBranch<H, V>,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct Branch<H, V> {
    path: [Box<HashOrNode<H, V>>; 16],
    value: V,
}

impl<V> Leaf<V> {
    pub fn new(path: Vec<u8>, value: V) -> Self {
        Leaf { path, value }
    }

    pub fn has_path(&self, path: &[u8]) -> bool {
        self.path == path
    }
}

fn nibbles_to_bytes(nibbles: &[u8]) -> Vec<u8> {
    assert_eq!(nibbles.len() % 2, 0);
    (0..nibbles.len())
        .step_by(2)
        .map(|i| (nibbles[i] << 4) + nibbles[i + 1])
        .collect::<Vec<u8>>()
}

fn bytes_to_nibbles(bytes: &[u8]) -> Vec<u8> {
    // XXX: Each iteration results in creation of a heap allocation (Vector). A simple for loop
    // might be a better choice
    bytes
        .into_iter()
        .flat_map(|b| vec![b >> 4, b & 15])
        .collect::<Vec<u8>>()
}

pub trait KnownLength {
    fn len(&self) -> usize;
}

impl KnownLength for Vec<u8> {
    fn len(&self) -> usize {
        self.len()
    }
}

/// Serialize node for creating hash or storing in database
pub trait PatriciaTrieNodeSerializer<H, V, S: KnownLength> {
    fn is_empty_root(&self, root: &H) -> bool;
    fn serialize(&self, node: NodeType<H, V>) -> Result<S, MerkleTreeError>;
    fn deserialize(&self, serz: S) -> Result<NodeType<H, V>, MerkleTreeError>;

    /// For leaf and extension nodes. The return type causes heap allocation but avoiding
    /// it (like an array with negative number when there is only one flag) pushes the logic
    /// of handling 1 or 2 nibbles to serializer.
    fn get_flagged_prefix_for_leaf(path_in_nibbles: &[u8]) -> Vec<u8> {
        if path_in_nibbles.len() % 2 == 1 {
            // path is odd, add only 1 nibble
            vec![3]
        } else {
            // path is even, add 2 nibbles
            vec![2, 0]
        }
    }

    fn get_flagged_prefix_for_extension(path_in_nibbles: &[u8]) -> Vec<u8> {
        if path_in_nibbles.len() % 2 == 1 {
            // path is odd, add only 1 nibble
            vec![1]
        } else {
            // path is even, add 2 nibbles
            vec![0, 0]
        }
    }

    /// Takes a path in bytes and retuns the path in nibbles after removing flag nibble(s).
    /// Also returns true or false depending on the path being of an extension or not.
    fn is_extension_path(path: &[u8]) -> Result<(bool, Vec<u8>), MerkleTreeError> {
        let mut nibbles = bytes_to_nibbles(path);
        if nibbles.is_empty() {
            return Ok((false, vec![]));
        }
        if nibbles[0] > 3 {
            return Err(MerkleTreeError::from_kind(
                MerkleTreeErrorKind::IncorrectFlagForRLPNode { flag: nibbles[0] },
            ));
        }
        if nibbles[0] < 2 {
            // nibbles[0] is 0 or 1, so must be extension
            if nibbles[0] == 0 {
                nibbles.remove(0);
            }
            nibbles.remove(0);
            Ok((true, nibbles))
        } else {
            // nibbles[0] is 2 or 3, so must be leaf
            if nibbles[0] == 2 {
                nibbles.remove(0);
            }
            nibbles.remove(0);
            Ok((false, nibbles))
        }
    }
}

#[derive(Clone)]
pub struct RLPSerializer {}

impl RLPSerializer {
    /// Serialize a node in RLP format
    fn bytes_for_node(node: NodeType<Vec<u8>, Vec<u8>>, rlp_stream: &mut RlpStream) {
        match node {
            NodeType::Empty => {
                rlp_stream.append_empty_data();
            }
            NodeType::Leaf(n) => {
                // A leaf has a flag that is prefixed to the leaf path before serialization
                let mut prefixed = Self::get_flagged_prefix_for_leaf(&n.path);
                prefixed.extend_from_slice(&n.path);
                let path = nibbles_to_bytes(&prefixed);
                // A leaf is serialized as a list of 2 items
                rlp_stream.append_list::<Vec<u8>, Vec<u8>>(&[path, n.value]);
            }
            NodeType::Extension(n) => {
                // An extension has a flag that is prefixed to the extension path before serialization
                let mut prefixed = Self::get_flagged_prefix_for_extension(&n.path);
                prefixed.extend_from_slice(&n.path);
                let path = nibbles_to_bytes(&prefixed);
                // A extension is serialized as a list of 2 items
                match n.key {
                    HashOrBranch::Hash(h) => {
                        rlp_stream.append_list::<Vec<u8>, Vec<u8>>(&[path, h]);
                    }
                    HashOrBranch::Branch(b) => {
                        // The second item in the extension node is a branch which itself will be a list
                        rlp_stream.begin_unbounded_list();
                        rlp_stream.append(&path);
                        Self::bytes_for_node(NodeType::Branch(b), rlp_stream);
                        rlp_stream.finalize_unbounded_list();
                    }
                }
            }
            NodeType::Branch(n) => {
                // The branch is serialized as a list
                rlp_stream.begin_unbounded_list();
                for p in n.path.to_vec() {
                    match *p {
                        HashOrNode::Hash(h) => {
                            rlp_stream.append(&h);
                        }
                        HashOrNode::Node(i_n) => Self::bytes_for_node(i_n, rlp_stream),
                    }
                }
                rlp_stream.append(&n.value);
                rlp_stream.finalize_unbounded_list();
            }
        }
    }

    fn node_from_bytes(rlp_serz: rlp::Rlp) -> Result<NodeType<Vec<u8>, Vec<u8>>, MerkleTreeError> {
        if rlp_serz.is_empty() {
            Ok(NodeType::<Vec<u8>, Vec<u8>>::Empty)
        } else if rlp_serz.is_list() {
            let s = rlp_serz.item_count().unwrap();
            if s == 17 {
                // a branch
                let branch = Self::parse_branch_node(&rlp_serz)?;
                Ok(NodeType::<Vec<u8>, Vec<u8>>::Branch(branch))
            } else if s == 2 {
                // extension or leaf
                let kv_node = Self::parse_key_value_node(&rlp_serz)?;
                match kv_node {
                    KeyValueNodeType::Leaf(n) => Ok(NodeType::Leaf(n)),
                    KeyValueNodeType::Extension(n) => Ok(NodeType::Extension(n)),
                }
            } else {
                let msg = String::from("RLP list length should be of length 2 or 17");
                Err(MerkleTreeError::from_kind(
                    MerkleTreeErrorKind::CannotDeserializeWithRLP { msg },
                ))
            }
        } else {
            let msg = String::from("RLP not a list nor data");
            Err(MerkleTreeError::from_kind(
                MerkleTreeErrorKind::CannotDeserializeWithRLP { msg },
            ))
        }
    }

    fn new_branch() -> Branch<Vec<u8>, Vec<u8>> {
        let path: [Box<HashOrNode<Vec<u8>, Vec<u8>>>; 16] = Default::default();
        Branch {
            path,
            value: vec![],
        }
    }

    /// Parse a given RLP slice as a branch
    fn parse_branch_node(rlp_serz: &rlp::Rlp) -> Result<Branch<Vec<u8>, Vec<u8>>, MerkleTreeError> {
        let mut branch = Self::new_branch();
        for i in 0..16 {
            let item = rlp_serz.at(i).unwrap();
            if item.is_empty() {
                // branch has empty node at index `i`
                branch.path[i] = Box::new(HashOrNode::Node(NodeType::<Vec<u8>, Vec<u8>>::Empty));
            } else if item.is_data() {
                // branch has a hash at index `i`
                let hash: Vec<u8> = item.as_val().unwrap();
                branch.path[i] = Box::new(HashOrNode::Hash(hash));
            } else if item.is_list() {
                let s = item.item_count().unwrap();
                if s == 2 {
                    // branch has a either a leaf or an extension node at index `i`
                    let kv_node = Self::parse_key_value_node(&item)?;
                    match kv_node {
                        KeyValueNodeType::Leaf(n) => {
                            branch.path[i] =
                                Box::new(HashOrNode::Node(NodeType::<Vec<u8>, Vec<u8>>::Leaf(n)));
                        }
                        KeyValueNodeType::Extension(n) => {
                            branch.path[i] = Box::new(HashOrNode::Node(
                                NodeType::<Vec<u8>, Vec<u8>>::Extension(n),
                            ));
                        }
                    }
                } else if s == 17 {
                    // branch has another branch node at index `i`
                    let inner_branch = Self::parse_branch_node(&item)?;
                    branch.path[i] = Box::new(HashOrNode::Node(
                        NodeType::<Vec<u8>, Vec<u8>>::Branch(inner_branch),
                    ));
                } else {
                    let msg = String::from("list inside branch is not of length 2 or 17");
                    return Err(MerkleTreeError::from_kind(
                        MerkleTreeErrorKind::CannotDeserializeWithRLP { msg },
                    ));
                }
            } else {
                let msg = String::from("branch's item neither empty, neither data, nor list");
                return Err(MerkleTreeError::from_kind(
                    MerkleTreeErrorKind::CannotDeserializeWithRLP { msg },
                ));
            }
        }
        let val = rlp_serz.at(16).unwrap();
        if val.is_data() {
            branch.value = val.as_val().unwrap();
        } else if val.is_empty() {
            branch.value = vec![];
        } else {
            let msg = String::from("branch's value neither empty nor data");
            return Err(MerkleTreeError::from_kind(
                MerkleTreeErrorKind::CannotDeserializeWithRLP { msg },
            ));
        }
        Ok(branch)
    }

    /// Parse a given RLP slice as a key value or an extension node.
    fn parse_key_value_node(
        rlp_serz: &rlp::Rlp,
    ) -> Result<KeyValueNodeType<Vec<u8>, Vec<u8>>, MerkleTreeError> {
        let item_1 = rlp_serz.at(0).unwrap();
        if !item_1.is_data() {
            let msg = String::from("first item of key-value RLP is not data");
            return Err(MerkleTreeError::from_kind(
                MerkleTreeErrorKind::CannotDeserializeWithRLP { msg },
            ));
        }
        let item_1: Vec<u8> = item_1.as_val().unwrap();
        let (is_extension, path) = Self::is_extension_path(&item_1)?;
        if !is_extension {
            // Its a leaf node
            let item_2 = rlp_serz.at(1).unwrap();
            if !item_2.is_data() {
                let msg = String::from("second item of leaf is not data");
                Err(MerkleTreeError::from_kind(
                    MerkleTreeErrorKind::CannotDeserializeWithRLP { msg },
                ))
            } else {
                let value: Vec<u8> = item_2.as_val().unwrap();
                Ok(KeyValueNodeType::<Vec<u8>, Vec<u8>>::Leaf(Leaf {
                    path,
                    value,
                }))
            }
        } else {
            // Its an extension node, check whether 2nd item is a hash or a branch
            let item_2 = rlp_serz.at(1).unwrap();
            if item_2.is_data() {
                // TODO: Check valid hash length
                let key: Vec<u8> = item_2.as_val().unwrap();
                Ok(KeyValueNodeType::<Vec<u8>, Vec<u8>>::Extension(Extension {
                    path,
                    key: HashOrBranch::Hash(key),
                }))
            } else if item_2.is_list() {
                let s = item_2.item_count().unwrap();
                if s == 17 {
                    let branch = Self::parse_branch_node(&item_2)?;
                    Ok(KeyValueNodeType::Extension(Extension {
                        path,
                        key: HashOrBranch::Branch(branch),
                    }))
                } else {
                    let msg = String::from("extension's list should be a branch");
                    Err(MerkleTreeError::from_kind(
                        MerkleTreeErrorKind::CannotDeserializeWithRLP { msg },
                    ))
                }
            } else {
                let msg = String::from("Extension 2nd items neither data nor list");
                Err(MerkleTreeError::from_kind(
                    MerkleTreeErrorKind::CannotDeserializeWithRLP { msg },
                ))
            }
        }
    }
}

/// For `RLPSerializer`, `self` is not used for serialization or deserialization but some serializers
/// might have some configuration that needs to be used while (de)serializing which can be accessed
/// with `self`
impl PatriciaTrieNodeSerializer<Vec<u8>, Vec<u8>, Vec<u8>> for RLPSerializer {
    fn is_empty_root(&self, root: &Vec<u8>) -> bool {
        rlp::Rlp::new(&root).is_empty()
    }

    fn serialize(&self, node: NodeType<Vec<u8>, Vec<u8>>) -> Result<Vec<u8>, MerkleTreeError> {
        let mut stream = RlpStream::new();
        RLPSerializer::bytes_for_node(node, &mut stream);
        Ok(stream.out())
    }

    fn deserialize(&self, serz: Vec<u8>) -> Result<NodeType<Vec<u8>, Vec<u8>>, MerkleTreeError> {
        let r = rlp::Rlp::new(&serz);
        RLPSerializer::node_from_bytes(r)
    }
}

pub trait NodeHasher<I, H> {
    fn output_size(&self) -> usize;
    fn hash(&self, node: I) -> Result<H, MerkleTreeError>;
}

#[derive(Clone)]
pub struct Sha3Hasher {}

impl NodeHasher<Vec<u8>, Vec<u8>> for Sha3Hasher {
    fn output_size(&self) -> usize {
        32
    }
    fn hash(&self, node: Vec<u8>) -> Result<Vec<u8>, MerkleTreeError> {
        let mut hasher = Sha3_256::new();
        hasher.input(&node);
        Ok(hasher.result().to_vec())
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct MerklePatriciaTrie<V, H, S: Clone + KnownLength, NS, NH>
where
    NS: PatriciaTrieNodeSerializer<H, V, S>,
    NH: NodeHasher<S, H>,
{
    pub root_node: NodeType<H, V>,
    hasher: NH,
    node_serializer: NS,
    pub phantom_1: PhantomData<V>,
    pub phantom_2: PhantomData<S>,
}

impl<V: Clone + Default + Eq, H: Clone, S: Clone + KnownLength, NS, NH>
    MerklePatriciaTrie<V, H, S, NS, NH>
where
    NS: PatriciaTrieNodeSerializer<H, V, S>,
    NH: NodeHasher<S, H>,
{
    /// Create a new empty trie
    pub fn new(hasher: NH, node_serializer: NS) -> Result<Self, MerkleTreeError> {
        Ok(Self {
            root_node: NodeType::Empty,
            hasher,
            node_serializer,
            phantom_1: PhantomData,
            phantom_2: PhantomData,
        })
    }

    /// Initialize a trie with a given root hash and database. The root hash must be
    /// present in the database.
    pub fn initialize_with_root_hash(
        hasher: NH,
        node_serializer: NS,
        root_hash: &H,
        hash_db: &mut dyn HashValueDb<H, S>,
    ) -> Result<Self, MerkleTreeError> {
        let serz_node = hash_db.get(root_hash)?;
        let root_node = node_serializer.deserialize(serz_node)?;
        Ok(Self {
            root_node,
            hasher,
            node_serializer,
            phantom_1: PhantomData,
            phantom_2: PhantomData,
        })
    }

    pub fn get_root_hash(&self) -> Result<H, MerkleTreeError> {
        self.hash_node(self.root_node.clone()).map(|t| t.0)
    }

    /// Get value of the given key. If `proof` is not None, it is populated with a proof.
    pub fn get(
        &self,
        key: &dyn Key,
        proof: &mut Option<Vec<NodeType<H, V>>>,
        hash_db: &dyn HashValueDb<H, S>,
    ) -> Result<V, MerkleTreeError> {
        self.get_from_tree_with_root(&self.root_node, key, proof, hash_db)
    }

    /// Get value of the given key in a tree with root `tree_root`. If `proof` is not None, it is populated with a proof.
    pub fn get_from_tree_with_root(
        &self,
        tree_root: &NodeType<H, V>,
        key: &dyn Key,
        proof: &mut Option<Vec<NodeType<H, V>>>,
        hash_db: &dyn HashValueDb<H, S>,
    ) -> Result<V, MerkleTreeError> {
        let path = key.to_nibbles();
        let need_proof = proof.is_some();
        let mut proof_nodes = Vec::<NodeType<H, V>>::new();
        let val = self.get_from_subtree(tree_root, path, (need_proof, &mut proof_nodes), hash_db);
        if need_proof {
            match proof {
                Some(v) => {
                    v.push(tree_root.clone());
                    v.append(&mut proof_nodes);
                }
                None => (),
            }
        }
        val
    }

    /// Insert a key-value into the trie.
    pub fn insert(
        &mut self,
        key: &dyn Key,
        value: V,
        hash_db: &mut dyn HashValueDb<H, S>,
    ) -> Result<H, MerkleTreeError> {
        let path = key.to_nibbles();
        let old_root_node = self.root_node.clone();
        // XXX: Maybe i should pass old_root_node and not its reference
        let new_root_node = self.insert_into_subtree(&old_root_node, path, value, hash_db)?;
        let new_root_hash = self.store_root_node_in_db(new_root_node.clone(), hash_db)?;
        self.root_node = new_root_node;
        Ok(new_root_hash)
    }

    /// Verify that a tree with root hash `root_hash` has a key `key` with value `value`
    pub fn verify_proof(
        key: &dyn Key,
        value: &V,
        proof: Vec<NodeType<H, V>>,
        hasher: NH,
        node_serializer: NS,
        root_hash: &H,
        hash_db: &mut dyn HashValueDb<H, S>,
    ) -> Result<bool, MerkleTreeError> {
        let new_trie = Self::initialize_with_given_nodes_and_root_hash(
            hasher,
            node_serializer,
            root_hash,
            proof,
            hash_db,
        )?;
        match new_trie.get(key, &mut None, hash_db) {
            Ok(v) => Ok(v == *value),
            Err(_) => Ok(false),
        }
    }

    /// Get all key-value pairs in a tree with root `root_node`. If `proof` is not None, it is populated
    /// with a proof. The argument `nibbles_to_key` is a function to convert nibbles to keys.
    /// Don't want to require `Key` trait to have a nibble_to_key function as this function might not be
    /// needed by all implementations.
    pub fn get_key_values<K>(
        &self,
        root_node: &NodeType<H, V>,
        proof: &mut Option<Vec<NodeType<H, V>>>,
        hash_db: &dyn HashValueDb<H, S>,
        nibbles_to_key: &dyn Fn(&[u8]) -> K, // TODO: nibbles_to_key can return an error, return type should be a result
    ) -> Result<Vec<(K, V)>, MerkleTreeError> {
        // TODO: Return value should be a iterator as the tree can contain lots of keys
        let need_proof = proof.is_some();
        let mut proof_nodes = Vec::<NodeType<H, V>>::new();
        let nv = self.get_key_nibbles_and_values(root_node, (need_proof, &mut proof_nodes), hash_db)?;

        if need_proof {
            match proof {
                Some(v) => {
                    v.push(root_node.clone());
                    v.append(&mut proof_nodes);
                }
                None => (),
            }
        }

        // Since the keys are in nibbles, convert them to a key using the passed function
        Ok(nv
            .into_iter()
            .map(|(n, v)| (nibbles_to_key(&n), v))
            .collect::<Vec<(K, V)>>())
    }

    /// Get all key-value pairs in a tree with root `root_node` and prefix `prefix_key`. If `proof` is
    /// not None, it is populated with a proof.
    pub fn get_keys_values_with_prefix<K>(
        &self,
        prefix_key: &dyn Key,
        node: &NodeType<H, V>,
        proof: &mut Option<Vec<NodeType<H, V>>>,
        hash_db: &dyn HashValueDb<H, S>,
        nibbles_to_key: &dyn Fn(&[u8]) -> K, // TODO: nibbles_to_key can return an error, return type should be a result
    ) -> Result<Vec<(K, V)>, MerkleTreeError> {
        // TODO: Return value should be a iterator
        let path = prefix_key.to_nibbles();
        let need_proof = proof.is_some();
        let mut proof_nodes = Vec::<NodeType<H, V>>::new();

        // Nibbles of the prefix before the prefix_node
        let mut seen_prefix_nibbles = vec![];

        // Find the node where the prefix ends
        let prefix_node = self.get_last_node_for_prefix_key(
            node,
            path,
            &mut seen_prefix_nibbles,
            (need_proof, &mut proof_nodes),
            hash_db,
        )?;
        // Get all key-value pairs from the tree rooted at the prefix_node
        let nv =
            self.get_key_nibbles_and_values(&prefix_node, (need_proof, &mut proof_nodes), hash_db)?;
        if need_proof {
            match proof {
                Some(v) => {
                    v.push(node.clone());
                    v.push(prefix_node.clone());
                    v.append(&mut proof_nodes);
                }
                None => (),
            }
        }

        // Since the keys are in nibbles, convert them to a key using the passed function after
        // adding the prefix
        Ok(nv
            .into_iter()
            .map(|(mut n, v)| {
                let mut key = seen_prefix_nibbles.clone();
                key.append(&mut n);
                (nibbles_to_key(&key), v)
            })
            .collect::<Vec<(K, V)>>())
    }

    pub fn verify_proof_multiple_keys(
        keys: Vec<&dyn Key>,
        values: &[V],
        proof: Vec<NodeType<H, V>>,
        hasher: NH,
        node_serializer: NS,
        root_hash: &H,
        hash_db: &mut dyn HashValueDb<H, S>,
    ) -> Result<bool, MerkleTreeError> {
        if keys.len() != values.len() {
            return Err(MerkleTreeError::from_kind(
                MerkleTreeErrorKind::UnequalNoOfKeysAndValues {num_keys: keys.len(), num_values: values.len()},
            ));
        }

        let new_trie = Self::initialize_with_given_nodes_and_root_hash(
            hasher,
            node_serializer,
            root_hash,
            proof,
            hash_db,
        )?;

        for i in 0..keys.len() {
            let key = keys[i];
            let value = &values[i];
            match new_trie.get(key, &mut None, hash_db) {
                Ok(v) => {
                    if v != *value {
                        return Ok(false);
                    }
                }
                Err(_) => return Ok(false),
            }
        }

        Ok(true)
    }

    /// Get the node from which all keys having the prefix `prefix_nibbles` diverge. This node can then
    /// be used to traverse all keys with the prefix.
    fn get_last_node_for_prefix_key(
        &self,
        node_to_start_from: &NodeType<H, V>,
        mut prefix_nibbles: Vec<u8>,
        seen_prefix_nibbles: &mut Vec<u8>,
        (need_proof, proof_nodes): (bool, &mut Vec<NodeType<H, V>>),
        hash_db: &dyn HashValueDb<H, S>,
    ) -> Result<NodeType<H, V>, MerkleTreeError> {
        match node_to_start_from {
            NodeType::Empty => Ok(NodeType::Empty),
            NodeType::Leaf(leaf) => {
                if leaf.path.starts_with(&prefix_nibbles) {
                    Ok(node_to_start_from.clone())
                } else {
                    return Err(MerkleTreeError::from_kind(
                        MerkleTreeErrorKind::NoKeyWithPrefixInTrie,
                    ));
                }
            }
            NodeType::Extension(ext) => {
                if prefix_nibbles.is_empty() {
                    return Err(MerkleTreeError::from_kind(
                        MerkleTreeErrorKind::NoKeyWithPrefixInTrie,
                    ));
                }
                if ext.path.starts_with(&prefix_nibbles) {
                    Ok(node_to_start_from.clone())
                } else if prefix_nibbles.starts_with(&ext.path) {
                    seen_prefix_nibbles.extend_from_slice(&ext.path);
                    match &ext.key {
                        HashOrBranch::Hash(h) => {
                            let inner_node = self.get_node_from_db(h, hash_db)?;
                            if need_proof {
                                proof_nodes.push(inner_node.clone());
                            }
                            self.get_last_node_for_prefix_key(
                                &inner_node,
                                prefix_nibbles[ext.path.len()..].to_vec(),
                                seen_prefix_nibbles,
                                (need_proof, proof_nodes),
                                hash_db,
                            )
                        }
                        HashOrBranch::Branch(branch) => self.get_last_node_for_prefix_key(
                            &NodeType::Branch(branch.clone()),
                            prefix_nibbles[ext.path.len()..].to_vec(),
                            seen_prefix_nibbles,
                            (need_proof, proof_nodes),
                            hash_db,
                        ),
                    }
                } else {
                    return Err(MerkleTreeError::from_kind(
                        MerkleTreeErrorKind::NoKeyWithPrefixInTrie,
                    ));
                }
            }
            NodeType::Branch(branch) => {
                if prefix_nibbles.is_empty() {
                    Ok(node_to_start_from.clone())
                } else {
                    let node_index = prefix_nibbles.remove(0);
                    let node = self.get_node_from_branch(node_index as usize, branch, hash_db)?;
                    seen_prefix_nibbles.push(node_index);
                    if need_proof {
                        proof_nodes.push(node.clone());
                    }
                    self.get_last_node_for_prefix_key(
                        &node,
                        prefix_nibbles,
                        seen_prefix_nibbles,
                        (need_proof, proof_nodes),
                        hash_db,
                    )
                }
            }
        }
    }

    /// Insert a value in the subtree at root `subtree_root` at the path `path`
    fn insert_into_subtree(
        &self,
        subtree_root: &NodeType<H, V>,
        mut path: Vec<u8>,
        value: V,
        hash_db: &mut dyn HashValueDb<H, S>,
    ) -> Result<NodeType<H, V>, MerkleTreeError> {
        match subtree_root {
            NodeType::Empty => {
                let leaf_node = NodeType::Leaf(Leaf::new(path, value));
                Ok(leaf_node)
            }
            NodeType::Leaf(leaf_node) => {
                if leaf_node.has_path(&path) {
                    // Updating value of an existing leaf
                    let leaf_node = NodeType::Leaf(Leaf::new(path, value));
                    Ok(leaf_node)
                } else {
                    // Creating a node, will result in creation of more than one new node.
                    let cur_path = &leaf_node.path;
                    let common_prefix = Self::get_common_prefix_in_paths(cur_path, &path);

                    if common_prefix.len() == 0 {
                        // paths for both nodes (new and existing) have no common prefix, create a branch node with 2 leaf nodes
                        let branch_path: [Box<HashOrNode<H, V>>; 16] = Default::default();
                        let mut branch = Branch {
                            path: branch_path,
                            value: V::default(),
                        };

                        self.store_leaf_in_branch(
                            &mut branch,
                            cur_path.to_vec(),
                            leaf_node.value.clone(),
                            hash_db,
                        )?;
                        self.store_leaf_in_branch(&mut branch, path, value, hash_db)?;

                        Ok(NodeType::Branch(branch))
                    } else {
                        if common_prefix.len() < cur_path.len() && common_prefix.len() < path.len()
                        {
                            // Some path prefix is common between both new and existing node, create an extension node
                            // with common prefix path as key and 2 leaf nodes in a branch node

                            // this branch will be the key for the extension node
                            let branch_path: [Box<HashOrNode<H, V>>; 16] = Default::default();
                            let mut branch = Branch {
                                path: branch_path,
                                value: V::default(),
                            };

                            // Store both leaves in the branch. The common prefix is not stored in
                            // the leaf path as its already part of the extension node.
                            self.store_leaf_in_branch(
                                &mut branch,
                                cur_path[common_prefix.len()..].to_vec(),
                                leaf_node.value.clone(),
                                hash_db,
                            )?;
                            self.store_leaf_in_branch(
                                &mut branch,
                                path[common_prefix.len()..].to_vec(),
                                value,
                                hash_db,
                            )?;

                            Ok(NodeType::Extension(Extension {
                                path: common_prefix,
                                key: HashOrBranch::Branch(branch),
                            }))
                        } else if common_prefix == *cur_path {
                            // Existing node and new node will be moved to a new branch node which will be the key of
                            // a new extension node with path as the common prefix. The value of the existing node will
                            // be the value of the branch node.

                            // this branch will be the key for the extension node
                            let branch_path: [Box<HashOrNode<H, V>>; 16] = Default::default();
                            let mut branch = Branch {
                                path: branch_path,
                                value: leaf_node.value.clone(),
                            };

                            // Store new node as a leaf node in the branch. The common prefix is not
                            // stored in the leaf path as its already part of the extension node.
                            self.store_leaf_in_branch(
                                &mut branch,
                                path[common_prefix.len()..].to_vec(),
                                value,
                                hash_db,
                            )?;

                            Ok(NodeType::Extension(Extension {
                                path: common_prefix,
                                key: HashOrBranch::Branch(branch),
                            }))
                        } else {
                            // common_prefix == path
                            // Existing node and new node will be moved to a new branch node which will be the key of
                            // a new extension node with path as the common prefix. The value of the new node will
                            // be the value of the branch node.

                            // this branch will be the key for the extension node
                            let branch_path: [Box<HashOrNode<H, V>>; 16] = Default::default();
                            let mut branch = Branch {
                                path: branch_path,
                                value,
                            };

                            // Store existing node as a leaf node in the branch. The common prefix
                            // is not stored in the leaf path as its already part of the extension node.
                            self.store_leaf_in_branch(
                                &mut branch,
                                cur_path[common_prefix.len()..].to_vec(),
                                leaf_node.value.clone(),
                                hash_db,
                            )?;

                            Ok(NodeType::Extension(Extension {
                                path: common_prefix,
                                key: HashOrBranch::Branch(branch),
                            }))
                        }
                    }
                }
            }
            NodeType::Extension(ext_node) => {
                if path == ext_node.path {
                    // Updating key of an existing extension node to contain the new node as well.
                    let key = self.update_extension_key(&ext_node.key, vec![], value, hash_db)?;
                    Ok(NodeType::Extension(Extension { path, key }))
                } else {
                    let cur_path = &ext_node.path;
                    let common_prefix = Self::get_common_prefix_in_paths(cur_path, &path);
                    if common_prefix.len() == 0 {
                        // paths for both nodes (new and existing) have no common prefix, create a
                        // branch node with 1 leaf node and 1 extension node
                        let mut branch_path: [Box<HashOrNode<H, V>>; 16] = Default::default();

                        self.store_extension_in_branch(
                            &mut branch_path,
                            cur_path.to_vec(),
                            ext_node.key.clone(),
                            hash_db,
                        )?;
                        let mut branch = Branch {
                            path: branch_path,
                            value: V::default(),
                        };
                        self.store_leaf_in_branch(&mut branch, path, value, hash_db)?;

                        Ok(NodeType::Branch(branch))
                    } else if common_prefix.len() < cur_path.len()
                        && common_prefix.len() < path.len()
                    {
                        // Some path prefix is common between both new and existing node, create an extension node
                        // with common prefix path as key and 1 leaf node and 1 extension node, both
                        // in a new branch node

                        // this branch will be the key for the extension node
                        let mut branch_path: [Box<HashOrNode<H, V>>; 16] = Default::default();

                        // The common prefix is not stored in the leaf path as its already part of the
                        // extension node.
                        self.store_extension_in_branch(
                            &mut branch_path,
                            cur_path[common_prefix.len()..].to_vec(),
                            ext_node.key.clone(),
                            hash_db,
                        )?;
                        let mut branch = Branch {
                            path: branch_path,
                            value: V::default(),
                        };
                        self.store_leaf_in_branch(
                            &mut branch,
                            path[common_prefix.len()..].to_vec(),
                            value,
                            hash_db,
                        )?;

                        Ok(NodeType::Extension(Extension {
                            path: common_prefix,
                            key: HashOrBranch::Branch(branch),
                        }))
                    } else if common_prefix == *cur_path {
                        // Existing node and new node will be moved to a new branch node which will be the key of
                        // a new extension node with path as the common prefix.

                        // Update key of the existing extension node to contain the new node as well.
                        let key = self.update_extension_key(
                            &ext_node.key,
                            path[common_prefix.len()..].to_vec(),
                            value,
                            hash_db,
                        )?;
                        Ok(NodeType::Extension(Extension {
                            path: common_prefix,
                            key,
                        }))
                    } else {
                        // common_prefix == path
                        // Existing node and new node will be moved to a new branch node which will be the key of
                        // a new extension node with path as the common prefix. The value of the new node will
                        // be the value of the branch node.

                        // this branch will be the key for the extension node
                        let mut branch_path: [Box<HashOrNode<H, V>>; 16] = Default::default();

                        // Store existing node as an extension node in the branch. The common prefix
                        // is not stored in the leaf path as its already part of the extension node.
                        self.store_extension_in_branch(
                            &mut branch_path,
                            cur_path[common_prefix.len()..].to_vec(),
                            ext_node.key.clone(),
                            hash_db,
                        )?;

                        let branch = Branch {
                            path: branch_path,
                            value,
                        };
                        Ok(NodeType::Extension(Extension {
                            path: common_prefix,
                            key: HashOrBranch::Branch(branch),
                        }))
                    }
                }
            }
            NodeType::Branch(branch) => {
                if path.is_empty() {
                    // Update value of this branch
                    let mut new_branch = branch.clone();
                    new_branch.value = value;
                    Ok(NodeType::Branch(new_branch))
                } else {
                    // Update the appropriate node in path of this branch and create a new branch with the updated node

                    // Find the appropriate node
                    let node_index = path.remove(0) as usize;
                    let node = self.get_node_from_branch(node_index, branch, hash_db)?;
                    // Update the appropriate node
                    let new_node = self.insert_into_subtree(&node, path, value, hash_db)?;

                    // Create a new branch with the updated node
                    let mut new_branch = branch.clone();
                    new_branch.path[node_index] =
                        Box::new(self.store_node_in_db_if_needed(new_node, hash_db)?);
                    Ok(NodeType::Branch(new_branch))
                }
            }
        }
    }

    /// Get value from the subtree at root `subtree_root` at the path `path`
    fn get_from_subtree(
        &self,
        subtree_root: &NodeType<H, V>,
        mut path: Vec<u8>,
        (need_proof, proof_nodes): (bool, &mut Vec<NodeType<H, V>>),
        hash_db: &dyn HashValueDb<H, S>,
    ) -> Result<V, MerkleTreeError> {
        let val = match subtree_root {
            NodeType::Empty => Err(MerkleTreeErrorKind::NotFoundInTree.into()),
            NodeType::Leaf(leaf_node) => {
                if leaf_node.has_path(&path) {
                    Ok(leaf_node.value.clone())
                } else {
                    Err(MerkleTreeErrorKind::NotFoundInTree.into())
                }
            }
            NodeType::Extension(ext_node) => {
                if path.starts_with(&ext_node.path) {
                    match &ext_node.key {
                        HashOrBranch::Hash(h) => {
                            let inner_node = self.get_node_from_db(h, hash_db)?;
                            if need_proof {
                                proof_nodes.push(inner_node.clone());
                            }
                            self.get_from_subtree(
                                &inner_node,
                                path[ext_node.path.len()..].to_vec(),
                                (need_proof, proof_nodes),
                                hash_db,
                            )
                        }
                        HashOrBranch::Branch(branch) => self.get_from_subtree(
                            &NodeType::Branch(branch.clone()),
                            path[ext_node.path.len()..].to_vec(),
                            (need_proof, proof_nodes),
                            hash_db,
                        ),
                    }
                } else {
                    Err(MerkleTreeErrorKind::NotFoundInTree.into())
                }
            }
            NodeType::Branch(branch) => {
                if path.is_empty() {
                    Ok(branch.value.clone())
                } else {
                    let node_index = path.remove(0) as usize;
                    let node = self.get_node_from_branch(node_index, branch, hash_db)?;
                    if need_proof {
                        proof_nodes.push(node.clone());
                    }
                    self.get_from_subtree(&node, path, (need_proof, proof_nodes), hash_db)
                }
            }
        };
        val
    }

    /// Get all key-value pairs in a tree with root `root_node`. If `proof` is not None, it is populated
    /// with a proof. The keys are returned as nibbles.
    fn get_key_nibbles_and_values(
        &self,
        node: &NodeType<H, V>,
        (need_proof, proof_nodes): (bool, &mut Vec<NodeType<H, V>>),
        hash_db: &dyn HashValueDb<H, S>,
    ) -> Result<Vec<(Vec<u8>, V)>, MerkleTreeError> {
        // TODO: Return value should be a iterator
        match node {
            NodeType::Empty => Ok(vec![]),
            NodeType::Leaf(l) => return Ok(vec![(l.path.clone(), l.value.clone())]),
            NodeType::Extension(ext_node) => {
                let path = ext_node.path.clone();
                let nv = match &ext_node.key {
                    HashOrBranch::Hash(h) => {
                        let inner_node = self.get_node_from_db(h, hash_db)?;
                        if need_proof {
                            proof_nodes.push(inner_node.clone());
                        }
                        self.get_key_nibbles_and_values(
                            &inner_node,
                            (need_proof, proof_nodes),
                            hash_db,
                        )?
                    }
                    HashOrBranch::Branch(branch) => self.get_key_nibbles_and_values(
                        &NodeType::Branch(branch.clone()),
                        (need_proof, proof_nodes),
                        hash_db,
                    )?,
                };
                let r = nv
                    .into_iter()
                    .map(|(mut n, v)| {
                        for p in path.iter().rev() {
                            n.insert(0, *p);
                        }
                        (n, v)
                    })
                    .collect::<Vec<(Vec<u8>, V)>>();
                Ok(r)
            }
            NodeType::Branch(branch) => {
                let mut nv = vec![];
                for i in 0..16 {
                    let node = self.get_node_from_branch(i, branch, hash_db)?;
                    if need_proof {
                        proof_nodes.push(node.clone());
                    }
                    for (mut n, v) in
                        self.get_key_nibbles_and_values(&node, (need_proof, proof_nodes), hash_db)?
                    {
                        n.insert(0, i as u8);
                        nv.push((n, v));
                    }
                }
                if branch.value != V::default() {
                    nv.push((Vec::<u8>::new(), branch.value.clone()))
                }
                Ok(nv)
            }
        }
    }

    /// Get node at a particualar index in a branch. If there is a hash at the index, get the node
    /// for that hash from the db
    fn get_node_from_branch(
        &self,
        node_index: usize,
        branch: &Branch<H, V>,
        hash_db: &dyn HashValueDb<H, S>,
    ) -> Result<NodeType<H, V>, MerkleTreeError> {
        let hash_or_node = branch.path[node_index].as_ref();
        match hash_or_node {
            HashOrNode::Hash(h) => self.get_node_from_db(h, hash_db),
            HashOrNode::Node(n) => Ok(n.clone()),
        }
    }

    fn serialize_node(&self, node: NodeType<H, V>) -> Result<S, MerkleTreeError> {
        self.node_serializer.serialize(node)
    }

    fn deserialize_node(&self, node: S) -> Result<NodeType<H, V>, MerkleTreeError> {
        self.node_serializer.deserialize(node)
    }

    /// Serialize and hash the serialized node. Returns the hash as well as the serialized value
    fn hash_node(&self, node: NodeType<H, V>) -> Result<(H, S), MerkleTreeError> {
        let serz_node = self.serialize_node(node)?;
        let hash = self.hasher.hash(serz_node.clone())?;
        Ok((hash, serz_node))
    }

    /// Store the node after serialization in the db. The key is the hash of the serialized node.
    fn store_root_node_in_db(
        &self,
        node: NodeType<H, V>,
        hash_db: &mut dyn HashValueDb<H, S>,
    ) -> Result<H, MerkleTreeError> {
        let (hash, serz_node) = self.hash_node(node.clone())?;
        hash_db.put(hash.clone(), serz_node)?;
        Ok(hash)
    }

    fn get_node_from_db(
        &self,
        hash: &H,
        hash_db: &dyn HashValueDb<H, S>,
    ) -> Result<NodeType<H, V>, MerkleTreeError> {
        let serz_node = hash_db.get(hash)?;
        self.deserialize_node(serz_node)
    }

    /// Store a leaf node in a branch node.
    fn store_leaf_in_branch(
        &self,
        branch: &mut Branch<H, V>,
        mut leaf_path: Vec<u8>,
        leaf_value: V,
        hash_db: &mut dyn HashValueDb<H, S>,
    ) -> Result<(), MerkleTreeError> {
        if leaf_path.is_empty() {
            branch.value = leaf_value;
        } else {
            let leaf_idx = leaf_path.remove(0) as usize;
            let leaf_node = NodeType::Leaf(Leaf {
                path: leaf_path,
                value: leaf_value,
            });
            let leaf = self.store_node_in_db_if_needed(leaf_node, hash_db)?;
            branch.path[leaf_idx] = Box::new(leaf);
        }
        Ok(())
    }

    /// Store an extension node in a branch node.
    fn store_extension_in_branch(
        &self,
        branch_path: &mut [Box<HashOrNode<H, V>>; 16],
        mut ext_path: Vec<u8>,
        ext_key: HashOrBranch<H, V>,
        hash_db: &mut dyn HashValueDb<H, S>,
    ) -> Result<(), MerkleTreeError> {
        if ext_path.len() == 1 {
            // If existing extension node's path, store the extension's key directly
            // in the branch node. Since extension will have a branch node only when
            // its length is less than hash output size, no need to deserialize it.
            let ext_node_index = ext_path.remove(0) as usize;
            branch_path[ext_node_index] = match ext_key {
                HashOrBranch::Hash(h) => Box::new(HashOrNode::Hash(h)),
                HashOrBranch::Branch(b) => Box::new(HashOrNode::Node(NodeType::Branch(b))),
            };
        } else {
            let ext_idx = ext_path.remove(0) as usize;
            let ext_node = NodeType::Extension(Extension {
                path: ext_path,
                key: ext_key,
            });
            let ext = self.store_node_in_db_if_needed(ext_node, hash_db)?;
            branch_path[ext_idx] = Box::new(ext);
        }
        Ok(())
    }

    /// Update key of the existing extension node to contain the new node as well.
    fn update_extension_key(
        &self,
        ext_key: &HashOrBranch<H, V>,
        path: Vec<u8>,
        value: V,
        hash_db: &mut dyn HashValueDb<H, S>,
    ) -> Result<HashOrBranch<H, V>, MerkleTreeError> {
        let new_node = match ext_key {
            HashOrBranch::Hash(h) => {
                let inner_node = self.get_node_from_db(h, hash_db)?;
                self.insert_into_subtree(&inner_node, path, value, hash_db)?
            }
            HashOrBranch::Branch(branch) => {
                self.insert_into_subtree(&NodeType::Branch(branch.clone()), path, value, hash_db)?
            }
        };

        // The new node must be a branch.
        if !new_node.is_branch() {
            let msg = String::from("The node should have been a branch and nothing else");
            return Err(MerkleTreeErrorKind::IncorrectNodeType { msg }.into());
        }

        // Store the branch in db if needed.
        let key = {
            let node = self.store_node_in_db_if_needed(new_node, hash_db)?;
            match node {
                HashOrNode::Hash(h) => HashOrBranch::Hash(h),
                HashOrNode::Node(n) => {
                    if !n.is_branch() {
                        let msg =
                            String::from("The node should have been a branch and nothing else");
                        return Err(MerkleTreeErrorKind::IncorrectNodeType { msg }.into());
                    }
                    match n {
                        NodeType::Branch(b) => HashOrBranch::Branch(b),
                        _ => {
                            let msg =
                                String::from("The node should have been a branch and nothing else");
                            return Err(MerkleTreeErrorKind::IncorrectNodeType { msg }.into());
                        }
                    }
                }
            }
        };
        Ok(key)
    }

    fn initialize_with_given_nodes_and_root_hash(
        hasher: NH,
        node_serializer: NS,
        root_hash: &H,
        nodes: Vec<NodeType<H, V>>,
        hash_db: &mut dyn HashValueDb<H, S>,
    ) -> Result<Self, MerkleTreeError> {
        for node in nodes {
            let serz_node = node_serializer.serialize(node)?;
            if serz_node.len() >= hasher.output_size() {
                let hash = hasher.hash(serz_node.clone())?;
                hash_db.put(hash.clone(), serz_node)?;
            }
        }
        Self::initialize_with_root_hash(hasher, node_serializer, root_hash, hash_db)
    }

    /// Return serialized node if size after serialization is less than hash output otherwise store node in db as key-value
    /// where key is the hash of the serialized node and value is the serialized node and return the hash (db key)
    fn store_node_in_db_if_needed(
        &self,
        node: NodeType<H, V>,
        hash_db: &mut dyn HashValueDb<H, S>,
    ) -> Result<HashOrNode<H, V>, MerkleTreeError> {
        let serz_node = self.serialize_node(node.clone())?;
        if serz_node.len() < self.hasher.output_size() {
            Ok(HashOrNode::Node(node))
        } else {
            let hash = self.hasher.hash(serz_node.clone())?;
            hash_db.put(hash.clone(), serz_node)?;
            Ok(HashOrNode::Hash(hash))
        }
    }

    /// Return the common prefix of given paths.
    fn get_common_prefix_in_paths(path_1: &[u8], path_2: &[u8]) -> Vec<u8> {
        let mut common_prefix = vec![];
        for i in 0..min(path_1.len(), path_2.len()) {
            if path_1[i] == path_2[i] {
                common_prefix.push(path_1[i]);
            } else {
                break;
            }
        }
        common_prefix
    }

    fn reset_root(&mut self) {
        self.root_node = NodeType::Empty
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use db::InMemoryHashValueDb;
    use std::collections::HashMap;
    extern crate rand;
    use self::rand::{thread_rng, Rng};

    /// Create a new trie and db and return them
    fn get_new_sha3_rlp_trie_with_in_memory_db() -> (
        MerklePatriciaTrie<Vec<u8>, Vec<u8>, Vec<u8>, RLPSerializer, Sha3Hasher>,
        InMemoryHashValueDb<Vec<u8>>,
    ) {
        let hasher = Sha3Hasher {};
        let node_serz = RLPSerializer {};
        // Create a new trie
        let trie = MerklePatriciaTrie::new(hasher.clone(), node_serz.clone()).unwrap();
        // Create a new db
        let db = InMemoryHashValueDb::<Vec<u8>>::new();
        (trie, db)
    }

    #[test]
    fn node_serializer() {
        // test serialization/deserialization of all node types
        let serializer = RLPSerializer {};
        let node_0: NodeType<Vec<u8>, Vec<u8>> = NodeType::Empty;
        let node_0_s = serializer.serialize(node_0.clone()).unwrap();
        assert!(serializer.is_empty_root(&node_0_s));
        let node_0_d = serializer.deserialize(node_0_s).unwrap();
        assert_eq!(node_0_d, node_0);

        let node_1 = NodeType::Leaf(Leaf {
            path: vec![0, 1, 2],
            value: vec![6, 7, 8, 9],
        });
        let node_1_s = serializer.serialize(node_1.clone()).unwrap();
        assert!(!serializer.is_empty_root(&node_1_s));
        let node_1_d = serializer.deserialize(node_1_s).unwrap();
        assert_eq!(node_1_d, node_1);

        let hash = vec![2, 5, 9, 14, 19];

        let node_2 = NodeType::Extension(Extension {
            path: vec![0, 1, 2],
            key: HashOrBranch::Hash(hash.clone()),
        });
        let node_2_s = serializer.serialize(node_2.clone()).unwrap();
        assert!(!serializer.is_empty_root(&node_2_s));
        let node_2_d = serializer.deserialize(node_2_s).unwrap();
        assert_eq!(node_2_d, node_2);

        let mut path: [Box<HashOrNode<Vec<u8>, Vec<u8>>>; 16] = Default::default();
        path[1] = Box::new(HashOrNode::Hash(hash.clone()));
        path[4] = Box::new(HashOrNode::Node(NodeType::Leaf(Leaf {
            path: vec![3, 6, 13],
            value: vec![6, 7, 8, 9],
        })));
        path[11] = Box::new(HashOrNode::Node(NodeType::Extension(Extension {
            path: vec![4, 6, 9],
            key: HashOrBranch::Hash(hash.clone()),
        })));
        let branch = Branch {
            path,
            value: vec![6, 7, 8, 9],
        };
        let node_2 = NodeType::Extension(Extension {
            path: vec![0, 1, 2],
            key: HashOrBranch::Branch(branch),
        });
        let node_2_s = serializer.serialize(node_2.clone()).unwrap();
        assert!(!serializer.is_empty_root(&node_2_s));
        let node_2_d = serializer.deserialize(node_2_s).unwrap();
        assert_eq!(node_2_d, node_2);

        let mut path: [Box<HashOrNode<Vec<u8>, Vec<u8>>>; 16] = Default::default();
        path[0] = Box::new(HashOrNode::Hash(hash.clone()));
        path[3] = Box::new(HashOrNode::Node(NodeType::Leaf(Leaf {
            path: vec![0, 1, 2],
            value: vec![6, 7, 8, 9],
        })));
        path[9] = Box::new(HashOrNode::Node(NodeType::Extension(Extension {
            path: vec![0, 1, 2],
            key: HashOrBranch::Hash(hash.clone()),
        })));
        let node_3 = NodeType::Branch(Branch {
            path,
            value: vec![6, 7, 8, 9],
        });
        let node_3_s = serializer.serialize(node_3.clone()).unwrap();
        assert!(!serializer.is_empty_root(&node_3_s));
        let node_3_d = serializer.deserialize(node_3_s).unwrap();
        assert_eq!(node_3_d, node_3);
    }

    #[test]
    fn node_serializer_empty_key_or_values() {
        let serializer = RLPSerializer {};

        // leaf node with empty value
        let node_1 = NodeType::Leaf(Leaf {
            path: vec![0, 1, 2],
            value: vec![],
        });
        let node_1_s = serializer.serialize(node_1.clone()).unwrap();
        let node_1_d = serializer.deserialize(node_1_s).unwrap();
        assert_eq!(node_1_d, node_1);

        let hash = vec![2, 5, 9, 14, 19];

        // branch node with empty value and a leaf and extension node with empty key
        let mut path: [Box<HashOrNode<Vec<u8>, Vec<u8>>>; 16] = Default::default();
        path[0] = Box::new(HashOrNode::Hash(hash.clone()));
        path[3] = Box::new(HashOrNode::Node(NodeType::Leaf(Leaf {
            path: vec![],
            value: vec![6, 7, 8, 9],
        })));
        path[9] = Box::new(HashOrNode::Node(NodeType::Extension(Extension {
            path: vec![],
            key: HashOrBranch::Hash(hash.clone()),
        })));
        let node_3 = NodeType::Branch(Branch {
            path,
            value: vec![],
        });
        let node_3_s = serializer.serialize(node_3.clone()).unwrap();
        let node_3_d = serializer.deserialize(node_3_s).unwrap();
        assert_eq!(node_3_d, node_3);
    }

    #[test]
    fn node_serializer_nested_nodes() {
        // A branch node contains extension node which itself contains a branch node which itself contains an extension node
        let serializer = RLPSerializer {};

        let hash = vec![2, 5, 9, 14, 19];

        let inner_extension_node = NodeType::Extension(Extension {
            path: vec![0, 1, 2],
            key: HashOrBranch::Hash(hash.clone()),
        });

        let mut path: [Box<HashOrNode<Vec<u8>, Vec<u8>>>; 16] = Default::default();
        path[0] = Box::new(HashOrNode::Hash(hash.clone()));
        path[3] = Box::new(HashOrNode::Node(NodeType::Leaf(Leaf {
            path: vec![0, 1, 2],
            value: vec![6, 7, 8, 9],
        })));
        path[9] = Box::new(HashOrNode::Node(inner_extension_node));
        let inner_branch = Branch {
            path,
            value: vec![6, 7, 8, 9],
        };

        let mut path: [Box<HashOrNode<Vec<u8>, Vec<u8>>>; 16] = Default::default();
        path[1] = Box::new(HashOrNode::Hash(hash.clone()));
        path[4] = Box::new(HashOrNode::Node(NodeType::Leaf(Leaf {
            path: vec![3, 6, 13],
            value: vec![6, 7, 8, 9],
        })));
        path[11] = Box::new(HashOrNode::Node(NodeType::Extension(Extension {
            path: vec![4, 6, 9],
            key: HashOrBranch::Branch(inner_branch.clone()),
        })));
        let branch = Branch {
            path,
            value: vec![6, 7, 8, 9],
        };
        let outer_extension_node = NodeType::Extension(Extension {
            path: vec![0, 1, 2],
            key: HashOrBranch::Branch(branch),
        });

        let mut path: [Box<HashOrNode<Vec<u8>, Vec<u8>>>; 16] = Default::default();
        path[0] = Box::new(HashOrNode::Hash(hash.clone()));
        path[3] = Box::new(HashOrNode::Node(NodeType::Leaf(Leaf {
            path: vec![0, 1, 2],
            value: vec![6, 7, 8, 9],
        })));
        path[9] = Box::new(HashOrNode::Node(outer_extension_node));
        let outer_branch_node = NodeType::Branch(Branch {
            path,
            value: vec![6, 7, 8, 9],
        });

        let outer_branch_node_s = serializer.serialize(outer_branch_node.clone()).unwrap();
        let outer_branch_node_d = serializer.deserialize(outer_branch_node_s).unwrap();
        assert_eq!(outer_branch_node, outer_branch_node_d);
    }

    #[test]
    fn test_nibbles_bytes_conversion() {
        let n1 = vec![1, 2];
        let b1 = vec![18];
        assert_eq!(nibbles_to_bytes(&n1), b1);
        assert_eq!(bytes_to_nibbles(&b1), n1);

        let b2 = vec![1, 2, 9, 98];
        let n2 = vec![0, 1, 0, 2, 0, 9, 6, 2];
        assert_eq!(bytes_to_nibbles(&b2), n2);
        assert_eq!(nibbles_to_bytes(&n2), b2);
    }

    #[test]
    fn patricia_trie_sha3_rlp_updating_leaf_node() {
        let (mut trie, mut db) = get_new_sha3_rlp_trie_with_in_memory_db();
        let rh_1 = trie.get_root_hash().unwrap();

        // First update to the trie results in a leaf node
        let key = vec![1, 2, 9, 98];
        let value = vec![1, 2, 9, 98, 10, 230];
        let rh_2 = trie.insert(&key, value.clone(), &mut db).unwrap();
        assert_eq!(rh_2, trie.get_root_hash().unwrap());
        assert_ne!(rh_1, rh_2);
        assert!(trie.root_node.is_leaf());

        let v = trie.get(&key, &mut None, &db).unwrap();
        assert_eq!(v, value);

        // Update an existing key
        let value_1 = vec![9, 1, 2, 75, 89, 189, 250];
        let rh_3 = trie.insert(&key, value_1.clone(), &mut db).unwrap();
        assert_eq!(rh_3, trie.get_root_hash().unwrap());
        assert_ne!(rh_3, rh_2);
        assert!(trie.root_node.is_leaf());

        let v = trie.get(&key, &mut None, &db).unwrap();
        assert_eq!(v, value_1);

        // Update with a key that has no common prefix with the existing key
        let key_2 = vec![17, 6, 8];
        let value_2 = vec![2, 4, 5, 6];
        let rh_4 = trie.insert(&key_2, value_2.clone(), &mut db).unwrap();
        assert_eq!(rh_4, trie.get_root_hash().unwrap());
        assert_ne!(rh_4, rh_3);
        assert!(trie.root_node.is_branch());

        let v = trie.get(&key_2, &mut None, &db).unwrap();
        assert_eq!(v, value_2);

        // Create a new trie
        let (mut trie, mut db) = get_new_sha3_rlp_trie_with_in_memory_db();

        let key_3 = vec![1, 2, 9, 98];
        let value_3 = vec![1, 2, 9, 98, 10, 230];
        trie.insert(&key_3, value_3.clone(), &mut db).unwrap();

        // Update with a key that has a common prefix with the existing key but common prefix is
        // shorter than both keys
        let key_4 = vec![1, 6, 8];
        let value_4 = vec![2, 4, 5, 6];
        trie.insert(&key_4, value_4.clone(), &mut db).unwrap();
        assert!(trie.root_node.is_extension());

        let v = trie.get(&key_3, &mut None, &db).unwrap();
        assert_eq!(v, value_3);
        let v = trie.get(&key_4, &mut None, &db).unwrap();
        assert_eq!(v, value_4);

        // Create a new trie
        let (mut trie, mut db) = get_new_sha3_rlp_trie_with_in_memory_db();

        let key_5 = vec![1, 2, 9, 98];
        let value_5 = vec![1, 2, 9, 98, 10, 230];
        trie.insert(&key_5, value_5.clone(), &mut db).unwrap();

        // Update with a key that has a common prefix equal to the existing key, i.e. existing key is a prefix of new key
        let key_6 = vec![1, 2, 9, 98, 100];
        let value_6 = vec![2, 4, 5, 6];
        trie.insert(&key_6, value_6.clone(), &mut db).unwrap();
        assert!(trie.root_node.is_extension());

        let v = trie.get(&key_5, &mut None, &db).unwrap();
        assert_eq!(v, value_5);
        let v = trie.get(&key_6, &mut None, &db).unwrap();
        assert_eq!(v, value_6);

        // Create a new trie
        let (mut trie, mut db) = get_new_sha3_rlp_trie_with_in_memory_db();

        let key_7 = vec![1, 2, 9, 98];
        let value_7 = vec![1, 2, 9, 98, 10, 230];
        trie.insert(&key_7, value_7.clone(), &mut db).unwrap();

        // Update with a key which is a prefix of existing key
        let key_8 = vec![1, 2, 9];
        let value_8 = vec![2, 4, 5, 6];
        trie.insert(&key_8, value_8.clone(), &mut db).unwrap();
        assert!(trie.root_node.is_extension());

        let v = trie.get(&key_7, &mut None, &db).unwrap();
        assert_eq!(v, value_7);
        let v = trie.get(&key_8, &mut None, &db).unwrap();
        assert_eq!(v, value_8);
    }

    #[test]
    fn patricia_trie_sha3_rlp_updating_extension_node() {
        let (mut trie, mut db) = get_new_sha3_rlp_trie_with_in_memory_db();

        // keys have a common prefix but prefix is smaller than both keys
        let key_1 = vec![1, 2, 9, 98];
        let value_1 = vec![1, 2, 9, 98, 10, 230];
        trie.insert(&key_1, value_1.clone(), &mut db).unwrap();

        let key_2 = vec![1, 17, 8];
        let value_2 = vec![2, 4, 5, 6];
        trie.insert(&key_2, value_2.clone(), &mut db).unwrap();

        assert_eq!(trie.get(&key_1, &mut None, &db).unwrap(), value_1);
        assert_eq!(trie.get(&key_2, &mut None, &db).unwrap(), value_2);

        match &trie.root_node {
            NodeType::<Vec<u8>, Vec<u8>>::Extension(ext_node) => match &ext_node.key {
                HashOrBranch::Branch(b) => {
                    for (i, p) in b.path.to_vec().into_iter().enumerate() {
                        match *p {
                            HashOrNode::Node(n) => match n {
                                NodeType::<Vec<u8>, Vec<u8>>::Empty => {
                                    if i == 0 || i == 1 {
                                        panic!("Node should have been a leaf but was empty")
                                    }
                                }
                                NodeType::<Vec<u8>, Vec<u8>>::Leaf(_) => {
                                    if i != 0 && i != 1 {
                                        panic!("Node should have been empty but was leaf")
                                    }
                                }
                                _ => panic!("Node should have been either leaf or empty"),
                            },
                            HashOrNode::Hash(_) => panic!("Should have been a node and not hash"),
                        }
                    }
                    assert!(b.value.is_empty())
                }
                _ => panic!("inner node should be branch but wasn't"),
            },
            _ => panic!("root node should be extension but wasn't"),
        }

        // key same as the common prefix
        let key_3 = vec![1];
        let value_3 = vec![2, 4, 5, 7, 8];
        trie.insert(&key_3, value_3.clone(), &mut db).unwrap();
        assert!(trie.root_node.is_extension());

        assert_eq!(trie.get(&key_3, &mut None, &db).unwrap(), value_3);

        let (mut trie, mut db) = get_new_sha3_rlp_trie_with_in_memory_db();

        // keys have a common prefix but prefix is smaller than both keys
        let key_4 = vec![1, 2, 9, 98];
        let value_4 = vec![1, 2, 9, 98, 10, 230];
        trie.insert(&key_4, value_4.clone(), &mut db).unwrap();

        let key_5 = vec![1, 2, 10];
        let value_5 = vec![2, 4, 5, 6];
        trie.insert(&key_5, value_5.clone(), &mut db).unwrap();

        // key longer than the common prefix
        let key_6 = vec![1, 2, 3];
        let value_6 = vec![2, 4, 5, 7, 8];
        trie.insert(&key_6, value_6.clone(), &mut db).unwrap();

        assert!(trie.root_node.is_extension());

        assert_eq!(trie.get(&key_4, &mut None, &db).unwrap(), value_4);
        assert_eq!(trie.get(&key_5, &mut None, &db).unwrap(), value_5);
        assert_eq!(trie.get(&key_6, &mut None, &db).unwrap(), value_6);
    }

    fn get_random_key_vals(
        num_keys: usize,
        min_key_size: usize,
        max_key_size: usize,
        min_val_size: usize,
        max_val_size: usize,
    ) -> HashMap<Vec<u8>, Vec<u8>> {
        let mut key_vals = HashMap::<Vec<u8>, Vec<u8>>::new();
        let mut rng = thread_rng();
        for _ in 0..num_keys {
            let key_size = rng.gen_range(min_key_size, max_key_size);
            let value_size = rng.gen_range(min_val_size, max_val_size);
            let mut key = Vec::<u8>::with_capacity(key_size);
            let mut value = Vec::<u8>::with_capacity(value_size);
            for _ in 0..key_size {
                key.push(rng.gen_range(0, 255));
            }
            for _ in 0..value_size {
                value.push(rng.gen_range(0, 255));
            }
            key_vals.insert(key, value);
        }
        key_vals
    }

    fn check_val_and_proof(
        trie: &MerklePatriciaTrie<Vec<u8>, Vec<u8>, Vec<u8>, RLPSerializer, Sha3Hasher>,
        root_hash: &Vec<u8>,
        key: &Vec<u8>,
        val: &Vec<u8>,
        db: &InMemoryHashValueDb<Vec<u8>>,
    ) {
        let mut proof_nodes = Vec::<NodeType<Vec<u8>, Vec<u8>>>::new();
        let mut proof = Some(proof_nodes);
        assert_eq!(trie.get(key, &mut proof, db).unwrap(), *val);
        proof_nodes = proof.unwrap();
        let mut temp_db = InMemoryHashValueDb::<Vec<u8>>::new();
        assert!(MerklePatriciaTrie::verify_proof(
            key,
            val,
            proof_nodes,
            Sha3Hasher {},
            RLPSerializer {},
            root_hash,
            &mut temp_db
        )
        .unwrap());
    }

    fn check_multi_key_proof(
        root_hash: &Vec<u8>,
        proof_nodes: Vec<NodeType<Vec<u8>, Vec<u8>>>,
        key_vals: Vec<(Vec<u8>, Vec<u8>)>,
    ) {
        let mut temp_db = InMemoryHashValueDb::<Vec<u8>>::new();
        let mut keys = vec![];
        let mut values = vec![];
        for (k, v) in &key_vals {
            keys.push(k as &dyn Key);
            values.push(v.clone());
        }

        assert!(MerklePatriciaTrie::verify_proof_multiple_keys(
            keys,
            &values,
            proof_nodes,
            Sha3Hasher {},
            RLPSerializer {},
            root_hash,
            &mut temp_db
        )
        .unwrap());
    }

    #[test]
    fn patricia_trie_sha3_rlp_proof() {
        let num_keys = 1000;
        let key_vals = get_random_key_vals(num_keys, 2, 50, 5, 500);
        let (mut trie, mut db) = get_new_sha3_rlp_trie_with_in_memory_db();
        for key in key_vals.keys() {
            let val = &key_vals[key];
            let rh = trie.insert(key, val.clone(), &mut db).unwrap();
            check_val_and_proof(&trie, &rh, key, val, &db);
        }
        let root_hash_after_update = trie.get_root_hash().unwrap();

        for key in key_vals.keys() {
            let val = &key_vals[key];
            check_val_and_proof(&trie, &root_hash_after_update, key, val, &db);
        }
    }

    #[test]
    fn patricia_trie_sha3_rlp_random_vals() {
        let (mut trie, mut db) = get_new_sha3_rlp_trie_with_in_memory_db();
        let test_cases = 10000;

        for (min_key_size, max_key_size, min_val_size, max_val_size) in
            vec![(10, 20, 30, 80), (20, 40, 40, 100), (40, 150, 100, 300)]
        {
            let key_vals = get_random_key_vals(
                test_cases,
                min_key_size,
                max_key_size,
                min_val_size,
                max_val_size,
            );
            for key in key_vals.keys() {
                let val = &key_vals[key];
                let rh = trie.insert(key, val.clone(), &mut db).unwrap();
                check_val_and_proof(&trie, &rh, key, val, &db);
            }

            let root_hash_after_update = trie.get_root_hash().unwrap();

            for key in key_vals.keys() {
                let val = &key_vals[key];
                check_val_and_proof(&trie, &root_hash_after_update, key, val, &db);
            }
        }
    }

    #[test]
    fn patricia_trie_sha3_rlp_init() {
        // Create a trie and update it with some key vals. Then initialize a new trie with the older
        // trie's root and database and check that this new trie contains all key-values of the old trie

        let num_keys = 100;
        let key_vals = get_random_key_vals(num_keys, 2, 50, 5, 500);
        let (mut trie, mut db) = get_new_sha3_rlp_trie_with_in_memory_db();

        for key in key_vals.keys() {
            let val = &key_vals[key];
            trie.insert(key, val.clone(), &mut db).unwrap();
            assert_eq!(trie.get(key, &mut None, &db).unwrap(), *val);
        }

        let root_hash_after_update = trie.get_root_hash().unwrap();

        let hasher = Sha3Hasher {};
        let node_serz = RLPSerializer {};
        // Create a new trie but with old trie's db and root hash
        let new_trie = MerklePatriciaTrie::initialize_with_root_hash(
            hasher.clone(),
            node_serz.clone(),
            &root_hash_after_update,
            &mut db,
        )
        .unwrap();

        assert_eq!(new_trie.get_root_hash().unwrap(), root_hash_after_update);

        for key in key_vals.keys() {
            let val = &key_vals[key];
            assert_eq!(new_trie.get(key, &mut None, &db).unwrap(), *val);
        }
    }

    #[test]
    fn patricia_trie_sha3_rlp_get_key_vals() {
        // Update a trie with some key values and then get all key values from trie and check
        // that they match the original key values.

        let num_keys = 1000;
        let key_vals = get_random_key_vals(num_keys, 2, 80, 5, 500);
        let (mut trie, mut db) = get_new_sha3_rlp_trie_with_in_memory_db();

        for key in key_vals.keys() {
            trie.insert(key, key_vals[key].clone(), &mut db).unwrap();
        }

        let mut proof_nodes = Vec::<NodeType<Vec<u8>, Vec<u8>>>::new();
        let mut proof = Some(proof_nodes);
        let key_vals_from_trie = trie
            .get_key_values::<Vec<u8>>(&trie.root_node, &mut proof, &db, &nibbles_to_bytes)
            .unwrap();
        assert_eq!(key_vals_from_trie.len(), num_keys);
        for (k, v) in &key_vals_from_trie {
            assert_eq!(key_vals[k], *v)
        }

        // verify proof
        let root_hash = trie.get_root_hash().unwrap();
        proof_nodes = proof.unwrap();
        check_multi_key_proof(&root_hash, proof_nodes, key_vals_from_trie)
    }

    fn check_prefix(
        trie: &MerklePatriciaTrie<Vec<u8>, Vec<u8>, Vec<u8>, RLPSerializer, Sha3Hasher>,
        root_hash: &Vec<u8>,
        prefix: &Vec<u8>,
        num_keys: usize,
        all_key_vals: &HashMap<Vec<u8>, Vec<u8>>,
        db: &InMemoryHashValueDb<Vec<u8>>,
    ) {
        let mut proof_nodes = Vec::<NodeType<Vec<u8>, Vec<u8>>>::new();
        let mut proof = Some(proof_nodes);

        let key_vals_with_prefix = trie
            .get_keys_values_with_prefix::<Vec<u8>>(
                prefix,
                &trie.root_node,
                &mut proof,
                db,
                &nibbles_to_bytes,
            )
            .unwrap();
        assert_eq!(key_vals_with_prefix.len(), num_keys / 3);
        for (k, v) in &key_vals_with_prefix {
            assert!(k.starts_with(prefix));
            assert_eq!(all_key_vals[k], *v);
        }

        // verify proof
        proof_nodes = proof.unwrap();
        check_multi_key_proof(&root_hash, proof_nodes, key_vals_with_prefix)
    }

    #[test]
    fn patricia_trie_sha3_rlp_get_prefix_key_vals() {
        // Update a trie with key values where some keys have common prefix and
        // then get keys with that prefix

        let num_keys = 3000;
        let _key_vals = get_random_key_vals(num_keys, 2, 80, 5, 500);

        // Add prefixes to some of the key values
        let prefix_1 = vec![1, 4, 15];
        let prefix_2 = vec![2, 6, 7, 8];
        let prefix_3 = vec![7, 8, 9, 10, 11];
        let mut key_vals = HashMap::<Vec<u8>, Vec<u8>>::new();
        let mut i = 0;
        for (mut k, v) in _key_vals {
            let mut new_key = if i % 3 == 0 {
                prefix_1.clone()
            } else if i % 3 == 1 {
                prefix_2.clone()
            } else {
                prefix_3.clone()
            };
            new_key.append(&mut k);
            key_vals.insert(new_key, v);
            i += 1;
        }

        let (mut trie, mut db) = get_new_sha3_rlp_trie_with_in_memory_db();
        for key in key_vals.keys() {
            trie.insert(key, key_vals[key].clone(), &mut db).unwrap();
        }

        let root_hash = trie.get_root_hash().unwrap();

        check_prefix(&trie, &root_hash, &prefix_1, num_keys, &key_vals, &db);

        check_prefix(&trie, &root_hash, &prefix_2, num_keys, &key_vals, &db);

        check_prefix(&trie, &root_hash, &prefix_3, num_keys, &key_vals, &db);
    }
}
