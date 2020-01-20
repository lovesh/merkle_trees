# Merkle trees in Rust

Various kinds of merkle trees with hash function and tree storage abstracted.

1. [Vanilla (inefficient) sparse merkle tree](./src/vanilla_sparse_merkle_tree.rs)
1. [Sparse merkle tree](./src/sparse_merkle_tree.rs) with optimizations from V. Buterin  
1. [Ethereum's Merkle Patricia trie](./src/merkle_patricia_trie.rs)
1. [Compact merkle tree](./src/compact_merkle_tree.rs) as described by Google's certificate transparency.


## Hashing

The hash function is abstract such that a hash function like SHA-2, SHA-3 or an algebraic hash function like MiMC can be 
used. For a binary tree, this is the hasher's trait

```rust
/// To be used with a binary tree
/// `D` is the type of data the leaf has, like a string or a big number, etc.
/// `H` is the type for the hash
pub trait Arity2Hasher<D, H> {
    /// Hash the given leaf data to get the leaf hash
    fn hash_leaf_data(&self, leaf: D) -> Result<H, MerkleTreeError>;
    
    /// Hash 2 adjacent nodes (leaves or inner nodes) to get their root hash
    fn hash_tree_nodes(&self, left_node: H, right_node: H) -> Result<H, MerkleTreeError>;
}
```

For a 4-ary tree, this is the hasher's trait
```rust
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
```

Say, i need to use SHA-256 in a binary merkle tree, then such an implementation can be used
```rust
pub struct Sha256Hasher {
    .....
}

/// When SHA-256 is used for hashing in a binary merkle tree
impl Arity2Hasher<&str, Vec<u8>> for Sha256Hasher {
    fn hash_leaf_data(&self, leaf: &str) -> Result<Vec<u8>, MerkleTreeError> {
        ....
    }

    fn hash_tree_nodes(
        &self,
        left_node: Vec<u8>,
        right_node: Vec<u8>,
    ) -> Result<Vec<u8>, MerkleTreeError> {
        ....
    }
}
```

When using SHA-256 in a 4-ary tree, similar implementation can be used
```rust
/// When SHA-256 is used for hashing in a 4-ary merkle tree
impl Arity4Hasher<&str, Vec<u8>> for Sha256Hasher {
    fn hash_leaf_data(&self, leaf: &str) -> Result<Vec<u8>, MerkleTreeError> {
        ....
    }

    fn hash_tree_nodes(
        &self,
        node_0: Vec<u8>,
        node_1: Vec<u8>,
        node_2: Vec<u8>,
        node_3: Vec<u8>,
    ) -> Result<Vec<u8>, MerkleTreeError> {
        ....
    }
}
```

Similarly, other hash functions can be used. For demonstration, an implementation of `Arity2Hasher` with algebraic hash function 
MiMC is present as well. MiMC is useful when using merkle trees in various SNARKs constructions where the data to hash and the 
hash output are big numbers.
```rust
/// When MiMC is used for hashing in a merkle tree
pub struct MiMCHasher {
    ...
}

/// When MiMC is used for hashing in a binary merkle tree
impl Arity2Hasher<BigUint, BigUint> for MiMCHasher {
    fn hash_leaf_data(&self, leaf: BigUint) -> Result<BigUint, MerkleTreeError> {
        ...
    }

    fn hash_tree_nodes(
        &self,
        left_node: BigUint,
        right_node: BigUint,
    ) -> Result<BigUint, MerkleTreeError> {
        ....
    }
}
```

## Database
The database needs to support a key-value style CRU (create, read, update) operations, hence the trait `HashValueDb` is provided.
```rust
/// Database to map hashes to values (H -> V)
/// `H` is the type for the hash
/// `V` is the type for the value
pub trait HashValueDb<H, V: Clone> {
    fn put(&mut self, hash: H, value: V) -> Result<(), MerkleTreeError>;

    fn get(&self, hash: &H) -> Result<V, MerkleTreeError>;
}
```

For most of the testing an in-memory implementation is used which keeps a `HashMap`. Since most of the code uses SHA-2 or SHA-3, 
the hash output can be treated as bytes  
```rust
/// Uses an in-memory hashmap and assumes the hash is bytes
#[derive(Clone, Debug)]
pub struct InMemoryHashValueDb<V: Clone> {
    db: HashMap<Vec<u8>, V>,
}

impl<V: Clone> HashValueDb<Vec<u8>, V> for InMemoryHashValueDb<V> {
    fn put(&mut self, hash: Vec<u8>, value: V) -> Result<(), MerkleTreeError> {
        ...
    }

    fn get(&self, hash: &Vec<u8>) -> Result<V, MerkleTreeError> {
        ...
    }
}
```

An implementation that assumes the hash output to be big numbers (like when MiMC is used) can be supported as well
```rust
impl<V: Clone> HashValueDb<BigUint, V> for InMemoryBigUintHashDb<V> {
    fn put(&mut self, hash: BigUint, value: V) -> Result<(), MerkleTreeError> {
        ...
    }

    fn get(&self, hash: &BigUint) -> Result<V, MerkleTreeError> {
        ...
    }
}
```

For demonstration, `HashValueDb` is implemented for persistent some databases as well like sqlite.
```rust
/// Testing implementation for sqlite
pub struct RusqliteHashValueDb {
    ...
}

impl HashValueDb<Vec<u8>, Vec<u8>> for RusqliteHashValueDb {
    fn put(&mut self, hash: Vec<u8>, value: Vec<u8>) -> Result<(), MerkleTreeError> {
        ...
    }

    fn get(&self, hash: &Vec<u8>) -> Result<Vec<u8>, MerkleTreeError> {
        ...
    }
}
```

## Leaves in sparse merkle tree
Since sparse merkle trees have huge number of leaves (with most being empty) like 2^32 or 2^64 or 2^256, Rust's native 
datatypes like u32 or u64 or u128 might not be enough so the leaf index is abstracted as well with a trait `LeafIndex`
```rust
pub trait LeafIndex {
    /// Path from root to leaf
    fn to_leaf_path(&self, arity: u8, tree_depth: usize) -> Vec<u8>;
}
```

Say the sparse merkle tree can have at most 2^64 leaves. Then a u64 type is sufficient for being used to index leaves.
```rust
/// When sparse merkle tree can have 2^64 leaves at max
impl LeafIndex for u64 {
    /// Returns the representation of the `u64` as a byte array in MSB form
    fn to_leaf_path(&self, arity: u8, tree_depth: usize) -> Vec<u8> {
        ....   
    }
}
``` 

Say the sparse merkle tree has > 2^128 leaves. The a `BigUint` or another big number type will be required to index leaves
```rust
/// When sparse merkle tree can have arbitrary number (usually > 2^128) of leaves
impl LeafIndex for BigUint {
    /// Returns the representation of the `BigUint` as a byte array in MSB form
    fn to_leaf_path(&self, arity: u8, tree_depth: usize) -> Vec<u8> {
        ....
    }
}
```

## Trees
1. Vanilla sparse merkle trees.
These sparse merkle trees do not perform any optimizations to use the fact that most leaves are empty. They are useful when using SNARKs. 
2 variations, binary and 4-ary are present. `VanillaBinarySparseMerkleTree<D: Clone, H: Clone, MTH>` and 
`VanillaArity4SparseMerkleTree<D: Clone, H: Clone, MTH>`. The types `D`, `H` and `MTH` correspond to the types of data, hash
and merkle tree hasher. Have a look at the tests for their usage.

1. Sparse merkle tree
The have several optimizations over the vanilla ones. Only a binary sparse merkle tree is present for now `BinarySparseMerkleTree<D: Clone, H: Clone, MTH>`.
The types have the same meaning as for the vanilla tree. Look at the tests for usage.

1. Merkle Patricia trie
Ethereum's merkle patricia trie . Apart from the hash function and storage, the node serialization is abstract as well `PatriciaTrieNodeSerializer`.
There is only one implementation of the serialization which is RLP (same as Ethereum) as of now. Look at the tests for usage.
    ```rust
    /// The type `V` is for the value of the data being stored in the trie.
    /// The type `H` is for the hash output
    /// The type `S` is for the serialized (node) output
    #[derive(Clone, Debug, Serialize, Deserialize)]
    pub struct MerklePatriciaTrie<V, H, S: Clone + KnownLength, NS, NH>
    where
        NS: PatriciaTrieNodeSerializer<H, V, S>,
        NH: NodeHasher<S, H>,
    {
        ....
    }
    ```
1. Compact merkle tree.
Append only merkle tree used in Google's certificate transparency and Hyperledger Indy's ledger. 
`CompactMerkleTree<D: Clone, H: Clone, MTH> where MTH: Arity2Hasher<D, H>`

## TODO
1. Make each tree usable as a feature.
1. Write the sparse merkle tree as a macro to generate trees of any power of 2 arity.