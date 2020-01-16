# Merkle trees in Rust

The nodes are abstract, i.e. leaf and node. The hash is abstract. The tree storage is abstract
Write the sparse merkle tree as a macro to generate trees of any power of 2 arity.
Domain separation while hashing leaves and nodes.

1. [Vanilla (inefficient) sparse merkle tree](./src/vanilla_sparse_merkle_tree.rs)
1. [Sparse merkle tree](./src/sparse_merkle_tree.rs) with optimizations from V. Buterin  
1. [Ethereum's Merkle Patricia trie](./src/merkle_patricia_trie.rs)
1. [Compact merkle tree](./src/compact_merkle_tree.rs) as described by Google's certificate transparency.

## TODO
1. Make each tree usable as a feature.