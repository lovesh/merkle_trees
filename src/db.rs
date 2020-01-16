use crate::errors::{MerkleTreeError, MerkleTreeErrorKind};
use num_bigint::BigUint;
use std::collections::HashMap;
use std::iter::FromIterator;

/// Database to map hashes to values (H -> V)
pub trait HashValueDb<H, V: Clone> {
    fn put(&mut self, hash: H, value: V) -> Result<(), MerkleTreeError>;

    fn get(&self, hash: &H) -> Result<V, MerkleTreeError>;
}

/// Uses an in-memory hashmap and assumes the hash is bytes
#[derive(Clone, Debug)]
pub struct InMemoryHashValueDb<V: Clone> {
    db: HashMap<Vec<u8>, V>,
}

impl<V: Clone> HashValueDb<Vec<u8>, V> for InMemoryHashValueDb<V> {
    fn put(&mut self, hash: Vec<u8>, value: V) -> Result<(), MerkleTreeError> {
        self.db.insert(hash, value);
        Ok(())
    }

    fn get(&self, hash: &Vec<u8>) -> Result<V, MerkleTreeError> {
        match self.db.get(hash) {
            Some(val) => Ok(val.clone()),
            None => Err(MerkleTreeErrorKind::HashNotFoundInDB {
                hash: hash.to_vec(),
            }
            .into()),
        }
    }
}

impl<T: Clone> InMemoryHashValueDb<T> {
    pub fn new() -> Self {
        let db = HashMap::<Vec<u8>, T>::new();
        Self { db }
    }
}

// XXX: This is duplicated from above InMemoryHashValueDb. Find a better way!!. Making the type H of HashValueDb
// as a iterator over bytes is not an option since such an iterator over BigUint does not exist
#[derive(Clone, Debug)]
pub struct InMemoryBigUintHashDb<V: Clone> {
    db: HashMap<Vec<u8>, V>,
}

impl<V: Clone> HashValueDb<BigUint, V> for InMemoryBigUintHashDb<V> {
    fn put(&mut self, hash: BigUint, value: V) -> Result<(), MerkleTreeError> {
        self.db.insert(hash.to_bytes_be(), value);
        Ok(())
    }

    fn get(&self, hash: &BigUint) -> Result<V, MerkleTreeError> {
        let b = hash.to_bytes_be();
        match self.db.get(&b) {
            Some(val) => Ok(val.clone()),
            None => Err(MerkleTreeErrorKind::HashNotFoundInDB { hash: b }.into()),
        }
    }
}

impl<T: Clone> InMemoryBigUintHashDb<T> {
    pub fn new() -> Self {
        let db = HashMap::<Vec<u8>, T>::new();
        Self { db }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sha2::{Digest, Sha256};

    #[test]
    fn test_in_memory_db_string_val() {
        let mut db = InMemoryHashValueDb::<String>::new();
        let data_1 = String::from("Hello world!");
        let mut hasher = Sha256::new();
        hasher.input(data_1.as_bytes());
        let hash_1 = hasher.result().to_vec();
        db.put(hash_1.clone(), data_1.clone()).unwrap();
        assert_eq!(db.get(&hash_1).unwrap(), data_1);

        let data_2 = String::from("Byte!");
        let mut hasher = Sha256::new();
        hasher.input(data_2.as_bytes());
        let hash_2 = hasher.result().to_vec();

        assert!(db.get(&hash_2).is_err());
        db.put(hash_2.clone(), data_2.clone()).unwrap();
        assert_eq!(db.get(&hash_2).unwrap(), data_2);
    }
}
