use crate::errors::{MerkleTreeError, MerkleTreeErrorKind};
use num_bigint::BigUint;
use std::collections::HashMap;
use std::iter::FromIterator;

/// Database to map hashes to values (H -> V)
/// `H` is the type for the hash
/// `V` is the type for the value
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
pub mod unqlite_db {
    /// Testing implementation for unqlite db
    use super::{HashValueDb, MerkleTreeError, MerkleTreeErrorKind};

    extern crate unqlite;
    use unqlite::{Config, Cursor, UnQLite, KV};

    pub struct UnqliteHashValueDb {
        db_name: String,
        db: UnQLite,
    }

    impl UnqliteHashValueDb {
        pub fn new(db_name: String) -> Self {
            // XXX: A real implementation will have error handling here
            let db = UnQLite::create(&db_name);
            Self { db_name, db }
        }
    }

    impl HashValueDb<Vec<u8>, Vec<u8>> for UnqliteHashValueDb {
        fn put(&mut self, hash: Vec<u8>, value: Vec<u8>) -> Result<(), MerkleTreeError> {
            // XXX: A real implementation will have error handling here
            self.db.kv_store(&hash, &value).unwrap();
            Ok(())
        }

        fn get(&self, hash: &Vec<u8>) -> Result<Vec<u8>, MerkleTreeError> {
            self.db.kv_fetch(hash).map_err(|_| {
                MerkleTreeError::from_kind(MerkleTreeErrorKind::HashNotFoundInDB {
                    hash: hash.to_vec(),
                })
            })
        }
    }
}

#[cfg(test)]
pub mod rusqlite_db {
    /// Testing implementation for sqlite
    use super::{HashValueDb, MerkleTreeError, MerkleTreeErrorKind};

    extern crate rusqlite;
    use rusqlite::{params, Connection, NO_PARAMS};

    pub struct RusqliteHashValueDb {
        db_path: String,
        pub table_name: String,
        pub db_conn: Connection,
    }

    impl RusqliteHashValueDb {
        pub fn new(db_path: String, table_name: String) -> Self {
            // XXX: A real implementation will have error handling here
            let db_conn = Connection::open(&db_path).unwrap();
            let sql = format!(
                "create table if not exists {} (key string primary key, value blob not null)",
                table_name
            );
            db_conn.execute(&sql, NO_PARAMS).unwrap();
            Self {
                db_path,
                table_name,
                db_conn,
            }
        }

        pub fn hash_to_hex(hash: &Vec<u8>) -> String {
            format!("{:x?}", hash)
                .replace(", ", "")
                .replace("[", "")
                .replace("]", "")
        }
    }

    impl HashValueDb<Vec<u8>, Vec<u8>> for RusqliteHashValueDb {
        fn put(&mut self, hash: Vec<u8>, value: Vec<u8>) -> Result<(), MerkleTreeError> {
            let hash_hex = Self::hash_to_hex(&hash);
            let sql = format!(
                "insert into {} (key, value) values (?1, ?2)",
                self.table_name
            );
            // XXX: A real implementation will have error handling here
            self.db_conn
                .execute(&sql, params![hash_hex, value])
                .unwrap();
            Ok(())
        }

        fn get(&self, hash: &Vec<u8>) -> Result<Vec<u8>, MerkleTreeError> {
            let sql = format!(
                "select value from {} where key='{}'",
                self.table_name,
                Self::hash_to_hex(hash)
            );
            self.db_conn
                .query_row(&sql, NO_PARAMS, |row| row.get(0))
                .map_err(|_| {
                    MerkleTreeError::from_kind(MerkleTreeErrorKind::HashNotFoundInDB {
                        hash: hash.to_vec(),
                    })
                })
        }
    }
}

#[cfg(test)]
pub mod sled_db {
    /// Testing implementation for sled
    use super::{HashValueDb, MerkleTreeError, MerkleTreeErrorKind};

    extern crate sled;
    use self::sled::{Config, Db};
    use crate::sha2::{Digest, Sha256};
    use std::marker::PhantomData;

    pub struct SledHashDb {
        config: Config,
        db: Db,
    }

    impl SledHashDb {
        pub fn new() -> Self {
            let config = Config::new().temporary(true);
            let db = config.open().unwrap();
            Self { config, db }
        }
    }

    impl HashValueDb<Vec<u8>, Vec<u8>> for SledHashDb {
        fn put(&mut self, hash: Vec<u8>, value: Vec<u8>) -> Result<(), MerkleTreeError> {
            // XXX: A real implementation will have error handling here
            self.db.insert(hash, value);
            Ok(())
        }

        fn get(&self, hash: &Vec<u8>) -> Result<Vec<u8>, MerkleTreeError> {
            match self.db.get(hash) {
                Ok(Some(ivec)) => Ok(ivec.to_vec()),
                _ => Err(MerkleTreeErrorKind::HashNotFoundInDB {
                    hash: hash.to_vec(),
                }
                .into()),
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sha2::{Digest, Sha256};
    use std::fs;

    fn check_db_put_get(db: &mut HashValueDb<Vec<u8>, Vec<u8>>) {
        let data_1 = "Hello world!".as_bytes().to_vec();
        let mut hasher = Sha256::new();
        hasher.input(&data_1);
        let hash_1 = hasher.result().to_vec();
        db.put(hash_1.clone(), data_1.clone()).unwrap();
        assert_eq!(db.get(&hash_1).unwrap(), data_1);

        let data_2 = "Byte!".as_bytes().to_vec();
        let mut hasher = Sha256::new();
        hasher.input(&data_2);
        let hash_2 = hasher.result().to_vec();

        assert!(db.get(&hash_2).is_err());
        db.put(hash_2.clone(), data_2.clone()).unwrap();
        assert_eq!(db.get(&hash_2).unwrap(), data_2);
    }

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

    #[test]
    fn test_unqlite_db_string_val() {
        let db_name = "unqlite_test.db";
        fs::remove_file(db_name);

        let mut db = unqlite_db::UnqliteHashValueDb::new(String::from(db_name));

        check_db_put_get(&mut db);
    }

    #[test]
    fn test_rusqlite_db_string_val() {
        let db_path = "./rusqlite_test.db";
        fs::remove_file(db_path);

        let mut db =
            rusqlite_db::RusqliteHashValueDb::new(String::from(db_path), String::from("kv_table"));

        check_db_put_get(&mut db);
    }

    #[test]
    fn test_sled_db_string_val() {
        let mut db = sled_db::SledHashDb::new();

        check_db_put_get(&mut db);
    }
}
