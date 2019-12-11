use failure::{Backtrace, Context, Fail};
use std::fmt;

#[derive(Clone, Eq, PartialEq, Debug, Fail)]
pub enum MerkleTreeErrorKind {
    /// Occurs when the hash is not found in the database. Relevant to databases implementing `HashValueDb`
    /// trait. The hash is usually the merkle tree hash
    #[fail(display = "Expected to find hash {:?} in the database.", hash)]
    HashNotFoundInDB { hash: Vec<u8> },

    #[fail(display = "Expected to find leaf index {:?} in the database.", index)]
    LeafIndexNotFoundInDB { index: u64 },

    #[fail(display = "Expected to find node index {:?} in the database.", index)]
    NodeIndexNotFoundInDB { index: u64 },

    #[fail(display = "Incorrect flag {:?} for RLP node", flag)]
    IncorrectFlagForRLPNode { flag: u8 },

    #[fail(display = "Cannot deserialize using RLP. Error: {:?}", msg)]
    CannotDeserializeWithRLP { msg: String },

    #[fail(display = "Incorrect node type. Error: {:?}", msg)]
    IncorrectNodeType { msg: String },

    #[fail(display = "Querying an empty tree")]
    CannotQueryEmptyTree,

    #[fail(display = "Trie does not have any key with given prefix")]
    NoKeyWithPrefixInTrie,

    #[fail(display = "Need equal number of keys and values, no of keys={}, no of values={}", num_keys, num_values)]
    UnequalNoOfKeysAndValues {num_keys: usize, num_values: usize},

    #[fail(display = "Not found in tree")]
    NotFoundInTree,

    #[fail(display = "Provide at least one leaf")]
    NoLeafProvided,

    #[fail(
        display = "Tree size should be at least {} but was {}",
        expected, given
    )]
    TreeSmallerThanExpected { expected: u64, given: u64 },

    #[fail(
        display = "Inclusion proof should be of size {} but was of size {}",
        expected, given
    )]
    ShorterInclusionProof { expected: u8, given: u8 },

    #[fail(display = "Error while inserting subtree: {:?}", msg)]
    ErrorInsertingSubtree { msg: String },

    #[fail(display = "End should be ahead of start, end={}, start={}", to, from)]
    IncorrectSpan { from: u64, to: u64 },

    #[fail(
        display = "Trying to get a consistency proof of larger tree from a shorter tree, new tree size = {}, old tree size = {}",
        new, old
    )]
    ConsistencyProofIncorrectTreeSize { old: u64, new: u64 },

    #[fail(
        display = "Consistency proof is needed only when the trees involved have at least one leaf"
    )]
    ConsistencyProofWithEmptyTree,

    #[fail(
        display = "Consistency proof should be of size {} but was of size {}",
        expected, given
    )]
    ShorterConsistencyProof { expected: u8, given: u8 },

    #[fail(display = "Old root does not match the root calculated from consistency proof")]
    InconsistentOldRoot,

    #[fail(display = "New root does not match the root calculated from consistency proof")]
    InconsistentNewRoot,
}

#[derive(Debug)]
pub struct MerkleTreeError {
    inner: Context<MerkleTreeErrorKind>,
}

impl MerkleTreeError {
    pub fn kind(&self) -> MerkleTreeErrorKind {
        self.inner.get_context().clone()
    }

    pub fn from_kind(kind: MerkleTreeErrorKind) -> Self {
        Self {
            inner: Context::new("").context(kind),
        }
    }
}

impl From<MerkleTreeErrorKind> for MerkleTreeError {
    fn from(kind: MerkleTreeErrorKind) -> Self {
        Self {
            inner: Context::new(kind),
        }
    }
}

impl From<Context<MerkleTreeErrorKind>> for MerkleTreeError {
    fn from(inner: Context<MerkleTreeErrorKind>) -> Self {
        Self { inner }
    }
}

impl Fail for MerkleTreeError {
    fn cause(&self) -> Option<&dyn Fail> {
        self.inner.cause()
    }

    fn backtrace(&self) -> Option<&Backtrace> {
        self.inner.backtrace()
    }
}

impl fmt::Display for MerkleTreeError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        fmt::Display::fmt(&self.inner, f)
    }
}
