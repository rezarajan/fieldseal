//! RFC 9162 Merkle trees (PUB-051, PUB-054): leaf and node hashes, inclusion and
//! consistency proofs, and their verification.
//!
//! Verification follows RFC 9162 §2.1.3.2 and §2.1.4.2 exactly. Proof generation is here
//! too, so the in-memory log and test fixtures build the same trees a public log does.

use fieldseal_kernel::digest::sha256_parts;
use fieldseal_kernel::id::Digest;

/// The longest audit or consistency path accepted: a tree of 2⁶⁴ leaves needs at most 64
/// hashes (twice that for consistency proofs, which are bounded the same way in practice).
pub const MAX_PATH: usize = 128;

/// An RFC 9162 audit path proving an entry's presence.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct InclusionProof {
    /// The entry's leaf index.
    pub leaf_index: u64,
    /// The tree size the proof is for.
    pub tree_size: u64,
    /// The audit path, leaf to root.
    pub path: Vec<Digest>,
}

/// An RFC 9162 consistency proof between two tree sizes.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct ConsistencyProof {
    /// The earlier size.
    pub old_size: u64,
    /// The later size.
    pub new_size: u64,
    /// The proof nodes.
    pub path: Vec<Digest>,
}

/// `SHA-256(0x00 ‖ leaf)` (PUB-051).
pub fn leaf_hash(leaf: &[u8]) -> Digest {
    sha256_parts(&[&[0x00], leaf])
}

/// `SHA-256(0x01 ‖ left ‖ right)` (PUB-051).
pub fn node_hash(left: &Digest, right: &Digest) -> Digest {
    sha256_parts(&[&[0x01], left.as_bytes(), right.as_bytes()])
}

fn split(n: usize) -> usize {
    let mut k = 1;
    while k * 2 < n {
        k *= 2;
    }
    k
}

/// The Merkle tree hash of a list of leaf hashes (RFC 9162 §2.1.1); the empty tree's is
/// `SHA-256("")`.
pub fn root(leaves: &[Digest]) -> Digest {
    match leaves.len() {
        0 => sha256_parts(&[]),
        1 => leaves[0],
        n => {
            let k = split(n);
            node_hash(&root(&leaves[..k]), &root(&leaves[k..]))
        }
    }
}

/// The audit path for leaf `m` of `leaves` (RFC 9162 §2.1.3.1).
pub fn audit_path(m: usize, leaves: &[Digest]) -> Vec<Digest> {
    let n = leaves.len();
    if n <= 1 {
        return vec![];
    }
    let k = split(n);
    if m < k {
        let mut p = audit_path(m, &leaves[..k]);
        p.push(root(&leaves[k..]));
        p
    } else {
        let mut p = audit_path(m - k, &leaves[k..]);
        p.push(root(&leaves[..k]));
        p
    }
}

fn subproof(m: usize, leaves: &[Digest], complete: bool) -> Vec<Digest> {
    let n = leaves.len();
    if m == n {
        return if complete { vec![] } else { vec![root(leaves)] };
    }
    let k = split(n);
    if m <= k {
        let mut p = subproof(m, &leaves[..k], complete);
        p.push(root(&leaves[k..]));
        p
    } else {
        let mut p = subproof(m - k, &leaves[k..], false);
        p.push(root(&leaves[..k]));
        p
    }
}

/// The consistency proof from the first `m` leaves to all of `leaves` (RFC 9162 §2.1.4.1);
/// empty when `m` is 0 or the whole tree.
pub fn consistency_path(m: usize, leaves: &[Digest]) -> Vec<Digest> {
    if m == 0 || m >= leaves.len() {
        return vec![];
    }
    subproof(m, leaves, true)
}

/// Verifies that `leaf` (a leaf hash) is at `proof.leaf_index` in the tree of
/// `proof.tree_size` leaves whose root is `root` (RFC 9162 §2.1.3.2).
pub fn verify_inclusion(leaf: &Digest, proof: &InclusionProof, root: &Digest) -> bool {
    if proof.leaf_index >= proof.tree_size || proof.path.len() > MAX_PATH {
        return false;
    }
    let (mut fnode, mut snode) = (proof.leaf_index, proof.tree_size - 1);
    let mut r = *leaf;
    for p in &proof.path {
        if snode == 0 {
            return false;
        }
        if fnode & 1 == 1 || fnode == snode {
            r = node_hash(p, &r);
            if fnode & 1 == 0 {
                while fnode & 1 == 0 && fnode != 0 {
                    fnode >>= 1;
                    snode >>= 1;
                }
            }
        } else {
            r = node_hash(&r, p);
        }
        fnode >>= 1;
        snode >>= 1;
    }
    snode == 0 && r == *root
}

/// Verifies that the tree of `proof.new_size` leaves with root `new_root` extends the tree
/// of `proof.old_size` leaves with root `old_root` (RFC 9162 §2.1.4.2). Equal sizes need an
/// empty proof and equal roots; any tree extends the empty tree.
pub fn verify_consistency(proof: &ConsistencyProof, old_root: &Digest, new_root: &Digest) -> bool {
    let (first, second) = (proof.old_size, proof.new_size);
    if first > second || proof.path.len() > MAX_PATH {
        return false;
    }
    if first == second {
        return proof.path.is_empty() && old_root == new_root;
    }
    if first == 0 {
        return proof.path.is_empty();
    }
    let mut path = proof.path.clone();
    if path.is_empty() {
        return false;
    }
    if first.is_power_of_two() {
        path.insert(0, *old_root);
    }
    let (mut fnode, mut snode) = (first - 1, second - 1);
    while fnode & 1 == 1 {
        fnode >>= 1;
        snode >>= 1;
    }
    let (mut fr, mut sr) = (path[0], path[0]);
    for c in &path[1..] {
        if snode == 0 {
            return false;
        }
        if fnode & 1 == 1 || fnode == snode {
            fr = node_hash(c, &fr);
            sr = node_hash(c, &sr);
            if fnode & 1 == 0 {
                while fnode & 1 == 0 && fnode != 0 {
                    fnode >>= 1;
                    snode >>= 1;
                }
            }
        } else {
            sr = node_hash(&sr, c);
        }
        fnode >>= 1;
        snode >>= 1;
    }
    fr == *old_root && sr == *new_root && snode == 0
}
