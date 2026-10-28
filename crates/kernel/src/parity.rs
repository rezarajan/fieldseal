//! Reed–Solomon parity for export files (WIRE-107..109): k = 10 data shards, m = 4 parity
//! shards over GF(2⁸).
//!
//! The code is fixed byte for byte so that any implementation produces the same parity:
//!
//! - GF(2⁸) with the reducing polynomial x⁸ + x⁴ + x³ + x² + 1 (`0x11D`) and generator 2;
//! - the 14 × 10 Vandermonde matrix `V[r][c] = r^c` (with `0^0 = 1`), multiplied on the right
//!   by the inverse of its top 10 × 10 block so that the code is systematic; rows 10..14 of
//!   the result give the parity shards.
//!
//! This is the construction of Backblaze's JavaReedSolomon and the `reed-solomon-erasure`
//! crate, which the tests check against.

use crate::digest::sha256;
use crate::error::{ErrorCode, WireError};
use crate::id::Digest;

/// Data shards.
pub const K: usize = 10;
/// Parity shards.
pub const M: usize = 4;

const EXP_LOG: ([u8; 512], [u8; 256]) = {
    let mut exp = [0u8; 512];
    let mut log = [0u8; 256];
    let mut x: u16 = 1;
    let mut i = 0;
    while i < 255 {
        exp[i] = x as u8;
        log[x as usize] = i as u8;
        x <<= 1;
        if x & 0x100 != 0 {
            x ^= 0x11d;
        }
        i += 1;
    }
    while i < 512 {
        exp[i] = exp[i - 255];
        i += 1;
    }
    (exp, log)
};
const EXP: [u8; 512] = EXP_LOG.0;
const LOG: [u8; 256] = EXP_LOG.1;

fn mul(a: u8, b: u8) -> u8 {
    if a == 0 || b == 0 { 0 } else { EXP[usize::from(LOG[usize::from(a)]) + usize::from(LOG[usize::from(b)])] }
}

fn inv(a: u8) -> u8 {
    EXP[255 - usize::from(LOG[usize::from(a)])]
}

fn pow(a: u8, n: usize) -> u8 {
    if n == 0 {
        1
    } else if a == 0 {
        0
    } else {
        EXP[(usize::from(LOG[usize::from(a)]) * n) % 255]
    }
}

type Matrix = Vec<Vec<u8>>;

fn mat_mul(a: &Matrix, b: &Matrix) -> Matrix {
    let (n, inner, p) = (a.len(), b.len(), b[0].len());
    (0..n)
        .map(|r| (0..p).map(|c| (0..inner).fold(0u8, |acc, i| acc ^ mul(a[r][i], b[i][c]))).collect())
        .collect()
}

/// Gauss–Jordan inversion; `None` if singular.
fn mat_inv(m: &Matrix) -> Option<Matrix> {
    let n = m.len();
    let mut a: Matrix = m.iter().enumerate().map(|(r, row)| {
        let mut row = row.clone();
        row.extend((0..n).map(|c| u8::from(c == r)));
        row
    }).collect();
    for col in 0..n {
        let pivot = (col..n).find(|&r| a[r][col] != 0)?;
        a.swap(col, pivot);
        let scale = inv(a[col][col]);
        for v in a[col].iter_mut() {
            *v = mul(*v, scale);
        }
        let pivot_row = a[col].clone();
        for (r, row) in a.iter_mut().enumerate() {
            let factor = row[col];
            if r != col && factor != 0 {
                for (v, p) in row.iter_mut().zip(&pivot_row) {
                    *v ^= mul(factor, *p);
                }
            }
        }
    }
    Some(a.into_iter().map(|row| row[n..].to_vec()).collect())
}

/// The systematic 14 × 10 encoding matrix.
fn encoding_matrix() -> Matrix {
    let vandermonde: Matrix = (0..K + M).map(|r| (0..K).map(|c| pow(r as u8, c)).collect()).collect();
    let top_inv = mat_inv(&vandermonde[..K].to_vec()).expect("Vandermonde top block is invertible");
    mat_mul(&vandermonde, &top_inv)
}

/// Multiplies `rows` of a matrix with the given shards.
fn apply(rows: &Matrix, shards: &[&[u8]], shard_size: usize) -> Vec<Vec<u8>> {
    rows.iter()
        .map(|row| {
            let mut out = vec![0u8; shard_size];
            for (coef, shard) in row.iter().zip(shards) {
                if *coef != 0 {
                    for (o, s) in out.iter_mut().zip(shard.iter()) {
                        *o ^= mul(*coef, *s);
                    }
                }
            }
            out
        })
        .collect()
}

/// The parity of WIRE-107 for one export part.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct Parity {
    /// The size of every shard, data and parity.
    pub shard_size: usize,
    /// SHA-256 of each zero-padded data shard.
    pub data_hashes: [Digest; K],
    /// The parity shards.
    pub parity_shards: [Vec<u8>; M],
}

/// The shard size for `len` bytes: `ceil(len / 10)`, at least 1.
pub fn shard_size(len: usize) -> usize {
    len.div_ceil(K).max(1)
}

fn data_shards(data: &[u8], size: usize) -> Vec<Vec<u8>> {
    (0..K)
        .map(|i| {
            let mut shard = vec![0u8; size];
            let start = (i * size).min(data.len());
            let end = ((i + 1) * size).min(data.len());
            shard[..end - start].copy_from_slice(&data[start..end]);
            shard
        })
        .collect()
}

/// Computes the parity of `data`: the concatenated header, manifest and journal bodies.
pub fn compute(data: &[u8]) -> Parity {
    let size = shard_size(data.len());
    let shards = data_shards(data, size);
    let refs: Vec<&[u8]> = shards.iter().map(Vec::as_slice).collect();
    let parity = apply(&encoding_matrix()[K..].to_vec(), &refs, size);
    Parity {
        shard_size: size,
        data_hashes: core::array::from_fn(|i| sha256(&shards[i])),
        parity_shards: core::array::from_fn(|i| parity[i].clone()),
    }
}

/// Repairs `data` in place (WIRE-109): damaged data shards are found by their hashes and
/// rebuilt from the intact shards and parity. Returns the number of shards repaired.
///
/// Parity shards carry no hashes, so a damaged one is detected by the rebuilt shards failing
/// their hashes; every choice of parity shards is tried. More than 4 damaged data shards, or
/// no consistent choice, is `E_PARITY`; a parity of the wrong shape for `data` is `E_HASH`.
/// The caller then checks the repaired bytes against the signed hashes (WIRE-108).
pub fn repair(data: &mut [u8], parity: &Parity) -> Result<usize, WireError> {
    let size = parity.shard_size;
    if size != shard_size(data.len()) || parity.parity_shards.iter().any(|p| p.len() != size) {
        return Err(WireError::new(ErrorCode::Hash, 0, "parity does not match the data size"));
    }
    let shards = data_shards(data, size);
    let damaged: Vec<usize> = (0..K).filter(|&i| sha256(&shards[i]) != parity.data_hashes[i]).collect();
    if damaged.is_empty() {
        return Ok(0);
    }
    if damaged.len() > M {
        return Err(WireError::new(ErrorCode::Parity, damaged[0] * size, "more damaged shards than parity can repair"));
    }
    let matrix = encoding_matrix();
    let intact: Vec<usize> = (0..K).filter(|i| !damaged.contains(i)).collect();
    for parity_rows in combinations(M, damaged.len()) {
        let rows: Vec<usize> = intact.iter().copied().chain(parity_rows.iter().map(|p| K + p)).collect();
        let sub: Matrix = rows.iter().map(|&r| matrix[r].clone()).collect();
        let Some(decode) = mat_inv(&sub) else { continue };
        let available: Vec<&[u8]> = rows
            .iter()
            .map(|&r| if r < K { shards[r].as_slice() } else { parity.parity_shards[r - K].as_slice() })
            .collect();
        let wanted: Matrix = damaged.iter().map(|&d| decode[d].clone()).collect();
        let rebuilt = apply(&wanted, &available, size);
        if damaged.iter().zip(&rebuilt).all(|(&d, s)| sha256(s) == parity.data_hashes[d]) {
            for (&d, shard) in damaged.iter().zip(&rebuilt) {
                let start = d * size;
                let end = ((d + 1) * size).min(data.len());
                if start < end {
                    data[start..end].copy_from_slice(&shard[..end - start]);
                }
            }
            return Ok(damaged.len());
        }
    }
    Err(WireError::new(ErrorCode::Parity, damaged[0] * size, "no consistent repair: parity damaged too"))
}

/// All `r`-element subsets of `0..n`, in lexicographic order.
fn combinations(n: usize, r: usize) -> Vec<Vec<usize>> {
    fn go(start: usize, n: usize, r: usize, cur: &mut Vec<usize>, out: &mut Vec<Vec<usize>>) {
        if cur.len() == r {
            out.push(cur.clone());
            return;
        }
        for i in start..n {
            cur.push(i);
            go(i + 1, n, r, cur, out);
            cur.pop();
        }
    }
    let mut out = Vec::new();
    go(0, n, r, &mut Vec::new(), &mut out);
    out
}
