use alloc::vec::Vec;
use core::convert::TryInto;

use curve25519_dalek::{
    ristretto::{CompressedRistretto, RistrettoPoint},
    scalar::Scalar,
    traits::MultiscalarMul,
};
use rand_core::{CryptoRng, RngCore};
use sha2::{Digest, Sha512};

use crate::crypto::{UpkePublicKey, UpkeSecretKey, UpkeCiphertext, UpkeUpdateToken};

#[derive(Debug)]
pub enum UpkeError {
    InvalidLength,
    InvalidGroupElement,
    InvalidScalar,
}

/// Parsed UPKE public key (internal representation): (g_1..g_ell, h)
pub struct ParsedUpkePublicKey {
    pub g: Vec<RistrettoPoint>,
    pub h: RistrettoPoint,
}

/// Parsed UPKE secret key (internal representation): (x_1..x_ell)
pub struct ParsedUpkeSecretKey {
    pub x: Vec<Scalar>,
}

/// Deterministically derive g_1..g_ell as Ristretto points.
/// Canonical approach: hash-to-group with domain separation.
pub fn derive_generators(domain: &[u8], seed_g: &[u8], ell: usize) -> Vec<RistrettoPoint> {
    (0..ell)
        .map(|i| {
            let mut h = Sha512::new();
            h.update(domain);
            h.update(seed_g);
            h.update(((i as u32) + 1).to_be_bytes());
            let digest = h.finalize();
            RistrettoPoint::hash_from_bytes::<Sha512>(&digest)
        })
        .collect()
}

/// Sample x_1..x_ell uniformly as Scalars.
pub fn sample_scalars<R: RngCore + CryptoRng>(rng: &mut R, ell: usize) -> Vec<Scalar> {
    (0..ell).map(|_| Scalar::random(rng)).collect()
}

/// Compute h = Π g_i^{x_i} using multiscalar multiplication.
pub fn compute_h(g: &[RistrettoPoint], x: &[Scalar]) -> RistrettoPoint {
    RistrettoPoint::multiscalar_mul(x.iter(), g.iter())
}

/// Serialize pk = g_1||...||g_ell||h (each compressed point is 32 bytes).
pub fn serialize_public_key(g: &[RistrettoPoint], h: &RistrettoPoint) -> UpkePublicKey {
    let mut out = Vec::with_capacity((g.len() + 1) * 32);
    for gi in g {
        out.extend_from_slice(gi.compress().as_bytes());
    }
    out.extend_from_slice(h.compress().as_bytes());
    UpkePublicKey::from(out)
}

/// Serialize sk = x_1||...||x_ell (each scalar is 32 bytes canonical).
pub fn serialize_secret_key(x: &[Scalar]) -> UpkeSecretKey {
    let mut out = Vec::with_capacity(x.len() * 32);
    for xi in x {
        out.extend_from_slice(xi.as_bytes());
    }
    UpkeSecretKey::from(out)
}

/// Parse pk bytes into (g_1..g_ell, h).
pub fn parse_public_key(pk: &UpkePublicKey, ell: usize) -> Result<(Vec<RistrettoPoint>, RistrettoPoint), UpkeError> {
    let b = pk.as_ref();
    let expected = (ell + 1) * 32;
    if b.len() != expected {
        return Err(UpkeError::InvalidLength);
    }

    let mut g = Vec::with_capacity(ell);
    for i in 0..ell {
        let start = i * 32;
        let end = start + 32;
        let arr: [u8; 32] = b[start..end].try_into().map_err(|_| UpkeError::InvalidLength)?;
        let p = CompressedRistretto(arr)
            .decompress()
            .ok_or(UpkeError::InvalidGroupElement)?;
        g.push(p);
    }

    let harr: [u8; 32] = b[ell * 32..(ell + 1) * 32]
        .try_into()
        .map_err(|_| UpkeError::InvalidLength)?;
    let h = CompressedRistretto(harr)
        .decompress()
        .ok_or(UpkeError::InvalidGroupElement)?;

    Ok((g, h))
}

/// Parse sk bytes into x_1..x_ell.
pub fn parse_secret_key(sk: &UpkeSecretKey, ell: usize) -> Result<Vec<Scalar>, UpkeError> {
    let b = sk.as_ref();
    if b.len() != ell * 32 {
        return Err(UpkeError::InvalidLength);
    }

    let mut x = Vec::with_capacity(ell);
    for i in 0..ell {
        let start = i * 32;
        let end = start + 32;
        let arr: [u8; 32] = b[start..end].try_into().map_err(|_| UpkeError::InvalidLength)?;
        let s = Scalar::from_canonical_bytes(arr).ok_or(UpkeError::InvalidScalar)?;
        x.push(s);
    }
    Ok(x)
}

/// Parse ciphertext: kem_output = f_1||...||f_ell (ell points), ciphertext = c (1 point).
pub fn parse_ciphertext(ct: &UpkeCiphertext, ell: usize) -> Result<(Vec<RistrettoPoint>, RistrettoPoint), UpkeError> {
    if ct.kem_output.len() != ell * 32 || ct.ciphertext.len() != 32 {
        return Err(UpkeError::InvalidLength);
    }

    let mut f = Vec::with_capacity(ell);
    for i in 0..ell {
        let start = i * 32;
        let end = start + 32;
        let arr: [u8; 32] = ct.kem_output[start..end].try_into().map_err(|_| UpkeError::InvalidLength)?;
        let p = CompressedRistretto(arr)
            .decompress()
            .ok_or(UpkeError::InvalidGroupElement)?;
        f.push(p);
    }

    let carr: [u8; 32] = ct.ciphertext.as_slice().try_into().map_err(|_| UpkeError::InvalidLength)?;
    let c = CompressedRistretto(carr)
        .decompress()
        .ok_or(UpkeError::InvalidGroupElement)?;

    Ok((f, c))
}

/// Deterministically derive generator g_i via hash-to-group (Ristretto).
fn derive_g_i(domain: &[u8], seed_g: &[u8], i: u32) -> RistrettoPoint {
    let mut hasher = Sha512::new();
    hasher.update(domain);
    hasher.update(seed_g);
    hasher.update(i.to_be_bytes());
    let digest = hasher.finalize();
    RistrettoPoint::hash_from_bytes::<Sha512>(&digest)
}

pub fn validate_update_token(tok: &UpkeUpdateToken, ell: usize) -> Result<(), UpkeError> {
    if tok.0.len() != ell {
        return Err(UpkeError::InvalidLength);
    }
    for ct in &tok.0 {
        let _ = parse_ciphertext(ct, ell)?;
    }
    Ok(())
}