use alloc::vec::Vec;
use core::convert::TryInto;

use curve25519_dalek::ristretto::RistrettoPoint;
use curve25519_dalek::constants::RISTRETTO_BASEPOINT_POINT;

use curve25519_dalek::ristretto::CompressedRistretto;

use curve25519_dalek::scalar::Scalar;
use curve25519_dalek::traits::MultiscalarMul;
use rand_core::{CryptoRng, RngCore};
use sha2::{Digest, Sha512};

use crate::crypto::{UpkePublicKey, UpkeSecretKey, UpkeCiphertext, UpkeUpdateToken};
use subtle::ConstantTimeEq;

#[derive(Debug)]
pub enum UpkeError {
    InvalidLength,
    InvalidGroupElement,
    InvalidScalar,
    InvalidPoint,
    InvalidUpdateToken
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

/// Serialize pk = g_1||...||g_ell||h (each compressed point is 32 bytes)[Updatable Public Key Encryption in the Standard Model]
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
        let s = Option::<Scalar>::from(Scalar::from_canonical_bytes(arr)).ok_or(UpkeError::InvalidScalar)?;
        x.push(s);
    }
    Ok(x)
}


/// Decrypt ct under sk:
/// - kem_output := f_1||...||f_ell, each f_i is a compressed Ristretto point (32 bytes)
/// - ciphertext := c, a compressed Ristretto point (32 bytes)
/// Return plaintext group element m = c - Σ f_i*s_i
pub fn upke_dec(sk: &UpkeSecretKey, ct: &UpkeCiphertext, ell: usize) -> Result<RistrettoPoint, UpkeError> {
    if ct.kem_output.len() != ell * 32 || ct.ciphertext.len() != 32 {
        return Err(UpkeError::InvalidLength);
    }

    // Parse secret scalars s_i
    let s = parse_secret_key(sk, ell)?;

    // Parse c
    let mut c_arr = [0u8; 32];
    c_arr.copy_from_slice(&ct.ciphertext);
    let c = CompressedRistretto(c_arr)
        .decompress()
        .ok_or(UpkeError::InvalidPoint)?;

    // Compute acc = Σ f_i*s_i
    let mut acc = RistrettoPoint::default();
    for i in 0..ell {
        let start = i * 32;
        let end = start + 32;

        let mut f_arr = [0u8; 32];
        f_arr.copy_from_slice(&ct.kem_output[start..end]);

        let f_i = CompressedRistretto(f_arr)
            .decompress()
            .ok_or(UpkeError::InvalidPoint)?;

        acc += f_i * s[i];
    }

    Ok(c - acc)
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

pub const UPKE_L: usize = 32;

/// Build one token ciphertext of the form:
/// (g_1^{r}, ..., g_ell^{r}, h^{r} * g^{delta})
fn u_enc_delta(
    g: &[RistrettoPoint],
    h: &RistrettoPoint,
    r: &Scalar,
    m:&RistrettoPoint,
) -> UpkeCiphertext {
    // f_j = g_j^r
    let mut kem_output = Vec::with_capacity(g.len() * 32);
    for gj in g {
        let fj = gj * r;
        kem_output.extend_from_slice(fj.compress().as_bytes());
    }

    // c = h^r * g^{delta}
    // additive form:
    // h^r = h * r
    // g^{delta} is either identity or basepoint
    let c_point = (*h) * r + *m;

    UpkeCiphertext {
        kem_output,
        ciphertext: c_point.compress().as_bytes().to_vec(),
    }
}

fn derive_scalar(seed: &[u8; 32], label: &[u8], i: u32) -> Scalar {
    // Hash(seed || label || i) -> 64 bytes -> Scalar
    let mut hasher = Sha512::new();
    hasher.update(seed);
    hasher.update(label);
    hasher.update(i.to_le_bytes());
    let digest = hasher.finalize(); // 64 bytes

    let mut wide = [0u8; 64];
    wide.copy_from_slice(&digest);
    Scalar::from_bytes_mod_order_wide(&wide)
}

fn derive_delta_bits(seed: &[u8; 32], ell: usize) -> Vec<u8> {
    // δ = first ell bits of H(seed || "delta")
    let mut delta = vec![0u8; ell];
    for i in 0..ell {
        let byte = seed[i / 8];
        let bit = (byte >> (i % 8)) & 1;
        delta[i] = bit;
    }
    delta
}
/// Upd-Pk as in the paper excerpt you attached.
///
/// Returns (update_token, new_public_key)
pub fn upke_upd_pk<R: RngCore + CryptoRng>(
    rng: &mut R,
    pk: &UpkePublicKey,
    ell: usize,
) -> Result<(UpkeUpdateToken, UpkePublicKey), UpkeError> {
    let (g, h) = parse_public_key(pk, ell).map_err(|_| UpkeError::InvalidPoint)?;
    
    let mut seed = [0u8; 32];
    rng.fill_bytes(&mut seed);

    // δ ∈ {0,1}^ell
    let delta = derive_delta_bits(&seed, ell);
    
    let scalars: Vec<Scalar> = delta.iter().map(|&b| Scalar::from(b as u64)).collect();

    // pk': h' = h * Π g_i^{δ_i}  (additive: h' = h + Σ δ_i*g_i)
    let h_prime = h + RistrettoPoint::multiscalar_mul(&scalars, &g);

    // new pk is (g||h')
    let new_pk = super::upke::serialize_public_key(&g, &h_prime);

    // up = (C_1,...,C_ell), where each C_i uses fresh r_i (or derived from r)
    let mut cts = Vec::with_capacity(ell);
    for i in 0..ell {
        let r_i = derive_scalar(&seed, b"upke-ri", i as u32);
        let m_i = if delta[i] == 1 {
            RISTRETTO_BASEPOINT_POINT
        } else {
            RistrettoPoint::default() // identity
        };
        let ct_i = u_enc_delta(&g, &h, &r_i, &m_i); 
        cts.push(ct_i);
    }

    let token = UpkeUpdateToken(cts);

    Ok((token, new_pk))
}

/// Update secret key using update token:
/// For each i:
///   m_i = Dec(sk, C_i) should be either identity (δ_i=0) or basepoint (δ_i=1)
/// Then: s'_i = s_i + δ_i
pub fn upke_upd_sk(sk: &UpkeSecretKey, token: &UpkeUpdateToken, ell: usize) -> Result<UpkeSecretKey, UpkeError> {
    if token.0.len() != ell {
        return Err(UpkeError::InvalidLength);
    }

    let mut s = parse_secret_key(sk, ell).map_err(|_| UpkeError::InvalidUpdateToken)?;

    for i in 0..ell {
        let m_i: RistrettoPoint = upke_dec(sk, &token.0[i], ell).map_err(|_| UpkeError::InvalidUpdateToken)?;

        // Проверяем, что расшифровка дала ровно identity или basepoint (CT comparison).
        let mi_bytes = m_i.compress();
        let is_id = mi_bytes
            .as_bytes()
            .ct_eq(RistrettoPoint::default().compress().as_bytes())
            .unwrap_u8();

        let is_bp = mi_bytes
            .as_bytes()
            .ct_eq(RISTRETTO_BASEPOINT_POINT.compress().as_bytes())
            .unwrap_u8();

        match (is_id, is_bp) {
            (1, 0) => {
                // δ_i = 0, ничего не делаем
            }
            (0, 1) => {
                // δ_i = 1
                s[i] += Scalar::ONE;
            }
            _ => {
                return Err(UpkeError::InvalidUpdateToken);
            }
        }
    }

    Ok(serialize_secret_key(&s))
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