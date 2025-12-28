// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// Copyright by contributors to this project.
// SPDX-License-Identifier: (Apache-2.0 OR MIT)

//! DDH-based Updatable Public Key Encryption (UPKE) / UKEM helper.
//!
//! This module implements the update logic shown in the user-provided diagram:
//! `Upd-Pk(pk)` produces `(up, pk')` where `pk'` is an updated public key and
//! `up` is an update token that allows the holder of the current secret key to
//! derive the new secret key.
//!
//! The implementation uses the Ristretto255 group from curve25519-dalek.

use alloc::vec::Vec;

use curve25519_dalek::{
    constants::RISTRETTO_BASEPOINT_POINT,
    ristretto::{CompressedRistretto, RistrettoPoint},
    scalar::Scalar,
};
use mls_rs_codec::{MlsDecode, MlsEncode, MlsSize};
use rand_core::{CryptoRng, RngCore};
use subtle::ConstantTimeEq;

/// Fixed length parameter `\ell`.
pub const UPKE_L: usize = 32;

/// Errors for UPKE operations.
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "std", derive(thiserror::Error))]
pub enum UpkeError {
    #[cfg_attr(feature = "std", error("invalid point encoding"))]
    InvalidPoint,
    #[cfg_attr(feature = "std", error("invalid length"))]
    InvalidLength,
    #[cfg_attr(feature = "std", error("invalid update token"))]
    InvalidUpdateToken,
}

/// UPKE secret key: `s = (s_1, ..., s_\ell)`.
///
/// This is *not* MLS state; applications should store it separately.
impl UpkeSecretKey {
    pub fn as_scalars(&self) -> &[Scalar; UPKE_L] {
        &self.s
    }
}


impl UpkePublicKey {
    pub fn parse(&self) -> Result<([RistrettoPoint; UPKE_L], RistrettoPoint), UpkeError> {
        if self.g.len() != 32 * UPKE_L || self.h.len() != 32 {
            return Err(UpkeError::InvalidLength);
        }

        let mut gs: [RistrettoPoint; UPKE_L] = [RISTRETTO_BASEPOINT_POINT; UPKE_L];

        for (i, chunk) in self.g.chunks_exact(32).enumerate() {
            let mut b = [0u8; 32];
            b.copy_from_slice(chunk);
            let p = CompressedRistretto(b)
                .decompress()
                .ok_or(UpkeError::InvalidPoint)?;
            gs[i] = p;
        }

        let mut hb = [0u8; 32];
        hb.copy_from_slice(&self.h);
        let h = CompressedRistretto(hb)
            .decompress()
            .ok_or(UpkeError::InvalidPoint)?;

        Ok((gs, h))
    }
}

/// Ciphertext `C = (f_1, ..., f_\ell, c)`.
#[derive(Clone, Debug, PartialEq, Eq, MlsSize, MlsEncode, MlsDecode)]
pub struct UpkeCiphertext {
    /// Concatenation of `\ell` compressed Ristretto points.
    #[mls_codec(with = "mls_rs_codec::byte_vec")]
    pub f: Vec<u8>,
    /// Compressed Ristretto point.
    #[mls_codec(with = "mls_rs_codec::byte_vec")]
    pub c: Vec<u8>,
}

/// Update token `up = (C_1, ..., C_\ell)`.
#[derive(Clone, Debug, PartialEq, Eq, MlsSize, MlsEncode, MlsDecode)]
pub struct UpkeUpdateToken {
    pub ciphertexts: Vec<UpkeCiphertext>,
}

#[derive(Clone, Debug, PartialEq, Eq, MlsSize, MlsEncode, MlsDecode)]
pub struct UpkeUpdate {
    pub target_leaf: u32,
    pub key_id: u64,
    pub new_public_key: UpkePublicKey,
    pub update_token: UpkeUpdateToken,
}

#[derive(Clone, Debug, PartialEq, Eq, MlsSize, MlsEncode, MlsDecode)]
pub struct UpkeUpdatesExt {
    pub updates: Vec<UpkeUpdate>,
}

impl crate::extension::MlsCodecExtension for UpkeUpdatesExt {
    fn extension_type() -> crate::extension::ExtensionType {
        crate::extension::ExtensionType::new(0xF100)
    }
}

/// Generate a fresh UPKE keypair.
pub fn upke_keygen<R: RngCore + CryptoRng>(rng: &mut R) -> (UpkeSecretKey, UpkePublicKey) {
    let mut s: [Scalar; UPKE_L] = [Scalar::ZERO; UPKE_L];
    let mut gs: [RistrettoPoint; UPKE_L] = [RISTRETTO_BASEPOINT_POINT; UPKE_L];

    for i in 0..UPKE_L {
        // Match the diagram: s_i in {0,1}.
        let bit = (rng.next_u32() & 1) as u64;
        s[i] = Scalar::from(bit);
        gs[i] = RistrettoPoint::random(rng);
    }

    let mut h = RistrettoPoint::default();
    for i in 0..UPKE_L {
        h += gs[i] * s[i];
    }

    let mut g_bytes = Vec::with_capacity(32 * UPKE_L);
    for i in 0..UPKE_L {
        g_bytes.extend_from_slice(gs[i].compress().as_bytes());
    }

    let pk = UpkePublicKey {
        g: g_bytes,
        h: h.compress().as_bytes().to_vec(),
    };

    (UpkeSecretKey { s }, pk)
}

/// Encrypt a group element `m` under `pk`.
pub fn upke_enc<R: RngCore + CryptoRng>(
    rng: &mut R,
    pk: &UpkePublicKey,
    m: &RistrettoPoint,
) -> Result<UpkeCiphertext, UpkeError> {
    let (gs, h) = pk.parse()?;
    let r = Scalar::random(rng);

    let mut f_bytes = Vec::with_capacity(32 * UPKE_L);
    let mut prod = RistrettoPoint::default();
    for i in 0..UPKE_L {
        let fi = gs[i] * r;
        f_bytes.extend_from_slice(fi.compress().as_bytes());
        // We will need \prod f_i^{s_i} during decrypt; no need to precompute here.
        prod += fi; // unused; kept to avoid warnings under cfg changes.
    }
    let _ = prod;

    let c = h * r + m;

    Ok(UpkeCiphertext {
        f: f_bytes,
        c: c.compress().as_bytes().to_vec(),
    })
}

/// Decrypt `ct` under `sk`.
pub fn upke_dec(sk: &UpkeSecretKey, ct: &UpkeCiphertext) -> Result<RistrettoPoint, UpkeError> {
    if ct.f.len() != 32 * UPKE_L || ct.c.len() != 32 {
        return Err(UpkeError::InvalidLength);
    }

    let mut c_bytes = [0u8; 32];
    c_bytes.copy_from_slice(&ct.c);
    let c = CompressedRistretto(c_bytes)
        .decompress()
        .ok_or(UpkeError::InvalidPoint)?;

    let mut acc = RistrettoPoint::default();
    for (i, chunk) in ct.f.chunks_exact(32).enumerate() {
        let mut b = [0u8; 32];
        b.copy_from_slice(chunk);
        let fi = CompressedRistretto(b)
            .decompress()
            .ok_or(UpkeError::InvalidPoint)?;
        acc += fi * sk.s[i];
    }

    Ok(c - acc)
}

/// Perform `Upd-Pk` from the diagram.
///
/// Returns `(update_token, new_public_key)`.
pub fn upke_upd_pk<R: RngCore + CryptoRng>(
    rng: &mut R,
    pk: &UpkePublicKey,
) -> Result<(UpkeUpdateToken, UpkePublicKey), UpkeError> {
    let (gs, h) = pk.parse()?;

    // Sample \delta in {0,1}^\ell.
    let mut delta_bits = [0u8; UPKE_L];
    for i in 0..UPKE_L {
        delta_bits[i] = (rng.next_u32() & 1) as u8;
    }

    // Compute h' = h * \prod g_i^{\delta_i}
    let mut h_prime = h;
    for i in 0..UPKE_L {
        if delta_bits[i] == 1 {
            h_prime += gs[i];
        }
    }

    // Encrypt each bit as m_i = g^{\delta_i} where g is the basepoint.
    let mut ciphertexts = Vec::with_capacity(UPKE_L);
    for i in 0..UPKE_L {
        let m_i = if delta_bits[i] == 1 {
            RISTRETTO_BASEPOINT_POINT
        } else {
            RistrettoPoint::default()
        };

        ciphertexts.push(upke_enc(rng, pk, &m_i)?);
    }

    Ok((
        UpkeUpdateToken { ciphertexts },
        UpkePublicKey {
            g: pk.g.clone(),
            h: h_prime.compress().as_bytes().to_vec(),
        },
    ))
}

/// Perform `Upd-Sk` from the diagram.
///
/// Returns the derived new secret key.
pub fn upke_upd_sk(sk: &UpkeSecretKey, up: &UpkeUpdateToken) -> Result<UpkeSecretKey, UpkeError> {
    if up.ciphertexts.len() != UPKE_L {
        return Err(UpkeError::InvalidLength);
    }

    let mut s_prime = sk.s;

    for i in 0..UPKE_L {
        let u_i = upke_dec(sk, &up.ciphertexts[i])?;

        // u_i must be either identity (delta=0) or basepoint (delta=1).
        let is_id = u_i
            .compress()
            .as_bytes()
            .ct_eq(RistrettoPoint::default().compress().as_bytes())
            .unwrap_u8();
        let is_bp = u_i
            .compress()
            .as_bytes()
            .ct_eq(RISTRETTO_BASEPOINT_POINT.compress().as_bytes())
            .unwrap_u8();

        match (is_id, is_bp) {
            (1, 0) => {
                // delta_i = 0
            }
            (0, 1) => {
                // delta_i = 1
                s_prime[i] += Scalar::ONE;
            }
            _ => return Err(UpkeError::InvalidUpdateToken),
        }
    }

    Ok(UpkeSecretKey { s: s_prime })
}

/// Validate that `(sk, pk)` form a consistent keypair.
pub fn upke_validate_pair(sk: &UpkeSecretKey, pk: &UpkePublicKey) -> Result<bool, UpkeError> {
    let (gs, h) = pk.parse()?;
    let mut h_check = RistrettoPoint::default();
    for i in 0..UPKE_L {
        h_check += gs[i] * sk.s[i];
    }
    Ok(h_check == h)
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand_core::OsRng;

    #[test]
    fn upke_upd_pk_and_upd_sk_produce_valid_pair() {
        let mut rng = OsRng;

        let (sk, pk) = upke_keygen(&mut rng);
        assert!(upke_validate_pair(&sk, &pk).unwrap());

        let (up, pk2) = upke_upd_pk(&mut rng, &pk).unwrap();
        let sk2 = upke_upd_sk(&sk, &up).unwrap();

        assert!(upke_validate_pair(&sk2, &pk2).unwrap());
    }
}
