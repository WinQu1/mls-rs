use crate::OpensslCryptoError;
use mls_rs_core::crypto::{UpkePublicKey, UpkeSecretKey};
use rand_chacha::ChaCha20Rng;
use rand_core::{CryptoRng, RngCore, SeedableRng};

pub const UPKE_L: usize = 32;

const DOMAIN: &[u8] = b"mls-rs upke v1";
const SEED_G: &[u8] = b"mls-rs upke generators v1";

/// Generate a UPKE keypair (sk=x_1||...||x_ell, pk=g_1||...||g_ell||h).
pub fn generate_keypair<RNG: RngCore + CryptoRng>(
    mut rng: RNG,
) -> Result<(UpkeSecretKey, UpkePublicKey), OpensslCryptoError> {
    let g = mls_rs_core::crypto::upke::derive_generators(DOMAIN, SEED_G, UPKE_L);
    let x = mls_rs_core::crypto::upke::sample_scalars(&mut rng, UPKE_L);
    let h = mls_rs_core::crypto::upke::compute_h(&g, &x);
    let pk = mls_rs_core::crypto::upke::serialize_public_key(&g, &h);
    let sk = mls_rs_core::crypto::upke::serialize_secret_key(&x);
    Ok((sk, pk))
}

/// Helper that uses the provider RNG via random bytes.
/// Call this from ukem_generate().
pub fn generate_keypair_from_provider_random<F>(
    mut random_bytes: F,
) -> Result<(UpkeSecretKey, UpkePublicKey), OpensslCryptoError>
where
    F: FnMut(&mut [u8]) -> Result<(), OpensslCryptoError>,
{
    let mut seed = [0u8; 32];
    random_bytes(&mut seed)?;
    let rng = ChaCha20Rng::from_seed(seed);
    generate_keypair(rng)
}
#[cfg(test)]
mod upke_tests;