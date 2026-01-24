use alloc::vec::Vec;
use shamir::SecretData;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ShareBytes {
    pub id: u8,
    pub bytes: Vec<u8>,
}

use mls_rs_core::error::IntoAnyError;
use base64::Engine as _;

#[derive(Clone, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "std", derive(thiserror::Error))]
pub enum SecretSharingError {
    #[cfg_attr(feature = "std", error("invalid threshold"))]
    InvalidThreshold,

    #[cfg_attr(feature = "std", error("invalid share count"))]
    InvalidShareCount,

    #[cfg_attr(feature = "std", error("encode failed"))]
    EncodeFailed,

    #[cfg_attr(feature = "std", error("split failed"))]
    SplitFailed,

    #[cfg_attr(feature = "std", error("recover failed"))]
    RecoverFailed,

    #[cfg_attr(feature = "std", error("decode failed"))]
    DecodeFailed,
}

impl IntoAnyError for SecretSharingError {
    #[cfg(feature = "std")]
    fn into_dyn_error(
        self,
    ) -> Result<Box<dyn std::error::Error + Send + Sync>, Self> {
        Ok(Box::new(self))
    }
}

/// Split seed bytes into m shares with threshold t.
/// Internally encodes seed as base64 string because shamir works with &str secrets. :contentReference[oaicite:3]{index=3}
pub fn split_seed_bytes(
    seed: &[u8],
    threshold: u8,
    share_count: u8,
) -> Result<Vec<ShareBytes>, SecretSharingError> {
    if threshold == 0 {
        return Err(SecretSharingError::InvalidThreshold);
    }
    if share_count == 0 || share_count < threshold {
        return Err(SecretSharingError::InvalidShareCount);
    }

    let seed_b64 = base64::engine::general_purpose::STANDARD
        .encode(seed);

    let sd = SecretData::with_secret(&seed_b64, threshold);

    let mut out = Vec::with_capacity(share_count as usize);
    for id in 1..=share_count {
        let bytes = sd.get_share(id).map_err(|_| SecretSharingError::SplitFailed)?;
        out.push(ShareBytes { id, bytes });
    }

    Ok(out)
}

/// Recover seed bytes from at least `threshold` shares.
/// Returns the original seed bytes.
pub fn recover_seed_bytes(
    threshold: u8,
    shares: &[ShareBytes],
) -> Result<Vec<u8>, SecretSharingError> {
    if threshold == 0 {
        return Err(SecretSharingError::InvalidThreshold);
    }
    if shares.len() < threshold as usize {
        return Err(SecretSharingError::RecoverFailed);
    }

    let share_vec: Vec<Vec<u8>> = shares
        .iter()
        .take(threshold as usize)
        .map(|s| s.bytes.clone())
        .collect();

    let recovered_b64 = SecretData::recover_secret(threshold, share_vec)
        .ok_or(SecretSharingError::RecoverFailed)?;

    let seed = base64::engine::general_purpose::STANDARD
        .decode(recovered_b64.as_bytes())
        .map_err(|_| SecretSharingError::DecodeFailed)?;

    Ok(seed)
}

#[cfg(test)]
pub(crate) mod test_utils {
    use alloc::vec::Vec;

    use crate::{
        crypto::SignatureSecretKey,
        tree_kem::{leaf_node::LeafNode, TreeKemPublic, UpdatePathNode},
    };

    #[derive(Copy, Clone, Debug)]
    pub struct CommitModifiers {
        pub modify_leaf: fn(&mut LeafNode, &SignatureSecretKey) -> Option<SignatureSecretKey>,
        pub modify_tree: fn(&mut TreeKemPublic),
        pub modify_path: fn(Vec<UpdatePathNode>) -> Vec<UpdatePathNode>,
    }

    impl Default for CommitModifiers {
        fn default() -> Self {
            Self {
                modify_leaf: |_, _| None,
                modify_tree: |_| (),
                modify_path: |a| a,
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::{rngs::OsRng, RngCore};

    fn random_seed() -> Vec<u8> {
        let mut buf = vec![0u8; 32];
        OsRng.fill_bytes(&mut buf);
        buf
    }

    #[test]
    fn split_then_recover_returns_original_seed() {
        let seed = random_seed();
        let threshold = 4u8;
        let share_count = 8u8;

        let shares = split_seed_bytes(&seed, threshold, share_count)
            .expect("split must succeed");
        assert_eq!(shares.len(), share_count as usize);

        // берём любые threshold shares
        let subset = vec![shares[0].clone(), shares[2].clone(), shares[4].clone(), shares[3].clone()];
        let recovered = recover_seed_bytes(threshold, &subset)
            .expect("recover must succeed with threshold shares");

        assert_eq!(recovered, seed);
    }

    #[test]
    fn recover_fails_with_insufficient_shares() {
        let seed = random_seed();

        let threshold = 3u8;
        let share_count = 5u8;

        let shares = split_seed_bytes(&seed, threshold, share_count)
            .expect("split must succeed");

        let subset = vec![shares[0].clone(), shares[1].clone()];
        let res = recover_seed_bytes(threshold, &subset);

        assert!(matches!(res, Err(SecretSharingError::RecoverFailed)));
    }

    #[test]
    fn recover_is_independent_of_order_for_same_subset() {
        let seed = random_seed();

        let threshold = 3u8;
        let share_count = 6u8;

        let shares = split_seed_bytes(&seed, threshold, share_count)
            .expect("split must succeed");

        let subset_a = vec![shares[0].clone(), shares[3].clone(), shares[5].clone()];
        let subset_b = vec![shares[5].clone(), shares[0].clone(), shares[3].clone()];

        let rec_a = recover_seed_bytes(threshold, &subset_a).unwrap();
        let rec_b = recover_seed_bytes(threshold, &subset_b).unwrap();

        assert_eq!(rec_a, seed);
        assert_eq!(rec_b, seed);
    }

    #[test]
    fn mixing_shares_from_different_seeds_fails_or_recovers_wrong_seed() {
        let seed1 = random_seed();
        let seed2 = random_seed();

        let threshold = 3u8;
        let share_count = 5u8;

        let s1 = split_seed_bytes(&seed1, threshold, share_count).unwrap();
        let s2 = split_seed_bytes(&seed2, threshold, share_count).unwrap();

        let mixed = vec![s1[0].clone(), s2[1].clone(), s1[2].clone()];

        let res = recover_seed_bytes(threshold, &mixed);

        match res {
            Err(_) => {}
            Ok(recovered) => {
                assert_ne!(recovered, seed1);
                assert_ne!(recovered, seed2);
            }
        }
    }
}