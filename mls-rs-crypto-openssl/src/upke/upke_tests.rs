use crate::OpensslCryptoProvider;

use super::*;
use curve25519_dalek::constants::RISTRETTO_BASEPOINT_POINT;
use curve25519_dalek::scalar::Scalar;
use rand_chacha::ChaCha20Rng;
use rand_chacha::rand_core::SeedableRng;
use mls_rs_core::crypto::upke::{parse_public_key, upke_dec, u_enc_delta, upke_upd_pk, upke_upd_sk};
use mls_rs_core::crypto::{HpkePublicKey, HpkeSecretKey};

#[test]
fn enc_dec_roundtrip_using_u_enc_delta() {
    let ell = 32;
    let mut rng = ChaCha20Rng::from_seed([42u8; 32]);

    let (sk, pk) = generate_keypair(&mut rng).expect("generate_keypair failed");
    let (g, h) = parse_public_key(&pk, ell).expect("pk parse failed");

    for _ in 0..20 {
        let r = Scalar::random(&mut rng);

        // m = basepoint * random_scalar
        let msg_scalar = Scalar::random(&mut rng);
        let m = RISTRETTO_BASEPOINT_POINT * msg_scalar;

        // 3) UpkeEncrypt and UpkeDecrypt
        let ct = u_enc_delta(&g, &h, &r, &m);
        let m2 = upke_dec(&sk, &ct, ell).expect("decrypt failed");

        assert_eq!(m.compress().as_bytes(), m2.compress().as_bytes());
    }
}

#[test]
fn updpk_updsk_produce_valid_new_keypair_and_decrypts_message() {
    let mut rng = ChaCha20Rng::from_seed([42u8; 32]);

    let (sk, pk) = generate_keypair(&mut rng).expect("generate_keypair failed");

    let pk_len = pk.as_ref().len();
    assert!(pk_len >= 64 && pk_len % 32 == 0, "unexpected pk length");
    let ell = (pk_len / 32) - 1;

    let (g, h) = parse_public_key(&pk, ell).expect("pk parse failed");
    assert_eq!((ell + 1) * 32, pk_len);

    let (token, pk_new) = upke_upd_pk(&mut rng, &pk, ell).expect("upke_upd_pk failed");
    let sk_new = upke_upd_sk(&sk, &token, ell).expect("upke_upd_sk failed");

    let (g_new, h_new) = parse_public_key(&pk_new, ell).expect("rotated pk parse failed");

    for i in 0..ell {
        assert_eq!(
            g[i].compress().as_bytes(),
            g_new[i].compress().as_bytes(),
            "generator g_{} changed after UpdPK",
            i
        );
    }

    for _ in 0..20 {
        let r = Scalar::random(&mut rng);
        let msg_scalar = Scalar::random(&mut rng);
        let m = RISTRETTO_BASEPOINT_POINT * msg_scalar;

        let ct = u_enc_delta(&g_new, &h_new, &r, &m);
        let m_dec = upke_dec(&sk_new, &ct, ell).expect("decrypt under rotated sk failed");

        assert_eq!(m.compress().as_bytes(), m_dec.compress().as_bytes());
    }

    for _ in 0..5 {
        let r = Scalar::random(&mut rng);
        let msg_scalar = Scalar::random(&mut rng);
        let m = RISTRETTO_BASEPOINT_POINT * msg_scalar;

        let ct = u_enc_delta(&g, &h, &r, &m);
        let m_dec = upke_dec(&sk, &ct, ell).expect("decrypt under original sk failed");

        assert_eq!(m.compress().as_bytes(), m_dec.compress().as_bytes());
    }
}

use std::time::Instant;

#[test]
fn bench_generate_keypair() {
    let mut rng = ChaCha20Rng::from_seed([42u8; 32]);

    let iterations = 1000;
    let mut times = Vec::with_capacity(iterations);

    for _ in 0..iterations {
        let start = Instant::now();

        let _ = generate_keypair(&mut rng)
            .expect("generate_keypair failed");

        times.push(start.elapsed())
    }

    times.sort_unstable();
    let median = if times.len() % 2 == 1 {
        times[times.len() / 2]
    } else {
        let mid = times.len() / 2;
        (times[mid - 1] + times[mid]) / 2
    };

    let median_ms = median.as_secs_f64() * 1000.0;
    println!("median time = {:.6} ms", median_ms);
}

#[test]
fn bench_kem_generate() {
    use std::time::Instant;

    use mls_rs_core::crypto::{CryptoProvider, CipherSuiteProvider};
    use mls_rs_core::crypto::{HpkeSecretKey, HpkePublicKey};

    let provider = OpensslCryptoProvider::new();

    let cs = provider.supported_cipher_suites()[0];

    let suite = provider
        .cipher_suite_provider(cs)
        .expect("cipher_suite_provider returned None");

    let iterations = 1000;
    let mut times = Vec::with_capacity(iterations);

    for _ in 0..iterations {
        let t0 = Instant::now();

        let (_sk, _pk): (HpkeSecretKey, HpkePublicKey) =
            suite.kem_generate().expect("kem_generate failed");
        
        times.push(t0.elapsed())
    }

    times.sort_unstable();
    let median = if times.len() % 2 == 1 {
        times[times.len() / 2]
    } else {
        let mid = times.len() / 2;
        (times[mid - 1] + times[mid]) / 2
    };

    let median_ms = median.as_secs_f64() * 1000.0;
    println!("median time = {:.6} ms", median_ms);
}

