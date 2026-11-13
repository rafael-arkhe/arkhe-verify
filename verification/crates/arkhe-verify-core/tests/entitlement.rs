use arkhe_verify_core::entitlement::{self, Entitlement, Token, PROFILE};
use ed25519_dalek::SigningKey;

fn issuer() -> (SigningKey, [u8; 32]) {
    let k = SigningKey::from_bytes(&[91; 32]);
    let p = k.verifying_key().to_bytes();
    (k, p)
}
fn sample(k: &SigningKey, mode: &str) -> Entitlement {
    Entitlement {
        profile: PROFILE.into(),
        product: "p1".into(),
        tier: "team".into(),
        mode: mode.into(),
        license_id: "lic_123".into(),
        instance_id: "ins_456".into(),
        issued_at: 1_000,
        expires_at: Some(2_000),
        key_id: hex::encode(k.verifying_key().to_bytes()),
    }
}
fn raw(t: &Token) -> Vec<u8> {
    serde_json::to_vec(t).unwrap()
}

#[test]
fn signed_token_round_trips_offline() {
    let (k, p) = issuer();
    let t = entitlement::sign(&sample(&k, "prod"), &k).unwrap();
    assert_eq!(
        entitlement::verify(&raw(&t), &[p], 1_500, false).unwrap(),
        sample(&k, "prod")
    );
}

#[test]
fn tampering_untrusted_keys_and_time_fail_closed() {
    let (k, p) = issuer();
    let t = entitlement::sign(&sample(&k, "prod"), &k).unwrap();
    let mut upgraded = t.clone();
    upgraded.payload = upgraded.payload.replace("\"team\"", "\"commercial\"");
    assert!(entitlement::verify(&raw(&upgraded), &[p], 1_500, false).is_err());
    let mut sig = t.clone();
    sig.signature.replace_range(0..2, "00");
    assert!(entitlement::verify(&raw(&sig), &[p], 1_500, false).is_err());
    let other = SigningKey::from_bytes(&[92; 32]).verifying_key().to_bytes();
    assert!(entitlement::verify(&raw(&t), &[other], 1_500, false).is_err());
    assert!(entitlement::verify(&raw(&t), &[p], 2_000, false).is_err());
    assert!(entitlement::verify(&raw(&t), &[p], 0, false).is_err());
    assert!(entitlement::verify(b"{}", &[p], 1_500, false).is_err());
    assert!(entitlement::verify(&vec![b' '; 9000], &[p], 1_500, false).is_err());
}

#[test]
fn self_signed_payload_with_foreign_key_id_is_rejected() {
    let (_, p) = issuer();
    let rogue = SigningKey::from_bytes(&[93; 32]);
    let t = entitlement::sign(&sample(&rogue, "prod"), &rogue).unwrap();
    assert!(entitlement::verify(&raw(&t), &[p], 1_500, false).is_err());
}

#[test]
fn test_mode_requires_opt_in_and_profile_is_enforced() {
    let (k, p) = issuer();
    let t = entitlement::sign(&sample(&k, "test"), &k).unwrap();
    assert!(entitlement::verify(&raw(&t), &[p], 1_500, false).is_err());
    assert!(entitlement::verify(&raw(&t), &[p], 1_500, true).is_ok());
    let mut bad = sample(&k, "prod");
    bad.tier = "enterprise".into();
    assert!(entitlement::sign(&bad, &k).is_err());
    let mut wrong_key = sample(&k, "prod");
    wrong_key.key_id = hex::encode([0u8; 32]);
    assert!(entitlement::sign(&wrong_key, &k).is_err());
}
