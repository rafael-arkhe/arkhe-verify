use arkhe_verify_core::release_keyset::{admit, message, DelegateSignature, DOMAIN};
use ed25519_dalek::{Signer, SigningKey};

fn key(byte: u8) -> SigningKey {
    SigningKey::from_bytes(&[byte; 32])
}

fn vote(secret: &SigningKey, digest: &[u8; 32]) -> DelegateSignature {
    let signature = secret.sign(&message(digest));
    DelegateSignature {
        public_key: secret.verifying_key().to_bytes(),
        signature: signature.to_bytes(),
    }
}

#[test]
fn two_delegates_admit_and_one_does_not() {
    let digest = [0x11; 32];
    let first = key(7);
    let second = key(8);
    let third = key(9);
    let keyset = [
        first.verifying_key().to_bytes(),
        second.verifying_key().to_bytes(),
        third.verifying_key().to_bytes(),
    ];
    let signatures = [vote(&first, &digest), vote(&second, &digest)];
    assert_eq!(admit(&digest, &keyset, 2, &signatures).unwrap(), 2);

    assert_eq!(
        admit(&digest, &keyset, 2, &signatures[..1]).unwrap_err(),
        "threshold"
    );
    assert_eq!(
        admit(&digest, &keyset, 1, &signatures[..1]).unwrap_err(),
        "threshold"
    );
}

#[test]
fn a_signature_over_another_digest_is_refused() {
    let first = key(7);
    let second = key(8);
    let keyset = [
        first.verifying_key().to_bytes(),
        second.verifying_key().to_bytes(),
    ];
    let foreign = vote(&first, &[0x22; 32]);
    let good = vote(&second, &[0x11; 32]);
    assert_eq!(
        admit(&[0x11; 32], &keyset, 2, &[foreign, good]).unwrap_err(),
        "signature"
    );
    assert!(message(&[0x11; 32]).starts_with(DOMAIN));
}

#[test]
fn duplicates_and_outsiders_are_refused() {
    let first = key(7);
    let second = key(8);
    let outsider = key(9);
    let digest = [0x33; 32];
    let keyset = [
        first.verifying_key().to_bytes(),
        second.verifying_key().to_bytes(),
    ];
    let repeated = vote(&first, &digest);
    assert_eq!(
        admit(&digest, &keyset, 2, &[repeated, repeated]).unwrap_err(),
        "signature"
    );
    assert_eq!(
        admit(&digest, &keyset, 2, &[repeated, vote(&outsider, &digest)]).unwrap_err(),
        "signature"
    );
    let doubled = [keyset[0], keyset[0]];
    assert_eq!(admit(&digest, &doubled, 2, &[repeated]).unwrap_err(), "keyset");
}
