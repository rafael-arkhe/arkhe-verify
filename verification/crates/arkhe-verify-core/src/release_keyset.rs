//! k-of-n Ed25519 signatures over a `ReleaseManifest` object digest.
//!
//! One verified signature is not a release. The threshold is at least 2.
//! This module stores no private key and names no roster.

use ed25519_dalek::{Signature, VerifyingKey};

pub const DOMAIN: &[u8] = b"AKG:RELEASE:SIG:v1\0";
const MAX_DELEGATES: usize = 64;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DelegateSignature {
    pub public_key: [u8; 32],
    pub signature: [u8; 64],
}

pub fn message(object_digest: &[u8; 32]) -> Vec<u8> {
    let mut out = Vec::with_capacity(DOMAIN.len() + 32);
    out.extend_from_slice(DOMAIN);
    out.extend_from_slice(object_digest);
    out
}

/// Count distinct keyset signatures over `object_digest`.
/// `threshold` below 2, a short keyset, a bad signature, or fewer than `k`
/// verified signatures is an error.
pub fn admit(
    object_digest: &[u8; 32],
    keyset: &[[u8; 32]],
    threshold: usize,
    signatures: &[DelegateSignature],
) -> Result<usize, &'static str> {
    if threshold < 2 {
        return Err("threshold");
    }
    if keyset.is_empty() || keyset.len() > MAX_DELEGATES || keyset.len() < threshold {
        return Err("keyset");
    }
    let mut seen = Vec::with_capacity(keyset.len());
    for key in keyset {
        if seen.contains(key) {
            return Err("keyset");
        }
        let verifying = VerifyingKey::from_bytes(key).map_err(|_| "keyset")?;
        if verifying.is_weak() {
            return Err("keyset");
        }
        seen.push(*key);
    }
    let signed = message(object_digest);
    let mut accepted = Vec::with_capacity(signatures.len());
    for vote in signatures {
        if !keyset.contains(&vote.public_key) || accepted.contains(&vote.public_key) {
            return Err("signature");
        }
        let key = VerifyingKey::from_bytes(&vote.public_key).map_err(|_| "signature")?;
        let signature = Signature::from_bytes(&vote.signature);
        if key.verify_strict(&signed, &signature).is_err() {
            return Err("signature");
        }
        accepted.push(vote.public_key);
    }
    if accepted.len() < threshold {
        return Err("threshold");
    }
    Ok(accepted.len())
}
