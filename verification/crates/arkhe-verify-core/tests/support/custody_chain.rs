//! Builds signed custody chains for tests. Party `k` has the deterministic key
//! seeded with `k + 1`; transfer `i` goes from party `i` to party `i + 1`.
use arkhe_core::{
    custody::{CustodyRole, CustodyTransfer, CUSTODY_VERSION},
    CanonicalEncode, Digest32,
};
use arkhe_verify_core::custody::SignedTransfer;
use ed25519_dalek::{Signer, SigningKey};

pub const ASSET: &str = "container:AMMO-7731";

pub fn key(party: usize) -> SigningKey {
    SigningKey::from_bytes(&[party as u8 + 1; 32])
}

pub fn state(i: usize) -> Digest32 {
    Digest32::blake3(b"test-state\0", &i.to_le_bytes())
}

pub fn sign(t: &CustodyTransfer, from: &SigningKey, to: &SigningKey) -> SignedTransfer {
    SignedTransfer {
        transfer_cbor: hex::encode(t.canonical_bytes()),
        releasing_signature: hex::encode(
            from.sign(&t.signing_bytes(CustodyRole::Releasing))
                .to_bytes(),
        ),
        receiving_signature: hex::encode(
            to.sign(&t.signing_bytes(CustodyRole::Receiving)).to_bytes(),
        ),
    }
}

pub fn transfer(i: usize, prev: Option<Digest32>) -> CustodyTransfer {
    CustodyTransfer {
        version: CUSTODY_VERSION,
        transfer_id: format!("xfer-{i:04}"),
        asset_id: ASSET.into(),
        prev_transfer: prev,
        state_before: state(i),
        state_after: state(i + 1),
        from_party: key(i).verifying_key().to_bytes(),
        to_party: key(i + 1).verifying_key().to_bytes(),
        declared_at_unix: 1_790_000_000 + i as u64 * 60,
        location_ref: Some(format!("depot-{}", i % 7)),
    }
}

/// Unsigned transfers and their signed forms, linked and continuous.
pub fn chain(n: usize) -> (Vec<CustodyTransfer>, Vec<SignedTransfer>) {
    let mut transfers: Vec<CustodyTransfer> = Vec::with_capacity(n);
    for i in 0..n {
        let prev = transfers.last().map(|t| t.object_digest());
        transfers.push(transfer(i, prev));
    }
    let signed = transfers
        .iter()
        .enumerate()
        .map(|(i, t)| sign(t, &key(i), &key(i + 1)))
        .collect();
    (transfers, signed)
}
