//! Offline verification of a CustodyTransfer chain for one asset. Each entry
//! carries the transfer's canonical bytes and both Ed25519 signatures. The
//! chain is accepted only if every transfer decodes strictly, both parties
//! signed it under their role, it links to the previous transfer, custody
//! passes from the previous receiver, and the asset state is continuous.
//!
//! Proves the record's integrity and who signed each hand-over. Does not prove
//! the physical asset matches the state documents, and declared times and
//! locations are not attested.
use arkhe_core::{
    custody::{CustodyRole, CustodyTransfer},
    CanonicalEncode, Digest32,
};
use ed25519_dalek::{Signature, VerifyingKey};
use serde::{Deserialize, Serialize};
use std::collections::HashSet;

pub const PROFILE: &str = "arkhe-custody-chain@1";
pub const MAX_CHAIN: usize = 10_000;
const MAX_TRANSFER_BYTES: usize = 4096;

/// Transport form: canonical CBOR of the transfer plus both signatures, hex.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SignedTransfer {
    pub transfer_cbor: String,
    pub releasing_signature: String,
    pub receiving_signature: String,
}

#[derive(Debug, Serialize)]
pub struct ChainVerdict {
    pub profile: &'static str,
    pub status: &'static str,
    pub asset_id: String,
    pub transfers: usize,
    pub head_digest: String,
    pub current_holder: String,
    pub current_state: String,
    /// Always false: the state digests commit to documents, not to the asset.
    pub physical_state_verified: bool,
    /// Always false: `declared_at_unix` and `location_ref` are declarations.
    pub declarations_attested: bool,
}

impl SignedTransfer {
    /// Strictly decode and check both signatures; returns the transfer.
    pub fn verify(&self) -> Result<CustodyTransfer, String> {
        let bytes = hex::decode(&self.transfer_cbor).map_err(|_| "transfer_cbor is not hex")?;
        if bytes.len() > MAX_TRANSFER_BYTES {
            return Err("transfer too large".into());
        }
        let t = CustodyTransfer::from_canonical_bytes(&bytes).map_err(|e| e.to_string())?;
        check_signature(
            &t,
            CustodyRole::Releasing,
            &t.from_party,
            &self.releasing_signature,
        )?;
        check_signature(
            &t,
            CustodyRole::Receiving,
            &t.to_party,
            &self.receiving_signature,
        )?;
        Ok(t)
    }
}

fn check_signature(
    t: &CustodyTransfer,
    role: CustodyRole,
    key: &[u8; 32],
    signature_hex: &str,
) -> Result<(), String> {
    let name = match role {
        CustodyRole::Releasing => "releasing",
        CustodyRole::Receiving => "receiving",
    };
    let key = VerifyingKey::from_bytes(key).map_err(|_| format!("{name} party key is invalid"))?;
    if key.is_weak() {
        return Err(format!("{name} party key is weak"));
    }
    let raw = hex::decode(signature_hex).map_err(|_| format!("{name} signature is not hex"))?;
    let signature =
        Signature::from_slice(&raw).map_err(|_| format!("{name} signature is malformed"))?;
    key.verify_strict(&t.signing_bytes(role), &signature)
        .map_err(|_| format!("{name} signature does not verify"))
}

/// Verify a complete chain for `asset_id`, first transfer first.
pub fn verify_chain(asset_id: &str, chain: &[SignedTransfer]) -> Result<ChainVerdict, String> {
    if chain.is_empty() {
        return Err("chain is empty".into());
    }
    if chain.len() > MAX_CHAIN {
        return Err("chain exceeds the verification bound".into());
    }
    let mut ids = HashSet::new();
    let mut prev: Option<CustodyTransfer> = None;
    for (i, entry) in chain.iter().enumerate() {
        let fail = |m: &str| Err(format!("transfer {i}: {m}"));
        let t = match entry.verify() {
            Ok(t) => t,
            Err(m) => return fail(&m),
        };
        if t.asset_id != asset_id {
            return fail("belongs to another asset");
        }
        if !ids.insert(t.transfer_id.clone()) {
            return fail("duplicate transfer_id");
        }
        match &prev {
            None if t.prev_transfer.is_some() => return fail("first transfer names a predecessor"),
            None => {}
            Some(p) => {
                if t.prev_transfer != Some(p.object_digest()) {
                    return fail("does not link to the previous transfer");
                }
                if t.from_party != p.to_party {
                    return fail("released by a party that did not hold custody");
                }
                if t.state_before != p.state_after {
                    return fail("state_before differs from the previous state_after");
                }
            }
        }
        prev = Some(t);
    }
    let head = prev.expect("non-empty chain");
    Ok(ChainVerdict {
        profile: PROFILE,
        status: "VERIFIED",
        asset_id: asset_id.into(),
        transfers: chain.len(),
        head_digest: head.object_digest().to_hex(),
        current_holder: hex::encode(head.to_party),
        current_state: head.state_after.to_hex(),
        physical_state_verified: false,
        declarations_attested: false,
    })
}

/// Digest the next transfer must name as `prev_transfer`.
pub fn head_digest(chain: &[SignedTransfer]) -> Result<Option<Digest32>, String> {
    chain
        .last()
        .map(|e| e.verify().map(|t| t.object_digest()))
        .transpose()
}
