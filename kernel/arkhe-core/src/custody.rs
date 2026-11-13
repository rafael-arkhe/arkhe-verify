//! CustodyTransfer v1 (AKG:CUSTODY:v1). One hand-over of one asset between
//! two Ed25519 parties. Both parties sign the same object digest under
//! role-separated domains, so a releasing signature can never be replayed as a
//! receiving one. Transfers of an asset form a chain through `prev_transfer`.
//! Signatures and chain checks live in `arkhe-verify-core::custody`; this
//! module has no keys and grants no authority.
//!
//! The state digests commit to documents describing the asset (manifest, seal
//! photo, RFID read). They prove the record was not altered, not that the
//! physical asset matches the document.
use crate::canonical::{decode_canonical, Cbor, DecodeError};
use crate::fields::{bytes32, digest, is_id, nullable, text, uint, Fields};
use crate::{CanonicalEncode, Digest32};
use serde::{Deserialize, Serialize};

pub const CUSTODY_VERSION: u64 = 1;
pub const SIGNATURE_DOMAIN: &[u8] = b"AKG:CUSTODY:SIG:v1\0";

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CustodyTransfer {
    pub version: u64,
    pub transfer_id: String,
    pub asset_id: String,
    /// Digest of the previous transfer of this asset; `None` only for the
    /// first transfer of a chain.
    pub prev_transfer: Option<Digest32>,
    pub state_before: Digest32,
    pub state_after: Digest32,
    /// Ed25519 public key of the party releasing custody.
    pub from_party: [u8; 32],
    /// Ed25519 public key of the party receiving custody.
    pub to_party: [u8; 32],
    /// Declared by the parties; not a trusted timestamp.
    pub declared_at_unix: u64,
    /// Declared location reference (grid square, depot code); not attested.
    pub location_ref: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CustodyRole {
    Releasing,
    Receiving,
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum CustodyError {
    #[error("canonical CBOR: {0}")]
    Cbor(#[from] DecodeError),
    #[error("schema: {0}")]
    Schema(&'static str),
}

impl From<&'static str> for CustodyError {
    fn from(m: &'static str) -> Self {
        Self::Schema(m)
    }
}

impl CustodyTransfer {
    pub fn validate(&self) -> Result<(), CustodyError> {
        let fail = |m| Err(CustodyError::Schema(m));
        if self.version != CUSTODY_VERSION {
            return fail("unsupported version");
        }
        if !is_id(&self.transfer_id) {
            return fail("transfer_id");
        }
        if !is_id(&self.asset_id) {
            return fail("asset_id");
        }
        if self.from_party == self.to_party {
            return fail("a party cannot transfer custody to itself");
        }
        if self.location_ref.as_deref().is_some_and(|l| !is_id(l)) {
            return fail("location_ref");
        }
        Ok(())
    }

    /// Bytes a party signs: role-separated domain, then the object digest.
    pub fn signing_bytes(&self, role: CustodyRole) -> Vec<u8> {
        let tag: &[u8] = match role {
            CustodyRole::Releasing => b"releasing\0",
            CustodyRole::Receiving => b"receiving\0",
        };
        [SIGNATURE_DOMAIN, tag, &self.object_digest().0].concat()
    }

    /// Stable subject shared by every transfer of `asset_id`.
    pub fn asset_subject(asset_id: &str) -> Digest32 {
        Digest32::blake3(b"AKG:CUSTODY:ASSET:v1\0", asset_id.as_bytes())
    }

    pub fn to_cbor(&self) -> Cbor {
        let bytes = |b: &[u8]| Cbor::Bytes(b.to_vec());
        Cbor::Map(
            [
                ("version", Cbor::Uint(self.version)),
                ("transfer_id", Cbor::Text(self.transfer_id.clone())),
                ("asset_id", Cbor::Text(self.asset_id.clone())),
                (
                    "prev_transfer",
                    self.prev_transfer.map_or(Cbor::Null, |d| bytes(&d.0)),
                ),
                ("state_before", bytes(&self.state_before.0)),
                ("state_after", bytes(&self.state_after.0)),
                ("from_party", bytes(&self.from_party)),
                ("to_party", bytes(&self.to_party)),
                ("declared_at_unix", Cbor::Uint(self.declared_at_unix)),
                (
                    "location_ref",
                    self.location_ref.clone().map_or(Cbor::Null, Cbor::Text),
                ),
            ]
            .into_iter()
            .map(|(k, v)| (k.to_owned(), v))
            .collect(),
        )
    }

    /// Strict inverse of `canonical_bytes`.
    pub fn from_canonical_bytes(input: &[u8]) -> Result<Self, CustodyError> {
        let mut f = Fields::new(decode_canonical(input)?)?;
        let value = Self {
            version: uint(f.take("version")?)?,
            transfer_id: text(f.take("transfer_id")?)?,
            asset_id: text(f.take("asset_id")?)?,
            prev_transfer: nullable(f.take("prev_transfer")?, digest)?,
            state_before: digest(f.take("state_before")?)?,
            state_after: digest(f.take("state_after")?)?,
            from_party: bytes32(f.take("from_party")?)?,
            to_party: bytes32(f.take("to_party")?)?,
            declared_at_unix: uint(f.take("declared_at_unix")?)?,
            location_ref: nullable(f.take("location_ref")?, text)?,
        };
        f.finish()?;
        value.validate()?;
        Ok(value)
    }
}

impl CanonicalEncode for CustodyTransfer {
    const DOMAIN_OBJECT: &'static [u8] = b"AKG:CUSTODY:v1\0";

    fn unsigned_projection(&self) -> serde_json::Value {
        serde_json::to_value(self).expect("typed CustodyTransfer")
    }

    fn canonical_bytes(&self) -> Vec<u8> {
        self.to_cbor().encode()
    }
}
