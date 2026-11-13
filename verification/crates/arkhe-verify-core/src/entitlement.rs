//! Offline Ed25519 entitlement tokens for paid Arkhe kits. An issuer exchanges
//! a checkout-provider license key for a signed token; verification needs no
//! network. A token proves issuance by a trusted key, not payment or identity.
use arkhe_core::Digest32;
use ed25519_dalek::{Signature, VerifyingKey};
use serde::{Deserialize, Serialize};

pub const PROFILE: &str = "arkhe/entitlement/v1";
pub const MAX_TOKEN: usize = 8192;
/// Tolerated issuer clock lead over the verifier, in seconds.
pub const MAX_SKEW: u64 = 300;
pub const TIERS: [&str; 3] = ["personal", "team", "commercial"];

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Entitlement {
    pub profile: String,
    pub product: String,
    pub tier: String,
    /// "prod" or "test" (checkout provider mode at issuance).
    pub mode: String,
    pub license_id: String,
    pub instance_id: String,
    pub issued_at: u64,
    pub expires_at: Option<u64>,
    /// Hex Ed25519 public key of the issuer.
    pub key_id: String,
}

/// Wire form: `payload` is the exact signed JSON text of an [`Entitlement`].
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Token {
    pub payload: String,
    pub signature: String,
}

pub fn digest(payload: &[u8]) -> Digest32 {
    Digest32::blake3(b"AKG:ENTITLEMENT:v1\0", payload)
}

pub fn well_formed(e: &Entitlement) -> bool {
    let id = |s: &str| !s.is_empty() && s.len() <= 128 && s.bytes().all(|b| b.is_ascii_graphic());
    e.profile == PROFILE
        && id(&e.product)
        && TIERS.contains(&e.tier.as_str())
        && (e.mode == "prod" || e.mode == "test")
        && id(&e.license_id)
        && id(&e.instance_id)
        && e.expires_at.is_none_or(|x| x > e.issued_at)
        && e.key_id.len() == 64
}

/// Verifies `raw` against `trusted` issuer keys at unix time `now`.
/// Test-mode tokens are accepted only when `allow_test` is set.
pub fn verify(
    raw: &[u8],
    trusted: &[[u8; 32]],
    now: u64,
    allow_test: bool,
) -> Result<Entitlement, &'static str> {
    if raw.len() > MAX_TOKEN {
        return Err("entitlement token exceeds size limit");
    }
    let token: Token = serde_json::from_slice(raw).map_err(|_| "malformed entitlement token")?;
    let e: Entitlement =
        serde_json::from_str(&token.payload).map_err(|_| "malformed entitlement payload")?;
    if !well_formed(&e) {
        return Err("entitlement payload violates profile");
    }
    let key: [u8; 32] = hex::decode(&e.key_id)
        .ok()
        .and_then(|k| k.try_into().ok())
        .ok_or("invalid entitlement key id")?;
    if !trusted.contains(&key) {
        return Err("entitlement issuer is not trusted");
    }
    let sig = hex::decode(&token.signature)
        .ok()
        .and_then(|s| Signature::from_slice(&s).ok())
        .ok_or("invalid entitlement signature encoding")?;
    VerifyingKey::from_bytes(&key)
        .map_err(|_| "invalid entitlement issuer key")?
        .verify_strict(&digest(token.payload.as_bytes()).0, &sig)
        .map_err(|_| "entitlement signature rejected")?;
    if e.mode == "test" && !allow_test {
        return Err("test-mode entitlement not accepted by this build");
    }
    if e.issued_at > now.saturating_add(MAX_SKEW) {
        return Err("entitlement issued in the future");
    }
    if e.expires_at.is_some_and(|x| x <= now) {
        return Err("entitlement expired");
    }
    Ok(e)
}

/// Issuer side: serializes and signs `e`. Rejects payloads verification would reject.
pub fn sign(e: &Entitlement, key: &ed25519_dalek::SigningKey) -> Result<Token, &'static str> {
    if !well_formed(e) || e.key_id != hex::encode(key.verifying_key().to_bytes()) {
        return Err("entitlement payload violates profile");
    }
    let payload = serde_json::to_string(e).map_err(|_| "entitlement serialization failed")?;
    use ed25519_dalek::Signer as _;
    let signature = hex::encode(key.sign(&digest(payload.as_bytes()).0).to_bytes());
    Ok(Token { payload, signature })
}
