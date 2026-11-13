//! ReleaseManifest v1 (AKG:RELEASE:v1). Binds one release's identifiers across
//! Git, Radicle, Hashtree and content digests. Unsigned core only: limiar
//! signatures are a separate envelope over `object_digest`. No authority here.
use crate::canonical::{decode_canonical, Cbor, DecodeError};
use crate::{CanonicalEncode, Digest32};
use serde::{Deserialize, Serialize};

pub const RELEASE_MANIFEST_VERSION: u64 = 1;
pub const MAX_ARTIFACTS: usize = 4096;
pub const MAX_PATH_BYTES: usize = 1024;
pub const MAX_ID_BYTES: usize = 128;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReleaseManifest {
    pub version: u64,
    pub release_id: String,
    /// `null` only for the first release of a chain; never omitted.
    #[serde(deserialize_with = "Option::deserialize")]
    pub prev_release_digest: Option<Digest32>,
    pub git: GitRef,
    #[serde(deserialize_with = "Option::deserialize")]
    pub radicle: Option<RadicleRef>,
    #[serde(deserialize_with = "Option::deserialize")]
    pub hashtree: Option<HashtreeRef>,
    /// Strictly ascending by path bytes; no duplicates.
    pub artifacts: Vec<Artifact>,
    #[serde(deserialize_with = "Option::deserialize")]
    pub sdd: Option<SddBinding>,
    #[serde(deserialize_with = "Option::deserialize")]
    pub build: Option<BuildBinding>,
    pub policy_digest: Digest32,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GitRef {
    /// Lowercase hex: 40 (SHA-1) or 64 (SHA-256) characters.
    pub commit_oid: String,
    #[serde(deserialize_with = "Option::deserialize")]
    pub tag: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RadicleRef {
    /// `rad:z` followed by base58btc characters.
    pub rid: String,
    pub canonical_refs_digest: Digest32,
}

/// Immutable Hashtree root: SHA-256 of the stored root block and, for CHK
/// content, the public decryption key. Never a mutable `npub/…` pointer.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HashtreeRef {
    pub root_hash: Digest32,
    #[serde(deserialize_with = "Option::deserialize")]
    pub decrypt_key: Option<Digest32>,
}

/// Both digests describe the same logical bytes at `path`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Artifact {
    pub path: String,
    pub size: u64,
    pub blake3: Digest32,
    pub sha256: Digest32,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SddBinding {
    pub gate_decision_digest: Digest32,
    pub constitution_digest: Digest32,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BuildBinding {
    pub system: String,
    pub flake_lock_digest: Digest32,
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ReleaseError {
    #[error("canonical CBOR: {0}")]
    Cbor(#[from] DecodeError),
    #[error("schema: {0}")]
    Schema(&'static str),
    #[error("digest does not match the expected release commitment")]
    DigestMismatch,
}

impl ReleaseManifest {
    pub fn validate(&self) -> Result<(), ReleaseError> {
        let fail = |m| Err(ReleaseError::Schema(m));
        if self.version != RELEASE_MANIFEST_VERSION {
            return fail("unsupported version");
        }
        if !is_id(&self.release_id) {
            return fail("release_id");
        }
        if !is_oid(&self.git.commit_oid) {
            return fail("git.commit_oid");
        }
        if self.git.tag.as_deref().is_some_and(|t| !is_id(t)) {
            return fail("git.tag");
        }
        if self.radicle.as_ref().is_some_and(|r| !is_rid(&r.rid)) {
            return fail("radicle.rid");
        }
        if self.build.as_ref().is_some_and(|b| !is_id(&b.system)) {
            return fail("build.system");
        }
        if self.artifacts.is_empty() || self.artifacts.len() > MAX_ARTIFACTS {
            return fail("artifact count");
        }
        if self.artifacts.iter().any(|a| !is_path(&a.path)) {
            return fail("artifact path");
        }
        if self
            .artifacts
            .windows(2)
            .any(|w| w[0].path.as_bytes() >= w[1].path.as_bytes())
        {
            return fail("artifacts not strictly ascending by path");
        }
        Ok(())
    }

    pub fn to_cbor(&self) -> Cbor {
        let opt = |v: Option<Cbor>| v.unwrap_or(Cbor::Null);
        let map = |pairs: Vec<(&str, Cbor)>| {
            Cbor::Map(pairs.into_iter().map(|(k, v)| (k.to_owned(), v)).collect())
        };
        map(vec![
            ("version", Cbor::Uint(self.version)),
            ("release_id", Cbor::Text(self.release_id.clone())),
            (
                "prev_release_digest",
                opt(self.prev_release_digest.map(bytes)),
            ),
            (
                "git",
                map(vec![
                    ("commit_oid", Cbor::Text(self.git.commit_oid.clone())),
                    ("tag", opt(self.git.tag.clone().map(Cbor::Text))),
                ]),
            ),
            (
                "radicle",
                opt(self.radicle.as_ref().map(|r| {
                    map(vec![
                        ("rid", Cbor::Text(r.rid.clone())),
                        ("canonical_refs_digest", bytes(r.canonical_refs_digest)),
                    ])
                })),
            ),
            (
                "hashtree",
                opt(self.hashtree.as_ref().map(|h| {
                    map(vec![
                        ("root_hash", bytes(h.root_hash)),
                        ("decrypt_key", opt(h.decrypt_key.map(bytes))),
                    ])
                })),
            ),
            (
                "artifacts",
                Cbor::Array(
                    self.artifacts
                        .iter()
                        .map(|a| {
                            map(vec![
                                ("path", Cbor::Text(a.path.clone())),
                                ("size", Cbor::Uint(a.size)),
                                ("blake3", bytes(a.blake3)),
                                ("sha256", bytes(a.sha256)),
                            ])
                        })
                        .collect(),
                ),
            ),
            (
                "sdd",
                opt(self.sdd.as_ref().map(|s| {
                    map(vec![
                        ("gate_decision_digest", bytes(s.gate_decision_digest)),
                        ("constitution_digest", bytes(s.constitution_digest)),
                    ])
                })),
            ),
            (
                "build",
                opt(self.build.as_ref().map(|b| {
                    map(vec![
                        ("system", Cbor::Text(b.system.clone())),
                        ("flake_lock_digest", bytes(b.flake_lock_digest)),
                    ])
                })),
            ),
            ("policy_digest", bytes(self.policy_digest)),
        ])
    }

    /// Strict inverse of `canonical_bytes`: rejects non-canonical encodings,
    /// unknown or missing keys, wrong types, and schema violations.
    pub fn from_canonical_bytes(input: &[u8]) -> Result<Self, ReleaseError> {
        let value = decode_canonical(input)?;
        let mut top = Fields::new(value)?;
        let manifest = Self {
            version: uint(top.take("version")?)?,
            release_id: text(top.take("release_id")?)?,
            prev_release_digest: nullable(top.take("prev_release_digest")?, digest)?,
            git: {
                let mut git = Fields::new(top.take("git")?)?;
                let value = GitRef {
                    commit_oid: text(git.take("commit_oid")?)?,
                    tag: nullable(git.take("tag")?, text)?,
                };
                git.finish()?;
                value
            },
            radicle: nullable(top.take("radicle")?, |v| {
                let mut f = Fields::new(v)?;
                let value = RadicleRef {
                    rid: text(f.take("rid")?)?,
                    canonical_refs_digest: digest(f.take("canonical_refs_digest")?)?,
                };
                f.finish()?;
                Ok(value)
            })?,
            hashtree: nullable(top.take("hashtree")?, |v| {
                let mut f = Fields::new(v)?;
                let value = HashtreeRef {
                    root_hash: digest(f.take("root_hash")?)?,
                    decrypt_key: nullable(f.take("decrypt_key")?, digest)?,
                };
                f.finish()?;
                Ok(value)
            })?,
            artifacts: match top.take("artifacts")? {
                Cbor::Array(items) => items
                    .into_iter()
                    .map(|v| {
                        let mut f = Fields::new(v)?;
                        let value = Artifact {
                            path: text(f.take("path")?)?,
                            size: uint(f.take("size")?)?,
                            blake3: digest(f.take("blake3")?)?,
                            sha256: digest(f.take("sha256")?)?,
                        };
                        f.finish()?;
                        Ok(value)
                    })
                    .collect::<Result<_, ReleaseError>>()?,
                _ => return Err(ReleaseError::Schema("artifacts type")),
            },
            sdd: nullable(top.take("sdd")?, |v| {
                let mut f = Fields::new(v)?;
                let value = SddBinding {
                    gate_decision_digest: digest(f.take("gate_decision_digest")?)?,
                    constitution_digest: digest(f.take("constitution_digest")?)?,
                };
                f.finish()?;
                Ok(value)
            })?,
            build: nullable(top.take("build")?, |v| {
                let mut f = Fields::new(v)?;
                let value = BuildBinding {
                    system: text(f.take("system")?)?,
                    flake_lock_digest: digest(f.take("flake_lock_digest")?)?,
                };
                f.finish()?;
                Ok(value)
            })?,
            policy_digest: digest(top.take("policy_digest")?)?,
        };
        top.finish()?;
        manifest.validate()?;
        Ok(manifest)
    }

    /// Accept received bytes only if they decode canonically, validate, and
    /// match the digest the caller obtained from an independent commitment.
    pub fn verify_bytes(input: &[u8], expected: Digest32) -> Result<Self, ReleaseError> {
        let manifest = Self::from_canonical_bytes(input)?;
        if manifest.object_digest() != expected {
            return Err(ReleaseError::DigestMismatch);
        }
        Ok(manifest)
    }
}

impl CanonicalEncode for ReleaseManifest {
    const DOMAIN_OBJECT: &'static [u8] = b"AKG:RELEASE:v1\0";

    fn unsigned_projection(&self) -> serde_json::Value {
        serde_json::to_value(self).expect("typed ReleaseManifest")
    }

    fn canonical_bytes(&self) -> Vec<u8> {
        self.to_cbor().encode()
    }
}

fn bytes(d: Digest32) -> Cbor {
    Cbor::Bytes(d.0.to_vec())
}

struct Fields(Vec<(String, Cbor)>);

impl Fields {
    fn new(value: Cbor) -> Result<Self, ReleaseError> {
        match value {
            Cbor::Map(pairs) => Ok(Self(pairs)),
            _ => Err(ReleaseError::Schema("expected map")),
        }
    }
    fn take(&mut self, key: &'static str) -> Result<Cbor, ReleaseError> {
        let index = self
            .0
            .iter()
            .position(|(k, _)| k == key)
            .ok_or(ReleaseError::Schema("missing field"))?;
        Ok(self.0.swap_remove(index).1)
    }
    fn finish(self) -> Result<(), ReleaseError> {
        if self.0.is_empty() {
            Ok(())
        } else {
            Err(ReleaseError::Schema("unknown field"))
        }
    }
}

fn uint(v: Cbor) -> Result<u64, ReleaseError> {
    match v {
        Cbor::Uint(n) => Ok(n),
        _ => Err(ReleaseError::Schema("expected unsigned integer")),
    }
}
fn text(v: Cbor) -> Result<String, ReleaseError> {
    match v {
        Cbor::Text(s) => Ok(s),
        _ => Err(ReleaseError::Schema("expected text")),
    }
}
fn digest(v: Cbor) -> Result<Digest32, ReleaseError> {
    match v {
        Cbor::Bytes(b) => Ok(Digest32(
            b.try_into()
                .map_err(|_| ReleaseError::Schema("digest length"))?,
        )),
        _ => Err(ReleaseError::Schema("expected byte string")),
    }
}
fn nullable<T>(
    v: Cbor,
    f: impl FnOnce(Cbor) -> Result<T, ReleaseError>,
) -> Result<Option<T>, ReleaseError> {
    match v {
        Cbor::Null => Ok(None),
        other => f(other).map(Some),
    }
}

fn is_id(s: &str) -> bool {
    !s.is_empty()
        && s.len() <= MAX_ID_BYTES
        && s.bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"._@+-/".contains(&b))
}
fn is_oid(s: &str) -> bool {
    (s.len() == 40 || s.len() == 64) && s.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))
}
fn is_rid(s: &str) -> bool {
    const B58: &[u8] = b"123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
    s.strip_prefix("rad:z").is_some_and(|rest| {
        !rest.is_empty() && rest.len() <= 64 && rest.bytes().all(|b| B58.contains(&b))
    })
}
/// Relative, `/`-separated, no empty, `.` or `..` segments, no backslash or NUL.
fn is_path(s: &str) -> bool {
    !s.is_empty()
        && s.len() <= MAX_PATH_BYTES
        && !s.contains(['\\', '\0'])
        && s.split('/')
            .all(|seg| !seg.is_empty() && seg != "." && seg != "..")
}
