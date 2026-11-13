//! AKG-CBOR-v1: RFC 8949 core deterministic encoding, definite lengths,
//! shortest integers, UTF-8 unchanged, byte digests, encoded-key ordered maps.
//! Unsigned projections contain all current fields (neither type has signatures).
use crate::{work::WorkIntent, worker::WorkerExecutionRecord, Digest32};
use serde_json::Value;

pub trait CanonicalEncode {
    const DOMAIN_OBJECT: &'static [u8];
    fn unsigned_projection(&self) -> Value;
    fn canonical_bytes(&self) -> Vec<u8> {
        encode(&self.unsigned_projection(), None)
    }
    fn object_digest(&self) -> Digest32 {
        Digest32::blake3(Self::DOMAIN_OBJECT, &self.canonical_bytes())
    }
}
fn head(major: u8, n: u64, out: &mut Vec<u8>) {
    let base = major << 5;
    match n {
        0..=23 => out.push(base | n as u8),
        24..=255 => out.extend([base | 24, n as u8]),
        256..=65535 => {
            out.push(base | 25);
            out.extend((n as u16).to_be_bytes());
        }
        65536..=4294967295 => {
            out.push(base | 26);
            out.extend((n as u32).to_be_bytes());
        }
        _ => {
            out.push(base | 27);
            out.extend(n.to_be_bytes());
        }
    }
}
pub fn encode_value(value: &Value) -> Vec<u8> {
    encode(value, None)
}

/// Encode a top-level map with explicitly typed byte strings, without treating
/// ordinary JSON arrays as bytes. Existing `encode_value` encodings are unchanged.
/// Byte keys must be unique and must not occur in `fields`.
pub fn encode_map_with_bytes(
    fields: &serde_json::Map<String, Value>,
    bytes: &[(&str, &[u8])],
) -> Result<Vec<u8>, &'static str> {
    let mut pairs: Vec<_> = fields
        .iter()
        .map(|(k, v)| (encode(&Value::String(k.clone()), None), encode(v, Some(k))))
        .collect();
    for (key, value) in bytes {
        let key = encode(&Value::String((*key).into()), None);
        if pairs.iter().any(|(existing, _)| *existing == key) {
            return Err("duplicate canonical map key");
        }
        let mut encoded = Vec::new();
        head(2, value.len() as u64, &mut encoded);
        encoded.extend_from_slice(value);
        pairs.push((key, encoded));
    }
    pairs.sort_by(|a, b| a.0.cmp(&b.0));
    let mut out = Vec::new();
    head(5, pairs.len() as u64, &mut out);
    for (key, value) in pairs {
        out.extend(key);
        out.extend(value);
    }
    Ok(out)
}

/// Explicitly typed AKG-CBOR-v1 value. Byte strings are a type, not a field-name
/// convention, so new objects need not extend the JSON byte-field list above.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Cbor {
    Uint(u64),
    Text(String),
    Bytes(Vec<u8>),
    Array(Vec<Cbor>),
    /// Keys are text; encoding sorts pairs by encoded key bytes.
    Map(Vec<(String, Cbor)>),
    Bool(bool),
    Null,
}

impl Cbor {
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::new();
        self.encode_into(&mut out);
        out
    }

    fn encode_into(&self, out: &mut Vec<u8>) {
        match self {
            Cbor::Uint(n) => head(0, *n, out),
            Cbor::Bytes(b) => {
                head(2, b.len() as u64, out);
                out.extend_from_slice(b);
            }
            Cbor::Text(s) => {
                head(3, s.len() as u64, out);
                out.extend_from_slice(s.as_bytes());
            }
            Cbor::Array(items) => {
                head(4, items.len() as u64, out);
                for item in items {
                    item.encode_into(out);
                }
            }
            Cbor::Map(pairs) => {
                let mut encoded: Vec<_> = pairs
                    .iter()
                    .map(|(k, v)| (Cbor::Text(k.clone()).encode(), v.encode()))
                    .collect();
                encoded.sort_by(|a, b| a.0.cmp(&b.0));
                head(5, encoded.len() as u64, out);
                for (k, v) in encoded {
                    out.extend(k);
                    out.extend(v);
                }
            }
            Cbor::Bool(false) => out.push(0xf4),
            Cbor::Bool(true) => out.push(0xf5),
            Cbor::Null => out.push(0xf6),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum DecodeError {
    #[error("truncated input")]
    Truncated,
    #[error("trailing bytes after the top-level item")]
    Trailing,
    #[error("unsupported major type, tag, float or indefinite length")]
    Unsupported,
    #[error("integer or length not in shortest form")]
    NonShortest,
    #[error("map keys must be unique text in encoded-byte order")]
    KeyOrder,
    #[error("invalid UTF-8 text")]
    Utf8,
    #[error("nesting or size limit exceeded")]
    Limit,
}

const MAX_DEPTH: usize = 16;

/// Strict AKG-CBOR-v1 decoder for the typed subset. Accepts only the encoding that
/// `Cbor::encode` produces for the decoded value, so one value has one byte form.
pub fn decode_canonical(bytes: &[u8]) -> Result<Cbor, DecodeError> {
    let mut reader = Reader { bytes, pos: 0 };
    let value = reader.item(0)?;
    if reader.pos != bytes.len() {
        return Err(DecodeError::Trailing);
    }
    Ok(value)
}

struct Reader<'a> {
    bytes: &'a [u8],
    pos: usize,
}

impl Reader<'_> {
    fn take(&mut self, n: usize) -> Result<&[u8], DecodeError> {
        let end = self.pos.checked_add(n).ok_or(DecodeError::Truncated)?;
        let slice = self
            .bytes
            .get(self.pos..end)
            .ok_or(DecodeError::Truncated)?;
        self.pos = end;
        Ok(slice)
    }

    fn argument(&mut self, info: u8) -> Result<u64, DecodeError> {
        let (n, min) = match info {
            0..=23 => return Ok(info as u64),
            24 => (self.take(1)?[0] as u64, 24),
            25 => (
                u16::from_be_bytes(self.take(2)?.try_into().unwrap()) as u64,
                256,
            ),
            26 => (
                u32::from_be_bytes(self.take(4)?.try_into().unwrap()) as u64,
                65536,
            ),
            27 => (
                u64::from_be_bytes(self.take(8)?.try_into().unwrap()),
                1 << 32,
            ),
            _ => return Err(DecodeError::Unsupported),
        };
        if n < min {
            return Err(DecodeError::NonShortest);
        }
        Ok(n)
    }

    fn length(&mut self, info: u8) -> Result<usize, DecodeError> {
        let n = self.argument(info)?;
        // Every element needs at least one byte; this bounds allocation by input size.
        if n > (self.bytes.len() - self.pos) as u64 {
            return Err(DecodeError::Truncated);
        }
        Ok(n as usize)
    }

    fn item(&mut self, depth: usize) -> Result<Cbor, DecodeError> {
        if depth > MAX_DEPTH {
            return Err(DecodeError::Limit);
        }
        let initial = self.take(1)?[0];
        let (major, info) = (initial >> 5, initial & 0x1f);
        Ok(match major {
            0 => Cbor::Uint(self.argument(info)?),
            2 => {
                let n = self.length(info)?;
                Cbor::Bytes(self.take(n)?.to_vec())
            }
            3 => {
                let n = self.length(info)?;
                let text = std::str::from_utf8(self.take(n)?).map_err(|_| DecodeError::Utf8)?;
                Cbor::Text(text.to_owned())
            }
            4 => {
                let n = self.length(info)?;
                let mut items = Vec::with_capacity(n);
                for _ in 0..n {
                    items.push(self.item(depth + 1)?);
                }
                Cbor::Array(items)
            }
            5 => {
                let n = self.length(info)?;
                let mut pairs = Vec::with_capacity(n);
                let mut previous: Option<&[u8]> = None;
                for _ in 0..n {
                    let start = self.pos;
                    let Cbor::Text(key) = self.item(depth + 1)? else {
                        return Err(DecodeError::KeyOrder);
                    };
                    let input = self.bytes;
                    let encoded_key = &input[start..self.pos];
                    if previous.is_some_and(|p| p >= encoded_key) {
                        return Err(DecodeError::KeyOrder);
                    }
                    previous = Some(encoded_key);
                    pairs.push((key, self.item(depth + 1)?));
                }
                Cbor::Map(pairs)
            }
            7 => match info {
                20 => Cbor::Bool(false),
                21 => Cbor::Bool(true),
                22 => Cbor::Null,
                _ => return Err(DecodeError::Unsupported),
            },
            // Negative integers are valid AKG-CBOR-v1 but not part of this typed subset.
            _ => return Err(DecodeError::Unsupported),
        })
    }
}

fn encode(v: &Value, field: Option<&str>) -> Vec<u8> {
    let mut out = Vec::new();
    match v {
        Value::Null => out.push(0xf6),
        Value::Bool(false) => out.push(0xf4),
        Value::Bool(true) => out.push(0xf5),
        Value::String(s) => {
            head(3, s.len() as u64, &mut out);
            out.extend(s.as_bytes());
        }
        Value::Number(n) => {
            if let Some(n) = n.as_u64() {
                head(0, n, &mut out);
            } else {
                head(
                    1,
                    (-1 - n.as_i64().expect("integer projection")) as u64,
                    &mut out,
                );
            }
        }
        Value::Array(a)
            if matches!(
                field,
                Some(
                    "hash"
                        | "target"
                        | "parameters_digest"
                        | "request_identity"
                        | "input_digest"
                        | "output_digest"
                        | "digest_element"
                        | "classification_digest"
                        | "policy_digest"
                        // AKG-IDENTITY-0001: digests and verifier key/signature
                        // material as byte strings; no existing field changes.
                        | "armored_key_digest"
                        | "bidirectional_digest"
                        | "value_digest"
                        | "proof_digest"
                        | "verifier_public_key"
                        | "verifier_signature"
                )
            ) =>
        {
            head(2, a.len() as u64, &mut out);
            out.extend(a.iter().map(|v| v.as_u64().expect("digest byte") as u8));
        }
        Value::Array(a) => {
            head(4, a.len() as u64, &mut out);
            let child = if matches!(field, Some("context_refs" | "evidence_refs")) {
                Some("digest_element")
            } else {
                None
            };
            for v in a {
                out.extend(encode(v, child));
            }
        }
        Value::Object(m) => {
            let mut pairs: Vec<_> = m
                .iter()
                .map(|(k, v)| (encode(&Value::String(k.clone()), None), encode(v, Some(k))))
                .collect();
            pairs.sort_by(|a, b| a.0.cmp(&b.0));
            head(5, pairs.len() as u64, &mut out);
            for (k, v) in pairs {
                out.extend(k);
                out.extend(v);
            }
        }
    }
    out
}
impl CanonicalEncode for WorkIntent {
    const DOMAIN_OBJECT: &'static [u8] = b"AKG:WORKINTENT:v1\0";
    fn unsigned_projection(&self) -> Value {
        let mut projection = serde_json::json!({"requested_by": self.requested_by, "intent_type": self.intent_type, "target": self.target, "parameters_digest": self.parameters_digest, "context_refs": self.context_refs, "request_identity": self.request_identity, "claimed_created_at": self.claimed_created_at});
        if !self.context.is_empty() {
            projection["context"] = serde_json::to_value(&self.context).expect("typed context");
        }
        projection
    }
}
impl CanonicalEncode for WorkerExecutionRecord {
    const DOMAIN_OBJECT: &'static [u8] = b"AKG:WER:v1\0";
    fn unsigned_projection(&self) -> Value {
        let mut projection = serde_json::json!({"module_id": self.module_id, "module_version": self.module_version, "input_digest": self.input_digest, "output_digest": self.output_digest, "evidence_refs": self.evidence_refs, "confidence_bps": self.confidence_bps, "uncertainty_note": self.uncertainty_note, "execution_id": self.execution_id});
        if let Some(operation) = self.operation {
            projection["operation"] = serde_json::to_value(operation).expect("operation");
        }
        if let Some(binding) = self.classification {
            projection["classification"] =
                serde_json::to_value(binding).expect("classification binding");
        }
        projection
    }
}
