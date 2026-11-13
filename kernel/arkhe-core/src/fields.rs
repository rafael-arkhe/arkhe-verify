//! Strict field extraction for typed AKG-CBOR-v1 decoders. Errors are static
//! strings; each object maps them into its own error type.
use crate::{canonical::Cbor, Digest32};

pub(crate) type FieldResult<T> = Result<T, &'static str>;

pub(crate) struct Fields(Vec<(String, Cbor)>);

impl Fields {
    pub(crate) fn new(value: Cbor) -> FieldResult<Self> {
        match value {
            Cbor::Map(pairs) => Ok(Self(pairs)),
            _ => Err("expected map"),
        }
    }
    pub(crate) fn take(&mut self, key: &'static str) -> FieldResult<Cbor> {
        let index = self
            .0
            .iter()
            .position(|(k, _)| k == key)
            .ok_or("missing field")?;
        Ok(self.0.swap_remove(index).1)
    }
    pub(crate) fn finish(self) -> FieldResult<()> {
        if self.0.is_empty() {
            Ok(())
        } else {
            Err("unknown field")
        }
    }
}

pub(crate) fn uint(v: Cbor) -> FieldResult<u64> {
    match v {
        Cbor::Uint(n) => Ok(n),
        _ => Err("expected unsigned integer"),
    }
}
pub(crate) fn text(v: Cbor) -> FieldResult<String> {
    match v {
        Cbor::Text(s) => Ok(s),
        _ => Err("expected text"),
    }
}
pub(crate) fn bytes32(v: Cbor) -> FieldResult<[u8; 32]> {
    match v {
        Cbor::Bytes(b) => b.try_into().map_err(|_| "expected 32 bytes"),
        _ => Err("expected byte string"),
    }
}
pub(crate) fn digest(v: Cbor) -> FieldResult<Digest32> {
    bytes32(v).map(Digest32)
}
pub(crate) fn nullable<T>(
    v: Cbor,
    f: impl FnOnce(Cbor) -> FieldResult<T>,
) -> FieldResult<Option<T>> {
    match v {
        Cbor::Null => Ok(None),
        other => f(other).map(Some),
    }
}

/// Identifier text: 1..=128 bytes of `[A-Za-z0-9._@+-/:]`.
pub(crate) fn is_id(s: &str) -> bool {
    !s.is_empty()
        && s.len() <= 128
        && s.bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"._@+-/:".contains(&b))
}
