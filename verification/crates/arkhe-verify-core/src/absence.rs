//! Offline verification of AbsenceRecord evidence. A WormGraph envelope of kind
//! `AbsenceRecord` commits only a digest; this regenerates the record from the
//! expectation and window index and checks the digest. It proves the record
//! names that expectation and window. It does not prove the window was silent:
//! that claim rests on the admission log the auditor read.
use arkhe_core::{
    expectation::{AbsenceRecord, ExecutionExpectation, ABSENCE_VERSION},
    CanonicalEncode, Digest32,
};
use serde::{Deserialize, Serialize};

pub const PROFILE: &str = "arkhe-absence@1";

/// JSON form of an `ExecutionExpectation`, with the policy digest in hex.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ExpectationSpec {
    pub version: u64,
    pub expectation_id: String,
    pub module_id: String,
    pub anchor_unix: u64,
    pub period_secs: u64,
    pub grace_secs: u64,
    pub policy_digest: String,
}

impl ExpectationSpec {
    pub fn expectation(&self) -> Result<ExecutionExpectation, String> {
        let e = ExecutionExpectation {
            version: self.version,
            expectation_id: self.expectation_id.clone(),
            module_id: self.module_id.clone(),
            anchor_unix: self.anchor_unix,
            period_secs: self.period_secs,
            grace_secs: self.grace_secs,
            policy_digest: parse_digest(&self.policy_digest)?,
        };
        e.validate().map_err(|e| e.to_string())?;
        Ok(e)
    }
}

#[derive(Debug, Serialize)]
pub struct Verdict {
    pub profile: &'static str,
    pub status: &'static str,
    pub expectation_digest: String,
    pub record_hash: String,
    pub module_id: String,
    pub window_index: u64,
    pub window_start_unix: u64,
    pub window_end_unix: u64,
    /// Always false: silence is attested by the auditor, not re-derived here.
    pub silence_reverified: bool,
}

/// Accept `record_hash` only if it is the digest of the absence record for
/// `window_index` of `spec`, and that window was closed at `now_unix`.
pub fn verify(
    spec: &ExpectationSpec,
    window_index: u64,
    record_hash: &str,
    now_unix: u64,
) -> Result<Verdict, String> {
    let e = spec.expectation()?;
    let claimed = parse_digest(record_hash)?;
    if window_index >= e.closed_windows(now_unix) {
        return Err("window was not closed at the given time".into());
    }
    let (start, end) = e.window(window_index).map_err(|e| e.to_string())?;
    let record = AbsenceRecord {
        version: ABSENCE_VERSION,
        expectation_digest: e.object_digest(),
        module_id: e.module_id.clone(),
        window_index,
        window_start_unix: start,
        window_end_unix: end,
    };
    record.check_bound_to(&e).map_err(|e| e.to_string())?;
    if record.object_digest() != claimed {
        return Err("record_hash is not this expectation's absence record for the window".into());
    }
    Ok(Verdict {
        profile: PROFILE,
        status: "VERIFIED",
        expectation_digest: record.expectation_digest.to_hex(),
        record_hash: claimed.to_hex(),
        module_id: record.module_id,
        window_index,
        window_start_unix: start,
        window_end_unix: end,
        silence_reverified: false,
    })
}

fn parse_digest(s: &str) -> Result<Digest32, String> {
    if s.len() != 64 || !s.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f')) {
        return Err("digest must be 64 lowercase hex characters".into());
    }
    let bytes = hex::decode(s).map_err(|e| e.to_string())?;
    Ok(Digest32(bytes.try_into().expect("32 bytes")))
}
