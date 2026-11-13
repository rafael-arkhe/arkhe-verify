//! ExecutionExpectation v1 (AKG:EXPECT:v1) and AbsenceRecord v1 (AKG:ABSENCE:v1).
//! A WER proves that work ran; it cannot prove that work which should have run
//! did not. An expectation declares a cadence for one module; auditing it
//! against admitted WERs turns each silent window into positive evidence.
//! Pure and clock-free: the caller supplies `now` and admission times taken
//! from the evidence log, never from the worker's own claims.
use crate::canonical::{decode_canonical, Cbor, DecodeError};
use crate::fields::{digest, is_id, text, uint, Fields};
use crate::{worker::WorkerExecutionRecord, CanonicalEncode, Digest32};
use serde::{Deserialize, Serialize};

pub const EXPECTATION_VERSION: u64 = 1;
pub const ABSENCE_VERSION: u64 = 1;
/// Bounds one audit call; callers advance `from_window` to catch up further.
pub const MAX_WINDOWS_PER_AUDIT: u64 = 10_000;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ExecutionExpectation {
    pub version: u64,
    pub expectation_id: String,
    /// Matched against `WorkerExecutionRecord::module_id`.
    pub module_id: String,
    /// Start of window 0, in Unix seconds.
    pub anchor_unix: u64,
    /// Window `k` is `[anchor + k*period, anchor + (k+1)*period)`.
    pub period_secs: u64,
    /// Late admissions up to `grace_secs` after a window still satisfy it.
    /// Strictly less than `period_secs`.
    pub grace_secs: u64,
    pub policy_digest: Digest32,
}

/// Evidence that no matching WER was admitted for one closed window.
/// Contains no evaluation time, so re-auditing a window yields the same digest.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AbsenceRecord {
    pub version: u64,
    pub expectation_digest: Digest32,
    pub module_id: String,
    pub window_index: u64,
    pub window_start_unix: u64,
    pub window_end_unix: u64,
}

/// One WER admission as seen by the evidence log. `admitted_at_unix` is the
/// log's own admission time; a worker-supplied timestamp must never be used.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Admission {
    pub admitted_at_unix: u64,
    pub module_id: String,
}

impl Admission {
    pub fn of(admitted_at_unix: u64, wer: &WorkerExecutionRecord) -> Self {
        Self {
            admitted_at_unix,
            module_id: wer.module_id.clone(),
        }
    }

    /// Reads `module_id` from stored canonical WER bytes without trusting any
    /// other field; the bytes come from the store, keyed by their digest.
    pub fn from_wer_bytes(admitted_at_unix: u64, canonical: &[u8]) -> Option<Self> {
        match decode_canonical(canonical).ok()? {
            Cbor::Map(pairs) => pairs.into_iter().find_map(|(k, v)| match (k.as_str(), v) {
                ("module_id", Cbor::Text(module_id)) => Some(Self {
                    admitted_at_unix,
                    module_id,
                }),
                _ => None,
            }),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ExpectationError {
    #[error("canonical CBOR: {0}")]
    Cbor(#[from] DecodeError),
    #[error("schema: {0}")]
    Schema(&'static str),
    #[error("absence record does not match its expectation: {0}")]
    Mismatch(&'static str),
    #[error("window arithmetic overflows u64")]
    Overflow,
    #[error("audit spans more than {MAX_WINDOWS_PER_AUDIT} windows")]
    TooManyWindows,
}

impl From<&'static str> for ExpectationError {
    fn from(m: &'static str) -> Self {
        Self::Schema(m)
    }
}

impl ExecutionExpectation {
    pub fn validate(&self) -> Result<(), ExpectationError> {
        let fail = |m| Err(ExpectationError::Schema(m));
        if self.version != EXPECTATION_VERSION {
            return fail("unsupported version");
        }
        if !is_id(&self.expectation_id) {
            return fail("expectation_id");
        }
        if !is_id(&self.module_id) {
            return fail("module_id");
        }
        if self.period_secs == 0 {
            return fail("period_secs");
        }
        if self.grace_secs >= self.period_secs {
            return fail("grace_secs must be below period_secs");
        }
        Ok(())
    }

    /// `[start, end)` of window `k`.
    pub fn window(&self, k: u64) -> Result<(u64, u64), ExpectationError> {
        let start = k
            .checked_mul(self.period_secs)
            .and_then(|o| o.checked_add(self.anchor_unix))
            .ok_or(ExpectationError::Overflow)?;
        let end = start
            .checked_add(self.period_secs)
            .ok_or(ExpectationError::Overflow)?;
        Ok((start, end))
    }

    /// Number of windows whose grace period has fully elapsed at `now_unix`.
    pub fn closed_windows(&self, now_unix: u64) -> u64 {
        self.anchor_unix
            .checked_add(self.grace_secs)
            .and_then(|first_close| now_unix.checked_sub(first_close))
            .and_then(|elapsed| elapsed.checked_div(self.period_secs))
            .unwrap_or(0)
    }

    /// Audit every closed window from `from_window` on against the WER
    /// admissions of the evidence log. Open windows are never judged: absence
    /// is only asserted once the grace period has passed.
    pub fn audit(
        &self,
        from_window: u64,
        now_unix: u64,
        admitted: &[Admission],
    ) -> Result<Vec<AbsenceRecord>, ExpectationError> {
        self.validate()?;
        let closed = self.closed_windows(now_unix);
        if closed.saturating_sub(from_window) > MAX_WINDOWS_PER_AUDIT {
            return Err(ExpectationError::TooManyWindows);
        }
        let times: Vec<u64> = admitted
            .iter()
            .filter(|a| a.module_id == self.module_id)
            .map(|a| a.admitted_at_unix)
            .collect();
        let in_range = |from: u64, to: u64| {
            times
                .iter()
                .copied()
                .filter(move |t| (from..to).contains(t))
        };
        // A run admitted in the first `grace_secs` of window k+1 is late for
        // window k only when k had no on-time run. Each run then credits at
        // most one window, so a single run can never hide a silent window.
        let late_for = |k: u64| -> Result<Vec<u64>, ExpectationError> {
            let (start, end) = self.window(k)?;
            if in_range(start, end).next().is_some() {
                return Ok(Vec::new());
            }
            let late_end = end
                .checked_add(self.grace_secs)
                .ok_or(ExpectationError::Overflow)?;
            Ok(in_range(end, late_end).collect())
        };
        let expectation_digest = self.object_digest();
        let mut absences = Vec::new();
        for k in from_window..closed {
            let (start, end) = self.window(k)?;
            let credited_to_previous = match k.checked_sub(1) {
                Some(prev) => late_for(prev)?,
                None => Vec::new(),
            };
            let satisfied = in_range(start, end).any(|t| !credited_to_previous.contains(&t))
                || !late_for(k)?.is_empty();
            if !satisfied {
                absences.push(AbsenceRecord {
                    version: ABSENCE_VERSION,
                    expectation_digest,
                    module_id: self.module_id.clone(),
                    window_index: k,
                    window_start_unix: start,
                    window_end_unix: end,
                });
            }
        }
        Ok(absences)
    }

    /// `[from, until)` of admission times that `audit(from_window, now)` reads,
    /// including the previous window's late runs. `None` if nothing is closed.
    pub fn admission_range(
        &self,
        from_window: u64,
        now_unix: u64,
    ) -> Result<Option<(u64, u64)>, ExpectationError> {
        let closed = self.closed_windows(now_unix);
        if closed <= from_window {
            return Ok(None);
        }
        let (from, _) = self.window(from_window.saturating_sub(1))?;
        let (_, last_end) = self.window(closed - 1)?;
        let until = last_end
            .checked_add(self.grace_secs)
            .ok_or(ExpectationError::Overflow)?;
        Ok(Some((from, until)))
    }

    /// Strict inverse of `canonical_bytes`.
    pub fn from_canonical_bytes(input: &[u8]) -> Result<Self, ExpectationError> {
        let mut f = Fields::new(decode_canonical(input)?)?;
        let value = Self {
            version: uint(f.take("version")?)?,
            expectation_id: text(f.take("expectation_id")?)?,
            module_id: text(f.take("module_id")?)?,
            anchor_unix: uint(f.take("anchor_unix")?)?,
            period_secs: uint(f.take("period_secs")?)?,
            grace_secs: uint(f.take("grace_secs")?)?,
            policy_digest: digest(f.take("policy_digest")?)?,
        };
        f.finish()?;
        value.validate()?;
        Ok(value)
    }

    pub fn to_cbor(&self) -> Cbor {
        map(vec![
            ("version", Cbor::Uint(self.version)),
            ("expectation_id", Cbor::Text(self.expectation_id.clone())),
            ("module_id", Cbor::Text(self.module_id.clone())),
            ("anchor_unix", Cbor::Uint(self.anchor_unix)),
            ("period_secs", Cbor::Uint(self.period_secs)),
            ("grace_secs", Cbor::Uint(self.grace_secs)),
            ("policy_digest", bytes(self.policy_digest)),
        ])
    }
}

impl AbsenceRecord {
    /// Checks that this record names `expectation` and one of its windows.
    /// It cannot show the window was silent: that needs the admission log.
    pub fn check_bound_to(
        &self,
        expectation: &ExecutionExpectation,
    ) -> Result<(), ExpectationError> {
        let fail = |m| Err(ExpectationError::Mismatch(m));
        expectation.validate()?;
        if self.version != ABSENCE_VERSION {
            return Err(ExpectationError::Schema("unsupported version"));
        }
        if self.expectation_digest != expectation.object_digest() {
            return fail("expectation_digest");
        }
        if self.module_id != expectation.module_id {
            return fail("module_id");
        }
        if expectation.window(self.window_index)? != (self.window_start_unix, self.window_end_unix)
        {
            return fail("window bounds");
        }
        Ok(())
    }

    /// Strict inverse of `canonical_bytes`.
    pub fn from_canonical_bytes(input: &[u8]) -> Result<Self, ExpectationError> {
        let mut f = Fields::new(decode_canonical(input)?)?;
        let value = Self {
            version: uint(f.take("version")?)?,
            expectation_digest: digest(f.take("expectation_digest")?)?,
            module_id: text(f.take("module_id")?)?,
            window_index: uint(f.take("window_index")?)?,
            window_start_unix: uint(f.take("window_start_unix")?)?,
            window_end_unix: uint(f.take("window_end_unix")?)?,
        };
        f.finish()?;
        if value.version != ABSENCE_VERSION {
            return Err(ExpectationError::Schema("unsupported version"));
        }
        if !is_id(&value.module_id) {
            return Err(ExpectationError::Schema("module_id"));
        }
        Ok(value)
    }

    pub fn to_cbor(&self) -> Cbor {
        map(vec![
            ("version", Cbor::Uint(self.version)),
            ("expectation_digest", bytes(self.expectation_digest)),
            ("module_id", Cbor::Text(self.module_id.clone())),
            ("window_index", Cbor::Uint(self.window_index)),
            ("window_start_unix", Cbor::Uint(self.window_start_unix)),
            ("window_end_unix", Cbor::Uint(self.window_end_unix)),
        ])
    }
}

impl CanonicalEncode for ExecutionExpectation {
    const DOMAIN_OBJECT: &'static [u8] = b"AKG:EXPECT:v1\0";

    fn unsigned_projection(&self) -> serde_json::Value {
        serde_json::to_value(self).expect("typed ExecutionExpectation")
    }

    fn canonical_bytes(&self) -> Vec<u8> {
        self.to_cbor().encode()
    }
}

impl CanonicalEncode for AbsenceRecord {
    const DOMAIN_OBJECT: &'static [u8] = b"AKG:ABSENCE:v1\0";

    fn unsigned_projection(&self) -> serde_json::Value {
        serde_json::to_value(self).expect("typed AbsenceRecord")
    }

    fn canonical_bytes(&self) -> Vec<u8> {
        self.to_cbor().encode()
    }
}

fn map(pairs: Vec<(&str, Cbor)>) -> Cbor {
    Cbor::Map(pairs.into_iter().map(|(k, v)| (k.to_owned(), v)).collect())
}
fn bytes(d: Digest32) -> Cbor {
    Cbor::Bytes(d.0.to_vec())
}
