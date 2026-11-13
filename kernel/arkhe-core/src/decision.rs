//! DecisionVerdict v1 (AKG:VERDICT:v1). The gate's only output: a binary
//! decision bound to a closed reason, so a reader can always tell a `Reject`
//! that a rule made from one caused by missing policy or a failed engine.
//! Anchor the verdict, not the bare decision; the decision alone loses that
//! distinction.
use crate::canonical::{decode_canonical, Cbor, DecodeError};
use crate::fields::{digest, is_id, nullable, text, uint, Fields};
use crate::{CanonicalEncode, Digest32};
use serde::{Deserialize, Serialize};

pub const VERDICT_VERSION: u64 = 1;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Decision {
    Allow,
    Reject,
}

/// Closed set. Adding a reason is a new verdict version.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum DecisionReason {
    /// A loaded policy has a rule for this event type and it allows.
    RuleAllowed,
    /// A loaded policy has a rule for this event type and it rejects.
    RuleRejected,
    /// The policy loaded but no rule covers this event type. Rejected
    /// fail-closed; this is where human review would apply if it existed.
    NoRuleMatched,
    /// The policy could not be loaded or evaluated. An infrastructure
    /// failure, not a decision about the event.
    PolicyUnavailable,
    /// The local emergency stop was set. Takes precedence over policy.
    EmergencyStop,
}

impl DecisionReason {
    fn as_str(self) -> &'static str {
        match self {
            Self::RuleAllowed => "RULE_ALLOWED",
            Self::RuleRejected => "RULE_REJECTED",
            Self::NoRuleMatched => "NO_RULE_MATCHED",
            Self::PolicyUnavailable => "POLICY_UNAVAILABLE",
            Self::EmergencyStop => "EMERGENCY_STOP",
        }
    }
    fn parse(s: &str) -> Option<Self> {
        [
            Self::RuleAllowed,
            Self::RuleRejected,
            Self::NoRuleMatched,
            Self::PolicyUnavailable,
            Self::EmergencyStop,
        ]
        .into_iter()
        .find(|r| r.as_str() == s)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DecisionVerdict {
    pub version: u64,
    /// Digest of what was decided on (e.g. a SecurityEvent).
    pub subject: Digest32,
    pub event_type: String,
    pub policy_id: String,
    /// Digest of the policy that was evaluated; `None` when it was not loaded.
    pub policy_digest: Option<Digest32>,
    /// The rule that decided; present exactly for rule reasons.
    pub rule_id: Option<String>,
    pub decision: Decision,
    pub reason: DecisionReason,
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum VerdictError {
    #[error("canonical CBOR: {0}")]
    Cbor(#[from] DecodeError),
    #[error("schema: {0}")]
    Schema(&'static str),
}

impl From<&'static str> for VerdictError {
    fn from(m: &'static str) -> Self {
        Self::Schema(m)
    }
}

impl DecisionVerdict {
    /// True when the decision rests on missing coverage or a failed policy,
    /// not on a rule: the cases a later review must look at.
    pub fn degraded(&self) -> bool {
        matches!(
            self.reason,
            DecisionReason::NoRuleMatched | DecisionReason::PolicyUnavailable
        )
    }

    /// Rejects any verdict whose fields contradict its reason.
    pub fn validate(&self) -> Result<(), VerdictError> {
        use DecisionReason::*;
        let fail = |m| Err(VerdictError::Schema(m));
        if self.version != VERDICT_VERSION {
            return fail("unsupported version");
        }
        if !is_id(&self.event_type) || !is_id(&self.policy_id) {
            return fail("event_type or policy_id");
        }
        if self.rule_id.as_deref().is_some_and(|r| !is_id(r)) {
            return fail("rule_id");
        }
        let expected = match self.reason {
            RuleAllowed => Decision::Allow,
            _ => Decision::Reject,
        };
        if self.decision != expected {
            return fail("decision contradicts reason");
        }
        let rule = matches!(self.reason, RuleAllowed | RuleRejected);
        if rule != self.rule_id.is_some() {
            return fail("rule_id must be present exactly for rule reasons");
        }
        if rule && self.policy_digest.is_none() {
            return fail("a rule decision needs the evaluated policy digest");
        }
        if self.reason == PolicyUnavailable && self.policy_digest.is_some() {
            return fail("an unavailable policy has no digest");
        }
        if self.reason == NoRuleMatched && self.policy_digest.is_none() {
            return fail("no-rule-matched needs the evaluated policy digest");
        }
        Ok(())
    }

    pub fn to_cbor(&self) -> Cbor {
        let opt_bytes = |d: Option<Digest32>| d.map_or(Cbor::Null, |d| Cbor::Bytes(d.0.to_vec()));
        Cbor::Map(
            [
                ("version", Cbor::Uint(self.version)),
                ("subject", Cbor::Bytes(self.subject.0.to_vec())),
                ("event_type", Cbor::Text(self.event_type.clone())),
                ("policy_id", Cbor::Text(self.policy_id.clone())),
                ("policy_digest", opt_bytes(self.policy_digest)),
                (
                    "rule_id",
                    self.rule_id.clone().map_or(Cbor::Null, Cbor::Text),
                ),
                (
                    "decision",
                    Cbor::Text(
                        match self.decision {
                            Decision::Allow => "ALLOW",
                            Decision::Reject => "REJECT",
                        }
                        .into(),
                    ),
                ),
                ("reason", Cbor::Text(self.reason.as_str().into())),
            ]
            .into_iter()
            .map(|(k, v)| (k.to_owned(), v))
            .collect(),
        )
    }

    /// Strict inverse of `canonical_bytes`.
    pub fn from_canonical_bytes(input: &[u8]) -> Result<Self, VerdictError> {
        let mut f = Fields::new(decode_canonical(input)?)?;
        let value = Self {
            version: uint(f.take("version")?)?,
            subject: digest(f.take("subject")?)?,
            event_type: text(f.take("event_type")?)?,
            policy_id: text(f.take("policy_id")?)?,
            policy_digest: nullable(f.take("policy_digest")?, digest)?,
            rule_id: nullable(f.take("rule_id")?, text)?,
            decision: match text(f.take("decision")?)?.as_str() {
                "ALLOW" => Decision::Allow,
                "REJECT" => Decision::Reject,
                _ => return Err(VerdictError::Schema("decision")),
            },
            reason: DecisionReason::parse(&text(f.take("reason")?)?)
                .ok_or(VerdictError::Schema("reason"))?,
        };
        f.finish()?;
        value.validate()?;
        Ok(value)
    }
}

impl CanonicalEncode for DecisionVerdict {
    const DOMAIN_OBJECT: &'static [u8] = b"AKG:VERDICT:v1\0";

    fn unsigned_projection(&self) -> serde_json::Value {
        serde_json::to_value(self).expect("typed DecisionVerdict")
    }

    fn canonical_bytes(&self) -> Vec<u8> {
        self.to_cbor().encode()
    }
}
