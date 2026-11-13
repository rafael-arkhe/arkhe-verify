use arkhe_core::{expectation::EXPECTATION_VERSION, CanonicalEncode};
use arkhe_verify_core::absence::{verify, ExpectationSpec};

const HOUR: u64 = 3600;
const T0: u64 = 1_790_000_000;

fn spec() -> ExpectationSpec {
    ExpectationSpec {
        version: EXPECTATION_VERSION,
        expectation_id: "laravel:schedule:run".into(),
        module_id: "billing-cron".into(),
        anchor_unix: T0,
        period_secs: HOUR,
        grace_secs: 300,
        policy_digest: "07".repeat(32),
    }
}

/// The digest the auditor commits for window 1 (no admissions at all).
fn committed_hash() -> String {
    let e = spec().expectation().unwrap();
    let records = e.audit(0, T0 + 2 * HOUR + 300, &[]).unwrap();
    records[1].object_digest().to_hex()
}

#[test]
fn auditor_record_verifies_offline() {
    let v = verify(&spec(), 1, &committed_hash(), T0 + 2 * HOUR + 300).unwrap();
    assert_eq!(v.status, "VERIFIED");
    assert_eq!(
        (v.window_start_unix, v.window_end_unix),
        (T0 + HOUR, T0 + 2 * HOUR)
    );
    assert!(!v.silence_reverified);
    let json = serde_json::to_value(&v).unwrap();
    assert_eq!(json["profile"], "arkhe-absence@1");
}

#[test]
fn wrong_window_or_expectation_is_rejected() {
    let hash = committed_hash();
    assert!(verify(&spec(), 0, &hash, T0 + 2 * HOUR + 300).is_err());
    let mut other = spec();
    other.grace_secs = 60;
    assert!(verify(&other, 1, &hash, T0 + 2 * HOUR + 300).is_err());
}

#[test]
fn open_window_cannot_carry_an_absence() {
    let err = verify(&spec(), 1, &committed_hash(), T0 + 2 * HOUR + 299).unwrap_err();
    assert_eq!(err, "window was not closed at the given time");
}

#[test]
fn malformed_inputs_are_rejected() {
    let hash = committed_hash();
    assert!(verify(&spec(), 1, &hash.to_uppercase(), T0 + 3 * HOUR).is_err());
    assert!(verify(&spec(), 1, &hash[..62], T0 + 3 * HOUR).is_err());
    let mut bad = spec();
    bad.policy_digest = "zz".repeat(32);
    assert!(verify(&bad, 1, &hash, T0 + 3 * HOUR).is_err());
    let mut invalid = spec();
    invalid.period_secs = 0;
    assert!(verify(&invalid, 1, &hash, T0 + 3 * HOUR).is_err());
    let unknown = r#"{"version":1,"expectation_id":"x","module_id":"m","anchor_unix":0,
        "period_secs":60,"grace_secs":0,"policy_digest":"","extra":1}"#;
    assert!(serde_json::from_str::<ExpectationSpec>(unknown).is_err());
}
