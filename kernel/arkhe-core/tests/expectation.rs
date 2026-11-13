use arkhe_core::{
    expectation::{
        AbsenceRecord, Admission, ExecutionExpectation, ExpectationError, EXPECTATION_VERSION,
    },
    worker::WorkerExecutionRecord,
    CanonicalEncode, Digest32,
};

const HOUR: u64 = 3600;
const T0: u64 = 1_790_000_000;

fn hourly() -> ExecutionExpectation {
    ExecutionExpectation {
        version: EXPECTATION_VERSION,
        expectation_id: "laravel:schedule:run".into(),
        module_id: "billing-cron".into(),
        anchor_unix: T0,
        period_secs: HOUR,
        grace_secs: 300,
        policy_digest: Digest32([7; 32]),
    }
}

fn wer(module: &str, id: &str) -> WorkerExecutionRecord {
    WorkerExecutionRecord {
        classification: None,
        operation: None,
        module_id: module.into(),
        module_version: "1.0.0".into(),
        input_digest: Digest32::ZERO,
        output_digest: Digest32::ZERO,
        evidence_refs: vec![],
        confidence_bps: None,
        uncertainty_note: None,
        execution_id: id.into(),
    }
}

fn run(at: u64) -> Admission {
    Admission::of(at, &wer("billing-cron", &format!("r{at}")))
}

#[test]
fn every_window_with_a_run_yields_no_absence() {
    let e = hourly();
    let admitted: Vec<_> = (0..3).map(|k| run(T0 + k * HOUR + 10)).collect();
    let now = T0 + 3 * HOUR + 300;
    assert_eq!(e.closed_windows(now), 3);
    assert!(e.audit(0, now, &admitted).unwrap().is_empty());
}

#[test]
fn silent_window_becomes_an_absence_record() {
    let e = hourly();
    // Window 1 has no run: the cron died silently.
    let admitted = [run(T0 + 5), run(T0 + 2 * HOUR + 600)];
    let absences = e.audit(0, T0 + 3 * HOUR + 300, &admitted).unwrap();
    assert_eq!(absences.len(), 1);
    let r = &absences[0];
    assert_eq!(r.window_index, 1);
    assert_eq!(
        (r.window_start_unix, r.window_end_unix),
        (T0 + HOUR, T0 + 2 * HOUR)
    );
    assert_eq!(r.expectation_digest, e.object_digest());
    assert_eq!(r.module_id, "billing-cron");
    r.check_bound_to(&e).unwrap();
}

#[test]
fn open_window_is_never_judged() {
    let e = hourly();
    // Window 0 ended but its grace period has not elapsed.
    assert_eq!(e.closed_windows(T0 + HOUR + 299), 0);
    assert!(e.audit(0, T0 + HOUR + 299, &[]).unwrap().is_empty());
    assert_eq!(e.audit(0, T0 + HOUR + 300, &[]).unwrap().len(), 1);
    // Before the anchor nothing is closed.
    assert!(e.audit(0, T0 - 1, &[]).unwrap().is_empty());
}

#[test]
fn late_run_within_grace_satisfies_the_window() {
    let e = hourly();
    let admitted = [run(T0 + HOUR + 299)];
    assert!(e.audit(0, T0 + HOUR + 300, &admitted).unwrap().is_empty());
    let too_late = [run(T0 + HOUR + 300)];
    assert_eq!(e.audit(0, T0 + HOUR + 300, &too_late).unwrap().len(), 1);
}

#[test]
fn one_run_in_the_grace_overlap_cannot_satisfy_two_windows() {
    let e = hourly();
    // Window 0 is silent; the only later run sits in window 0's grace period,
    // which is also the start of window 1. It is credited to one window only.
    let one = [run(T0 + HOUR + 5)];
    let absences = e.audit(0, T0 + 2 * HOUR + 300, &one).unwrap();
    assert_eq!(absences.len(), 1);
    assert_eq!(absences[0].window_index, 1);
    // A second run in window 1 means both windows ran.
    let two = [run(T0 + HOUR + 5), run(T0 + HOUR + 1800)];
    assert!(e.audit(0, T0 + 2 * HOUR + 300, &two).unwrap().is_empty());
    // If window 0 ran on time, a run at the start of window 1 is simply window 1's.
    let on_time = [run(T0 + 10), run(T0 + HOUR + 5)];
    assert!(e
        .audit(0, T0 + 2 * HOUR + 300, &on_time)
        .unwrap()
        .is_empty());
}

#[test]
fn other_modules_do_not_satisfy_the_expectation() {
    let e = hourly();
    let admitted = [Admission::of(T0 + 10, &wer("mailer", "m"))];
    assert_eq!(e.audit(0, T0 + HOUR + 300, &admitted).unwrap().len(), 1);
}

#[test]
fn reaudit_is_idempotent_and_resumable() {
    let e = hourly();
    let now = T0 + 4 * HOUR + 300;
    let first = e.audit(0, now, &[]).unwrap();
    let again = e.audit(0, now, &[]).unwrap();
    let digests =
        |v: &[AbsenceRecord]| -> Vec<Digest32> { v.iter().map(|r| r.object_digest()).collect() };
    assert_eq!(digests(&first), digests(&again));
    let resumed = e.audit(2, now, &[]).unwrap();
    assert_eq!(digests(&resumed), digests(&first[2..]));
}

#[test]
fn admission_range_covers_the_previous_windows_late_runs() {
    let e = hourly();
    assert_eq!(e.admission_range(0, T0 + HOUR + 299).unwrap(), None);
    assert_eq!(
        e.admission_range(0, T0 + 2 * HOUR + 300).unwrap(),
        Some((T0, T0 + 2 * HOUR + 300))
    );
    // Resuming at window 2 still reads window 1, whose late runs window 2 excludes.
    assert_eq!(
        e.admission_range(2, T0 + 3 * HOUR + 300).unwrap(),
        Some((T0 + HOUR, T0 + 3 * HOUR + 300))
    );
    assert_eq!(e.admission_range(3, T0 + 3 * HOUR + 300).unwrap(), None);
}

type Mutation = fn(&mut ExecutionExpectation);

#[test]
fn invalid_expectations_are_rejected() {
    let cases: [(Mutation, &str); 5] = [
        (|e| e.version = 2, "unsupported version"),
        (|e| e.period_secs = 0, "period_secs"),
        (
            |e| e.grace_secs = HOUR,
            "grace_secs must be below period_secs",
        ),
        (|e| e.module_id.clear(), "module_id"),
        (|e| e.expectation_id = "bad id".into(), "expectation_id"),
    ];
    for (mutate, msg) in cases {
        let mut e = hourly();
        mutate(&mut e);
        assert_eq!(
            e.audit(0, T0 + 10 * HOUR, &[]),
            Err(ExpectationError::Schema(msg))
        );
        assert_eq!(
            ExecutionExpectation::from_canonical_bytes(&e.canonical_bytes()),
            Err(ExpectationError::Schema(msg))
        );
    }
}

#[test]
fn unbounded_backlog_fails_closed() {
    let mut e = hourly();
    e.period_secs = 1;
    e.grace_secs = 0;
    assert_eq!(
        e.audit(0, T0 + 20_000, &[]),
        Err(ExpectationError::TooManyWindows)
    );
    assert_eq!(e.audit(15_000, T0 + 20_000, &[]).unwrap().len(), 5_000);
}

#[test]
fn digests_are_domain_separated_and_field_sensitive() {
    let e = hourly();
    let r = &e.audit(0, T0 + HOUR + 300, &[]).unwrap()[0];
    assert_ne!(e.object_digest(), r.object_digest());
    let mut changed = hourly();
    changed.grace_secs = 301;
    assert_ne!(e.object_digest(), changed.object_digest());
}

#[test]
fn canonical_bytes_round_trip_strictly() {
    let e = hourly();
    let r = e.audit(0, T0 + HOUR + 300, &[]).unwrap().remove(0);
    let eb = e.canonical_bytes();
    let rb = r.canonical_bytes();
    assert_eq!(ExecutionExpectation::from_canonical_bytes(&eb).unwrap(), e);
    assert_eq!(AbsenceRecord::from_canonical_bytes(&rb).unwrap(), r);
    for bytes in [&eb, &rb] {
        let mut trailing = bytes.clone();
        trailing.push(0);
        assert!(ExecutionExpectation::from_canonical_bytes(&trailing).is_err());
        assert!(AbsenceRecord::from_canonical_bytes(&trailing).is_err());
    }
    // Neither type decodes as the other.
    assert!(ExecutionExpectation::from_canonical_bytes(&rb).is_err());
    assert!(AbsenceRecord::from_canonical_bytes(&eb).is_err());
}

#[test]
fn absence_bound_to_another_expectation_or_window_is_rejected() {
    let e = hourly();
    let r = e.audit(0, T0 + HOUR + 300, &[]).unwrap().remove(0);
    let mut other = hourly();
    other.grace_secs = 60;
    assert_eq!(
        r.check_bound_to(&other),
        Err(ExpectationError::Mismatch("expectation_digest"))
    );
    let mut shifted = r.clone();
    shifted.window_start_unix += 1;
    assert_eq!(
        shifted.check_bound_to(&e),
        Err(ExpectationError::Mismatch("window bounds"))
    );
    let mut renamed = r;
    renamed.module_id = "mailer".into();
    assert_eq!(
        renamed.check_bound_to(&e),
        Err(ExpectationError::Mismatch("module_id"))
    );
}

#[test]
fn admission_reads_module_id_from_stored_wer_bytes() {
    let w = wer("billing-cron", "x");
    assert_eq!(
        Admission::from_wer_bytes(T0, &w.canonical_bytes()),
        Some(Admission::of(T0, &w))
    );
    assert_eq!(Admission::from_wer_bytes(T0, b"not cbor"), None);
    assert_eq!(
        Admission::from_wer_bytes(T0, &hourly().canonical_bytes()).map(|a| a.module_id),
        Some("billing-cron".into()),
        "callers must only pass bytes stored as WorkerExecutionRecord"
    );
}
