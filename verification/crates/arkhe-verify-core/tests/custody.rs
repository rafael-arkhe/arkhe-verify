#[path = "support/custody_chain.rs"]
mod support;

use arkhe_core::{custody::CustodyTransfer, CanonicalEncode};
use arkhe_verify_core::custody::{head_digest, verify_chain, SignedTransfer};
use support::{chain, key, sign, state, transfer, ASSET};

#[test]
fn hundred_transfer_chain_verifies_offline() {
    let (transfers, signed) = chain(100);
    let v = verify_chain(ASSET, &signed).unwrap();
    assert_eq!(v.status, "VERIFIED");
    assert_eq!(v.transfers, 100);
    assert_eq!(v.head_digest, transfers[99].object_digest().to_hex());
    assert_eq!(
        v.current_holder,
        hex::encode(key(100).verifying_key().to_bytes())
    );
    assert_eq!(v.current_state, state(100).to_hex());
    assert!(!v.physical_state_verified && !v.declarations_attested);
    assert_eq!(
        head_digest(&signed).unwrap(),
        Some(transfers[99].object_digest())
    );
}

#[test]
fn every_single_byte_change_to_any_leaf_is_rejected() {
    // Three leaves cover every link position: first (no predecessor), middle
    // (linked both ways) and head (no successor). Every byte of each is flipped.
    let (_, signed) = chain(3);
    for leaf in 0..signed.len() {
        let bytes = hex::decode(&signed[leaf].transfer_cbor).unwrap();
        for pos in 0..bytes.len() {
            let mut altered = bytes.clone();
            altered[pos] ^= 0x01;
            let mut tampered = signed.clone();
            tampered[leaf].transfer_cbor = hex::encode(&altered);
            assert!(
                verify_chain(ASSET, &tampered).is_err(),
                "leaf {leaf} byte {pos} accepted"
            );
        }
    }
}

#[test]
fn role_separation_does_not_depend_on_distinct_keys() {
    // Even under one key, a releasing signature is not a receiving signature:
    // the signed preimages differ by a role tag.
    use arkhe_core::custody::CustodyRole;
    use ed25519_dalek::{Signer, Verifier};
    let t = transfer(0, None);
    let k = key(0);
    let released = k.sign(&t.signing_bytes(CustodyRole::Releasing));
    assert_ne!(
        t.signing_bytes(CustodyRole::Releasing),
        t.signing_bytes(CustodyRole::Receiving)
    );
    assert!(k
        .verifying_key()
        .verify(&t.signing_bytes(CustodyRole::Receiving), &released)
        .is_err());
}

#[test]
fn re_signed_alteration_breaks_the_link_to_the_next_transfer() {
    // An insider holding both keys of transfer 3 re-signs a changed state_after.
    let (mut transfers, mut signed) = chain(6);
    transfers[3].state_after = state(999);
    signed[3] = sign(&transfers[3], &key(3), &key(4));
    let err = verify_chain(ASSET, &signed).unwrap_err();
    assert_eq!(err, "transfer 4: does not link to the previous transfer");
}

#[test]
fn state_discontinuity_is_rejected() {
    let (mut transfers, mut signed) = chain(3);
    transfers[2].state_before = state(77);
    signed[2] = sign(&transfers[2], &key(2), &key(3));
    assert_eq!(
        verify_chain(ASSET, &signed).unwrap_err(),
        "transfer 2: state_before differs from the previous state_after"
    );
}

#[test]
fn release_by_a_party_without_custody_is_rejected() {
    let (mut transfers, mut signed) = chain(3);
    // Party 9 never held the asset but signs as the releasing party.
    transfers[2].from_party = key(9).verifying_key().to_bytes();
    signed[2] = sign(&transfers[2], &key(9), &key(3));
    assert_eq!(
        verify_chain(ASSET, &signed).unwrap_err(),
        "transfer 2: released by a party that did not hold custody"
    );
}

#[test]
fn missing_or_misplaced_signatures_are_rejected() {
    let (_, signed) = chain(2);
    let mut swapped = signed.clone();
    // The receiving signature cannot stand in for the releasing one.
    swapped[1].releasing_signature = signed[1].receiving_signature.clone();
    assert_eq!(
        verify_chain(ASSET, &swapped).unwrap_err(),
        "transfer 1: releasing signature does not verify"
    );
    let mut foreign = signed.clone();
    let t = transfer(1, Some(transfer(0, None).object_digest()));
    foreign[1].receiving_signature = sign(&t, &key(1), &key(8)).receiving_signature;
    assert_eq!(
        verify_chain(ASSET, &foreign).unwrap_err(),
        "transfer 1: receiving signature does not verify"
    );
}

#[test]
fn duplicate_transfer_id_is_rejected() {
    let (mut transfers, mut signed) = chain(3);
    transfers[2].transfer_id = transfers[0].transfer_id.clone();
    signed[2] = sign(&transfers[2], &key(2), &key(3));
    assert_eq!(
        verify_chain(ASSET, &signed).unwrap_err(),
        "transfer 2: duplicate transfer_id"
    );
}

#[test]
fn fork_reordering_and_truncation_are_rejected() {
    let (transfers, signed) = chain(4);
    // A second transfer extending transfer 1: same predecessor as transfer 2.
    let mut fork = transfer(2, Some(transfers[1].object_digest()));
    fork.transfer_id = "xfer-fork".into();
    fork.to_party = key(20).verifying_key().to_bytes();
    let fork = sign(&fork, &key(2), &key(20));
    let forked = vec![
        signed[0].clone(),
        signed[1].clone(),
        signed[2].clone(),
        fork,
    ];
    assert_eq!(
        verify_chain(ASSET, &forked).unwrap_err(),
        "transfer 3: does not link to the previous transfer"
    );
    let reordered = vec![signed[0].clone(), signed[2].clone(), signed[1].clone()];
    assert!(verify_chain(ASSET, &reordered).is_err());
    // A chain must start at its first transfer.
    assert_eq!(
        verify_chain(ASSET, &signed[1..]).unwrap_err(),
        "transfer 0: first transfer names a predecessor"
    );
    assert_eq!(verify_chain(ASSET, &[]).unwrap_err(), "chain is empty");
}

#[test]
fn wrong_asset_and_self_transfer_are_rejected() {
    let (_, signed) = chain(2);
    assert_eq!(
        verify_chain("container:OTHER", &signed).unwrap_err(),
        "transfer 0: belongs to another asset"
    );
    let mut t = transfer(0, None);
    t.to_party = t.from_party;
    let selfie = sign(&t, &key(0), &key(0));
    assert!(verify_chain(ASSET, &[selfie])
        .unwrap_err()
        .contains("cannot transfer custody to itself"));
}

#[test]
fn canonical_bytes_round_trip_and_reject_unknown_json_fields() {
    let t = transfer(0, None);
    assert_eq!(
        CustodyTransfer::from_canonical_bytes(&t.canonical_bytes()).unwrap(),
        t
    );
    let mut trailing = t.canonical_bytes();
    trailing.push(0);
    assert!(CustodyTransfer::from_canonical_bytes(&trailing).is_err());
    let json =
        r#"{"transfer_cbor":"","releasing_signature":"","receiving_signature":"","extra":1}"#;
    assert!(serde_json::from_str::<SignedTransfer>(json).is_err());
}
