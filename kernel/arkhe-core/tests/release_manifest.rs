use arkhe_core::{
    canonical::{decode_canonical, Cbor},
    release::{ReleaseError, ReleaseManifest},
    CanonicalEncode, Digest32,
};
use serde_json::Value;

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}
fn unhex(text: &str) -> Vec<u8> {
    (0..text.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&text[i..i + 2], 16).unwrap())
        .collect()
}
fn vectors() -> Vec<Value> {
    let document: Value =
        serde_json::from_str(include_str!("../../../tests/release_manifest_vectors.json")).unwrap();
    document["vectors"].as_array().unwrap().clone()
}
fn parse(input: &Value) -> Result<ReleaseManifest, String> {
    let manifest: ReleaseManifest =
        serde_json::from_value(input.clone()).map_err(|e| e.to_string())?;
    manifest.validate().map_err(|e| e.to_string())?;
    Ok(manifest)
}
fn e02() -> ReleaseManifest {
    parse(&vectors()[0]["input"]).unwrap()
}

#[test]
fn independent_python_vectors() {
    let rows = vectors();
    assert_eq!(rows.len(), 23);
    for row in rows {
        assert_eq!(row["domain_hex"], hex(ReleaseManifest::DOMAIN_OBJECT));
        let id = row["id"].as_str().unwrap();
        match (
            row["component"].as_str().unwrap(),
            row["expected"].as_str().unwrap(),
        ) {
            ("ReleaseManifest", "ACCEPT") => {
                let manifest = parse(&row["input"]).unwrap();
                let bytes = manifest.canonical_bytes();
                assert_eq!(
                    hex(&bytes),
                    row["expected_output"]["canonical_cbor_hex"],
                    "{id}"
                );
                let digest = manifest.object_digest();
                assert_eq!(
                    digest.to_hex(),
                    row["expected_output"]["object_digest_hex"],
                    "{id}"
                );
                assert_eq!(
                    ReleaseManifest::verify_bytes(&bytes, digest).unwrap(),
                    manifest
                );
            }
            ("ReleaseManifest", "REJECT") => {
                assert!(parse(&row["input"]).is_err(), "accepted {id}");
            }
            ("ReleaseManifestBytes", "REJECT") => {
                let bytes = unhex(row["input_cbor_hex"].as_str().unwrap());
                let result = match row.get("expected_digest_hex") {
                    Some(d) => ReleaseManifest::verify_bytes(
                        &bytes,
                        Digest32(unhex(d.as_str().unwrap()).try_into().unwrap()),
                    ),
                    None => ReleaseManifest::from_canonical_bytes(&bytes),
                };
                assert!(result.is_err(), "accepted {id}");
            }
            other => panic!("unknown vector kind {other:?}"),
        }
    }
}

#[test]
fn every_single_byte_alteration_is_rejected() {
    let manifest = e02();
    let bytes = manifest.canonical_bytes();
    let expected = manifest.object_digest();
    for position in 0..bytes.len() {
        for mask in [0x01u8, 0x80] {
            let mut altered = bytes.clone();
            altered[position] ^= mask;
            assert!(
                ReleaseManifest::verify_bytes(&altered, expected).is_err(),
                "accepted alteration at byte {position} mask {mask:#x}"
            );
        }
    }
}

#[test]
fn decoded_value_has_exactly_one_byte_form() {
    for row in vectors().iter().filter(|r| r["expected"] == "ACCEPT") {
        let bytes = parse(&row["input"]).unwrap().canonical_bytes();
        let value = decode_canonical(&bytes).unwrap();
        assert_eq!(value.encode(), bytes);
        let decoded = ReleaseManifest::from_canonical_bytes(&bytes).unwrap();
        assert_eq!(decoded.canonical_bytes(), bytes);
    }
}

#[test]
fn every_field_is_digest_bound() {
    let base = e02();
    let mut variants = vec![];
    let mut m = base.clone();
    m.release_id.push('x');
    variants.push(m);
    let mut m = base.clone();
    m.prev_release_digest = Some(Digest32([0; 32]));
    variants.push(m);
    let mut m = base.clone();
    m.git.tag = None;
    variants.push(m);
    let mut m = base.clone();
    m.hashtree.as_mut().unwrap().decrypt_key = None;
    variants.push(m);
    let mut m = base.clone();
    m.artifacts[1].size += 1;
    variants.push(m);
    let mut m = base.clone();
    m.artifacts[2].blake3.0[31] ^= 1;
    variants.push(m);
    let mut m = base.clone();
    m.policy_digest.0[0] ^= 1;
    variants.push(m);
    for variant in variants {
        assert_ne!(variant.object_digest(), base.object_digest());
    }
}

#[test]
fn strict_decoder_rejects_out_of_subset_items() {
    for bytes in [
        &[0x20][..],                                             // negative integer
        &[0xf9, 0x3c, 0x00],                                     // half float
        &[0xc0, 0x60],                                           // tag
        &[0x9f, 0xff],                                           // indefinite array
        &[0x62, 0xff, 0xfe],                                     // invalid UTF-8
        &[0xa1, 0x01, 0x01],                                     // non-text key
        &[0x5b, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff], // huge length
    ] {
        assert!(decode_canonical(bytes).is_err(), "{bytes:02x?}");
    }
    assert_eq!(decode_canonical(&[0xf6]).unwrap(), Cbor::Null);
    assert!(matches!(
        ReleaseManifest::from_canonical_bytes(&[0xa0]),
        Err(ReleaseError::Schema(_))
    ));
}
