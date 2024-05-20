#![cfg(feature = "serde")]

mod helpers;

use frost_bjj::{
    keys::{
        dkg::{round1, round2},
        KeyPackage, PublicKeyPackage, SecretShare,
    },
    round1::SigningCommitments,
    round2::SignatureShare,
    SigningPackage,
};

use helpers::samples;

#[test]
fn check_signing_commitments_serialization() {
    let commitments = samples::signing_commitments();

    let json = serde_json::to_string_pretty(&commitments).unwrap();
    println!("{}", json);

    let decoded_commitments: SigningCommitments = serde_json::from_str(&json).unwrap();
    assert!(commitments == decoded_commitments);

    let json = r#"{
        "hiding": "8b7d2d877a253c4b7733e1b91f05e0fcedf96bd11c2e572549b2a0f703727925",
        "binding": "53686d2b4005178e1843106f2992a867a01d8a84afbe9e8bda300abfaf6c6601",
        "ciphersuite": "FROST(babyjubjub, SHA-256)"
      }"#;
    let decoded_commitments: SigningCommitments = serde_json::from_str(json).unwrap();
    assert!(commitments == decoded_commitments);

    let invalid_json = "{}";
    assert!(serde_json::from_str::<SigningCommitments>(invalid_json).is_err());

    // Wrong ciphersuite
    let invalid_json = r#"{
      "hiding": "8b7d2d877a253c4b7733e1b91f05e0fcedf96bd11c2e572549b2a0f703727925",
      "binding": "53686d2b4005178e1843106f2992a867a01d8a84afbe9e8bda300abfaf6c6601",
      "ciphersuite": "FROST(Wrong, SHA-512)"
    }"#;
    assert!(serde_json::from_str::<SigningCommitments>(invalid_json).is_err());

    // Invalid identifier
    let invalid_json = r#"{
        "hiding": "8b7d2d877a253c4b7733e1b91f05e0fcedf96bd11c2e572549b2a0f703727925",
        "binding": "53686d2b4005178e1843106f2992a867a01d8a84afbe9e8bda300abfaf6c6601"
      }"#;
    assert!(serde_json::from_str::<SigningCommitments>(invalid_json).is_err());

    // Invalid field
    let invalid_json = r#"{
        "foo": "8b7d2d877a253c4b7733e1b91f05e0fcedf96bd11c2e572549b2a0f703727925",
        "binding": "53686d2b4005178e1843106f2992a867a01d8a84afbe9e8bda300abfaf6c6601"
      }"#;
    assert!(serde_json::from_str::<SigningCommitments>(invalid_json).is_err());

    // Missing field
    let invalid_json = r#"{
        "foo": "0000000000000000000000000000000000000000000000000000000000000000",
        "binding": "53686d2b4005178e1843106f2992a867a01d8a84afbe9e8bda300abfaf6c6601"
      }"#;
    assert!(serde_json::from_str::<SigningCommitments>(invalid_json).is_err());

    // Extra field
    let invalid_json = r#"{
        "hiding": "8b7d2d877a253c4b7733e1b91f05e0fcedf96bd11c2e572549b2a0f703727925",
        "binding": "53686d2b4005178e1843106f2992a867a01d8a84afbe9e8bda300abfaf6c6601",
        "extra": 1
      }"#;
    assert!(serde_json::from_str::<SigningCommitments>(invalid_json).is_err());
}

#[test]
fn check_signing_package_serialization() {
    let signing_package = samples::signing_package();

    let json = serde_json::to_string_pretty(&signing_package).unwrap();
    println!("{}", json);

    let decoded_signing_package: SigningPackage = serde_json::from_str(&json).unwrap();
    assert!(signing_package == decoded_signing_package);

    let invalid_json = "{}";
    assert!(serde_json::from_str::<SigningPackage>(invalid_json).is_err());

    let json = r#"{
      "signing_commitments": {
        "2a00000000000000000000000000000000000000000000000000000000000000": {
          "hiding": "8b7d2d877a253c4b7733e1b91f05e0fcedf96bd11c2e572549b2a0f703727925",
          "binding": "53686d2b4005178e1843106f2992a867a01d8a84afbe9e8bda300abfaf6c6601",
          "ciphersuite": "FROST(babyjubjub, SHA-256)"
        }
      },
      "message": "68656c6c6f20776f726c64",
      "ciphersuite": "FROST(babyjubjub, SHA-256)"
    }"#;
    let decoded_signing_package: SigningPackage = serde_json::from_str(json).unwrap();
    assert!(signing_package == decoded_signing_package);

    // Invalid identifier
    let invalid_json = r#"{
      "signing_commitments": {
        "0000000000000000000000000000000000000000000000000000000000000000": {
          "hiding": "8b7d2d877a253c4b7733e1b91f05e0fcedf96bd11c2e572549b2a0f703727925",
          "binding": "53686d2b4005178e1843106f2992a867a01d8a84afbe9e8bda300abfaf6c6601",
          "ciphersuite": "FROST(babyjubjub, SHA-256)"
        }
      },
      "message": "68656c6c6f20776f726c64",
      "ciphersuite": "FROST(babyjubjub, SHA-256)"
    }"#;
    assert!(serde_json::from_str::<SigningPackage>(invalid_json).is_err());

    // Invalid field
    let invalid_json = r#"{
      "signing_commitments": {
        "2a00000000000000000000000000000000000000000000000000000000000000": {
          "foo": "8b7d2d877a253c4b7733e1b91f05e0fcedf96bd11c2e572549b2a0f703727925",
          "binding": "53686d2b4005178e1843106f2992a867a01d8a84afbe9e8bda300abfaf6c6601",
          "ciphersuite": "FROST(babyjubjub, SHA-256)"
        }
      },
      "message": "68656c6c6f20776f726c64",
      "ciphersuite": "FROST(babyjubjub, SHA-256)"
    }"#;
    assert!(serde_json::from_str::<SigningPackage>(invalid_json).is_err());

    // Missing field
    let invalid_json = r#"{
      "signing_commitments": {
        "2a00000000000000000000000000000000000000000000000000000000000000": {
          "binding": "53686d2b4005178e1843106f2992a867a01d8a84afbe9e8bda300abfaf6c6601",
          "ciphersuite": "FROST(babyjubjub, SHA-256)"
        }
      },
      "message": "68656c6c6f20776f726c64",
      "ciphersuite": "FROST(babyjubjub, SHA-256)"
    }"#;
    assert!(serde_json::from_str::<SigningPackage>(invalid_json).is_err());

    // Extra field
    let invalid_json = r#"{
      "signing_commitments": {
        "2a00000000000000000000000000000000000000000000000000000000000000": {
          "hiding": "8b7d2d877a253c4b7733e1b91f05e0fcedf96bd11c2e572549b2a0f703727925",
          "binding": "53686d2b4005178e1843106f2992a867a01d8a84afbe9e8bda300abfaf6c6601",
          "ciphersuite": "FROST(babyjubjub, SHA-256)"
        }
      },
      "message": "68656c6c6f20776f726c64",
      "extra": 1,
      "ciphersuite": "FROST(babyjubjub, SHA-256)"
    }
    "#;
    assert!(serde_json::from_str::<SigningPackage>(invalid_json).is_err());
}

#[test]
fn check_signature_share_serialization() {
    let signature_share = samples::signature_share();

    let json = serde_json::to_string_pretty(&signature_share).unwrap();
    println!("{}", json);

    let decoded_signature_share: SignatureShare = serde_json::from_str(&json).unwrap();
    assert!(signature_share == decoded_signature_share);

    let json = r#"{
      "share": "a1c4c0d092baa1ef06f41526d0f32972b21c20e079b0067a037819e8de5b0804",
      "ciphersuite": "FROST(babyjubjub, SHA-256)"
    }"#;
    let decoded_commitments: SignatureShare = serde_json::from_str(json).unwrap();
    assert!(signature_share == decoded_commitments);

    let invalid_json = "{}";
    assert!(serde_json::from_str::<SignatureShare>(invalid_json).is_err());

    // Invalid field
    let invalid_json = r#"{
        "foo": "a1c4c0d092baa1ef06f41526d0f32972b21c20e079b0067a037819e8de5b0804",
        "ciphersuite": "FROST(babyjubjub, SHA-256)"
      }"#;
    assert!(serde_json::from_str::<SignatureShare>(invalid_json).is_err());

    // Missing field
    let invalid_json = r#"{
        "ciphersuite": "FROST(babyjubjub, SHA-256)"
      }"#;
    assert!(serde_json::from_str::<SignatureShare>(invalid_json).is_err());

    // Extra field
    let invalid_json = r#"{
        "share": "a1c4c0d092baa1ef06f41526d0f32972b21c20e079b0067a037819e8de5b0804",
        "extra": 1,
        "ciphersuite": "FROST(babyjubjub, SHA-256)"
      }"#;
    assert!(serde_json::from_str::<SignatureShare>(invalid_json).is_err());
}

#[test]
fn check_secret_share_serialization() {
    let secret_share = samples::secret_share();

    let json = serde_json::to_string_pretty(&secret_share).unwrap();
    println!("{}", json);

    let decoded_secret_share: SecretShare = serde_json::from_str(&json).unwrap();
    assert!(secret_share == decoded_secret_share);

    let json = r#"{
        "identifier": "2a00000000000000000000000000000000000000000000000000000000000000",
        "value": "a1c4c0d092baa1ef06f41526d0f32972b21c20e079b0067a037819e8de5b0804",
        "commitment": [
          "8b7d2d877a253c4b7733e1b91f05e0fcedf96bd11c2e572549b2a0f703727925"
        ],
        "ciphersuite": "FROST(babyjubjub, SHA-256)"
      }"#;
    let decoded_secret_share: SecretShare = serde_json::from_str(json).unwrap();
    assert!(secret_share == decoded_secret_share);

    let invalid_json = "{}";
    assert!(serde_json::from_str::<SecretShare>(invalid_json).is_err());

    // Invalid identifier
    let invalid_json = r#"{
        "identifier": "0000000000000000000000000000000000000000000000000000000000000000",
        "value": "a1c4c0d092baa1ef06f41526d0f32972b21c20e079b0067a037819e8de5b0804",
        "commitment": [
          "8b7d2d877a253c4b7733e1b91f05e0fcedf96bd11c2e572549b2a0f703727925"
        ],
        "ciphersuite": "FROST(babyjubjub, SHA-256)"
      }"#;
    assert!(serde_json::from_str::<SecretShare>(invalid_json).is_err());

    // Invalid field
    let invalid_json = r#"{
        "identifier": "2a00000000000000000000000000000000000000000000000000000000000000",
        "foo": "a1c4c0d092baa1ef06f41526d0f32972b21c20e079b0067a037819e8de5b0804",
        "commitment": [
          "8b7d2d877a253c4b7733e1b91f05e0fcedf96bd11c2e572549b2a0f703727925"
        ],
        "ciphersuite": "FROST(babyjubjub, SHA-256)"
      }"#;
    assert!(serde_json::from_str::<SecretShare>(invalid_json).is_err());

    // Missing field
    let invalid_json = r#"{
        "identifier": "2a00000000000000000000000000000000000000000000000000000000000000",
        "commitment": [
          "8b7d2d877a253c4b7733e1b91f05e0fcedf96bd11c2e572549b2a0f703727925"
        ],
        "ciphersuite": "FROST(babyjubjub, SHA-256)"
      }"#;
    assert!(serde_json::from_str::<SecretShare>(invalid_json).is_err());

    // Extra field
    let invalid_json = r#"{
        "identifier": "2a00000000000000000000000000000000000000000000000000000000000000",
        "value": "a1c4c0d092baa1ef06f41526d0f32972b21c20e079b0067a037819e8de5b0804",
        "commitment": [
          "8b7d2d877a253c4b7733e1b91f05e0fcedf96bd11c2e572549b2a0f703727925"
        ],
        "extra": 1,
        "ciphersuite": "FROST(babyjubjub, SHA-256)"
      }"#;
    assert!(serde_json::from_str::<SecretShare>(invalid_json).is_err());
}

#[test]
fn check_key_package_serialization() {
    let key_package = samples::key_package();

    let json = serde_json::to_string_pretty(&key_package).unwrap();
    println!("{}", json);

    let decoded_key_package: KeyPackage = serde_json::from_str(&json).unwrap();
    assert!(key_package == decoded_key_package);

    let json = r#"{
        "identifier": "2a00000000000000000000000000000000000000000000000000000000000000",
        "secret_share": "a1c4c0d092baa1ef06f41526d0f32972b21c20e079b0067a037819e8de5b0804",
        "public": "8b7d2d877a253c4b7733e1b91f05e0fcedf96bd11c2e572549b2a0f703727925",
        "group_public": "8b7d2d877a253c4b7733e1b91f05e0fcedf96bd11c2e572549b2a0f703727925",
        "min_signers": 2,
        "ciphersuite": "FROST(babyjubjub, SHA-256)"
      }"#;
    let decoded_key_package: KeyPackage = serde_json::from_str(json).unwrap();
    assert!(key_package == decoded_key_package);

    let invalid_json = "{}";
    assert!(serde_json::from_str::<KeyPackage>(invalid_json).is_err());

    // Invalid identifier
    let invalid_json = r#"{
        "identifier": "0000000000000000000000000000000000000000000000000000000000000000",
        "secret_share": "a1c4c0d092baa1ef06f41526d0f32972b21c20e079b0067a037819e8de5b0804",
        "public": "8b7d2d877a253c4b7733e1b91f05e0fcedf96bd11c2e572549b2a0f703727925",
        "group_public": "8b7d2d877a253c4b7733e1b91f05e0fcedf96bd11c2e572549b2a0f703727925",
        "ciphersuite": "FROST(babyjubjub, SHA-256)"
      }"#;
    assert!(serde_json::from_str::<KeyPackage>(invalid_json).is_err());

    // Invalid field
    let invalid_json = r#"{
        "identifier": "2a00000000000000000000000000000000000000000000000000000000000000",
        "foo": "a1c4c0d092baa1ef06f41526d0f32972b21c20e079b0067a037819e8de5b0804",
        "public": "8b7d2d877a253c4b7733e1b91f05e0fcedf96bd11c2e572549b2a0f703727925",
        "group_public": "8b7d2d877a253c4b7733e1b91f05e0fcedf96bd11c2e572549b2a0f703727925",
        "ciphersuite": "FROST(babyjubjub, SHA-256)"
      }"#;
    assert!(serde_json::from_str::<KeyPackage>(invalid_json).is_err());

    // Missing field
    let invalid_json = r#"{
        "identifier": "2a00000000000000000000000000000000000000000000000000000000000000",
        "public": "8b7d2d877a253c4b7733e1b91f05e0fcedf96bd11c2e572549b2a0f703727925",
        "group_public": "8b7d2d877a253c4b7733e1b91f05e0fcedf96bd11c2e572549b2a0f703727925",
        "ciphersuite": "FROST(babyjubjub, SHA-256)"
      }"#;
    assert!(serde_json::from_str::<KeyPackage>(invalid_json).is_err());

    // Extra field
    let invalid_json = r#"{
        "identifier": "2a00000000000000000000000000000000000000000000000000000000000000",
        "secret_share": "a1c4c0d092baa1ef06f41526d0f32972b21c20e079b0067a037819e8de5b0804",
        "public": "8b7d2d877a253c4b7733e1b91f05e0fcedf96bd11c2e572549b2a0f703727925",
        "group_public": "8b7d2d877a253c4b7733e1b91f05e0fcedf96bd11c2e572549b2a0f703727925",
        "extra_field": 1,
        "ciphersuite": "FROST(babyjubjub, SHA-256)"
      }"#;
    assert!(serde_json::from_str::<KeyPackage>(invalid_json).is_err());
}

#[test]
fn check_public_key_package_serialization() {
    let public_key_package = samples::public_key_package();

    let json = serde_json::to_string_pretty(&public_key_package).unwrap();
    println!("{}", json);

    let decoded_public_key_package: PublicKeyPackage = serde_json::from_str(&json).unwrap();
    assert!(public_key_package == decoded_public_key_package);

    let json = r#"{
        "signer_pubkeys": {
          "2a00000000000000000000000000000000000000000000000000000000000000": "8b7d2d877a253c4b7733e1b91f05e0fcedf96bd11c2e572549b2a0f703727925"
        },
        "group_public": "8b7d2d877a253c4b7733e1b91f05e0fcedf96bd11c2e572549b2a0f703727925",
        "ciphersuite": "FROST(babyjubjub, SHA-256)"
      }"#;
    let decoded_public_key_package: PublicKeyPackage = serde_json::from_str(json).unwrap();
    assert!(public_key_package == decoded_public_key_package);

    let invalid_json = "{}";
    assert!(serde_json::from_str::<PublicKeyPackage>(invalid_json).is_err());

    // Invalid identifier
    let invalid_json = r#"{
        "signer_pubkeys": {
          "0000000000000000000000000000000000000000000000000000000000000000": "8b7d2d877a253c4b7733e1b91f05e0fcedf96bd11c2e572549b2a0f703727925"
        },
        "group_public": "8b7d2d877a253c4b7733e1b91f05e0fcedf96bd11c2e572549b2a0f703727925",
        "ciphersuite": "FROST(babyjubjub, SHA-256)"
      }"#;
    assert!(serde_json::from_str::<PublicKeyPackage>(invalid_json).is_err());

    // Invalid field
    let invalid_json = r#"{
        "signer_pubkeys": {
          "2a00000000000000000000000000000000000000000000000000000000000000": "8b7d2d877a253c4b7733e1b91f05e0fcedf96bd11c2e572549b2a0f703727925"
        },
        "foo": "8b7d2d877a253c4b7733e1b91f05e0fcedf96bd11c2e572549b2a0f703727925",
        "ciphersuite": "FROST(babyjubjub, SHA-256)"
      }"#;
    assert!(serde_json::from_str::<PublicKeyPackage>(invalid_json).is_err());

    // Missing field
    let invalid_json = r#"{
        "signer_pubkeys": {
          "2a00000000000000000000000000000000000000000000000000000000000000": "8b7d2d877a253c4b7733e1b91f05e0fcedf96bd11c2e572549b2a0f703727925"
        },
        "ciphersuite": "FROST(babyjubjub, SHA-256)"
      }"#;
    assert!(serde_json::from_str::<PublicKeyPackage>(invalid_json).is_err());

    // Extra field
    let invalid_json = r#"{
        "signer_pubkeys": {
          "2a00000000000000000000000000000000000000000000000000000000000000": "8b7d2d877a253c4b7733e1b91f05e0fcedf96bd11c2e572549b2a0f703727925"
        },
        "group_public": "8b7d2d877a253c4b7733e1b91f05e0fcedf96bd11c2e572549b2a0f703727925",
        "extra": 1,
        "ciphersuite": "FROST(babyjubjub, SHA-256)"
      }"#;
    assert!(serde_json::from_str::<PublicKeyPackage>(invalid_json).is_err());
}

#[test]
fn check_round1_package_serialization() {
    let round1_package = samples::round1_package();

    let json = serde_json::to_string_pretty(&round1_package).unwrap();
    println!("{}", json);

    let decoded_round1_package: round1::Package = serde_json::from_str(&json).unwrap();
    assert!(round1_package == decoded_round1_package);

    let json = r#"{
        "commitment": [
          "8b7d2d877a253c4b7733e1b91f05e0fcedf96bd11c2e572549b2a0f703727925"
        ],
        "proof_of_knowledge": "8b7d2d877a253c4b7733e1b91f05e0fcedf96bd11c2e572549b2a0f703727925a1c4c0d092baa1ef06f41526d0f32972b21c20e079b0067a037819e8de5b0804",
        "ciphersuite": "FROST(babyjubjub, SHA-256)"
      }"#;
    let decoded_round1_package: round1::Package = serde_json::from_str(json).unwrap();
    assert!(round1_package == decoded_round1_package);

    let invalid_json = "{}";
    assert!(serde_json::from_str::<round1::Package>(invalid_json).is_err());

    // Invalid field
    let invalid_json = r#"{
        "commitment": [
          "8b7d2d877a253c4b7733e1b91f05e0fcedf96bd11c2e572549b2a0f703727925"
        ],
        "foo": "8b7d2d877a253c4b7733e1b91f05e0fcedf96bd11c2e572549b2a0f703727925a1c4c0d092baa1ef06f41526d0f32972b21c20e079b0067a037819e8de5b0804",
        "ciphersuite": "FROST(babyjubjub, SHA-256)"
      }"#;
    assert!(serde_json::from_str::<round1::Package>(invalid_json).is_err());

    // Missing field
    let invalid_json = r#"{
        "commitment": [
          "8b7d2d877a253c4b7733e1b91f05e0fcedf96bd11c2e572549b2a0f703727925"
        ],
        "ciphersuite": "FROST(babyjubjub, SHA-256)"
      }"#;
    assert!(serde_json::from_str::<round1::Package>(invalid_json).is_err());

    // Extra field
    let invalid_json = r#"{
        "commitment": [
          "8b7d2d877a253c4b7733e1b91f05e0fcedf96bd11c2e572549b2a0f703727925"
        ],
        "proof_of_knowledge": "8b7d2d877a253c4b7733e1b91f05e0fcedf96bd11c2e572549b2a0f703727925a1c4c0d092baa1ef06f41526d0f32972b21c20e079b0067a037819e8de5b0804",
        "extra": 1,
        "ciphersuite": "FROST(babyjubjub, SHA-256)"
      }"#;
    assert!(serde_json::from_str::<round1::Package>(invalid_json).is_err());
}

#[test]
fn check_round2_package_serialization() {
    let round2_package = samples::round2_package();

    let json = serde_json::to_string_pretty(&round2_package).unwrap();
    println!("{}", json);

    let decoded_round2_package: round2::Package = serde_json::from_str(&json).unwrap();
    assert!(round2_package == decoded_round2_package);

    let json = r#"{
        "secret_share": "a1c4c0d092baa1ef06f41526d0f32972b21c20e079b0067a037819e8de5b0804",
        "ciphersuite": "FROST(babyjubjub, SHA-256)"
      }"#;
    let decoded_round2_package: round2::Package = serde_json::from_str(json).unwrap();
    assert!(round2_package == decoded_round2_package);

    let invalid_json = "{}";
    assert!(serde_json::from_str::<round2::Package>(invalid_json).is_err());

    // Invalid field
    let invalid_json = r#"{
        "foo": "a1c4c0d092baa1ef06f41526d0f32972b21c20e079b0067a037819e8de5b0804",
        "ciphersuite": "FROST(babyjubjub, SHA-256)"
      }"#;
    assert!(serde_json::from_str::<round2::Package>(invalid_json).is_err());

    // Missing field
    let invalid_json = r#"{
        "ciphersuite": "FROST(babyjubjub, SHA-256)"
      }"#;
    assert!(serde_json::from_str::<round2::Package>(invalid_json).is_err());

    // Extra field
    let invalid_json = r#"{
        "secret_share": "a1c4c0d092baa1ef06f41526d0f32972b21c20e079b0067a037819e8de5b0804",
        "extra": 1,
        "ciphersuite": "FROST(babyjubjub, SHA-256)"
      }"#;
    assert!(serde_json::from_str::<round2::Package>(invalid_json).is_err());
}
