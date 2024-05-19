use crate::*;

// fail: called `Result::unwrap()` on an `Err` value: [2
#[test]
fn check_deserialize_non_canonical() {
    let mut encoded_generator = <BabyJubJubSha256 as Ciphersuite>::Group::serialize(
        &<BabyJubJubSha256 as Ciphersuite>::Group::generator(),
    );

    let r = <BabyJubJubSha256 as Ciphersuite>::Group::deserialize(&encoded_generator);
    assert!(r.is_ok());

    // The first byte should be 0x02 or 0x03. Set other value to
    // create a non-canonical encoding.
    encoded_generator[0] = 0xFF;

    let r = <BabyJubJubSha256 as Ciphersuite>::Group::deserialize(&encoded_generator);
    assert_eq!(r, Err(GroupError::MalformedElement));

    // Besides the first byte, it is still possible to get non-canonical encodings.
    // This is x = p + 2 which is non-canonical and maps to a valid prime-order point.
    let encoded_point =
        hex::decode("ff861a672cfc76c26ae1c0db15117c2a767b27101fedac909e2058a7246caaaa")
            .unwrap()
            .try_into()
            .unwrap();
    let r = <BabyJubJubSha256 as Ciphersuite>::Group::deserialize(&encoded_point);
    assert_eq!(r, Err(GroupError::MalformedElement));
}

#[test]
fn encode() {
    let mut encoded_generator = <BabyJubJubSha256 as Ciphersuite>::Group::serialize(
        &<BabyJubJubSha256 as Ciphersuite>::Group::generator(),
    );
    encoded_generator[0] = 0xFF;
}

#[test]
fn check_deserialize_identity() {
    // The identity is actually encoded as a single byte; but the API does not
    // allow us to change that. Try to send something similar.
    let encoded_identity = [0u8; 32];

    let r = <BabyJubJubSha256 as Ciphersuite>::Group::deserialize(&encoded_identity);
    assert_eq!(r, Err(GroupError::MalformedElement));
}
