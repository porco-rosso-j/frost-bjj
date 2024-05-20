use ark_ed_on_bn254::Fq;
use ark_ff::MontFp;

use crate::{babyjubjub::EdwardsAffine, *};

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
        hex::decode("ff0000fc647df850245c6e1e12fa0c4a175660a06d11146e0a684cb89c13190c")
            .unwrap()
            .try_into()
            .unwrap();
    let r = <BabyJubJubSha256 as Ciphersuite>::Group::deserialize(&encoded_point);
    assert_eq!(r, Err(GroupError::MalformedElement));
}

#[test]
fn check_deserialize_identity() {
    // The identity is actually encoded as a single byte; but the API does not
    // allow us to change that. Try to send something similar.
    const x: Fq = MontFp!("0");
    const y: Fq = MontFp!("1");
    let id_zero = EdwardsAffine { x, y };

    let mut array = [0u8; 32];
    let mut vec = Vec::new();
    id_zero
        .serialize_with_mode(&mut vec, Compress::Yes)
        .expect("should succeed");

    array.copy_from_slice(&vec);

    let r = <BabyJubJubSha256 as Ciphersuite>::Group::deserialize(&array);
    assert_eq!(r, Err(GroupError::InvalidIdentityElement));
}
