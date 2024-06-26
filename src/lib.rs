#![allow(non_snake_case)]
#![deny(missing_docs)]
#![cfg_attr(docsrs, feature(doc_auto_cfg))]
#![cfg_attr(docsrs, feature(doc_cfg))]
#![doc = include_str!("../README.md")]
#![doc = document_features::document_features!()]

use std::collections::HashMap;

use ark_ec::{twisted_edwards::TECurveConfig, CurveConfig, CurveGroup};
use ark_ed_on_bn254::Fr;
use ark_ff::{
    field_hashers::DefaultFieldHasher, fields::field_hashers::HashToField, BigInteger,
    Field as ArkField, One, PrimeField, UniformRand, Zero,
};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize, Compress, Validate};
use ark_std::vec::Vec;

use rand_core::{CryptoRng, RngCore};
use sha2::{Digest, Sha256};

use frost_core::{frost, Scalar};

#[cfg(feature = "serde")]
use frost_core::serde;

#[cfg(test)]
mod tests;

pub use frost_core::{Ciphersuite, Field, FieldError, Group, GroupError};
pub use rand_core;

mod babyjubjub;
use babyjubjub::{EdwardsConfig, EdwardsProjective};

/// An error.
pub type Error = frost_core::Error<BabyJubJubSha256>;

/// An implementation of the FROST(babyjubjub, SHA-256) ciphersuite scalar field.
#[derive(Clone, Copy)]
pub struct BabyJubJubScalarField;

impl Field for BabyJubJubScalarField {
    type Scalar = Fr;

    type Serialization = [u8; 32];

    fn zero() -> Self::Scalar {
        Fr::zero()
    }

    fn one() -> Self::Scalar {
        Fr::one()
    }

    fn invert(scalar: &Self::Scalar) -> Result<Self::Scalar, FieldError> {
        // [`Scalar`]'s Eq/PartialEq does a constant-time comparison
        if *scalar == <Self as Field>::zero() {
            Err(FieldError::InvalidZeroScalar)
        } else {
            Ok(scalar.inverse().unwrap())
        }
    }

    fn random<R: RngCore + CryptoRng>(rng: &mut R) -> Self::Scalar {
        Fr::rand(rng)
    }

    fn serialize(scalar: &Self::Scalar) -> Self::Serialization {
        let bytes = scalar.into_bigint().to_bytes_le();
        let mut array = [0u8; 32];
        array[..bytes.len()].copy_from_slice(&bytes);
        array
    }

    fn deserialize(buf: &Self::Serialization) -> Result<Self::Scalar, FieldError> {
        match Self::Scalar::from_le_bytes_mod_order(buf).into() {
            Some(s) => Ok(s),
            None => Err(FieldError::MalformedScalar),
        }
    }

    fn little_endian_serialize(scalar: &Self::Scalar) -> Self::Serialization {
        Self::serialize(scalar)
    }
}

/// An implementation of the FROST(babyjubjub, SHA-256) ciphersuite group.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct BabyJubJubGroup;

impl Group for BabyJubJubGroup {
    type Field = BabyJubJubScalarField;

    type Element = EdwardsProjective;

    type Serialization = [u8; 32];

    fn cofactor() -> <Self::Field as Field>::Scalar {
        Fr::from(EdwardsConfig::COFACTOR[0])
    }

    fn identity() -> Self::Element {
        EdwardsProjective::zero()
    }

    fn generator() -> Self::Element {
        EdwardsProjective::from(EdwardsConfig::GENERATOR)
    }

    fn serialize(element: &Self::Element) -> Self::Serialization {
        // let mut vec: Vec<u8> = vec![0; 32];
        let mut vec = Vec::new();
        let mut array = [0u8; 32];

        // let affine = element.0.into_affine();
        let affine = element.into_affine();

        affine
            .serialize_with_mode(&mut vec, Compress::Yes)
            .expect("Serialization should succeed");

        match vec.len() {
            32 => array.copy_from_slice(&vec),
            1 => {
                panic!("Unexpected serialized length for an identity element.");
            }
            _ => panic!("Unexpected serialized length: {}", vec.len()),
        }

        array
    }

    fn deserialize(buf: &Self::Serialization) -> Result<Self::Element, GroupError> {
        // println!("here");
        let point: EdwardsProjective =
            EdwardsProjective::deserialize_with_mode(&buf[..], Compress::Yes, Validate::Yes)
                .map_err(|_| GroupError::MalformedElement)?;

        // println!("point: {:?}", point);
        if point.is_zero().into() {
            Err(GroupError::InvalidIdentityElement)
        } else {
            Ok(point)
        }
    }
}

fn hash_to_array(inputs: &[&[u8]]) -> [u8; 32] {
    let mut h = Sha256::new();
    for i in inputs {
        h.update(i);
    }
    let mut output = [0u8; 32];
    output.copy_from_slice(h.finalize().as_slice());
    output
}

fn hash_to_scalar(domain: &[u8], msg: &[u8]) -> Fr {
    let hasher: DefaultFieldHasher<Sha256> = HashToField::<Fr>::new(domain); // Note the braces around 32 if it's a const parameter
    let result: Vec<Fr> = hasher.hash_to_field(msg, 32);
    result[0]
}

/// Context string from the ciphersuite in the [spec].
///
/// [spec]: https://www.ietf.org/archive/id/draft-irtf-cfrg-frost-14.html#section-6.5-1
const CONTEXT_STRING: &str = "FROST-babyjubjub-SHA256-v1";

/// An implementation of the FROST(babyjubjub, SHA-256) ciphersuite.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(crate = "self::serde"))]
pub struct BabyJubJubSha256;

impl Ciphersuite for BabyJubJubSha256 {
    const ID: &'static str = "FROST(babyjubjub, SHA-256)";

    type Group = BabyJubJubGroup;

    type HashOutput = [u8; 32];

    type SignatureSerialization = [u8; 64];

    /// H1 for FROST(babyjubjub, SHA-256)
    ///
    /// [spec]: https://www.ietf.org/archive/id/draft-irtf-cfrg-frost-14.html#section-6.5-2.2.2.1
    fn H1(m: &[u8]) -> <<Self::Group as Group>::Field as Field>::Scalar {
        hash_to_scalar((CONTEXT_STRING.to_owned() + "rho").as_bytes(), m)
    }

    /// H2 for FROST(babyjubjub, SHA-256)
    ///
    /// [spec]: https://www.ietf.org/archive/id/draft-irtf-cfrg-frost-14.html#section-6.5-2.2.2.2
    fn H2(m: &[u8]) -> <<Self::Group as Group>::Field as Field>::Scalar {
        hash_to_scalar((CONTEXT_STRING.to_owned() + "chal").as_bytes(), m)
    }

    /// H3 for FROST(babyjubjub, SHA-256)
    ///
    /// [spec]: https://www.ietf.org/archive/id/draft-irtf-cfrg-frost-14.html#section-6.5-2.2.2.3
    fn H3(m: &[u8]) -> <<Self::Group as Group>::Field as Field>::Scalar {
        hash_to_scalar((CONTEXT_STRING.to_owned() + "nonce").as_bytes(), m)
    }

    /// H4 for FROST(babyjubjub, SHA-256)
    ///
    /// [spec]: https://www.ietf.org/archive/id/draft-irtf-cfrg-frost-14.html#section-6.5-2.2.2.4
    fn H4(m: &[u8]) -> Self::HashOutput {
        hash_to_array(&[CONTEXT_STRING.as_bytes(), b"msg", m])
    }

    /// H5 for FROST(babyjubjub, SHA-256)
    ///
    /// [spec]: https://www.ietf.org/archive/id/draft-irtf-cfrg-frost-14.html#section-6.5-2.2.2.5
    fn H5(m: &[u8]) -> Self::HashOutput {
        hash_to_array(&[CONTEXT_STRING.as_bytes(), b"com", m])
    }

    /// HDKG for FROST(babyjubjub, SHA-256)
    fn HDKG(m: &[u8]) -> Option<<<Self::Group as Group>::Field as Field>::Scalar> {
        Some(hash_to_scalar(
            (CONTEXT_STRING.to_owned() + "dkg").as_bytes(),
            m,
        ))
    }

    /// HID for FROST(babyjubjub, SHA-256)
    fn HID(m: &[u8]) -> Option<<<Self::Group as Group>::Field as Field>::Scalar> {
        Some(hash_to_scalar(
            (CONTEXT_STRING.to_owned() + "id").as_bytes(),
            m,
        ))
    }
}

type B = BabyJubJubSha256;

/// A FROST(babyjubjub, SHA-256) participant identifier.
pub type Identifier = frost::Identifier<B>;

/// FROST(babyjubjub, SHA-256) keys, key generation, key shares.
pub mod keys {

    use super::*;
    use std::collections::HashMap;

    /// The identifier list to use when generating key shares.
    pub type IdentifierList<'a> = frost::keys::IdentifierList<'a, B>;

    /// Allows all participants' keys to be generated using a central, trusted
    /// dealer.
    pub fn generate_with_dealer<RNG: RngCore + CryptoRng>(
        max_signers: u16,
        min_signers: u16,
        identifiers: IdentifierList,
        mut rng: RNG,
    ) -> Result<(HashMap<Identifier, SecretShare>, PublicKeyPackage), Error> {
        frost::keys::generate_with_dealer(max_signers, min_signers, identifiers, &mut rng)
    }

    /// Splits an existing key into FROST shares.
    ///
    /// This is identical to [`generate_with_dealer`] but receives an existing key
    /// instead of generating a fresh one. This is useful in scenarios where
    /// the key needs to be generated externally or must be derived from e.g. a
    /// seed phrase.
    pub fn split<R: RngCore + CryptoRng>(
        secret: &SigningKey,
        max_signers: u16,
        min_signers: u16,
        identifiers: IdentifierList,
        rng: &mut R,
    ) -> Result<(HashMap<Identifier, SecretShare>, PublicKeyPackage), Error> {
        frost::keys::split(secret, max_signers, min_signers, identifiers, rng)
    }

    /// Recompute the secret from t-of-n secret shares using Lagrange interpolation.
    ///
    /// This can be used if for some reason the original key must be restored; e.g.
    /// if threshold signing is not required anymore.
    ///
    /// This is NOT required to sign with FROST; the whole point of FROST is being
    /// able to generate signatures only using the shares, without having to
    /// reconstruct the original key.
    ///
    /// The caller is responsible for providing at least `min_signers` shares;
    /// if less than that is provided, a different key will be returned.
    pub fn reconstruct(secret_shares: &[KeyPackage]) -> Result<SigningKey, Error> {
        frost::keys::reconstruct(secret_shares)
    }

    /// Secret and public key material generated by a dealer performing
    /// [`generate_with_dealer`].
    ///
    /// # Security
    ///
    /// To derive a FROST(babyjubjub, SHA-256) keypair, the receiver of the [`SecretShare`] *must* call
    /// .into(), which under the hood also performs validation.
    pub type SecretShare = frost::keys::SecretShare<B>;

    /// A secret scalar value representing a signer's share of the group secret.
    pub type SigningShare = frost::keys::SigningShare<B>;

    /// A public group element that represents a single signer's public verification share.
    pub type VerifyingShare = frost::keys::VerifyingShare<B>;

    /// A FROST(babyjubjub, SHA-256) keypair, which can be generated either by a trusted dealer or using
    /// a DKG.
    ///
    /// When using a central dealer, [`SecretShare`]s are distributed to
    /// participants, who then perform verification, before deriving
    /// [`KeyPackage`]s, which they store to later use during signing.
    pub type KeyPackage = frost::keys::KeyPackage<B>;

    /// Public data that contains all the signers' public keys as well as the
    /// group public key.
    ///
    /// Used for verification purposes before publishing a signature.
    pub type PublicKeyPackage = frost::keys::PublicKeyPackage<B>;

    /// Contains the commitments to the coefficients for our secret polynomial _f_,
    /// used to generate participants' key shares.
    ///
    /// [`VerifiableSecretSharingCommitment`] contains a set of commitments to the coefficients (which
    /// themselves are scalars) for a secret polynomial f, where f is used to
    /// generate each ith participant's key share f(i). Participants use this set of
    /// commitments to perform verifiable secret sharing.
    ///
    /// Note that participants MUST be assured that they have the *same*
    /// [`VerifiableSecretSharingCommitment`], either by performing pairwise comparison, or by using
    /// some agreed-upon public location for publication, where each participant can
    /// ensure that they received the correct (and same) value.
    pub type VerifiableSecretSharingCommitment = frost::keys::VerifiableSecretSharingCommitment<B>;

    pub mod dkg;
    pub mod repairable;
}

/// FROST(babyjubjub, SHA-256) Round 1 functionality and types.
pub mod round1 {
    use crate::keys::SigningShare;

    use super::*;

    /// Comprised of FROST(babyjubjub, SHA-256) hiding and binding nonces.
    ///
    /// Note that [`SigningNonces`] must be used *only once* for a signing
    /// operation; re-using nonces will result in leakage of a signer's long-lived
    /// signing key.
    pub type SigningNonces = frost::round1::SigningNonces<B>;

    /// Published by each participant in the first round of the signing protocol.
    ///
    /// This step can be batched if desired by the implementation. Each
    /// SigningCommitment can be used for exactly *one* signature.
    pub type SigningCommitments = frost::round1::SigningCommitments<B>;

    /// A commitment to a signing nonce share.
    pub type NonceCommitment = frost::round1::NonceCommitment<B>;

    /// Performed once by each participant selected for the signing operation.
    ///
    /// Generates the signing nonces and commitments to be used in the signing
    /// operation.
    pub fn commit<RNG>(secret: &SigningShare, rng: &mut RNG) -> (SigningNonces, SigningCommitments)
    where
        RNG: CryptoRng + RngCore,
    {
        frost::round1::commit::<B, RNG>(secret, rng)
    }
}

/// Generated by the coordinator of the signing operation and distributed to
/// each signing party.
pub type SigningPackage = frost::SigningPackage<B>;

/// FROST(babyjubjub, SHA-256) Round 2 functionality and types, for signature share generation.
pub mod round2 {
    use super::*;

    /// A FROST(babyjubjub, SHA-256) participant's signature share, which the Coordinator will aggregate with all other signer's
    /// shares into the joint signature.
    pub type SignatureShare = frost::round2::SignatureShare<B>;

    /// Performed once by each participant selected for the signing operation.
    ///
    /// Receives the message to be signed and a set of signing commitments and a set
    /// of randomizing commitments to be used in that signing operation, including
    /// that for this participant.
    ///
    /// Assumes the participant has already determined which nonce corresponds with
    /// the commitment that was assigned by the coordinator in the SigningPackage.
    pub fn sign(
        signing_package: &SigningPackage,
        signer_nonces: &round1::SigningNonces,
        key_package: &keys::KeyPackage,
    ) -> Result<SignatureShare, Error> {
        frost::round2::sign(signing_package, signer_nonces, key_package)
    }
}

/// A Schnorr signature on FROST(babyjubjub, SHA-256).
pub type Signature = frost_core::Signature<B>;

/// Verifies each FROST(babyjubjub, SHA-256) participant's signature share, and if all are valid,
/// aggregates the shares into a signature to publish.
///
/// Resulting signature is compatible with verification of a plain Schnorr
/// signature.
///
/// This operation is performed by a coordinator that can communicate with all
/// the signing participants before publishing the final signature. The
/// coordinator can be one of the participants or a semi-trusted third party
/// (who is trusted to not perform denial of service attacks, but does not learn
/// any secret information). Note that because the coordinator is trusted to
/// report misbehaving parties in order to avoid publishing an invalid
/// signature, if the coordinator themselves is a signer and misbehaves, they
/// can avoid that step. However, at worst, this results in a denial of
/// service attack due to publishing an invalid signature.
pub fn aggregate(
    signing_package: &SigningPackage,
    signature_shares: &HashMap<Identifier, round2::SignatureShare>,
    pubkeys: &keys::PublicKeyPackage,
) -> Result<Signature, Error> {
    frost::aggregate(signing_package, signature_shares, pubkeys)
}

/// A signing key for a Schnorr signature on FROST(babyjubjub, SHA-256).
pub type SigningKey = frost_core::SigningKey<B>;

/// A valid verifying key for Schnorr signatures on FROST(babyjubjub, SHA-256).
pub type VerifyingKey = frost_core::VerifyingKey<B>;

#[test]
fn scalar_one() {
    // let scalar = Fr::from(BigInt([42, 0, 0, 0]));
    // println!("scalar test: {:?}", &scalar);
    // // let ret = BabyJubJubScalarField::serialize(&scalar);
    // // println!("ret(): {:?}", ret);

    // let mut array = [0u8; 32];
    // array[0] = 42;

    // let ser = Identifier::deserialize(&array).unwrap();
    // println!("ser(): {:?}", ser);

    // let v: Identifier = Identifier::try_from(42u16).unwrap();
    // println!("v(): {:?}", v);

    let identifier: Identifier = 42u16.try_into().unwrap();

    println!("identifier(): {:?}", identifier);
}
