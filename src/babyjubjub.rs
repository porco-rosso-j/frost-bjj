use ark_ec::{
    models::CurveConfig,
    twisted_edwards::{Affine, MontCurveConfig, Projective, TECurveConfig},
};
use ark_ed_on_bn254::{Fq, Fr};
use ark_ff::MontFp;
use std::ops::{Add, Mul, Sub};

#[derive(Clone, Default, PartialEq, Eq)]
pub struct EdwardsConfig;

pub type EdwardsAffine = Affine<EdwardsConfig>;
pub type EdwardsProjective = Projective<EdwardsConfig>;

/// `Baby-JubJub` is a twisted Edwards curve. These curves have equations of the
/// form: ax² + y² = 1 + dx²y².
/// over some base finite field Fq.
///
/// Baby-JubJub's curve equation: x² + y² = 1 + (168696/168700)x²y²
///
/// q = 21888242871839275222246405745257275088548364400416034343698204186575808495617

impl CurveConfig for EdwardsConfig {
    type BaseField = Fq;
    type ScalarField = Fr;

    const COFACTOR: &'static [u64] = &[8];

    const COFACTOR_INV: Fr =
        MontFp!("2394026564107420727433200628387514462817212225638746351800188703329891451411");
}

impl TECurveConfig for EdwardsConfig {
    const COEFF_A: Fq = MontFp!("168700");
    const COEFF_D: Fq = MontFp!("168696");

    #[inline(always)]
    fn mul_by_a(elem: Self::BaseField) -> Self::BaseField {
        elem * <EdwardsConfig as TECurveConfig>::COEFF_A
    }

    const GENERATOR: EdwardsAffine = EdwardsAffine::new_unchecked(GENERATOR_X, GENERATOR_Y);

    type MontCurveConfig = EdwardsConfig;
}

impl MontCurveConfig for EdwardsConfig {
    const COEFF_A: Fq = MontFp!("168698");

    // const COEFF_B: Fq = MontFp!("168700");
    const COEFF_B: Fq = MontFp!("1");

    type TECurveConfig = EdwardsConfig;
}

// generator
// pub const GENERATOR_X: Fq =
//     MontFp!("995203441582195749578291179787384436505546430278305826713579947235728471134");
// pub const GENERATOR_Y: Fq =
//     MontFp!("5472060717959818805561601436314318772137091100104008585924551046643952123905");

// base
pub const GENERATOR_X: Fq =
    MontFp!("5299619240641551281634865583518297030282874472190772894086521144482721001553");
pub const GENERATOR_Y: Fq =
    MontFp!("16950150798460657717958625567821834550301663161624707787222815936182638968203");

pub struct BabyJubJubElement(pub EdwardsProjective);

impl Add for BabyJubJubElement {
    type Output = Self;

    fn add(self, other: Self) -> Self::Output {
        let proj_sum = self.0 + other.0;
        BabyJubJubElement(proj_sum)
    }
}

impl Sub for BabyJubJubElement {
    type Output = Self;

    fn sub(self, other: Self) -> Self::Output {
        let proj_sum = self.0 - other.0;
        BabyJubJubElement(proj_sum)
    }
}

impl Mul<Fr> for BabyJubJubElement {
    type Output = Self;

    fn mul(self, scalar: Fr) -> Self::Output {
        let proj_self: EdwardsProjective = self.0.into();
        let proj_result = proj_self.mul(&scalar);
        BabyJubJubElement(proj_result)
    }
}
