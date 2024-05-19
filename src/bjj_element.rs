use ark_ed_on_bn254::{EdwardsAffine, EdwardsProjective, Fq, Fr};
use ark_ff::{MontFp, PrimeField};
use std::ops::{Add, Mul, Sub};

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
// pub struct BabyJubJubElement(pub EdwardsAffine);
pub struct BabyJubJubElement(pub EdwardsProjective);

impl BabyJubJubElement {
    pub const FR_MODULUS: Fq =
        MontFp!("2736030358979909402780800718157159386076813972158567259200215660948447373041");
}

// TODO: might add assign for all belo

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

// impl Mul<Fq> for BabyJubJubElement {
//     type Output = Self;

//     fn mul(self, scalar: Fq) -> Self::Output {
//         if scalar < Self::FR_MODULUS {
//             let scalar_fr = Fr::from(scalar.into_bigint());
//             let proj_self: EdwardsProjective = self.0.into();
//             let proj_result = proj_self.mul(&scalar_fr);
//             BabyJubJubElement(proj_result)
//         } else {
//             panic!("Scalar value exceeds the modulus of Fr and cannot be converted safely.");
//         }
//     }
// }
impl Mul<Fr> for BabyJubJubElement {
    type Output = Self;

    fn mul(self, scalar: Fr) -> Self::Output {
        let proj_self: EdwardsProjective = self.0.into();
        let proj_result = proj_self.mul(&scalar);
        BabyJubJubElement(proj_result)
    }
}
