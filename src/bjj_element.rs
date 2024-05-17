use ark_ec::CurveGroup;
use ark_ed_on_bn254::{EdwardsAffine, EdwardsProjective, Fr};
use std::ops::{Add, Mul, Sub};

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct BabyJubJubElement(pub EdwardsAffine);

impl Add for BabyJubJubElement {
    type Output = Self;

    fn add(self, other: Self) -> Self::Output {
        let proj_sum = self.0 + other.0;
        BabyJubJubElement(proj_sum.into_affine())
    }
}

impl Sub for BabyJubJubElement {
    type Output = Self;

    fn sub(self, other: Self) -> Self::Output {
        let proj_sum = self.0 - other.0;

        BabyJubJubElement(proj_sum.into_affine())
    }
}

impl Mul<Fr> for BabyJubJubElement {
    type Output = Self;
    fn mul(self, scalar: Fr) -> Self::Output {
        let proj_self: EdwardsProjective = self.0.into();
        let proj_result = proj_self.mul(&scalar);
        BabyJubJubElement(proj_result.into())
    }
}
