use ark_ed_on_bn254::Fq;
use ark_ff::MontFp;

use crate::{babyjubjub::EdwardsAffine, *};

#[test]
fn membership_zero_one() {
    const x: Fq = MontFp!("0");
    const y: Fq = MontFp!("1");
    let id_zero = EdwardsAffine { x, y };
    println!(
        "is_in_correct_subgroup_assuming_on_curve: {:?}",
        id_zero.is_in_correct_subgroup_assuming_on_curve()
    );
}

#[test]
fn membership_one_zero() {
    const x: Fq = MontFp!("1");
    const y: Fq = MontFp!("0");
    let id_zero = EdwardsAffine { x, y };
    println!(
        "is_in_correct_subgroup_assuming_on_curve: {:?}",
        id_zero.is_in_correct_subgroup_assuming_on_curve()
    );
}

#[test]
fn membership_base_point() {
    const x: Fq =
        MontFp!("5299619240641551281634865583518297030282874472190772894086521144482721001553");
    const y: Fq =
        MontFp!("16950150798460657717958625567821834550301663161624707787222815936182638968203");
    let id_zero = EdwardsAffine { x, y };
    println!(
        "is_in_correct_subgroup_assuming_on_curve: {:?}",
        id_zero.is_in_correct_subgroup_assuming_on_curve()
    );
}

#[test]
fn test_add_same_point() {
    const x: Fq =
        MontFp!("17777552123799933955779906779655732241715742912184938656739573121738514868268");
    const y: Fq =
        MontFp!("2626589144620713026669568689430873010625803728049924121243784502389097019475");

    let p: EdwardsAffine = EdwardsAffine { x, y };
    let p_proj = EdwardsProjective::from(p);
    println!("p_proj: {:?} ", p_proj);

    let res = p_proj + p_proj;
    let res_affine = res.into_affine();

    println!("res: {:?} ", res_affine);

    const x_ret: Fq =
        MontFp!("6890855772600357754907169075114257697580319025794532037257385534741338397365");
    const y_ret: Fq =
        MontFp!("4338620300185947561074059802482547481416142213883829469920100239455078257889");

    let p_ret: EdwardsAffine = EdwardsAffine { x: x_ret, y: y_ret };
    let p_ret_proj = EdwardsProjective::from(p_ret);

    let ret = p_ret_proj.into_affine();
    println!("p_ret_proj: {:?} ", ret);

    assert_eq!(res_affine.x, ret.x);
    assert_eq!(res_affine.y, ret.y);
}

#[test]
fn test_add_diff_point() {
    const x_1: Fq =
        MontFp!("17777552123799933955779906779655732241715742912184938656739573121738514868268");
    const y_1: Fq =
        MontFp!("2626589144620713026669568689430873010625803728049924121243784502389097019475");

    let p_1: EdwardsAffine = EdwardsAffine { x: x_1, y: y_1 };
    let p_1_proj = EdwardsProjective::from(p_1);
    println!("p_1_proj: {:?} ", p_1_proj);

    const x_2: Fq =
        MontFp!("16540640123574156134436876038791482806971768689494387082833631921987005038935");
    const y_2: Fq =
        MontFp!("20819045374670962167435360035096875258406992893633759881276124905556507972311");

    let p_2: EdwardsAffine = EdwardsAffine { x: x_2, y: y_2 };
    let p_2_proj = EdwardsProjective::from(p_2);
    println!("p_2_proj: {:?} ", p_2_proj);

    let res = p_1_proj + p_2_proj;
    let res_affine = res.into_affine();

    println!("res: {:?} ", res_affine);

    const x_ret: Fq =
        MontFp!("7916061937171219682591368294088513039687205273691143098332585753343424131937");
    const y_ret: Fq =
        MontFp!("14035240266687799601661095864649209771790948434046947201833777492504781204499");

    let p_ret: EdwardsAffine = EdwardsAffine { x: x_ret, y: y_ret };
    let p_ret_proj = EdwardsProjective::from(p_ret);

    let ret = p_ret_proj.into_affine();
    println!("p_ret_proj: {:?} ", ret);

    assert_eq!(res_affine.x, ret.x);
    assert_eq!(res_affine.y, ret.y);
}

#[test]
fn test_mul_scalar() {
    const x: Fq =
        MontFp!("17777552123799933955779906779655732241715742912184938656739573121738514868268");
    const y: Fq =
        MontFp!("2626589144620713026669568689430873010625803728049924121243784502389097019475");

    let p: EdwardsAffine = EdwardsAffine { x, y };
    let p_proj = EdwardsProjective::from(p);
    // println!("p_proj: {:?} ", p_proj);

    const s: Fr = MontFp!("3");

    let res = p_proj * s;
    let res_affine = res.into_affine();
    println!("res: {:?} ", res_affine);

    const x_ret: Fq =
        MontFp!("19372461775513343691590086534037741906533799473648040012278229434133483800898");
    const y_ret: Fq =
        MontFp!("9458658722007214007257525444427903161243386465067105737478306991484593958249");

    let p_ret: EdwardsAffine = EdwardsAffine { x: x_ret, y: y_ret };
    let p_ret_proj = EdwardsProjective::from(p_ret);

    let ret = p_ret_proj.into_affine();
    println!("p_ret_proj: {:?} ", ret);

    assert_eq!(res_affine.x, ret.x);
    assert_eq!(res_affine.y, ret.y);
}
