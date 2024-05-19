use frost_bjj::BabyJubJubSha256;
use rand::thread_rng;

// the trait `frost_rerandomized::frost_core::Ciphersuite` is not implemented for `BabyJubJubSha256`

#[test]
fn check_randomized_sign_with_dealer() {
    let rng = thread_rng();

    let (_msg, _group_signature, _group_pubkey) =
        frost_rerandomized::tests::check_randomized_sign_with_dealer::<BabyJubJubSha256, _>(rng);
}
