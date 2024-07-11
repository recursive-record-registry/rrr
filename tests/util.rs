use proptest::{
    arbitrary::{any, Arbitrary},
    collection::vec,
    prop_compose,
    strategy::{BoxedStrategy, Strategy},
};
use rrr::{
    crypto::signature::{SigningKey, VerifyingKey},
    registry::RegistryConfig,
};

#[allow(unused)]
#[derive(Debug)]
pub struct RegistryConfigWithSigningKeys {
    pub signing_keys: Vec<SigningKey>,
    pub config: RegistryConfig,
}

prop_compose! {
    fn arb_registry_config_with_signing_keys()(
        signing_keys in vec(any::<SigningKey>(), 0..4),
        config in any::<RegistryConfig>(),
    ) -> RegistryConfigWithSigningKeys {
        RegistryConfigWithSigningKeys {
            signing_keys: signing_keys.clone(),
            config: RegistryConfig {
                verifying_keys: signing_keys.iter().map(VerifyingKey::from).collect(),
                ..config
            },
        }
    }
}

impl Arbitrary for RegistryConfigWithSigningKeys {
    type Parameters = ();
    type Strategy = BoxedStrategy<Self>;

    fn arbitrary_with(_: Self::Parameters) -> Self::Strategy {
        arb_registry_config_with_signing_keys().boxed()
    }
}
