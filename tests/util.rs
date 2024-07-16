use proptest::{
    arbitrary::{any, Arbitrary},
    collection::vec,
    prop_compose,
    strategy::{BoxedStrategy, Just, Strategy},
};
use rrr::{
    crypto::signature::{SigningKey, VerifyingKey},
    record::segment::{arb_segment, Segment},
    registry::RegistryConfig,
};

#[allow(unused)]
#[derive(Debug, Clone)]
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

#[allow(unused)]
#[derive(Debug)]
pub struct RegistryConfigWithSigningKeysAndSegment {
    pub registry_config_with_signing_keys: RegistryConfigWithSigningKeys,
    pub segment: Segment,
}

prop_compose! {
    fn arb_registry_config_with_signing_keys_and_segment()(
        registry_config_with_signing_keys in any::<RegistryConfigWithSigningKeys>(),
    )(
        segment in arb_segment(&registry_config_with_signing_keys.config.kdf),
        registry_config_with_signing_keys in Just(registry_config_with_signing_keys),
    ) -> RegistryConfigWithSigningKeysAndSegment {
        RegistryConfigWithSigningKeysAndSegment {
            registry_config_with_signing_keys,
            segment,
        }
    }
}

impl Arbitrary for RegistryConfigWithSigningKeysAndSegment {
    type Parameters = ();
    type Strategy = BoxedStrategy<Self>;

    fn arbitrary_with(_: Self::Parameters) -> Self::Strategy {
        arb_registry_config_with_signing_keys_and_segment().boxed()
    }
}
