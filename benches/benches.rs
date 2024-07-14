#![feature(custom_test_frameworks)]
#![test_runner(criterion::runner)]

use aes_gcm::aead::OsRng;
use criterion::Criterion;
use criterion_macro::criterion;
use rrr::{
    crypto::{
        kdf::{
            hkdf::{HkdfParams, HkdfPrf},
            KdfAlgorithm,
        },
        password_hash::{argon2::Argon2Params, PasswordHashAlgorithm},
    },
    record::{RecordKey, RecordName},
    registry::{ConfigParam, RegistryConfigHash, RegistryConfigKdf},
};
use tokio::runtime::Runtime;

fn with_samples(samples: usize) -> Criterion {
    Criterion::default().sample_size(samples)
}

#[criterion(with_samples(10))]
fn bench_hash_params(c: &mut Criterion) {
    let hash = RegistryConfigHash {
        algorithm: PasswordHashAlgorithm::Argon2(
            Argon2Params::default_with_random_pepper_of_recommended_length(OsRng),
        ),
        output_length_in_bytes: ConfigParam::try_from(32).unwrap(),
    };
    let kdf = RegistryConfigKdf {
        algorithm: KdfAlgorithm::Hkdf(HkdfParams {
            prf: HkdfPrf::Sha256,
        }),
        succession_nonce_length_in_bytes: ConfigParam::try_from(32).unwrap(),
        file_name_length_in_bytes: ConfigParam::try_from(8).unwrap(),
    };
    let key = RecordKey {
        record_name: RecordName::from(b"hello".to_vec()),
        predecessor_nonce: kdf.get_root_record_predecessor_nonce(),
    };

    c.bench_function("hash_params", |b| {
        b.to_async(Runtime::new().unwrap())
            .iter(|| async { key.hash(&hash).await.unwrap() })
    });
}
