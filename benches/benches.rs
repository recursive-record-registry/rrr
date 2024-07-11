#![feature(custom_test_frameworks)]
#![test_runner(criterion::runner)]

use aes_gcm::aead::OsRng;
use criterion::Criterion;
use criterion_macro::criterion;
use rrr::{
    crypto::password_hash::{argon2::Argon2Params, PasswordHashAlgorithm},
    record::{RecordKey, RecordName},
    registry::{ConfigParam, RegistryConfigHash},
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
        kdf_input_length_in_bytes: ConfigParam::try_from(32).unwrap(),
        successor_nonce_length_in_bytes: ConfigParam::try_from(32).unwrap(),
    };
    let key = RecordKey {
        record_name: RecordName::from(b"hello"),
        predecessor_nonce: hash.get_root_record_predecessor_nonce(),
    };

    c.bench_function("hash_params", |b| {
        b.to_async(Runtime::new().unwrap())
            .iter(|| async { key.hash(&hash).await.unwrap() })
    });
}
