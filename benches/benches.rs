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
        algorithm: PasswordHashAlgorithm::Argon2(Argon2Params::default()),
        output_length_in_bytes: ConfigParam::try_from(32).unwrap(),
    };
    let kdf = RegistryConfigKdf::builder()
        .with_algorithm(KdfAlgorithm::Hkdf(HkdfParams {
            prf: HkdfPrf::Sha256,
        }))
        .with_file_name_length_in_bytes(8)
        .with_succession_nonce_length_in_bytes(32)
        .build_with_random_root_predecessor_nonce(OsRng)
        .unwrap();
    let key = RecordKey {
        record_name: RecordName::from(b"hello".to_vec()),
        predecessor_nonce: kdf.get_root_record_predecessor_nonce().clone(),
    };

    c.bench_function("hash_params", |b| {
        b.to_async(Runtime::new().unwrap())
            .iter(|| async { key.hash(&hash).await.unwrap() })
    });
}
