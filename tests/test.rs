use aes_gcm::aead::{rand_core::RngCore, OsRng};
use chrono::{Duration, Utc};
use prop::{array, collection::vec};
use proptest::prelude::*;
use rrr::serde_utils::{BytesOrAscii, BytesOrHexString};
use rrr::{
    crypto::encryption::EncryptionAlgorithm,
    record::{HashedRecordKey, Record, RecordKey, RecordMetadata},
    registry::Registry,
};
use tempfile::tempdir;
use test_strategy::proptest;
use tracing_test::traced_test;
use util::RegistryConfigWithSigningKeys;

mod util;

async fn hash_registry_path<L: std::fmt::Debug>(
    registry: &Registry<L>,
    record_names: &[Vec<u8>],
) -> Vec<(RecordKey, HashedRecordKey)> {
    let mut result = Vec::<(RecordKey, HashedRecordKey)>::new();

    for record_name in record_names {
        let record_key = RecordKey {
            record_name: record_name.clone(),
            predecessor_nonce: if let Some((_, hashed_key)) = result.last() {
                hashed_key
                    .derive_succession_nonce(&registry.config.kdf)
                    .await
                    .unwrap()
            } else {
                registry.config.kdf.get_root_record_predecessor_nonce()
            },
        };
        let hashed_record_key = record_key.hash(&registry.config.hash).await.unwrap();
        result.push((record_key, hashed_record_key));
    }

    result
}

prop_compose! {
    fn arb_record_name()(bytes in vec(any::<u8>(), 0..256)) -> BytesOrHexString<Vec<u8>> {
        BytesOrHexString(bytes)
    }
}

#[rustfmt::skip]
#[proptest(async = "tokio")]
#[traced_test]
async fn prop_registry(
    config_with_signing_keys: RegistryConfigWithSigningKeys,
    #[strategy(array::uniform(arb_record_name()))]
    record_names: [BytesOrHexString<Vec<u8>>; 4],
    encryption_algorithm: Option<EncryptionAlgorithm>,
) {
    let RegistryConfigWithSigningKeys {
        signing_keys,
        config,
    } = config_with_signing_keys;
    let registry_dir = tempdir().unwrap();

    dbg!(&registry_dir);

    let mut csprng = OsRng;
    let registry_path = registry_dir.path().to_path_buf();
    let mut registry = Registry::create(registry_path.clone(), config, false)
        .await
        .unwrap();
    let mut now = Utc::now();
    let record_names = std::iter::once(Vec::new())
        .chain(record_names.into_iter().map(|BytesOrHexString(record_name)| record_name))
        .collect::<Vec<Vec<u8>>>();

    let record_keys = hash_registry_path(&registry, &record_names).await;
    let mut records = Vec::<Record>::new();

    for (_, hashed_record_key) in &record_keys {
        let record = Record {
            metadata: {
                let mut metadata = RecordMetadata::default();
                metadata.insert_created_at(now);
                now += Duration::minutes(1);
                metadata
            },
            data: {
                let mut data = [0_u8; 32];
                csprng.fill_bytes(&mut data);
                BytesOrAscii(data.into())
            },
        };

        registry
            .save_record(
                &signing_keys,
                hashed_record_key,
                &record,
                0, // TODO
                0, // TODO
                &[], // TODO
                encryption_algorithm.as_ref(), // TODO
                false,
            )
            .await
            .unwrap();
        records.push(record);
    }

    let registry = registry.lock_read().await.unwrap();

    {
        let loaded_registry = Registry::open(registry_path.clone()).await.unwrap();

        assert_eq!(loaded_registry, registry);

        let loaded_record_keys = hash_registry_path(&loaded_registry, &record_names).await;

        assert_eq!(loaded_record_keys, record_keys);

        let mut loaded_records = Vec::new();

        for (_, hashed_record_key) in &record_keys {
            let loaded_record = loaded_registry
                .load_record(
                    hashed_record_key,
                    0, // TODO
                    0, // TODO
                )
                .await
                .unwrap()
                .unwrap();
            loaded_records.push(loaded_record);
        }

        assert_eq!(loaded_records, records);
    }
}

// #[tokio::test]
// async fn it_works() {
//     let hash = RegistryConfigHash {
//         algorithm: PasswordHashAlgorithm::Argon2(
//             Argon2Params::default_with_random_pepper_of_recommended_length(OsRng),
//         ),
//         kdf_input_length_in_bytes: 32,
//         successor_nonce_length_in_bytes: 32,
//     };
//     let record = RecordWithContext {
//         record: Cow::Owned(Record {
//             metadata: Default::default(),
//             data: ByteBuf::from(b"Hello, world!"),
//             // created_at: Timestamp(
//             //     DateTime::parse_from_rfc3339("2024-06-02T17:41:57Z")
//             //         .unwrap()
//             //         .into(),
//             // ),
//             // modified_at: Timestamp(Utc::now()),
//         }),
//         context: RecordContext {
//             key: RecordKey {
//                 record_name: b"hello".into(),
//                 predecessor_nonce: SuccessionNonce(
//                     (0_u8..hash.successor_nonce_length_in_bytes as u8).collect::<Box<[u8]>>(),
//                 ),
//             },
//         },
//     };

//     dbg!(&record);

//     let mut result = Vec::<u8>::new();
//     let hashed_key = record.context.key.hash(&hash).await.unwrap();
//     record
//         .record
//         .write(&[], &mut result, &hashed_key)
//         .await
//         .unwrap();

//     println!("Result:\n{:02x}", result.iter().format(""));
// }
