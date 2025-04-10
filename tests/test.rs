use futures::future::BoxFuture;
use futures::FutureExt;
use prop::collection::vec;
use proptest::prelude::*;
use rrr::error::Error;
use rrr::record::segment::{RecordNonce, RecordVersion, SegmentEncryption};
use rrr::record::{RecordName, SuccessionNonce};
use rrr::utils::fd_lock::FileLock;
use rrr::utils::serde::BytesOrHexString;
use rrr::{
    record::{HashedRecordKey, Record, RecordKey},
    registry::Registry,
};
use tempfile::tempdir;
use test_strategy::proptest;
use tracing_test::traced_test;
use util::RegistryConfigWithSigningKeys;

mod util;

#[derive(Debug)]
pub struct RecordTestNode {
    record_name: RecordName,
    record_versions: Vec<Record>,
    successors: Vec<RecordTestNode>,
}

prop_compose! {
    /// A strategy for generating a leaf record.
    fn arb_record_test_leaf(
        max_duplicates: usize,
        max_record_name_bytes: usize,
    )(
        record_name_bytes in vec(any::<u8>(), 0..max_record_name_bytes),
        record_versions in vec(any::<Record>(), 1..=(max_duplicates + 1)),
    ) -> RecordTestNode {
        RecordTestNode {
            record_name: RecordName::from(record_name_bytes),
            record_versions,
            successors: vec![],
        }
    }
}

/// A strategy for generating a tree of records.
fn arb_record_test_tree(
    depth: u32,
    desired_size: u32,
    expected_branch_size: u32,
    max_duplicates: usize,
) -> impl Strategy<Value = RecordTestNode> {
    let leaf = arb_record_test_leaf(max_duplicates, 256);

    leaf.prop_recursive(depth, desired_size, expected_branch_size, move |inner| {
        (
            vec(inner.clone(), 0..(expected_branch_size as usize)),
            arb_record_test_leaf(max_duplicates, 256),
        )
            .prop_map(|(successors, mut parent)| {
                parent.successors = successors;
                parent
            })
    })
}

fn hash_registry_tree_recursive<'a, L: FileLock + 'a>(
    registry: &'a Registry<L>,
    record_test_node: &'a RecordTestNode,
    predecessor_nonce: Option<&'a SuccessionNonce>,
    result: &'a mut Vec<(RecordKey, HashedRecordKey, RecordVersion, Record)>,
) -> BoxFuture<'a, ()> {
    async move {
        let record_key = RecordKey {
            record_name: record_test_node.record_name.clone(),
            predecessor_nonce: if let Some(predecessor_nonce) = predecessor_nonce {
                predecessor_nonce.clone()
            } else {
                registry
                    .config
                    .kdf
                    .get_root_record_predecessor_nonce()
                    .clone()
            },
        };
        let hashed_record_key = record_key.hash(&registry.config.hash).await.unwrap();
        let succession_nonce = hashed_record_key
            .derive_succession_nonce(&registry.config.kdf)
            .await
            .unwrap();

        for (record_version, record) in record_test_node.record_versions.iter().enumerate() {
            result.push((
                record_key.clone(),
                hashed_record_key.clone(),
                (record_version as u64).into(),
                record.clone(),
            ));
        }

        for successor in &record_test_node.successors {
            hash_registry_tree_recursive(registry, successor, Some(&succession_nonce), result)
                .await;
        }
    }
    .boxed()
}

async fn hash_registry_tree<'a, L: FileLock + 'a>(
    registry: &'a Registry<L>,
    record_test_node: &'a RecordTestNode,
    predecessor_nonce: Option<&'a SuccessionNonce>,
) -> Vec<(RecordKey, HashedRecordKey, RecordVersion, Record)> {
    let mut result = Vec::new();
    hash_registry_tree_recursive(registry, record_test_node, predecessor_nonce, &mut result).await;
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
    #[strategy(arb_record_test_tree(3, 16, 3, 2))]
    record_test_tree: RecordTestNode,
    encryption: Option<SegmentEncryption>,
) {
    dbg!(&record_test_tree);

    let RegistryConfigWithSigningKeys {
        signing_keys,
        config,
    } = config_with_signing_keys;
    let registry_dir = tempdir().unwrap();

    dbg!(&registry_dir);

    let registry_path = registry_dir.path().to_path_buf();
    let mut registry = Registry::create(registry_path.clone(), config, false)
        .await
        .unwrap();
    let record_keys = hash_registry_tree(&registry, &record_test_tree, None).await;
    let mut records = Vec::<(Record, RecordNonce)>::new();

    for (_, hashed_record_key, record_version, record) in &record_keys {
        let mut max_collision_resolution_attempts = 0;

        loop {
            let result = registry
                .save_record(
                    &signing_keys,
                    hashed_record_key,
                    record,
                    *record_version,
                    max_collision_resolution_attempts,
                    &[], // TODO
                    encryption.as_ref(), // TODO
                    false,
                )
                .await;

            match result {
                Ok(record_nonce) => {
                    assert_eq!(*record_nonce, max_collision_resolution_attempts);
                    break;
                },
                Err(Error::CollisionResolutionFailed) => {
                    max_collision_resolution_attempts += 1;
                    continue;
                }
                Err(error) => return Err(error.into()),
            }
        };

        records.push((
            record.clone(),
            max_collision_resolution_attempts.into(),
        ));
    }

    let registry = registry.lock_read().await.unwrap();

    {
        let loaded_registry = Registry::open(registry_path.clone()).await.unwrap();

        assert_eq!(loaded_registry, registry);

        let loaded_record_keys = hash_registry_tree(&loaded_registry, &record_test_tree, None).await;

        assert_eq!(loaded_record_keys, record_keys);

        let mut loaded_records = Vec::new();

        for ((_, hashed_record_key, record_version, _), &record_nonce) in record_keys.iter().zip(records.iter().map(|(_, record_nonce)| record_nonce)) {
            if *record_nonce > 0 {
                let result = loaded_registry
                    .load_record(
                        hashed_record_key,
                        *record_version,
                        *record_nonce - 1,
                    )
                    .await;
                dbg!(&result);
                let found = matches!(result, Ok(Some(_)));

                assert!(!found, "record found despite insufficient max collision resolution attempts: {}", *record_nonce);
            }

            let result = loaded_registry
                .load_record(
                    hashed_record_key,
                    *record_version,
                    *record_nonce,
                )
                .await
                .unwrap()
                .unwrap();

            loaded_records.push((result.record, result.record_nonce));
        }

        // TODO: Check segment equality
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
