use rrr::{
    crypto::encryption::EncryptionAlgorithm,
    crypto::{
        kdf::KdfAlgorithm,
        password_hash::{PasswordHashAlgorithm, argon2::Argon2Params},
    },
    error::Error,
    record::{
        HashRecordPath, Record, RecordPath,
        segment::{
            FragmentKey, KdfUsageFragmentParameters, RecordNonce, RecordParameters, RecordVersion,
            Segment, SegmentEncryption,
        },
    },
    registry::{ConfigParam, Registry, RegistryConfig, RegistryConfigHash, RegistryConfigKdf},
    utils::{
        fd_lock::{ReadLock, WriteLock},
        fs::temporary_path,
        serde::BytesOrAscii,
    },
};
use std::{
    path::{Path, PathBuf},
    time::Duration,
};

/// A config with cheap password hashing, and a random root predecessor nonce of the given length.
fn config(succession_nonce_length_in_bytes: u64) -> RegistryConfig {
    let mut argon2_params = Argon2Params::default();
    argon2_params.m_cost = 64;
    argon2_params.t_cost = 1;

    RegistryConfig {
        hash: RegistryConfigHash {
            algorithm: PasswordHashAlgorithm::Argon2(argon2_params),
            output_length_in_bytes: ConfigParam::try_from(32).unwrap(),
        },
        kdf: RegistryConfigKdf::builder()
            .with_algorithm(KdfAlgorithm::Hkdf(Default::default()))
            .with_succession_nonce_length_in_bytes(succession_nonce_length_in_bytes)
            .build_with_random_root_predecessor_nonce(rand::rng())
            .unwrap(),
        verifying_keys: vec![],
    }
}

fn config_file_length(registry_path: &Path) -> u64 {
    std::fs::metadata(Registry::<ReadLock>::get_config_path_from_registry_directory(registry_path))
        .unwrap()
        .len()
}

#[tokio::test]
async fn lock_write_preserves_config() {
    let registry_dir = tempfile::tempdir().unwrap();
    let registry_path = registry_dir.path().to_path_buf();
    let config = config(32);

    drop(
        Registry::create(registry_path.clone(), config.clone(), false)
            .await
            .unwrap(),
    );

    let registry = Registry::open(registry_path.clone()).await.unwrap();
    let registry = registry.lock_write().await.unwrap();
    drop(registry);

    let registry = Registry::open(registry_path.clone()).await.unwrap();
    assert_eq!(registry.config, config);
}

#[tokio::test]
async fn save_config_replaces_previous_config() {
    let registry_dir = tempfile::tempdir().unwrap();
    let registry_path = registry_dir.path().to_path_buf();
    let mut registry = Registry::create(registry_path.clone(), config(64), false)
        .await
        .unwrap();
    let initial_length = config_file_length(&registry_path);

    // Save a shorter config twice, through the same lock, so that a stale config or trailing bytes
    // would be noticed.
    let shorter_config = config(16);
    registry.config = shorter_config.clone();
    registry.save_config().await.unwrap();
    registry.save_config().await.unwrap();

    let shorter_length = config_file_length(&registry_path);
    assert!(shorter_length < initial_length);

    // Also save a config after re-acquiring the write lock.
    let registry = registry.lock_read().await.unwrap();
    let mut registry = registry.lock_write().await.unwrap();
    let final_config = config(16);
    registry.config = final_config.clone();
    registry.save_config().await.unwrap();
    drop(registry);

    assert_eq!(config_file_length(&registry_path), shorter_length);
    let registry = Registry::open(registry_path.clone()).await.unwrap();
    assert_eq!(registry.config, final_config);
    assert!(
        !temporary_path(
            Registry::<ReadLock>::get_config_path_from_registry_directory(&registry_path)
        )
        .unwrap()
        .exists()
    );
}

#[tokio::test]
async fn create_fails_if_registry_exists() {
    let registry_dir = tempfile::tempdir().unwrap();
    let registry_path = registry_dir.path().to_path_buf();
    let original_config = config(32);

    drop(
        Registry::create(registry_path.clone(), original_config.clone(), false)
            .await
            .unwrap(),
    );

    let result = Registry::create(registry_path.clone(), config(48), false).await;
    assert!(
        matches!(&result, Err(Error::Io(error)) if error.kind() == std::io::ErrorKind::AlreadyExists),
        "{result:?}"
    );
    let registry = Registry::open(registry_path.clone()).await.unwrap();
    assert_eq!(registry.config, original_config);
}

#[tokio::test]
async fn readers_block_writers() {
    let registry_dir = tempfile::tempdir().unwrap();
    let registry_path = registry_dir.path().to_path_buf();

    drop(
        Registry::create(registry_path.clone(), config(32), false)
            .await
            .unwrap(),
    );

    let reader = Registry::open(registry_path.clone()).await.unwrap();
    let writer = tokio::spawn({
        let registry_path = registry_path.clone();
        async move {
            Registry::open(registry_path)
                .await
                .unwrap()
                .lock_write()
                .await
                .unwrap()
        }
    });

    tokio::time::sleep(Duration::from_millis(500)).await;
    assert!(
        !writer.is_finished(),
        "the writer did not wait for the reader"
    );

    drop(reader);
    tokio::time::timeout(Duration::from_secs(10), writer)
        .await
        .expect("the writer did not acquire the lock after the reader released it")
        .unwrap();
}

#[tokio::test]
async fn open_recreates_missing_lock_file() {
    let registry_dir = tempfile::tempdir().unwrap();
    let registry_path = registry_dir.path().to_path_buf();
    let config = config(32);

    drop(
        Registry::create(registry_path.clone(), config.clone(), false)
            .await
            .unwrap(),
    );

    // Registries created before the lock file was introduced do not have one.
    let lock_path = Registry::<ReadLock>::get_lock_path_from_registry_directory(&registry_path);
    std::fs::remove_file(&lock_path).unwrap();

    let registry = Registry::open(registry_path.clone()).await.unwrap();
    assert_eq!(registry.config, config);
    assert!(lock_path.exists());
}

#[tokio::test]
async fn open_creates_no_lock_file_outside_registry() {
    let directory = tempfile::tempdir().unwrap();
    let directory_path = directory.path().to_path_buf();

    let result = Registry::open(directory_path.clone()).await;
    assert!(
        matches!(&result, Err(Error::Io(error)) if error.kind() == std::io::ErrorKind::NotFound),
        "{result:?}"
    );
    assert_eq!(std::fs::read_dir(&directory_path).unwrap().count(), 0);
}

#[tokio::test]
async fn save_config_removes_temporary_file_on_failure() {
    let registry_dir = tempfile::tempdir().unwrap();
    let registry_path = registry_dir.path().to_path_buf();
    let mut registry = Registry::create(registry_path.clone(), config(32), false)
        .await
        .unwrap();

    // Make replacing the config file fail, by putting a directory in its place.
    let config_path = Registry::<ReadLock>::get_config_path_from_registry_directory(&registry_path);
    std::fs::remove_file(&config_path).unwrap();
    std::fs::create_dir(&config_path).unwrap();

    registry.save_config().await.unwrap_err();

    assert!(
        !temporary_path(
            Registry::<ReadLock>::get_config_path_from_registry_directory(&registry_path)
        )
        .unwrap()
        .exists()
    );
}

fn record(data: &[u8]) -> Record {
    Record {
        metadata: Default::default(),
        data: BytesOrAscii(data.to_vec()),
    }
}

fn encryptions() -> [Option<SegmentEncryption>; 2] {
    [
        None,
        Some(SegmentEncryption {
            algorithm: EncryptionAlgorithm::Aes256Gcm,
            padding_to_bytes: 1024,
        }),
    ]
}

fn fragment_count(registry_path: &Path) -> usize {
    std::fs::read_dir(
        Registry::<ReadLock>::get_records_directory_from_registry_directory(registry_path),
    )
    .unwrap()
    .count()
}

async fn save(
    registry: &mut Registry<WriteLock>,
    data: &[u8],
    max_collision_resolution_attempts: u64,
    split_at: &[usize],
    encryption: Option<&SegmentEncryption>,
    overwrite: bool,
) -> rrr::error::Result<RecordNonce> {
    registry
        .save_record(
            &[],
            &RecordPath::default(),
            &record(data),
            RecordVersion(0),
            max_collision_resolution_attempts,
            split_at,
            encryption,
            overwrite,
        )
        .await
}

async fn load(registry: &Registry<WriteLock>, max_collision_resolution_attempts: u64) -> Vec<u8> {
    registry
        .load_record(
            &RecordPath::default(),
            RecordVersion(0),
            max_collision_resolution_attempts,
        )
        .await
        .unwrap()
        .unwrap()
        .record
        .data
        .0
        .clone()
}

#[tokio::test]
async fn save_record_overwrites_same_version() {
    for encryption in encryptions() {
        let registry_dir = tempfile::tempdir().unwrap();
        let registry_path = registry_dir.path().to_path_buf();
        let mut registry = Registry::create(registry_path.clone(), config(32), false)
            .await
            .unwrap();

        // The previous record has more segments than the new one, all of which must be removed.
        let nonce = save(
            &mut registry,
            b"previous record",
            0,
            &[4, 8],
            encryption.as_ref(),
            false,
        )
        .await
        .unwrap();
        assert_eq!(nonce, RecordNonce(0));
        assert_eq!(fragment_count(&registry_path), 3);

        let nonce = save(
            &mut registry,
            b"new record",
            0,
            &[],
            encryption.as_ref(),
            true,
        )
        .await
        .unwrap();
        assert_eq!(nonce, RecordNonce(0));
        assert_eq!(load(&registry, 0).await, b"new record");
        assert_eq!(fragment_count(&registry_path), 1);
    }
}

#[tokio::test]
async fn save_record_without_overwrite_keeps_existing_record() {
    let registry_dir = tempfile::tempdir().unwrap();
    let registry_path = registry_dir.path().to_path_buf();
    let mut registry = Registry::create(registry_path.clone(), config(32), false)
        .await
        .unwrap();

    save(&mut registry, b"previous record", 0, &[], None, false)
        .await
        .unwrap();
    let result = save(&mut registry, b"new record", 0, &[], None, false).await;

    assert!(
        matches!(result, Err(Error::CollisionResolutionFailed)),
        "{result:?}"
    );
    assert_eq!(load(&registry, 0).await, b"previous record");
}

/// Returns the contents of the only fragment of a record, saved in a separate registry.
async fn fragment_of_another_record(encryption: Option<&SegmentEncryption>) -> Vec<u8> {
    let registry_dir = tempfile::tempdir().unwrap();
    let registry_path = registry_dir.path().to_path_buf();
    let mut registry = Registry::create(registry_path.clone(), config(32), false)
        .await
        .unwrap();

    save(&mut registry, b"another record", 0, &[], encryption, false)
        .await
        .unwrap();

    let records_path =
        Registry::<ReadLock>::get_records_directory_from_registry_directory(&registry_path);
    let mut fragment_paths = std::fs::read_dir(records_path).unwrap();
    let fragment_path = fragment_paths.next().unwrap().unwrap().path();
    assert!(fragment_paths.next().is_none());
    std::fs::read(fragment_path).unwrap()
}

/// Returns the key and path of the record's first fragment with nonce 0.
async fn first_fragment(registry: &Registry<WriteLock>) -> (FragmentKey, PathBuf) {
    let fragment_key = FragmentKey {
        hashed_record_key: RecordPath::default()
            .hash_record_path(registry)
            .await
            .unwrap(),
        fragment_parameters: KdfUsageFragmentParameters {
            record_parameters: RecordParameters {
                version: RecordVersion(0),
                nonce: RecordNonce(0),
            },
            segment_index: 0.into(),
        },
    };
    let fragment_path = registry.get_fragment_path(
        &fragment_key
            .derive_file_name(&registry.config.kdf)
            .await
            .unwrap(),
    );

    (fragment_key, fragment_path)
}

#[tokio::test]
async fn save_record_overwrite_keeps_colliding_fragments_of_other_records() {
    for encryption in encryptions() {
        let colliding_file = fragment_of_another_record(encryption.as_ref()).await;
        let registry_dir = tempfile::tempdir().unwrap();
        let registry_path = registry_dir.path().to_path_buf();
        let mut registry = Registry::create(registry_path.clone(), config(32), false)
            .await
            .unwrap();

        let (fragment_key, colliding_path) = first_fragment(&registry).await;
        std::fs::write(&colliding_path, &colliding_file).unwrap();

        // Make sure that both ways of telling fragments of other records apart are covered.
        let error = Segment::read_fragment(&registry, &fragment_key)
            .await
            .unwrap_err();
        match &encryption {
            None => assert!(matches!(error, Error::FileTagMismatch), "{error:?}"),
            Some(_) => assert!(matches!(error, Error::Cipher(_)), "{error:?}"),
        }

        // The previous record ends up under nonce 1, and so must the new one.
        for data in [&b"previous record"[..], b"new record"] {
            let nonce = save(&mut registry, data, 1, &[], encryption.as_ref(), true)
                .await
                .unwrap();
            assert_eq!(nonce, RecordNonce(1));
            assert_eq!(load(&registry, 1).await, data);
            assert_eq!(std::fs::read(&colliding_path).unwrap(), colliding_file);
            assert_eq!(fragment_count(&registry_path), 2);
        }
    }
}

#[tokio::test]
async fn save_record_overwrite_fails_on_invalid_fragment() {
    let registry_dir = tempfile::tempdir().unwrap();
    let registry_path = registry_dir.path().to_path_buf();
    let mut registry = Registry::create(registry_path.clone(), config(32), false)
        .await
        .unwrap();

    let (_, invalid_path) = first_fragment(&registry).await;
    std::fs::write(&invalid_path, b"not a fragment").unwrap();

    let result = save(&mut registry, b"new record", 1, &[], None, true).await;

    assert!(matches!(result, Err(Error::Coset(_))), "{result:?}");
    assert_eq!(std::fs::read(&invalid_path).unwrap(), b"not a fragment");
    assert_eq!(fragment_count(&registry_path), 1);
}

#[tokio::test]
async fn save_record_failure_leaves_no_fragments() {
    let registry_dir = tempfile::tempdir().unwrap();
    let registry_path = registry_dir.path().to_path_buf();
    let mut registry = Registry::create(registry_path.clone(), config(32), false)
        .await
        .unwrap();
    let data = [b'x'; 1000];
    let encryption = |padding_to_bytes| SegmentEncryption {
        algorithm: EncryptionAlgorithm::Aes256Gcm,
        padding_to_bytes,
    };

    // The first segment fits, and is written before the second one turns out not to.
    let result = save(
        &mut registry,
        &data,
        0,
        &[10],
        Some(&encryption(256)),
        false,
    )
    .await;

    assert!(
        matches!(result, Err(Error::SegmentTooLarge { .. })),
        "{result:?}"
    );
    assert_eq!(fragment_count(&registry_path), 0);

    // The save can be retried without overwriting, and without any further record nonces.
    let nonce = save(
        &mut registry,
        &data,
        0,
        &[10],
        Some(&encryption(2048)),
        false,
    )
    .await
    .unwrap();
    assert_eq!(nonce, RecordNonce(0));
    assert_eq!(load(&registry, 0).await, data);
}
