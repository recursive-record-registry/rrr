use rrr::{
    crypto::{
        kdf::KdfAlgorithm,
        password_hash::{PasswordHashAlgorithm, argon2::Argon2Params},
    },
    error::Error,
    registry::{ConfigParam, Registry, RegistryConfig, RegistryConfigHash, RegistryConfigKdf},
    utils::fd_lock::ReadLock,
};
use std::{path::Path, time::Duration};

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
        !Registry::<ReadLock>::get_config_temporary_path_from_registry_directory(&registry_path)
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
        !Registry::<ReadLock>::get_config_temporary_path_from_registry_directory(&registry_path)
            .exists()
    );
}
