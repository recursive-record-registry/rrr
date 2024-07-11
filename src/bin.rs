use std::path::PathBuf;

use chrono::DateTime;
use clap::Parser;
use rrr::{
    crypto::encryption::EncryptionAlgorithm,
    owned::{record::OwnedRecord, registry::OwnedRegistry},
    record::{Record, RecordKey, RecordMetadata, SuccessionNonce},
    registry::{Registry, RegistryConfig, WriteLock},
    serde_utils::BytesOrAscii,
};
use tokio::io::AsyncReadExt;

#[derive(Parser)]
#[command(version, about)]
enum Command {
    /// Creates a new source registry.
    New {
        /// The directory in which to create a new source registry.
        directory: PathBuf,
        /// Force existing files to be overwritten.
        #[arg(short, long, default_value = "false")]
        force: bool,
    },
    /// Compiles a source registry into an RRR registry.
    Make {
        /// Path to a source registry.
        #[arg(short, long, default_value = ".")]
        input_directory: PathBuf,
        /// Path to a directory in which to put RRR registry.
        #[arg(short, long, default_value = "target")]
        output_directory: PathBuf,
        /// Force existing files to be overwritten.
        #[arg(short, long, default_value = "false")]
        force: bool,
    },
}

async fn make_recursive(
    output_registry: &mut Registry<WriteLock>,
    input_registry: &OwnedRegistry,
    input_record: &OwnedRecord,
    predecessor_nonce: &SuccessionNonce,
    force: bool,
) -> color_eyre::Result<()> {
    let mut data = Vec::new();

    input_record
        .read()
        .await?
        .expect("Data not found.")
        .read_to_end(&mut data)
        .await?;

    let output_record = Record {
        metadata: {
            let mut metadata = RecordMetadata::default();

            if let Some(created_at) = input_record.config.metadata.created_at.as_ref() {
                let created_at_chrono = DateTime::parse_from_rfc3339(&created_at.to_string())?;

                metadata.insert_created_at(created_at_chrono);
            }

            metadata
        },
        data: BytesOrAscii(data),
    };
    let key = RecordKey {
        record_name: input_record.config.name.to_vec(),
        predecessor_nonce: predecessor_nonce.clone(),
    };
    let hashed_key = key.hash(&input_registry.hash).await?;

    output_registry
        .save_record(
            &input_registry.signing_keys,
            &hashed_key,
            &output_record,
            0,                                   // TODO
            0,                                   // TODO
            &[],                                 // TODO
            Some(&EncryptionAlgorithm::A256GCM), // TODO
            force,
        )
        .await?;

    Ok(())
}

#[tokio::main]
async fn main() -> color_eyre::Result<()> {
    match Command::parse() {
        Command::New { directory, force } => {
            OwnedRegistry::generate(&directory, force).await.unwrap();
            println!("New registry successfully generated in {directory:?}.");
        }
        Command::Make {
            input_directory,
            output_directory,
            force,
        } => {
            let input_registry = OwnedRegistry::load(input_directory).await?;
            let input_root_record = input_registry.load_root_record().await?;
            let mut output_registry = Registry::create(
                output_directory,
                RegistryConfig::from(&input_registry),
                force,
            )
            .await?;

            // TODO: Verify target registry keys

            make_recursive(
                &mut output_registry,
                &input_registry,
                &input_root_record,
                &Default::default(),
                force,
            )
            .await?;
        }
    }

    Ok(())
}

#[test]
fn verify_cli() {
    use clap::CommandFactory;
    Command::command().debug_assert();
}
