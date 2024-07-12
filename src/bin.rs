#![feature(async_closure)]

use std::path::PathBuf;

use clap::{Parser, ValueEnum};
use color_eyre::Result;
use futures::TryStreamExt;
use rrr::{
    record::{HashedRecordKey, RecordKey},
    registry::Registry,
};

#[derive(Parser)]
#[command(version, about)]
struct Args {
    #[arg(short('d'), long, default_value = ".")]
    pub registry_directory: PathBuf,
    #[command(subcommand)]
    pub command: Command,
}

#[derive(Parser, Clone)]
enum Command {
    Info {},
    Read {
        /// Enter record names in a hexadecimal format, instead of UTF-8.
        #[arg(short('f'), long, value_enum, default_value_t = Default::default())]
        record_name_format: RecordNameFormat,
        #[arg(short('c'), long, value_enum, default_value = "4")]
        max_collision_resolution_attempts: u64,
        #[arg(short('r'), long, value_enum, default_value = "")]
        root_record_name: String,
        record_names: Vec<String>,
    },
}

#[derive(ValueEnum, Clone, Copy, Default)]
enum RecordNameFormat {
    #[default]
    #[value(alias("utf-8"))]
    Utf8,
    #[value(alias("hex"))]
    Hexadecimal,
}

impl RecordNameFormat {
    fn convert_record_name_to_bytes(&self, record_name: String) -> Result<Vec<u8>> {
        match self {
            RecordNameFormat::Utf8 => Ok(record_name.into_bytes()),
            RecordNameFormat::Hexadecimal => Ok(hex::decode(record_name)?),
        }
    }
}

async fn resolve_path<L>(
    registry: &Registry<L>,
    root_record_name: Vec<u8>,
    record_names: Vec<Vec<u8>>,
) -> color_eyre::Result<HashedRecordKey> {
    let hashed_record_key_root = RecordKey {
        record_name: root_record_name,
        predecessor_nonce: registry.config.kdf.get_root_record_predecessor_nonce(),
    }
    .hash(&registry.config.hash)
    .await?;
    let predecessor_nonce = futures::stream::iter(record_names.into_iter().map(Ok))
        .try_fold(
            hashed_record_key_root,
            async |hashed_record_key: HashedRecordKey, record_name| {
                let predecessor_nonce = hashed_record_key
                    .derive_succession_nonce(&registry.config.kdf)
                    .await?;
                let record_key = RecordKey {
                    record_name,
                    predecessor_nonce,
                };

                record_key.hash(&registry.config.hash).await
            },
        )
        .await?;

    Ok(predecessor_nonce)
}

#[tokio::main]
async fn main() -> color_eyre::Result<()> {
    let args = Args::parse();

    match args.command {
        Command::Info {} => {
            let registry = Registry::open(args.registry_directory).await?;

            println!("{registry:#?}");
        }
        Command::Read {
            record_name_format,
            max_collision_resolution_attempts,
            root_record_name,
            record_names,
        } => {
            let registry = Registry::open(args.registry_directory).await?;
            let root_record_name =
                record_name_format.convert_record_name_to_bytes(root_record_name)?;
            let record_names = record_names
                .into_iter()
                .map(|record_name| record_name_format.convert_record_name_to_bytes(record_name))
                .collect::<Result<Vec<_>, _>>()?;
            let hashed_record_key = resolve_path(&registry, root_record_name, record_names).await?;
            let record = registry
                .load_record(
                    &hashed_record_key,
                    0, // TODO
                    max_collision_resolution_attempts,
                )
                .await?;

            println!("{record:#?}");
        }
    }

    Ok(())
}

#[test]
fn verify_cli() {
    use clap::CommandFactory;
    Command::command().debug_assert();
}
