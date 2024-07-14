use std::path::PathBuf;

use crate::{
    cbor::SerializeExt,
    record::{HashedRecordKey, RecordKey, RecordName, RecordPath},
    registry::Registry,
};
use clap::{Args, Parser, Subcommand, ValueEnum};
use color_eyre::{
    eyre::{bail, eyre, OptionExt},
    Result,
};
use futures::TryStreamExt;
use itertools::Itertools;
use tokio::io::AsyncWriteExt;

#[derive(Parser, Debug, Clone)]
#[command(version, about)]
pub struct RrrArgs {
    /// The path to a registry directory containing a `registry.cbor` file.
    /// By default, the current working directory is used.
    #[arg(short('d'), long, default_value = ".")]
    pub registry_directory: PathBuf,
    #[command(subcommand)]
    pub command: RrrCommandKind,
}

#[derive(Subcommand, Debug, Clone)]
pub enum RrrCommandKind {
    Registry {
        #[command(subcommand)]
        subcommand: RrrSubcommandRegistry,
    },
    Record {
        #[command(subcommand)]
        subcommand: RrrSubcommandRecord,
    },
}

#[derive(Subcommand, Debug, Clone)]
pub enum RrrSubcommandRegistry {
    /// Read the metadata of the registry.
    Info,
}

#[derive(Subcommand, Debug, Clone)]
pub enum RrrSubcommandRecord {
    /// List versions of a record.
    ListVersions {
        #[command(flatten)]
        record_path_args: RrrArgsRecordPath,
    },
    /// Read the metadata of the record.
    Info {
        // TODO: Option for the latest version, default.
        /// The version of the record to open.
        /// See [`ListVersions`].
        #[arg(short('v'), long)]
        record_version: u64,
        #[command(flatten)]
        record_path_args: RrrArgsRecordPath,
    },
    /// Read the specified record version from the registry.
    Read {
        // TODO: Option for the latest version, default.
        /// The version of the record to open.
        /// See [`ListVersions`].
        #[arg(short('v'), long)]
        record_version: u64,
        #[command(flatten)]
        record_path_args: RrrArgsRecordPath,
    },
}

#[derive(Args, Debug, Clone)]
pub struct RrrArgsRecordPath {
    /// How many attempts should be performed to resolve file name collisions.
    /// A higher value may be necessary for registries with short fragment file names.
    /// The default value of 4 is conservative for registries with fragment file names
    /// of recommended length, it is perhaps even excessive.
    #[arg(short('c'), long, value_enum, default_value = "4")]
    pub max_collision_resolution_attempts: u64,
    /// The format in which record names are specified.
    #[arg(short('f'), long, value_enum, default_value_t = Default::default())]
    pub record_name_format: RecordNameFormat,
    /// Whether the default record name of the root record ("") should be prepended to `RECORD_NAMES`.
    /// Enabling this makes it possible to replace the root record name with a custom value.
    /// This is an advanced feature that should not be necessary to use in most cases.
    #[arg(short('r'), long, value_enum, default_value = "false")]
    pub no_prepend_root_record_name: bool,
    /// A path to a record to read, made up of individual record names.
    /// If no record names are specified, the root record is read.
    pub record_names: Vec<String>,
}

impl RrrArgsRecordPath {
    async fn parse_record_path(&self) -> Result<RecordPath> {
        let mut result = Vec::new();

        if !self.no_prepend_root_record_name {
            result.push(Default::default());
        }

        for record_name in &self.record_names {
            result.push(
                self.record_name_format
                    .convert_record_name_to_bytes(record_name)?,
            );
        }

        Ok(result.try_into()?)
    }
}

#[derive(ValueEnum, Clone, Copy, Default, Debug)]
pub enum RecordNameFormat {
    /// UTF-8 strings.
    /// Example: "password".
    #[default]
    #[value(alias("utf-8"))]
    Utf8,
    /// Strings of hexadecimal digits, where 2 consecutive digits represent a single byte.
    /// Alias: "hex".
    /// Example: "70617373776f7264" (identical to "password" in UTF-8).
    #[value(alias("hex"))]
    Hexadecimal,
}

impl RecordNameFormat {
    fn convert_record_name_to_bytes(&self, record_name: impl AsRef<str>) -> Result<RecordName> {
        match self {
            RecordNameFormat::Utf8 => Ok(RecordName::from(Vec::from(record_name.as_ref()))),
            RecordNameFormat::Hexadecimal => {
                Ok(RecordName::from(hex::decode(record_name.as_ref())?))
            }
        }
    }
}

async fn resolve_path<L>(
    registry: &Registry<L>,
    record_path: &RecordPath,
) -> color_eyre::Result<HashedRecordKey> {
    let mut record_names_iter = record_path.iter();
    let hashed_record_key_root = RecordKey {
        record_name: record_names_iter
            .next()
            .expect("record path should never be empty")
            .clone(),
        predecessor_nonce: registry
            .config
            .kdf
            .get_root_record_predecessor_nonce()
            .clone(),
    }
    .hash(&registry.config.hash)
    .await?;
    let predecessor_nonce = futures::stream::iter(record_names_iter.cloned().map(Ok))
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

impl RrrArgs {
    pub async fn process(self) -> color_eyre::Result<()> {
        match self.command {
            RrrCommandKind::Registry { subcommand } => match subcommand {
                RrrSubcommandRegistry::Info => {
                    let registry = Registry::open(self.registry_directory).await?;

                    println!("{registry:#?}");
                }
            },
            RrrCommandKind::Record { subcommand } => match subcommand {
                RrrSubcommandRecord::ListVersions { record_path_args } => {
                    let registry = Registry::open(self.registry_directory).await?;
                    let record_names = record_path_args.parse_record_path().await?;
                    let hashed_record_key = resolve_path(&registry, &record_names).await?;

                    bail!("Not yet implemented");
                }
                RrrSubcommandRecord::Info {
                    record_version,
                    record_path_args,
                } => {
                    let registry = Registry::open(self.registry_directory).await?;
                    let record_path = record_path_args.parse_record_path().await?;
                    let hashed_record_key = resolve_path(&registry, &record_path).await?;
                    let record = registry
                        .load_record(
                            &hashed_record_key,
                            record_version.into(),
                            record_path_args.max_collision_resolution_attempts,
                        )
                        .await?
                        .ok_or_else(|| eyre!("record not found: {record_path}"))?;

                    println!("# Record parameters");
                    println!("- path:          {}", record_path.iter().format(" "));
                    println!("- name:          {}", record_path.last());
                    println!("- version:       {}", record_version);
                    println!("- nonce:         {}", *record.record_nonce);
                    println!("- content bytes: {}", record.data.len());
                    println!(
                        "- total bytes:   {}",
                        record
                            .segments
                            .iter()
                            .map(|segment| segment.segment_bytes)
                            .sum::<usize>()
                    );
                    println!("# Segments");

                    for segment in &record.segments {
                        println!("- {}", segment.fragment_file_name);
                        println!("  - content bytes: {}", segment.segment_bytes);
                        println!(
                            "  - enc. alg.:     {}",
                            segment
                                .fragment_encryption_algorithm
                                .map(|alg| alg.to_string())
                                .unwrap_or_else(|| "none".to_string())
                        );
                    }

                    println!("# Record metadata");

                    for (key, value) in record.metadata.iter() {
                        let key_diag = cbor_diag::parse_bytes(key.as_cbor_bytes()?)?.to_diag();
                        let value_diag = cbor_diag::parse_bytes(value.as_cbor_bytes()?)?.to_diag();

                        println!("- {key_diag}: {value_diag}");
                    }
                }
                RrrSubcommandRecord::Read {
                    record_version,
                    record_path_args,
                } => {
                    let registry = Registry::open(self.registry_directory).await?;
                    let record_path = record_path_args.parse_record_path().await?;
                    let hashed_record_key = resolve_path(&registry, &record_path).await?;
                    let record = registry
                        .load_record(
                            &hashed_record_key,
                            record_version.into(),
                            record_path_args.max_collision_resolution_attempts,
                        )
                        .await?
                        .ok_or_else(|| eyre!("record not found: {record_path}"))?;

                    tokio::io::stdout().write_all(&record.data).await?;
                }
            },
        }

        Ok(())
    }
}

#[test]
fn verify_cli() {
    use clap::CommandFactory;
    RrrArgs::command().debug_assert();
}
