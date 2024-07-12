//! The CDDL tests are supposed to ensure conformance to the COSE specification,
//! as well as restrict the CBOR output generated by this library.

use cddl::{
    cddl_from_str, parser,
    validator::{cbor::CBORValidator, Validator},
};
use coset::CborSerializable;
use itertools::Itertools;
use rrr::{
    cbor::{SerializeExt, Value, ValueExt},
    crypto::encryption::EncryptionAlgorithm,
    record::{Record, RecordKey},
    segment::{FragmentKey, KdfUsage, KdfUsageFragmentParameters, Segment},
};
use std::{fs, path::Path};
use test_strategy::proptest;
use tracing_test::traced_test;
use util::RegistryConfigWithSigningKeys;

mod util;

#[test]
#[traced_test]
fn compile_cddl_files() -> Result<(), parser::Error> {
    let mut result = Ok(());

    for file in fs::read_dir("cddl").unwrap() {
        let file = file.unwrap();

        if file.path().extension().unwrap() != "cddl" {
            continue;
        }

        let file_content = fs::read_to_string(file.path()).unwrap();
        match parser::cddl_from_str(&file_content, true) {
            Ok(_) => println!("file: {:#?} ... success", file.path()),
            Err(_) => {
                eprintln!("file: {:#?} ... failure", file.path());
                result = Err(parser::Error::INCREMENTAL);
            }
        }
    }

    result
}

fn validate_with_cddl(cddl_path: impl AsRef<Path>, cbor: Value) {
    let cddl_string = fs::read_to_string(cddl_path).unwrap();
    let cddl = cddl_from_str(&cddl_string, true).unwrap();

    {
        let mut bytes = Vec::new();
        coset::cbor::into_writer(&cbor, &mut bytes).unwrap();
        println!("cbor: {:02x}", bytes.iter().format(""));
    }

    let mut cv = CBORValidator::new(&cddl, cbor, None);

    match cv.validate() {
        Ok(()) => (),
        Err(cddl::validator::cbor::Error::Validation(validation_errors)) => {
            let mut message = String::new();
            for (index, validation_error) in validation_errors.into_iter().enumerate() {
                message += &format!("#{index}: {validation_error}\n");
            }
            panic!("{message}");
        }
        err @ Err(_) => err.unwrap(),
    }
}

#[proptest]
#[traced_test]
fn verify_cddl_record(record: Record) {
    validate_with_cddl("cddl/record.cddl", Value::serialized(&record).unwrap());
}

#[proptest]
#[traced_test]
fn verify_cddl_registry(config_with_signing_keys: RegistryConfigWithSigningKeys) {
    let RegistryConfigWithSigningKeys { config, .. } = config_with_signing_keys;

    validate_with_cddl("cddl/registry.cddl", Value::serialized(&config).unwrap());
}

#[proptest]
#[traced_test]
fn verify_cddl_segment(segment: Segment) {
    validate_with_cddl("cddl/segment.cddl", Value::serialized(&segment).unwrap());
}

#[proptest(async = "tokio")]
#[traced_test]
async fn verify_cddl_fragment(
    config_with_signing_keys: RegistryConfigWithSigningKeys,
    segment: Segment,
    encryption_algorithm: Option<EncryptionAlgorithm>,
) {
    let RegistryConfigWithSigningKeys {
        config,
        signing_keys,
    } = config_with_signing_keys;
    let record_key = RecordKey {
        record_name: vec![],                                               // TODO
        predecessor_nonce: config.kdf.get_root_record_predecessor_nonce(), // TODO
    };
    let hashed_record_key = record_key.hash(&config.hash).await.unwrap();
    let fragment_key = FragmentKey {
        hashed_record_key: hashed_record_key.clone(),
        fragment_parameters: KdfUsageFragmentParameters {
            record_version: 0, // TODO
            record_nonce: 0,   // TODO
            segment_index: 0,  // TODO
        },
    };
    let mut fragment_bytes = Vec::<u8>::new();

    segment
        .write_fragment(
            &signing_keys,
            &config.kdf,
            &mut fragment_bytes,
            &fragment_key,
            encryption_algorithm.as_ref(),
        )
        .await
        .unwrap();

    dbg!(&segment);

    validate_with_cddl(
        "cddl/fragment.cddl",
        Value::from_slice(&fragment_bytes).unwrap(),
    );
}

#[proptest(async = "tokio")]
#[traced_test]
async fn verify_cddl_kdf_usage(kdf_usage: KdfUsage) {
    let cbor = kdf_usage.as_canonical_cbor_value().unwrap();

    assert!(cbor.is_canonical(), "KDF usage is not in a canonical form");
    validate_with_cddl("cddl/kdf_usage.cddl", cbor);
}
