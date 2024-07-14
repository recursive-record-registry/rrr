use crate::crypto::encryption::EncryptionAlgorithm;
use crate::crypto::kdf::KdfExt;
use crate::crypto::password_hash::PasswordHash;
use crate::error::Result;
use crate::record::segment::{
    FragmentEncryptionKeyBytes, FragmentFileNameBytes, KdfUsage,
    KdfUsageFragmentParameters, KdfUsageFragmentUsage,
};
use crate::registry::{Registry, RegistryConfigHash, RegistryConfigKdf};
use crate::utils::serde::{BytesOrHexString, Secret};
use async_trait::async_trait;
use std::ops::{Deref, DerefMut};
use std::fmt::Debug;
use zeroize::{Zeroize, ZeroizeOnDrop};

use super::{RecordName, SuccessionNonce};

#[derive(Clone, Debug, PartialEq, Eq, Zeroize, ZeroizeOnDrop)]
pub struct RecordKey {
    // TODO: Use / as a path separator, and escape / with //.
    pub record_name: RecordName,
    pub predecessor_nonce: SuccessionNonce,
}

impl RecordKey {
    pub fn hash_blocking(&self, hash_params: &RegistryConfigHash) -> Result<HashedRecordKey> {
        let mut output_bytes =
            vec![0_u8; *hash_params.output_length_in_bytes as usize].into_boxed_slice();
        hash_params.algorithm.hash_password(
            &self.record_name,
            &self.predecessor_nonce,
            &mut output_bytes,
        )?;
        let hashed_record_key = HashedRecordKey(Secret(output_bytes));
        Ok(hashed_record_key)
    }

    pub async fn hash(&self, hash_params: &RegistryConfigHash) -> Result<HashedRecordKey> {
        let key = self.clone();
        let hash_params = hash_params.clone();
        tokio::task::spawn_blocking(move || -> Result<HashedRecordKey> {
            key.hash_blocking(&hash_params)
        })
        .await?
    }
}

#[derive(Clone, PartialEq, Eq, Debug, Zeroize, ZeroizeOnDrop)]
pub struct HashedRecordKey(pub(crate) Secret<Box<[u8]>>);

impl Deref for HashedRecordKey {
    type Target = [u8];

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl DerefMut for HashedRecordKey {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}

impl HashedRecordKey {
    pub(crate) fn derive_key_blocking(
        &self,
        usage: &KdfUsage,
        kdf_params: &RegistryConfigKdf,
        okm: &mut [u8],
    ) -> Result<()> {
        kdf_params
            .algorithm
            .derive_key_from_canonicalized_cbor(self, usage, okm)?;
        Ok(())
    }

    pub(crate) async fn derive_key(
        &self,
        usage: &KdfUsage,
        kdf_params: &RegistryConfigKdf,
        okm: &mut [u8],
    ) -> Result<()> {
        let key = self.clone();
        let usage = usage.clone();
        let kdf_params = kdf_params.clone();
        let okm_len = okm.len();
        let received_okm = tokio::task::spawn_blocking(move || -> Result<Vec<u8>> {
            let mut okm = vec![0_u8; okm_len];
            key.derive_key_blocking(&usage, &kdf_params, &mut okm)
                .map(move |()| okm)
        })
        .await??;

        okm.copy_from_slice(&received_okm);

        Ok(())
    }

    pub async fn derive_succession_nonce(
        &self,
        kdf_params: &RegistryConfigKdf,
    ) -> Result<SuccessionNonce> {
        let mut okm =
            vec![0_u8; *kdf_params.succession_nonce_length_in_bytes as usize].into_boxed_slice();

        self.derive_key(&KdfUsage::SuccessionNonce {}, kdf_params, &mut okm)
            .await?;

        Ok(SuccessionNonce(Secret(okm)))
    }

    pub async fn derive_fragment_file_name(
        &self,
        kdf_params: &RegistryConfigKdf,
        fragment_parameters: &KdfUsageFragmentParameters,
    ) -> Result<FragmentFileNameBytes> {
        let mut okm = vec![0_u8; *kdf_params.file_name_length_in_bytes as usize].into_boxed_slice();
        let usage = KdfUsage::Fragment {
            usage: KdfUsageFragmentUsage::FileName,
            parameters: fragment_parameters.clone(),
        };

        self.derive_key(&usage, kdf_params, &mut okm).await?;

        Ok(FragmentFileNameBytes(BytesOrHexString(okm)))
    }

    pub async fn derive_fragment_encryption_key(
        &self,
        kdf_params: &RegistryConfigKdf,
        encryption_alg: &EncryptionAlgorithm,
        fragment_parameters: &KdfUsageFragmentParameters,
    ) -> Result<FragmentEncryptionKeyBytes> {
        let mut okm = vec![0_u8; encryption_alg.key_length_in_bytes()].into_boxed_slice();
        let usage = KdfUsage::Fragment {
            usage: KdfUsageFragmentUsage::EncryptionKey,
            parameters: fragment_parameters.clone(),
        };

        self.derive_key(&usage, kdf_params, &mut okm).await?;

        Ok(FragmentEncryptionKeyBytes(Secret(okm)))
    }
}

#[async_trait]
pub trait HashRecordPath {
    async fn hash_record_path<L>(&self, registry: &Registry<L>) -> Result<HashedRecordKey>
    where
        L: Sync;
}

#[async_trait]
impl HashRecordPath for RecordKey {
    async fn hash_record_path<L>(&self, registry: &Registry<L>) -> Result<HashedRecordKey>
    where
        L: Sync,
    {
        self.hash(&registry.config.hash).await
    }
}

#[async_trait]
impl HashRecordPath for HashedRecordKey {
    async fn hash_record_path<L>(&self, _registry: &Registry<L>) -> Result<HashedRecordKey>
    where
        L: Sync,
    {
        Ok(self.clone())
    }
}
