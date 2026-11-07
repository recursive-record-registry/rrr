use crate::crypto::signature::SigningKey;

use super::segment::SegmentEncryption;

/// The default for `max_collision_resolution_attempts`, used both when saving and when loading
/// records.
///
/// Readers only find records saved within their own number of attempts, so records should not be
/// saved with more attempts than readers are expected to use.
/// This value is conservative for registries with fragment file names of recommended length.
/// A higher value may be necessary for registries with short fragment file names.
pub const DEFAULT_MAX_COLLISION_RESOLUTION_ATTEMPTS: u64 = 4;

/// The default for `max_version_lookahead`, used when searching for record versions.
///
/// Readers stop searching for newer versions of a record after this many consecutive versions are
/// found to be missing.
pub const DEFAULT_MAX_VERSION_LOOKAHEAD: u64 = 10;

/// Options for loading a version of a record, see
/// [`Registry::load_record`](crate::registry::Registry::load_record).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct LoadRecordOptions {
    /// The highest collision index to try, see
    /// [`CollisionIndex`](super::segment::CollisionIndex).
    pub max_collision_resolution_attempts: u64,
}

impl Default for LoadRecordOptions {
    fn default() -> Self {
        Self {
            max_collision_resolution_attempts: DEFAULT_MAX_COLLISION_RESOLUTION_ATTEMPTS,
        }
    }
}

/// Options for listing the versions of a record, see
/// [`Registry::list_record_versions`](crate::registry::Registry::list_record_versions).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ListRecordVersionsOptions {
    /// How many consecutive missing versions to skip, while searching for newer versions.
    ///
    /// For example, when this is set to 1, and the versions 0, 1, 3, 5, 8 are saved, the
    /// versions 0, 1, 3 and 5 are listed.
    pub max_version_lookahead: u64,
    /// The highest collision index to try for each version, see
    /// [`CollisionIndex`](super::segment::CollisionIndex).
    pub max_collision_resolution_attempts: u64,
}

impl Default for ListRecordVersionsOptions {
    fn default() -> Self {
        Self {
            max_version_lookahead: DEFAULT_MAX_VERSION_LOOKAHEAD,
            max_collision_resolution_attempts: DEFAULT_MAX_COLLISION_RESOLUTION_ATTEMPTS,
        }
    }
}

impl From<ListRecordVersionsOptions> for LoadRecordOptions {
    fn from(value: ListRecordVersionsOptions) -> Self {
        Self {
            max_collision_resolution_attempts: value.max_collision_resolution_attempts,
        }
    }
}

/// Options for saving a version of a record, see
/// [`Registry::save_record`](crate::registry::Registry::save_record).
///
/// There is no [`Default`] implementation, so that saving records unsigned or unencrypted is
/// always an explicit choice. Use [`SaveRecordOptions::new`] to set the remaining options to their
/// defaults:
///
/// ```
/// # use rrr::record::SaveRecordOptions;
/// # let signing_keys = [];
/// # let encryption = None;
/// let options = SaveRecordOptions {
///     overwrite: true,
///     ..SaveRecordOptions::new(&signing_keys, encryption)
/// };
/// ```
#[derive(Clone, Copy, Debug)]
pub struct SaveRecordOptions<'a> {
    /// The keys to sign the record's fragments with.
    /// The registry's verifying keys should correspond to these.
    /// If empty, the fragments are not signed.
    pub signing_keys: &'a [SigningKey],
    /// How to encrypt the record's fragments.
    /// If `None`, the fragments are not encrypted.
    pub encryption: Option<&'a SegmentEncryption>,
    /// The offsets in the serialized record at which it is split into segments, in non-decreasing
    /// order. If empty, the record is saved as a single segment.
    pub split_at: &'a [usize],
    /// The highest collision index to try, see
    /// [`CollisionIndex`](super::segment::CollisionIndex) and
    /// [`DEFAULT_MAX_COLLISION_RESOLUTION_ATTEMPTS`].
    pub max_collision_resolution_attempts: u64,
    /// Whether to replace a record already saved with the same version.
    pub overwrite: bool,
}

impl<'a> SaveRecordOptions<'a> {
    /// Creates options that sign and encrypt fragments as specified, and leave the rest at their
    /// defaults: no splitting, [`DEFAULT_MAX_COLLISION_RESOLUTION_ATTEMPTS`], and no overwriting.
    pub fn new(signing_keys: &'a [SigningKey], encryption: Option<&'a SegmentEncryption>) -> Self {
        Self {
            signing_keys,
            encryption,
            split_at: &[],
            max_collision_resolution_attempts: DEFAULT_MAX_COLLISION_RESOLUTION_ATTEMPTS,
            overwrite: false,
        }
    }
}
