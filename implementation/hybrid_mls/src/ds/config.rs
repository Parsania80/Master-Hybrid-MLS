use std::path::{Path, PathBuf};

pub const DEFAULT_MAX_BYTES: u64 = 20 * 1024 * 1024 * 1024;

#[derive(Clone, Debug)]
pub struct StorageConfig {
    pub root_dir: PathBuf,
    pub db_path: PathBuf,
    pub max_bytes: u64,
}

impl StorageConfig {
    pub fn new(root_dir: impl AsRef<Path>, db_path: impl AsRef<Path>) -> Self {
        Self {
            root_dir: root_dir.as_ref().to_path_buf(),
            db_path: db_path.as_ref().to_path_buf(),
            max_bytes: DEFAULT_MAX_BYTES,
        }
    }
}
