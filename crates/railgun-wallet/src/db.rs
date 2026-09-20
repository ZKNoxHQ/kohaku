//! On-disk key-value store for the SDK.
//!
//! Replaces `kohaku_db::fs::FilesystemDatabase`, which names each file `hex(key)`. The UTXO
//! indexer uses keys that embed the 127-character 0zk address, so the hex name exceeds the
//! 255-byte file name limit and `register` fails with ENAMETOOLONG. Here the file name is
//! `sha256(key)`, and writes go through a temp file and a rename so a crash mid-write cannot leave
//! a truncated tree or pending-POI entry behind.

use std::{
    io,
    path::PathBuf,
    sync::atomic::{AtomicU64, Ordering},
};

use kohaku_db::{Database, DatabaseError};
use sha2::{Digest, Sha256};

pub struct WalletDb {
    dir: PathBuf,
    tmp_counter: AtomicU64,
}

impl WalletDb {
    pub fn new(dir: impl Into<PathBuf>) -> io::Result<Self> {
        let dir = dir.into();
        std::fs::create_dir_all(&dir)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            // Holds decrypted notes and nullifying keys.
            std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700))?;
        }
        Ok(Self {
            dir,
            tmp_counter: AtomicU64::new(0),
        })
    }

    fn key_path(&self, key: &[u8]) -> PathBuf {
        self.dir.join(hex::encode(Sha256::digest(key)))
    }
}

fn storage(e: io::Error) -> DatabaseError {
    DatabaseError::StorageError(e.to_string())
}

#[async_trait::async_trait]
impl Database for WalletDb {
    async fn get(&self, key: &[u8]) -> Result<Option<Vec<u8>>, DatabaseError> {
        match tokio::fs::read(self.key_path(key)).await {
            Ok(data) => Ok(Some(data)),
            Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(None),
            Err(e) => Err(storage(e)),
        }
    }

    async fn set(&self, key: &[u8], value: &[u8]) -> Result<(), DatabaseError> {
        let path = self.key_path(key);
        let n = self.tmp_counter.fetch_add(1, Ordering::Relaxed);
        let tmp = path.with_extension(format!("tmp{n}"));
        tokio::fs::write(&tmp, value).await.map_err(storage)?;
        tokio::fs::rename(&tmp, &path).await.map_err(storage)
    }

    async fn delete(&self, key: &[u8]) -> Result<(), DatabaseError> {
        match tokio::fs::remove_file(self.key_path(key)).await {
            Ok(()) => Ok(()),
            Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(()),
            Err(e) => Err(storage(e)),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn long_keys_round_trip() {
        let dir = std::env::temp_dir().join(format!("rgw-db-test-{}", std::process::id()));
        let db = WalletDb::new(&dir).unwrap();
        let key = vec![0xabu8; 400];
        assert_eq!(db.get(&key).await.unwrap(), None);
        db.set(&key, b"one").await.unwrap();
        db.set(&key, b"two").await.unwrap();
        assert_eq!(db.get(&key).await.unwrap(), Some(b"two".to_vec()));
        db.delete(&key).await.unwrap();
        assert_eq!(db.get(&key).await.unwrap(), None);
        std::fs::remove_dir_all(&dir).ok();
    }
}
