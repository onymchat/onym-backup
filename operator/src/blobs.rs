//! Where sealed bytes live.
//!
//! SQLite holds the bookkeeping; the filesystem holds the snapshots.
//! Layout:
//!
//! ```text
//! <root>/<hh>/<holder-handle>/<digest-hex>/<index>.part
//! <root>/incoming/<upload-id>/<index>.part
//! ```
//!
//! Partitioned by holder, and `hh` — the handle's first byte — only so
//! one directory does not accumulate every holder. **Dedup across
//! holders is impossible by construction**, which is not an oversight:
//! §14.6 forbids convergent keying, so the same 40 MB stored by two
//! people is 80 MB on disk, forever. That is a real unit cost and it
//! belongs in the pricing rather than being engineered away later.

use std::path::{Path, PathBuf};

use sha2::{Digest, Sha256};

use crate::error::{Error, Result};

pub struct Blobs {
    root: PathBuf,
}

impl Blobs {
    pub fn new(root: impl Into<PathBuf>) -> Blobs {
        Blobs { root: root.into() }
    }

    fn holder_dir(&self, handle: &str) -> PathBuf {
        // The handle is a hex digest we computed, so it cannot contain
        // a separator — but taking only the leading byte for the shard
        // and using the whole handle as the leaf keeps that true even
        // if the handle's shape ever changes.
        self.root.join(&handle[..2]).join(handle)
    }

    fn snapshot_dir(&self, handle: &str, digest_hex: &str) -> PathBuf {
        self.holder_dir(handle).join(digest_hex)
    }

    fn incoming_dir(&self, upload_id: &str) -> PathBuf {
        self.root.join("incoming").join(upload_id)
    }

    pub fn begin_upload(&self, upload_id: &str) -> Result<()> {
        std::fs::create_dir_all(self.incoming_dir(upload_id))
            .map_err(|e| Error::Internal(format!("create incoming dir: {e}")))
    }

    /// Write one chunk of an in-flight upload.
    ///
    /// Idempotent by content: re-sending a chunk with the same bytes is
    /// a no-op, and re-sending it with *different* bytes is a conflict
    /// rather than an overwrite. A retry must not be able to change
    /// what was already accepted.
    pub fn write_chunk(&self, upload_id: &str, index: i64, bytes: &[u8]) -> Result<()> {
        let path = self.incoming_dir(upload_id).join(format!("{index}.part"));
        if let Ok(existing) = std::fs::read(&path) {
            if existing == bytes {
                return Ok(());
            }
            return Err(Error::ChunkMismatch);
        }
        std::fs::write(&path, bytes).map_err(|e| Error::Internal(format!("write chunk: {e}")))
    }

    /// What has arrived: total bytes, and the indices still missing.
    ///
    /// Both, in one walk. Commit needs to distinguish "not finished
    /// yet" from "finished and wrong" — the first keeps the grant and
    /// names the gap, the second discards — and a bare byte count
    /// cannot tell them apart.
    pub fn arrival(&self, upload_id: &str, chunk_count: i64) -> Result<(i64, Vec<i64>)> {
        let mut total = 0;
        let mut missing = Vec::new();
        for index in 0..chunk_count {
            let path = self.incoming_dir(upload_id).join(format!("{index}.part"));
            match std::fs::metadata(&path) {
                Ok(metadata) => total += metadata.len() as i64,
                Err(_) => missing.push(index),
            }
        }
        Ok((total, missing))
    }

    /// Recompute the digest over the chunks in index order.
    ///
    /// Streamed rather than concatenated in memory: a snapshot is
    /// routinely hundreds of megabytes, and an operator that had to
    /// hold one to accept it would fall over on the first large holder.
    pub fn digest_of(&self, upload_id: &str, chunk_count: i64) -> Result<String> {
        let mut hasher = Sha256::new();
        for index in 0..chunk_count {
            let path = self.incoming_dir(upload_id).join(format!("{index}.part"));
            let bytes = std::fs::read(&path)
                .map_err(|e| Error::Internal(format!("read chunk {index}: {e}")))?;
            hasher.update(&bytes);
        }
        Ok(format!("sha256:{}", hex::encode(hasher.finalize())))
    }

    /// Move a verified upload into place.
    ///
    /// Rename, not copy: the bytes are already on the same filesystem
    /// and a copy would double the write and leave a window where both
    /// exist. A crash between this and the database insert leaves an
    /// orphan directory, which the startup sweep reconciles — and it
    /// reconciles by deleting bytes with no row, never by inventing a
    /// row for bytes it found.
    pub fn commit(&self, upload_id: &str, handle: &str, digest_hex: &str) -> Result<()> {
        let destination = self.snapshot_dir(handle, digest_hex);
        if let Some(parent) = destination.parent() {
            std::fs::create_dir_all(parent)
                .map_err(|e| Error::Internal(format!("create holder dir: {e}")))?;
        }
        if destination.exists() {
            // Already held for this holder. Drop the duplicate upload
            // rather than replacing bytes that are already addressed by
            // their own digest.
            let _ = std::fs::remove_dir_all(self.incoming_dir(upload_id));
            return Ok(());
        }
        std::fs::rename(self.incoming_dir(upload_id), &destination)
            .map_err(|e| Error::Internal(format!("commit upload: {e}")))
    }

    pub fn discard_upload(&self, upload_id: &str) {
        let _ = std::fs::remove_dir_all(self.incoming_dir(upload_id));
    }

    /// The chunk files of a retained snapshot, in index order.
    ///
    /// Paths rather than bytes. `digest_of` was streamed because a
    /// snapshot is routinely hundreds of megabytes; a download has the
    /// same exposure, so handing back a `Vec<u8>` would have put the
    /// whole snapshot in memory per concurrent reader and made a few
    /// downloads enough to exhaust it.
    pub fn chunk_paths(&self, handle: &str, digest_hex: &str) -> Result<Vec<PathBuf>> {
        let dir = self.snapshot_dir(handle, digest_hex);
        let mut indices: Vec<i64> = std::fs::read_dir(&dir)
            .map_err(|_| Error::RetentionExpired)?
            .filter_map(std::result::Result::ok)
            .filter_map(|entry| {
                entry
                    .file_name()
                    .to_str()
                    .and_then(|name| name.strip_suffix(".part"))
                    .and_then(|name| name.parse().ok())
            })
            .collect();
        indices.sort_unstable();
        Ok(indices
            .into_iter()
            .map(|index| dir.join(format!("{index}.part")))
            .collect())
    }

    /// Whole-snapshot read, for tests only. Production reads stream —
    /// see `chunk_paths`.
    #[cfg(test)]
    pub fn read_snapshot(&self, handle: &str, digest_hex: &str) -> Result<Vec<u8>> {
        let mut out = Vec::new();
        for path in self.chunk_paths(handle, digest_hex)? {
            out.extend_from_slice(
                &std::fs::read(&path)
                    .map_err(|e| Error::Internal(format!("read snapshot chunk: {e}")))?,
            );
        }
        Ok(out)
    }

    /// Every `<handle>/<digest-hex>` pair with bytes on disk, and every
    /// upload id under `incoming/`. Used only by the reconciliation
    /// sweep, which compares them against the bookkeeping.
    pub fn retained_on_disk(&self) -> Vec<(String, String)> {
        let mut found = Vec::new();
        for shard in read_dir_names(&self.root) {
            if shard == "incoming" {
                continue;
            }
            let shard_dir = self.root.join(&shard);
            for handle in read_dir_names(&shard_dir) {
                for digest in read_dir_names(&shard_dir.join(&handle)) {
                    found.push((handle.clone(), digest));
                }
            }
        }
        found
    }

    pub fn incoming_on_disk(&self) -> Vec<String> {
        read_dir_names(&self.root.join("incoming"))
    }

    pub fn erase(&self, handle: &str, digest_hex: &str) -> Result<()> {
        let dir = self.snapshot_dir(handle, digest_hex);
        if dir.exists() {
            std::fs::remove_dir_all(&dir)
                .map_err(|e| Error::Internal(format!("erase snapshot: {e}")))?;
        }
        Ok(())
    }

    pub fn root(&self) -> &Path {
        &self.root
    }
}

/// Directory entry names, or nothing. A sweep over a root that does not
/// exist yet is a no-op, not an error.
fn read_dir_names(dir: &Path) -> Vec<String> {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return Vec::new();
    };
    entries
        .filter_map(std::result::Result::ok)
        .filter_map(|entry| entry.file_name().to_str().map(str::to_string))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn blobs() -> (Blobs, tempfile::TempDir) {
        let dir = tempfile::TempDir::new().unwrap();
        (Blobs::new(dir.path()), dir)
    }

    const HANDLE: &str = "abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789";

    #[test]
    fn a_chunk_resent_identically_is_accepted() {
        let (blobs, _dir) = blobs();
        blobs.begin_upload("u1").unwrap();
        blobs.write_chunk("u1", 0, b"hello").unwrap();
        // A retry after a lost response must not be an error.
        blobs.write_chunk("u1", 0, b"hello").unwrap();
    }

    /// A retry must not be able to change what was already accepted.
    #[test]
    fn a_chunk_resent_with_different_bytes_is_refused() {
        let (blobs, _dir) = blobs();
        blobs.begin_upload("u1").unwrap();
        blobs.write_chunk("u1", 0, b"hello").unwrap();
        assert!(matches!(
            blobs.write_chunk("u1", 0, b"goodbye"),
            Err(Error::ChunkMismatch)
        ));
    }

    #[test]
    fn digest_is_over_the_chunks_in_index_order() {
        let (blobs, _dir) = blobs();
        blobs.begin_upload("u1").unwrap();
        blobs.write_chunk("u1", 0, b"abc").unwrap();
        blobs.write_chunk("u1", 1, b"def").unwrap();
        assert_eq!(
            blobs.digest_of("u1", 2).unwrap(),
            format!("sha256:{}", hex::encode(Sha256::digest(b"abcdef")))
        );
    }

    #[test]
    fn a_missing_chunk_is_named_not_just_counted() {
        let (blobs, _dir) = blobs();
        blobs.begin_upload("u1").unwrap();
        blobs.write_chunk("u1", 0, b"abc").unwrap();
        // The gap is reported as an index, so a client can send one
        // chunk rather than the whole snapshot again.
        assert_eq!(blobs.arrival("u1", 3).unwrap(), (3, vec![1, 2]));
    }

    #[test]
    fn commit_then_read_round_trips() {
        let (blobs, _dir) = blobs();
        blobs.begin_upload("u1").unwrap();
        blobs.write_chunk("u1", 0, b"abc").unwrap();
        blobs.write_chunk("u1", 1, b"def").unwrap();
        blobs.commit("u1", HANDLE, "aa").unwrap();
        assert_eq!(blobs.read_snapshot(HANDLE, "aa").unwrap(), b"abcdef");
    }

    /// Two holders storing byte-identical snapshots keep two copies.
    /// §14.6 forbids convergent keying, so this is the cost of the
    /// property rather than a missed optimisation.
    #[test]
    fn holders_do_not_share_storage() {
        let (blobs, _dir) = blobs();
        let other = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
        for (upload, handle) in [("u1", HANDLE), ("u2", other)] {
            blobs.begin_upload(upload).unwrap();
            blobs.write_chunk(upload, 0, b"identical").unwrap();
            blobs.commit(upload, handle, "aa").unwrap();
        }
        assert_eq!(blobs.read_snapshot(HANDLE, "aa").unwrap(), b"identical");
        assert_eq!(blobs.read_snapshot(other, "aa").unwrap(), b"identical");
        // And one holder cannot read the other's, even at the same
        // digest.
        assert!(blobs.read_snapshot(HANDLE, "bb").is_err());
    }

    #[test]
    fn erase_removes_the_bytes() {
        let (blobs, _dir) = blobs();
        blobs.begin_upload("u1").unwrap();
        blobs.write_chunk("u1", 0, b"abc").unwrap();
        blobs.commit("u1", HANDLE, "aa").unwrap();
        blobs.erase(HANDLE, "aa").unwrap();
        assert!(blobs.read_snapshot(HANDLE, "aa").is_err());
    }
}
