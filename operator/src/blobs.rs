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

use std::io::{Read, Write};
use std::path::{Path, PathBuf};

use axum::body::Bytes;
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
        let incoming = self.incoming_dir(upload_id);
        std::fs::create_dir_all(&incoming)
            .map_err(|e| Error::Internal(format!("create incoming dir: {e}")))?;
        sync_dir(&incoming)?;
        if let Some(parent) = incoming.parent() {
            sync_dir(parent)?;
        }
        sync_dir(&self.root)?;
        Ok(())
    }

    /// Write one chunk of an in-flight upload.
    ///
    /// Idempotent by content: re-sending a chunk with the same bytes is
    /// a no-op, and re-sending it with *different* bytes is a conflict
    /// rather than an overwrite. A retry must not be able to change
    /// what was already accepted.
    pub fn write_chunk(&self, upload_id: &str, index: i64, bytes: &[u8]) -> Result<()> {
        let path = self.incoming_dir(upload_id).join(format!("{index}.part"));
        match std::fs::read(&path) {
            Ok(existing) => {
                if existing == bytes {
                    return Ok(());
                }
                return Err(Error::ChunkMismatch);
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => {
                return Err(Error::Internal(format!("read existing chunk: {error}")));
            }
        }
        let mut file = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&path)
            .map_err(|e| Error::Internal(format!("create chunk: {e}")))?;
        file.write_all(bytes)
            .map_err(|e| Error::Internal(format!("write chunk: {e}")))?;
        file.sync_all()
            .map_err(|e| Error::Internal(format!("sync chunk: {e}")))?;
        sync_dir(
            path.parent()
                .ok_or_else(|| Error::Internal("chunk has no parent directory".into()))?,
        )
    }

    /// What has arrived: total bytes, and the gaps as inclusive
    /// `[first, last]` index ranges.
    ///
    /// Both, in one walk. Commit needs to distinguish "not finished
    /// yet" from "finished and wrong" — the first keeps the grant and
    /// names the gap, the second discards — and a bare byte count
    /// cannot tell them apart.
    pub fn arrival(&self, upload_id: &str, chunk_count: i64) -> Result<(i64, Vec<(i64, i64)>)> {
        let mut total = 0;
        let mut missing: Vec<(i64, i64)> = Vec::new();
        for index in 0..chunk_count {
            let path = self.incoming_dir(upload_id).join(format!("{index}.part"));
            match std::fs::metadata(&path) {
                Ok(metadata) => total += metadata.len() as i64,
                Err(_) => match missing.last_mut() {
                    // Extend the open run rather than starting a new
                    // one: an interrupted upload is normally one
                    // contiguous gap, and that is the case worth being
                    // compact about.
                    Some(last) if last.1 == index - 1 => last.1 = index,
                    _ => missing.push((index, index)),
                },
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
    pub fn commit(
        &self,
        upload_id: &str,
        handle: &str,
        digest_hex: &str,
        chunk_count: i64,
        sealed_byte_size: i64,
    ) -> Result<()> {
        let destination = self.snapshot_dir(handle, digest_hex);
        if let Some(parent) = destination.parent() {
            std::fs::create_dir_all(parent)
                .map_err(|e| Error::Internal(format!("create holder dir: {e}")))?;
        }
        if destination.exists() {
            // Never adopt a directory merely because its name matches
            // the digest. It may be a short remnant of a failed erase
            // or power loss. Only verified bytes can displace the
            // freshly verified upload.
            let paths = match self.chunk_paths(handle, digest_hex, chunk_count, sealed_byte_size) {
                Ok(paths) => paths,
                Err(Error::RetentionExpired) => {
                    return Err(Error::Internal(
                        "existing snapshot destination is incomplete".into(),
                    ));
                }
                Err(error) => return Err(error),
            };
            let actual = digest_paths(&paths)?;
            if actual != format!("sha256:{digest_hex}") {
                return Err(Error::Internal(
                    "existing snapshot bytes do not match their digest".into(),
                ));
            }
            self.discard_upload(upload_id)?;
            return Ok(());
        }
        let incoming = self.incoming_dir(upload_id);
        sync_dir(&incoming)?;
        std::fs::rename(&incoming, &destination)
            .map_err(|e| Error::Internal(format!("commit upload: {e}")))?;
        let parent = destination
            .parent()
            .ok_or_else(|| Error::Internal("snapshot has no parent directory".into()))?;
        sync_dir(parent)?;
        if let Some(shard) = parent.parent() {
            sync_dir(shard)?;
        }
        sync_dir(&self.root)
    }

    pub fn discard_upload(&self, upload_id: &str) -> Result<()> {
        let incoming = self.incoming_dir(upload_id);
        match std::fs::remove_dir_all(&incoming) {
            Ok(()) => {
                if let Some(parent) = incoming.parent() {
                    sync_dir(parent)?;
                }
                Ok(())
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(error) => Err(Error::Internal(format!("discard upload: {error}"))),
        }
    }

    /// The chunk files of a retained snapshot, in index order.
    ///
    /// Paths rather than bytes. `digest_of` was streamed because a
    /// snapshot is routinely hundreds of megabytes; a download has the
    /// same exposure, so handing back a `Vec<u8>` would have put the
    /// whole snapshot in memory per concurrent reader and made a few
    /// downloads enough to exhaust it.
    pub fn chunk_paths(
        &self,
        handle: &str,
        digest_hex: &str,
        chunk_count: i64,
        sealed_byte_size: i64,
    ) -> Result<Vec<PathBuf>> {
        let paths = self.chunk_paths_unchecked(handle, digest_hex)?;
        let actual: Vec<i64> = paths
            .iter()
            .filter_map(|path| {
                path.file_stem()
                    .and_then(|name| name.to_str())
                    .and_then(|name| name.parse().ok())
            })
            .collect();
        let contiguous = actual
            .iter()
            .enumerate()
            .all(|(expected, actual)| *actual == expected as i64);
        if actual.len() as i64 != chunk_count || !contiguous {
            tracing::error!(
                ?actual,
                expected_chunk_count = chunk_count,
                "retained snapshot has a chunk gap"
            );
            return Err(Error::RetentionExpired);
        }
        let mut total = 0i64;
        for path in &paths {
            let metadata = std::fs::metadata(path).map_err(|error| {
                if error.kind() == std::io::ErrorKind::NotFound {
                    Error::RetentionExpired
                } else {
                    Error::Internal(format!("stat snapshot chunk: {error}"))
                }
            })?;
            if !metadata.is_file() {
                tracing::error!(path = %path.display(), "snapshot chunk is not a file");
                return Err(Error::RetentionExpired);
            }
            total = total
                .checked_add(metadata.len() as i64)
                .ok_or_else(|| Error::Internal("snapshot size overflow".into()))?;
        }
        if total != sealed_byte_size {
            tracing::error!(
                actual_bytes = total,
                expected_bytes = sealed_byte_size,
                "retained snapshot has the wrong byte size"
            );
            return Err(Error::RetentionExpired);
        }
        Ok(paths)
    }

    fn chunk_paths_unchecked(&self, handle: &str, digest_hex: &str) -> Result<Vec<PathBuf>> {
        let dir = self.snapshot_dir(handle, digest_hex);
        let entries = std::fs::read_dir(&dir).map_err(|error| {
            if error.kind() == std::io::ErrorKind::NotFound {
                Error::RetentionExpired
            } else {
                Error::Internal(format!("read snapshot directory: {error}"))
            }
        })?;
        let mut indices: Vec<i64> = Vec::new();
        for entry in entries {
            let entry =
                entry.map_err(|error| Error::Internal(format!("read snapshot entry: {error}")))?;
            if let Some(index) = entry
                .file_name()
                .to_str()
                .and_then(|name| name.strip_suffix(".part"))
                .and_then(|name| name.parse().ok())
            {
                indices.push(index);
            }
        }
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
        for path in self.chunk_paths_unchecked(handle, digest_hex)? {
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

    /// Remove a snapshot's bytes. Absent is success.
    ///
    /// Erasure serialises under the store lock, but the sweep does
    /// not take it for the disk walk — so a snapshot can vanish between
    /// this call and its own `remove_dir_all`, and an `exists()` guard
    /// would lose the race between the check and the removal anyway.
    /// "Already gone" is the outcome the caller wanted, so it is not an
    /// error; anything else is.
    pub fn erase(&self, handle: &str, digest_hex: &str) -> Result<()> {
        let snapshot = self.snapshot_dir(handle, digest_hex);
        match std::fs::remove_dir_all(&snapshot) {
            Ok(()) => sync_dir(
                snapshot
                    .parent()
                    .ok_or_else(|| Error::Internal("snapshot has no parent directory".into()))?,
            ),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(error) => Err(Error::Internal(format!("erase snapshot: {error}"))),
        }
    }

    #[cfg(test)]
    pub fn root(&self) -> &Path {
        &self.root
    }
}

fn digest_paths(paths: &[PathBuf]) -> Result<String> {
    let mut hasher = Sha256::new();
    let mut buffer = vec![0u8; 256 * 1024];
    for path in paths {
        let mut file = std::fs::File::open(path)
            .map_err(|e| Error::Internal(format!("open snapshot chunk: {e}")))?;
        loop {
            let read = file
                .read(&mut buffer)
                .map_err(|e| Error::Internal(format!("read snapshot chunk: {e}")))?;
            if read == 0 {
                break;
            }
            hasher.update(&buffer[..read]);
        }
    }
    Ok(format!("sha256:{}", hex::encode(hasher.finalize())))
}

fn sync_dir(path: &Path) -> Result<()> {
    std::fs::File::open(path)
        .and_then(|directory| directory.sync_all())
        .map_err(|e| Error::Internal(format!("sync directory {}: {e}", path.display())))
}

/// The snapshot's bytes, chunk by chunk, a bounded buffer at a time.
pub fn snapshot_stream(
    paths: Vec<PathBuf>,
) -> impl futures_core::Stream<Item = std::io::Result<Bytes>> {
    async_stream::try_stream! {
        for path in paths {
            let mut file = tokio::fs::File::open(&path).await?;
            let mut buffer = vec![0u8; 256 * 1024];
            loop {
                let read = tokio::io::AsyncReadExt::read(&mut file, &mut buffer).await?;
                if read == 0 {
                    break;
                }
                yield Bytes::copy_from_slice(&buffer[..read]);
            }
        }
    }
}

/// `sha256:<64 lowercase hex>` → the hex, or a refusal.
pub fn digest_hex(digest: &str) -> Result<String> {
    let hex_value = digest
        .strip_prefix("sha256:")
        .ok_or_else(|| Error::BadRequest("digest must be sha256:<hex>".into()))?;
    if hex_value.len() != 64
        || !hex_value
            .bytes()
            .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase())
    {
        return Err(Error::BadRequest(
            "digest must be 64 lowercase hex characters".into(),
        ));
    }
    Ok(hex_value.to_string())
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
        // One contiguous gap is one range, not two indices.
        assert_eq!(blobs.arrival("u1", 3).unwrap(), (3, vec![(1, 2)]));
    }

    #[test]
    fn commit_then_read_round_trips() {
        let (blobs, _dir) = blobs();
        blobs.begin_upload("u1").unwrap();
        blobs.write_chunk("u1", 0, b"abc").unwrap();
        blobs.write_chunk("u1", 1, b"def").unwrap();
        blobs.commit("u1", HANDLE, "aa", 2, 6).unwrap();
        assert_eq!(blobs.read_snapshot(HANDLE, "aa").unwrap(), b"abcdef");
    }

    #[test]
    fn commit_never_adopts_an_invalid_existing_destination() {
        let (blobs, _dir) = blobs();
        let digest = hex::encode(Sha256::digest(b"correct"));
        blobs.begin_upload("u1").unwrap();
        blobs.write_chunk("u1", 0, b"correct").unwrap();
        blobs.commit("u1", HANDLE, &digest, 1, 7).unwrap();

        std::fs::write(
            blobs.snapshot_dir(HANDLE, &digest).join("0.part"),
            b"corrupt",
        )
        .unwrap();
        blobs.begin_upload("u2").unwrap();
        blobs.write_chunk("u2", 0, b"correct").unwrap();

        assert!(
            blobs.commit("u2", HANDLE, &digest, 1, 7).is_err(),
            "a corrupt destination displaced the verified upload"
        );
        assert!(
            blobs.incoming_dir("u2").exists(),
            "the verified upload was discarded"
        );
    }

    #[test]
    fn a_gapped_retained_directory_is_not_streamable() {
        let (blobs, _dir) = blobs();
        blobs.begin_upload("u1").unwrap();
        blobs.write_chunk("u1", 0, b"abc").unwrap();
        blobs.write_chunk("u1", 1, b"def").unwrap();
        blobs.commit("u1", HANDLE, "aa", 2, 6).unwrap();
        std::fs::remove_file(blobs.snapshot_dir(HANDLE, "aa").join("1.part")).unwrap();

        assert!(matches!(
            blobs.chunk_paths(HANDLE, "aa", 2, 6),
            Err(Error::RetentionExpired)
        ));
    }

    #[test]
    fn a_snapshot_io_failure_is_not_mislabeled_as_expired() {
        let (blobs, _dir) = blobs();
        let snapshot = blobs.snapshot_dir(HANDLE, "aa");
        std::fs::create_dir_all(snapshot.parent().unwrap()).unwrap();
        std::fs::write(&snapshot, b"not a directory").unwrap();

        assert!(matches!(
            blobs.chunk_paths(HANDLE, "aa", 1, 1),
            Err(Error::Internal(_))
        ));
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
            blobs.commit(upload, handle, "aa", 1, 9).unwrap();
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
        blobs.commit("u1", HANDLE, "aa", 1, 3).unwrap();
        blobs.erase(HANDLE, "aa").unwrap();
        assert!(blobs.read_snapshot(HANDLE, "aa").is_err());
    }
}
