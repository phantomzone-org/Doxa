use std::{
	fs::{self, File, OpenOptions},
	io::{Read, Seek, SeekFrom, Write},
	path::{Path, PathBuf},
};

use anyhow::{Context, Result};
use crc32fast::Hasher as Crc32Hasher;
use serde::{Deserialize, Serialize};

const SNAPSHOT_VERSION_V1: u32 = 1;
const SNAPSHOT_VERSION_V2: u32 = 2;
const CURRENT_SNAPSHOT_VERSION: u32 = SNAPSHOT_VERSION_V2;

/// Tree identifiers used for persistence isolation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TreeId {
	NotesCommitment,
	NotesNullifier,
	AccountsCommitment,
	AccountsNullifier,
}

impl TreeId {
	fn dir_name(&self) -> &'static str {
		match self {
			TreeId::NotesCommitment => "notes_commitment",
			TreeId::NotesNullifier => "notes_nullifier",
			TreeId::AccountsCommitment => "accounts_commitment",
			TreeId::AccountsNullifier => "accounts_nullifier",
		}
	}
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct Snapshot<T> {
	version: u32,
	/// Byte offset into WAL after the last applied record.
	wal_pos: u64,
	/// Committed batches applied to `state`.
	committed_batches: u64,
	/// Last on-chain block that has been reconciled into this local state.
	#[serde(default)]
	last_block: u64,
	/// Last on-chain transaction index reconciled into this local state.
	#[serde(default)]
	last_tx_index: u64,
	/// Last on-chain log index reconciled into this local state.
	#[serde(default)]
	last_log_index: u64,
	state: T,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct WalRecord {
	/// Inserted values in the exact order used to derive the root.
	values: Vec<[u8; 32]>,
	/// CRC32 of the `values` bytes (each entry as 32 raw bytes, in order).
	/// Guards against silent on-disk corruption during WAL replay.
	/// NOTE: adding this field makes WAL records incompatible with pre-checksum files;
	/// delete the tree store directory when upgrading from an older version.
	checksum: u32,
}

impl WalRecord {
	fn new(values: Vec<[u8; 32]>) -> Self {
		let checksum = Self::crc32(&values);
		Self {
			values,
			checksum,
		}
	}

	fn verify(&self) -> bool {
		Self::crc32(&self.values) == self.checksum
	}

	fn crc32(values: &[[u8; 32]]) -> u32 {
		let mut h = Crc32Hasher::new();
		for v in values {
			h.update(v.as_slice());
		}
		h.finalize()
	}
}

pub struct TreeStore<T> {
	tree_id: TreeId,
	dir: PathBuf,
	wal_path: PathBuf,
	snapshot_path: PathBuf,
	wal: File,
	/// In-memory WAL end position; updated after every successful write.
	/// Avoids TOCTOU from repeated `metadata().len()` syscalls.
	wal_end: u64,
	pub snapshot_every_batches: u64,
	_phantom: std::marker::PhantomData<T>,
}

impl<T> TreeStore<T>
where
	T: Serialize + for<'de> Deserialize<'de> + Clone,
{
	/// Opens or creates the on-disk storage for one logical tree.
	///
	/// Why needed:
	/// - Separates persistence per tree to avoid cross-tree corruption.
	/// - Keeps WAL append-only and snapshots isolated for crash recovery.
	pub fn open(base_dir: &Path, tree_id: TreeId, snapshot_every_batches: u64) -> Result<Self> {
		let dir = base_dir.join(tree_id.dir_name());
		fs::create_dir_all(&dir).with_context(|| format!("create tree dir: {}", dir.display()))?;

		let wal_path = dir.join("wal.bin");
		let snapshot_path = dir.join("snapshot.bin");

		let wal = OpenOptions::new()
			.create(true)
			.read(true)
			.append(true)
			.open(&wal_path)
			.with_context(|| format!("open wal: {}", wal_path.display()))?;
		// Read current WAL size once at open; all subsequent accesses use the in-memory counter.
		let wal_end = wal
			.metadata()
			.with_context(|| format!("stat wal: {}", wal_path.display()))?
			.len();

		Ok(Self {
			tree_id,
			dir,
			wal_path,
			snapshot_path,
			wal,
			wal_end,
			snapshot_every_batches: snapshot_every_batches.max(1),
			_phantom: std::marker::PhantomData,
		})
	}

	pub fn exists(&self) -> bool {
		self.snapshot_path.is_file() || self.wal_path.is_file()
	}

	pub fn load_or_init<F>(&mut self, init: F) -> Result<(T, StoreMeta)>
	where
		F: FnOnce() -> T,
	{
		let (state, meta) = match self.read_snapshot()? {
			Some((snap, meta)) => (snap.state, meta),
			None => {
				let state = init();
				(
					state,
					StoreMeta {
						wal_pos: 0,
						committed_batches: 0,
						snapshot_version: CURRENT_SNAPSHOT_VERSION,
						last_block: 0,
						last_tx_index: 0,
						last_log_index: 0,
					},
				)
			},
		};

		Ok((state, meta))
	}

	pub fn replay_wal_since_snapshot<A>(
		&mut self,
		state: &mut T,
		meta: &StoreMeta,
		mut apply: A,
	) -> Result<(u64, u64)>
	where
		A: FnMut(&mut T, Vec<[u8; 32]>) -> Result<()>,
	{
		// Replays only records that are newer than the snapshot's wal_pos.
		// This makes restart idempotent even after partial writes.
		let wal_end = self.wal_end;
		if meta.wal_pos > wal_end {
			return Err(anyhow::anyhow!(
				"WAL position beyond end (tree={:?}, wal_pos={}, wal_len={})",
				self.tree_id,
				meta.wal_pos,
				wal_end
			));
		}

		self.wal.seek(SeekFrom::Start(meta.wal_pos))?;
		let mut pos = meta.wal_pos;
		let mut replayed: u64 = 0;
		while pos < wal_end {
			let (rec, next_pos) = read_len_prefixed::<WalRecord>(&mut self.wal, pos)
				.with_context(|| format!("replay wal record at pos={pos}"))?;
			anyhow::ensure!(
				rec.verify(),
				"WAL record checksum mismatch at pos={pos} (tree={:?}); the file may be corrupt",
				self.tree_id
			);
			pos = next_pos;
			apply(state, rec.values)?;
			replayed = replayed.saturating_add(1);
		}
		Ok((pos, replayed))
	}

	pub fn append_wal(&mut self, values: Vec<[u8; 32]>) -> Result<u64> {
		let rec = WalRecord::new(values);
		let pos_before = self.wal_end;
		let bytes = bincode::serialize(&rec)?;
		let record_len = u32::try_from(bytes.len())
			.map_err(|_| anyhow::anyhow!("wal record too large: {} bytes", bytes.len()))?;
		self.wal.write_all(&record_len.to_le_bytes())?;
		self.wal.write_all(&bytes)?;
		self.wal.flush()?;
		self.wal.sync_data()?;
		// Advance in-memory counter atomically after a successful flush.
		self.wal_end = pos_before + 4 + bytes.len() as u64;
		Ok(pos_before)
	}

	pub fn wal_len(&self) -> u64 {
		self.wal_end
	}

	pub fn commit_batch(
		&mut self,
		state: &T,
		meta: &mut StoreMeta,
		values: Vec<[u8; 32]>,
	) -> Result<()> {
		// WAL is written first, then metadata advanced, then optional snapshot.
		// This ordering guarantees replay can recover committed batches after crashes.
		self.append_wal(values)?;
		meta.wal_pos = self.wal_end;
		meta.committed_batches = meta.committed_batches.saturating_add(1);
		self.maybe_checkpoint(state, meta)?;
		Ok(())
	}

	pub fn maybe_checkpoint(&self, state: &T, meta: &StoreMeta) -> Result<()> {
		if !meta
			.committed_batches
			.is_multiple_of(self.snapshot_every_batches)
		{
			return Ok(());
		}
		self.write_snapshot(state, meta)
	}

	pub fn force_checkpoint(&self, state: &T, meta: &StoreMeta) -> Result<()> {
		self.write_snapshot(state, meta)
	}

	pub fn truncate(&mut self) -> Result<()> {
		self.wal.flush().ok();
		// Truncate the existing append-mode handle to zero; no need to reopen.
		self.wal
			.set_len(0)
			.with_context(|| format!("truncate wal: {}", self.wal_path.display()))?;
		self.wal_end = 0;
		if self.snapshot_path.is_file() {
			let _ = fs::remove_file(&self.snapshot_path);
		}
		Ok(())
	}

	fn read_snapshot(&self) -> Result<Option<(Snapshot<T>, StoreMeta)>> {
		if !self.snapshot_path.is_file() {
			return Ok(None);
		}
		let mut f = File::open(&self.snapshot_path)
			.with_context(|| format!("open snapshot: {}", self.snapshot_path.display()))?;
		let mut buf = Vec::new();
		f.read_to_end(&mut buf)?;
		let snap: Snapshot<T> = bincode::deserialize(&buf)
			.with_context(|| format!("decode snapshot: {}", self.snapshot_path.display()))?;
		if snap.version != SNAPSHOT_VERSION_V1 && snap.version != SNAPSHOT_VERSION_V2 {
			return Err(anyhow::anyhow!(
				"unsupported snapshot version {} (tree={:?})",
				snap.version,
				self.tree_id
			));
		}
		let meta = StoreMeta {
			wal_pos: snap.wal_pos,
			committed_batches: snap.committed_batches,
			snapshot_version: snap.version,
			last_block: snap.last_block,
			last_tx_index: snap.last_tx_index,
			last_log_index: snap.last_log_index,
		};
		Ok(Some((snap, meta)))
	}

	fn write_snapshot(&self, state: &T, meta: &StoreMeta) -> Result<()> {
		let snap = Snapshot {
			version: CURRENT_SNAPSHOT_VERSION,
			wal_pos: meta.wal_pos,
			committed_batches: meta.committed_batches,
			last_block: meta.last_block,
			last_tx_index: meta.last_tx_index,
			last_log_index: meta.last_log_index,
			state: state.clone(),
		};
		let bytes = bincode::serialize(&snap)?;

		atomic_write(&self.dir, &self.snapshot_path, &bytes)
			.with_context(|| format!("write snapshot: {}", self.snapshot_path.display()))?;
		Ok(())
	}
}

#[derive(Debug, Clone)]
pub struct StoreMeta {
	/// End WAL position after applied replay.
	pub wal_pos: u64,
	pub committed_batches: u64,
	/// Snapshot schema version loaded from disk.
	/// `0` is never valid and is reserved as "unknown/uninitialized".
	pub snapshot_version: u32,
	/// Last on-chain block that has been reconciled into this local state.
	pub last_block: u64,
	/// Last on-chain transaction index reconciled into this local state.
	pub last_tx_index: u64,
	/// Last on-chain log index reconciled into this local state.
	pub last_log_index: u64,
}

fn read_len_prefixed<T: for<'de> Deserialize<'de>>(f: &mut File, pos: u64) -> Result<(T, u64)> {
	let mut len_buf = [0u8; 4];
	f.read_exact(&mut len_buf)?;
	let len = u32::from_le_bytes(len_buf) as usize;
	let mut buf = vec![0u8; len];
	f.read_exact(&mut buf)?;
	let v: T = bincode::deserialize(&buf)?;
	let next = pos + 4 + len as u64;
	Ok((v, next))
}

fn atomic_write(dir: &Path, dst: &Path, contents: &[u8]) -> Result<()> {
	let tmp = dst.with_extension("tmp");
	{
		let mut f = File::create(&tmp)?;
		f.write_all(contents)?;
		f.flush()?;
		f.sync_data()?;
	}
	fs::rename(&tmp, dst)?;
	// Best-effort directory fsync for durability.
	if let Ok(d) = File::open(dir) {
		let _ = d.sync_all();
	}
	Ok(())
}

#[cfg(test)]
mod tests {
	use rand::{rngs::StdRng, SeedableRng};
	use tessera_trees::tree::{
		hasher::{HashOutput, NewRandom},
		CommitmentTree,
	};

	use super::*;

	fn unique_test_dir(name: &str) -> PathBuf {
		let pid = std::process::id();
		let nanos = std::time::SystemTime::now()
			.duration_since(std::time::UNIX_EPOCH)
			.expect("system clock before unix epoch")
			.as_nanos();
		std::env::temp_dir().join(format!("tessera_tree_store_{name}_{pid}_{nanos}"))
	}

	#[test]
	fn load_legacy_v1_snapshot_and_upgrade_to_v2() -> Result<()> {
		let base = unique_test_dir("upgrade_v1");
		fs::create_dir_all(base.join("notes_commitment"))?;

		let mut state = CommitmentTree::<HashOutput>::new(4);
		// Build a non-empty tree and persist it as legacy snapshot format.
		let mut rng = StdRng::from_seed([3u8; 32]);
		let leaf = HashOutput::new_random(&mut rng);
		let _ = state.insert_batch(vec![leaf, leaf])?;

		let legacy_snapshot = Snapshot {
			version: SNAPSHOT_VERSION_V1,
			wal_pos: 0,
			committed_batches: 0,
			last_block: 0,
			last_tx_index: 0,
			last_log_index: 0,
			state: state.clone(),
		};
		let legacy_bytes = bincode::serialize(&legacy_snapshot)?;
		fs::write(
			base.join("notes_commitment").join("snapshot.bin"),
			legacy_bytes,
		)?;

		let mut store = TreeStore::<CommitmentTree<HashOutput>>::open(&base, TreeId::NotesCommitment, 1)?;
		let (loaded_state, meta) = store.load_or_init(|| CommitmentTree::new(4))?;
		assert_eq!(meta.snapshot_version, SNAPSHOT_VERSION_V1);
		assert_eq!(loaded_state.num_leaves(), 2);

		store.force_checkpoint(&loaded_state, &meta)?;
		let snap_bytes = fs::read(base.join("notes_commitment").join("snapshot.bin"))?;
		let snap: Snapshot<CommitmentTree<HashOutput>> = bincode::deserialize(&snap_bytes)?;
		assert_eq!(snap.version, CURRENT_SNAPSHOT_VERSION);
		assert_eq!(meta.snapshot_version, SNAPSHOT_VERSION_V1);

		let _ = fs::remove_dir_all(&base);
		Ok(())
	}

	#[test]
	fn fresh_snapshot_written_as_current_version() -> Result<()> {
		let base = unique_test_dir("fresh_v2");
		let mut store =
			TreeStore::<CommitmentTree<HashOutput>>::open(&base, TreeId::AccountsCommitment, 1)?;
		let (state, meta) = store.load_or_init(|| CommitmentTree::new(4))?;
		assert_eq!(meta.snapshot_version, CURRENT_SNAPSHOT_VERSION);

		store.force_checkpoint(&state, &meta)?;
		let snap_bytes = fs::read(base.join("accounts_commitment").join("snapshot.bin"))?;
		let snap: Snapshot<CommitmentTree<HashOutput>> = bincode::deserialize(&snap_bytes)?;
		assert_eq!(snap.version, CURRENT_SNAPSHOT_VERSION);

		let _ = fs::remove_dir_all(&base);
		Ok(())
	}
}
