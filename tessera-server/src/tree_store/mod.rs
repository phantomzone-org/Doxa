use std::{
	fs::{self, File, OpenOptions},
	io::{Read, Seek, SeekFrom, Write},
	path::{Path, PathBuf},
};

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};

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
}

pub struct TreeStore<T> {
	tree_id: TreeId,
	dir: PathBuf,
	wal_path: PathBuf,
	snapshot_path: PathBuf,
	wal: File,
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

		Ok(Self {
			tree_id,
			dir,
			wal_path,
			snapshot_path,
			wal,
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
		let wal_end = self.wal.metadata()?.len();
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
			pos = next_pos;
			apply(state, rec.values)?;
			replayed = replayed.saturating_add(1);
		}
		Ok((pos, replayed))
	}

	pub fn append_wal(&mut self, values: Vec<[u8; 32]>) -> Result<u64> {
		let rec = WalRecord {
			values,
		};
		let pos_before = self.wal.metadata()?.len();
		write_len_prefixed(&mut self.wal, &rec)?;
		self.wal.flush()?;
		self.wal.sync_data()?;
		Ok(pos_before)
	}

	pub fn wal_len(&self) -> Result<u64> {
		Ok(self.wal.metadata()?.len())
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
		meta.wal_pos = self.wal.metadata()?.len();
		meta.committed_batches = meta.committed_batches.saturating_add(1);
		self.maybe_checkpoint(state, meta)?;
		Ok(())
	}

	pub fn maybe_checkpoint(&self, state: &T, meta: &StoreMeta) -> Result<()> {
		if meta.committed_batches % self.snapshot_every_batches != 0 {
			return Ok(());
		}
		self.write_snapshot(state, meta)
	}

	pub fn force_checkpoint(&self, state: &T, meta: &StoreMeta) -> Result<()> {
		self.write_snapshot(state, meta)
	}

	pub fn truncate(&mut self) -> Result<()> {
		// Close and reopen WAL to truncate.
		self.wal.flush().ok();
		self.wal = OpenOptions::new()
			.create(true)
			.read(true)
			.append(true)
			.truncate(true)
			.open(&self.wal_path)
			.with_context(|| format!("truncate wal: {}", self.wal_path.display()))?;
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
		if snap.version != 1 {
			return Err(anyhow::anyhow!(
				"unsupported snapshot version {} (tree={:?})",
				snap.version,
				self.tree_id
			));
		}
		let meta = StoreMeta {
			wal_pos: snap.wal_pos,
			committed_batches: snap.committed_batches,
			last_block: snap.last_block,
			last_tx_index: snap.last_tx_index,
			last_log_index: snap.last_log_index,
		};
		Ok(Some((snap, meta)))
	}

	fn write_snapshot(&self, state: &T, meta: &StoreMeta) -> Result<()> {
		let snap = Snapshot {
			version: 1,
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

fn write_len_prefixed<T: Serialize>(f: &mut File, v: &T) -> Result<()> {
	let bytes = bincode::serialize(v)?;
	let len = u32::try_from(bytes.len())
		.map_err(|_| anyhow::anyhow!("wal record too large: {} bytes", bytes.len()))?;
	f.write_all(&len.to_le_bytes())?;
	f.write_all(&bytes)?;
	Ok(())
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
