//! Read-only btrfs (T5.2) — scoped ruthlessly to "resolve a path + read a file",
//! with **CRC32C verification of every metadata block** (AC5.2 / GC-03).
//!
//! Path: superblock → bootstrap the logical→physical map from the superblock's
//! `sys_chunk_array` → read the chunk tree for the full map → read the root tree
//! to find the FS_TREE → walk the FS_TREE (name-hash directory lookups) to the
//! target inode → read its `EXTENT_DATA` items. Single/DUP chunk profiles only
//! (we read stripe 0 — a full copy); RAID0/striping is out of scope.
//!
//! Every on-disk length/offset is bounds-checked, and a tree node whose stored
//! CRC32C doesn't match its contents is rejected rather than trusted.

use alloc::format;
use alloc::string::String;
use alloc::vec;
use alloc::vec::Vec;

use super::block::Disk;

const SB_OFFSET: u64 = 0x1_0000;
const MAGIC: &[u8; 8] = b"_BHRfS_M";
const CSUM_SIZE: usize = 32;
const HEADER_SIZE: usize = 101;

// Item / object types we care about.
const INODE_ITEM: u8 = 1;
const DIR_ITEM: u8 = 84;
const EXTENT_DATA: u8 = 108;
const ROOT_ITEM: u8 = 132;
const CHUNK_ITEM: u8 = 228;
const FS_TREE_OBJECTID: u64 = 5;

/// Max btrfs B-tree height (real trees are far shallower) — bounds recursion.
const MAX_TREE_HEIGHT: u8 = 8;
/// Max tree nodes to read while collecting chunks — bounds a crafted cyclic /
/// fan-out chunk tree.
const MAX_CHUNK_NODES: u32 = 100_000;

/// True if `disk` has a btrfs superblock.
pub fn probe(disk: &Disk) -> bool {
    let mut m = [0u8; 8];
    disk.read_at(SB_OFFSET + 0x40, &mut m).is_ok() && &m == MAGIC
}

/// Read the file at `path` from the btrfs volume. `path` may be `/a/b` or
/// `@sub/a/b`; the `@`-prefixed subvolume component is accepted but P5 resolves
/// files from the default (FS_TREE) subvolume, so it is skipped.
pub fn read_file(disk: &Disk, path: &str) -> Result<Vec<u8>, String> {
    let fs = Btrfs::mount(disk)?;
    fs.read_path(path)
}

// ---------------------------------------------------------------------------
// CRC32C (verified conventions: csum = std CRC32C; name hash = raw, seed ~1)
// ---------------------------------------------------------------------------

fn crc32c_raw(seed: u32, data: &[u8]) -> u32 {
    let mut crc = seed;
    for &byte in data {
        crc ^= u32::from(byte);
        for _ in 0..8 {
            let mask = (crc & 1).wrapping_neg();
            crc = (crc >> 1) ^ (0x82F6_3B78 & mask);
        }
    }
    crc
}
/// btrfs metadata checksum: standard CRC32C (init 0xFFFFFFFF, final invert).
fn csum(data: &[u8]) -> u32 {
    !crc32c_raw(0xFFFF_FFFF, data)
}
/// btrfs directory name hash: raw CRC32C, seed `~1`, no final invert.
fn name_hash(name: &[u8]) -> u64 {
    u64::from(crc32c_raw(0xFFFF_FFFE, name))
}

// ---------------------------------------------------------------------------

/// A chunk maps a logical range to a physical location (stripe 0).
#[derive(Clone, Copy)]
struct Chunk {
    logical: u64,
    length: u64,
    physical: u64,
}

/// A btrfs tree key.
#[derive(Clone, Copy, PartialEq, Eq)]
struct Key {
    objectid: u64,
    kind: u8,
    offset: u64,
}
impl Key {
    fn cmp(&self, o: &Key) -> core::cmp::Ordering {
        (self.objectid, self.kind, self.offset).cmp(&(o.objectid, o.kind, o.offset))
    }
}

struct Btrfs<'a> {
    disk: &'a Disk,
    node_size: usize,
    chunks: Vec<Chunk>,
    fs_tree_root: u64,
    fs_tree_level: u8,
}

impl<'a> Btrfs<'a> {
    fn mount(disk: &'a Disk) -> Result<Self, String> {
        let sb = disk.read_vec(SB_OFFSET, 4096)?;
        if &sb[0x40..0x48] != MAGIC {
            return Err(String::from("btrfs: bad superblock magic"));
        }
        if le16(&sb, 0xc4)? != 0 {
            return Err(String::from("btrfs: unsupported checksum type (only crc32c)"));
        }
        // Verify the superblock's own checksum (bytes after the 32-byte csum).
        verify_csum(&sb, "superblock")?;

        let root = le64(&sb, 0x50)?;
        let chunk_root = le64(&sb, 0x58)?;
        // Bound node_size (hostile field) before it becomes an allocation size.
        let node_size = le32(&sb, 0x94)? as usize;
        if node_size < HEADER_SIZE || node_size > 65536 {
            return Err(format!("btrfs: implausible node_size {node_size}"));
        }
        let chunk_root_level = sb[0xc7];
        let sys_size = le32(&sb, 0xa0)? as usize;

        // 1. Bootstrap the chunk map from the superblock sys_chunk_array (@0x32b).
        let mut chunks = Vec::new();
        parse_chunk_array(sb.get(0x32b..0x32b + sys_size).ok_or_else(|| String::from("btrfs: sys_chunk_array out of range"))?, &mut chunks)?;

        let mut fs = Btrfs { disk, node_size, chunks, fs_tree_root: 0, fs_tree_level: 0 };

        // 2. Read the chunk tree for the complete map (bounded traversal).
        let mut budget = MAX_CHUNK_NODES;
        fs.collect_chunks(chunk_root, chunk_root_level, &mut budget)?;

        // 3. Read the root tree to find the FS_TREE root.
        let (root_leaf, root_level_actual) = (root, sb[0xc6]);
        let (leaf, idx) = fs
            .search(root, root_level_actual, Key { objectid: FS_TREE_OBJECTID, kind: ROOT_ITEM, offset: 0 })?
            .ok_or_else(|| String::from("btrfs: FS_TREE root item not found"))?;
        let _ = root_leaf;
        let item = item_data(&leaf, idx, node_size)?;
        // btrfs_root_item: the tree root bytenr is at offset 0xb0 (after the
        // embedded inode_item), and the level byte at 0xc7.
        fs.fs_tree_root = le64(item, 0xb0)?;
        fs.fs_tree_level = *item.get(0xc7).ok_or_else(|| String::from("btrfs: short root_item"))?;
        Ok(fs)
    }

    /// Map a logical address to physical via the chunk map.
    fn map(&self, logical: u64) -> Result<u64, String> {
        for c in &self.chunks {
            let end = c.logical.checked_add(c.length).ok_or_else(|| String::from("btrfs: chunk range overflow"))?;
            if logical >= c.logical && logical < end {
                return c
                    .physical
                    .checked_add(logical - c.logical)
                    .ok_or_else(|| String::from("btrfs: physical address overflow"));
            }
        }
        Err(format!("btrfs: logical address {logical:#x} not in any chunk"))
    }

    /// Read + CRC-verify a tree node at a logical address.
    fn read_node(&self, logical: u64) -> Result<Vec<u8>, String> {
        let phys = self.map(logical)?;
        let node = self.disk.read_vec(phys, self.node_size)?;
        verify_csum(&node, "tree node")?;
        Ok(node)
    }

    /// Walk the chunk tree, adding every CHUNK_ITEM to the map. `budget` bounds
    /// the total nodes read (rejects a crafted cyclic / fan-out tree), and the
    /// height cap bounds recursion depth.
    fn collect_chunks(&mut self, logical: u64, level: u8, budget: &mut u32) -> Result<(), String> {
        if level > MAX_TREE_HEIGHT {
            return Err(String::from("btrfs: chunk tree too tall"));
        }
        if *budget == 0 {
            return Err(String::from("btrfs: chunk tree too large (possible cycle)"));
        }
        *budget -= 1;
        let node = self.read_node(logical)?;
        let nritems = le32(&node, 0x60)? as usize;
        if level == 0 {
            for i in 0..nritems {
                let key = read_key(&node, HEADER_SIZE + i * 25)?;
                if key.kind == CHUNK_ITEM {
                    let data = item_data(&node, i, self.node_size)?;
                    parse_chunk(key.offset, data, &mut self.chunks)?;
                }
            }
        } else {
            for i in 0..nritems {
                let child = le64(&node, HEADER_SIZE + i * 33 + 17)?;
                self.collect_chunks(child, level - 1, budget)?;
            }
        }
        Ok(())
    }

    /// Descend a tree to the leaf where `key` would live; return `(leaf, index)`
    /// of the first item `>= key`, or `None` if the tree is empty / key is past
    /// the end.
    fn search(&self, root: u64, level: u8, key: Key) -> Result<Option<(Vec<u8>, usize)>, String> {
        if level > MAX_TREE_HEIGHT {
            return Err(String::from("btrfs: tree too tall"));
        }
        let mut node = self.read_node(root)?;
        let mut level = level;
        while level > 0 {
            let nritems = le32(&node, 0x60)? as usize;
            let mut child = None;
            for i in 0..nritems {
                let k = read_key(&node, HEADER_SIZE + i * 33)?;
                if k.cmp(&key) != core::cmp::Ordering::Greater {
                    child = Some(le64(&node, HEADER_SIZE + i * 33 + 17)?);
                } else {
                    break;
                }
            }
            let child = child.ok_or_else(|| String::from("btrfs: key before first child"))?;
            node = self.read_node(child)?;
            level -= 1;
        }
        // Leaf: first item >= key.
        let nritems = le32(&node, 0x60)? as usize;
        for i in 0..nritems {
            let k = read_key(&node, HEADER_SIZE + i * 25)?;
            if k.cmp(&key) != core::cmp::Ordering::Less {
                return Ok(Some((node, i)));
            }
        }
        Ok(None)
    }

    fn read_path(&self, path: &str) -> Result<Vec<u8>, String> {
        // Accept and skip a leading `@subvol` component (P5 uses the default subvol).
        let mut inode = 256u64; // FS_TREE root directory
        for comp in path.split('/').filter(|c| !c.is_empty()) {
            if comp.starts_with('@') {
                continue;
            }
            inode = self.lookup(inode, comp)?;
        }
        self.read_inode(inode)
    }

    /// Look up `name` in directory inode `dir`, returning the child inode number.
    fn lookup(&self, dir: u64, name: &str) -> Result<u64, String> {
        let key = Key { objectid: dir, kind: DIR_ITEM, offset: name_hash(name.as_bytes()) };
        let (leaf, idx) = self.search(self.fs_tree_root, self.fs_tree_level, key)?.ok_or_else(|| format!("btrfs: '{name}' not found"))?;
        if read_key(&leaf, HEADER_SIZE + idx * 25)? != key {
            return Err(format!("btrfs: '{name}' not found"));
        }
        let data = item_data(&leaf, idx, self.node_size)?;
        // One or more btrfs_dir_item entries share a hash; match the exact name.
        let mut off = 0usize;
        while off + 30 <= data.len() {
            let child = le64(data, off)?; // location key objectid
            let data_len = le16(data, off + 25)? as usize;
            let name_len = le16(data, off + 27)? as usize;
            let nstart = off + 30;
            if nstart + name_len <= data.len() && &data[nstart..nstart + name_len] == name.as_bytes() {
                return Ok(child);
            }
            off = nstart + name_len + data_len;
        }
        Err(format!("btrfs: '{name}' not found (hash collision, no name match)"))
    }

    /// Read the full contents of a file inode from its EXTENT_DATA items.
    fn read_inode(&self, inode: u64) -> Result<Vec<u8>, String> {
        const MAX_FILE: u64 = 256 << 20;
        // Inode size from the INODE_ITEM.
        let (leaf, idx) = self
            .search(self.fs_tree_root, self.fs_tree_level, Key { objectid: inode, kind: INODE_ITEM, offset: 0 })?
            .ok_or_else(|| format!("btrfs: inode {inode} not found"))?;
        if read_key(&leaf, HEADER_SIZE + idx * 25)?.objectid != inode {
            return Err(format!("btrfs: inode {inode} not found"));
        }
        let size = le64(item_data(&leaf, idx, self.node_size)?, 16)?;
        if size > MAX_FILE {
            return Err(format!("btrfs: file size {size} exceeds cap"));
        }
        let mut file = vec![0u8; size as usize];

        // Walk EXTENT_DATA items (inode, 108, file_offset) in order.
        let mut off = 0u64;
        while off < size {
            let (leaf, idx) = match self.search(
                self.fs_tree_root,
                self.fs_tree_level,
                Key { objectid: inode, kind: EXTENT_DATA, offset: off },
            )? {
                Some(x) => x,
                None => break,
            };
            let k = read_key(&leaf, HEADER_SIZE + idx * 25)?;
            if k.objectid != inode || k.kind != EXTENT_DATA {
                break;
            }
            let file_off = k.offset as usize;
            let ed = item_data(&leaf, idx, self.node_size)?;
            let ram_bytes = le64(ed, 8)?;
            let etype = *ed.get(20).ok_or_else(|| String::from("btrfs: short extent"))?;
            let advance;
            // How much of this extent falls inside the (byte-exact) file size.
            let remaining = file.len().saturating_sub(file_off);
            if etype == 0 {
                // Inline: data lives in the item (compression 0 only).
                if *ed.get(16).ok_or_else(|| String::from("btrfs: short extent"))? != 0 {
                    return Err(String::from("btrfs: compressed inline extent unsupported"));
                }
                let payload = ed.get(21..).ok_or_else(|| String::from("btrfs: short inline extent"))?;
                let n = payload.len().min(remaining);
                copy_into(&mut file, file_off, &payload[..n])?;
                advance = ram_bytes.max(payload.len() as u64);
            } else {
                let disk_bytenr = le64(ed, 21)?;
                let extent_off = le64(ed, 37)?;
                let num_bytes = le64(ed, 45)?;
                if disk_bytenr != 0 {
                    // Read only the bytes that fall within the file (extents are
                    // block-aligned and the last one can extend past EOF).
                    let want = (num_bytes as usize).min(remaining);
                    let phys = self.map(disk_bytenr + extent_off)?;
                    let buf = self.disk.read_vec(phys, want)?;
                    copy_into(&mut file, file_off, &buf)?;
                }
                advance = num_bytes;
            }
            // Require strictly-forward progress: a checked add that also rejects
            // a crafted extent whose length would wrap `off` backwards (which
            // would otherwise re-select the same item forever).
            let next = (file_off as u64)
                .checked_add(advance)
                .ok_or_else(|| String::from("btrfs: extent offset overflow"))?;
            if next <= off {
                return Err(String::from("btrfs: non-advancing extent"));
            }
            off = next;
        }
        Ok(file)
    }
}

/// Verify a metadata block's stored CRC32C against its contents (bytes after the
/// 32-byte csum). Rejects a mismatch (AC5.2).
fn verify_csum(block: &[u8], what: &str) -> Result<(), String> {
    let stored = le32(block, 0)?;
    let region = block.get(CSUM_SIZE..).ok_or_else(|| format!("btrfs: {what} too small"))?;
    let computed = csum(region);
    if stored != computed {
        return Err(format!("btrfs: {what} CRC32C mismatch (stored {stored:#010x}, computed {computed:#010x}) — REFUSING"));
    }
    Ok(())
}

/// Parse a `sys_chunk_array`: repeated (disk_key(17), chunk).
fn parse_chunk_array(mut buf: &[u8], out: &mut Vec<Chunk>) -> Result<(), String> {
    while buf.len() >= 17 {
        let logical = le64(buf, 9)?; // disk_key.offset = chunk logical start
        let chunk = &buf[17..];
        let consumed = parse_chunk(logical, chunk, out)?;
        let total = 17 + consumed;
        buf = buf.get(total..).ok_or_else(|| String::from("btrfs: truncated sys_chunk_array"))?;
    }
    Ok(())
}

/// Parse one btrfs_chunk; append it to `out` and return its byte length.
fn parse_chunk(logical: u64, chunk: &[u8], out: &mut Vec<Chunk>) -> Result<usize, String> {
    let length = le64(chunk, 0)?;
    let num_stripes = le16(chunk, 44)? as usize;
    if num_stripes == 0 {
        return Err(String::from("btrfs: chunk with zero stripes"));
    }
    // stripe 0 at offset 48: devid(8), offset(8), uuid(16).
    let physical = le64(chunk, 48 + 8)?;
    out.push(Chunk { logical, length, physical });
    Ok(48 + num_stripes * 32)
}

/// Slice of a leaf item's data (`node[HEADER + item.data_offset ..][.. data_size]`).
fn item_data<'b>(node: &'b [u8], index: usize, node_size: usize) -> Result<&'b [u8], String> {
    let item = HEADER_SIZE + index * 25;
    let data_off = le32(node, item + 17)? as usize;
    let data_size = le32(node, item + 21)? as usize;
    let start = HEADER_SIZE + data_off;
    let end = start.checked_add(data_size).ok_or_else(|| String::from("btrfs: item data overflow"))?;
    if end > node_size {
        return Err(String::from("btrfs: item data past node"));
    }
    node.get(start..end).ok_or_else(|| String::from("btrfs: item data out of range"))
}

fn read_key(node: &[u8], off: usize) -> Result<Key, String> {
    Ok(Key {
        objectid: le64(node, off)?,
        kind: *node.get(off + 8).ok_or_else(|| String::from("btrfs: short key"))?,
        offset: le64(node, off + 9)?,
    })
}

fn copy_into(file: &mut [u8], at: usize, src: &[u8]) -> Result<(), String> {
    let end = at.checked_add(src.len()).ok_or_else(|| String::from("btrfs: extent offset overflow"))?;
    let dst = file.get_mut(at..end).ok_or_else(|| String::from("btrfs: extent past file end"))?;
    dst.copy_from_slice(src);
    Ok(())
}

fn le16(b: &[u8], off: usize) -> Result<u16, String> {
    b.get(off..off + 2).map(|s| u16::from_le_bytes([s[0], s[1]])).ok_or_else(|| String::from("btrfs: read past buffer"))
}
fn le32(b: &[u8], off: usize) -> Result<u32, String> {
    b.get(off..off + 4).map(|s| u32::from_le_bytes([s[0], s[1], s[2], s[3]])).ok_or_else(|| String::from("btrfs: read past buffer"))
}
fn le64(b: &[u8], off: usize) -> Result<u64, String> {
    b.get(off..off + 8)
        .map(|s| u64::from_le_bytes([s[0], s[1], s[2], s[3], s[4], s[5], s[6], s[7]]))
        .ok_or_else(|| String::from("btrfs: read past buffer"))
}
