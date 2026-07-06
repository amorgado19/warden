//! Read-only ext4 (T5.1): superblock → block-group descriptors → inodes →
//! extent trees → directory walk → file read.
//!
//! Extent-based inodes only (the modern ext4 default; the test image uses them);
//! legacy indirect-block inodes are rejected rather than mis-read. Every on-disk
//! offset/length is bounds-checked (GC-03).

use alloc::format;
use alloc::string::String;
use alloc::vec;
use alloc::vec::Vec;

use super::block::Disk;

const EXT4_MAGIC: u16 = 0xEF53;
const EXT4_EXTENTS_FL: u32 = 0x0008_0000;
const EXTENT_MAGIC: u16 = 0xF30A;
const INCOMPAT_64BIT: u32 = 0x0080;

/// True if `disk` starts with an ext4 superblock.
pub fn probe(disk: &Disk) -> bool {
    let mut m = [0u8; 2];
    disk.read_at(1024 + 56, &mut m).is_ok() && u16::from_le_bytes(m) == EXT4_MAGIC
}

/// Read the file at `path` (absolute, `/`-separated) from the ext4 volume.
pub fn read_file(disk: &Disk, path: &str) -> Result<Vec<u8>, String> {
    let fs = Ext4::mount(disk)?;
    let inode = fs.resolve(path)?;
    fs.read_inode_data(&inode)
}

struct Ext4<'a> {
    disk: &'a Disk,
    block_size: u64,
    inode_size: u64,
    inodes_per_group: u32,
    first_data_block: u32,
    desc_size: u64,
    has_64bit: bool,
}

impl<'a> Ext4<'a> {
    fn mount(disk: &'a Disk) -> Result<Self, String> {
        let sb = disk.read_vec(1024, 1024)?;
        if le16(&sb, 56)? != EXT4_MAGIC {
            return Err(String::from("ext4: bad superblock magic"));
        }
        // Bound the block size (hostile field): ext4 uses 1–64 KiB.
        let log_bs = le32(&sb, 24)?;
        if log_bs > 6 {
            return Err(format!("ext4: implausible block size (log {log_bs})"));
        }
        let block_size = 1024u64 << log_bs;
        let inode_size = match le16(&sb, 88)? {
            0 => 128,
            n => u64::from(n),
        };
        let incompat = le32(&sb, 96)?;
        let has_64bit = incompat & INCOMPAT_64BIT != 0;
        let desc_size = if has_64bit {
            match le16(&sb, 254)? {
                0 => 32,
                n => u64::from(n),
            }
        } else {
            32
        };
        Ok(Self {
            disk,
            block_size,
            inode_size,
            inodes_per_group: le32(&sb, 40)?,
            first_data_block: le32(&sb, 20)?,
            desc_size,
            has_64bit,
        })
    }

    /// Read the raw inode bytes for inode number `ino`.
    fn read_inode(&self, ino: u32) -> Result<Vec<u8>, String> {
        if ino == 0 {
            return Err(String::from("ext4: inode 0 is invalid"));
        }
        if self.inodes_per_group == 0 {
            return Err(String::from("ext4: zero inodes_per_group"));
        }
        let group = (ino - 1) / self.inodes_per_group;
        let index = u64::from((ino - 1) % self.inodes_per_group);

        // Group-descriptor table starts at the block after the superblock block.
        let gdt = (u64::from(self.first_data_block) + 1) * self.block_size;
        let gd = self.disk.read_vec(gdt + u64::from(group) * self.desc_size, self.desc_size as usize)?;
        let itable_lo = u64::from(le32(&gd, 8)?);
        let itable_hi = if self.has_64bit && self.desc_size >= 44 { u64::from(le32(&gd, 40)?) } else { 0 };
        let itable = (itable_hi << 32) | itable_lo;

        let off = itable * self.block_size + index * self.inode_size;
        self.disk.read_vec(off, self.inode_size as usize)
    }

    /// Read the full data of an inode (file or directory) via its extent tree.
    fn read_inode_data(&self, inode: &[u8]) -> Result<Vec<u8>, String> {
        // Hard cap the declared size before allocating (the size field is hostile).
        const MAX_INODE_BYTES: u64 = 256 << 20;
        let size = (u64::from(le32(inode, 108)?) << 32) | u64::from(le32(inode, 4)?);
        if size > MAX_INODE_BYTES {
            return Err(format!("ext4: inode size {size} exceeds the {MAX_INODE_BYTES}-byte cap"));
        }
        if le32(inode, 32)? & EXT4_EXTENTS_FL == 0 {
            return Err(String::from("ext4: legacy (non-extent) inode is unsupported"));
        }
        let size_usize = usize::try_from(size).map_err(|_| String::from("ext4: file too large"))?;
        let mut data = vec![0u8; size_usize];
        // The extent tree root lives in i_block (inode offset 40, 60 bytes).
        let root = inode.get(40..100).ok_or_else(|| String::from("ext4: truncated inode"))?;
        // ext4 extent trees are at most ~5 deep; the budget rejects a cyclic /
        // self-referential index node (which would otherwise recurse forever).
        self.walk_extents(root, &mut data, size, 5)?;
        Ok(data)
    }

    fn walk_extents(&self, node: &[u8], data: &mut [u8], size: u64, budget: u32) -> Result<(), String> {
        if le16(node, 0)? != EXTENT_MAGIC {
            return Err(String::from("ext4: bad extent header magic"));
        }
        let entries = le16(node, 2)?;
        let depth = le16(node, 6)?;
        if depth != 0 && budget == 0 {
            return Err(String::from("ext4: extent tree too deep (possible cycle)"));
        }
        for i in 0..entries as usize {
            let off = 12 + i * 12;
            if depth == 0 {
                let logical = u64::from(le32(node, off)?);
                let mut len = u64::from(le16(node, off + 4)?);
                if len > 32768 {
                    len -= 32768; // uninitialized extent
                }
                let phys = (u64::from(le16(node, off + 6)?) << 32) | u64::from(le32(node, off + 8)?);
                let byte_off = logical.checked_mul(self.block_size).ok_or_else(|| String::from("ext4: extent offset overflow"))?;
                if byte_off >= size {
                    continue;
                }
                // Read/allocate only the bytes that land inside the file (never
                // the untrusted len*block_size, which could be gigabytes).
                let want = (len * self.block_size).min(size - byte_off) as usize;
                let buf = self.disk.read_vec(phys * self.block_size, want)?;
                let start = byte_off as usize;
                let dst = data.get_mut(start..start + want).ok_or_else(|| String::from("ext4: extent past file end"))?;
                dst.copy_from_slice(&buf);
            } else {
                let leaf = (u64::from(le16(node, off + 8)?) << 32) | u64::from(le32(node, off + 4)?);
                let block = self.disk.read_vec(leaf * self.block_size, self.block_size as usize)?;
                self.walk_extents(&block, data, size, budget - 1)?;
            }
        }
        Ok(())
    }

    /// Find `name` in a directory inode, returning the child inode number.
    fn lookup(&self, dir: &[u8], name: &str) -> Result<u32, String> {
        let data = self.read_inode_data(dir)?;
        let mut off = 0usize;
        while off + 8 <= data.len() {
            let ino = le32(&data, off)?;
            let rec_len = le16(&data, off + 4)? as usize;
            let name_len = data[off + 6] as usize;
            if rec_len < 8 {
                break;
            }
            if ino != 0 && off + 8 + name_len <= data.len() && &data[off + 8..off + 8 + name_len] == name.as_bytes() {
                return Ok(ino);
            }
            off += rec_len;
        }
        Err(format!("ext4: '{name}' not found"))
    }

    /// Resolve an absolute path to its inode bytes.
    fn resolve(&self, path: &str) -> Result<Vec<u8>, String> {
        let mut inode = self.read_inode(2)?; // root inode
        for comp in path.split('/').filter(|c| !c.is_empty()) {
            let ino = self.lookup(&inode, comp)?;
            inode = self.read_inode(ino)?;
        }
        Ok(inode)
    }
}

fn le16(b: &[u8], off: usize) -> Result<u16, String> {
    b.get(off..off + 2)
        .map(|s| u16::from_le_bytes([s[0], s[1]]))
        .ok_or_else(|| String::from("ext4: read past buffer"))
}
fn le32(b: &[u8], off: usize) -> Result<u32, String> {
    b.get(off..off + 4)
        .map(|s| u32::from_le_bytes([s[0], s[1], s[2], s[3]]))
        .ok_or_else(|| String::from("ext4: read past buffer"))
}
