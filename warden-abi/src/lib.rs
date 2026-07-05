//! # `warden-abi` — Warden ⇄ kernel handoff ABI
//!
//! This crate defines [`WardenBootInfo`], the single `#[repr(C)]` structure that
//! the Warden bootloader hands to a custom ("warden-rich") kernel at entry, plus
//! the typed sub-structures it points at. It has **no dependencies** (not even on
//! the `uefi` crate) so kernels can build against it in isolation.
//!
//! ## Stability contract (build-spec §3.1 / ADR NEG-004)
//!
//! The in-memory layout of every type here is part of a **versioned ABI**. Any
//! change to a field, its type, or the struct layout **must** bump
//! [`WARDEN_ABI_VERSION`]. Kernels validate [`WardenBootInfo::magic`] and
//! [`WardenBootInfo::abi_version`] before trusting the structure. The layout is
//! *frozen* at the end of P4; until then it may still evolve (with a version
//! bump each time). The compile-time assertions at the bottom of this file are
//! the tripwire that catches accidental layout drift.
//!
//! ## Representation notes
//!
//! * All cross-boundary pointers are stored as `u64` **physical addresses**, not
//!   Rust references — the kernel may not share Warden's virtual mappings when it
//!   reads them.
//! * "Optional" fields use explicit `present: u8` discriminants rather than
//!   `Option<T>`, because `Option`'s layout is not a stable `#[repr(C)]`.
//! * Enumerations that cross the boundary are `#[repr(transparent)]` newtypes
//!   over `u32` with associated constants, not Rust `enum`s: an out-of-range
//!   value received from the other side must not be undefined behaviour.

#![no_std]
#![forbid(unsafe_code)]

/// `"WARDEN\0\x01"` — identifies a valid [`WardenBootInfo`] to the kernel.
pub const WARDEN_MAGIC: u64 = 0x5741_5244_454E_0001;

/// Current handoff ABI version. Bump on **any** layout change (build-spec §3.1).
/// Not frozen until the end of P4.
pub const WARDEN_ABI_VERSION: u32 = 1;

/// Page size assumed by every `pages` count in this ABI (UEFI 4 KiB pages).
pub const PAGE_SIZE: u64 = 4096;

/// A UTF-8 string living at a physical address (pointer + byte length).
///
/// Not NUL-terminated. `ptr` is a physical address; `len` is a byte count.
#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct PhysStr {
    pub ptr: u64,
    pub len: u64,
}

impl PhysStr {
    /// The empty string (`ptr == 0`, `len == 0`).
    pub const EMPTY: Self = Self { ptr: 0, len: 0 };
}

/// An optional physical address range (e.g. the TPM event log).
#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct OptRange {
    /// `1` if `base`/`len` are meaningful, `0` otherwise.
    pub present: u8,
    pub _pad: [u8; 7],
    pub base: u64,
    pub len: u64,
}

impl OptRange {
    /// A not-present range.
    pub const NONE: Self = Self { present: 0, _pad: [0; 7], base: 0, len: 0 };
}

/// Classification of a physical memory region as seen by the kernel.
///
/// A `#[repr(transparent)]` newtype (not an `enum`) so unknown values crossing
/// the ABI are well-defined. Compare against the associated constants.
#[repr(transparent)]
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct MemoryKind(pub u32);

impl MemoryKind {
    /// Free RAM the kernel may use.
    pub const USABLE: Self = Self(0);
    /// Firmware/hardware reserved — never touch.
    pub const RESERVED: Self = Self(1);
    /// ACPI tables; reclaimable once parsed.
    pub const ACPI_RECLAIMABLE: Self = Self(2);
    /// ACPI non-volatile storage; preserve.
    pub const ACPI_NVS: Self = Self(3);
    /// Memory-mapped I/O; not RAM.
    pub const MMIO: Self = Self(4);
    /// Memory Warden used for the loader/boot data; reclaimable by the kernel.
    pub const BOOTLOADER_RECLAIMABLE: Self = Self(5);
    /// Region occupied by the loaded kernel image and its modules.
    pub const KERNEL_AND_MODULES: Self = Self(6);
    /// Linear framebuffer.
    pub const FRAMEBUFFER: Self = Self(7);
    /// Faulty/unusable RAM.
    pub const BAD_MEMORY: Self = Self(8);
}

/// One physical memory region.
#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct MemRegion {
    /// Physical start address.
    pub base: u64,
    /// Length in [`PAGE_SIZE`] pages.
    pub pages: u64,
    /// What the region is.
    pub kind: MemoryKind,
    pub _pad: u32,
}

/// The physical memory map: a pointer to a `[MemRegion; count]` array.
#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct MemMap {
    /// Physical address of the first [`MemRegion`].
    pub regions: u64,
    /// Number of regions.
    pub count: u64,
}

impl MemMap {
    /// An empty map.
    pub const EMPTY: Self = Self { regions: 0, count: 0 };
}

/// One boot module handed to the kernel.
#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct Module {
    /// Module name (physical UTF-8 string).
    pub name: PhysStr,
    /// Physical base address of the module's contents.
    pub base: u64,
    /// Length in [`PAGE_SIZE`] pages.
    pub pages: u64,
}

/// The list of boot modules: a pointer to a `[Module; count]` array.
#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct ModuleList {
    /// Physical address of the first [`Module`].
    pub modules: u64,
    /// Number of modules.
    pub count: u64,
}

impl ModuleList {
    /// No modules.
    pub const EMPTY: Self = Self { modules: 0, count: 0 };
}

/// Pixel layout of a linear framebuffer.
#[repr(transparent)]
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct PixelFormat(pub u32);

impl PixelFormat {
    /// 32-bit `0x00RRGGBB` little-endian (byte order B,G,R,x).
    pub const BGRX8: Self = Self(0);
    /// 32-bit `0x00BBGGRR` little-endian (byte order R,G,B,x).
    pub const RGBX8: Self = Self(1);
    /// Format not described here; consult firmware-specific masks (unused in v1).
    pub const OTHER: Self = Self(0xFFFF_FFFF);
}

/// An optional linear framebuffer (GOP) description.
#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct OptFb {
    /// `1` if a framebuffer is present, `0` otherwise.
    pub present: u8,
    pub _pad: [u8; 7],
    /// Physical base address of the framebuffer.
    pub base: u64,
    /// Bytes per scanline (may exceed `width * bytes_per_pixel`).
    pub pitch: u64,
    /// Visible width in pixels.
    pub width: u32,
    /// Visible height in pixels.
    pub height: u32,
    /// Bits per pixel.
    pub bpp: u32,
    /// Pixel layout.
    pub format: PixelFormat,
}

impl OptFb {
    /// No framebuffer.
    pub const NONE: Self =
        Self { present: 0, _pad: [0; 7], base: 0, pitch: 0, width: 0, height: 0, bpp: 0, format: PixelFormat::OTHER };
}

/// The root handoff structure. A pointer to one of these is the sole argument to
/// a warden-rich kernel's entry point.
///
/// See the crate-level docs for the stability contract.
#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct WardenBootInfo {
    /// Must equal [`WARDEN_MAGIC`].
    pub magic: u64,
    /// Must be understood by the kernel; see [`WARDEN_ABI_VERSION`].
    pub abi_version: u32,
    pub _pad: u32,
    /// Physical memory map.
    pub memmap: MemMap,
    /// Optional linear framebuffer.
    pub framebuffer: OptFb,
    /// Loaded boot modules.
    pub modules: ModuleList,
    /// Virtual base of the higher-half direct map (HHDM).
    pub hhdm_offset: u64,
    /// Physical address of the ACPI RSDP.
    pub rsdp: u64,
    /// Optional TPM measured-boot event log.
    pub tpm_event_log: OptRange,
    /// Kernel command line (physical UTF-8 string).
    pub cmdline: PhysStr,
}

impl WardenBootInfo {
    /// Returns `true` iff `magic` and `abi_version` match what this crate defines.
    /// A kernel should call this before reading any other field.
    #[must_use]
    pub const fn is_valid(&self) -> bool {
        self.magic == WARDEN_MAGIC && self.abi_version == WARDEN_ABI_VERSION
    }
}

// ---------------------------------------------------------------------------
// Layout tripwire (build-spec §3.1): if any of these fail at compile time, the
// ABI layout changed and `WARDEN_ABI_VERSION` must be bumped deliberately.
//
// Sizes + alignment alone do not catch a *reorder* of two same-size fields
// (e.g. `hhdm_offset`↔`rsdp`, both `u64`), which would silently strand kernels.
// The `offset_of!` assertions below pin every field's position, so any reorder
// is a compile error that forces a conscious version bump.
// ---------------------------------------------------------------------------
const _: () = {
    use core::mem::{align_of, offset_of, size_of};

    // Sizes.
    assert!(size_of::<PhysStr>() == 16);
    assert!(size_of::<OptRange>() == 24);
    assert!(size_of::<MemRegion>() == 24);
    assert!(size_of::<MemMap>() == 16);
    assert!(size_of::<Module>() == 32);
    assert!(size_of::<ModuleList>() == 16);
    assert!(size_of::<OptFb>() == 40);
    assert!(size_of::<WardenBootInfo>() == 144);

    // Alignment.
    assert!(align_of::<WardenBootInfo>() == 8);
    assert!(align_of::<OptFb>() == 8);
    assert!(align_of::<MemRegion>() == 8);

    // Field offsets — the reorder tripwire.
    assert!(offset_of!(WardenBootInfo, magic) == 0);
    assert!(offset_of!(WardenBootInfo, abi_version) == 8);
    assert!(offset_of!(WardenBootInfo, _pad) == 12);
    assert!(offset_of!(WardenBootInfo, memmap) == 16);
    assert!(offset_of!(WardenBootInfo, framebuffer) == 32);
    assert!(offset_of!(WardenBootInfo, modules) == 72);
    assert!(offset_of!(WardenBootInfo, hhdm_offset) == 88);
    assert!(offset_of!(WardenBootInfo, rsdp) == 96);
    assert!(offset_of!(WardenBootInfo, tpm_event_log) == 104);
    assert!(offset_of!(WardenBootInfo, cmdline) == 128);

    assert!(offset_of!(MemMap, regions) == 0);
    assert!(offset_of!(MemMap, count) == 8);
    assert!(offset_of!(MemRegion, base) == 0);
    assert!(offset_of!(MemRegion, pages) == 8);
    assert!(offset_of!(MemRegion, kind) == 16);
    assert!(offset_of!(PhysStr, ptr) == 0);
    assert!(offset_of!(PhysStr, len) == 8);
    assert!(offset_of!(OptRange, base) == 8);
    assert!(offset_of!(OptRange, len) == 16);
    assert!(offset_of!(OptFb, base) == 8);
    assert!(offset_of!(OptFb, pitch) == 16);
    assert!(offset_of!(OptFb, width) == 24);
    assert!(offset_of!(OptFb, height) == 28);
    assert!(offset_of!(OptFb, bpp) == 32);
    assert!(offset_of!(OptFb, format) == 36);
    assert!(offset_of!(Module, base) == 16);
    assert!(offset_of!(Module, pages) == 24);
};
