//! Warden-rich reference kernel (P4 / T4.4).
//!
//! Warden loads this ELF higher-half, sets up identity + HHDM + kernel page
//! tables, exits boot services, and jumps to `_start` with a pointer to
//! [`WardenBootInfo`] in the first-argument register (`rdi` on x86_64 / `x0` on
//! aarch64 — the `extern "C"` ABI handles both). We run post-ExitBootServices
//! with no firmware services, so we drive the platform UART directly (COM1 on
//! x86_64, PL011 on the aarch64 QEMU `virt`). We validate the ABI contract, walk
//! the memory map **via the HHDM** (proving the offset works), print what we
//! received, and halt. This proves the handoff end-to-end on both arches.

#![no_std]
#![no_main]

use warden_abi::{MemoryKind, MemRegion, WardenBootInfo, WARDEN_ABI_VERSION, WARDEN_MAGIC};

/// Arch-specific serial + halt. Everything else in this kernel is arch-generic.
#[cfg(target_arch = "x86_64")]
mod plat {
    use core::arch::asm;
    const COM1: u16 = 0x3F8;
    /// SAFETY: writes THR / polls LSR of the COM1 UART; no memory effects.
    pub fn putb(b: u8) {
        unsafe {
            loop {
                let lsr: u8;
                asm!("in al, dx", out("al") lsr, in("dx") COM1 + 5, options(nomem, nostack, preserves_flags));
                if lsr & 0x20 != 0 {
                    break;
                }
            }
            asm!("out dx, al", in("dx") COM1, in("al") b, options(nomem, nostack, preserves_flags));
        }
    }
    pub fn halt() -> ! {
        loop {
            // SAFETY: `hlt` only pauses the CPU; no memory effects.
            unsafe { asm!("hlt", options(nomem, nostack, preserves_flags)) };
        }
    }
}

#[cfg(target_arch = "aarch64")]
mod plat {
    use core::arch::asm;
    use core::ptr::{read_volatile, write_volatile};
    const PL011_DR: usize = 0x0900_0000;
    const PL011_FR: usize = 0x0900_0018;
    const FR_TXFF: u32 = 1 << 5;
    /// SAFETY: MMIO to the PL011 register block (mapped Device by Warden's TTBR0).
    pub fn putb(b: u8) {
        unsafe {
            while read_volatile(PL011_FR as *const u32) & FR_TXFF != 0 {}
            write_volatile(PL011_DR as *mut u8, b);
        }
    }
    pub fn halt() -> ! {
        loop {
            // SAFETY: `wfi` only pauses the CPU; no memory effects.
            unsafe { asm!("wfi", options(nomem, nostack, preserves_flags)) };
        }
    }
}

use plat::{halt, putb};
fn puts(s: &str) {
    for b in s.bytes() {
        if b == b'\n' {
            putb(b'\r');
        }
        putb(b);
    }
}
fn puthex(n: u64) {
    puts("0x");
    for i in (0..16).rev() {
        putb(b"0123456789abcdef"[((n >> (i * 4)) & 0xf) as usize]);
    }
}
fn putdec(mut n: u64) {
    if n == 0 {
        putb(b'0');
        return;
    }
    let mut buf = [0u8; 20];
    let mut i = 20;
    while n > 0 {
        i -= 1;
        buf[i] = b'0' + (n % 10) as u8;
        n /= 10;
    }
    for b in &buf[i..] {
        putb(*b);
    }
}

/// Kernel entry. `bootinfo` is an HHDM-virtual pointer to [`WardenBootInfo`].
#[no_mangle]
extern "C" fn _start(bootinfo: *const WardenBootInfo) -> ! {
    puts("\n[refkernel] warden-rich kernel entered\n");
    if bootinfo.is_null() {
        puts("[refkernel] FATAL: null bootinfo\n");
        halt();
    }
    // SAFETY: Warden guarantees `bootinfo` points at a valid WardenBootInfo
    // mapped via HHDM; we only read it.
    let bi = unsafe { &*bootinfo };

    puts("[refkernel] magic=");
    puthex(bi.magic);
    puts(" abi_version=");
    putdec(u64::from(bi.abi_version));
    putb(b'\n');

    if bi.magic != WARDEN_MAGIC {
        puts("[refkernel] FATAL: bad magic\n");
        halt();
    }
    if bi.abi_version != WARDEN_ABI_VERSION {
        puts("[refkernel] FATAL: bad abi_version\n");
        halt();
    }
    puts("[refkernel] CONTRACT OK: magic + abi_version valid\n");

    puts("[refkernel] hhdm_offset=");
    puthex(bi.hhdm_offset);
    putb(b'\n');
    puts("[refkernel] rsdp=");
    puthex(bi.rsdp);
    putb(b'\n');
    puts("[refkernel] memmap regions=");
    putdec(bi.memmap.count);
    putb(b'\n');

    if bi.framebuffer.present != 0 {
        puts("[refkernel] framebuffer ");
        putdec(u64::from(bi.framebuffer.width));
        putb(b'x');
        putdec(u64::from(bi.framebuffer.height));
        puts(" bpp=");
        putdec(u64::from(bi.framebuffer.bpp));
        puts(" pitch=");
        putdec(bi.framebuffer.pitch);
        puts(" base=");
        puthex(bi.framebuffer.base);
        putb(b'\n');
    } else {
        puts("[refkernel] framebuffer: none\n");
    }

    // Walk the memory map through the HHDM (the array pointer is physical).
    let regions = (bi.memmap.regions + bi.hhdm_offset) as *const MemRegion;
    let mut usable_pages = 0u64;
    for i in 0..bi.memmap.count {
        // SAFETY: `regions[0..count]` is the physical array mapped via HHDM.
        let r = unsafe { &*regions.add(i as usize) };
        if r.kind == MemoryKind::USABLE {
            usable_pages += r.pages;
        }
    }
    puts("[refkernel] usable pages (walked via HHDM)=");
    putdec(usable_pages);
    puts(" (");
    putdec(usable_pages * 4 / 1024);
    puts(" MiB)\n");

    puts("[refkernel] WARDEN-P4-KERNEL-OK\n");
    halt();
}

#[panic_handler]
fn panic(_: &core::panic::PanicInfo) -> ! {
    puts("[refkernel] PANIC\n");
    halt();
}
