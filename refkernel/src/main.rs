//! Warden-rich reference kernel (P4 / T4.4).
//!
//! Warden loads this ELF higher-half, sets up identity + HHDM + kernel page
//! tables, exits boot services, and jumps to `_start` with a pointer to
//! [`WardenBootInfo`] in `rdi` (System V AMD64). We run post-ExitBootServices
//! with no firmware services, so we drive COM1 directly. We validate the ABI
//! contract, walk the memory map **via the HHDM** (proving the offset works),
//! print what we received, and halt. This proves the handoff end-to-end.

#![no_std]
#![no_main]

use core::arch::asm;

use warden_abi::{MemoryKind, MemRegion, WardenBootInfo, WARDEN_ABI_VERSION, WARDEN_MAGIC};

const COM1: u16 = 0x3F8;

#[inline]
unsafe fn outb(port: u16, val: u8) {
    asm!("out dx, al", in("dx") port, in("al") val, options(nomem, nostack, preserves_flags));
}
#[inline]
unsafe fn inb(port: u16) -> u8 {
    let v: u8;
    asm!("in al, dx", out("al") v, in("dx") port, options(nomem, nostack, preserves_flags));
    v
}

fn putb(b: u8) {
    // SAFETY: polling LSR + writing THR of COM1; no memory effects.
    unsafe {
        while inb(COM1 + 5) & 0x20 == 0 {}
        outb(COM1, b);
    }
}
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

fn halt() -> ! {
    loop {
        // SAFETY: `hlt` pauses the CPU; no memory effects.
        unsafe { asm!("hlt", options(nomem, nostack, preserves_flags)) };
    }
}
