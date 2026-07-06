//! Minimal UEFI application used to prove Warden's explicit chainloading
//! (P8 / T8.2 / AC8.2). Warden `LoadImage`s + `StartImage`s this app; it prints a
//! distinctive marker over the firmware console (which OVMF routes to serial in
//! `-nographic`) and returns cleanly, handing control back to Warden.

#![no_std]
#![no_main]

use uefi::prelude::*;
use uefi::{cstr16, system};

#[entry]
fn main() -> Status {
    system::with_stdout(|out| {
        let _ = out.output_string(cstr16!("\r\nCHAINLOAD-TARGET-OK\r\n"));
    });
    Status::SUCCESS
}

#[panic_handler]
fn panic(_: &core::panic::PanicInfo) -> ! {
    // A test stub; never expected to panic. No unwinding (panic = "abort").
    loop {}
}
