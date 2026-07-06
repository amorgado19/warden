//! Architecture-specific low-level primitives.
//!
//! Everything above this module is arch-generic; the small, dangerous, per-ISA
//! bits (port/MMIO serial, CPU halt, and later MMU/page-table setup) live here.
//! P0 supports **x86_64 only**; the aarch64 shim arrives in P7 (T7.1).

#[cfg(target_arch = "x86_64")]
mod x86_64;
#[cfg(target_arch = "x86_64")]
pub use x86_64::{enter_kernel, halt, serial_init, serial_write_byte};
// `serial_read_byte` is defined now but first wired up for menu input in P1
// (T1.4); re-exported there.
#[cfg(target_arch = "x86_64")]
#[allow(unused_imports)]
pub use x86_64::serial_read_byte;

#[cfg(not(target_arch = "x86_64"))]
compile_error!(
    "Warden currently targets x86_64 only; the aarch64 arch shim lands in P7 (T7.1)."
);
