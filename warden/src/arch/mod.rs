//! Architecture-specific low-level primitives.
//!
//! Everything above this module is arch-generic; the small, dangerous, per-ISA
//! bits (port/MMIO serial, CPU halt, MMU/page-table setup) live here. Both
//! x86_64 and aarch64 (P7) are supported; each backend exposes the same surface:
//! `serial_init`, `serial_write_byte`, `serial_read_byte`, `enter_kernel`, `halt`.

#[cfg(target_arch = "x86_64")]
mod x86_64;
#[cfg(target_arch = "x86_64")]
pub use x86_64::{enter_kernel, halt, serial_init, serial_write_byte};
#[cfg(target_arch = "x86_64")]
#[allow(unused_imports)]
pub use x86_64::serial_read_byte;

#[cfg(target_arch = "aarch64")]
mod aarch64;
#[cfg(target_arch = "aarch64")]
pub use aarch64::{enter_kernel, halt, serial_init, serial_write_byte, sync_instruction_cache};
#[cfg(target_arch = "aarch64")]
#[allow(unused_imports)]
pub use aarch64::serial_read_byte;

#[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))]
compile_error!("Warden supports x86_64 and aarch64 only.");
