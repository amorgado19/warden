//! Menu key input from **both** the serial line and the firmware console (DEC-008).
//!
//! Two sources are polled, non-blocking, and normalised to a single [`Key`]:
//!   * the COM1 serial line, where arrow keys arrive as ANSI escape sequences
//!     (`ESC [ A` / `ESC [ B`) — parsed by a small state machine that survives
//!     across polls — plus number/Enter/vi-style `j`/`k`/`r`;
//!   * the firmware Simple Text Input protocol, which reports arrows as
//!     `ScanCode::UP`/`DOWN` and everything else as printable characters.

use uefi::proto::console::text::{Key as FwKey, ScanCode};

use crate::arch;

/// A normalised menu keystroke.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Key {
    Up,
    Down,
    Enter,
    /// A digit `1..=9` (0 is ignored as a menu index).
    Digit(u8),
    /// `r` — request the rescue prompt.
    Rescue,
    /// Any other printable ASCII byte — used by the rescue shell for its
    /// single-letter commands (`l`/`m`/`p`/`h`/…). The menu ignores it.
    Char(u8),
}

/// Serial ANSI-escape parser state.
#[derive(Clone, Copy)]
enum Esc {
    Normal,
    /// Saw `ESC`.
    Seen,
    /// Saw `ESC [` (CSI).
    Csi,
}

/// Polls serial + firmware console for keystrokes. Holds the serial escape
/// state so multi-byte arrow sequences split across polls are handled.
pub struct InputReader {
    esc: Esc,
}

impl InputReader {
    #[must_use]
    pub const fn new() -> Self {
        Self { esc: Esc::Normal }
    }

    /// Return the next available keystroke, or `None` if nothing is pending.
    pub fn poll(&mut self) -> Option<Key> {
        // Firmware console first (arrow keys are unambiguous there)…
        if let Some(k) = poll_firmware() {
            return Some(k);
        }
        // …then drain any bytes waiting on the serial line.
        while let Some(byte) = arch::serial_read_byte() {
            if let Some(k) = self.feed_serial(byte) {
                return Some(k);
            }
        }
        None
    }

    fn feed_serial(&mut self, byte: u8) -> Option<Key> {
        match self.esc {
            Esc::Normal => match byte {
                0x1B => {
                    self.esc = Esc::Seen;
                    None
                }
                b'\r' | b'\n' => Some(Key::Enter),
                b'0'..=b'9' => Some(Key::Digit(byte - b'0')),
                b'j' | b'J' => Some(Key::Down),
                b'k' | b'K' => Some(Key::Up),
                b'r' | b'R' => Some(Key::Rescue),
                b if b.is_ascii_graphic() => Some(Key::Char(b)),
                _ => None,
            },
            Esc::Seen => match byte {
                // CSI (`ESC [`) and SS3 (`ESC O`, application-cursor mode) both
                // introduce arrow sequences.
                b'[' | b'O' => {
                    self.esc = Esc::Csi;
                    None
                }
                // A lone ESC (real Escape key, line noise, truncated sequence):
                // don't swallow the following key — re-interpret this byte as a
                // normal keystroke.
                _ => {
                    self.esc = Esc::Normal;
                    self.feed_serial(byte)
                }
            },
            Esc::Csi => {
                // Consume CSI parameter (0x30..=0x3F) and intermediate
                // (0x20..=0x2F) bytes silently; the sequence ends at a final byte
                // (0x40..=0x7E). This swallows modified-arrow / function-key
                // sequences (e.g. `ESC [ 1 ; 2 A`) whole, instead of leaking their
                // tail digits as phantom `Digit`/`Char` keystrokes that could
                // select or boot the wrong entry.
                if (0x40..=0x7E).contains(&byte) {
                    self.esc = Esc::Normal;
                    match byte {
                        b'A' => Some(Key::Up),
                        b'B' => Some(Key::Down),
                        _ => None,
                    }
                } else {
                    None // still inside the sequence — keep consuming
                }
            }
        }
    }
}

/// Returns `true` iff boot services are live and a stdin console exists (so
/// `with_stdin` won't hit its internal null-pointer assertions).
fn stdin_present() -> bool {
    match uefi::table::system_table_raw() {
        // SAFETY: pointer installed by `#[entry]`; valid while boot services are
        // alive. We only read two pointer fields and never retain the reference.
        Some(st) => unsafe {
            let st = st.as_ref();
            !st.boot_services.is_null() && !st.stdin.is_null()
        },
        None => false,
    }
}

// NOTE: `stdin.read_key()` trusts the firmware to deliver valid UCS-2 — the
// `uefi` crate `.unwrap()`s the `Char16` conversion, so a (spec-violating) lone
// UTF-16 surrogate from firmware would panic upstream. Real keyboard/console
// drivers (incl. OVMF) never emit one, so we accept that residual risk here
// rather than dropping to the raw SimpleTextInputEx protocol.
fn poll_firmware() -> Option<Key> {
    if !stdin_present() {
        return None;
    }
    uefi::system::with_stdin(|stdin| match stdin.read_key() {
        Ok(Some(FwKey::Special(ScanCode::UP))) => Some(Key::Up),
        Ok(Some(FwKey::Special(ScanCode::DOWN))) => Some(Key::Down),
        Ok(Some(FwKey::Printable(c))) => map_char(char::from(c)),
        _ => None,
    })
}

fn map_char(c: char) -> Option<Key> {
    match c {
        '\r' | '\n' => Some(Key::Enter),
        '0'..='9' => Some(Key::Digit(c as u8 - b'0')),
        'j' | 'J' => Some(Key::Down),
        'k' | 'K' => Some(Key::Up),
        'r' | 'R' => Some(Key::Rescue),
        c if c.is_ascii_graphic() => Some(Key::Char(c as u8)),
        _ => None,
    }
}
