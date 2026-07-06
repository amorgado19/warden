//! The numbered text boot menu (T1.3): renders entries, runs a countdown that
//! auto-selects the default, and accepts serial/console input to move the
//! highlight or pick an entry.

use alloc::string::String;
use core::fmt::Write;
use core::time::Duration;

use uefi::boot::stall;
use warden_config::Config;

use crate::console::{self, input::InputReader, input::Key};

/// The operator's decision from the menu.
pub enum Choice {
    /// Boot the entry at this index.
    Boot(usize),
    /// Drop to the rescue prompt.
    Rescue,
}

/// Poll cadence. Small enough to feel responsive, large enough not to busy-spin.
const TICK_MS: u64 = 50;

/// Render the menu and run the selection loop until the operator chooses or the
/// countdown elapses. Never returns until a choice is made.
pub fn run(config: &Config, banner: Option<&str>) -> Choice {
    let mode = config.global.console;
    let n = config.entries.len();
    let mut sel = config.default_index();
    render(config, sel, banner);

    // Countdown in ms; `None` == wait forever (timeout == 0).
    let mut remaining: Option<i64> = match config.global.timeout {
        0 => None,
        secs => Some(i64::from(secs) * 1000),
    };
    status(config, remaining);
    // Track the *displayed* (ceil) second so the re-render trigger and the shown
    // value stay in lockstep (otherwise the top second prints twice).
    let mut last_secs_shown = remaining.map(|ms| (ms + 999) / 1000);

    let mut reader = InputReader::new();
    loop {
        if let Some(key) = reader.poll() {
            // Only *actionable* keys cancel the countdown and drive the menu.
            // Stray serial bytes (line noise, a BMC handshake) map to Key::Char or
            // an out-of-range digit and are ignored WITHOUT cancelling the
            // countdown — otherwise a single spurious byte could strand a headless
            // boot / the A/B auto-rollback (AC6.1).
            match key {
                Key::Up => {
                    cancel_countdown(mode, &mut remaining);
                    sel = (sel + n - 1) % n;
                    render(config, sel, banner);
                    status(config, None);
                }
                Key::Down => {
                    cancel_countdown(mode, &mut remaining);
                    sel = (sel + 1) % n;
                    render(config, sel, banner);
                    status(config, None);
                }
                Key::Digit(d) if (1..=n).contains(&(d as usize)) => {
                    console::emit(mode, "\n[number key selects]\n");
                    return Choice::Boot(d as usize - 1);
                }
                Key::Enter => return Choice::Boot(sel),
                Key::Rescue => return Choice::Rescue,
                // Key::Char / out-of-range digit: not interaction; countdown survives.
                _ => {}
            }
            continue;
        }

        stall(Duration::from_millis(TICK_MS));

        if let Some(ms) = remaining {
            let ms = ms - TICK_MS as i64;
            if ms <= 0 {
                console::emit(mode, "\n[timeout — auto-selecting default]\n");
                return Choice::Boot(config.default_index());
            }
            remaining = Some(ms);
            let secs = (ms + 999) / 1000; // ceil — matches what status() prints
            if Some(secs) != last_secs_shown {
                last_secs_shown = Some(secs);
                status(config, remaining);
            }
        }
    }
}

/// Cancel the auto-boot countdown on the first actionable keystroke.
fn cancel_countdown(mode: warden_config::ConsoleMode, remaining: &mut Option<i64>) {
    if remaining.is_some() {
        *remaining = None;
        console::emit(mode, "\n[input received — countdown cancelled]\n");
    }
}

fn render(config: &Config, sel: usize, banner: Option<&str>) {
    let mut s = String::new();
    s.push_str("\n=== Warden boot menu ===\n");
    if let Some(b) = banner {
        // T6.4: expose the A/B slot / tries state to the operator.
        let _ = write!(s, "{b}\n");
    }
    for (i, e) in config.entries.iter().enumerate() {
        let marker = if i == sel { '>' } else { ' ' };
        let default_tag = if e.id == config.global.default { "  (default)" } else { "" };
        // Ignore fmt errors: writing into a String is infallible.
        let _ = write!(
            s,
            "  {} {}) {:<30} [{}]{}\n",
            marker,
            i + 1,
            e.title,
            e.protocol.as_str(),
            default_tag
        );
    }
    console::emit(config.global.console, &s);
}

fn status(config: &Config, remaining: Option<i64>) {
    // Number-key selection only reaches 1..=9 (single digit). Entries beyond
    // that are still reachable with up/down, but don't advertise a number that
    // would be ignored.
    let sel_max = config.entries.len().min(9);
    let mut s = String::new();
    match remaining {
        Some(ms) => {
            let secs = (ms + 999) / 1000; // ceil to whole seconds
            let _ = write!(
                s,
                "auto-boot '{}' in {}s  (up/down or j/k move, 1-{} select, Enter boot, r rescue)\n",
                config.global.default, secs, sel_max
            );
        }
        None => {
            let _ = write!(
                s,
                "select: up/down or j/k move, 1-{} number, Enter boot, r rescue\n",
                sel_max
            );
        }
    }
    console::emit(config.global.console, &s);
}
