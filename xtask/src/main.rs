//! Warden build/run helper (host tool).
//!
//! Subcommands:
//!   * `build-x64`            — build the bootloader and stage it as `BOOTX64.EFI`.
//!   * `run-x64 [config]`     — build + stage + stage a config fixture, then
//!                              launch QEMU interactively (serial on stdio,
//!                              `-nographic`) so you can drive Warden by hand.
//!   * `test-x64` / `test-menu`  — AC1.1: valid config, timeout auto-selects default.
//!   * `test-input`              — AC1.2: inject a number key, selection changes.
//!   * `test-rescue`             — AC1.3: broken config -> rescue prompt, no panic.
//!   * `test-p1`                 — run all three P1 scenarios; non-zero if any fail.
//!
//! Each `test-*` boots QEMU headless, captures the serial log with a watchdog,
//! and asserts required markers are present, forbidden markers are absent, and
//! QEMU was still running at the deadline (a clean halt, not a reset/triple
//! fault under `-no-reboot`). Firmware paths come from `$OVMF_CODE`/`$OVMF_VARS`
//! (auto-created from the edk2 template when missing). Paths resolve relative to
//! the workspace root, so cwd does not matter.

use std::env;
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::process::{exit, Child, Command, ExitStatus, Stdio};
use std::sync::mpsc;
use std::thread;
use std::time::{Duration, Instant};

const TARGET: &str = "x86_64-unknown-uefi";
const EFI_ARTIFACT: &str = "target/x86_64-unknown-uefi/release/warden.efi";
const ESP_TARGET: &str = "esp/EFI/BOOT/BOOTX64.EFI";
const ESP_CONFIG: &str = "esp/warden.toml";
const DEFAULT_OVMF_CODE: &str = "/usr/share/edk2/x64/OVMF_CODE.4m.fd";
const DEFAULT_OVMF_VARS_TEMPLATE: &str = "/usr/share/edk2/x64/OVMF_VARS.4m.fd";
const DEFAULT_OVMF_VARS_LOCAL: &str = "OVMF_VARS.local.fd";

/// Strings whose presence means the boot went wrong even if success markers also
/// appear (memory-map dump failed, or the loader panicked).
const FORBIDDEN: &[&str] = &["could not obtain UEFI memory map", "WARDEN PANIC"];

fn main() {
    let args: Vec<String> = env::args().skip(1).collect();
    match args.first().map(String::as_str) {
        Some("build-x64") => {
            build();
            stage();
        }
        Some("run-x64") => {
            build();
            stage();
            stage_config(args.get(1).map(String::as_str).unwrap_or("warden.toml"));
            run_interactive();
        }
        Some("test-x64" | "test-menu") => {
            build();
            stage();
            exit(if test_menu() { 0 } else { 1 });
        }
        Some("test-input") => {
            build();
            stage();
            exit(if test_input() { 0 } else { 1 });
        }
        Some("test-rescue") => {
            build();
            stage();
            exit(if test_rescue() { 0 } else { 1 });
        }
        Some("test-p1") => {
            build();
            stage();
            // Run all three so the report is complete, then AND the results.
            let menu = test_menu();
            let input = test_input();
            let rescue = test_rescue();
            eprintln!("[xtask] P1 results: menu={menu} input={input} rescue={rescue}");
            exit(if menu && input && rescue { 0 } else { 1 });
        }
        _ => {
            eprintln!("usage: cargo xtask <build-x64 | run-x64 [config] | test-menu | test-input | test-rescue | test-p1>");
            exit(2);
        }
    }
}

// ---------------------------------------------------------------------------
// P1 acceptance scenarios
// ---------------------------------------------------------------------------

/// AC1.1 — valid config renders entries and the timeout auto-selects `default`.
fn test_menu() -> bool {
    run_scenario(Scenario {
        name: "menu (AC1.1)",
        secs: 25,
        config: "warden.toml", // timeout = 3, default = demo
        input: None,
        required: &[
            "Warden v",
            "memory summary:",
            "Warden boot menu",
            "Demo Entry",
            "auto-selecting default",
            "selected entry: demo",
            "reached final halt",
        ],
        forbidden: FORBIDDEN,
    })
}

/// AC1.2 — a number key over serial changes the selection; the entry is booted.
fn test_input() -> bool {
    run_scenario(Scenario {
        name: "input (AC1.2)",
        secs: 30,
        config: "warden-wait.toml", // timeout = 0 -> waits for our keystroke
        input: Some(b"2"),           // select the 2nd entry ("bravo")
        required: &[
            "Warden boot menu",
            "Bravo Entry",
            "number key selects",
            "selected entry: bravo",
            "reached final halt",
        ],
        forbidden: FORBIDDEN,
    })
}

/// AC1.3 — a malformed config yields a readable error + rescue prompt, no panic.
fn test_rescue() -> bool {
    run_scenario(Scenario {
        name: "rescue (AC1.3)",
        secs: 20,
        config: "warden-broken.toml",
        input: None,
        // Rescue loops awaiting input, so "halting" is intentionally NOT required;
        // the clean-halt check (QEMU still running at the deadline) proves no crash.
        required: &["config error (line", "WARDEN RESCUE"],
        forbidden: &["WARDEN PANIC"],
    })
}

struct Scenario {
    name: &'static str,
    secs: u64,
    config: &'static str,
    /// Bytes to feed to the serial line ~10s after boot (once the menu is up).
    input: Option<&'static [u8]>,
    required: &'static [&'static str],
    forbidden: &'static [&'static str],
}

fn run_scenario(s: Scenario) -> bool {
    eprintln!("\n========== scenario: {} ==========", s.name);
    stage_config(s.config);

    let root = workspace_root();
    let mut cmd = Command::new("qemu-system-x86_64");
    cmd.current_dir(&root)
        .args(qemu_base_args(&root))
        .args(["-display", "none", "-serial", "stdio"])
        .stdout(Stdio::piped())
        .stderr(Stdio::inherit());
    if s.input.is_some() {
        cmd.stdin(Stdio::piped());
    } else {
        cmd.stdin(Stdio::null());
    }

    eprintln!("[xtask] booting QEMU headless (config={}, watchdog {}s)…", s.config, s.secs);
    let mut child = cmd.spawn().expect("failed to spawn qemu-system-x86_64");
    let mut stdout = child.stdout.take().expect("piped stdout");

    // Reader thread drains serial until the pipe closes.
    let (tx, rx) = mpsc::channel();
    let reader = thread::spawn(move || {
        let mut buf = Vec::new();
        let _ = stdout.read_to_end(&mut buf);
        let _ = tx.send(buf);
    });

    // Optional input injector: (re)send the keystroke every 1.5s once the menu
    // should be up. Retrying makes the test robust to variable TCG boot time —
    // an early byte lost to serial_init's FIFO reset is superseded by a later
    // one; once the entry is selected Warden halts and ignores the rest.
    if let Some(bytes) = s.input {
        if let Some(mut stdin) = child.stdin.take() {
            let payload = bytes.to_vec();
            thread::spawn(move || {
                thread::sleep(Duration::from_secs(4));
                for _ in 0..12 {
                    if stdin.write_all(&payload).is_err() {
                        break;
                    }
                    let _ = stdin.flush();
                    thread::sleep(Duration::from_millis(1500));
                }
            });
        }
    }

    let outcome = watch(&mut child, s.secs);

    let buf = rx.recv_timeout(Duration::from_secs(5)).unwrap_or_default();
    let _ = reader.join();
    let log = String::from_utf8_lossy(&buf);
    println!("----- captured serial ({}) -----\n{log}\n----- end serial -----", s.name);

    let mut ok = true;
    for m in s.required {
        let present = log.contains(m);
        eprintln!("[xtask] require {:>4}: {m:?}", if present { "OK" } else { "MISS" });
        ok &= present;
    }
    for f in s.forbidden {
        if log.contains(f) {
            eprintln!("[xtask] forbid  HIT: {f:?}");
            ok = false;
        }
    }
    match outcome {
        Outcome::CleanHalt => eprintln!("[xtask] halt     OK: QEMU still running at deadline (clean halt)"),
        Outcome::ExitedEarly(status) => {
            eprintln!("[xtask] halt   FAIL: QEMU exited early ({status}) — reset/triple-fault or launch error");
            ok = false;
        }
        Outcome::WatchError => {
            eprintln!("[xtask] halt   FAIL: watch error while polling QEMU");
            ok = false;
        }
    }
    eprintln!("[xtask] scenario {}: {}", s.name, if ok { "PASS" } else { "FAIL" });
    ok
}

/// Result of watching the QEMU process to its deadline.
enum Outcome {
    /// Still running at the deadline — the expected clean `hlt` (we killed it).
    CleanHalt,
    /// Exited before the deadline — a reset/triple-fault under `-no-reboot`, or
    /// a launch error.
    ExitedEarly(ExitStatus),
    /// `try_wait` errored; child reaped, treated as failure.
    WatchError,
}

/// Poll for an early process exit up to `secs`. Always leaves the child reaped
/// so the serial reader thread's pipe closes and `join()` cannot block.
fn watch(child: &mut Child, secs: u64) -> Outcome {
    let deadline = Instant::now() + Duration::from_secs(secs);
    while Instant::now() < deadline {
        match child.try_wait() {
            Ok(Some(status)) => return Outcome::ExitedEarly(status),
            Ok(None) => thread::sleep(Duration::from_millis(200)),
            Err(e) => {
                eprintln!("[xtask] try_wait failed: {e}");
                let _ = child.kill();
                let _ = child.wait();
                return Outcome::WatchError;
            }
        }
    }
    let _ = child.kill();
    let _ = child.wait();
    Outcome::CleanHalt
}

// ---------------------------------------------------------------------------
// Build / stage / QEMU plumbing
// ---------------------------------------------------------------------------

fn workspace_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("xtask manifest has a parent")
        .to_path_buf()
}

fn build() {
    let cargo = env::var("CARGO").unwrap_or_else(|_| "cargo".to_string());
    eprintln!("[xtask] building warden.efi ({TARGET}, release)…");
    let status = Command::new(cargo)
        .current_dir(workspace_root())
        .args(["build", "-p", "warden", "--release", "--target", TARGET])
        .status()
        .expect("failed to spawn cargo");
    if !status.success() {
        eprintln!("[xtask] build failed");
        exit(1);
    }
}

fn stage() {
    let root = workspace_root();
    let src = root.join(EFI_ARTIFACT);
    let dst = root.join(ESP_TARGET);
    if let Some(parent) = dst.parent() {
        std::fs::create_dir_all(parent).expect("create esp/EFI/BOOT");
    }
    std::fs::copy(&src, &dst).unwrap_or_else(|e| {
        eprintln!("[xtask] staging copy {} -> {} failed: {e}", src.display(), dst.display());
        exit(1);
    });
    eprintln!("[xtask] staged {} -> {}", src.display(), dst.display());
}

/// Copy `fixtures/<name>` to the ESP as `warden.toml`.
fn stage_config(name: &str) {
    let root = workspace_root();
    let src = root.join("fixtures").join(name);
    let dst = root.join(ESP_CONFIG);
    std::fs::copy(&src, &dst).unwrap_or_else(|e| {
        eprintln!("[xtask] staging config {} -> {} failed: {e}", src.display(), dst.display());
        exit(1);
    });
    eprintln!("[xtask] staged config {} -> {}", src.display(), dst.display());
}

/// Resolve OVMF firmware paths, failing loudly if the CODE image is missing and
/// auto-creating the writable VARS file from the edk2 template when absent.
fn resolve_ovmf(root: &Path) -> (String, String) {
    let code = env::var("OVMF_CODE").unwrap_or_else(|_| DEFAULT_OVMF_CODE.to_string());
    let vars = env::var("OVMF_VARS")
        .unwrap_or_else(|_| root.join(DEFAULT_OVMF_VARS_LOCAL).to_string_lossy().into_owned());

    if !Path::new(&code).exists() {
        eprintln!(
            "[xtask] OVMF CODE image not found: {code}\n\
             [xtask] set $OVMF_CODE to your edk2 OVMF_CODE*.fd (see `ls /usr/share/edk2/x64/`)."
        );
        exit(1);
    }
    if !Path::new(&vars).exists() {
        match std::fs::copy(DEFAULT_OVMF_VARS_TEMPLATE, &vars) {
            Ok(_) => eprintln!("[xtask] created writable OVMF vars {vars} from {DEFAULT_OVMF_VARS_TEMPLATE}"),
            Err(e) => {
                eprintln!(
                    "[xtask] OVMF VARS file {vars} missing and could not be created from \
                     {DEFAULT_OVMF_VARS_TEMPLATE}: {e}\n\
                     [xtask] set $OVMF_VARS to a writable copy of your edk2 OVMF_VARS*.fd."
                );
                exit(1);
            }
        }
    }
    (code, vars)
}

fn qemu_base_args(root: &Path) -> Vec<String> {
    let (ovmf_code, ovmf_vars) = resolve_ovmf(root);
    let esp = root.join("esp");
    vec![
        "-drive".into(),
        format!("if=pflash,format=raw,readonly=on,file={ovmf_code}"),
        "-drive".into(),
        format!("if=pflash,format=raw,file={ovmf_vars}"),
        "-drive".into(),
        format!("format=raw,file=fat:rw:{}", esp.display()),
        "-m".into(),
        "256M".into(),
        "-no-reboot".into(),
    ]
}

fn run_interactive() {
    let root = workspace_root();
    let mut cmd = Command::new("qemu-system-x86_64");
    cmd.current_dir(&root)
        .args(qemu_base_args(&root))
        .args(["-serial", "stdio", "-nographic"]);
    eprintln!("[xtask] launching QEMU (interactive). Ctrl-A X to quit.");
    let status = cmd.status().expect("failed to spawn qemu-system-x86_64");
    if !status.success() {
        eprintln!("[xtask] qemu exited with {status}");
    }
}
