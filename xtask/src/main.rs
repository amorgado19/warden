//! Warden build/run helper (host tool).
//!
//! Subcommands:
//!   * `build-x64` — build the bootloader and stage it as `BOOTX64.EFI`.
//!   * `run-x64`   — build + stage, then launch QEMU interactively (serial on
//!                   stdio, `-nographic`) so you can drive Warden by hand.
//!   * `test-x64 [secs] [markers...]` — build + stage, boot QEMU headless with a
//!                   captured serial log and a watchdog timeout, then assert the
//!                   expected marker strings appear, the forbidden strings do
//!                   not, and QEMU was *still running* at the deadline (a clean
//!                   halt — an early exit means reset/triple-fault under
//!                   `-no-reboot`). This is the automated form of a phase
//!                   `Verify` block; it exits non-zero on failure.
//!
//! Firmware image paths come from `$OVMF_CODE` / `$OVMF_VARS`, falling back to
//! the Arch Linux edk2 locations; the writable vars file is auto-created from
//! the read-only template when missing so the automated path is self-contained.
//! All paths are resolved relative to the workspace root, so the cwd does not
//! matter.

use std::env;
use std::io::Read;
use std::path::{Path, PathBuf};
use std::process::{exit, Command, ExitStatus, Stdio};
use std::sync::mpsc;
use std::thread;
use std::time::{Duration, Instant};

const TARGET: &str = "x86_64-unknown-uefi";
const EFI_ARTIFACT: &str = "target/x86_64-unknown-uefi/release/warden.efi";
const ESP_TARGET: &str = "esp/EFI/BOOT/BOOTX64.EFI";
const DEFAULT_OVMF_CODE: &str = "/usr/share/edk2/x64/OVMF_CODE.4m.fd";
const DEFAULT_OVMF_VARS_TEMPLATE: &str = "/usr/share/edk2/x64/OVMF_VARS.4m.fd";
const DEFAULT_OVMF_VARS_LOCAL: &str = "OVMF_VARS.local.fd";
const DEFAULT_TEST_SECS: u64 = 30;

/// Success markers proving the P0 `Verify` block passed (AC0.2). All are printed
/// *only* on the good path: `memory summary:` follows a successful map dump, so
/// it never appears if `memory_map()` errored.
fn default_markers() -> Vec<String> {
    vec!["Warden v".into(), "memory summary:".into(), "halting".into()]
}

/// Strings whose presence means the boot went wrong even if the success markers
/// also appear (e.g. the memory-map dump failed, or the app panicked).
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
            run_interactive();
        }
        Some("test-x64") => {
            build();
            stage();
            // `secs` is optional and must be numeric. If the first arg is not a
            // number, treat every trailing arg as a marker (do not silently
            // swallow it as a bad timeout).
            let (secs, markers) = match args.get(1) {
                Some(a) => match a.parse::<u64>() {
                    Ok(n) => (n, args.get(2..).map(<[String]>::to_vec).unwrap_or_default()),
                    Err(_) => (DEFAULT_TEST_SECS, args[1..].to_vec()),
                },
                None => (DEFAULT_TEST_SECS, Vec::new()),
            };
            let markers = if markers.is_empty() { default_markers() } else { markers };
            if !test_headless(secs, &markers) {
                exit(1);
            }
        }
        _ => {
            eprintln!("usage: cargo xtask <build-x64 | run-x64 | test-x64 [secs] [markers...]>");
            exit(2);
        }
    }
}

/// Workspace root = parent of this crate's manifest directory.
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

/// Resolve OVMF firmware paths and make sure they are usable. Fails loudly
/// (rather than letting QEMU fail opaquely) if the read-only CODE image is
/// missing, and auto-creates the writable VARS file from the edk2 template when
/// it is absent, so `cargo xtask test-x64` works on a fresh checkout.
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
                    "[xtask] OVMF VARS file {vars} is missing and could not be created from \
                     {DEFAULT_OVMF_VARS_TEMPLATE}: {e}\n\
                     [xtask] set $OVMF_VARS to a writable copy of your edk2 OVMF_VARS*.fd."
                );
                exit(1);
            }
        }
    }
    (code, vars)
}

/// Common QEMU argument vector shared by interactive + headless runs.
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

/// Boot headless, capture the serial log, and assert the P0 acceptance criteria:
/// required markers present, forbidden markers absent, and QEMU still running at
/// the deadline (a clean `hlt` — not an early exit from a reset/triple-fault).
fn test_headless(secs: u64, markers: &[String]) -> bool {
    let root = workspace_root();
    let mut cmd = Command::new("qemu-system-x86_64");
    cmd.current_dir(&root)
        .args(qemu_base_args(&root))
        // Clean serial-only capture: no display, serial straight to our pipe.
        // QEMU's own diagnostics go to our stderr so launch failures are visible.
        .args(["-display", "none", "-serial", "stdio"])
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::inherit());

    eprintln!("[xtask] booting QEMU headless (watchdog {secs}s)…");
    let mut child = cmd.spawn().expect("failed to spawn qemu-system-x86_64");
    let mut stdout = child.stdout.take().expect("piped stdout");

    // Reader thread drains serial until the pipe closes (QEMU exits or is killed).
    let (tx, rx) = mpsc::channel();
    let reader = thread::spawn(move || {
        let mut buf = Vec::new();
        let _ = stdout.read_to_end(&mut buf);
        let _ = tx.send(buf);
    });

    // Poll for an early exit up to the deadline. Our app halts and never exits,
    // so a process still running at the deadline is the expected clean halt. An
    // early exit means a reset/triple-fault (we pass `-no-reboot`) or a launch
    // error — a boot failure that a marker-only check would miss (AC0.2's "no
    // reboot loop, no triple fault").
    let deadline = Instant::now() + Duration::from_secs(secs);
    let mut early_exit: Option<ExitStatus> = None;
    while Instant::now() < deadline {
        match child.try_wait() {
            Ok(Some(status)) => {
                early_exit = Some(status);
                break;
            }
            Ok(None) => thread::sleep(Duration::from_millis(200)),
            Err(e) => {
                eprintln!("[xtask] try_wait failed: {e}");
                break;
            }
        }
    }
    let clean_halt = early_exit.is_none();
    if clean_halt {
        let _ = child.kill();
        let _ = child.wait();
    }

    let buf = rx.recv_timeout(Duration::from_secs(5)).unwrap_or_default();
    let _ = reader.join();
    let serial_log = String::from_utf8_lossy(&buf);

    println!("----- captured serial -----\n{serial_log}\n----- end serial -----");

    let mut ok = true;

    for m in markers {
        let present = serial_log.contains(m.as_str());
        eprintln!("[xtask] require {:>5}: {m:?}", if present { "OK" } else { "MISS" });
        ok &= present;
    }
    for f in FORBIDDEN {
        let present = serial_log.contains(f);
        if present {
            eprintln!("[xtask] forbid  HIT : {f:?}");
        }
        ok &= !present;
    }
    match early_exit {
        Some(status) => {
            eprintln!("[xtask] halt    FAIL: QEMU exited early ({status}) — reset/triple-fault or launch error, not a clean halt");
            ok = false;
        }
        None => eprintln!("[xtask] halt      OK: QEMU still running at deadline (clean halt)"),
    }

    if ok {
        eprintln!("[xtask] PASS");
    } else {
        eprintln!("[xtask] FAIL");
    }
    ok
}
