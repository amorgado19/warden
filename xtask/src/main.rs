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

/// Fixed **test** ed25519 seed → a deterministic keypair, so the public key
/// embedded in Warden and the private key used to sign here always match without
/// storing key files. NOT a production key.
const SIGNING_SEED: [u8; 32] = *b"warden-p3-test-ed25519-seed-0001";

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
        Some("test-linux") => {
            build();
            stage();
            exit(if test_linux() { 0 } else { 1 });
        }
        Some("test-measured") => {
            build();
            stage();
            exit(if test_measured() { 0 } else { 1 });
        }
        Some("test-rich") => {
            build();
            stage();
            exit(if test_rich() { 0 } else { 1 });
        }
        Some("pubkey") => print_pubkey(),
        Some("sign-kernel") => sign_kernel(),
        Some("sign-efi") => sign_efi(),
        Some("test-secure-good") => {
            build();
            stage();
            sign_kernel();
            exit(if test_secure_good() { 0 } else { 1 });
        }
        Some("test-secure-bad") => {
            build();
            stage();
            sign_kernel();
            exit(if test_secure_bad() { 0 } else { 1 });
        }
        Some("test-p3") => {
            build();
            stage();
            sign_kernel();
            // The measured-boot replay+PCR gate is the hard blocker before P4.
            let measured = test_measured();
            let good = test_secure_good();
            let bad = test_secure_bad();
            eprintln!("[xtask] P3 results: measured-gate={measured} secure-good={good} secure-bad={bad}");
            exit(if measured && good && bad { 0 } else { 1 });
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
            eprintln!("usage: cargo xtask <build-x64 | run-x64 [config] | test-menu | test-input | test-rescue | test-linux | test-p1>");
            exit(2);
        }
    }
}

// ---------------------------------------------------------------------------
// P1 acceptance scenarios
// ---------------------------------------------------------------------------

/// AC1.1 — valid config renders entries and the timeout auto-selects `default`.
/// In P2 a selection triggers a real boot; these fixtures name a kernel that is
/// not staged, so the boot fails *gracefully* to the rescue prompt (no panic),
/// which also exercises P2's boot-failure handling.
fn test_menu() -> bool {
    run_scenario(warden_scenario(
        "menu (AC1.1)",
        25,
        "warden.toml", // timeout = 3, default = demo (kernel not staged)
        None,
        &[
            "Warden v",
            "memory summary:",
            "Warden boot menu",
            "Demo Entry",
            "auto-selecting default",
            "selected entry: demo",
            "linux boot of 'demo' failed", // boot attempted + failed gracefully
            "WARDEN RESCUE",               // dropped to rescue, no panic
        ],
        FORBIDDEN,
    ))
}

/// AC1.2 — a number key over serial changes the selection; the entry is booted.
/// (The named kernel is not staged, so the boot then fails gracefully; AC1.2 is
/// about the selection, proven by "selected entry: bravo".)
fn test_input() -> bool {
    run_scenario(warden_scenario(
        "input (AC1.2)",
        30,
        "warden-wait.toml", // timeout = 0 -> waits for our keystroke
        Some(b"2"),          // select the 2nd entry ("bravo")
        &[
            "Warden boot menu",
            "Bravo Entry",
            "number key selects",
            "selected entry: bravo",
            "linux boot of 'bravo' failed",
        ],
        FORBIDDEN,
    ))
}

/// AC1.3 — a malformed config yields a readable error + rescue prompt, no panic.
fn test_rescue() -> bool {
    run_scenario(warden_scenario(
        "rescue (AC1.3)",
        20,
        "warden-broken.toml",
        None,
        // Rescue loops awaiting input, so "reached final halt" is intentionally
        // NOT required; the clean-halt check (QEMU still running) proves no crash.
        &["config error (line", "WARDEN RESCUE"],
        &["WARDEN PANIC"],
    ))
}

/// AC2.1/AC2.2 — boot a stock vmlinuz via the EFI stub with a minimal initramfs;
/// the kernel logs its banner + our configured cmdline, reaches userspace, and
/// powers off. Requires test-assets/{vmlinuz,initramfs.img} (see README/xtask).
fn test_linux() -> bool {
    run_scenario(Scenario {
        name: "linux (AC2.1/AC2.2)",
        secs: 90,
        config: "warden-linux.toml",
        mem: "512M",
        accel: true,
        stage: &[("vmlinuz", "vmlinuz"), ("initramfs.img", "initramfs.img")],
        kernel_owns_exit: true,
        tpm: false, // boots without a TPM too (measured boot skips gracefully)
        input: None,
        required: &[
            "selected entry: arch",    // Warden picked the linux entry
            "starting Linux EFI stub", // Warden handed off
            "Linux version 7.1.2",     // AC2.1: kernel booted to a serial log
            // AC2.2: the KERNEL's own "Command line:" log carries our full
            // configured cmdline. This is the kernel line (no quotes), NOT
            // Warden's pre-handoff `cmdline: "..."` echo, so it only passes if
            // the raw LoadOptions write actually delivered the cmdline.
            "Command line: console=ttyS0,115200 loglevel=7 warden_p2=cmdline_ok",
            "WARDEN-P2-USERSPACE-OK", // reached userspace (our init)
        ],
        forbidden: &["WARDEN PANIC"],
    })
}

/// AC3.2 + the hard gate before P4: with swtpm attached, Warden measures the
/// components into PCRs, then the event log **replays to the same PCR values**
/// (non-zero). Asserts the gate PASS marker.
fn test_measured() -> bool {
    run_scenario(Scenario {
        name: "measured-boot (AC3.2 gate)",
        secs: 90,
        config: "warden-linux.toml",
        mem: "512M",
        accel: true,
        stage: &[("vmlinuz", "vmlinuz"), ("initramfs.img", "initramfs.img")],
        kernel_owns_exit: true,
        tpm: true,
        input: None,
        required: &[
            "Secure Boot: disabled", // SB-state read path is exercised
            "MEASURE: PCR8 <- warden.config",
            "MEASURE: PCR9 <- warden.kernel",
            "REPLAY PCR8: MATCH",
            "REPLAY PCR9: MATCH",
            "MEASURED-BOOT GATE: PASS",
            "WARDEN-P2-USERSPACE-OK", // still boots the kernel after measuring
        ],
        forbidden: &["WARDEN PANIC", "MEASURED-BOOT GATE: FAIL", "REPLAY PCR8: MISMATCH", "REPLAY PCR9: MISMATCH"],
    })
}

/// AC4.1 — the reference kernel boots via the custom warden-rich handoff:
/// Warden loads the ELF, builds page tables, exits boot services, and jumps; the
/// kernel validates magic+abi_version, walks the memmap via HHDM, and prints the
/// framebuffer geometry. A page-table bug faults → QEMU resets → caught as an
/// early exit.
fn test_rich() -> bool {
    build_refkernel();
    run_scenario(Scenario {
        name: "warden-rich (AC4.1)",
        secs: 60,
        config: "warden-rich.toml",
        mem: "1G",
        accel: true,
        stage: &[("refkernel", "refkernel")],
        kernel_owns_exit: false, // the ref kernel halts; QEMU still running == clean
        tpm: false,
        input: None,
        required: &[
            "jumping to warden-rich kernel",
            "[refkernel] warden-rich kernel entered",
            "[refkernel] CONTRACT OK",
            "[refkernel] framebuffer",
            "[refkernel] usable pages (walked via HHDM)",
            "WARDEN-P4-KERNEL-OK",
        ],
        forbidden: &["WARDEN PANIC", "[refkernel] FATAL", "[refkernel] PANIC"],
    })
}

/// Build the bare-metal reference kernel ELF and stage it under test-assets.
fn build_refkernel() {
    let root = workspace_root();
    let cargo = env::var("CARGO").unwrap_or_else(|_| "cargo".to_string());
    eprintln!("[xtask] building refkernel (x86_64-unknown-none)…");
    let status = Command::new(&cargo)
        .current_dir(&root)
        .env(
            "RUSTFLAGS",
            "-C link-arg=-Trefkernel/linker.ld -C relocation-model=static -C code-model=kernel",
        )
        .args(["build", "-p", "refkernel", "--release", "--target", "x86_64-unknown-none"])
        .status()
        .expect("failed to spawn cargo for refkernel");
    if !status.success() {
        eprintln!("[xtask] refkernel build failed");
        exit(1);
    }
    let src = root.join("target/x86_64-unknown-none/release/refkernel");
    let dst = root.join("test-assets/refkernel");
    std::fs::create_dir_all(root.join("test-assets")).ok();
    std::fs::copy(&src, &dst).expect("copy refkernel");
}

/// AC3.1 (accept) — a validly-signed kernel passes verification and boots.
fn test_secure_good() -> bool {
    run_scenario(Scenario {
        name: "secure-good (AC3.1 signed boots)",
        secs: 90,
        config: "warden-signed.toml",
        mem: "512M",
        accel: true,
        stage: &[("vmlinuz", "vmlinuz"), ("initramfs.img", "initramfs.img"), ("vmlinuz.sig", "vmlinuz.sig")],
        kernel_owns_exit: true,
        tpm: false,
        input: None,
        required: &["signature OK", "Linux version 7.1.2", "WARDEN-P2-USERSPACE-OK"],
        forbidden: &["WARDEN PANIC", "signature INVALID", "REFUSING"],
    })
}

/// AC3.1 (refuse) — a tampered signature is refused with a clear message; the
/// kernel is never loaded, and Warden drops to rescue without panicking.
fn test_secure_bad() -> bool {
    run_scenario(Scenario {
        name: "secure-bad (AC3.1 tampered refused)",
        secs: 30,
        config: "warden-signed.toml",
        mem: "512M",
        accel: true,
        // Stage the *bad* signature in place of the good one.
        stage: &[("vmlinuz", "vmlinuz"), ("initramfs.img", "initramfs.img"), ("vmlinuz.sig.bad", "vmlinuz.sig")],
        kernel_owns_exit: false,
        tpm: false,
        input: None,
        required: &["signature INVALID", "REFUSING to boot", "WARDEN RESCUE"],
        forbidden: &["WARDEN PANIC", "Linux version 7.1.2", "WARDEN-P2-USERSPACE-OK"],
    })
}

struct Scenario {
    name: &'static str,
    secs: u64,
    config: &'static str,
    /// QEMU RAM (a real kernel needs more than the Warden-only default).
    mem: &'static str,
    /// Use hardware acceleration (`kvm:tcg`) — needed for a real kernel boot.
    accel: bool,
    /// (test-assets basename, ESP basename) files to stage before boot.
    stage: &'static [(&'static str, &'static str)],
    /// If true, the guest (kernel) owns power: QEMU exiting is success, not a
    /// Warden reboot loop.
    kernel_owns_exit: bool,
    /// Attach an emulated TPM 2.0 (swtpm) for measured-boot scenarios.
    tpm: bool,
    /// Bytes to feed to the serial line once the menu is up (retried).
    input: Option<&'static [u8]>,
    required: &'static [&'static str],
    forbidden: &'static [&'static str],
}

/// Defaults for a Warden-only scenario (no kernel, small RAM, TCG).
const fn warden_scenario(
    name: &'static str,
    secs: u64,
    config: &'static str,
    input: Option<&'static [u8]>,
    required: &'static [&'static str],
    forbidden: &'static [&'static str],
) -> Scenario {
    Scenario {
        name,
        secs,
        config,
        mem: "256M",
        accel: false,
        stage: &[],
        kernel_owns_exit: false,
        tpm: false,
        input,
        required,
        forbidden,
    }
}

fn run_scenario(s: Scenario) -> bool {
    eprintln!("\n========== scenario: {} ==========", s.name);
    stage_config(s.config);
    for (src, dst) in s.stage {
        stage_asset(src, dst);
    }

    let root = workspace_root();

    // Optional emulated TPM 2.0 (swtpm) for measured-boot scenarios.
    let swtpm = if s.tpm { Some(start_swtpm(&root)) } else { None };

    let mut cmd = Command::new("qemu-system-x86_64");
    cmd.current_dir(&root).args(qemu_base_args(&root, s.mem));
    if s.accel {
        cmd.args(["-machine", "accel=kvm:tcg"]);
    }
    if let Some((_, sock)) = &swtpm {
        cmd.args(["-chardev", &format!("socket,id=chrtpm,path={}", sock.display())])
            .args(["-tpmdev", "emulator,id=tpm0,chardev=chrtpm"])
            .args(["-device", "tpm-tis,tpmdev=tpm0"]);
    }
    cmd.args(["-display", "none", "-serial", "stdio"])
        .stdout(Stdio::piped())
        .stderr(Stdio::inherit());
    if s.input.is_some() {
        cmd.stdin(Stdio::piped());
    } else {
        cmd.stdin(Stdio::null());
    }

    // On a host without KVM the accel scenarios fall back to slow TCG; scale the
    // watchdog so a correct-but-slow boot doesn't false-fail.
    let secs = if s.accel && !Path::new("/dev/kvm").exists() {
        let bumped = s.secs * 4;
        eprintln!("[xtask] /dev/kvm absent — QEMU falls back to slow TCG; watchdog {}s -> {bumped}s", s.secs);
        bumped
    } else {
        s.secs
    };

    eprintln!("[xtask] booting QEMU headless (config={}, watchdog {secs}s)…", s.config);
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

    let outcome = watch(&mut child, secs);

    if let Some((mut tpm, _)) = swtpm {
        let _ = tpm.kill();
        let _ = tpm.wait();
    }

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
        Outcome::CleanHalt if s.kernel_owns_exit => {
            // The kernel should have powered off; still running is suspicious but
            // the markers are the source of truth, so don't fail solely on this.
            eprintln!("[xtask] exit   WARN: guest still running at deadline (expected power-off)");
        }
        Outcome::CleanHalt => eprintln!("[xtask] halt     OK: QEMU still running at deadline (clean halt)"),
        Outcome::ExitedEarly(status) if s.kernel_owns_exit => {
            eprintln!("[xtask] exit     OK: guest powered off ({status}) — kernel owns exit")
        }
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

fn qemu_base_args(root: &Path, mem: &str) -> Vec<String> {
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
        mem.into(),
        "-no-reboot".into(),
    ]
}

// ---------------------------------------------------------------------------
// Signing (P3) — deterministic test keypair from SIGNING_SEED
// ---------------------------------------------------------------------------

fn signing_key() -> ed25519_dalek::SigningKey {
    ed25519_dalek::SigningKey::from_bytes(&SIGNING_SEED)
}

/// Print the public key as a Rust const, to paste into `warden/src/trust`.
fn print_pubkey() {
    let pk = signing_key().verifying_key().to_bytes();
    println!("pub const SIGNING_PUBKEY: [u8; 32] = [");
    for row in pk.chunks(8) {
        print!("   ");
        for b in row {
            print!(" 0x{b:02x},");
        }
        println!();
    }
    println!("];");
}

/// Sign `test-assets/vmlinuz` → `vmlinuz.sig` (valid) + `vmlinuz.sig.bad`
/// (a valid signature with one byte flipped, for the tampered-refusal test).
fn sign_kernel() {
    use ed25519_dalek::Signer;
    let root = workspace_root();
    let kernel = std::fs::read(root.join("test-assets/vmlinuz")).unwrap_or_else(|e| {
        eprintln!("[xtask] read test-assets/vmlinuz failed: {e} (download a kernel first)");
        exit(1);
    });
    let sig = signing_key().sign(&kernel).to_bytes();
    std::fs::write(root.join("test-assets/vmlinuz.sig"), sig).expect("write sig");
    let mut bad = sig;
    bad[0] ^= 0x01; // flip one byte → invalid signature
    std::fs::write(root.join("test-assets/vmlinuz.sig.bad"), bad).expect("write bad sig");
    eprintln!("[xtask] signed vmlinuz -> vmlinuz.sig (+ vmlinuz.sig.bad)");
}

/// Sign the staged `warden.efi` with a test db key (T3.5), demonstrating the
/// Secure Boot signing story: firmware verifies Warden's PE signature against an
/// enrolled db certificate. Generates a throwaway test cert if none exists,
/// `sbsign`s the image, and `sbverify`s the result.
fn sign_efi() {
    build();
    stage();
    let root = workspace_root();
    let ta = root.join("test-assets");
    std::fs::create_dir_all(&ta).ok();
    let key = ta.join("db.key");
    let crt = ta.join("db.crt");

    if !key.exists() || !crt.exists() {
        let st = Command::new("openssl")
            .args([
                "req", "-new", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "3650",
                "-subj", "/CN=Warden Test db/",
                "-keyout", &key.to_string_lossy(),
                "-out", &crt.to_string_lossy(),
            ])
            .status()
            .expect("run openssl");
        if !st.success() {
            eprintln!("[xtask] openssl cert generation failed");
            exit(1);
        }
    }

    let efi = root.join(ESP_TARGET);
    let signed = ta.join("BOOTX64.signed.efi");
    let sign = Command::new("sbsign")
        .args([
            "--key", &key.to_string_lossy(),
            "--cert", &crt.to_string_lossy(),
            "--output", &signed.to_string_lossy(),
            &efi.to_string_lossy(),
        ])
        .status()
        .expect("run sbsign");
    if !sign.success() {
        eprintln!("[xtask] sbsign failed");
        exit(1);
    }
    let verify = Command::new("sbverify")
        .args(["--cert", &crt.to_string_lossy(), &signed.to_string_lossy()])
        .status()
        .expect("run sbverify");
    if verify.success() {
        eprintln!("[xtask] warden.efi signed + sbverify OK -> {}", signed.display());
    } else {
        eprintln!("[xtask] sbverify FAILED");
        exit(1);
    }
}

/// Start an emulated TPM 2.0 (swtpm) on a fresh state dir, returning the process
/// handle and the control socket QEMU connects to. OVMF's TCG driver performs
/// TPM2_Startup, so no swtpm_setup/manufacture is needed.
fn start_swtpm(root: &Path) -> (Child, PathBuf) {
    let dir = root.join("test-assets").join("tpm");
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).expect("create tpm state dir");
    let sock = dir.join("swtpm-sock");

    let child = Command::new("swtpm")
        .args([
            "socket",
            "--tpm2",
            "--tpmstate",
            &format!("dir={}", dir.display()),
            "--ctrl",
            &format!("type=unixio,path={}", sock.display()),
        ])
        .stdout(Stdio::null())
        .stderr(Stdio::inherit())
        .spawn()
        .unwrap_or_else(|e| {
            eprintln!("[xtask] could not start swtpm ({e}) — is `swtpm` installed?");
            exit(1);
        });

    // Wait for the control socket to appear before launching QEMU.
    for _ in 0..100 {
        if sock.exists() {
            break;
        }
        thread::sleep(Duration::from_millis(50));
    }
    eprintln!("[xtask] swtpm listening at {}", sock.display());
    (child, sock)
}

/// Copy a built test asset (`test-assets/<src>`) onto the ESP as `<dst>`.
fn stage_asset(src: &str, dst: &str) {
    let root = workspace_root();
    let from = root.join("test-assets").join(src);
    let to = root.join("esp").join(dst);
    std::fs::copy(&from, &to).unwrap_or_else(|e| {
        eprintln!(
            "[xtask] staging asset {} -> {} failed: {e}\n\
             [xtask] build it first: `bash test/build-initramfs.sh` and place a kernel at test-assets/vmlinuz",
            from.display(),
            to.display()
        );
        exit(1);
    });
    eprintln!("[xtask] staged asset {} -> {}", from.display(), to.display());
}

fn run_interactive() {
    let root = workspace_root();
    let mut cmd = Command::new("qemu-system-x86_64");
    cmd.current_dir(&root)
        .args(qemu_base_args(&root, "512M"))
        .args(["-machine", "accel=kvm:tcg", "-serial", "stdio", "-nographic"]);
    eprintln!("[xtask] launching QEMU (interactive). Ctrl-A X to quit.");
    let status = cmd.status().expect("failed to spawn qemu-system-x86_64");
    if !status.success() {
        eprintln!("[xtask] qemu exited with {status}");
    }
}
