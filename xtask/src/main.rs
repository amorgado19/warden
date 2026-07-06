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
const DEFAULT_OVMF_VARS_LOCAL: &str = "OVMF_VARS.local.fd";
/// Candidate (CODE, VARS-template) OVMF pairs, most-specific first. Each pair is
/// a matched build (2 MiB vs 4 MiB must not be mixed). Covers Arch
/// (`edk2/x64`) and Debian/Ubuntu (`OVMF/*_4M`, `OVMF/*`) layouts so CI needs no
/// firmware-path env. `$OVMF_CODE` still overrides the code image.
const OVMF_PAIRS: &[(&str, &str)] = &[
    ("/usr/share/edk2/x64/OVMF_CODE.4m.fd", "/usr/share/edk2/x64/OVMF_VARS.4m.fd"),
    ("/usr/share/OVMF/OVMF_CODE_4M.fd", "/usr/share/OVMF/OVMF_VARS_4M.fd"),
    ("/usr/share/OVMF/OVMF_CODE.fd", "/usr/share/OVMF/OVMF_VARS.fd"),
    ("/usr/share/edk2-ovmf/x64/OVMF_CODE.fd", "/usr/share/edk2-ovmf/x64/OVMF_VARS.fd"),
];

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
        Some("test-ext4") => {
            build();
            stage();
            exit(if test_ext4() { 0 } else { 1 });
        }
        Some("test-btrfs") => {
            build();
            stage();
            exit(if test_btrfs() { 0 } else { 1 });
        }
        Some("test-btrfs-corrupt") => {
            build();
            stage();
            exit(if test_btrfs_corrupt() { 0 } else { 1 });
        }
        Some("build-a64") => {
            build_a64();
        }
        Some("test-a64") => {
            exit(if test_a64_smoke() { 0 } else { 1 });
        }
        Some("test-chainload") => {
            exit(if test_chainload() { 0 } else { 1 });
        }
        Some("test-rescue-shell") => {
            exit(if test_rescue_shell() { 0 } else { 1 });
        }
        Some("test-p8") => {
            let rescue = test_rescue_shell();
            let chain = test_chainload();
            eprintln!("[xtask] P8 results: rescue-shell(AC8.1)={rescue} chainload(AC8.2)={chain}");
            exit(if rescue && chain { 0 } else { 1 });
        }
        Some("test-a64-rich") => {
            exit(if test_a64_rich() { 0 } else { 1 });
        }
        Some("test-a64-measured") => {
            exit(if test_a64_measured() { 0 } else { 1 });
        }
        Some("test-p6-rollback") => {
            build();
            stage();
            exit(if test_p6_rollback() { 0 } else { 1 });
        }
        Some("test-p6-confirm") => {
            build();
            stage();
            exit(if test_p6_confirm() { 0 } else { 1 });
        }
        Some("test-p6-fault") => {
            build();
            stage();
            exit(if test_p6_faultinject() { 0 } else { 1 });
        }
        Some("test-p6") => {
            build();
            stage();
            let rb = test_p6_rollback();
            let cf = test_p6_confirm();
            let fi = test_p6_faultinject();
            eprintln!("[xtask] P6 results: rollback(AC6.1)={rb} confirm={cf} fault-inject(AC6.2)={fi}");
            exit(if rb && cf && fi { 0 } else { 1 });
        }
        Some("test-p5") => {
            build();
            stage();
            let ext4 = test_ext4();
            let btrfs = test_btrfs();
            let corrupt = test_btrfs_corrupt();
            eprintln!("[xtask] P5 results: ext4={ext4} btrfs={btrfs} btrfs-corrupt={corrupt}");
            exit(if ext4 && btrfs && corrupt { 0 } else { 1 });
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
        Some("test-secure-enrolled") => {
            exit(if test_secure_enrolled() { 0 } else { 1 });
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
        disks: &[],
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
        disks: &[],
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
        disks: &[],
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

/// AC5.1 — boot a kernel read from an attached **ext4** volume.
fn test_ext4() -> bool {
    run_scenario(Scenario {
        name: "ext4 (AC5.1)",
        secs: 90,
        config: "warden-ext4.toml",
        mem: "512M",
        accel: true,
        stage: &[("initramfs.img", "initramfs.img")], // kernel comes from ext4, not the ESP
        kernel_owns_exit: true,
        tpm: false,
        disks: &["ext4.img"],
        input: None,
        required: &[
            "Linux version 7.1.2",
            "Command line: console=ttyS0,115200 loglevel=7 warden_p5=ext4_ok",
            "WARDEN-P2-USERSPACE-OK",
        ],
        forbidden: &["WARDEN PANIC", "no matching filesystem"],
    })
}

/// AC5.2 (good) — boot a kernel read from an attached **btrfs** volume, with
/// CRC32C verification of every metadata block passing.
fn test_btrfs() -> bool {
    run_scenario(Scenario {
        name: "btrfs (AC5.2 good)",
        secs: 90,
        config: "warden-btrfs.toml",
        mem: "512M",
        accel: true,
        stage: &[("initramfs.img", "initramfs.img")],
        kernel_owns_exit: true,
        tpm: false,
        disks: &["btrfs.img"],
        input: None,
        required: &[
            "Linux version 7.1.2",
            "Command line: console=ttyS0,115200 loglevel=7 warden_p5=btrfs_ok",
            "WARDEN-P2-USERSPACE-OK",
        ],
        forbidden: &["WARDEN PANIC", "CRC32C mismatch", "no matching filesystem"],
    })
}

/// AC5.2 (reject) — a btrfs image with a corrupted metadata block is refused
/// (CRC32C mismatch), not silently used; Warden drops to rescue without a panic.
fn test_btrfs_corrupt() -> bool {
    corrupt_btrfs_metadata();
    run_scenario(Scenario {
        name: "btrfs-corrupt (AC5.2 reject)",
        secs: 30,
        config: "warden-btrfs.toml",
        mem: "512M",
        accel: true,
        stage: &[("initramfs.img", "initramfs.img")],
        kernel_owns_exit: false,
        tpm: false,
        disks: &["btrfs-bad.img"],
        input: None,
        required: &["CRC32C mismatch", "REFUSING", "WARDEN RESCUE"],
        forbidden: &["WARDEN PANIC", "Linux version 7.1.2", "WARDEN-P2-USERSPACE-OK"],
    })
}

/// Copy btrfs.img -> btrfs-bad.img and flip a byte inside the chunk-tree node
/// (physical 0x1500000, in its checksummed region) so its CRC32C no longer matches.
fn corrupt_btrfs_metadata() {
    let ta = workspace_root().join("test-assets");
    let src = ta.join("btrfs.img");
    let dst = ta.join("btrfs-bad.img");
    std::fs::copy(&src, &dst).expect("copy btrfs.img");
    let mut data = std::fs::read(&dst).expect("read btrfs-bad.img");
    let off = 0x150_0000 + 200; // inside the chunk-tree node, past its 32-byte csum
    if off < data.len() {
        data[off] ^= 0xff;
    }
    std::fs::write(&dst, &data).expect("write btrfs-bad.img");
    eprintln!("[xtask] wrote corrupted btrfs-bad.img (flipped a chunk-tree metadata byte)");
}

// ---------------------------------------------------------------------------
// P6 — A/B boot assessment test plumbing
// ---------------------------------------------------------------------------

fn mk_record(active: &str, lkg: &str, tries: u32, max: u32, gen: u64) -> warden_assess::StateRecord {
    warden_assess::StateRecord {
        generation: gen,
        active: warden_assess::id_from_str(active).expect("id fits"),
        last_known_good: warden_assess::id_from_str(lkg).expect("id fits"),
        tries_remaining: tries,
        max_tries: max,
    }
}

/// Write `test-assets/state.img`: LBA0 header + double-buffered records at LBA1/2.
fn seed_state_disk(records: &[(usize, warden_assess::StateRecord)]) {
    let ta = workspace_root().join("test-assets");
    std::fs::create_dir_all(&ta).ok();
    let mut img = vec![0u8; 1 << 20]; // 1 MiB, 512-byte sectors
    img[0..8].copy_from_slice(b"WARDNDSK");
    for (slot, rec) in records {
        let bytes = rec.encode();
        let off = 512 * (1 + slot);
        img[off..off + bytes.len()].copy_from_slice(&bytes);
    }
    std::fs::write(ta.join("state.img"), &img).expect("write state.img");
    eprintln!("[xtask] seeded state.img ({} record(s))", records.len());
}

/// Corrupt one state record in place — simulates a torn write to that buffer.
fn corrupt_state_slot(slot: usize) {
    let p = workspace_root().join("test-assets/state.img");
    let mut img = std::fs::read(&p).expect("read state.img");
    let off = 512 * (1 + slot) + 20; // a payload byte inside the record
    img[off] ^= 0xff;
    std::fs::write(&p, &img).expect("write state.img");
    eprintln!("[xtask] corrupted state.img slot {slot} (simulated torn write)");
}

/// Delete the writable OVMF vars so the next boot starts from fresh NVRAM (no
/// stale `WardenConfirm` leaking across independent P6 tests).
fn reset_ovmf_vars() {
    let _ = std::fs::remove_file(workspace_root().join(DEFAULT_OVMF_VARS_LOCAL));
}

/// One power cycle: boot warden-ab.toml with the (persistent) state disk attached.
fn p6_cycle(name: &'static str, required: &'static [&'static str], forbidden: &'static [&'static str]) -> bool {
    run_scenario(Scenario {
        name,
        secs: 90,
        config: "warden-ab.toml",
        mem: "512M",
        accel: true,
        stage: &[("vmlinuz", "vmlinuz"), ("initramfs.img", "initramfs.img")],
        kernel_owns_exit: true,
        tpm: false,
        disks: &["state.img"],
        input: None,
        required,
        forbidden,
    })
}

/// AC6.1 — a slot that never confirms auto-rolls-back after max_tries, no console.
fn test_p6_rollback() -> bool {
    reset_ovmf_vars();
    seed_state_disk(&[(0, mk_record("bad", "good", 2, 2, 1))]);
    let c1 = p6_cycle(
        "P6 AC6.1 cycle 1/3 — attempt bad",
        &["assess: Attempt", "boot 'bad'", "WARDEN-P2-USERSPACE-OK"],
        &["WARDEN PANIC", "assess: Rollback", "WARDEN-CONFIRM-SET"],
    );
    let c2 = p6_cycle(
        "P6 AC6.1 cycle 2/3 — attempt bad",
        &["assess: Attempt", "boot 'bad'"],
        &["WARDEN PANIC", "assess: Rollback"],
    );
    let c3 = p6_cycle(
        "P6 AC6.1 cycle 3/3 — auto rollback to good",
        &["assess: Rollback", "boot 'good'", "WARDEN-P2-USERSPACE-OK", "WARDEN-CONFIRM-SET"],
        &["WARDEN PANIC"],
    );
    let ok = c1 && c2 && c3;
    eprintln!("[xtask] P6 AC6.1 (auto-rollback, no console): {}", if ok { "PASS" } else { "FAIL" });
    ok
}

/// The healthy path: an unconfirmed attempt that then confirms is marked good.
fn test_p6_confirm() -> bool {
    reset_ovmf_vars();
    seed_state_disk(&[(0, mk_record("good", "good", 2, 2, 1))]);
    let c1 = p6_cycle(
        "P6 confirm 1/2 — attempt good (sets signal)",
        &["assess: Attempt", "boot 'good'", "WARDEN-CONFIRM-SET"],
        &["WARDEN PANIC", "assess: Rollback"],
    );
    let c2 = p6_cycle(
        "P6 confirm 2/2 — signal consumed, marked good",
        &["assess: Confirm", "boot 'good'"],
        &["WARDEN PANIC", "assess: Rollback"],
    );
    let ok = c1 && c2;
    eprintln!("[xtask] P6 confirm (success signal marks last-known-good): {}", if ok { "PASS" } else { "FAIL" });
    ok
}

/// AC6.2 — a torn write to one buffer leaves a valid old state; no brick.
fn test_p6_faultinject() -> bool {
    reset_ovmf_vars();
    // slot0 = older valid (gen1), slot1 = newer valid (gen2); then tear slot1.
    seed_state_disk(&[(0, mk_record("good", "good", 2, 2, 1)), (1, mk_record("good", "good", 1, 2, 2))]);
    corrupt_state_slot(1);
    let ok = p6_cycle(
        "P6 AC6.2 — torn buffer, fall back to valid old state (no brick)",
        &["assess: Attempt", "boot 'good'", "WARDEN-P2-USERSPACE-OK"],
        &["WARDEN PANIC", "no Warden state disk"],
    );
    eprintln!("[xtask] P6 AC6.2 (fault-injection, no brick): {}", if ok { "PASS" } else { "FAIL" });
    ok
}

// ---------------------------------------------------------------------------
// P7 — aarch64 port (build + QEMU virt smoke test)
// ---------------------------------------------------------------------------

const TARGET_A64: &str = "aarch64-unknown-uefi";
const EFI_ARTIFACT_A64: &str = "target/aarch64-unknown-uefi/release/warden.efi";
const ESP_A64: &str = "esp-a64";
const AAVMF_VARS_LOCAL: &str = "AAVMF_VARS.local.fd";
/// Candidate (CODE, VARS-template) AAVMF pairs — Arch (`edk2/aarch64`) and
/// Debian/Ubuntu (`AAVMF/*`, `qemu-efi-aarch64/*`). `$AAVMF_CODE` overrides the code.
const AAVMF_PAIRS: &[(&str, &str)] = &[
    ("/usr/share/edk2/aarch64/QEMU_EFI.fd", "/usr/share/edk2/aarch64/QEMU_VARS.fd"),
    ("/usr/share/AAVMF/AAVMF_CODE.fd", "/usr/share/AAVMF/AAVMF_VARS.fd"),
    ("/usr/share/qemu-efi-aarch64/QEMU_EFI.fd", "/usr/share/qemu-efi-aarch64/QEMU_VARS.fd"),
];

/// Build `warden.efi` for aarch64 and stage it as `BOOTAA64.EFI`.
fn build_a64() {
    let root = workspace_root();
    let cargo = env::var("CARGO").unwrap_or_else(|_| "cargo".into());
    eprintln!("[xtask] building warden.efi ({TARGET_A64}, release)…");
    let status = Command::new(&cargo)
        .current_dir(&root)
        .args(["build", "-p", "warden", "--release", "--target", TARGET_A64])
        .status()
        .expect("failed to spawn cargo");
    assert!(status.success(), "aarch64 warden build failed");
    let dst = root.join(ESP_A64).join("EFI/BOOT/BOOTAA64.EFI");
    std::fs::create_dir_all(dst.parent().unwrap()).expect("mkdir esp-a64");
    std::fs::copy(root.join(EFI_ARTIFACT_A64), &dst).expect("stage BOOTAA64.EFI");
    eprintln!("[xtask] staged {} -> {}", EFI_ARTIFACT_A64, dst.display());
}

/// Resolve AAVMF (aarch64 edk2) code + a writable vars copy.
fn resolve_aavmf(root: &Path) -> (String, String) {
    let (code, vars_tpl) = find_firmware("AAVMF_CODE", AAVMF_PAIRS);
    let vars = root.join(AAVMF_VARS_LOCAL);
    if !vars.exists() {
        std::fs::copy(&vars_tpl, &vars).unwrap_or_else(|e| {
            eprintln!("[xtask] cannot create writable AAVMF vars {} from {vars_tpl}: {e}", vars.display());
            exit(1);
        });
    }
    (code, vars.to_string_lossy().into_owned())
}

/// Build the reference kernel for aarch64 and stage it into the aarch64 ESP.
fn build_refkernel_a64() {
    let root = workspace_root();
    let cargo = env::var("CARGO").unwrap_or_else(|_| "cargo".into());
    eprintln!("[xtask] building refkernel (aarch64-unknown-none)…");
    let status = Command::new(&cargo)
        .current_dir(&root)
        // aarch64's tiny code model reaches the higher-half base via adrp/add; the
        // x86-only `code-model=kernel` is dropped.
        .env("RUSTFLAGS", "-C link-arg=-Trefkernel/linker.ld -C relocation-model=static")
        .args(["build", "-p", "refkernel", "--release", "--target", "aarch64-unknown-none"])
        .status()
        .expect("failed to spawn cargo for aarch64 refkernel");
    assert!(status.success(), "aarch64 refkernel build failed");
    std::fs::copy(
        root.join("target/aarch64-unknown-none/release/refkernel"),
        root.join(ESP_A64).join("refkernel"),
    )
    .expect("stage aarch64 refkernel");
}

/// Stage a fixture config into the aarch64 ESP.
fn stage_a64_config(config: &str) {
    let root = workspace_root();
    std::fs::copy(root.join("fixtures").join(config), root.join(ESP_A64).join("warden.toml")).expect("stage config");
}

/// Boot the (already-staged) aarch64 ESP under QEMU `virt` + AAVMF, capture the
/// serial log, and assert the required / forbidden markers. aarch64 runs under
/// slow TCG on an x86 host, hence the generous watchdog. `tpm` attaches an
/// emulated TPM 2.0 (swtpm via `tpm-tis-device`) for measured-boot scenarios.
fn run_a64(name: &str, secs: u64, tpm: bool, required: &[&str], forbidden: &[&str]) -> bool {
    let root = workspace_root();
    let (code, vars) = resolve_aavmf(&root);
    let swtpm = if tpm { Some(start_swtpm(&root)) } else { None };
    let mut cmd = Command::new("qemu-system-aarch64");
    cmd.current_dir(&root)
        .args(["-machine", "virt", "-cpu", "cortex-a72", "-m", "512M"])
        .args(["-drive", &format!("if=pflash,format=raw,readonly=on,file={code}")])
        .args(["-drive", &format!("if=pflash,format=raw,file={vars}")])
        .args(["-drive", &format!("format=raw,file=fat:rw:{}", root.join(ESP_A64).display())])
        .args(["-display", "none", "-serial", "stdio"]);
    if let Some((_, sock)) = &swtpm {
        cmd.args(["-chardev", &format!("socket,id=chrtpm,path={}", sock.display())])
            .args(["-tpmdev", "emulator,id=tpm0,chardev=chrtpm"])
            .args(["-device", "tpm-tis-device,tpmdev=tpm0"]);
    }
    cmd.stdout(Stdio::piped()).stderr(Stdio::inherit()).stdin(Stdio::null());

    eprintln!("[xtask] booting QEMU aarch64 ({name}, virt + AAVMF{}, watchdog {secs}s)…", if tpm { " + swtpm" } else { "" });
    let mut child = cmd.spawn().expect("failed to spawn qemu-system-aarch64");
    let mut stdout = child.stdout.take().expect("piped stdout");
    let (tx, rx) = mpsc::channel();
    let reader = thread::spawn(move || {
        let mut buf = Vec::new();
        let _ = stdout.read_to_end(&mut buf);
        let _ = tx.send(buf);
    });
    let _ = watch(&mut child, secs);
    if let Some((mut tpm, _)) = swtpm {
        let _ = tpm.kill();
        let _ = tpm.wait();
    }
    let buf = rx.recv_timeout(Duration::from_secs(5)).unwrap_or_default();
    let _ = reader.join();
    let log = String::from_utf8_lossy(&buf);
    println!("----- captured serial ({name}) -----\n{log}\n----- end serial -----");

    let mut ok = true;
    for m in required {
        let present = log.contains(m);
        eprintln!("[xtask] require {:>4}: {m:?}", if present { "OK" } else { "MISS" });
        ok &= present;
    }
    for f in forbidden {
        if log.contains(f) {
            eprintln!("[xtask] forbid  HIT: {f:?}");
            ok = false;
        }
    }
    eprintln!("[xtask] scenario {name}: {}", if ok { "PASS" } else { "FAIL" });
    ok
}

/// AC7.1 (P0/P1 on aarch64) — banner, memory-map dump, and menu render.
fn test_a64_smoke() -> bool {
    build_a64();
    stage_a64_config("warden.toml");
    run_a64(
        "aarch64 smoke (AC7.1 P0/P1)",
        150,
        false,
        &["[aarch64]", "UEFI memory map:", "memory summary:", "=== Warden boot menu ===", "auto-boot 'demo'"],
        &["WARDEN PANIC"],
    )
}

/// AC7.1 (P3 on aarch64) — measured boot: run the rich handoff with an emulated
/// TPM so `measure_and_gate` extends the PCRs and replays the event log. Verifies
/// the measured-boot gate AND the P4 handoff together on aarch64.
fn test_a64_measured() -> bool {
    build_a64();
    build_refkernel_a64();
    stage_a64_config("warden-rich.toml");
    run_a64(
        "aarch64 measured + rich (AC7.1 P3/P4)",
        150,
        true,
        &["MEASURED-BOOT GATE: PASS", "[refkernel] warden-rich kernel entered", "WARDEN-P4-KERNEL-OK"],
        &["WARDEN PANIC", "MEASURED-BOOT GATE: FAIL", "[refkernel] FATAL"],
    )
}

/// AC7.1 (P4 on aarch64) — the warden-rich custom handoff: Warden builds the
/// aarch64 (VMSAv8) page tables, exits boot services, and jumps to the reference
/// kernel, which validates the ABI contract and walks the memmap via the HHDM.
fn test_a64_rich() -> bool {
    build_a64();
    build_refkernel_a64();
    stage_a64_config("warden-rich.toml");
    run_a64(
        "aarch64 warden-rich (AC7.1 P4)",
        150,
        false,
        &[
            "jumping to warden-rich kernel",
            "[refkernel] warden-rich kernel entered",
            "[refkernel] CONTRACT OK",
            "[refkernel] usable pages (walked via HHDM)",
            "WARDEN-P4-KERNEL-OK",
        ],
        &["WARDEN PANIC", "[refkernel] FATAL"],
    )
}

// ---------------------------------------------------------------------------
// P8 — rescue shell + explicit chainloading
// ---------------------------------------------------------------------------

/// Build the chainload test app and stage it under test-assets as `hello.efi`.
fn build_chainload_hello() {
    let root = workspace_root();
    let cargo = env::var("CARGO").unwrap_or_else(|_| "cargo".into());
    eprintln!("[xtask] building chainload-hello (x86_64-unknown-uefi)…");
    let status = Command::new(&cargo)
        .current_dir(&root)
        .args(["build", "-p", "chainload-hello", "--release", "--target", "x86_64-unknown-uefi"])
        .status()
        .expect("failed to spawn cargo for chainload-hello");
    assert!(status.success(), "chainload-hello build failed");
    std::fs::create_dir_all(root.join("test-assets")).ok();
    std::fs::copy(
        root.join("target/x86_64-unknown-uefi/release/chainload-hello.efi"),
        root.join("test-assets/hello.efi"),
    )
    .expect("stage hello.efi");
}

/// AC8.2 — an entry that declares `protocol = "chainload"` launches another UEFI
/// app (and nothing is chainloaded without such an entry).
fn test_chainload() -> bool {
    build();
    stage();
    build_chainload_hello();
    run_scenario(Scenario {
        name: "chainload (AC8.2)",
        secs: 30,
        config: "warden-chainload.toml",
        mem: "512M",
        accel: true,
        stage: &[("hello.efi", "hello.efi")],
        kernel_owns_exit: false, // the chainloaded app returns; Warden stays alive
        tpm: false,
        disks: &[],
        input: None,
        required: &["chainloading 'hello'", "CHAINLOAD-TARGET-OK"],
        forbidden: &["WARDEN PANIC", "LoadImage failed", "StartImage failed"],
    })
}

/// AC8.1 — the interactive rescue shell inspects measured-boot state (`p`) and
/// boots a hand-typed entry (`2`). The default entry measures then fails to load,
/// so Warden drops to the shell with PCRs already extended.
fn test_rescue_shell() -> bool {
    build();
    stage();
    run_scenario(Scenario {
        name: "rescue shell (AC8.1)",
        secs: 90,
        config: "warden-rescue-shell.toml",
        mem: "512M",
        accel: true,
        stage: &[("vmlinuz", "vmlinuz"), ("initramfs.img", "initramfs.img")],
        kernel_owns_exit: true,
        tpm: true,
        disks: &[],
        input: Some(b"p2"),
        required: &[
            "=== WARDEN RESCUE ===",
            "PCR8 (SHA-256)",                 // `p` inspected measured-boot state
            "rescue: booting one-off entry 2", // `2` booted a hand-typed entry
            "warden_p8=rescue_boot",
            "WARDEN-P2-USERSPACE-OK",
        ],
        forbidden: &["WARDEN PANIC"],
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
        disks: &[],
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
        disks: &[],
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
    /// Extra raw disks (test-assets basenames) to attach — e.g. an ext4/btrfs image.
    disks: &'static [&'static str],
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
        disks: &[],
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
    for disk in s.disks {
        let path = root.join("test-assets").join(disk);
        cmd.args(["-drive", &format!("format=raw,file={}", path.display())]);
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
/// Pick the first firmware (CODE, VARS-template) pair whose files exist,
/// honouring `$<code_env>` as a code override. Exits with guidance if none is
/// found (so CI on Arch or Debian/Ubuntu both work without a firmware-path env).
fn find_firmware(code_env: &str, pairs: &[(&str, &str)]) -> (String, String) {
    let override_code = env::var(code_env).ok();
    if let Some(oc) = &override_code {
        // Override that names a known pair with existing files → use that pair.
        if let Some((c, v)) = pairs.iter().find(|(c, _)| c == oc) {
            if Path::new(c).exists() && Path::new(v).exists() {
                return ((*c).to_string(), (*v).to_string());
            }
        }
        // Override exists but isn't a known pair → use it + first existing vars.
        if Path::new(oc).exists() {
            if let Some((_, v)) = pairs.iter().find(|(_, v)| Path::new(v).exists()) {
                return (oc.clone(), (*v).to_string());
            }
        }
    }
    for (c, v) in pairs {
        if Path::new(c).exists() && Path::new(v).exists() {
            return ((*c).to_string(), (*v).to_string());
        }
    }
    eprintln!("[xtask] no {code_env} firmware pair found — install edk2/OVMF/AAVMF or set ${code_env}. Tried:");
    for (c, v) in pairs {
        eprintln!("          {c}  +  {v}");
    }
    exit(1);
}

/// Resolve OVMF: a firmware CODE image + a writable, per-checkout VARS copy.
fn resolve_ovmf(root: &Path) -> (String, String) {
    let (code, vars_tpl) = find_firmware("OVMF_CODE", OVMF_PAIRS);
    let vars = env::var("OVMF_VARS")
        .unwrap_or_else(|_| root.join(DEFAULT_OVMF_VARS_LOCAL).to_string_lossy().into_owned());
    if !Path::new(&vars).exists() {
        std::fs::copy(&vars_tpl, &vars).unwrap_or_else(|e| {
            eprintln!("[xtask] cannot create writable OVMF vars {vars} from {vars_tpl}: {e}");
            exit(1);
        });
        eprintln!("[xtask] created writable OVMF vars {vars} from {vars_tpl}");
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

/// Secure-Boot OVMF `CODE` images (SMM build) across Arch + Debian/Ubuntu.
const OVMF_SECBOOT_CODES: &[&str] = &[
    "/usr/share/edk2/x64/OVMF_CODE.secboot.4m.fd",
    "/usr/share/OVMF/OVMF_CODE_4M.secboot.fd",
    "/usr/share/OVMF/OVMF_CODE.secboot.fd",
];

/// Run a host tool, exiting with a message on failure.
fn run_or_die(cmd: &str, args: &[&str], desc: &str) {
    let status = Command::new(cmd).args(args).status().unwrap_or_else(|e| {
        eprintln!("[xtask] cannot run `{cmd}` ({e}) — is it installed and on PATH?");
        exit(1);
    });
    if !status.success() {
        eprintln!("[xtask] {desc} failed");
        exit(1);
    }
}

/// AC3.3 — the full Secure Boot round-trip. Sign warden.efi with a test db key,
/// enroll PK/KEK/db into an OVMF variable store (setup mode → user mode, Secure
/// Boot on), boot the signed Warden under the Secure-Boot firmware with an
/// UNSIGNED kernel entry, and confirm Warden reads `SecureBoot=1` and REFUSES the
/// entry. Requires `virt-fw-vars` (virt-firmware), `sbsign`, `openssl`, and an
/// `OVMF_CODE.secboot*` image on the host.
fn test_secure_enrolled() -> bool {
    let root = workspace_root();
    let ta = root.join("test-assets");
    std::fs::create_dir_all(&ta).ok();

    build();
    stage_config("warden-unsigned.toml");
    stage_asset("vmlinuz", "vmlinuz");
    stage_asset("initramfs.img", "initramfs.img");

    // 1. A test db keypair (RSA-2048 self-signed).
    let key = ta.join("db.key");
    let crt = ta.join("db.crt");
    if !key.exists() || !crt.exists() {
        run_or_die(
            "openssl",
            &[
                "req", "-new", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "3650",
                "-subj", "/CN=Warden Test db/",
                "-keyout", &key.to_string_lossy(),
                "-out", &crt.to_string_lossy(),
            ],
            "openssl cert generation",
        );
    }

    // 2. Sign the staged BOOTX64.EFI so the Secure-Boot firmware will load it.
    let signed = ta.join("BOOTX64.signed.efi");
    let esp_efi = root.join(ESP_TARGET);
    run_or_die(
        "sbsign",
        &[
            "--key", &key.to_string_lossy(),
            "--cert", &crt.to_string_lossy(),
            "--output", &signed.to_string_lossy(),
            &esp_efi.to_string_lossy(),
        ],
        "sbsign warden.efi",
    );
    std::fs::copy(&signed, &esp_efi).expect("stage signed BOOTX64.EFI");

    // 3. Enroll PK/KEK/db into a fresh vars store (setup → user mode).
    let (_, vars_tpl) = find_firmware("OVMF_CODE", OVMF_PAIRS);
    let enrolled = ta.join("OVMF_VARS.secboot.fd");
    let cs = crt.to_string_lossy();
    const OWNER_GUID: &str = "605dab50-e046-4300-abb6-3dd810dd8b23";
    run_or_die(
        "virt-fw-vars",
        &[
            "-i", &vars_tpl,
            "-o", &enrolled.to_string_lossy(),
            "--set-pk", OWNER_GUID, &cs,
            "--add-kek", OWNER_GUID, &cs,
            "--add-db", OWNER_GUID, &cs,
        ],
        "virt-fw-vars enrollment (install virt-firmware; ensure ~/.local/bin is on PATH)",
    );

    let secboot_code = match OVMF_SECBOOT_CODES.iter().find(|p| Path::new(p).exists()) {
        Some(p) => *p,
        None => {
            eprintln!("[xtask] no Secure-Boot OVMF code found (looked for OVMF_CODE.secboot*)");
            return false;
        }
    };
    let vars_local = root.join("OVMF_VARS.secboot.local.fd");
    std::fs::copy(&enrolled, &vars_local).expect("copy enrolled vars");

    // 4. Boot under Secure Boot. The secure variable store needs q35 + SMM.
    let mut cmd = Command::new("qemu-system-x86_64");
    cmd.current_dir(&root)
        .args(["-machine", "q35,smm=on,accel=kvm:tcg"])
        .args(["-global", "driver=cfi.pflash01,property=secure,value=on"])
        .args(["-global", "ICH9-LPC.disable_s3=1"])
        .args(["-drive", &format!("if=pflash,format=raw,unit=0,readonly=on,file={secboot_code}")])
        .args(["-drive", &format!("if=pflash,format=raw,unit=1,file={}", vars_local.display())])
        .args(["-drive", &format!("format=raw,file=fat:rw:{}", root.join("esp").display())])
        .args(["-m", "512M", "-display", "none", "-serial", "stdio"])
        .stdout(Stdio::piped())
        .stderr(Stdio::inherit())
        .stdin(Stdio::null());

    let secs = if Path::new("/dev/kvm").exists() { 40 } else { 120 };
    eprintln!("[xtask] booting Secure-Boot QEMU (enrolled PK/KEK/db + signed warden.efi, watchdog {secs}s)…");
    let mut child = cmd.spawn().expect("failed to spawn qemu-system-x86_64");
    let mut stdout = child.stdout.take().expect("piped stdout");
    let (tx, rx) = mpsc::channel();
    let reader = thread::spawn(move || {
        let mut b = Vec::new();
        let _ = stdout.read_to_end(&mut b);
        let _ = tx.send(b);
    });
    let _ = watch(&mut child, secs);
    let buf = rx.recv_timeout(Duration::from_secs(5)).unwrap_or_default();
    let _ = reader.join();
    let log = String::from_utf8_lossy(&buf);
    println!("----- captured serial (secure-enrolled) -----\n{log}\n----- end serial -----");

    let required = ["Secure Boot: ENABLED", "REFUSING to boot unsigned entry", "WARDEN RESCUE"];
    let forbidden = ["WARDEN PANIC", "Linux version"];
    let mut ok = true;
    for m in required {
        let p = log.contains(m);
        eprintln!("[xtask] require {:>4}: {m:?}", if p { "OK" } else { "MISS" });
        ok &= p;
    }
    for f in forbidden {
        if log.contains(f) {
            eprintln!("[xtask] forbid  HIT: {f:?}");
            ok = false;
        }
    }
    eprintln!("[xtask] scenario secure-enrolled (AC3.3): {}", if ok { "PASS" } else { "FAIL" });
    ok
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
