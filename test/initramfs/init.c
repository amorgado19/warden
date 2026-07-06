/* Minimal PID 1 for the P2/P6 boot tests.
 *
 * Console access is made self-contained rather than relying on the kernel's
 * built-in default /dev/console node (CONFIG_DEVTMPFS_MOUNT does NOT apply to an
 * initramfs boot): we mount devtmpfs on /dev ourselves (ignoring EBUSY if the
 * kernel already provided /dev) and open /dev/console for the marker. Then we
 * print a distinctive marker the harness greps for and power off cleanly (QEMU
 * exits) — an unambiguous "reached userspace" signal for AC2.1. Built fully
 * static; no libc at runtime.
 *
 * P6 boot-success signal (T6.3): if the kernel cmdline carries
 * `warden_confirm=<id>`, we set the UEFI variable `WardenConfirm` (Warden vendor
 * GUID) to `<id>` via efivarfs before powering off. On the next boot Warden reads
 * and deletes it, promoting `<id>` to last-known-good. An entry with no such
 * cmdline token never confirms — so it is a "bad" slot that will roll back.
 */
#include <fcntl.h>
#include <string.h>
#include <sys/mount.h>
#include <sys/reboot.h>
#include <sys/stat.h>
#include <unistd.h>

/* efivarfs path for WardenConfirm under the Warden vendor GUID
 * (guid! "57415244-454e-5354-4154-450000000001"). */
static const char CONFIRM_PATH[] =
    "/sys/firmware/efi/efivars/WardenConfirm-57415244-454e-5354-4154-450000000001";

/* If `warden_confirm=<id>` is on the cmdline, set the WardenConfirm UEFI var to
 * <id>. Best-effort; failures are non-fatal (the slot simply won't confirm). */
static void warden_confirm(int con) {
    /* Need procfs for the kernel cmdline; the minimal initramfs doesn't mount it. */
    (void)mkdir("/proc", 0755);
    (void)mount("proc", "/proc", "proc", 0, 0);
    int cf = open("/proc/cmdline", O_RDONLY);
    if (cf < 0) {
        return;
    }
    char cmd[1024];
    long n = (long)read(cf, cmd, sizeof(cmd) - 1);
    (void)close(cf);
    if (n <= 0) {
        return;
    }
    cmd[n] = 0;

    const char *key = "warden_confirm=";
    char *p = strstr(cmd, key);
    if (!p) {
        return;
    }
    p += strlen(key);
    /* Extract the id up to whitespace/end. */
    unsigned char buf[4 + 64];
    buf[0] = 0x07; /* NON_VOLATILE | BOOTSERVICE_ACCESS | RUNTIME_ACCESS */
    buf[1] = 0;
    buf[2] = 0;
    buf[3] = 0;
    int i = 0;
    /* Cap at 32 to match Warden's on-disk slot-id field (warden_assess::ID_LEN). */
    while (p[i] && p[i] != ' ' && p[i] != '\n' && p[i] != '\t' && i < 32) {
        buf[4 + i] = (unsigned char)p[i];
        i++;
    }
    if (i == 0) {
        return;
    }

    /* sysfs must be mounted first: the kernel then exposes the
     * /sys/firmware/efi/efivars directory that efivarfs mounts onto. */
    (void)mkdir("/sys", 0755);
    (void)mount("sysfs", "/sys", "sysfs", 0, 0);
    (void)mount("efivarfs", "/sys/firmware/efi/efivars", "efivarfs", 0, 0);

    int vf = open(CONFIRM_PATH, O_WRONLY | O_CREAT, 0644);
    if (vf < 0) {
        static const char err[] = "WARDEN-CONFIRM-FAILED (open)\n";
        (void)write(con, err, sizeof(err) - 1);
        return;
    }
    /* Single write of [attrs u32 LE][id bytes], as efivarfs requires. */
    if (write(vf, buf, (size_t)(4 + i)) == (ssize_t)(4 + i)) {
        static const char ok[] = "WARDEN-CONFIRM-SET\n";
        (void)write(con, ok, sizeof(ok) - 1);
    } else {
        static const char err[] = "WARDEN-CONFIRM-FAILED (write)\n";
        (void)write(con, err, sizeof(err) - 1);
    }
    (void)close(vf);
}

int main(void) {
    static const char msg[] = "\nWARDEN-P2-USERSPACE-OK\n";

    /* Ensure /dev/console exists even without the kernel's default cpio. */
    (void)mount("devtmpfs", "/dev", "devtmpfs", 0, 0); /* ignore EBUSY / errors */
    int fd = open("/dev/console", O_WRONLY);
    if (fd < 0) {
        fd = 1; /* fall back to the fd the kernel wired up, if any */
    }

    (void)write(fd, msg, sizeof(msg) - 1);
    (void)write(2, msg, sizeof(msg) - 1); /* also stderr, best-effort */

    /* P6: emit the boot-success signal if this entry asked for it. */
    warden_confirm(fd);
    sync();

    /* As PID 1 with CAP_SYS_BOOT, power off. QEMU exits on guest power-off. */
    reboot(RB_POWER_OFF);
    /* Should be unreachable; never return (returning from PID 1 panics). */
    for (;;) {
        pause();
    }
    return 0;
}
