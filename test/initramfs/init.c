/* Minimal PID 1 for the P2 boot test.
 *
 * Console access is made self-contained rather than relying on the kernel's
 * built-in default /dev/console node (CONFIG_DEVTMPFS_MOUNT does NOT apply to an
 * initramfs boot): we mount devtmpfs on /dev ourselves (ignoring EBUSY if the
 * kernel already provided /dev) and open /dev/console for the marker. Then we
 * print a distinctive marker the harness greps for and power off cleanly (QEMU
 * exits) — an unambiguous "reached userspace" signal for AC2.1. Built fully
 * static; no libc at runtime.
 */
#include <fcntl.h>
#include <sys/mount.h>
#include <sys/reboot.h>
#include <unistd.h>

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
    sync();

    /* As PID 1 with CAP_SYS_BOOT, power off. QEMU exits on guest power-off. */
    reboot(RB_POWER_OFF);
    /* Should be unreachable; never return (returning from PID 1 panics). */
    for (;;) {
        pause();
    }
    return 0;
}
