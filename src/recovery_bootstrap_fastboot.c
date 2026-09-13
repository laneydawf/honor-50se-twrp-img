#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <linux/reboot.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mount.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/sysmacros.h>
#include <time.h>
#include <unistd.h>

#define BUILD_TAG "honor-jlh-twrp-v19-bringup"
#define WATCHDOG_SECONDS 180
#define LOG_LIMIT (16 * 1024 * 1024)

static int early_fd = -1, kernel_fd = -1, cache_fd = -1;
static char cache_directory[256];

static void write_all(int fd, const void *data, size_t size) {
    const char *p = data;
    while (fd >= 0 && size) {
        ssize_t count = write(fd, p, size);
        if (count < 0 && errno == EINTR) continue;
        if (count <= 0) return;
        p += count;
        size -= (size_t)count;
    }
}

static void note(const char *format, ...) {
    char message[1024];
    struct timespec when = {0};
    clock_gettime(CLOCK_BOOTTIME, &when);
    int prefix = snprintf(message, sizeof(message), "codex-twrp[%lld]: ", (long long)when.tv_sec);
    va_list args;
    va_start(args, format);
    vsnprintf(message + prefix, sizeof(message) - (size_t)prefix, format, args);
    va_end(args);
    size_t length = strlen(message);
    if (length < sizeof(message) - 1) message[length++] = '\n';
    write_all(early_fd, message, length);
    write_all(kernel_fd, message, length);
    write_all(cache_fd, message, length);
    if (cache_fd >= 0) fsync(cache_fd);
}

static void directory(const char *name, mode_t mode) {
    if (mkdir(name, mode) && errno != EEXIST) note("mkdir %s: %s", name, strerror(errno));
}

static int copy_file(const char *source, const char *destination, size_t limit) {
    int input = open(source, O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
    if (input < 0) return -1;
    int output = open(destination, O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC | O_NOFOLLOW, 0600);
    if (output < 0) { close(input); return -1; }
    char buffer[8192];
    size_t total = 0;
    while (total < limit) {
        size_t wanted = sizeof(buffer);
        if (wanted > limit - total) wanted = limit - total;
        ssize_t count = read(input, buffer, wanted);
        if (count < 0 && errno == EINTR) continue;
        if (count <= 0) break;
        write_all(output, buffer, (size_t)count);
        total += (size_t)count;
    }
    fsync(output);
    close(output);
    close(input);
    return 0;
}

static void prepare_cache(void) {
    char metadata[2048] = {0};
    int fd = open("/sys/class/block/sdc19/uevent", O_RDONLY | O_CLOEXEC);
    if (fd < 0) return;
    ssize_t count = read(fd, metadata, sizeof(metadata) - 1);
    close(fd);
    if (count <= 0 || !strstr(metadata, "\nPARTNAME=cache\n")) return;
    unsigned int major_number = 0, minor_number = 0;
    FILE *device = fopen("/sys/class/block/sdc19/dev", "r");
    if (!device) return;
    int parsed = fscanf(device, "%u:%u", &major_number, &minor_number);
    fclose(device);
    if (parsed != 2 || major_number == 0) return;
    if (mknod("/codex/cache.device", S_IFBLK | 0600, makedev(major_number, minor_number)) && errno != EEXIST) return;
    directory("/codex/cache", 0700);
    if (mount("/codex/cache.device", "/codex/cache", "ext4", MS_NOSUID | MS_NODEV | MS_NOEXEC | MS_NOATIME, NULL)) {
        note("cache log mount: %s", strerror(errno));
        return;
    }
    struct timespec when;
    clock_gettime(CLOCK_REALTIME, &when);
    for (int attempt = 0; attempt < 100; attempt++) {
        snprintf(cache_directory, sizeof(cache_directory), "/codex/cache/codex-twrp-v19-%lld-%d", (long long)when.tv_sec, attempt);
        if (!mkdir(cache_directory, 0700)) break;
        if (errno != EEXIST) { cache_directory[0] = 0; return; }
        if (attempt == 99) { cache_directory[0] = 0; return; }
    }
    char path[320];
    snprintf(path, sizeof(path), "%s/bootstrap.log", cache_directory);
    cache_fd = open(path, O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC, 0600);
    note("cache log directory %s", cache_directory);
}

static void restore_policy_files(void) {
    const char *files[] = {
        "sepolicy", "file_contexts", "plat_file_contexts", "plat_property_contexts", "vendor_file_contexts", "vendor_property_contexts",
        "system_ext_file_contexts", "system_ext_property_contexts", "product_file_contexts", "product_property_contexts",
        "odm_file_contexts", "odm_property_contexts", "plat_service_contexts", "vendor_service_contexts",
        "plat_hwservice_contexts", "vendor_hwservice_contexts", "plat_seapp_contexts", "vendor_seapp_contexts", NULL
    };
    for (int i = 0; files[i]; i++) {
        char source[256], destination[128];
        snprintf(source, sizeof(source), "/codex/policy/%s", files[i]);
        if (access(source, R_OK)) continue;
        snprintf(destination, sizeof(destination), "/%s", files[i]);
        if (copy_file(source, destination, 4 * 1024 * 1024)) note("restore %s failed: %s", files[i], strerror(errno));
        else { chmod(destination, 0644); note("restored /%s", files[i]); }
    }
    if (!rename("/vendor/etc/init", "/vendor/etc/init.honor-stock")) note("retained stock vendor rc files under init.honor-stock");
    else note("stock vendor rc rename: %s", strerror(errno));
}

static bool recovery_ui_started(void) {
    FILE *log = fopen("/tmp/recovery.log", "r");
    if (!log) return false;
    char line[2048];
    size_t read_bytes = 0;
    bool ready = false;
    while (read_bytes < 1024 * 1024 && fgets(line, sizeof(line), log)) {
        read_bytes += strlen(line);
        if (strstr(line, "I:Set page: 'main2'") || strstr(line, "I:Set page: 'fastboot'")) { ready = true; break; }
    }
    fclose(log);
    return ready;
}

static void watchdog(int reader) {
    char path[320];
    int output = open("/codex/kernel.log", O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, 0600);
    int persistent = -1;
    if (cache_directory[0]) {
        snprintf(path, sizeof(path), "%s/kernel.log", cache_directory);
        persistent = open(path, O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC, 0600);
    }
    size_t total = 0;
    bool ui_ready = false;
    struct timespec started;
    clock_gettime(CLOCK_BOOTTIME, &started);
    for (int iteration = 0;; iteration++) {
        char buffer[8192];
        while (reader >= 0 && total < LOG_LIMIT) {
            ssize_t count = read(reader, buffer, sizeof(buffer));
            if (count < 0 && errno == EINTR) continue;
            if (count <= 0) break;
            write_all(output, buffer, (size_t)count);
            write_all(persistent, buffer, (size_t)count);
            total += (size_t)count;
        }
        if (persistent >= 0) fsync(persistent);
        if (iteration % 5 == 0 && cache_directory[0]) {
            snprintf(path, sizeof(path), "%s/recovery.log", cache_directory);
            copy_file("/tmp/recovery.log", path, 1024 * 1024);
        }
        if (!ui_ready && iteration % 5 == 0 && recovery_ui_started()) {
            ui_ready = true;
            note("recovery main or fastboot page reached; automatic bootloader fallback disabled");
        }
        if (iteration % 10 == 0) {
            char state[96] = {0};
            int state_fd = open("/sys/class/udc/musb-hdrc/state", O_RDONLY | O_CLOEXEC);
            if (state_fd >= 0) { read(state_fd, state, sizeof(state) - 1); close(state_fd); }
            state[strcspn(state, "\r\n")] = 0;
            note("watchdog alive; USB=%s; hold=%d", state, access("/codex/hold", F_OK) == 0);
        }
        if (!access("/codex/stop", F_OK)) { note("log collector stopped by ADB"); break; }
        struct timespec now;
        clock_gettime(CLOCK_BOOTTIME, &now);
        if (!ui_ready && now.tv_sec - started.tv_sec >= WATCHDOG_SECONDS && access("/codex/hold", F_OK)) {
            note("no ADB hold marker after %d seconds; requesting bootloader", WATCHDOG_SECONDS);
            sync();
            syscall(SYS_reboot, LINUX_REBOOT_MAGIC1, LINUX_REBOOT_MAGIC2, LINUX_REBOOT_CMD_RESTART2, "bootloader");
            note("bootloader reboot syscall failed: %s", strerror(errno));
            break;
        }
        sleep(1);
    }
    if (persistent >= 0) { fsync(persistent); close(persistent); }
    if (output >= 0) close(output);
    if (reader >= 0) close(reader);
    _exit(0);
}

int main(int argc, char **argv) {
    if (argc == 2 && !strcmp(argv[1], "--selftest")) {
        printf("%s: static bootstrap; PID1 guard active; watchdog=%ds until recovery main page; no device changes in selftest\n", BUILD_TAG, WATCHDOG_SECONDS);
        return 0;
    }
    if (getpid() != 1) {
        fprintf(stderr, "Refusing bootstrap outside PID 1. Use --selftest.\n");
        return 2;
    }
    umask(022);
    directory("/codex", 0755);
    early_fd = open("/codex/early.log", O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, 0600);
    directory("/dev", 0755);
    directory("/proc", 0755);
    directory("/sys", 0755);
    mount("proc", "/proc", "proc", MS_NOSUID | MS_NODEV | MS_NOEXEC, NULL);
    mount("sysfs", "/sys", "sysfs", MS_NOSUID | MS_NODEV | MS_NOEXEC, NULL);
    mknod("/dev/null", S_IFCHR | 0666, makedev(1, 3));
    mknod("/dev/console", S_IFCHR | 0600, makedev(5, 1));
    mknod("/dev/kmsg", S_IFCHR | 0600, makedev(1, 11));
    kernel_fd = open("/dev/kmsg", O_WRONLY | O_CLOEXEC);
    note("%s entered static PID1 bootstrap", BUILD_TAG);
    prepare_cache();
    restore_policy_files();
    int reader = open("/dev/kmsg", O_RDONLY | O_NONBLOCK | O_CLOEXEC);
    pid_t child = fork();
    if (child == 0) watchdog(reader);
    if (reader >= 0) close(reader);
    // FirstStageMain treats a pre-existing proc/sys mount as a fatal error.
    // The collector's kmsg descriptor and cache mount survive this handoff.
    if (umount2("/proc", MNT_DETACH)) note("release proc: %s", strerror(errno));
    if (umount2("/sys", MNT_DETACH)) note("release sysfs: %s", strerror(errno));
    note("released temporary proc/sys mounts for first-stage init");
    note("executing TWRP init; collector pid=%d", child);
    char *const arguments[] = {"/init", NULL};
    execv("/system/bin/init", arguments);
    note("exec init failed: %s", strerror(errno));
    for (;;) pause();
}
