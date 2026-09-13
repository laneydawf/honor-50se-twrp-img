#define _GNU_SOURCE
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <linux/fs.h>
#include <linux/loop.h>
#include <linux/magic.h>
#include <poll.h>
#include <signal.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/file.h>
#include <sys/ioctl.h>
#include <sys/mount.h>
#include <sys/stat.h>
#include <sys/statfs.h>
#include <sys/statvfs.h>
#include <sys/sysmacros.h>
#include <sys/syscall.h>
#include <sys/system_properties.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#define CAP 512
#define MP_FLAGS (MS_NOSUID | MS_NODEV | MS_NOATIME)
static struct {
    char base[CAP], data[CAP], alias[CAP], view[CAP], pub[CAP], peer[CAP], dest[CAP];
    char raw[CAP], mapped[CAP];
    int rawfd, mapfd, lockfd, fault;
    pid_t recovery;
    unsigned long long recovery_start;
    dev_t device;
    bool bound, unlocked, writable, published;
} ctx = {.rawfd = -1, .mapfd = -1, .lockfd = -1};
static volatile sig_atomic_t stopped;

static int fail(const char *why) {
    fprintf(stderr, "HONOR_BACKUP: %s: %s (%d)\n", why, strerror(errno), errno);
    return -1;
}
static int path(char *out, const char *a, const char *b) {
    int n = snprintf(out, CAP, "%s%s", a, b);
    if (n < 0 || n >= CAP) { errno = ENAMETOOLONG; return fail("path"); }
    return 0;
}
static int regular_file(const char *name, int flags) {
    char p[CAP]; struct stat st;
    if (path(p, ctx.base, name)) return -1;
    int fd = open(p, flags | O_CLOEXEC | O_NOFOLLOW, 0600);
    if (fd < 0) return -1;
    if (fstat(fd, &st) || !S_ISREG(st.st_mode) || st.st_uid || st.st_nlink != 1) {
        close(fd); errno = EPERM; return -1;
    }
    return fd;
}
static int state_file(const char *name, const char *value) {
    int fd = regular_file(name, O_WRONLY | O_CREAT | O_TRUNC);
    if (fd < 0) return fail("session state");
    size_t n = strlen(value);
    int rc = write(fd, value, n) != (ssize_t)n;
    close(fd);
    return rc ? fail("session state write") : 0;
}
static void remove_state(const char *name) {
    char p[CAP];
    if (!path(p, ctx.base, name)) unlink(p);
}
static int readonly(const char *p, bool expected) {
    struct statvfs st;
    if (statvfs(p, &st)) return fail(p);
    if (!!(st.f_flag & ST_RDONLY) != expected) { errno = EROFS; return fail(p); }
    return 0;
}
static int ro_value(int fd, int expected) {
    int value = -1;
    if (ioctl(fd, BLKROGET, &value) || value != expected) { errno = EROFS; return fail("block readonly state"); }
    return 0;
}
static int set_ro(int fd, int value) {
    return ioctl(fd, BLKROSET, &value) || ro_value(fd, value) ? fail("set block readonly") : 0;
}
static int private_dir(const char *p) {
    struct stat st; struct statfs fs;
    if (mkdir(p, 0700) && errno != EEXIST) return fail(p);
    if (lstat(p, &st) || statfs(p, &fs) || !S_ISDIR(st.st_mode) || st.st_uid ||
        (st.st_mode & 0777) != 0700 || (fs.f_type != TMPFS_MAGIC && fs.f_type != RAMFS_MAGIC)) {
        errno = EPERM; return fail("private RAM directory");
    }
    return 0;
}
static int directory(const char *p, dev_t device) {
    struct stat st;
    if (lstat(p, &st) || !S_ISDIR(st.st_mode) || st.st_dev != device) {
        errno = EINVAL; return fail("unexpected directory or symlink");
    }
    return 0;
}
static int block(const char *p, dev_t *device) {
    char resolved[PATH_MAX]; struct stat st;
    if (!realpath(p, resolved)) return -1;
    int fd = open(resolved, O_RDONLY | O_DIRECT | O_CLOEXEC | O_NOFOLLOW);
    if (fd < 0) return -1;
    if (fstat(fd, &st) || !S_ISBLK(st.st_mode) || ro_value(fd, 1)) {
        close(fd); errno = EPERM; return -1;
    }
    *device = st.st_rdev;
    return fd;
}
static uint32_t le32(const unsigned char *p) {
    return (uint32_t)p[0] | (uint32_t)p[1] << 8 | (uint32_t)p[2] << 16 | (uint32_t)p[3] << 24;
}
static uint64_t le64(const unsigned char *p) { return le32(p) | (uint64_t)le32(p + 4) << 32; }
static uint32_t crc(const unsigned char *p, size_t n) {
    uint32_t c = F2FS_SUPER_MAGIC;
    for (size_t i = 0; i < n; i++) {
        c ^= p[i];
        for (int j = 0; j < 8; j++) c = (c >> 1) ^ (0xedb88320U & (0U - (c & 1)));
    }
    return c;
}
static bool cp_valid(const unsigned char *p) {
    unsigned n = le32(p + 164);
    return n >= 192 && n <= 4092 && crc(p, n) == le32(p + n);
}
static int clean_checkpoint(void) {
    _Alignas(4096) unsigned char super[4096], other[4096], cp[4096], end[4096], chosen[4096];
    const unsigned char *sb = super + 1024;
    uint64_t bytes = 0, version = 0; uint32_t flags = 0; bool valid = false;
    if (ioctl(ctx.mapfd, BLKGETSIZE64, &bytes) || pread(ctx.mapfd, super, sizeof(super), 0) != sizeof(super) ||
        pread(ctx.mapfd, other, sizeof(other), 4096) != sizeof(other) || memcmp(sb, other + 1024, 128) ||
        le32(sb) != F2FS_SUPER_MAGIC || le32(sb + 16) != 12 || le32(sb + 20) != 9) {
        errno = EINVAL; return fail("F2FS superblock");
    }
    uint64_t first = le32(sb + 76);
    for (int i = 0; i < 2; ++i) {
        uint64_t start = first + (uint64_t)i * 512;
        if ((start + 512) * 4096 > bytes || pread(ctx.mapfd, cp, sizeof(cp), start * 4096) != sizeof(cp) || !cp_valid(cp)) continue;
        uint32_t count = le32(cp + 136);
        if (count < 2 || count > 512 || pread(ctx.mapfd, end, sizeof(end), (start + count - 1) * 4096) != sizeof(end) ||
            !cp_valid(end) || le64(end) != le64(cp)) continue;
        uint64_t v = le64(cp);
        if (!valid || (int64_t)(v - version) > 0) {
            valid = true; version = v; flags = le32(cp + 132); memcpy(chosen, cp, sizeof(chosen));
        }
    }
    printf("Checkpoint version=%llu flags=0x%x\n", (unsigned long long)version, flags);
    if (!valid || (flags & 0x1a) || (flags & ~0x1ffU)) {
        errno = EUCLEAN; return fail("unsupported or unhealthy F2FS checkpoint");
    }
    if (flags & 1) return 0;
    uint64_t main = le32(sb + 92), segments = le32(sb + 68);
    uint64_t segno = le32(chosen + 40);
    unsigned offset = chosen[70] | (unsigned)chosen[71] << 8;
    if (!(flags & 0x40) || version > UINT32_MAX || segno >= segments || offset >= 512 ||
        (main + segments * 512) * 4096 > bytes) {
        errno = EUCLEAN; return fail("unrecognized F2FS recovery-log layout");
    }
    uint64_t address = main + segno * 512 + offset;
    uint64_t expected = version | (uint64_t)le32(chosen + le32(chosen + 164)) << 32;
    if (pread(ctx.mapfd, end, sizeof(end), address * 4096) != sizeof(end)) return fail("read recovery-log head");
    if (le64(end + 4084) == expected) {
        errno = EUCLEAN; return fail("pending F2FS recovery log; backup writes refused");
    }
    puts("F2FS checkpoint CRC valid and roll-forward log empty; no recovery writes needed.");
    return 0;
}
static unsigned long long process_start(pid_t pid, pid_t *parent) {
    char p[64], buf[4096];
    snprintf(p, sizeof(p), "/proc/%d/stat", pid);
    int fd = open(p, O_RDONLY | O_CLOEXEC);
    if (fd < 0) return 0;
    ssize_t n = read(fd, buf, sizeof(buf) - 1); close(fd);
    if (n <= 0) return 0;
    buf[n] = 0; char *q = strrchr(buf, ')');
    if (!q || q[1] != ' ') return 0;
    char *save = NULL, *token = strtok_r(q + 2, " ", &save);
    for (int field = 3; token; ++field, token = strtok_r(NULL, " ", &save)) {
        if (field == 3 && (*token == 'Z' || *token == 'X')) return 0;
        if (field == 4 && parent) *parent = (pid_t)strtol(token, NULL, 10);
        /* PID 1 can legitimately start at tick zero; reserve zero for missing. */
        if (field == 22) return strtoull(token, NULL, 10) + 1;
    }
    return 0;
}
#ifndef HONOR_BACKUP_LAB
static bool property(const char *name, const char *expected) {
    char value[PROP_VALUE_MAX]; __system_property_get(name, value);
    return !strcmp(value, expected);
}
static int dispatch(bool backup) {
    return __system_property_set("sys.honor.backup_arg", backup ? "backup" : "honor_backup_skipped=1") ||
           __system_property_set("sys.honor.backup_action", backup ? "nandroid" : "set");
}
static int guards(void) {
    const char *blocks[] = {"/dev/block/by-name/metadata", "/dev/block/by-name/persist"};
    for (size_t i = 0; i < 2; i++) {
        dev_t d; int fd = block(blocks[i], &d);
        if (fd < 0) return fail("key storage protection");
        close(fd);
    }
    return readonly("/metadata", true) || readonly("/sec_storage", true) || readonly("/data/unencrypted/key", true);
}
static int find_recovery(void) {
    DIR *dir = opendir("/proc");
    if (!dir) return -1;
    struct dirent *e;
    while ((e = readdir(dir))) {
        char *tail; long pid = strtol(e->d_name, &tail, 10);
        if (*tail || pid <= 1) continue;
        char p[64], exe[PATH_MAX];
        snprintf(p, sizeof(p), "/proc/%ld/exe", pid);
        ssize_t n = readlink(p, exe, sizeof(exe) - 1);
        if (n <= 0) continue;
        exe[n] = 0; pid_t parent = 0;
        unsigned long long start = process_start((pid_t)pid, &parent);
        if (!strcmp(exe, "/system/bin/recovery") && parent == 1 && start) {
            ctx.recovery = (pid_t)pid; ctx.recovery_start = start; break;
        }
    }
    closedir(dir);
    if (!ctx.recovery) { errno = ESRCH; return fail("Recovery process"); }
    return 0;
}
static int environment(void) {
    char build[64] = {0};
    int fd = open("/codex/build.txt", O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
    if (fd >= 0) { read(fd, build, sizeof(build) - 1); close(fd); }
    if (getuid() || strcmp(build, "honor-jlh-twrp-v19-bringup\n") ||
        !property("ro.boot.mode", "recovery") || !property("ro.boot.slot_suffix", "_a") ||
        !property("ro.product.device", "HNJLH") || !property("sys.codex.crypto_state", "services_ready") ||
        !property("twrp.all.users.decrypted", "true")) {
        errno = EPERM; return fail("Honor Recovery and decrypted storage required");
    }
    return guards() || find_recovery();
}
#else
static int dispatch(bool backup) { (void)backup; return 0; }
static int guards(void) { return 0; }
static int environment(void) { return getuid() ? -1 : 0; }
#endif
static int preflight(void) {
    if (environment() || private_dir(ctx.base)) return -1;
    dev_t rawdev;
    ctx.rawfd = block(ctx.raw, &rawdev);
    ctx.mapfd = block(ctx.mapped, &ctx.device);
    if (ctx.rawfd < 0 || ctx.mapfd < 0) return fail("open protected userdata");
#ifdef HONOR_BACKUP_LAB
    struct loop_info64 info; struct stat file; struct statfs fs; char p[CAP];
    if (path(p, ctx.base, "/../userdata.img") || stat(p, &file) || statfs(p, &fs) ||
        !S_ISREG(file.st_mode) || file.st_size != 268435456 || fs.f_type != TMPFS_MAGIC ||
        major(rawdev) != 7 || rawdev != ctx.device || ioctl(ctx.rawfd, LOOP_GET_STATUS64, &info) ||
        info.lo_inode != file.st_ino || info.lo_device != file.st_dev) {
        errno = EPERM; return fail("RAM loop fixture identity");
    }
#else
    if ((major(rawdev) != 8 && major(rawdev) != 259) || major(ctx.device) != 253) {
        errno = EPERM; return fail("userdata device class");
    }
    char p[CAP], name[128] = {0};
    snprintf(p, sizeof(p), "/sys/dev/block/%u:%u/dm/name", major(ctx.device), minor(ctx.device));
    int fd = open(p, O_RDONLY | O_CLOEXEC);
    if (fd < 0) return fail("userdata mapper name");
    read(fd, name, sizeof(name) - 1); close(fd);
    if (strcmp(name, "userdata\n")) { errno = EINVAL; return fail("wrong userdata mapper"); }
    snprintf(p, sizeof(p), "/sys/dev/block/%u:%u/slaves", major(ctx.device), minor(ctx.device));
    DIR *slaves = opendir(p); struct dirent *e; int count = 0, matching = 0;
    if (!slaves) return fail("userdata mapper backing");
    while ((e = readdir(slaves))) {
        if (e->d_name[0] == '.') continue;
        count++; char node[CAP]; struct stat st;
        if (!path(node, "/dev/block/", e->d_name) && !stat(node, &st) && st.st_rdev == rawdev) matching++;
    }
    closedir(slaves);
    if (count != 1 || matching != 1) { errno = EINVAL; return fail("unexpected mapper backing"); }
#endif
    struct statfs fsdata;
    if (statfs(ctx.data, &fsdata) || (unsigned long)fsdata.f_type != F2FS_SUPER_MAGIC ||
        directory(ctx.data, ctx.device) || directory(ctx.alias, ctx.device) ||
        readonly(ctx.data, true) || readonly(ctx.alias, true) || clean_checkpoint()) return -1;
    char media_path[CAP];
    if (path(media_path, ctx.data, "/media") || directory(media_path, ctx.device) ||
        path(media_path, ctx.data, "/media/0") || directory(media_path, ctx.device)) return -1;
    if (private_dir(ctx.base) || private_dir(ctx.view)) return -1;
    ctx.lockfd = regular_file("/lock", O_RDWR | O_CREAT);
    if (ctx.lockfd < 0 || flock(ctx.lockfd, LOCK_EX | LOCK_NB)) return fail("backup session already active");
    return 0;
}
static int inject(int point) {
    if (ctx.fault != point) return 0;
    errno = EIO; return fail("injected RAM-lab failure");
}
static int add_directory(int parent, const char *name) {
    bool added = !mkdirat(parent, name, 0770);
    if (!added && errno != EEXIST) return -1;
    int fd = openat(parent, name, O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW);
    if (fd < 0) return -1;
    struct stat st;
    if (fstat(fd, &st) || st.st_dev != ctx.device || (added && (fchown(fd, 1023, 1023) || fchmod(fd, 0770)))) {
        close(fd); return -1;
    }
    return fd;
}
static int begin_mounts(void) {
    if (mount(ctx.data, ctx.view, NULL, MS_BIND, NULL)) return fail("private storage view");
    ctx.bound = true;
    if (mount(NULL, ctx.view, NULL, MS_PRIVATE, NULL) || inject(1)) return -1;
    ctx.unlocked = true;
    if (set_ro(ctx.rawfd, 0) || set_ro(ctx.mapfd, 0) || inject(2)) return -1;
    if (mount(NULL, ctx.view, "f2fs", MS_REMOUNT | MP_FLAGS, "inlinecrypt,background_gc=off,nodiscard")) return fail("backup filesystem preparation");
    ctx.writable = true;
    if (readonly(ctx.data, true) || readonly(ctx.alias, true) || readonly(ctx.view, false) || guards() || inject(3)) return -1;
    char media[CAP];
    if (path(media, ctx.view, "/media/0")) return -1;
    int parent = open(media, O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW);
    if (parent < 0) return fail("decrypted internal storage");
    int twrp = add_directory(parent, "TWRP"); close(parent);
    if (twrp < 0) return fail("TWRP directory");
    int backups = add_directory(twrp, "BACKUPS"); close(twrp);
    if (backups < 0) return fail("BACKUPS directory");
    close(backups);
    if (inject(4) || mount(ctx.dest, ctx.pub, NULL, MS_BIND, NULL)) return fail("publish backup directory");
    ctx.published = true;
    if (readonly(ctx.pub, false) || readonly(ctx.peer, false) || readonly(ctx.data, true) || readonly(ctx.alias, true) || guards() || inject(5)) return -1;
    puts("Only TWRP/BACKUPS is writable; original data and key paths remain read-only.");
    return 0;
}
static int cleanup(void) {
    int rc = 0;
    if (ctx.writable) {
        int fd = open(ctx.view, O_RDONLY | O_DIRECTORY | O_CLOEXEC);
        if (fd < 0 || syscall(SYS_syncfs, fd)) { fail("backup sync"); rc = 1; }
        if (fd >= 0) close(fd);
    }
    if (ctx.published && umount2(ctx.pub, 0)) {
        fail("unpublish backup directory"); rc = 1;
        if (umount2(ctx.pub, MNT_DETACH)) fail("detach stale backup view");
    }
    if (ctx.writable) {
        int result = -1;
        for (int i = 0; i < 30; i++) {
            result = mount(NULL, ctx.view, "f2fs", MS_REMOUNT | MS_RDONLY | MP_FLAGS,
                           "inlinecrypt,background_gc=on,discard");
            if (!result || errno != EBUSY) break;
            usleep(100000);
        }
        if (result) { fail("restore F2FS readonly"); rc = 1; }
        else if (mount(NULL, ctx.view, "f2fs", MS_REMOUNT | MS_RDONLY | MP_FLAGS,
                       "norecovery,inlinecrypt,background_gc=on,discard")) {
            fail("restore norecovery"); rc = 1;
        }
    }
    if (ctx.unlocked) {
        if (set_ro(ctx.mapfd, 1)) rc = 1;
        if (set_ro(ctx.rawfd, 1)) rc = 1;
    }
    if (ctx.bound && umount2(ctx.view, 0)) { fail("remove private view"); rc = 1; }
    if (readonly(ctx.data, true) || readonly(ctx.alias, true) || guards() ||
        ro_value(ctx.rawfd, 1) || ro_value(ctx.mapfd, 1)) rc = 1;
    if (access(ctx.pub, F_OK) == 0 && readonly(ctx.pub, true)) rc = 1;
    if (access(ctx.peer, F_OK) == 0 && readonly(ctx.peer, true)) rc = 1;
    if (ctx.writable && !rc && clean_checkpoint()) rc = 1;
    puts(rc ? "BACKUP_CLEANUP_FAILED" : "BACKUP_READONLY_RESTORED");
    return rc;
}
static void on_signal(int sig) { stopped = sig; }
static void daemon_run(int response) {
    signal(SIGTERM, on_signal); signal(SIGINT, on_signal); signal(SIGHUP, on_signal); signal(SIGPIPE, SIG_IGN);
    setsid(); chdir("/");
    int log = regular_file("/session.log", O_WRONLY | O_CREAT | O_TRUNC);
    int nullfd = open("/dev/null", O_RDONLY | O_CLOEXEC);
    if (log < 0 || nullfd < 0 || dup2(nullfd, 0) < 0 || dup2(log, 1) < 0 || dup2(log, 2) < 0) _exit(2);
    close(log); close(nullfd);
    char pid[64]; snprintf(pid, sizeof(pid), "%d\n", getpid());
    state_file("/pid", pid);
    int rc = begin_mounts();
    if (rc || stopped || dispatch(true)) {
        cleanup(); state_file("/result", "1\n"); dispatch(false);
        char answer = '1'; write(response, &answer, 1); close(response); _exit(1);
    }
    char answer = '0';
    if (write(response, &answer, 1) != 1) stopped = SIGPIPE;
    close(response);
    time_t deadline = time(NULL) + 24 * 60 * 60;
    while (!stopped) {
        int done = regular_file("/finish", O_RDONLY);
        if (done >= 0) { close(done); break; }
        if (errno != ENOENT || process_start(ctx.recovery, NULL) != ctx.recovery_start || time(NULL) > deadline) {
            puts("Recovery session ended; closing backup storage."); stopped = SIGTERM; break;
        }
        usleep(100000);
    }
    rc = cleanup();
    state_file("/result", rc ? "1\n" : "0\n");
    dispatch(false);
    _exit(rc);
}
static int begin(void) {
    if (dispatch(false) || preflight()) return 1;
    remove_state("/finish"); remove_state("/result"); remove_state("/pid");
    int p[2];
    if (pipe2(p, O_CLOEXEC)) return 1;
    fflush(NULL);
    pid_t child = fork();
    if (child < 0) return 1;
    if (!child) { close(p[0]); daemon_run(p[1]); }
    close(p[1]);
    char answer = '1'; struct pollfd fds = {.fd = p[0], .events = POLLIN};
    if (poll(&fds, 1, 45000) <= 0 || read(p[0], &answer, 1) != 1) {
        kill(child, SIGTERM); answer = '1';
    }
    close(p[0]); close(ctx.lockfd); ctx.lockfd = -1;
    if (answer != '0') { puts("Backup storage could not be prepared. See /tmp/honor-backup-store/session.log"); return 1; }
    puts("BACKUP_STORAGE_READY");
    return 0;
}
static int end(int prepare_status, int backup_status) {
    if (private_dir(ctx.base)) return 1;
    int lock = regular_file("/lock", O_RDWR | O_CREAT);
    if (lock < 0) return 1;
    if (flock(lock, LOCK_EX | LOCK_NB)) {
        if (errno != EWOULDBLOCK || state_file("/finish", "end\n")) { close(lock); return 1; }
        bool acquired = false;
        for (int i = 0; i < 450; i++) {
            if (!flock(lock, LOCK_EX | LOCK_NB)) { acquired = true; break; }
            usleep(100000);
        }
        if (!acquired) { close(lock); errno = ETIMEDOUT; return fail("backup cleanup timeout") != 0; }
    }
    char result = '1'; int fd = regular_file("/result", O_RDONLY);
    if (fd >= 0) { if (read(fd, &result, 1) != 1) result = '1'; close(fd); }
    close(lock);
    if (prepare_status || backup_status || result != '0') { puts("BACKUP_FAILED_OR_CANCELLED_WITH_ERROR"); return 1; }
    puts("BACKUP_FINISHED_AND_READONLY_RESTORED");
    return 0;
}
#ifdef HONOR_BACKUP_LAB
static int snapshot_fixture(const char *root, const char *source) {
    if (private_dir(root)) return 1;
    int input = open(source, O_RDONLY | O_DIRECT | O_CLOEXEC);
    struct stat st, backing; struct statfs fs; struct loop_info64 info;
    uint64_t size = 0;
    if (input < 0 || fstat(input, &st) || !S_ISBLK(st.st_mode) || major(st.st_rdev) != 7 ||
        ioctl(input, BLKGETSIZE64, &size) || size != 268435456 || ioctl(input, LOOP_GET_STATUS64, &info) ||
        strnlen((char *)info.lo_file_name, LO_NAME_SIZE) >= LO_NAME_SIZE ||
        strncmp((char *)info.lo_file_name, "/tmp/honor-backup-lab-", 22) ||
        stat((char *)info.lo_file_name, &backing) || statfs((char *)info.lo_file_name, &fs) ||
        !S_ISREG(backing.st_mode) || fs.f_type != TMPFS_MAGIC || backing.st_ino != info.lo_inode || backing.st_dev != info.lo_device) {
        errno = EPERM; return fail("snapshot requires a new RAM loop fixture") != 0;
    }
    char dest[CAP];
    if (path(dest, root, "/userdata.img")) return 1;
    int output = open(dest, O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC | O_NOFOLLOW, 0600);
    if (output < 0) return 1;
    unsigned char *buffer = NULL;
    if (posix_memalign((void **)&buffer, 4096, 1048576)) return 1;
    for (uint64_t offset = 0; offset < size; offset += 1048576) {
        if (pread(input, buffer, 1048576, offset) != 1048576 || write(output, buffer, 1048576) != 1048576) {
            fail("direct snapshot I/O"); return 1;
        }
    }
    close(input); close(output); free(buffer);
    puts("RAM_SNAPSHOT_CREATED_WITH_DIRECT_READS");
    return 0;
}
#endif
int main(int argc, char **argv) {
    setvbuf(stdout, NULL, _IONBF, 0);
#ifdef HONOR_BACKUP_LAB
    if (argc < 5 || strncmp(argv[2], "/tmp/honor-backup-lab-", 22) || strstr(argv[2], "/../") ||
        strchr(argv[2] + 22, '/')) return 2;
    if (path(ctx.base, argv[2], "/guard") || path(ctx.data, argv[2], "/data") ||
        path(ctx.alias, argv[2], "/sdcard") || path(ctx.raw, argv[3], "") || path(ctx.mapped, argv[3], "")) return 2;
    ctx.recovery = (pid_t)strtol(argv[4], NULL, 10);
    ctx.recovery_start = process_start(ctx.recovery, NULL);
    if (!ctx.recovery_start) return 2;
    if (argc > 5) ctx.fault = atoi(argv[5]);
    if (!strcmp(argv[1], "--snapshot")) return snapshot_fixture(argv[2], argv[3]);
#else
    if (argc < 2) return 2;
    strcpy(ctx.base, "/tmp/honor-backup-store"); strcpy(ctx.data, "/data"); strcpy(ctx.alias, "/sdcard");
    strcpy(ctx.raw, "/dev/block/by-name/userdata"); strcpy(ctx.mapped, "/dev/block/mapper/userdata");
#endif
    if (path(ctx.view, ctx.base, "/view") || path(ctx.pub, ctx.data, "/media/0/TWRP/BACKUPS") ||
        path(ctx.peer, ctx.alias, "/TWRP/BACKUPS") || path(ctx.dest, ctx.view, "/media/0/TWRP/BACKUPS")) return 2;
    if (!strcmp(argv[1], "--check")) {
        int rc = preflight();
        if (!rc) puts("BACKUP_CHECK_PASSED: no userdata writes");
        return rc != 0;
    }
    if (!strcmp(argv[1], "--begin")) return begin();
#ifdef HONOR_BACKUP_LAB
    if (!strcmp(argv[1], "--end") && argc == 8) return end(atoi(argv[6]), atoi(argv[7]));
#else
    if (!strcmp(argv[1], "--end") && argc == 4 && strlen(argv[2]) == 1 && strlen(argv[3]) == 1 &&
        (argv[2][0] == '0' || argv[2][0] == '1') && (argv[3][0] == '0' || argv[3][0] == '1')) return end(atoi(argv[2]), atoi(argv[3]));
#endif
    return 2;
}
