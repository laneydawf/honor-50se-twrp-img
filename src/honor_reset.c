#define _GNU_SOURCE
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <linux/fs.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/file.h>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#ifndef HONOR_RESET_LAB
#include <linux/dm-ioctl.h>
#include <sys/mount.h>
#include <sys/sysmacros.h>
#include <sys/system_properties.h>
#endif

#define MIB (1024ULL * 1024)
#define BUILD "honor-jlh-twrp-v19-bringup\n"
struct target {
    char path[PATH_MAX];
    struct stat identity;
    uint64_t bytes;
};

static int fail(const char *message) {
    fprintf(stderr, "ERROR: %s (errno=%d: %s)\n", message, errno, strerror(errno));
    return -1;
}

static int join(char *out, size_t cap, const char *left, const char *right) {
    int n = snprintf(out, cap, "%s/%s", left, right);
    if (n < 0 || (size_t)n >= cap) { errno = ENAMETOOLONG; return fail("path too long"); }
    return 0;
}

static uint32_t le32(const unsigned char *p) {
    return (uint32_t)p[0] | (uint32_t)p[1] << 8 | (uint32_t)p[2] << 16 | (uint32_t)p[3] << 24;
}

static int same_target(const struct target *t) {
    struct stat st;
    if (lstat(t->path, &st)) return fail("target vanished");
    if (st.st_mode != t->identity.st_mode || st.st_dev != t->identity.st_dev ||
        st.st_ino != t->identity.st_ino || st.st_rdev != t->identity.st_rdev) {
        errno = ESTALE;
        return fail("target identity changed");
    }
    int fd = open(t->path, O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
    if (fd < 0) return fail("open target for validation");
    uint64_t size = (uint64_t)st.st_size;
    int rc = S_ISBLK(st.st_mode) ? ioctl(fd, BLKGETSIZE64, &size) : 0;
    close(fd);
    if (rc || size != t->bytes) { errno = EINVAL; return fail("target size changed"); }
    return 0;
}

static int run(char *const argv[]) {
    printf("RUN %s\n", argv[0]);
    fflush(NULL);
    pid_t child = fork();
    if (child < 0) return fail("fork formatter");
    if (!child) {
        int nullfd = open("/dev/null", O_RDONLY);
        if (nullfd < 0 || dup2(nullfd, STDIN_FILENO) < 0) _exit(126);
        if (nullfd != STDIN_FILENO) close(nullfd);
        execv(argv[0], argv);
        perror("exec formatter");
        _exit(127);
    }
    int status;
    pid_t done;
    do { done = waitpid(child, &status, 0); } while (done < 0 && errno == EINTR);
    if (done < 0) return fail("wait for formatter");
    if (!WIFEXITED(status) || WEXITSTATUS(status) != 0) {
        fprintf(stderr, "Tool failed: exit=%d signal=%d\n",
                WIFEXITED(status) ? WEXITSTATUS(status) : -1,
                WIFSIGNALED(status) ? WTERMSIG(status) : 0);
        errno = EIO;
        return -1;
    }
    return 0;
}

static int check_super(const struct target *t, bool f2fs) {
    if (same_target(t)) return -1;
    int fd = open(t->path, O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
    if (fd < 0) return fail("read fresh superblock");
    unsigned char buf[4096];
    int copies = f2fs ? 2 : 1;
    for (int i = 0; i < copies; ++i) {
        ssize_t n = pread(fd, buf, sizeof(buf), 1024 + (off_t)i * 4096);
        bool valid = n == (ssize_t)sizeof(buf);
        if (valid && f2fs) valid = le32(buf) == 0xf2f52010 && le32(buf + 16) == 12;
        if (valid && !f2fs) valid = buf[56] == 0x53 && buf[57] == 0xef && le32(buf + 24) == 2;
        if (!valid) { close(fd); errno = EINVAL; return fail("fresh filesystem header invalid"); }
    }
    close(fd);
    return 0;
}

static int format_pair(struct target *data, struct target *meta, const char *bin, const char *config, const char *contexts) {
    char mkf[PATH_MAX], ckf[PATH_MAX], mke[PATH_MAX], cke[PATH_MAX], labeler[PATH_MAX], loader[PATH_MAX];
    if (join(mkf, sizeof(mkf), bin, "make_f2fs") || join(ckf, sizeof(ckf), bin, "fsck.f2fs") ||
        join(mke, sizeof(mke), bin, "mke2fs") || join(cke, sizeof(cke), bin, "e2fsck") ||
        join(labeler, sizeof(labeler), bin, "e2fsdroid") || join(loader, sizeof(loader), bin, "sload_f2fs")) return -1;
    if (access(mkf, X_OK) || access(ckf, X_OK) || access(mke, X_OK) || access(cke, X_OK) ||
        access(config, R_OK) || access(labeler, X_OK) || access(loader, X_OK) || access(contexts, R_OK)) return fail("formatter payload incomplete");
    if (setenv("MKE2FS_CONFIG", config, 1)) return fail("set formatter config");
    if (same_target(data) || same_target(meta)) return -1;
    char *mkf_args[] = {mkf, "-f", "-g", "android", "-O", "encrypt,extra_attr,project_quota",
                       "-t", "1", data->path, NULL};
    char *ckf_args[] = {ckf, "--dry-run", "--no-kernel-check", data->path, NULL};
    char *load_args[] = {loader, "-t", "/data", data->path, NULL};
    puts("[1/2] Creating and checking a fresh userdata F2FS filesystem");
    if (run(mkf_args) || check_super(data, true) || run(load_args) || run(ckf_args)) return -1;
    if (same_target(meta)) return -1;
    char *mke_args[] = {mke, "-F", "-t", "ext4", "-b", "4096", "-I", "256", "-m", "0",
                       "-L", "metadata", "-E", "lazy_itable_init=0,lazy_journal_init=0",
                       meta->path, NULL};
    char *cke_args[] = {cke, "-f", "-n", meta->path, NULL};
    char *label_args[] = {labeler, "-e", "-S", (char *)contexts, "-a", "/metadata", meta->path, NULL};
    puts("[2/2] Creating and checking a fresh metadata EXT4 filesystem");
    if (run(mke_args) || check_super(meta, false) || run(label_args) || run(cke_args)) return -1;
    for (int i = 0; i < 2; ++i) {
        struct target *t = i ? meta : data;
        int fd = open(t->path, O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
        if (fd < 0) return fail("open for final fsync");
        int rc = fsync(fd);
        close(fd);
        if (rc) return fail("filesystem flush failed");
    }
    return 0;
}

#ifdef HONOR_RESET_LAB
static int new_image(struct target *t, const char *dir, const char *name, uint64_t size) {
    if (join(t->path, sizeof(t->path), dir, name)) return -1;
    int fd = open(t->path, O_RDWR | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC, 0600);
    if (fd < 0) return fail("lab refuses an existing file, link or device");
    int rc = ftruncate(fd, (off_t)size) || fstat(fd, &t->identity);
    close(fd);
    if (rc || !S_ISREG(t->identity.st_mode) || t->identity.st_nlink != 1) return fail("new lab file invalid");
    t->bytes = size;
    return 0;
}

int main(int argc, char **argv) {
    setvbuf(stdout, NULL, _IONBF, 0);
    if (argc != 6 || strcmp(argv[1], "--lab-new")) {
        fputs("Lab build: --lab-new NEW_DIRECTORY FORMATTER_DIRECTORY MKE2FS_CONFIG FILE_CONTEXTS\n", stderr);
        return 2;
    }
    if (mkdir(argv[2], 0700)) { fail("lab directory must not already exist"); return 2; }
    char canonical[PATH_MAX];
    if (!realpath(argv[2], canonical)) return 2;
    struct target data = {0}, meta = {0};
    if (new_image(&data, canonical, "userdata.img", 512 * MIB) ||
        new_image(&meta, canonical, "metadata.img", 16 * MIB)) return 2;
    if (format_pair(&data, &meta, argv[3], argv[4], argv[5])) return 1;
    puts("LAB_PASS: new regular images only; no phone partition opened");
    return 0;
}

#else
static struct target targets[2];
static bool protection_touched;
static bool own_meta_mount;
static const char *const inspect_meta = "/tmp/honor-reset-metadata";
static const char *const services[] = {
    "keystore2", "honor-keymaster", "honor-gatekeeper", "honor-teeauth",
    "honor-libteec", "honor-teecd", "vold", "applogcat", "rillogcat", "sleeplogcat"
};

static int read_small(const char *path, unsigned char *buf, size_t cap, size_t *count) {
    int fd = open(path, O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
    if (fd < 0) return -1;
    ssize_t n = read(fd, buf, cap);
    close(fd);
    if (n < 0 || (size_t)n == cap) { errno = EOVERFLOW; return -1; }
    *count = (size_t)n;
    buf[n] = 0;
    return 0;
}

static int prop_equal(const char *name, const char *expected) {
    char value[PROP_VALUE_MAX] = {0};
    __system_property_get(name, value);
    return !strcmp(value, expected);
}

static int recovery_only(bool check) {
    unsigned char tag[128];
    size_t size;
    if (getuid() != 0 || !prop_equal("ro.boot.mode", "recovery") ||
        !prop_equal("ro.product.device", "HNJLH") ||
        read_small("/codex/build.txt", tag, sizeof(tag) - 1, &size) ||
        (strcmp((char *)tag, BUILD) && !(check && !strcmp((char *)tag, "honor-jlh-twrp-v18-bringup\n")))) {
        errno = EPERM;
        return fail("production reset requires this Honor Recovery; Android is refused");
    }
    return 0;
}

static int block_target(struct target *t, const char *part, uint64_t low, uint64_t high) {
    char path[PATH_MAX], sys[PATH_MAX], expected[80];
    if (join(path, sizeof(path), "/dev/block/by-name", part) || !realpath(path, t->path)) return fail("resolve partition");
    if (strncmp(t->path, "/dev/block/", 11) || lstat(t->path, &t->identity) ||
        !S_ISBLK(t->identity.st_mode)) { errno = ENODEV; return fail("not a raw block partition"); }
    snprintf(sys, sizeof(sys), "/sys/dev/block/%u:%u/uevent", major(t->identity.st_rdev), minor(t->identity.st_rdev));
    unsigned char buf[4096];
    size_t size;
    snprintf(expected, sizeof(expected), "\nPARTNAME=%s\n", part);
    if (read_small(sys, buf + 1, sizeof(buf) - 2, &size)) return fail("read kernel partition identity");
    buf[0] = '\n';
    if (!strstr((char *)buf, expected)) { errno = ENODEV; return fail("kernel PARTNAME does not match target"); }
    int fd = open(t->path, O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
    if (fd < 0) return fail("open raw block for size");
    int rc = ioctl(fd, BLKGETSIZE64, &t->bytes);
    close(fd);
    if (rc || t->bytes < low || t->bytes > high || t->bytes % 4096) {
        errno = EINVAL; return fail("partition size outside JLH bounds");
    }
    printf("Target %s: %u:%u, %llu bytes\n", part, major(t->identity.st_rdev),
           minor(t->identity.st_rdev), (unsigned long long)t->bytes);
    return 0;
}

static int empty_dir_or_absent(const char *path) {
    DIR *d = opendir(path);
    if (!d) return errno == ENOENT ? 0 : fail("inspect update directory");
    struct dirent *e;
    int rc = 0;
    errno = 0;
    while ((e = readdir(d))) {
        if (strcmp(e->d_name, ".") && strcmp(e->d_name, "..")) { errno = EBUSY; rc = -1; break; }
    }
    if (!rc && errno) rc = -1;
    closedir(d);
    if (rc) { fprintf(stderr, "Nonempty preflight directory: %s\n", path); return fail("pending snapshot or block-device holder found"); }
    return 0;
}

static int gsi_empty_defaults(const char *view) {
    char path[PATH_MAX];
    if (join(path, sizeof(path), view, "gsi")) return -1;
    DIR *d = opendir(path);
    if (!d) return errno == ENOENT ? 0 : fail("inspect GSI state");
    struct dirent *e;
    int rc = 0;
    errno = 0;
    while ((e = readdir(d))) {
        if (!strcmp(e->d_name, ".") || !strcmp(e->d_name, "..")) continue;
        if (strcmp(e->d_name, "dsu") && strcmp(e->d_name, "ota") && strcmp(e->d_name, "remount")) { rc = -1; break; }
        char child[PATH_MAX];
        struct stat st;
        if (join(child, sizeof(child), path, e->d_name) || lstat(child, &st) || !S_ISDIR(st.st_mode) ||
            empty_dir_or_absent(child)) { rc = -1; break; }
        errno = 0;
    }
    if (!rc && errno) rc = -1;
    closedir(d);
    if (rc) { errno = EBUSY; return fail("GSI/DSU or remount images exist; reset refused"); }
    return 0;
}

static int read_mounts(bool remove_mounts, dev_t dmdev) {
    char selected[64][PATH_MAX];
    size_t count = 0;
    FILE *f = fopen("/proc/self/mountinfo", "re");
    if (!f) return fail("open mountinfo");
    char *line = NULL;
    size_t cap = 0;
    int rc = 0;
    while (getline(&line, &cap, f) > 0) {
        unsigned ma, mi;
        char root[PATH_MAX], point[PATH_MAX], options[1024];
        if (sscanf(line, "%*u %*u %u:%u %4095s %4095s %1023s", &ma, &mi, root, point, options) != 5) {
            errno = EINVAL; rc = fail("unrecognized mountinfo"); break;
        }
        dev_t dev = makedev(ma, mi);
        bool data_path = !strcmp(point, "/data") || !strncmp(point, "/data/", 6) || !strcmp(point, "/sdcard");
        bool meta_path = !strcmp(point, "/metadata") || !strncmp(point, "/metadata/", 10) || !strcmp(point, inspect_meta);
        bool data_dev = dev == targets[0].identity.st_rdev || (dmdev && dev == dmdev);
        bool meta_dev = dev == targets[1].identity.st_rdev;
        if (!data_path && !meta_path && !data_dev && !meta_dev) continue;
        bool allowed = (data_path && data_dev) || (meta_path && meta_dev);
        const char *names[] = {"mode", "ref", "per_boot_ref"};
        for (size_t j = 0; !allowed && j < 3; ++j) {
            char dest[128], source[128];
            snprintf(dest, sizeof(dest), "/data/unencrypted/%s", names[j]);
            snprintf(source, sizeof(source), "/tmp/codex-fbe-runtime/%s", names[j]);
            struct stat a, b;
            if (!strcmp(point, dest) && !stat(dest, &a) && !stat(source, &b) &&
                S_ISREG(a.st_mode) && S_ISREG(b.st_mode) && a.st_dev == b.st_dev && a.st_ino == b.st_ino) allowed = true;
        }
        if (!allowed || count == 64 || strchr(point, '\\')) {
            errno = EBUSY; rc = fail("unexpected mount involving reset targets"); break;
        }
        strcpy(selected[count++], point);
    }
    if (ferror(f)) rc = fail("read mountinfo");
    free(line);
    fclose(f);
    if (rc || !remove_mounts) return rc;
    for (size_t i = 0; i < count; ++i)
        for (size_t j = i + 1; j < count; ++j)
            if (strlen(selected[j]) > strlen(selected[i])) {
                char temp[PATH_MAX];
                strcpy(temp, selected[i]); strcpy(selected[i], selected[j]); strcpy(selected[j], temp);
            }
    for (size_t i = 0; i < count; ++i) {
        if (umount2(selected[i], 0)) return fail("target is busy; unmount refused");
        if (!strcmp(selected[i], inspect_meta)) own_meta_mount = false;
        printf("Unmounted %s\n", selected[i]);
    }
    return 0;
}

static int snapshot_check(void) {
    if (prop_equal("ro.gsid.image_running", "1") || prop_equal("ro.gsid.image_running", "true") ||
        prop_equal("init.svc.snapuserd", "running") || prop_equal("init.svc.update_engine", "running")) {
        errno = EBUSY; return fail("DSU or update service is active");
    }
    int fd = open("/dev/block/by-name/misc", O_RDONLY | O_CLOEXEC);
    if (fd < 0) return fail("read Virtual A/B status");
    unsigned char msg[64];
    ssize_t n = pread(fd, msg, sizeof(msg), 32768);
    close(fd);
    if (n != sizeof(msg)) return fail("short Virtual A/B status");
    unsigned nonzero = 0;
    for (size_t i = 0; i < sizeof(msg); ++i) nonzero |= msg[i];
    if (nonzero && ((msg[0] != 1 && msg[0] != 2) || le32(msg + 1) != 0x56740ab0 || msg[5] != 0)) {
        errno = EBUSY; return fail("Virtual A/B merge not NONE or status unknown");
    }
    struct stat st;
    const char *view = "/metadata";
    if (stat(view, &st) || st.st_dev != targets[1].identity.st_rdev) {
        if (mkdir(inspect_meta, 0700) && errno != EEXIST) return fail("create RAM metadata view");
        if (lstat(inspect_meta, &st) || !S_ISDIR(st.st_mode)) return fail("invalid RAM metadata view");
        if (mount(targets[1].path, inspect_meta, "ext4", MS_RDONLY | MS_NOSUID | MS_NODEV | MS_NOEXEC, "noload"))
            return fail("cannot inspect metadata read-only; update state unknown");
        own_meta_mount = true;
        view = inspect_meta;
    }
    char path[PATH_MAX];
    if (join(path, sizeof(path), view, "ota/state")) return -1;
    unsigned char state[4096];
    size_t size = 0;
    if (read_small(path, state, sizeof(state) - 1, &size)) {
        if (errno != ENOENT) return fail("unreadable OTA state");
    } else if (size && !(size == 4 && !memcmp(state, "none", 4)) && !(size == 2 && state[0] == 8 && state[1] == 0)) {
        errno = EBUSY; return fail("OTA state is not empty/NONE; finish the update first");
    }
    const char *dirs[] = {"ota/snapshots", "ota/images"};
    for (size_t i = 0; i < sizeof(dirs) / sizeof(dirs[0]); ++i) {
        if (join(path, sizeof(path), view, dirs[i]) || empty_dir_or_absent(path)) return -1;
    }
    if (gsi_empty_defaults(view)) return -1;
    puts("Snapshot preflight: no pending update or DSU state");
    return 0;
}

static int holders(dev_t *dmdev) {
    *dmdev = 0;
    char path[PATH_MAX];
    for (int i = 0; i < 2; ++i) {
        snprintf(path, sizeof(path), "/sys/dev/block/%u:%u/holders", major(targets[i].identity.st_rdev), minor(targets[i].identity.st_rdev));
        DIR *d = opendir(path);
        if (!d) return fail("read partition holders");
        struct dirent *e;
        int rc = 0;
        errno = 0;
        while ((e = readdir(d))) {
            if (!strcmp(e->d_name, ".") || !strcmp(e->d_name, "..")) continue;
            if (i || *dmdev || strncmp(e->d_name, "dm-", 3)) { errno = EBUSY; rc = -1; break; }
            char item[PATH_MAX], file[PATH_MAX];
            unsigned char name[128], dev[128];
            size_t ns, ds;
            if (join(item, sizeof(item), path, e->d_name) || join(file, sizeof(file), item, "dm/name") ||
                read_small(file, name, sizeof(name) - 1, &ns) || strcmp((char *)name, "userdata\n") ||
                join(file, sizeof(file), item, "dev") || read_small(file, dev, sizeof(dev) - 1, &ds)) { rc = -1; break; }
            unsigned ma, mi;
            if (sscanf((char *)dev, "%u:%u", &ma, &mi) != 2) { rc = -1; break; }
            *dmdev = makedev(ma, mi);
            if (join(file, sizeof(file), item, "holders") || empty_dir_or_absent(file)) { rc = -1; break; }
            if (join(file, sizeof(file), item, "slaves")) { rc = -1; break; }
            DIR *slaves = opendir(file);
            if (!slaves) { rc = -1; break; }
            struct dirent *s;
            size_t slaves_count = 0;
            while ((s = readdir(slaves))) {
                if (!strcmp(s->d_name, ".") || !strcmp(s->d_name, "..")) continue;
                char link[PATH_MAX];
                struct stat slave;
                if (join(link, sizeof(link), "/dev/block", s->d_name) || stat(link, &slave) ||
                    slave.st_rdev != targets[0].identity.st_rdev) { rc = -1; break; }
                ++slaves_count;
            }
            closedir(slaves);
            if (rc || slaves_count != 1) { rc = -1; break; }
            errno = 0;
        }
        if (!rc && errno) rc = -1;
        closedir(d);
        if (rc) { errno = EBUSY; return fail("unexpected block-device holder; reset refused"); }
    }
    return 0;
}

static int stop_crypto(void) {
    for (size_t i = 0; i < sizeof(services) / sizeof(services[0]); ++i) {
        char prop[PROP_NAME_MAX];
        snprintf(prop, sizeof(prop), "init.svc.%s", services[i]);
        char state[PROP_VALUE_MAX] = {0};
        __system_property_get(prop, state);
        if (state[0] && strcmp(state, "stopped") && __system_property_set("ctl.stop", services[i]))
            return fail("cannot stop data-using service");
    }
    for (int attempt = 0; attempt < 60; ++attempt) {
        bool stopped = true;
        for (size_t i = 0; i < sizeof(services) / sizeof(services[0]); ++i) {
            char prop[PROP_NAME_MAX], value[PROP_VALUE_MAX] = {0};
            snprintf(prop, sizeof(prop), "init.svc.%s", services[i]);
            __system_property_get(prop, value);
            if (value[0] && strcmp(value, "stopped")) stopped = false;
        }
        if (stopped) return 0;
        usleep(100000);
    }
    errno = EBUSY;
    return fail("crypto service did not stop");
}

static int remove_userdata_dm(dev_t expected) {
    if (!expected) return 0;
    int fd = open("/dev/device-mapper", O_RDWR | O_CLOEXEC);
    if (fd < 0) fd = open("/dev/mapper/control", O_RDWR | O_CLOEXEC);
    if (fd < 0) return fail("open device-mapper control");
    struct dm_ioctl io = {0};
    io.version[0] = 4;
    io.data_size = sizeof(io);
    io.data_start = sizeof(io);
    strcpy(io.name, "userdata");
    int rc = ioctl(fd, DM_DEV_STATUS, &io);
    if (!rc && (io.open_count || io.dev != (uint64_t)expected)) { errno = EBUSY; rc = -1; }
    if (!rc) {
        memset(&io, 0, sizeof(io));
        io.version[0] = 4;
        io.data_size = io.data_start = sizeof(io);
        strcpy(io.name, "userdata");
        rc = ioctl(fd, DM_DEV_REMOVE, &io);
    }
    close(fd);
    if (rc) return fail("userdata mapper still in use; no forced removal");
    puts("Removed idle userdata mapping (key material was not queried)");
    return 0;
}

static int set_ro(struct target *t, int ro) {
    if (same_target(t)) return -1;
    int fd = open(t->path, O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
    if (fd < 0) return fail("open target for block protection");
    int actual = -1;
    int rc = ioctl(fd, BLKROSET, &ro) || ioctl(fd, BLKROGET, &actual);
    close(fd);
    if (rc || actual != ro) return fail("block protection transition failed");
    return 0;
}

static void cleanup(void) {
    if (protection_touched) {
        for (int i = 0; i < 2; ++i) if (targets[i].path[0]) (void)set_ro(&targets[i], 1);
    }
    if (own_meta_mount && umount2(inspect_meta, 0)) perror("remove read-only metadata view");
}

int main(int argc, char **argv) {
    setvbuf(stdout, NULL, _IONBF, 0);
    bool check = argc == 2 && !strcmp(argv[1], "--check");
    bool prepare = argc == 2 && !strcmp(argv[1], "--prepare-check");
    bool execute = argc == 3 && !strcmp(argv[1], "--execute") && !strcmp(argv[2], "ERASE_ALL_DATA");
    if (!check && !prepare && !execute) {
        fputs("Use --check, --prepare-check (detach data without writes), or --execute ERASE_ALL_DATA after confirmation.\n", stderr);
        return 2;
    }
    if (recovery_only(check || prepare)) return 2;
    unsetenv("LD_PRELOAD");
    if (setenv("LD_LIBRARY_PATH", "/system/lib64:/vendor/lib64", 1)) return 2;
    int lock = open("/tmp/honor-reset.lock", O_RDWR | O_CREAT | O_CLOEXEC | O_NOFOLLOW, 0600);
    if (lock < 0 || flock(lock, LOCK_EX | LOCK_NB)) { fail("another reset is active"); return 2; }
    if (chdir("/")) return 2;
    atexit(cleanup);
    if (block_target(&targets[0], "userdata", 2ULL * 1024 * MIB, 1024ULL * 1024 * MIB) ||
        block_target(&targets[1], "metadata", 4 * MIB, 512 * MIB) ||
        targets[0].identity.st_rdev == targets[1].identity.st_rdev) return 2;
    dev_t dmdev;
    if (holders(&dmdev) || read_mounts(false, dmdev) || snapshot_check()) return 2;
    puts("Preflight passed: only userdata and metadata are reset targets");
    if (check) { puts("CHECK_ONLY: no services stopped, no keys or partitions written"); return 0; }
    puts(prepare ? "PREPARE_ONLY: detach data for validation; do not release RO or format" :
         "CONFIRMED FULL RESET: apps, lockscreen data, photos, downloads and internal storage will be erased");
    if (stop_crypto() || read_mounts(true, dmdev) || remove_userdata_dm(dmdev)) return 1;
    if (holders(&dmdev) || dmdev) { fail("userdata still has a mapper"); return 1; }
    for (int i = 0; i < 2; ++i) {
        int fd = open(targets[i].path, O_RDONLY | O_EXCL | O_CLOEXEC | O_NOFOLLOW);
        if (fd < 0) { fail("partition is still claimed"); return 1; }
        close(fd);
    }
    if (prepare) { puts("PREPARE_PASS: targets detached and unclaimed; no keys or partitions written. Reboot Recovery now."); return 0; }
    protection_touched = true;
    if (set_ro(&targets[0], 0) || set_ro(&targets[1], 0)) return 1;
    if (format_pair(&targets[0], &targets[1], "/system/bin", "/system/etc/mke2fs.conf", "/file_contexts")) return 1;
    if (set_ro(&targets[0], 1) || set_ro(&targets[1], 1)) return 1;
    puts("RESET_SUCCESS: both fresh filesystems verified. Reboot Android to initialize new encryption keys.");
    return 0;
}
#endif
