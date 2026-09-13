#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <linux/fs.h>
#include <linux/fscrypt.h>
#include <linux/keyctl.h>
#include <linux/magic.h>
#include <linux/posix_acl.h>
#include <linux/posix_acl_xattr.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/mount.h>
#include <sys/stat.h>
#include <sys/statfs.h>
#include <sys/statvfs.h>
#include <sys/syscall.h>
#include <sys/system_properties.h>
#include <sys/xattr.h>
#include <unistd.h>

#define RAM_DIR "/tmp/codex-fbe-runtime"
static const char *const names[] = {"mode", "ref", "per_boot_ref"};
static const char *const protected_blocks[] = {
    "/dev/block/by-name/metadata", "/dev/block/by-name/persist",
    "/dev/block/by-name/userdata", "/dev/block/mapper/userdata"
};
static bool recovery_environment;

static void note(const char *format, ...) {
    int saved = errno;
    int fd = open("/tmp/data-runtime.log", O_WRONLY | O_APPEND | O_CREAT | O_CLOEXEC | O_NOFOLLOW, 0600);
    if (fd >= 0) {
        va_list ap;
        va_start(ap, format);
        vdprintf(fd, format, ap);
        va_end(ap);
        dprintf(fd, "\n");
        close(fd);
    }
    errno = saved;
}

static bool is_recovery(void) {
    char mode[PROP_VALUE_MAX] = {0};
    char tag[64] = {0};
    __system_property_get("ro.boot.mode", mode);
    int fd = open("/codex/build.txt", O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
    if (fd < 0) return false;
    ssize_t size = read(fd, tag, sizeof(tag) - 1);
    close(fd);
    return getuid() == 0 && !strcmp(mode, "recovery") && size > 15 &&
           !strncmp(tag, "honor-jlh-twrp-", 15);
}

static int fs_kind(int fd, bool ram) {
    struct statfs fs;
    struct statvfs flags;
    if (fstatfs(fd, &fs) || fstatvfs(fd, &flags)) return -1;
    if (ram) {
        if ((fs.f_type == TMPFS_MAGIC || fs.f_type == RAMFS_MAGIC) && !(flags.f_flag & ST_RDONLY)) return 0;
    } else if ((unsigned long)fs.f_type == F2FS_SUPER_MAGIC && (flags.f_flag & ST_RDONLY)) {
        return 0;
    }
    errno = EROFS;
    return -1;
}

static int write_all(int fd, const void *data, size_t size) {
    const unsigned char *p = data;
    while (size) {
        ssize_t n = write(fd, p, size);
        if (n < 0 && errno == EINTR) continue;
        if (n <= 0) return -1;
        size -= (size_t)n;
        p += n;
    }
    return 0;
}

static int read_small(int fd, unsigned char *data, size_t cap, size_t *size) {
    struct stat st;
    if (fstat(fd, &st)) return -1;
    if (!S_ISREG(st.st_mode) || st.st_size < 0 || (unsigned long long)st.st_size >= cap) {
        errno = EINVAL;
        return -1;
    }
    *size = 0;
    while (*size < (size_t)st.st_size) {
        ssize_t n = pread(fd, data + *size, (size_t)st.st_size - *size, (off_t)*size);
        if (n < 0 && errno == EINTR) continue;
        if (n <= 0) { errno = EIO; return -1; }
        *size += (size_t)n;
    }
    return 0;
}

static bool same_file(const char *left, const char *right) {
    struct stat a, b;
    return !lstat(left, &a) && !lstat(right, &b) && S_ISREG(a.st_mode) &&
           S_ISREG(b.st_mode) && a.st_dev == b.st_dev && a.st_ino == b.st_ino;
}

static int protect_blocks(void) {
    int ro = 1;
    for (size_t i = 0; i < sizeof(protected_blocks) / sizeof(protected_blocks[0]); ++i) {
        int fd = open(protected_blocks[i], O_RDONLY | O_CLOEXEC);
        if (fd < 0) return -1;
        int rc = (int)syscall(SYS_ioctl, fd, BLKROSET, &ro);
        int saved = errno;
        close(fd);
        if (rc) { errno = saved; return -1; }
    }
    return 0;
}

static int runtime_install(void) {
    if (!is_recovery()) { errno = EPERM; return -1; }
    /* The key directory must remain on the original read-only F2FS mount. */
    int key = open("/data/unencrypted/key", O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW);
    if (key < 0) return -1;
    int rc = fs_kind(key, false);
    close(key);
    if (rc || protect_blocks()) return -1;
    if (mkdir(RAM_DIR, 0700) && errno != EEXIST) return -1;
    int ram = open(RAM_DIR, O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW);
    if (ram < 0) return -1;
    struct stat rootst;
    rc = fstat(ram, &rootst);
    if (rc || rootst.st_uid != 0 || (rootst.st_mode & 0777) != 0700 || fs_kind(ram, true)) {
        close(ram);
        errno = EPERM;
        return -1;
    }
    close(ram);
    bool added[3] = {false, false, false};
    for (size_t i = 0; i < 3; ++i) {
        char target[128], source[128];
        snprintf(target, sizeof(target), "/data/unencrypted/%s", names[i]);
        snprintf(source, sizeof(source), RAM_DIR "/%s", names[i]);
        if (same_file(target, source)) continue;
        int input = open(target, O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
        if (input < 0) goto fail;
        unsigned char buffer[4096];
        size_t length = 0;
        struct stat st;
        rc = fs_kind(input, false) || fstat(input, &st) || read_small(input, buffer, sizeof(buffer), &length);
        close(input);
        if (rc) goto fail;
        int output = open(source, O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC | O_NOFOLLOW, 0600);
        if (output < 0) goto fail;
        rc = fs_kind(output, true) || fchown(output, st.st_uid, st.st_gid) ||
             fchmod(output, st.st_mode & 0777) || write_all(output, buffer, length) || fsync(output);
        memset(buffer, 0, sizeof(buffer));
        close(output);
        if (rc) goto fail;
        if (syscall(SYS_mount, source, target, NULL, MS_BIND, NULL)) goto fail;
        added[i] = true;
        if (!same_file(target, source)) { errno = EIO; goto fail; }
        note("RAM runtime bind ready: %s", target);
    }
    note("All three runtime files are in RAM; original key directory and data remain read-only");
    return 0;
fail:
    {
        int saved = errno;
        for (int i = 2; i >= 0; --i) {
            if (added[i]) {
                char target[128];
                snprintf(target, sizeof(target), "/data/unencrypted/%s", names[i]);
                syscall(SYS_umount2, target, 0);
            }
        }
        note("RAM runtime installation failed: errno=%d", saved);
        errno = saved;
        return -1;
    }
}

#ifndef RUNTIME_PROGRAM
static void prepare_fscrypt_keyring(void) {
    long keyring = syscall(SYS_keyctl, KEYCTL_SEARCH, KEY_SPEC_SESSION_KEYRING, "keyring", "fscrypt", 0);
    if (keyring >= 0) {
        note("Existing fscrypt session keyring is available");
        return;
    }
    if (errno != ENOKEY) {
        note("fscrypt keyring lookup failed: errno=%d", errno);
        return;
    }
    keyring = syscall(SYS_add_key, "keyring", "fscrypt", NULL, 0, KEY_SPEC_SESSION_KEYRING);
    if (keyring < 0) note("fscrypt keyring creation failed: errno=%d", errno);
    else note("Created empty fscrypt keyring in the inherited session; no disk changes");
}

__attribute__((constructor)) static void loaded(void) {
    recovery_environment = is_recovery();
    /* Do not preload into mount helpers, TEE clients, or other subprocesses. */
    unsetenv("LD_PRELOAD");
    if (recovery_environment) {
        note("Recovery read-only runtime library loaded");
        prepare_fscrypt_keyring();
    }
}

int mount(const char *source, const char *target, const char *kind,
          unsigned long flags, const void *data) {
    bool data_mount = recovery_environment && target && !strcmp(target, "/data") &&
                      !(flags & (MS_BIND | MS_MOVE));
    if (data_mount && !(flags & MS_RDONLY)) {
        note("Refused a writable /data mount");
        errno = EROFS;
        return -1;
    }
    int rc = (int)syscall(SYS_mount, source, target, kind, flags, data);
    int saved = errno;
    if (!rc && data_mount) {
        if (runtime_install()) note("Post-mount runtime setup failed: errno=%d", errno);
    }
    errno = saved;
    return rc;
}

/* The kernel normalizes IDs on non-named ACL entries to ACL_UNDEFINED_ID.
 * Only ACL_USER and ACL_GROUP IDs carry semantics; tags and permissions must
 * match on every entry. Neither missing nor different ACLs are accepted.
 */
static bool same_acl(const void *a, const void *b, size_t size) {
    if (size < sizeof(struct posix_acl_xattr_header) ||
        (size - sizeof(struct posix_acl_xattr_header)) % sizeof(struct posix_acl_xattr_entry)) return false;
    const struct posix_acl_xattr_header *left = a, *right = b;
    if (left->a_version != POSIX_ACL_XATTR_VERSION || right->a_version != left->a_version) return false;
    const struct posix_acl_xattr_entry *x = (const void *)(left + 1), *y = (const void *)(right + 1);
    size_t count = (size - sizeof(*left)) / sizeof(*x);
    if (count < 3) return false;
    for (size_t i = 0; i < count; ++i) {
        if (x[i].e_tag != y[i].e_tag || x[i].e_perm != y[i].e_perm || (x[i].e_perm & ~7)) return false;
        switch (x[i].e_tag) {
            case ACL_USER: case ACL_GROUP:
                if (x[i].e_id != y[i].e_id) return false;
                break;
            case ACL_USER_OBJ: case ACL_GROUP_OBJ: case ACL_MASK: case ACL_OTHER:
                break;
            default: return false;
        }
    }
    return true;
}

int setxattr(const char *path, const char *name, const void *value, size_t size, int flags) {
    if (recovery_environment && path && !strncmp(path, "/data/", 6) && name &&
        !strcmp(name, "system.posix_acl_default") && value && size <= 4096 && flags == 0) {
        int saved = errno;
        int fd = open(path, O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW);
        if (fd >= 0) {
            if (!fs_kind(fd, false)) {
                unsigned char current[4096];
                ssize_t length = fgetxattr(fd, name, current, sizeof(current));
                int error = errno;
                close(fd);
                if (length < 0) { errno = error; return -1; }
                if ((size_t)length == size && same_acl(current, value, size)) {
                    note("Verified existing matching default ACL without writes: %s", path);
                    errno = saved;
                    return 0;
                }
                note("Rejected mismatching default ACL on read-only data: %s", path);
                errno = EINVAL;
                return -1;
            }
            close(fd);
        }
        errno = saved;
    }
    return (int)syscall(SYS_setxattr, path, name, value, size, flags);
}

/* Bionic's ioctl ABI uses int for the request. Unhandled requests pass through. */
int ioctl(int fd, int request, ...) {
    va_list ap;
    va_start(ap, request);
    void *arg = va_arg(ap, void *);
    va_end(ap);
    if (recovery_environment && (unsigned int)request == FS_IOC_SET_ENCRYPTION_POLICY && arg) {
        int saved = errno;
        struct stat st;
        char proc[64], path[4096];
        snprintf(proc, sizeof(proc), "/proc/self/fd/%d", fd);
        ssize_t length = readlink(proc, path, sizeof(path) - 1);
        if (length > 0) path[length] = 0;
        if (length > 6 && !strncmp(path, "/data/", 6) && !fstat(fd, &st) &&
            S_ISDIR(st.st_mode) && !fs_kind(fd, false)) {
            struct fscrypt_get_policy_ex_arg current = {.policy_size = sizeof(current.policy)};
            if (syscall(SYS_ioctl, fd, FS_IOC_GET_ENCRYPTION_POLICY_EX, &current)) return -1;
            unsigned version = *(const unsigned char *)arg;
            size_t size = version == FSCRYPT_POLICY_V2 ? sizeof(struct fscrypt_policy_v2) :
                          version == FSCRYPT_POLICY_V1 ? sizeof(struct fscrypt_policy_v1) : 0;
            if (size && current.policy_size == size && !memcmp(&current.policy, arg, size)) {
                note("Verified existing matching encryption policy without writes: %s", path);
                errno = saved;
                return 0;
            }
            note("Rejected mismatching encryption policy on read-only data: %s", path);
            errno = EINVAL;
            return -1;
        }
        errno = saved;
    }
    if (recovery_environment && request == BLKROSET && arg && *(const int *)arg == 0) {
        struct stat supplied, expected;
        if (!fstat(fd, &supplied) && S_ISBLK(supplied.st_mode)) {
            for (size_t i = 0; i < sizeof(protected_blocks) / sizeof(protected_blocks[0]); ++i) {
                if (i >= 2 && access("/dev/block/mapper/userdata", F_OK)) continue;
                if (!stat(protected_blocks[i], &expected) && supplied.st_rdev == expected.st_rdev) {
                    int ro = 1;
                    int rc = (int)syscall(SYS_ioctl, fd, BLKROSET, &ro);
                    note("Applied read-only block policy for %s: rc=%d", protected_blocks[i], rc);
                    return rc;
                }
            }
        }
    }
    return (int)syscall(SYS_ioctl, fd, (unsigned int)request, arg);
}
#else
static int verify_ram_writes(void) {
    for (size_t i = 0; i < 3; ++i) {
        char target[128], source[128];
        snprintf(target, sizeof(target), "/data/unencrypted/%s", names[i]);
        snprintf(source, sizeof(source), RAM_DIR "/%s", names[i]);
        if (!same_file(target, source)) { errno = EINVAL; return -1; }
        int fd = open(target, O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
        if (fd < 0) return -1;
        unsigned char buffer[4096];
        size_t length = 0;
        int rc = fs_kind(fd, true) || read_small(fd, buffer, sizeof(buffer), &length);
        close(fd);
        if (rc) return -1;
        fd = open(target, O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC | O_NOFOLLOW, 0666);
        if (fd < 0) return -1;
        rc = write_all(fd, buffer, length) || fsync(fd);
        memset(buffer, 0, sizeof(buffer));
        close(fd);
        if (rc) return -1;
        printf("RAM write+fsync passed: %s (%zu bytes)\n", target, length);
    }
    return 0;
}

static int remove_binds(void) {
    for (int i = 2; i >= 0; --i) {
        char target[128], source[128];
        snprintf(target, sizeof(target), "/data/unencrypted/%s", names[i]);
        snprintf(source, sizeof(source), RAM_DIR "/%s", names[i]);
        if (same_file(target, source) && syscall(SYS_umount2, target, 0)) return -1;
    }
    return 0;
}

int main(int argc, char **argv) {
    if (argc == 2 && !strcmp(argv[1], "--selftest")) {
        puts("Three-file RAM overlay; recovery-only; original F2FS must be read-only; no key blob writes");
        return 0;
    }
    if (!is_recovery()) { fputs("Refusing outside this Honor recovery\n", stderr); return 2; }
    int rc;
    if (argc == 2 && !strcmp(argv[1], "--install")) rc = runtime_install();
    else if (argc == 2 && !strcmp(argv[1], "--verify-ram-writes")) rc = verify_ram_writes();
    else if (argc == 2 && !strcmp(argv[1], "--remove-binds")) rc = remove_binds();
    else { fputs("Expected --install, --verify-ram-writes, or --remove-binds\n", stderr); return 2; }
    if (rc) { perror("Runtime overlay"); return 1; }
    return 0;
}
#endif
