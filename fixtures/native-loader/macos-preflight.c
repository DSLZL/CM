/* Tiny Darwin controls; a working dlopen alone never qualifies frozen loading. */
#include <CommonCrypto/CommonDigest.h>
#include <arpa/inet.h>
#include <dlfcn.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <spawn.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>

#ifdef CM_PAYLOAD
static int constructed;

__attribute__((constructor)) static void initialize(void) {
    const char *marker = getenv("CM_PREFLIGHT_MARKER");
    const char *verified = getenv("CM_PREFLIGHT_VERIFIED");
    if (!marker || !verified || strcmp(verified, "yes") != 0)
        _exit(91);
    int fd = open(marker, O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC, 0600);
    if (fd < 0 || write(fd, "verified-constructor\n", 21) != 21 || close(fd) != 0)
        _exit(92);
    constructed = 41;
}

int cm_preflight_value(void) { return constructed; }
#else
extern char **environ;

static void require(int condition, const char *operation) {
    if (!condition) {
        fprintf(stderr, "CM native probe failed: %s (errno=%d)\n", operation, errno);
        exit(1);
    }
}

static int denied(int code) { return code == EACCES || code == EPERM; }

static int load_control(const char *path, const char *expected, const char *marker) {
    struct stat info;
    int fd = open(path, O_RDONLY | O_NOFOLLOW | O_CLOEXEC);
    require(fd >= 0 && fstat(fd, &info) == 0 && S_ISREG(info.st_mode) &&
        info.st_size > 0 && info.st_size <= 32 * 1024 * 1024, "bounded payload");
    size_t size = (size_t)info.st_size, offset = 0;
    unsigned char *data = malloc(size);
    require(data != NULL, "payload allocation");
    while (offset < size) {
        ssize_t count = read(fd, data + offset, size - offset);
        require(count > 0, "payload read");
        offset += (size_t)count;
    }
    require(close(fd) == 0, "payload close");
    unsigned char hash[CC_SHA256_DIGEST_LENGTH];
    require(CC_SHA256(data, (CC_LONG)size, hash) != NULL, "payload hash");
    free(data);
    char actual[65];
    for (size_t index = 0; index < sizeof(hash); ++index)
        snprintf(actual + 2 * index, 3, "%02x", hash[index]);
    if (strcmp(expected, actual) != 0) {
        puts("{\"status\":\"rejected\",\"gate\":\"payload-hash\",\"native_executed\":false}");
        return 3;
    }
    require(access(marker, F_OK) != 0 && errno == ENOENT, "constructor absent before load");
    require(setenv("CM_PREFLIGHT_MARKER", marker, 1) == 0 &&
        setenv("CM_PREFLIGHT_VERIFIED", "yes", 1) == 0, "constructor verification marker");
    void *library = dlopen(path, RTLD_NOW | RTLD_LOCAL);
    if (!library)
        fprintf(stderr, "dlopen: %s\n", dlerror());
    require(library != NULL, "ordinary positive dlopen");
    int (*value)(void) = (int (*)(void))dlsym(library, "cm_preflight_value");
    require(value != NULL && value() == 41 && access(marker, F_OK) == 0, "verified constructor and export");
    puts("{\"status\":\"pass\",\"control\":\"ordinary-path-dlopen\",\"constructor_value\":41,\"native_executed\":true,\"frozen_loading_qualified\":false}");
    return 0;
}

static int snapshot_probe(const char *root) {
    char path[PATH_MAX];
    require(snprintf(path, sizeof(path), "%s/retained-writer", root) > 0, "control name");
    int writer = open(path, O_CREAT | O_EXCL | O_RDWR | O_CLOEXEC, 0600);
    require(writer >= 0 && write(writer, "before", 6) == 6, "writable control");
    int retained_writer = dup(writer);
    int reader = open(path, O_RDONLY | O_CLOEXEC);
    require(retained_writer >= 0 && reader >= 0 && unlink(path) == 0 && close(writer) == 0, "unlink control");
    require(pwrite(reader, "X", 1, 0) == -1 && errno == EBADF, "read-only descriptor write denied");
    require(pwrite(retained_writer, "after!", 6, 0) == 6, "retained writer mutates unlinked object");
    char changed[6];
    require(pread(reader, changed, sizeof(changed), 0) == 6 && memcmp(changed, "after!", 6) == 0,
        "read-only object changed via retained writer");
    require(close(reader) == 0 && close(retained_writer) == 0, "close diagnostic control");
    require(snprintf(path, sizeof(path), "%s/anonymous-directory", root) > 0, "directory name");
    require(mkdir(path, 0700) == 0, "empty directory");
    int directory = open(path, O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    int adversary = open(path, O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    require(directory >= 0 && adversary >= 0 && rmdir(path) == 0, "retain adversarial directory before unlink");
    writer = openat(directory, "payload", O_CREAT | O_EXCL | O_RDWR | O_NOFOLLOW | O_CLOEXEC, 0600);
    int creation_error = errno;
    int reopened = -1, reopen_error = 0;
    if (writer >= 0) {
        require(write(writer, "candidate", 9) == 9, "candidate bytes");
        reopened = openat(adversary, "payload", O_RDWR | O_NOFOLLOW | O_CLOEXEC);
        reopen_error = reopened < 0 ? errno : 0;
        if (reopened >= 0) {
            require(pwrite(reopened, "X", 1, 0) == 1, "retained directory writer");
            require(close(reopened) == 0, "adversarial writer close");
        }
        require(unlinkat(directory, "payload", 0) == 0 && close(writer) == 0, "candidate cleanup");
    }
    require(close(directory) == 0 && close(adversary) == 0, "directory descriptors close");
    printf("{\"status\":\"failed\",\"gate\":\"same-byte-snapshot\","
        "\"retained_writer_control\":\"pass\",\"post_rmdir_create\":%s,\"create_errno\":%d,"
        "\"adversarial_directory_reopen\":%s,\"reopen_errno\":%d,"
        "\"frozen_loading_qualified\":false,\"native_executed\":false}\n",
        writer >= 0 ? "true" : "false", writer < 0 ? creation_error : 0,
        reopened >= 0 ? "true" : "false", reopen_error);
    /* No production loading path is proven, even if an unexpected API result needs investigation. */
    return 2;
}

static void mapped_digest(const void *mapping, size_t size, const char *gate) {
    unsigned char hash[CC_SHA256_DIGEST_LENGTH];
    require(CC_SHA256(mapping, (CC_LONG)size, hash) != NULL, "complete mapped byte hash");
    char actual[65];
    for (size_t index = 0; index < sizeof(hash); ++index)
        snprintf(actual + 2 * index, 3, "%02x", hash[index]);
    printf("{\"gate\":\"%s\",\"mapped_bytes\":%zu,\"sha256\":\"%s\",\"native_executed\":false}\n",
        gate, size, actual);
    require(fflush(stdout) == 0, "mapped hash evidence before next fault");
}

static int executable_map_probe(const char *path, off_t signature_offset, size_t signature_size,
    int retained, int fault_read) {
    struct stat source, viewed;
    int writer = open(path, O_RDWR | O_NOFOLLOW | O_CLOEXEC);
    int reader = open(path, O_RDONLY | O_NOFOLLOW | O_CLOEXEC);
    require(writer >= 0 && reader >= 0 && fstat(writer, &source) == 0 &&
        fstat(reader, &viewed) == 0 && S_ISREG(source.st_mode) &&
        source.st_dev == viewed.st_dev && source.st_ino == viewed.st_ino &&
        source.st_size > 0 && source.st_size <= 32 * 1024 * 1024, "mapped diagnostic object");
    require(!signature_size || (signature_offset > 0 && signature_offset < source.st_size &&
        signature_size <= (size_t)(source.st_size - signature_offset)), "bounded embedded signature");
    unsigned char before, after;
    require(pread(reader, &before, 1, 0) == 1, "mapped diagnostic initial byte");
    unsigned char replacement = before ^ 0xff;
    int barrier[2], receipt[2];
    require(pipe(barrier) == 0 && pipe(receipt) == 0, "mapped diagnostic barriers");
    struct { ssize_t bytes; int error; } outcome = {0, 0};
    pid_t child = fork();
    require(child >= 0, "retained writer fork");
    if (child == 0) {
        require(close(reader) == 0 && close(barrier[1]) == 0 && close(receipt[0]) == 0,
            "writer descriptor boundaries");
        if (!retained)
            require(close(writer) == 0, "positive control has no retained writer");
        require(write(receipt[1], "r", 1) == 1, "writer readiness barrier");
        char signal;
        require(read(barrier[0], &signal, 1) == 1, "writer waits for mapping");
        if (signal == 'w' && retained) {
            outcome.bytes = pwrite(writer, &replacement, 1, 0);
            outcome.error = outcome.bytes < 0 ? errno : 0;
        } else {
            require(signal == 's' || (signal == 'w' && !retained), "unavailable mapping skips write");
        }
        require(write(receipt[1], &outcome, sizeof(outcome)) == (ssize_t)sizeof(outcome) &&
            (!retained || close(writer) == 0) && close(barrier[0]) == 0 && close(receipt[1]) == 0,
            "writer result and cleanup");
        _exit(0);
    }
    require(close(writer) == 0 && close(barrier[0]) == 0 && close(receipt[1]) == 0,
        "reader descriptor boundaries");
    char ready;
    require(read(receipt[0], &ready, 1) == 1 && ready == 'r', "writer is ready before signature attachment");
    size_t size = (size_t)source.st_size;
    int signature_result = 0, signature_error = 0;
    if (signature_size) {
        /* The kernel reports page-rounded coverage; map only bytes before the signature. */
        size = (size_t)signature_offset;
        fsignatures_t signature = {.fs_file_start = 0,
            .fs_blob_start = (void *)(uintptr_t)signature_offset, .fs_blob_size = signature_size,
            .fs_fsignatures_size = sizeof(signature)};
        signature_result = fcntl(reader, F_ADDFILESIGS_INFO, &signature);
        signature_error = signature_result < 0 ? errno : 0;
        char cdhash[41] = "";
        if (signature_result == 0) {
            for (size_t index = 0; index < sizeof(signature.fs_cdhash); ++index)
                snprintf(cdhash + 2 * index, 3, "%02x", (unsigned char)signature.fs_cdhash[index]);
        }
        printf("{\"gate\":\"kernel-signature-api\",\"return_code\":%d,\"errno\":%d,"
            "\"signed_bytes\":%lld,\"cdhash\":\"%s\",\"hash_type\":%d}\n", signature_result,
            signature_error, signature_result == 0 ? (long long)signature.fs_file_start : 0, cdhash,
            signature_result == 0 ? signature.fs_hash_type : 0);
        require(fflush(stdout) == 0, "signature evidence before mapping faults");
    }
    /* A diagnostic mapping only; never parse, relocate or execute its bytes. */
    void *mapping = signature_result < 0 ? MAP_FAILED : mmap(NULL, size, PROT_READ | PROT_EXEC, MAP_PRIVATE, reader, 0);
    int map_error = mapping == MAP_FAILED && signature_result == 0 ? errno : 0;
    int locked = 0, lock_error = 0;
    size_t pages = 0;
    long page_size = signature_size ? sysconf(_SC_PAGESIZE) : 0;
    require(!signature_size || page_size > 0, "native page size");
    if (signature_size && !fault_read && mapping != MAP_FAILED) {
        locked = mlock(mapping, size) == 0;
        lock_error = locked ? 0 : errno;
        if (locked) {
            volatile unsigned char checksum = 0;
            for (size_t offset = 0; offset < size; offset += (size_t)page_size) {
                checksum ^= ((volatile unsigned char *)mapping)[offset];
                ++pages;
            }
            checksum ^= ((volatile unsigned char *)mapping)[size - 1];
            (void)checksum;
        }
    }
    if (fault_read && mapping != MAP_FAILED)
        mapped_digest(mapping, size, "kernel-signature-prefault");
    require(write(barrier[1], mapping == MAP_FAILED || (signature_size && !locked && !fault_read) ? "s" : "w", 1) == 1 &&
        close(barrier[1]) == 0, "release writer after mapping");
    require(read(receipt[0], &outcome, sizeof(outcome)) == (ssize_t)sizeof(outcome) && close(receipt[0]) == 0,
        "mapped writer result");
    int status;
    require(waitpid(child, &status, 0) == child && WIFEXITED(status) && WEXITSTATUS(status) == 0,
        "mapped writer completed");
    require(pread(reader, &after, 1, 0) == 1 && close(reader) == 0, "mapped object readback");
    if (fault_read) {
        printf("{\"gate\":\"kernel-signature-writer\",\"retained_writer\":%s,"
            "\"retained_writer_bytes\":%ld,\"write_errno\":%d,\"object_changed\":%s,\"native_executed\":false}\n",
            retained ? "true" : "false", (long)outcome.bytes, outcome.error, before != after ? "true" : "false");
        require(fflush(stdout) == 0, "writer evidence and cleanup before rereading mapped pages");
        require(mapping != MAP_FAILED, "signed fault diagnostic mapping");
        mapped_digest(mapping, size, "kernel-signature-reread");
        require(munmap(mapping, size) == 0, "fault diagnostic unmap");
        return 2;
    }
    if (locked)
        require(munlock(mapping, size) == 0, "diagnostic unlock");
    if (mapping != MAP_FAILED)
        require(munmap(mapping, size) == 0, "diagnostic unmap");
    printf("{\"status\":\"unqualified\",\"gate\":\"%s\",\"mapped\":%s,\"map_errno\":%d,"
        "\"retained_writer_bytes\":%ld,\"write_errno\":%d,\"object_changed\":%s,"
        "\"frozen_loading_qualified\":false,\"native_executed\":false",
        signature_size ? "kernel-signature-map" : "executable-map",
        mapping == MAP_FAILED ? "false" : "true", map_error, (long)outcome.bytes, outcome.error,
        before != after ? "true" : "false");
    if (signature_size)
        printf(",\"locked\":%s,\"lock_errno\":%d,\"mapped_bytes\":%zu,\"prefaulted_pages\":%zu,\"page_size\":%ld,\"retained_writer\":%s",
            locked ? "true" : "false", lock_error, mapping == MAP_FAILED ? 0 : size, pages,
            page_size, retained ? "true" : "false");
    puts("}");
    return 2;
}

static void denied_read(const char *path) {
    int fd = open(path, O_RDONLY | O_CLOEXEC);
    int code = errno;
    if (fd >= 0)
        close(fd);
    require(fd < 0 && denied(code), "outside read denied by policy");
}

static void denied_spawn(const char *path, int search) {
    pid_t child;
    char *args[] = {(char *)path, "--version", NULL};
    int code = search ? posix_spawnp(&child, path, NULL, NULL, args, environ)
                      : posix_spawn(&child, path, NULL, NULL, args, environ);
    if (code == 0) {
        int status;
        waitpid(child, &status, 0);
    }
    require(denied(code), "tool execution denied by policy");
}

static void connect_probe(const char *port, int allowed, int datagram) {
    int fd = socket(AF_INET, datagram ? SOCK_DGRAM : SOCK_STREAM, 0);
    int code = errno;
    if (fd >= 0) {
        struct sockaddr_in address = {.sin_len = sizeof(address), .sin_family = AF_INET,
            .sin_port = htons((unsigned short)strtoul(port, NULL, 10))};
        require(inet_pton(AF_INET, "127.0.0.1", &address.sin_addr) == 1, "numeric loopback");
        int result = datagram ? (int)sendto(fd, "probe", 5, 0, (struct sockaddr *)&address, sizeof(address))
                              : connect(fd, (struct sockaddr *)&address, sizeof(address));
        code = errno;
        if (allowed)
            require(result == 0 && !datagram, "allowed provider connection");
        else
            require(result == -1 && denied(code), "other endpoint denied");
        require(close(fd) == 0, "network close");
    } else {
        require(!allowed && denied(code), "socket denied");
    }
}

static void isolation_checks(char **args) {
    char content[9], output[PATH_MAX];
    int fd = open(args[2], O_RDONLY | O_CLOEXEC);
    require(fd >= 0 && read(fd, content, sizeof(content)) == 9 &&
        memcmp(content, "immutable", 9) == 0 && close(fd) == 0, "input read control");
    fd = open(args[2], O_WRONLY | O_CLOEXEC);
    int code = errno;
    if (fd >= 0)
        close(fd);
    require(fd < 0 && denied(code), "input mutation denied");
    require(snprintf(output, sizeof(output), "%s/output-%ld", args[3], (long)getpid()) > 0, "work name");
    fd = open(output, O_CREAT | O_EXCL | O_RDWR | O_CLOEXEC, 0600);
    require(fd >= 0 && write(fd, "work", 4) == 4 && lseek(fd, 0, SEEK_SET) == 0 &&
        read(fd, content, 4) == 4 && memcmp(content, "work", 4) == 0 && close(fd) == 0, "work read-write control");
    for (int index = 4; index <= 6; ++index)
        denied_read(args[index]);
    denied_spawn(args[7], 0);
    denied_spawn(args[8], 0);
    char tool[PATH_MAX];
    require(strlen(args[7]) < sizeof(tool), "tool path");
    strcpy(tool, args[7]);
    char *name = strrchr(tool, '/');
    require(name != NULL, "absolute tool");
    *name++ = '\0';
    require(setenv("PATH", tool, 1) == 0, "controlled tool PATH");
    denied_spawn(name, 1);
    connect_probe(args[9], 1, 0);
    connect_probe(args[10], 0, 0);
    connect_probe(args[10], 0, 1);
}

int main(int argc, char **argv) {
    if (argc == 2 && strcmp(argv[1], "startup") == 0) {
        puts("{\"status\":\"pass\",\"gate\":\"seatbelt-startup\"}");
        return 0;
    }
    if (argc == 5 && strcmp(argv[1], "load") == 0)
        return load_control(argv[2], argv[3], argv[4]);
    if (argc == 3 && strcmp(argv[1], "snapshot") == 0)
        return snapshot_probe(argv[2]);
    if (argc == 3 && strcmp(argv[1], "executable-map") == 0)
        return executable_map_probe(argv[2], 0, 0, 1, 0);
    if (argc == 6 && (strcmp(argv[1], "kernel-signature") == 0 ||
        strcmp(argv[1], "kernel-signature-fault") == 0)) {
        char *end;
        unsigned long offset = strtoul(argv[3], &end, 10);
        require(*argv[3] && *end == '\0' && offset > 0 && offset <= 32 * 1024 * 1024, "signature offset argument");
        unsigned long size = strtoul(argv[4], &end, 10);
        require(*argv[4] && *end == '\0' && size > 0 && size <= 32 * 1024 * 1024, "signature size argument");
        require(strcmp(argv[5], "none") == 0 || strcmp(argv[5], "writer") == 0, "closed signature adversary");
        return executable_map_probe(argv[2], (off_t)offset, (size_t)size, strcmp(argv[5], "writer") == 0,
            strcmp(argv[1], "kernel-signature-fault") == 0);
    }
    if (argc == 11 && strcmp(argv[1], "isolation") == 0) {
        isolation_checks(argv);
        pid_t child = fork();
        require(child >= 0, "inheritance fork");
        if (child == 0) {
            isolation_checks(argv);
            _exit(0);
        }
        int status;
        require(waitpid(child, &status, 0) == child && WIFEXITED(status) && WEXITSTATUS(status) == 0,
            "fork child retains all policy denials and positive controls");
        puts("{\"status\":\"pass\",\"gate\":\"seatbelt-controls\",\"parent_checks\":12,\"child_checks\":12}");
        return 0;
    }
    fprintf(stderr, "Invalid native mechanism probe arguments\n");
    return 64;
}
#endif
