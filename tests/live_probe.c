// SPDX-License-Identifier: MIT
// Copyright (c) 2026 dhtfish98
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <grp.h>
#include <limits.h>
#include <poll.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/un.h>
#include <sys/utsname.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

struct client_result {
    int connected;
    int direct_file_errno;
    int response_length;
    int sent_length;
    int elapsed_ms;
    char response[64];
};

static void fail(const char *message) {
    perror(message);
    exit(2);
}

static void hex(const char *data, size_t length) {
    for (size_t i = 0; i < length; ++i) printf("%02x", (unsigned char)data[i]);
}

static void join_path(char *out, size_t capacity, const char *parent,
                      const char *suffix) {
    size_t base = strlen(parent), extra = strlen(suffix);
    if (base >= capacity || extra >= capacity - base) {
        errno = ENAMETOOLONG;
        fail("join path");
    }
    memcpy(out, parent, base);
    memcpy(out + base, suffix, extra + 1);
}

static void file_expect(const char *path, const char *wanted, const char *label) {
    int fd = open(path, O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
    if (fd < 0) fail("file_expect open");
    char contents[256];
    ssize_t size = read(fd, contents, sizeof(contents));
    close(fd);
    if (size < 0 || (size_t)size != strlen(wanted) ||
        memcmp(contents, wanted, (size_t)size) != 0) {
        fprintf(stderr, "FILE_CHECK=%s FAIL\n", label);
        exit(3);
    }
    printf("FILE_CHECK=%s PASS bytes=%ld hex=", label, (long)size);
    hex(contents, (size_t)size);
    putchar('\n');
    fflush(stdout);
}

static void wait_ready(const char *socket_path) {
    struct timespec delay = {.tv_nsec = 10000000};
    for (unsigned attempt = 0; attempt < 300; ++attempt) {
        struct stat st;
        if (lstat(socket_path, &st) == 0 && S_ISSOCK(st.st_mode) &&
            (st.st_mode & 0777) == 0666 && st.st_uid == 0) {
            printf("SOCKET_READY owner=%u mode=%03o\n", (unsigned)st.st_uid,
                   (unsigned)(st.st_mode & 0777));
            return;
        }
        nanosleep(&delay, NULL);
    }
    fprintf(stderr, "socket readiness timed out\n");
    exit(4);
}

static pid_t launch(const char *binary, const char *socket_path, const char *file,
                    int connections) {
    pid_t child = fork();
    if (child < 0) fail("fork server");
    if (child == 0) {
        char count[16];
        snprintf(count, sizeof(count), "%d", connections);
        execl(binary, binary, socket_path, file, "1000", count, (char *)NULL);
        fail("exec server");
    }
    wait_ready(socket_path);
    return child;
}

static int write_all(int fd, const char *data, size_t length) {
    while (length != 0) {
        ssize_t n = write(fd, data, length);
        if (n < 0 && errno == EINTR) continue;
        if (n <= 0) return -1;
        data += n;
        length -= (size_t)n;
    }
    return 0;
}

static struct client_result request_as(uid_t uid, const char *socket_path,
                                       const char *file, const char *wire,
                                       int slow_drip) {
    int channel[2];
    if (pipe(channel) != 0) fail("pipe");
    pid_t child = fork();
    if (child < 0) fail("fork client");
    if (child == 0) {
        close(channel[0]);
        struct client_result result = {0};
        if (setgroups(0, NULL) || setresgid(uid, uid, uid) || setresuid(uid, uid, uid))
            _exit(11);
        errno = 0;
        int direct = open(file, O_WRONLY | O_APPEND | O_CLOEXEC);
        result.direct_file_errno = direct < 0 ? errno : 0;
        if (direct >= 0) close(direct);
        int fd = socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
        if (fd < 0) _exit(12);
        struct sockaddr_un address = {.sun_family = AF_UNIX};
        if (strlen(socket_path) >= sizeof(address.sun_path)) _exit(13);
        strcpy(address.sun_path, socket_path);
        if (connect(fd, (struct sockaddr *)&address, sizeof(address)) == 0) {
            result.connected = 1;
            struct timespec started, finished;
            if (clock_gettime(CLOCK_MONOTONIC, &started) != 0) _exit(15);
            if (slow_drip) {
                for (size_t i = 0; i < strlen(wire); ++i) {
                    if (send(fd, wire + i, 1, MSG_NOSIGNAL) != 1) break;
                    ++result.sent_length;
                    struct pollfd ready = {.fd = fd, .events = POLLIN | POLLHUP};
                    if (poll(&ready, 1, 400) != 0) break;
                }
                (void)shutdown(fd, SHUT_WR);
            } else if (write_all(fd, wire, strlen(wire)) == 0 &&
                       shutdown(fd, SHUT_WR) == 0) {
                result.sent_length = (int)strlen(wire);
            }
            if (result.sent_length > 0) {
                while (result.response_length < (int)sizeof(result.response) - 1) {
                    ssize_t n = read(fd, result.response + result.response_length,
                                     sizeof(result.response) - 1 - (size_t)result.response_length);
                    if (n < 0 && errno == EINTR) continue;
                    if (n <= 0) break;
                    result.response_length += (int)n;
                }
            }
            if (clock_gettime(CLOCK_MONOTONIC, &finished) != 0) _exit(16);
            result.elapsed_ms = (int)((finished.tv_sec - started.tv_sec) * 1000 +
                                      (finished.tv_nsec - started.tv_nsec) / 1000000);
        }
        close(fd);
        if (write_all(channel[1], (const char *)&result, sizeof(result)) != 0) _exit(14);
        close(channel[1]);
        _exit(0);
    }
    close(channel[1]);
    struct client_result result = {0};
    ssize_t count = read(channel[0], &result, sizeof(result));
    close(channel[0]);
    int status = 0;
    if (waitpid(child, &status, 0) != child || !WIFEXITED(status) ||
        WEXITSTATUS(status) != 0 || count != sizeof(result)) {
        fprintf(stderr, "client child failed uid=%u status=%d bytes=%ld\n",
                (unsigned)uid, status, (long)count);
        exit(5);
    }
    return result;
}

static void case_expect(const char *label, uid_t uid, const char *socket_path,
                        const char *file, const char *wire, const char *wanted_reply,
                        const char *wanted_file) {
    struct client_result result = request_as(uid, socket_path, file, wire, 0);
    printf("CASE=%s process_uid=%u direct_file_errno=%d connected=%d elapsed_ms=%d send_hex=",
           label, (unsigned)uid, result.direct_file_errno, result.connected,
           result.elapsed_ms);
    hex(wire, (size_t)result.sent_length);
    printf(" recv_hex=");
    hex(result.response, (size_t)result.response_length);
    putchar('\n');
    fflush(stdout);
    if (result.direct_file_errno != EACCES || result.connected != 1 ||
        result.response_length != (int)strlen(wanted_reply) ||
        memcmp(result.response, wanted_reply, strlen(wanted_reply)) != 0) {
        fprintf(stderr, "CASE_CHECK=%s FAIL\n", label);
        exit(6);
    }
    printf("CASE_CHECK=%s PASS\n", label);
    file_expect(file, wanted_file, label);
}

static void slow_case_expect(const char *socket_path, const char *file,
                             const char *wanted_file) {
    const char *wire = "PUT 1000 drip001 HOLD\n";
    struct client_result result = request_as(1001, socket_path, file, wire, 1);
    printf("CASE=strong_slow_drip_uid1001 process_uid=1001 direct_file_errno=%d connected=%d elapsed_ms=%d sent_bytes=%d send_hex=",
           result.direct_file_errno, result.connected, result.elapsed_ms,
           result.sent_length);
    hex(wire, (size_t)result.sent_length);
    printf(" recv_hex=");
    hex(result.response, (size_t)result.response_length);
    putchar('\n');
    fflush(stdout);
    if (result.direct_file_errno != EACCES || result.connected != 1 ||
        result.sent_length < 2 || result.elapsed_ms < 1500 ||
        result.elapsed_ms > 4000 ||
        result.response_length != (int)strlen("ERR MALFORMED\n") ||
        memcmp(result.response, "ERR MALFORMED\n", strlen("ERR MALFORMED\n")) != 0) {
        fprintf(stderr, "CASE_CHECK=strong_slow_drip_uid1001 FAIL\n");
        exit(6);
    }
    printf("CASE_CHECK=strong_slow_drip_uid1001 PASS\n");
    file_expect(file, wanted_file, "strong_slow_drip_uid1001");
}

static void server_expect_exit(pid_t child, const char *socket_path, const char *label) {
    int status;
    if (waitpid(child, &status, 0) != child || !WIFEXITED(status) ||
        WEXITSTATUS(status) != 0 || access(socket_path, F_OK) == 0) {
        fprintf(stderr, "SERVER_CHECK=%s FAIL status=%d\n", label, status);
        exit(7);
    }
    printf("SERVER_CHECK=%s PASS status=0 socket_removed=1\n", label);
}

static void reject_untrusted_path(const char *binary, const char *socket_path,
                                  const char *file, const char *label) {
    pid_t child = fork();
    if (child < 0) fail("fork rejected server");
    if (child == 0) {
        execl(binary, binary, socket_path, file, "1000", "1", (char *)NULL);
        _exit(127);
    }
    int status = 0;
    struct stat st;
    if (waitpid(child, &status, 0) != child || !WIFEXITED(status) ||
        WEXITSTATUS(status) != 65 || lstat(socket_path, &st) == 0 || errno != ENOENT) {
        fprintf(stderr, "PATH_CHECK=%s FAIL status=%d\n", label, status);
        exit(8);
    }
    printf("PATH_CHECK=%s PASS status=65 socket_absent=1\n", label);
    fflush(stdout);
}

static void setup_file(const char *path) {
    int fd = open(path, O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC | O_NOFOLLOW, 0600);
    if (fd < 0) fail("create fixture");
    if (write_all(fd, "BASE\n", 5) != 0 || close(fd) != 0) fail("initialize fixture");
    struct stat st;
    if (lstat(path, &st) != 0 || st.st_uid != 0 || (st.st_mode & 0777) != 0600)
        fail("fixture ownership or mode");
    printf("PROTECTED_FILE owner=%u mode=%03o\n", (unsigned)st.st_uid,
           (unsigned)(st.st_mode & 0777));
}

int main(int argc, char **argv) {
    if (argc != 4 || geteuid() != 0) {
        fprintf(stderr, "usage as root: live-probe WEAK_LAB_BINARY STRONG_BINARY SHORT_TMP_DIR\n");
        return 64;
    }
    if (strlen(argv[3]) > 72 || argv[3][0] != '/') return 64;
    if (mkdir(argv[3], 0755) != 0) fail("mkdir fixture");
    char socket_path[108], weak_file[108], strong_file[108];
    join_path(socket_path, sizeof(socket_path), argv[3], "/service.sock");
    join_path(weak_file, sizeof(weak_file), argv[3], "/weak.data");
    join_path(strong_file, sizeof(strong_file), argv[3], "/strong.data");
    setup_file(weak_file);
    setup_file(strong_file);
    struct utsname kernel;
    if (uname(&kernel) != 0) fail("uname");
    printf("KERNEL_RELEASE=%s\n", kernel.release);
    const char *spoof = "PUT 1000 attack001 WEAK_SPOOF\n";
    const char *legit = "PUT 1000 valid001 LEGIT\n";
    pid_t weak = launch(argv[1], socket_path, weak_file, 1);
    case_expect("weak_spoof_uid1001", 1001, socket_path, weak_file, spoof,
                "OK WRITE\n", "BASE\nWEAK_SPOOF\n");
    server_expect_exit(weak, socket_path, "weak_lab");
    pid_t strong = launch(argv[2], socket_path, strong_file, 7);
    case_expect("strong_spoof_uid1001", 1001, socket_path, strong_file, spoof,
                "ERR UID_DENIED\n", "BASE\n");
    case_expect("strong_legit_uid1000", 1000, socket_path, strong_file, legit,
                "OK WRITE\n", "BASE\nLEGIT\n");
    case_expect("strong_replay_uid1000", 1000, socket_path, strong_file, legit,
                "ERR REPLAY\n", "BASE\nLEGIT\n");
    case_expect("strong_claim_mismatch_uid1000", 1000, socket_path, strong_file,
                "PUT 1001 false001 FALSE\n", "ERR CLAIM_MISMATCH\n", "BASE\nLEGIT\n");
    case_expect("strong_replay_spoof_uid1001", 1001, socket_path, strong_file, legit,
                "ERR UID_DENIED\n", "BASE\nLEGIT\n");
    case_expect("strong_second_legit_uid1000", 1000, socket_path, strong_file,
                "PUT 1000 valid002 LEGIT2\n", "OK WRITE\n", "BASE\nLEGIT\nLEGIT2\n");
    slow_case_expect(socket_path, strong_file, "BASE\nLEGIT\nLEGIT2\n");
    server_expect_exit(strong, socket_path, "strong");
    char bad_ancestor[108], bad_parent[108], bad_socket[108], bad_file[108];
    join_path(bad_ancestor, sizeof(bad_ancestor), argv[3], "/uid1001");
    join_path(bad_parent, sizeof(bad_parent), bad_ancestor, "/rootparent");
    join_path(bad_socket, sizeof(bad_socket), bad_parent, "/service.sock");
    join_path(bad_file, sizeof(bad_file), bad_parent, "/protected.data");
    if (mkdir(bad_ancestor, 0755) || chown(bad_ancestor, 1001, 1001) ||
        mkdir(bad_parent, 0755)) fail("untrusted ancestor fixture");
    reject_untrusted_path(argv[2], bad_socket, strong_file, "uid1001_ancestor");
    file_expect(strong_file, "BASE\nLEGIT\nLEGIT2\n", "uid1001_ancestor");
    setup_file(bad_file);
    reject_untrusted_path(argv[2], socket_path, bad_file, "file_uid1001_ancestor");
    file_expect(bad_file, "BASE\n", "file_uid1001_ancestor");
    if (unlink(bad_file) || rmdir(bad_parent) || rmdir(bad_ancestor))
        fail("untrusted ancestor cleanup");
    char trusted_parent[108], alias[108], aliased_socket[108],
        trusted_file[108], aliased_file[108];
    join_path(trusted_parent, sizeof(trusted_parent), argv[3], "/trusted");
    join_path(alias, sizeof(alias), argv[3], "/alias");
    join_path(aliased_socket, sizeof(aliased_socket), alias, "/service.sock");
    join_path(trusted_file, sizeof(trusted_file), trusted_parent, "/protected.data");
    join_path(aliased_file, sizeof(aliased_file), alias, "/protected.data");
    if (mkdir(trusted_parent, 0755) || symlink(trusted_parent, alias))
        fail("symlink ancestor fixture");
    reject_untrusted_path(argv[2], aliased_socket, strong_file, "symlink_ancestor");
    file_expect(strong_file, "BASE\nLEGIT\nLEGIT2\n", "symlink_ancestor");
    setup_file(trusted_file);
    reject_untrusted_path(argv[2], socket_path, aliased_file, "file_symlink_ancestor");
    file_expect(trusted_file, "BASE\n", "file_symlink_ancestor");
    if (unlink(trusted_file) || unlink(alias) || rmdir(trusted_parent))
        fail("symlink ancestor cleanup");
    if (unlink(weak_file) || unlink(strong_file) || rmdir(argv[3])) fail("cleanup");
    printf("CLEANUP=PASS\nTEST_EXIT=0\n");
    return 0;
}
