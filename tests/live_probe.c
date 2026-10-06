// SPDX-License-Identifier: MIT
// Copyright (c) 2026 dhtfish98
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <grp.h>
#include <limits.h>
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
    char response[64];
};

static void fail(const char *message) {
    perror(message);
    exit(2);
}

static void hex(const char *data, size_t length) {
    for (size_t i = 0; i < length; ++i) printf("%02x", (unsigned char)data[i]);
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
                                       const char *file, const char *wire) {
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
            if (write_all(fd, wire, strlen(wire)) == 0 && shutdown(fd, SHUT_WR) == 0) {
                while (result.response_length < (int)sizeof(result.response) - 1) {
                    ssize_t n = read(fd, result.response + result.response_length,
                                     sizeof(result.response) - 1 - (size_t)result.response_length);
                    if (n < 0 && errno == EINTR) continue;
                    if (n <= 0) break;
                    result.response_length += (int)n;
                }
            }
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
    struct client_result result = request_as(uid, socket_path, file, wire);
    printf("CASE=%s process_uid=%u direct_file_errno=%d connected=%d send_hex=",
           label, (unsigned)uid, result.direct_file_errno, result.connected);
    hex(wire, strlen(wire));
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

static void server_expect_exit(pid_t child, const char *socket_path, const char *label) {
    int status;
    if (waitpid(child, &status, 0) != child || !WIFEXITED(status) ||
        WEXITSTATUS(status) != 0 || access(socket_path, F_OK) == 0) {
        fprintf(stderr, "SERVER_CHECK=%s FAIL status=%d\n", label, status);
        exit(7);
    }
    printf("SERVER_CHECK=%s PASS status=0 socket_removed=1\n", label);
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
    snprintf(socket_path, sizeof(socket_path), "%s/service.sock", argv[3]);
    snprintf(weak_file, sizeof(weak_file), "%s/weak.data", argv[3]);
    snprintf(strong_file, sizeof(strong_file), "%s/strong.data", argv[3]);
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
    pid_t strong = launch(argv[2], socket_path, strong_file, 6);
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
    server_expect_exit(strong, socket_path, "strong");
    if (unlink(weak_file) || unlink(strong_file) || rmdir(argv[3])) fail("cleanup");
    printf("CLEANUP=PASS\nTEST_EXIT=0\n");
    return 0;
}
