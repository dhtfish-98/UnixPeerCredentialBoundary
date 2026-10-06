// SPDX-License-Identifier: MIT
// Copyright (c) 2026 dhtfish98
#define _GNU_SOURCE
#include "peer_gate.h"

#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <poll.h>
#include <signal.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/un.h>
#include <time.h>
#include <unistd.h>

#define MAX_REQUEST 128
#define MAX_CONNECTIONS 16

static void fatal(const char *step) {
    perror(step);
    exit(2);
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

static int parse_uid(const char *value, uid_t *uid) {
    if (!*value || *value == '+' || *value == '-') return -1;
    errno = 0;
    char *end = NULL;
    unsigned long parsed = strtoul(value, &end, 10);
    if (errno || *end || parsed > UINT_MAX) return -1;
    *uid = (uid_t)parsed;
    return 0;
}

static int is_token(const char *value, size_t min_len, size_t max_len) {
    size_t length = strlen(value);
    if (length < min_len || length > max_len) return 0;
    for (size_t i = 0; i < length; ++i) {
        char c = value[i];
        if (!((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
              (c >= '0' && c <= '9') || c == '_' || c == '-')) return 0;
    }
    return 1;
}

static int read_request(int fd, char *buffer, size_t capacity) {
    struct timespec started;
    if (clock_gettime(CLOCK_MONOTONIC, &started) != 0) return -1;
    int64_t deadline_ms = (int64_t)started.tv_sec * 1000 + started.tv_nsec / 1000000 + 2000;
    size_t count = 0;
    for (;;) {
        if (count == capacity - 1) return -1;
        struct timespec now;
        if (clock_gettime(CLOCK_MONOTONIC, &now) != 0) return -1;
        int64_t remaining_ms = deadline_ms - ((int64_t)now.tv_sec * 1000 + now.tv_nsec / 1000000);
        if (remaining_ms <= 0) return -1;
        struct pollfd ready = {.fd = fd, .events = POLLIN | POLLHUP};
        int polled = poll(&ready, 1, (int)remaining_ms);
        if (polled < 0 && errno == EINTR) continue;
        if (polled <= 0) return -1;
        ssize_t n = recv(fd, buffer + count, capacity - 1 - count, MSG_DONTWAIT);
        if (n < 0 && errno == EINTR) continue;
        if (n < 0 && errno == EAGAIN) continue;
        if (n < 0) return -1;
        if (n == 0) break;
        count += (size_t)n;
    }
    if (count == 0 || buffer[count - 1] != '\n' || memchr(buffer, '\0', count) != NULL)
        return -1;
    buffer[count] = '\0';
    return (int)count;
}

static int decode_request(const char *request, uid_t *declared,
                          char *nonce, char *payload) {
    char uid_text[16];
    char extra;
    if (sscanf(request, "PUT %15s %32s %32s %c", uid_text, nonce, payload, &extra) != 3 ||
        parse_uid(uid_text, declared) != 0 || !is_token(nonce, 8, 32) ||
        !is_token(payload, 1, 32)) return -1;
    char canonical[MAX_REQUEST];
    int n = snprintf(canonical, sizeof(canonical), "PUT %u %s %s\n",
                     (unsigned)*declared, nonce, payload);
    if (n < 0 || (size_t)n >= sizeof(canonical) || strcmp(canonical, request) != 0)
        return -1;
    return 0;
}

static void validate_parent(const char *socket_path) {
    size_t length = strlen(socket_path);
    if (length < 3 || length >= sizeof(((struct sockaddr_un *)0)->sun_path) ||
        socket_path[0] != '/' || socket_path[length - 1] == '/') {
        fprintf(stderr, "socket path must be short and absolute\n");
        exit(64);
    }
    const char *last_slash = strrchr(socket_path, '/');
    if (!last_slash || last_slash == socket_path ||
        strcmp(last_slash + 1, ".") == 0 || strcmp(last_slash + 1, "..") == 0) {
        fprintf(stderr, "socket must be under a dedicated root-owned directory\n");
        exit(64);
    }
    int directory = open("/", O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    if (directory < 0) fatal("open root directory");
    struct stat st;
    if (fstat(directory, &st) != 0 || !S_ISDIR(st.st_mode) || st.st_uid != 0 ||
        (st.st_mode & 0022) != 0) {
        fprintf(stderr, "root directory failed trust check\n");
        close(directory);
        exit(65);
    }
    const char *component = socket_path + 1;
    while (component < last_slash) {
        const char *end = strchr(component, '/');
        if (!end || end > last_slash || end == component ||
            (end - component == 1 && component[0] == '.') ||
            (end - component == 2 && component[0] == '.' && component[1] == '.')) {
            fprintf(stderr, "noncanonical socket path\n");
            close(directory);
            exit(64);
        }
        char name[sizeof(((struct sockaddr_un *)0)->sun_path)];
        size_t part_length = (size_t)(end - component);
        memcpy(name, component, part_length);
        name[part_length] = '\0';
        int child = openat(directory, name, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
        close(directory);
        if (child < 0) {
            fprintf(stderr, "socket path ancestor is missing or is a symlink\n");
            exit(65);
        }
        directory = child;
        if (fstat(directory, &st) != 0 || !S_ISDIR(st.st_mode) || st.st_uid != 0 ||
            ((st.st_mode & 0022) != 0 &&
             (end == last_slash || (st.st_mode & S_ISVTX) == 0))) {
            fprintf(stderr, "socket path ancestor is not root-controlled\n");
            close(directory);
            exit(65);
        }
        component = end + 1;
    }
    close(directory);
}

int main(int argc, char **argv) {
    if (argc != 5) {
        fprintf(stderr, "usage: managed-write-server SOCKET ROOT_0600_FILE AUTHORIZED_UID CONNECTIONS\n");
        return 64;
    }
    if (geteuid() != 0) {
        fprintf(stderr, "service must run as root in this controlled lab\n");
        return 65;
    }
    (void)signal(SIGPIPE, SIG_IGN);
    uid_t authorized;
    uid_t connection_count_uid;
    if (parse_uid(argv[3], &authorized) || parse_uid(argv[4], &connection_count_uid) ||
        connection_count_uid == 0 || connection_count_uid > MAX_CONNECTIONS) return 64;
    int file_fd = open(argv[2], O_WRONLY | O_APPEND | O_CLOEXEC | O_NOFOLLOW);
    if (file_fd < 0) fatal("open protected file");
    struct stat file_stat;
    if (fstat(file_fd, &file_stat) || !S_ISREG(file_stat.st_mode) ||
        file_stat.st_uid != 0 || (file_stat.st_mode & 0777) != 0600) {
        fprintf(stderr, "protected file must be root-owned regular file mode 0600\n");
        close(file_fd);
        return 65;
    }
    validate_parent(argv[1]);
    struct stat existing;
    if (lstat(argv[1], &existing) == 0 || errno != ENOENT) {
        fprintf(stderr, "socket path already exists or is inaccessible\n");
        close(file_fd);
        return 65;
    }
    int listener = socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
    if (listener < 0) fatal("socket");
    struct sockaddr_un address = {.sun_family = AF_UNIX};
    memcpy(address.sun_path, argv[1], strlen(argv[1]) + 1);
    if (bind(listener, (struct sockaddr *)&address, sizeof(address)) != 0) fatal("bind");
    if (listen(listener, 8) != 0) fatal("listen");
    if (chmod(argv[1], 0666) != 0) fatal("chmod socket");
    struct stat socket_stat;
    if (lstat(argv[1], &socket_stat) != 0) fatal("stat socket");
    printf("SERVER_READY mode=%s pid=%ld socket_mode=%03o socket_owner=%u protected_mode=%03o protected_owner=%u authorized_uid=%u\n",
#ifdef PEER_GATE_WEAK_LAB
           "WEAK_LAB",
#else
           "SO_PEERCRED",
#endif
           (long)getpid(), (unsigned)(socket_stat.st_mode & 0777),
           (unsigned)socket_stat.st_uid, (unsigned)(file_stat.st_mode & 0777),
           (unsigned)file_stat.st_uid, (unsigned)authorized);
    fflush(stdout);
    char seen[MAX_CONNECTIONS][33] = {{0}};
    size_t seen_count = 0;
    for (unsigned i = 0; i < (unsigned)connection_count_uid; ++i) {
        int peer = accept4(listener, NULL, NULL, SOCK_CLOEXEC);
        if (peer < 0) fatal("accept");
        char request[MAX_REQUEST] = {0};
        char nonce[33] = {0}, payload[33] = {0};
        uid_t declared = (uid_t)-1;
        int received = read_request(peer, request, sizeof(request));
        const char *answer = "ERR MALFORMED\n";
        struct peer_gate_evidence evidence = {0};
        enum peer_gate_result decision = PEER_GATE_CREDENTIAL_ERROR;
        if (received > 0 && decode_request(request, &declared, nonce, payload) == 0) {
#ifdef PEER_GATE_WEAK_LAB
            decision = declared == authorized ? PEER_GATE_ALLOW : PEER_GATE_UID_DENIED;
#else
            decision = peer_gate_check(peer, authorized, declared, &evidence);
#endif
            if (decision == PEER_GATE_UID_DENIED) answer = "ERR UID_DENIED\n";
            else if (decision == PEER_GATE_CLAIM_MISMATCH) answer = "ERR CLAIM_MISMATCH\n";
            else if (decision == PEER_GATE_CREDENTIAL_ERROR) answer = "ERR PEER_CREDENTIAL\n";
            else {
                int replay = 0;
                for (size_t j = 0; j < seen_count; ++j)
                    if (strcmp(seen[j], nonce) == 0) replay = 1;
                if (replay) answer = "ERR REPLAY\n";
                else {
                    char line[80];
                    int line_len = snprintf(line, sizeof(line), "%s\n", payload);
                    if (line_len <= 0 || (size_t)line_len >= sizeof(line) ||
                        write_all(file_fd, line, (size_t)line_len) != 0)
                        answer = "ERR STORAGE\n";
                    else {
                        memcpy(seen[seen_count++], nonce, strlen(nonce) + 1);
                        answer = "OK WRITE\n";
                    }
                }
            }
        }
        printf("SERVER_EVENT mode=%s slot=%u observed_pid=%ld observed_uid=%u observed_gid=%u declared_uid=%u nonce=%s response=%s",
#ifdef PEER_GATE_WEAK_LAB
               "WEAK_LAB",
#else
               "SO_PEERCRED",
#endif
               i, (long)evidence.pid, (unsigned)evidence.uid, (unsigned)evidence.gid,
               (unsigned)declared, nonce[0] ? nonce : "-", answer);
        fflush(stdout);
        (void)write_all(peer, answer, strlen(answer));
        close(peer);
    }
    close(listener);
    close(file_fd);
    if (unlink(argv[1]) != 0) fatal("unlink socket");
    printf("SERVER_EXIT mode=%s status=0\n",
#ifdef PEER_GATE_WEAK_LAB
           "WEAK_LAB"
#else
           "SO_PEERCRED"
#endif
    );
    return 0;
}
