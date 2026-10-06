// SPDX-License-Identifier: MIT
// Copyright (c) 2026 dhtfish98
#define _GNU_SOURCE
#include "peer_gate.h"

#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <signal.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/time.h>
#include <sys/un.h>
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
    size_t count = 0;
    for (;;) {
        if (count == capacity - 1) return -1;
        ssize_t n = read(fd, buffer + count, capacity - 1 - count);
        if (n < 0 && errno == EINTR) continue;
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
    char parent[sizeof(((struct sockaddr_un *)0)->sun_path)];
    size_t length = strlen(socket_path);
    if (length == 0 || length >= sizeof(parent) || socket_path[0] != '/') {
        fprintf(stderr, "socket path must be short and absolute\n");
        exit(64);
    }
    memcpy(parent, socket_path, length + 1);
    char *slash = strrchr(parent, '/');
    if (!slash || slash == parent) {
        fprintf(stderr, "socket must be under a dedicated root-owned directory\n");
        exit(64);
    }
    *slash = '\0';
    struct stat st;
    if (lstat(parent, &st) != 0 || !S_ISDIR(st.st_mode) || st.st_uid != 0 ||
        (st.st_mode & 0022) != 0) {
        fprintf(stderr, "socket parent must be a root-owned non-writable directory\n");
        exit(65);
    }
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
        struct timeval timeout = {.tv_sec = 2};
        (void)setsockopt(peer, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout));
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
