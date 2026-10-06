// SPDX-License-Identifier: MIT
// Copyright (c) 2026 dhtfish98
#ifndef UNIX_PEER_GATE_H
#define UNIX_PEER_GATE_H

#include <sys/types.h>

enum peer_gate_result {
    PEER_GATE_ALLOW = 0,
    PEER_GATE_CREDENTIAL_ERROR,
    PEER_GATE_UID_DENIED,
    PEER_GATE_CLAIM_MISMATCH
};

struct peer_gate_evidence {
    pid_t pid;
    uid_t uid;
    gid_t gid;
};

// Linux AF_UNIX SOCK_STREAM connection credential check. Fail closed on errors.
enum peer_gate_result peer_gate_check(int connected_fd, uid_t authorized_uid,
                                      uid_t declared_uid,
                                      struct peer_gate_evidence *evidence);

#endif
