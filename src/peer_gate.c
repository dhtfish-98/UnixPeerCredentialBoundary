// SPDX-License-Identifier: MIT
// Copyright (c) 2026 dhtfish98
#define _GNU_SOURCE
#include "peer_gate.h"

#include <string.h>
#include <sys/socket.h>

enum peer_gate_result peer_gate_check(int connected_fd, uid_t authorized_uid,
                                      uid_t declared_uid,
                                      struct peer_gate_evidence *evidence) {
    if (evidence == NULL || connected_fd < 0) return PEER_GATE_CREDENTIAL_ERROR;
    memset(evidence, 0, sizeof(*evidence));
    struct ucred credentials;
    socklen_t length = sizeof(credentials);
    if (getsockopt(connected_fd, SOL_SOCKET, SO_PEERCRED, &credentials, &length) != 0 ||
        length != sizeof(credentials) || credentials.pid <= 0) {
        return PEER_GATE_CREDENTIAL_ERROR;
    }
    evidence->pid = credentials.pid;
    evidence->uid = credentials.uid;
    evidence->gid = credentials.gid;
    if (credentials.uid != authorized_uid) return PEER_GATE_UID_DENIED;
    if (declared_uid != credentials.uid) return PEER_GATE_CLAIM_MISMATCH;
    return PEER_GATE_ALLOW;
}
