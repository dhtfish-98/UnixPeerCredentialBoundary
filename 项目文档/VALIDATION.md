# Validation snapshot — 2026-10-06

Status: **local real-kernel PASS; GitHub-hosted CI and release OPEN**.

The exact source used for the final local VM run is recorded by SHA-256 in `Build/验证/UnixPeerCredentialBoundary-20261006/vm-final-source-20261006/receipt.json`. Its receipt SHA-256 is `081e81d697124e831d789fd2f1934c2abe7ce12e6d61859718477ea82247427c`; its raw serial SHA-256 is `6839d1d65a8c6b4608888f0c4121c0253f3f953978722beeb023b02e5b54b1a5`. The harness pinned Linux kernel `6.18.52-0-virt`, its initramfs, and Zig by SHA-256; the resulting three static AArch64 ELF programs are hashed in the receipt. VM process exit was 0 and all 14 receipt predicates passed.

| Actual Linux process / request | Observed response | Protected file effect |
| --- | --- | --- |
| UID 1001 directly opens root-owned `0600` file | `EACCES` 13 | None |
| UID 1001 claims UID 1000 on weak lab | `OK WRITE` | `WEAK_SPOOF` appended |
| UID 1001 sends the same bytes to strong service | `ERR UID_DENIED`; server logs kernel UID 1001 | Unchanged at `BASE\n` |
| UID 1000 claims UID 1000 | `OK WRITE`; server logs kernel UID 1000 | `LEGIT` appended |
| UID 1000 repeats the exact valid bytes | `ERR REPLAY` | Unchanged |
| UID 1000 declares UID 1001 | `ERR CLAIM_MISMATCH` | Unchanged |
| UID 1001 repeats the legitimate UID 1000 bytes | `ERR UID_DENIED` | Unchanged |
| UID 1000 uses a fresh nonce | `OK WRITE` | `LEGIT2` appended |

The serial log contains the hexadecimal bytes for every sent request, received response and protected file state, plus server-reported kernel PID/UID/GID, socket owner/mode `0/666`, protected file owner/mode `0/600`, success exits and cleanup. This evidence is for a controlled local VM. The Linux CI workflow has been prepared but not run on GitHub at this snapshot; a GitHub release or official CVP decision must not be inferred from this local result.
