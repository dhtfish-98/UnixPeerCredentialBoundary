# Validation snapshot — 2026-10-06

Status: **local real-kernel PASS; GitHub-hosted CI and release OPEN**.

The exact source used for the revised local VM run is recorded by SHA-256 in `Build/验证/UnixPeerCredentialBoundary-20261006/vm-path-negatives-20261006/receipt.json`. Its receipt SHA-256 is `1f6acf7decb108c277454e32768eb458ca274da5a4b4391839d89c72cb7e5bfe`; its raw serial SHA-256 is `c85da30c56ef6a477dded21ad6b5309223e2e894cb1dc47bed9bd84ca1d8f655`. The harness pinned Linux kernel `6.18.52-0-virt`, its initramfs, and Zig by SHA-256; the resulting three static AArch64 ELF programs are hashed in the receipt. The disposable guest root directory was normalized from owner UID 501 to root/`0755` before the experiment, which the serial log records. VM process exit was 0 and all 18 receipt predicates passed.

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
| UID 1001 drip-feeds a request every 400 ms | `ERR MALFORMED` after 2,001 ms total | Unchanged |
| Socket parent is root-owned but its ancestor is UID 1001-owned | Server refuses startup with status 65; no socket | Unchanged |
| Socket ancestor is a symlink | Server refuses startup with status 65; no socket | Unchanged |

The serial log contains the hexadecimal bytes for every sent request, received response and protected file state, plus server-reported kernel PID/UID/GID, socket owner/mode `0/666`, protected file owner/mode `0/600`, success exits and cleanup. This evidence is for a controlled local VM. The Linux CI workflow has been prepared but not run on GitHub at this snapshot; a GitHub release or official CVP decision must not be inferred from this local result.
