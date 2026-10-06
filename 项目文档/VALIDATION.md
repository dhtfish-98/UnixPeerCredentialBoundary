# Validation snapshot — 2026-10-06

The local real-kernel run below was frozen on 2026-10-06. The prior [v0.1.0 public release](https://github.com/dhtfish-98/UnixPeerCredentialBoundary/releases/tag/v0.1.0) also passed exact-commit Linux CI on the [main run](https://github.com/dhtfish-98/UnixPeerCredentialBoundary/actions/runs/37408286936) and [tag run](https://github.com/dhtfish-98/UnixPeerCredentialBoundary/actions/runs/37408397517). Each run exercised the real UID and AF_UNIX boundary on an Ubuntu-hosted Linux kernel; the release includes source and a separate evidence bundle. Check [Releases](https://github.com/dhtfish-98/UnixPeerCredentialBoundary/releases) and its linked workflow for the current version.

The exact source used for the revised local VM run is recorded by SHA-256 in `Build/验证/UnixPeerCredentialBoundary-20261006/vm-gcc-clean-central-20261006/receipt.json`. Its receipt SHA-256 is `068de631019f70003da51f3d3b62a2582e8777cf277264d2130aeb85a355ba2a`; its raw serial SHA-256 is `6fff16a7684020f1d4f1a52a00750213a86c535ab40edc98b0bdba8e2c105f0d`. The harness pinned Linux kernel `6.18.52-0-virt`, its initramfs, and Zig by SHA-256; the resulting three static AArch64 ELF programs are hashed in the receipt. The disposable guest root directory was normalized from owner UID 501 to root/`0755` before the experiment, which the serial log records. VM process exit was 0 and all 20 receipt predicates passed. All three binaries also compiled without warnings under the local x86_64 Linux GCC 15.2 cross compiler with `-std=c11 -O2 -Wall -Wextra -Werror`; that is a compile check, not an x86 runtime result.

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
| Protected-file ancestor is UID 1001-owned | Server refuses startup with status 65; no socket | The protected file remains `BASE\n` |
| Protected-file ancestor is a symlink | Server refuses startup with status 65; no socket | The protected file remains `BASE\n` |

The serial log contains the hexadecimal bytes for every sent request, received response and protected file state, plus server-reported kernel PID/UID/GID, socket owner/mode `0/666`, protected file owner/mode `0/600`, success exits and cleanup. This table is from a controlled local VM; the linked hosted runs independently verify the same guarded boundary on Linux. Neither environment establishes integration into another service or an official CVP decision.
