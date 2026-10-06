# Origin, authorship, and rights

The gate, service, probe, and automation in this project are authored for this candidate by **dhtfish98**, under MIT. The weak lab is expressly insecure experimental code and is compiled only with `PEER_GATE_WEAK_LAB=1`; the normal service build has no runtime weak switch.

The design uses the documented Linux `AF_UNIX` and `SO_PEERCRED` interfaces ([unix(7)](https://man7.org/linux/man-pages/man7/unix.7.html)). The VM harness uses Apple's Virtualization framework and a locally pinned Alpine Linux kernel/initramfs and Zig compiler from the workspace environment. These external runtime components are not copied into the source repository or claimed as project-authored code. Their own rights remain with their respective authors. The tiny Swift VM host is dhtfish98's own harness pattern already used in the RootlessIdMapBoundary workspace project.

No third-party project vulnerability or remote-service behavior is claimed. The file contents, accounts, UIDs and request markers are synthetic. The project has no affiliation with Anthropic and its existence does not demonstrate an accepted Cyber Verification Program application.
