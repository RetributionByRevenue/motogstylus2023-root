# Full Writeup

Complete technical narrative of rooting the Moto G Stylus 5G 2023 (genevn)
via GhostLock (CVE-2026-43499).

## Documents

| File | What's in it |
|---|---|
| [CONFIRMED-FINDINGS.md](CONFIRMED-FINDINGS.md) | Hard technical facts: kernel offsets, memory layout, config flags, struct sizes — everything verified against the actual vmlinux and running kernel |
| [BUGS-FIXED.md](BUGS-FIXED.md) | The two critical bugs that blocked W2 (credential overwrite) and how they were diagnosed and fixed |
| [HISTORY.md](HISTORY.md) | Chronological narrative: from firmware extraction through QEMU debugging to the first successful root |
| [FINAL-RUN.md](FINAL-RUN.md) | Annotated log of the winning run — the first clean W1 → W2 → KernelSU chain |

## Reading order

If you want to understand the exploit: start with the main [README.md](../README.md)
for the high-level flow, then [CONFIRMED-FINDINGS.md](CONFIRMED-FINDINGS.md) for the
hard numbers.

If you want to understand the debugging journey: read [BUGS-FIXED.md](BUGS-FIXED.md)
first — those two bugs are the core intellectual contribution of this port — then
[HISTORY.md](HISTORY.md) for the full timeline.

If you just want to see it work: [FINAL-RUN.md](FINAL-RUN.md).
