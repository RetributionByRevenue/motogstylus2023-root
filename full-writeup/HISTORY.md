# Project History

Chronological narrative of porting GhostLock (CVE-2026-43499) to the
Motorola Moto G Stylus 5G 2023 (genevn, XT2315-1).

## Phase 1: Firmware analysis

Started with the Moto G's factory firmware (`U1TGNS34.42-86-3-19-2-3-3-3`).
Extracted `boot.img`, unpacked the kernel, and pulled the `vmlinux` for
static analysis.

Key discoveries:
- Kernel `5.10.240` — in the vulnerable range for CVE-2026-43499 (5.7–7.1,
  not fixed in 5.10.x)
- `CONFIG_SECURITY_SELINUX_DEVELOP=y` — runtime enforcing changes possible
- `CONFIG_MODULE_SIG` not set — unsigned kernel modules load
- `CONFIG_MODVERSIONS=y` — CRC entries required
- `perf_event_paranoid = -1` — unprivileged perf access (needed for KASLR leak)
- Qualcomm SM6450 "parrot" SoC with standard ARM64 mitigations (PAN, SCS, CFI)

Extracted all critical offsets: `init_cred` at `0x027C0A60`, `selinux_state`
at `0x02A52B90`, task_struct field offsets, `rt_mutex_waiter` layout.

## Phase 2: QEMU debugging environment

Set up a QEMU emulator with the device's kernel image to test the exploit
safely without risking the physical phone. This proved invaluable for
understanding crash behavior without waiting for 30-second reboot cycles.

The emulator confirmed:
- KASLR detection via perf_event worked
- Heap spray mechanics were sound
- The basic pselect/futex race could trigger

Caveat: some memory layout details differ between QEMU and real hardware
(physical addresses, kernel load address), but the exploit logic and code
paths are identical.

## Phase 3: 5.10 compact waiter adaptation

The existing GhostLock codebase targeted 6.1+ kernels with a larger
`rt_mutex_waiter` struct. The 5.10 kernel uses a compact 10-word (0x50 byte)
layout without separate `tree_prio` / `pi_prio` fields.

Updated the spray page geometry, pselect overlay offsets, and waiter field
calculations for the compact layout.

## Phase 4: KernelSU module loading challenges

The post-root handoff — loading `kernelsu.ko` — hit a cascade of problems:

1. **toybox `insmod -f`** — the `-f` flag isn't supported; switched to direct
   `finit_module` syscall
2. **Vermagic mismatch** — fixed with `objcopy --update-section`
3. **Empty `__versions`** — appended CRC data to satisfy `CONFIG_MODVERSIONS`
4. **80+ non-exported symbols** — Motorola's kernel doesn't export many symbols
   KernelSU needs. Built a runtime ELF patcher (`ko_loader.h`) that resolves
   symbol addresses from the vmlinux and patches `SHN_UNDEF → SHN_ABS` at load
   time
5. **ETXTBSY on finit_module** — close/fsync/reopen cycle before the syscall

## Phase 5: First real-device test (W1 works, W2 crashes)

With all the groundwork done, tested on the real Moto G:
- **W1 (SELinux)**: Succeeded ~50% of the time. SELinux switched to permissive.
- **W2 (cred)**: Crashed the phone 100% of the time. Every single attempt →
  kernel panic → reboot.

This was expected to be a minor tuning issue. It was not.

## Phase 6: Bug hunting

### Canary test

Added a `W2_CANARY` mode that performs a mode-2 ghost write to a safe writable
variable (`perf_event_paranoid`) instead of the child's cred. The canary also
crashed 100% — **the mode-2 write mechanism itself was broken**, not just the
target address.

### Bug #1: Direct map read-only

Traced the crash to `__rb_change_child`'s side-write to `*(fake_right + 8)`.
`fake_right` was computed with `data_addr()`, producing a direct-map alias
(`0xffffff80...`). On Motorola/Qualcomm, the direct map of kernel `.data` is
**read-only** at the page table level. The side-write faulted.

**Fix**: Changed `data_addr()` to `text_addr()` in `util.c` line 691. The
KIMAGE mapping IS writable for `.data`.

W2 still crashed 100% after this fix. The page fault was gone, but something
else was destroying the kernel.

### Bug #2: Phase 2 pi_tree corruption

Deep analysis of the rb_erase path revealed two phases of rbtree operations.
The spray page correctly set up `RB_EMPTY_NODE` on W0's `pi_tree_entry`
(util.c lines 813-817), which tells `rt_mutex_dequeue_pi` to skip the Phase 2
dequeue.

**But** the pselect overlay in `fops.c` overwrote `pi_pc_value` with
`fake_right` (= `init_cred` KIMAGE address for W2), **destroying the
RB_EMPTY_NODE**. Now Phase 2 fired, performing a second `rb_erase` through
`init_cred`, corrupting the global credential structure → panic.

**Fix**: Set `pi_pc_value = fake_w0 + 0x18` (self-referencing = RB_EMPTY_NODE
preserved after overlay). Phase 2 now correctly skipped.

See [BUGS-FIXED.md](BUGS-FIXED.md) for the complete technical analysis.

## Phase 7: Root achieved

With both fixes applied, the exploit succeeded **on the first attempt**:

```
[+] W1 success — SELinux permissive          (57ms)
[+] child is root!                            (58ms)
[*] uid=0(root) gid=0(root) context=u:r:ksu:s0 enforce=1
[+] KernelSU ready
```

Total exploit time: ~21 seconds. Device survived without crash or reboot.
KernelSU module loaded, `ksud install` completed, ReSukiSU manager connected.

## Phase 8: Stability assessment

Over multiple boots, the exploit lands roughly 50% of the time per boot.
The failure mode is benign — the pselect race simply doesn't trigger, and the
exploit exits cleanly. A fresh reboot and retry resolves it. Typical: 1–3
boots to root.

Keeping WiFi off and waiting 60 seconds after boot for the system to settle
improved reliability noticeably.
