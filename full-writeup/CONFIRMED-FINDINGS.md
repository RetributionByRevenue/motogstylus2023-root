# Confirmed Findings

Hard technical facts verified against `vmlinux` (5.10.240) and the running
Moto G Stylus 5G 2023 (genevn, XT2315-1). All addresses are KIMAGE-relative
offsets from `_text = 0xffffffc008000000` unless noted.

## Kernel version

```
5.10.240-android12-9-00006-g25161a557b20-ab14744618
```

Firmware: `U1TGNS34.42-86-3-19-2-3-3-3`

## Vulnerability

**CVE-2026-43499** — futex PI (Priority Inheritance) use-after-free.

In `remove_waiter`, `mrs x20, sp_el0` loads the CURRENT task (the requeuer),
then `str xzr, [x20, #2200]` clears `current->pi_blocked_on = NULL`. This
clears the **requeuer's** `pi_blocked_on`, not the **waiter's**. The waiter's
`pi_blocked_on` remains dangling after `FUTEX_CMP_REQUEUE_PI` returns
`-EDEADLK`.

Affected: Linux 5.7 – 7.1. Fixed in 6.1.175, 6.6.140, 6.12.86. **NOT fixed
in 5.10.x** — the Moto G's kernel is permanently vulnerable.

## Kernel memory layout

```
_text              = 0xffffffc008000000   (KIMAGE base, before KASLR)
_sdata             = 0xffffffc00a790000   (writable .data starts)
init_cred          = 0xffffffc00a7c0a60   (IN writable .data)
__start_once       = 0xffffffc00a92d598   (ro_after_init starts)
selinux_state      = 0xffffffc00aa52b90   (in .bss, WRITABLE)
```

### Critical offsets (from `_text`)

| Symbol | Offset | Section |
|---|---|---|
| `init_cred` | `0x027C0A60` | `.data` (writable) |
| `selinux_state` | `0x02A52B90` | `.bss` (writable) |
| `__schedule` | `0x01A01E9C` | `.text` |

### Physical memory

```
kphys_load   = 0xa8000000
phys_offset  = 0x80000000
PAGE_OFFSET  = 0xffffff8000000000
```

## KASLR

`CONFIG_RANDOMIZE_BASE=y`. Virtual base randomized. Detected at runtime via
`perf_event` IP sampling — 1024 kernel instruction pointers collected, densest
4KB window identifies `__schedule` at known offset `0x01A01E9C` from base.

## task_struct offsets

| Field | Offset |
|---|---|
| `prio` | `0x84` |
| `mm` | `0x518` |
| `real_cred` | `0x778` |
| `cred` | `0x780` |
| `pi_lock` | `0x86C` |
| `pi_waiters` | `0x880` |
| `pi_top_task` | `0x890` |
| `pi_blocked_on` | `0x898` |

## rt_mutex_waiter layout (5.10 compact, 10 words = 0x50 bytes)

```
+0x00  tree_entry.rb_node  (tree_entry.__rb_parent_color)
+0x08  tree_entry.rb_right
+0x10  tree_entry.rb_left
+0x18  pi_tree_entry.rb_node  (pi_tree_entry.__rb_parent_color)
+0x20  pi_tree_entry.rb_right
+0x28  pi_tree_entry.rb_left
+0x30  task
+0x38  lock
+0x40  prio
+0x48  deadline
```

This is the **compact** layout — no separate `tree_prio` / `pi_prio` fields.
6.1+ kernels have a larger layout with separate priority sub-structs.

## Kernel config (security-relevant)

| Config | Value |
|---|---|
| `CONFIG_ARM64_SW_TTBR0_PAN` | `y` |
| `CONFIG_SHADOW_CALL_STACK` | `y` |
| `CONFIG_CFI_CLANG` | `y` |
| `CONFIG_RANDOMIZE_BASE` | `y` |
| `CONFIG_PREEMPT` | `y` |
| `CONFIG_MODULE_SIG` | not set |
| `CONFIG_MODVERSIONS` | `y` |
| `CONFIG_KPROBES` | `y` |
| `CONFIG_SECURITY_SELINUX_DEVELOP` | `y` |
| `CONFIG_SECURITY_SELINUX_DISABLE` | not set |
| `CONFIG_MODULE_FORCE_LOAD` | not set |
| `perf_event_paranoid` | `-1` |

## Direct map vs KIMAGE mapping

- `data_addr(x)` → direct map alias: `PAGE_OFFSET + phys - phys_offset` → `0xffffff80...` range
- `text_addr(x)` → KIMAGE mapping: `kaslr_base + offset` → `0xffffffdc/e...` range

**Critical**: Motorola/Qualcomm marks the direct-map alias of kernel `.data` as
**READ-ONLY**. Any write to `data_addr(init_cred)` faults. Must use
`text_addr(init_cred)` for the W2 ghost write.

## selinux_state

`selinux_state` is the **struct base**. The `enforcing` field is at byte
offset 0 within the struct. Writing `0x00` to `selinux_state` sets
`enforcing = 0` → SELinux permissive.

`CONFIG_SECURITY_SELINUX_DEVELOP=y` means the kernel respects runtime
enforcing changes. `CONFIG_SECURITY_SELINUX_DISABLE` is NOT set, so the
`disable` path is unavailable.

## Ghost write mechanism

### Phase 1: tree_entry rb_erase

`rb_erase` Case 2 (node has only left child):
- `child = tree_left = target_address`
- `child->__rb_parent_color = tree.__rb_parent_color = ghost_write_value`

For W1: writes spray page addr (low byte `0x00`) to `*selinux_state` → `enforcing = 0`.
For W2: writes `init_cred` (KIMAGE) to `child_task->cred`.

Side-effect: `__rb_change_child` writes to `*(tree.__rb_parent_color + 8)`.

### Phase 2: pi_tree_entry operations

`rt_mutex_dequeue_pi` checks `RB_EMPTY_NODE` on the pi_tree_entry. If NOT
empty, fires a **second** `rb_erase` through the pi_tree_entry values.

For W1: Phase 2 goes through spray_page+0x100 (writable, benign).
For W2: Phase 2 would go through `init_cred` (KIMAGE) — **corrupts the global
credential structure and panics the kernel**. Must preserve `RB_EMPTY_NODE`
through the pselect overlay.

## KernelSU module loading

- `CONFIG_MODULE_SIG` is not set — unsigned modules load.
- `CONFIG_MODVERSIONS=y` — CRC entries required in `__versions` section.
- `CONFIG_MODULE_FORCE_LOAD` is not set — cannot skip CRC checks.
- 80+ non-exported symbols — resolved by runtime ELF patching in `ko_loader.h`.
- toybox `insmod` lacks `-f` flag — use `finit_module` syscall directly.
- Vermagic must match exactly — patched via `objcopy --update-section`.
