# Bugs Fixed

Two critical bugs blocked the W2 (credential overwrite) ghost write on the
Moto G Stylus 2023. Both had to be fixed for root to succeed — Bug #1 was
necessary but not sufficient; Bug #2 was the breakthrough.

---

## Bug #1: Direct map read-only on Motorola/Qualcomm

### Symptom

W2 crashed the phone 100% of the time. W1 succeeded roughly 50% of the time
(expected). Every W2 attempt → immediate kernel panic → reboot.

### Diagnosis

A canary test was added: `W2_CANARY=1` performed a mode-2 ghost write to a
safe writable variable (`perf_event_paranoid` in `.data`) instead of to the
child task's `cred`. The canary also crashed 100%, confirming the mode-2
mechanism itself was broken — not the specific target address.

### Root cause

The `fake_right` value for mode 2 was computed using `data_addr()`:

```c
// util.c line 691 — BEFORE fix
fake_right = data_addr(KIMAGE_TEXT_BASE + active_offsets->off_init_cred);
// Produced: 0xffffff802a7c0a60 (direct map alias)
```

The ghost write's side-effect — `__rb_change_child` — writes to
`*(fake_right + 8)`, i.e. `*(init_cred + 8)` via the direct map. But
**Motorola/Qualcomm marks the direct-map alias of kernel `.data` as
read-only**. The write faults with a page-level permission error.

### Fix

```c
// util.c line 691 — AFTER fix
fake_right = text_addr(KIMAGE_TEXT_BASE + active_offsets->off_init_cred);
// Produces: 0xffffffe57b9c0a60 (KIMAGE mapping, writable)
```

Changed `data_addr()` to `text_addr()` so the side-write goes through the
KIMAGE mapping, which IS writable for `.data` section addresses.

### Result

Fixed the page fault. But W2 **still crashed 100%**. Something else was wrong.

**File**: `src/core/util.c` line 691

---

## Bug #2: Phase 2 RB_EMPTY_NODE destroyed by pselect overlay

### Symptom

Even after Bug #1 fix, W2 crashed 100%. All 5 retry attempts in the loop
triggered kernel panics. W1 also crashed occasionally — not 100%, but more
than expected.

### Diagnosis

Deep analysis of the rb_erase code path revealed **two phases** of rbtree
operations during the PI-walk:

1. **Phase 1** (`tree_entry`): The intended ghost write — rb_erase walks the
   `tree_entry` fields and writes the target value. This is what W1 and W2
   rely on.

2. **Phase 2** (`pi_tree_entry`): `rt_mutex_dequeue_pi` checks
   `RB_EMPTY_NODE(node)` on the waiter's `pi_tree_entry`. If the node is
   NOT marked empty, it fires a **second** `rb_erase` through the
   `pi_tree_entry` values.

The spray page setup in `util.c` (lines 813-817) correctly sets W0's
`pi_tree_entry` to `RB_EMPTY_NODE` — a self-referencing `__rb_parent_color`
that tells `rt_mutex_dequeue_pi` to skip Phase 2.

**But** the pselect overlay in `fops.c` (lines 206-209) **overwrites**
the pi_tree_entry fields AFTER the spray page is set up:

```c
// fops.c lines 206-209 — BEFORE fix
} else if (pselect_custom_write_enabled()) {
    pi_pc_value = fake_right ? fake_right : (pselect_custom_target - 8);
    pi_right_value = 0;
    pi_left_value = pselect_custom_target;
}
```

For W2, `fake_right = init_cred_KIMAGE`, so `pi_pc_value = init_cred_KIMAGE`.
This **destroys the RB_EMPTY_NODE** setup. Now `rt_mutex_dequeue_pi` sees a
non-empty node and fires Phase 2 `rb_erase` through `init_cred` — corrupting
the global credential structure and panicking the kernel.

For W1, `pi_pc_value` pointed to spray_page+0x100 (writable, benign), so
Phase 2 happened but didn't crash — it just wrote to a throwaway spray page.
This is why W1 mostly worked while W2 always crashed.

### Fix

```c
// fops.c lines 206-209 — AFTER fix
} else if (pselect_custom_write_enabled()) {
    pi_pc_value = fake_w0 + 0x18;  // self-referencing = RB_EMPTY_NODE preserved
    pi_right_value = 0;
    pi_left_value = 0;
}
```

Set `pi_pc_value` to `fake_w0 + 0x18` — the pi_tree_entry's own address. This
makes `__rb_parent_color` point to itself, which is exactly the `RB_EMPTY_NODE`
pattern. Now `rt_mutex_dequeue_pi` sees an empty node and **skips Phase 2
entirely**, preventing the destructive second rb_erase through `init_cred`.

### Result

**Root achieved on the first attempt.** W1 succeeded (SELinux → permissive in
57ms), W2 succeeded (child is root, no crash), KernelSU loaded
(`context=u:r:ksu:s0`), device survived.

**File**: `src/core/fops.c` lines 206-209

---

## Why both fixes were required

| | Bug #1 only | Bug #2 only | Both fixes |
|---|---|---|---|
| **W1** | ~50% success | ~50% success | ~50% success |
| **W2** | 100% crash (page fault on direct map) | 100% crash (Phase 2 corrupts init_cred) | Success |
| **Root** | Never | Never | **Yes** |

Bug #1 eliminated the page-level fault. Bug #2 eliminated the logical
corruption. Neither fix alone was sufficient — both had to be applied
together for W2 to land safely.
