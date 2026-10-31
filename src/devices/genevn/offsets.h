/* Motorola Moto g stylus 2023 (genevn, XT2315-1) — Qualcomm SM6450,
 * kernel 5.10.240-android12-9-00006-g25161a557b20-ab14744618
 * (fw: U1TGNS34.42-86-3-19-2-3-3-3, Android 14 — the build the attached
 * phone actually runs; measured 2026-10-28 from fw-240/boot.img).
 *
 * Same GKI branch (android12-9 5.10) family layout as the 5.10.233 base:
 * all shared data symbols carry the same sections; per-symbol offsets below
 * are re-measured on analysis-240 vmlinux (kallsyms 143033 symbols;
 * reconstruct_vmlinux + export_kallsyms) + extract_target verification.
 *
 * Compact waiter (10 words), static pselect geometry:
 *   futex chain: __arm64_sys_futex(0x90) -> do_futex(0x70) ->
 *     futex_wait_requeue_pi(0x1a0), waiter (rt_mutex_wait_proxy_lock x2)
 *     @ body_sp+0x90  => waiter = futex_entry - 0x210
 *   pselect chain: __arm64_sys_pselect6(0xa0) -> core_sys_select(0x1c0),
 *     stack_fds @ sp+0x50 (kvfree guard `cmp x21, sp+0x50`)
 *     => buffer = pselect_entry - 0x210  => waiter-buffer = 0 (word 0)
 *   select() chain (what the code actually calls): __arm64_sys_select(0x80)
 *     => buffer = entry - 0x1F0; static waiter-buffer = +0x20 (shift 4).
 *     Sony measured static-1 on-device (canary); sweep shift 3..5 on device.
 *
 * Verified from this kernel's own disassembly (capstone, no BTF):
 *   task_struct: prio 0x84, pi_lock 0x86c, pi_waiters 0x880, pi_top_task
 *     0x890, pi_blocked_on 0x898 (=STRUCT_OFFSETS_5_10), real_cred 0x778,
 *     cred 0x780, audit_context 0x838, current sp_el0 base as usual.
 *   cred: copy 0xa8 (=168, prepare_creds memcpy), usage word@0,
 *     uid group 4..0x20, cap sets 5 x u64 at 0x28..0x4f, nodecount 0x98,
 *     user_ns refcount 0x90, groups ptr 0x80.
 *   selinux: enforcing byte = selinux_state + 0x0
 *     (sel_write_enforce: `strb w8, [x22]`, x22 = state; policycap bytes
 *     at +0xb..+0xc, percpu status ptr at +0x10 — do not use +0x10).
 *   waiter: rt_mutex_adjust_prio_chain reads waiter->lock@0x38,
 *     wake_state@0x40, deadline@0x48; task@0x30; compact 5.10 layout.
 *
 * Path A (UMH, C ashmem) unavailable: off_ashmem_misc_fops=0 → direct
 * PI write W1/W2 route. compat_ioctl slot = ashmem_ioctl (5.10 has no
 * separate ashmem_compat_ioctl symbol).
 *
 * kernel_phys_load unknown (no rooted unit of this model): Qualcomm DRAM
 * base = 0x80000000 (vendor_boot dtb reserved-memory starts at 0x80000000),
 * load address very likely 0xa8000000 (matches SM8650 pattern; reserved
 * carveouts end at 0xa7000000). Verify on device: first panic prints
 * PHYS_OFFSET in the cmdline tail; /proc/iomem "Kernel code" for the load
 * address. Env override: KPHYS=0xa8000000.
 *
 * Offsets relative to KIMAGE_TEXT_BASE 0xffffffc008000000 (text + kallsyms
 * derived, 142717 symbols; reconstruct_vmlinux + export_kallsyms).
 */

OFFSETS_ENTRY("5.10.240-android12-9-00006-g25161a557b20-ab14744618",
  .kernel_phys_load=0, .phys_offset=0x80000000, STRUCT_OFFSETS_5_10,
  .kimage_text_base=0xffffffc008000000ULL,
  .off_init_task=0x027ABE80, .off_init_cred=0x027C0A60, .off_init_uts_ns=0x027ABC28,
  .off_empty_zero_page=0x0299E000, .off_root_task_group=0x029A3040,
  .off_selinux_enforcing=0x02A52B90, .off_kptr_restrict=0x0279CDE8,
  .off_selinux_blob_sizes=0x022F8A00, .off_security_hook_heads=0x022F8368,
  .off_kmalloc_caches=0x022F7EA0, .off_anon_pipe_buf_ops=0x02160528,
  .off_ashmem_misc_fops=0, .off_ashmem_fops=0x022B5850,
  .off_ashmem_ioctl=0x011A4AEC, .off_ashmem_compat_ioctl=0x011A4AEC,
  .off_ashmem_mmap=0x011A565C, .off_ashmem_open=0x011A589C,
  .off_ashmem_release=0x011A593C, .off_ashmem_show_fdinfo=0x011A5A60,
  .off_configfs_read_iter=0x00689D74, .off_configfs_bin_write_iter=0x00689FEC,
  .off_copy_splice_read=0, .off_noop_llseek=0x00547000,
  .off_cap_capable_active=0,
  .off_slide_nfulnl_logger=0x027A1338, .off_slide_loggers_0_1=0x027A1270,
  .off_slide_boot_id=0x02A71BBD,
  .off_root_user=0x027BF5E0, .off_init_user_ns=0x027BF678, .off_init_groups=0x027C0B08,
  .off_system_unbound_wq=0x02799E08, .off_call_usermodehelper_exec_work=0x00166498,
),
