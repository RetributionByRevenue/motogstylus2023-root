# Motorola Moto G Stylus 5G (2023) — Root via GhostLock

Root exploit for the **Motorola Moto G Stylus 5G 2023 (genevn, XT2315-1)** on kernel
`5.10.240-android12-9-00006-g25161a557b20-ab14744618`, locked bootloader, using
GhostLock (CVE-2026-43499) via USB adb. No bootloader unlock, no flashing.

> **Disclaimer:** for use on your own device only. Rooting may void your
> warranty, trip DRM checks, and carries a real brick risk if you accept OTA
> updates afterwards. Provided as-is, no warranty.

## Files

| File | Purpose |
|---|---|
| `ghostlock_static` | The exploit binary (statically linked, runs on the phone via adb shell) |
| `sample-success.log` | What a successful run looks like |
| `src/` | Complete exploit source code — build it yourself, study the mechanism |
| `tools/` | Python helpers for extracting kernel offsets from a vmlinux / BTF |
| `tools/BakaSU-v4.2.0-rc3.apk` | Root manager APK (known working version) |
| `full-writeup/` | The complete project history: bugs found, pivots, confirmed findings |

## Device Details

| Property | Value |
|---|---|
| Model | Moto G Stylus 5G - 2023 (XT2315-1) |
| Codename | `genevn` |
| SoC | Qualcomm SM6450 "parrot" |
| Kernel | `5.10.240-android12-9-00006-g25161a557b20-ab14744618` |
| Android | 14 (SDK 34), security patch 2026-05-01 |
| RAM | 6 GB Samsung LP4x |
| Bootloader | OEM locked |
| Firmware | U1TGNS34.42-86-3-19-2-3-3-3 |

## Requirements

- USB debugging enabled, adb working
- **Airplane mode ON** (or at minimum WiFi off) before running the exploit —
  network activity generates kernel interrupts and workqueue churn that compete
  with the race window, significantly reducing the landing rate
- **BakaSU v4.2.0-rc3** (formerly ReSukiSU) installed on the phone
  (`com.resukisu.resukisu`) — it supplies `libksud.so` and is the root-manager
  UI. This specific version is known to work; other versions may not. A copy of
  the APK is included at `tools/BakaSU-v4.2.0-rc3.apk`
- The `ksud` binary and KernelSU `.ko` module pushed to `/data/local/tmp/`
  (the exploit loads the module automatically from a root shell)

## How it works

1. **KASLR leak** — perf_event sampling collects kernel instruction pointers;
   clustering detects `__schedule` at known offset → KASLR base + slide.
2. **Heap spray** — KernelSnitch futex collision leaks a kernel `mm_struct`
   pointer → a payload page address in kernel memory, sprayed via UDP skb.
3. **W1 (SELinux)** — pselect/futex PI-walk race reinterprets the payload page
   as rbtree + PI-waiter nodes (compact 5.10 layout, 10 words). rb_erase
   trick writes `0x00` to `selinux_state` (offset `0x02A52B90`) → SELinux
   permissive.
4. **W2 (cred)** — same mechanism overwrites the child task's `cred` pointer
   with `init_cred` (offset `0x027C0A60`) via KIMAGE mapping → child runs
   as **uid 0**. Phase 2 pi_tree is preserved as `RB_EMPTY_NODE` through
   the pselect overlay to prevent a second rb_erase through `init_cred`.
5. **Handoff** — grandchild forks with clean creds, runtime-patches the
   KernelSU `.ko` (resolves 80+ non-exported symbols, adds `__versions`
   CRCs), calls `finit_module`, then `ksud install` → KernelSU active.

### Key challenges on this device (vs. other GhostLock targets)

- **5.10 compact waiter** — 10-word `rt_mutex_waiter` (no separate `tree_prio`
  / `pi_prio` fields), different pselect overlay geometry than 6.1+.
- **Direct map read-only** — Motorola/Qualcomm marks the direct-map alias of
  kernel `.data` as read-only; W2 must use the KIMAGE mapping (`text_addr`)
  for `init_cred`, not the linear map (`data_addr`).
- **Phase 2 pi_tree corruption** — the pselect overlay destroys the spray
  page's `RB_EMPTY_NODE` setup on W0's `pi_tree_entry`; without preserving
  it, `rt_mutex_dequeue_pi` fires a second `rb_erase` through `init_cred`,
  panicking the kernel 100% of the time.
- **No `ashmem_misc_fops`** — UMH path unavailable; uses direct PI-write W1/W2
  route instead.
- **80+ non-exported symbols** — KernelSU `.ko` references symbols Motorola
  doesn't export; solved by runtime ELF patching (`ko_loader.h`).

## Usage

Push and run:

```bash
adb push ghostlock_static /data/local/tmp/
adb shell "chmod 755 /data/local/tmp/ghostlock_static"
adb shell "/data/local/tmp/ghostlock_static"
```

Success looks like:

```
[+] KASLR: base=0xffffffe579200000 slide=0x2571200000
[*] SELINUX CHECK after pselect: enforce=0
[+] child is root!
[+] root shell pid=22233 uid=0
[*] uid=0(root) gid=0(root) groups=0(root) context=u:r:ksu:s0 enforce=1
```

Verify:

```bash
adb shell su -c id
# uid=0(root) gid=0(root) groups=0(root) context=u:r:ksu:s0
```

## Important

- **Root is per-boot.** The kernel module lives in memory only; a reboot clears
  it. After every reboot, re-run the exploit. Expect roughly a 50%
  landing rate per boot — if it exits without `[+] KernelSU ready`, just reboot
  and run it again (1–3 tries is normal).
- Termux and other apps need a one-time grant in the BakaSU **Superuser**
  tab. The grant resets on reboot — re-grant after re-rooting.
- **Do not take OTA updates** while rooted — an OTA on a locked bootloader with
  kernel patching is a brick risk. Once rooted you can kill automatic updates:
  `su -c 'pm disable-user com.motorola.ccc.ota && settings put global ota_disable_automatic_update 1'`
- A panic during a run is possible — the phone simply reboots; retry.
- If the phone lands in **fastboot mode** after a crash, run `fastboot reboot`
  from your PC to boot it back to Android.

## Building from source

See [`src/README.md`](src/README.md) for build instructions. Requires
`aarch64-linux-gnu-gcc` (any recent cross-compiler).

## Credits

- [GhostLock (CVE-2026-43499)](https://github.com/YuKongA/ghostlock-app) — the
  futex PI UAF exploit mechanism
- [KernelSU](https://github.com/tiann/KernelSU) / [SukiSU-Ultra](https://github.com/pzqqt/SukiSU-Ultra) —
  kernel module and root manager
- [ReSukiSU](https://github.com/Baka-SU/BakaSU) — root manager APK

## License

This project is provided for educational and research purposes. The exploit
source is derived from the GhostLock project (Apache-2.0). Use responsibly.
