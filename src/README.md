# Building from source

## Toolchain

Any `aarch64-linux-gnu-gcc` cross-compiler works. On Debian/Ubuntu:

```bash
sudo apt install gcc-aarch64-linux-gnu
```

## Compile

From the repo root:

```bash
aarch64-linux-gnu-gcc -static -O2 -Wall \
  -Wno-unused-parameter -Wno-sign-compare -Wno-unused-function \
  -Isrc/core -Isrc/devices \
  -DTARGET_CONFIG_H=\"target.h\" \
  src/core/main.c \
  src/core/util.c \
  src/core/slide.c \
  src/core/fops.c \
  src/core/pipe_physrw.c \
  src/core/root.c \
  src/core/miniadb.c \
  src/core/umh_root.c \
  -lpthread -lm \
  -o ghostlock_static
```

The binary is statically linked so it runs on bare adb shell with no
library dependencies.

## Source layout

```
src/
├── core/
│   ├── main.c              # Exploit orchestration, retry loop, child/grandchild flow
│   ├── util.c              # Spray page construction, ghost-write setup, KASLR detection
│   ├── fops.c              # pselect overlay payload — the actual UAF trigger
│   ├── slide.c             # KASLR slide detection via perf_event IP clustering
│   ├── root.c              # Post-root operations: KernelSU module load, ksud install
│   ├── pipe_physrw.c       # Pipe-based kernel physical r/w primitives
│   ├── umh_root.c          # UMH (usermode helper) root path (not used on this device)
│   ├── miniadb.c           # Minimal adb protocol for reverse-shell comms
│   ├── ko_loader.h         # Runtime ELF patcher: resolves non-exported symbols, adds CRCs
│   ├── ko_fixup.h          # Auto-generated symbol addresses + CRC entries for this kernel
│   ├── target.h            # Task struct offsets, waiter layout, spray page geometry
│   ├── common.h            # Shared macros and type definitions
│   ├── offset.h            # Offset calculation helpers (text_addr / data_addr)
│   ├── runtime_struct_offsets.h  # Runtime struct offset detection
│   └── kernelsnitch/       # Futex hash collision + mm_struct leak
│       ├── kernelsnitch.h
│       ├── futex_hash.h
│       ├── utils.h
│       └── timeutils.h
├── devices/
│   ├── offsets.h           # Device selector / common offset definitions
│   └── genevn/
│       └── offsets.h       # Moto G Stylus 2023 specific: kernel symbol offsets
```

## Adding support for another device

1. Extract a `vmlinux` from the device's boot image.
2. Run `tools/extract_target.py` to get task_struct offsets.
3. Run `tools/check_feasibility.py` to verify the kernel is vulnerable.
4. Create `src/devices/<codename>/offsets.h` with the device's symbol offsets.
5. Regenerate `ko_fixup.h` with the new kernel's symbol addresses and CRCs.
6. Build and test.
