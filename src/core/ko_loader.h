/* Runtime KernelSU .ko patcher and loader for genevn.
 * Patches the ELF symbol table to resolve non-exported symbols
 * using vmlinux addresses + KASLR slide, adds correct CRC entries
 * to __versions, then calls init_module(). */

#ifndef KO_LOADER_H
#define KO_LOADER_H

#include <elf.h>
#include <fcntl.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include "ko_fixup.h"

struct modversion_info {
  uint64_t crc;
  char name[56];
};

static int patch_and_load_ko(const char *ko_path, uint64_t kaslr_slide) {
  int fd = open(ko_path, O_RDONLY);
  if (fd < 0) return -1;

  struct stat st;
  if (fstat(fd, &st) < 0) { close(fd); return -1; }
  size_t orig_size = st.st_size;

  /* Allocate extra space for new __versions section */
  size_t versions_size = KO_CRC_COUNT * sizeof(struct modversion_info);
  size_t alloc_size = orig_size + versions_size + 4096;
  uint8_t *buf = malloc(alloc_size);
  if (!buf) { close(fd); return -1; }

  ssize_t nread = read(fd, buf, orig_size);
  close(fd);
  if (nread != (ssize_t)orig_size) { free(buf); return -1; }

  /* Verify ELF */
  Elf64_Ehdr *ehdr = (Elf64_Ehdr *)buf;
  if (memcmp(ehdr->e_ident, ELFMAG, SELFMAG) != 0 ||
      ehdr->e_ident[EI_CLASS] != ELFCLASS64) {
    free(buf); return -1;
  }

  Elf64_Shdr *shdrs = (Elf64_Shdr *)(buf + ehdr->e_shoff);
  uint16_t shnum = ehdr->e_shnum;

  /* Find .symtab, .strtab, .modinfo, __versions sections */
  Elf64_Shdr *symtab_sh = NULL, *strtab_sh = NULL;
  Elf64_Shdr *modinfo_sh = NULL, *versions_sh = NULL;
  Elf64_Shdr *shstrtab_sh = &shdrs[ehdr->e_shstrndx];
  char *shstrtab = (char *)(buf + shstrtab_sh->sh_offset);

  for (int i = 0; i < shnum; i++) {
    char *name = shstrtab + shdrs[i].sh_name;
    if (shdrs[i].sh_type == SHT_SYMTAB) symtab_sh = &shdrs[i];
    if (strcmp(name, ".strtab") == 0) strtab_sh = &shdrs[i];
    if (strcmp(name, ".modinfo") == 0) modinfo_sh = &shdrs[i];
    if (strcmp(name, "__versions") == 0) versions_sh = &shdrs[i];
  }

  if (!symtab_sh || !strtab_sh) {
    pr_warning("ko_loader: no .symtab/.strtab\n");
    free(buf); return -1;
  }

  /* Step 1: Patch non-exported symbols from SHN_UNDEF → SHN_ABS */
  char *strtab = (char *)(buf + strtab_sh->sh_offset);
  Elf64_Sym *syms = (Elf64_Sym *)(buf + symtab_sh->sh_offset);
  int nsyms = symtab_sh->sh_size / sizeof(Elf64_Sym);
  int patched = 0;

  for (int i = 0; i < nsyms; i++) {
    if (syms[i].st_shndx != SHN_UNDEF) continue;
    if (syms[i].st_name == 0) continue;
    const char *sym_name = strtab + syms[i].st_name;

    for (int j = 0; j < KO_MISSING_COUNT; j++) {
      if (strcmp(sym_name, ko_missing[j].name) == 0) {
        uint64_t runtime_addr = ko_missing[j].vmlinux_addr + kaslr_slide;
        syms[i].st_shndx = SHN_ABS;
        syms[i].st_value = runtime_addr;
        patched++;
        break;
      }
    }
  }
  pr_info("ko_loader: patched %d/%d non-exported symbols\n", patched, KO_MISSING_COUNT);

  /* Step 2: Build __versions data with correct CRCs */
  struct modversion_info *vers = calloc(KO_CRC_COUNT, sizeof(struct modversion_info));
  if (!vers) { free(buf); return -1; }
  for (int i = 0; i < KO_CRC_COUNT; i++) {
    vers[i].crc = ko_crcs[i].crc;
    strncpy(vers[i].name, ko_crcs[i].name, sizeof(vers[i].name) - 1);
  }

  /* Write patched .ko + versions to a temp file, then use finit_module
   * (init_module with raw buffer doesn't let us easily add new sections).
   * Instead: write patched image to temp file, use objcopy-like approach
   * to update __versions, or just embed versions in existing section space. */

  /* Actually, for init_module we need the raw image. The kernel module loader
   * reads sections from the image. If __versions section exists (even with
   * size 0), we need to fill it with CRC data. Since the section has size 0,
   * we can't just write into it.
   *
   * Plan B: Write patched .ko to temp file, then fix __versions by extending
   * the file. But that's complex ELF surgery.
   *
   * Plan C: If the versions section has size 0 AND we removed it with objcopy,
   * the section index will be 0 → check_modstruct_version returns
   * try_to_force_load which ALSO fails.
   *
   * Plan D: SKIP CRC checks entirely by patching the kernel's
   * check_modstruct_version to always return 1. We already have ghost write!
   *
   * Actually the SIMPLEST approach: We already have root. We can write to
   * /proc/sys/kernel/modprobe and other kernel params. But the real answer is:
   * just write the __versions data into the existing image if we can find space,
   * OR write a new file with the section properly included.
   */

  /* Write the complete patched module to a temp file, appending __versions
   * data and fixing up the section header to point to it. */
  size_t new_size = orig_size;

  if (versions_sh) {
    /* __versions section exists — append CRC data at end of file,
     * update section header to point there */
    size_t vers_data_off = (orig_size + 7) & ~7ULL; /* align to 8 */
    versions_sh->sh_offset = vers_data_off;
    versions_sh->sh_size = KO_CRC_COUNT * sizeof(struct modversion_info);
    new_size = vers_data_off + versions_sh->sh_size;
  }

  char tmppath[] = "/data/local/tmp/.ko_patched_XXXXXX";
  int tmpfd = mkstemp(tmppath);
  if (tmpfd < 0) {
    pr_warning("ko_loader: mkstemp failed: %s\n", strerror(errno));
    free(vers); free(buf); return -1;
  }

  /* Write the patched ELF image */
  if (write(tmpfd, buf, orig_size) != (ssize_t)orig_size) {
    pr_warning("ko_loader: write failed\n");
    close(tmpfd); unlink(tmppath); free(vers); free(buf); return -1;
  }

  if (versions_sh) {
    /* Pad to alignment */
    size_t pad = ((orig_size + 7) & ~7ULL) - orig_size;
    if (pad > 0) {
      char zeros[8] = {0};
      write(tmpfd, zeros, pad);
    }
    /* Write __versions data */
    write(tmpfd, vers, KO_CRC_COUNT * sizeof(struct modversion_info));
  }

  free(vers);
  free(buf);
  fsync(tmpfd);
  close(tmpfd);

  /* Reopen read-only for finit_module (kernel rejects write-open fds) */
  int rofd = open(tmppath, O_RDONLY);
  if (rofd < 0) {
    pr_warning("ko_loader: reopen failed: %s\n", strerror(errno));
    unlink(tmppath);
    return -1;
  }
  long ret = syscall(__NR_finit_module, rofd, "", 0);
  int saved_errno = errno;
  close(rofd);

  if (ret == 0) {
    pr_success("ko_loader: module loaded from %s!\n", ko_path);
    unlink(tmppath);
    /* Post-load diagnostics */
    FILE *dlog2 = popen("dmesg | tail -40", "r");
    if (dlog2) {
      char dline2[256];
      while (fgets(dline2, sizeof(dline2), dlog2))
        pr_info("  post-load dmesg: %s", dline2);
      pclose(dlog2);
    }
    /* Check sysfs */
    struct stat sysfs_st;
    if (stat("/sys/module/kernelsu", &sysfs_st) == 0) {
      pr_success("ko_loader: /sys/module/kernelsu/ exists\n");
    } else {
      pr_warning("ko_loader: /sys/module/kernelsu/ MISSING (errno=%d)\n", errno);
    }
    /* Check /proc/modules */
    FILE *pmod = fopen("/proc/modules", "r");
    if (pmod) {
      char mline[256];
      while (fgets(mline, sizeof(mline), pmod)) {
        if (strstr(mline, "kernelsu"))
          pr_info("  /proc/modules: %s", mline);
      }
      fclose(pmod);
    }
    return 0;
  }

  if (saved_errno == EEXIST) {
    pr_info("ko_loader: module already loaded (EEXIST) — OK\n");
    unlink(tmppath);
    return 0;
  }
  pr_warning("ko_loader: finit_module failed: errno=%d (%s)\n", saved_errno, strerror(saved_errno));
  FILE *dlog = popen("dmesg | tail -20", "r");
  if (dlog) {
    char dline[256];
    while (fgets(dline, sizeof(dline), dlog))
      pr_info("  dmesg: %s", dline);
    pclose(dlog);
  }
  unlink(tmppath);
  return -1;
}

#endif /* KO_LOADER_H */
