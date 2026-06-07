/* SPDX-License-Identifier: GPL-2.0 */
/*
 * include/nekros/types.h — Nekros kernel primitive types
 *
 * Every kernel source file includes this first.
 * No standard library. No external dependencies.
 * Built for x86-64 long mode.
 */
#ifndef NEKROS_TYPES_H
#define NEKROS_TYPES_H

/* ── Compiler attributes ──────────────────────────────────── */
#define __packed          __attribute__((packed))
#define __aligned(n)      __attribute__((aligned(n)))
#define __noreturn        __attribute__((noreturn))
#define __used            __attribute__((used))
#define __section(s)      __attribute__((section(s)))
#define __always_inline   __attribute__((always_inline)) inline
#define __noinline        __attribute__((noinline))
#define __weak            __attribute__((weak))
#define __cold            __attribute__((cold))
#define __pure            __attribute__((pure))
#define likely(x)         __builtin_expect(!!(x), 1)
#define unlikely(x)       __builtin_expect(!!(x), 0)
#define barrier()         __asm__ __volatile__("" ::: "memory")
#define ARRAY_SIZE(a)     (sizeof(a) / sizeof((a)[0]))
#define ALIGN(x, a)       (((x) + (a) - 1) & ~((a) - 1))
#define ALIGN_DOWN(x, a)  ((x) & ~((a) - 1))
#define MIN(a, b)         ((a) < (b) ? (a) : (b))
#define MAX(a, b)         ((a) > (b) ? (a) : (b))
#define BIT(n)            (1UL << (n))
#define NULL              ((void *)0)
#define offsetof(t, m)    __builtin_offsetof(t, m)
#define container_of(ptr, type, member) \
    ((type *)((char *)(ptr) - offsetof(type, member)))

/* ── Integer types ────────────────────────────────────────── */
typedef unsigned char       u8;
typedef unsigned short      u16;
typedef unsigned int        u32;
typedef unsigned long long  u64;
typedef signed char         s8;
typedef signed short        s16;
typedef signed int          s32;
typedef signed long long    s64;
typedef u64                 uintptr_t;
typedef s64                 intptr_t;
typedef u64                 size_t;
typedef s64                 ssize_t;
typedef s32                 pid_t;
typedef u32                 uid_t;
typedef u32                 gid_t;
typedef u64                 phys_addr_t;
typedef u64                 virt_addr_t;
typedef u64                 off_t;
typedef u32                 dev_t;
typedef u64                 ino_t;
typedef u32                 mode_t;

/* ── Boolean ──────────────────────────────────────────────── */
typedef _Bool bool;
#define true  1
#define false 0

/* ── Fixed-point arithmetic (Q16, Q32) ───────────────────── */
typedef u64 q16_t;   /* 48.16 fixed point */
typedef u64 q32_t;   /* 32.32 fixed point */
#define Q16(n)       ((q16_t)((n) << 16))
#define Q32(n)       ((q32_t)((u64)(n) << 32))
#define Q16_TO_INT(x) ((x) >> 16)
#define Q32_TO_INT(x) ((x) >> 32)

/* ── Error codes ──────────────────────────────────────────── */
#define EOK      0
#define EPERM    1
#define ENOENT   2
#define ESRCH    3
#define EINTR    4
#define EIO      5
#define ENXIO    6
#define E2BIG    7
#define ENOMEM  12
#define EACCES  13
#define EFAULT  14
#define EBUSY   16
#define EEXIST  17
#define ENODEV  19
#define ENOTDIR 20
#define EISDIR  21
#define EINVAL  22
#define ENFILE  23
#define EMFILE  24
#define EFBIG   27
#define ENOSPC  28
#define EROFS   30
#define EPIPE   32
#define ERANGE  34
#define EAGAIN  35
#define ENOSYS  38
#define ENODATA 61
#define ETIME   62
#define ENOBUFS 105
#define EALREADY 114
#define ENOTTY   25
#define EMSGSIZE 90
#define ENOBUFS 105
#define ETIMEDOUT 110

#define IS_ERR(ptr)     ((uintptr_t)(ptr) > (uintptr_t)-4096UL)
#define ERR_PTR(e)      ((void *)(intptr_t)(e))
#define PTR_ERR(ptr)    ((s64)(intptr_t)(ptr))

/* ── Page constants ───────────────────────────────────────── */
#define PAGE_SHIFT      12
#define PAGE_SIZE       (1UL << PAGE_SHIFT)
#define PAGE_MASK       (~(PAGE_SIZE - 1))
#define PAGE_ALIGN(a)   ALIGN(a, PAGE_SIZE)
#define virt_to_phys(v) ((phys_addr_t)(v) - 0xFFFFFFFF80000000ULL)
#define phys_to_virt(p) ((virt_addr_t)(p) + 0xFFFFFFFF80000000ULL)

/* ── CPU constants ────────────────────────────────────────── */
#define NCPUS_MAX       256
#define CACHE_LINE_SIZE 64

/* ── Atomic types (x86-64 guaranteed word-size atomicity) ─── */
typedef struct { volatile s32 counter; } atomic_t;
typedef struct { volatile s64 counter; } atomic64_t;

static __always_inline s32 atomic_read(const atomic_t *a)
    { return __atomic_load_n(&a->counter, __ATOMIC_SEQ_CST); }
static __always_inline void atomic_set(atomic_t *a, s32 v)
    { __atomic_store_n(&a->counter, v, __ATOMIC_SEQ_CST); }
static __always_inline s32 atomic_inc_return(atomic_t *a)
    { return __atomic_add_fetch(&a->counter, 1, __ATOMIC_SEQ_CST); }
static __always_inline s32 atomic_dec_return(atomic_t *a)
    { return __atomic_sub_fetch(&a->counter, 1, __ATOMIC_SEQ_CST); }
static __always_inline s64 atomic64_read(const atomic64_t *a)
    { return __atomic_load_n(&a->counter, __ATOMIC_SEQ_CST); }
static __always_inline void atomic64_set(atomic64_t *a, s64 v)
    { __atomic_store_n(&a->counter, v, __ATOMIC_SEQ_CST); }
static __always_inline s64 atomic64_inc_return(atomic64_t *a)
    { return __atomic_add_fetch(&a->counter, 1, __ATOMIC_SEQ_CST); }
static __always_inline s64 atomic64_add_return(atomic64_t *a, s64 v)
    { return __atomic_add_fetch(&a->counter, v, __ATOMIC_SEQ_CST); }
static __always_inline s64 atomic64_cmpxchg(atomic64_t *a, s64 old, s64 new)
    { __atomic_compare_exchange_n(&a->counter, &old, new, 0,
        __ATOMIC_SEQ_CST, __ATOMIC_SEQ_CST); return old; }

/* ── Spinlock (x86-64 ticket lock) ───────────────────────── */
typedef struct {
    volatile u16 owner;
    volatile u16 next;
} spinlock_t;
#define SPINLOCK_INIT   { 0, 0 }

static __always_inline void spin_lock(spinlock_t *l) {
    u16 ticket = __atomic_fetch_add(&l->next, 1, __ATOMIC_SEQ_CST);
    while (__atomic_load_n(&l->owner, __ATOMIC_ACQUIRE) != ticket)
        __asm__ volatile("pause" ::: "memory");
}
static __always_inline void spin_unlock(spinlock_t *l) {
    __atomic_fetch_add(&l->owner, 1, __ATOMIC_RELEASE);
}
static __always_inline bool spin_trylock(spinlock_t *l) {
    u16 t = __atomic_load_n(&l->next, __ATOMIC_RELAXED);
    u16 o = __atomic_load_n(&l->owner, __ATOMIC_RELAXED);
    if (t != o) return false;
    return __atomic_compare_exchange_n(&l->next, &t, t + 1, 0,
        __ATOMIC_SEQ_CST, __ATOMIC_RELAXED);
}

/* ── Doubly-linked list ───────────────────────────────────── */
typedef struct list_head { struct list_head *next, *prev; } list_head_t;
#define LIST_HEAD_INIT(n) { &(n), &(n) }
#define LIST_HEAD(n)      list_head_t n = LIST_HEAD_INIT(n)

static inline void list_init(list_head_t *h) { h->next = h->prev = h; }
static inline bool list_empty(const list_head_t *h) { return h->next == h; }
static inline void __list_add(list_head_t *n,
    list_head_t *prev, list_head_t *next) {
    next->prev = n; n->next = next;
    n->prev = prev; prev->next = n;
}
static inline void list_add(list_head_t *n, list_head_t *h)
    { __list_add(n, h, h->next); }
static inline void list_add_tail(list_head_t *n, list_head_t *h)
    { __list_add(n, h->prev, h); }
static inline void list_del(list_head_t *n) {
    n->prev->next = n->next;
    n->next->prev = n->prev;
    n->next = n->prev = NULL;
}
#define list_entry(ptr, type, member) container_of(ptr, type, member)
#define list_for_each(pos, head) \
    for (pos = (head)->next; pos != (head); pos = pos->next)
#define list_for_each_safe(pos, n, head) \
    for (pos = (head)->next, n = pos->next; pos != (head); \
         pos = n, n = pos->next)
#define list_for_each_entry(pos, head, member) \
    for (pos = list_entry((head)->next, typeof(*pos), member); \
         &pos->member != (head); \
         pos = list_entry(pos->member.next, typeof(*pos), member))

/* ── Read-write lock ──────────────────────────────────────── */
typedef struct { atomic_t count; } rwlock_t;
#define RWLOCK_INIT { .count = { 0 } }
static inline void read_lock(rwlock_t *l) {
    while (1) {
        s32 c = atomic_read(&l->count);
        if (c >= 0 && __atomic_compare_exchange_n(
                &l->count.counter, &c, c+1, 0,
                __ATOMIC_SEQ_CST, __ATOMIC_RELAXED))
            return;
        __asm__ volatile("pause");
    }
}
static inline void read_unlock(rwlock_t *l) { atomic_dec_return(&l->count); }
static inline void write_lock(rwlock_t *l) {
    s32 zero = 0;
    while (!__atomic_compare_exchange_n(&l->count.counter, &zero, -1, 0,
            __ATOMIC_SEQ_CST, __ATOMIC_RELAXED)) {
        zero = 0; __asm__ volatile("pause");
    }
}
static inline void write_unlock(rwlock_t *l) { atomic_set(&l->count, 0); }


/* Additional POSIX error codes */
#define EBADF        9
#define ENOTCONN   107
#define ECONNRESET 104
#endif /* NEKROS_TYPES_H */

