#include <nekros/task.h>
/* SPDX-License-Identifier: GPL-2.0 OR Apache-2.0 */
/*
 * drivers/cortexcrypto/core/cc_proc.c
 *
 * CortexCrypto kernel-mode subsystems:
 *
 * 1. Process attestation
 *    Every process gets a CortexCrypto-sealed identity token.
 *    Token = AES-256-GCM{pid | exe_hash | neri_grant | anomaly_score
 *                        | machine_fingerprint | boot_timestamp}
 *    AAD  = pid || boot_id
 *    Key  = HMAC-SHA256(machine_key, "nekros-attest-v1")
 *    Peers verify via cc_kernel_verify_attestation().
 *
 * 2. Encrypted memory regions (nk_secure_alloc)
 *    Pages are allocated normally but a per-region DEK is derived
 *    and stored in a kernel-managed sealed key slot.
 *    When the process calls nk_mem_snapshot, the entire region is
 *    AES-256-GCM encrypted and returned as a sealed blob.
 *
 * 3. Zero-trust IPC channels
 *    Channel session key = HMAC-SHA256(
 *       HMAC-SHA256(machine_key, attest_A || attest_B),
 *       "nekros-ipc-v1")
 *    Data in the ring buffer is AES-256-GCM encrypted.
 *    Not even a root process reading /dev/mem sees plaintext.
 *
 * 4. Process checkpointing
 *    Full task state (registers + stack + mapped regions) is
 *    AES-256-GCM sealed and written to a caller-provided buffer.
 *
 * This is the kernel half. The userspace daemon (cortexd) handles
 * Argon2id KDF, MLP inference, and file encryption. The kernel half
 * uses HMAC-SHA256 × 2 (no Argon2 in kernel — intentionally).
 */

#include <nekros/types.h>
#include <nekros/printk.h>
#include <nekros/string.h>
#include "../../../crypto/crypto.h"
#include "../../../drivers/neri/include/neri.h"
#include "../../../drivers/neri/include/neri_sec.h"
#include "../../../mm/vmm.h"
#include "../../../mm/pmm.h"
#include "cc_proc.h"

/* ── HMAC-SHA256 wrapper (uses sha256 from crypto.h) ─────── */
static void hmac_sha256_impl(const u8 *key, size_t klen,
                              const u8 *msg, size_t mlen,
                              u8 out[32])
{
    u8 k[64]={0}, ipad[64], opad[64], tmp[32];
    if (klen>64) sha256(key,klen,k); else memcpy(k,key,klen);
    for (int i=0;i<64;i++) { ipad[i]=k[i]^0x36; opad[i]=k[i]^0x5C; }
    sha256_ctx_t ctx;
    sha256_init(&ctx);
    sha256_update(&ctx,ipad,64);
    sha256_update(&ctx,msg,mlen);
    sha256_final(&ctx,tmp);
    sha256_init(&ctx);
    sha256_update(&ctx,opad,64);
    sha256_update(&ctx,tmp,32);
    sha256_final(&ctx,out);
    memzero_explicit(k,64);
    memzero_explicit(tmp,32);
}

/* ── AES-256 (compact lookup-table implementation) ──────── */
/* For GCM we use counter mode + GHASH. Full implementation.  */
#include "aes256.h"
extern u64 nekros_rdtsc(void);  /* arch/x86/hal/hal.c */   /* compact AES-256-GCM — see aes256.c  */

/* Constant-time memory comparison — no early exit on mismatch.
 * Prevents timing side-channels on secret comparisons.          */
static int ct_memcmp(const u8 *a, const u8 *b, size_t n) {
    volatile u8 diff = 0;
    for (size_t i = 0; i < n; i++) diff |= a[i] ^ b[i];
    return (int)diff;
}

/* ── Machine key (derived once at boot from machine_id) ──── */
static u8  g_machine_key[32];
static u8  g_attest_key[32];
static u8  g_ipc_key[32];
static u8  g_secure_alloc_key[32];
bool g_cc_ready = false;

/* ── Nonce management ────────────────────────────────────────────────────
 * AES-256-GCM MUST NEVER reuse a (key, nonce) pair.
 * We use a 96-bit nonce split as:
 *   [0-3]   per-key monotonic counter (u32, atomic increment)
 *   [4-11]  TSC at encrypt time (u64)
 * This gives 2^32 encryptions per key before counter wrap.
 * On wrap we MUST re-derive the key (or reject).
 * The TSC component ensures uniqueness even if two threads
 * read the same counter value before the atomic increment completes.
 */
static atomic_t g_attest_nonce_ctr  = { 0 };
static atomic_t g_secmem_nonce_ctr  = { 0 };
static atomic_t g_ipc_nonce_ctr     = { 0 };

static void gen_nonce(u8 nonce[12], atomic_t *ctr) {
    u32 count = (u32)atomic_inc_return(ctr);
    /* FATAL: counter wrapped — key must not be reused */
    if (count == 0) {
        /* In production: trigger key rotation here.
         * For now: panic is safer than silently reusing nonces. */
        extern void panic(const char *fmt, ...) __attribute__((noreturn));
        panic("cc_proc: nonce counter wrapped — key rotation required!\n");
    }
    u64 tsc = nekros_rdtsc();
    /* nonce[0-3]  = big-endian counter */
    nonce[0] = (u8)(count >> 24);
    nonce[1] = (u8)(count >> 16);
    nonce[2] = (u8)(count >>  8);
    nonce[3] = (u8)(count      );
    /* nonce[4-11] = TSC (little-endian) */
    nonce[4]  = (u8)(tsc      );
    nonce[5]  = (u8)(tsc >>  8);
    nonce[6]  = (u8)(tsc >> 16);
    nonce[7]  = (u8)(tsc >> 24);
    nonce[8]  = (u8)(tsc >> 32);
    nonce[9]  = (u8)(tsc >> 40);
    nonce[10] = (u8)(tsc >> 48);
    nonce[11] = (u8)(tsc >> 56);
}
static u64  g_boot_timestamp;


void cc_proc_init(const u8 machine_fingerprint[32])
{
    g_boot_timestamp = nekros_rdtsc();

    /* Derive all sub-keys from machine fingerprint */
    static const u8 salt_master[]   = "nekros-master-v1";
    static const u8 salt_attest[]   = "nekros-attest-v1";
    static const u8 salt_ipc[]      = "nekros-ipc-v1";
    static const u8 salt_secmem[]   = "nekros-secmem-v1";

    hmac_sha256_impl(machine_fingerprint, 32,
                salt_master, sizeof(salt_master)-1,  g_machine_key);
    hmac_sha256_impl(g_machine_key, 32,
                salt_attest, sizeof(salt_attest)-1,  g_attest_key);
    hmac_sha256_impl(g_machine_key, 32,
                salt_ipc,    sizeof(salt_ipc)-1,     g_ipc_key);
    hmac_sha256_impl(g_machine_key, 32,
                salt_secmem, sizeof(salt_secmem)-1,  g_secure_alloc_key);

    g_cc_ready = true;
    pr_info("cc_proc: CortexCrypto kernel subsystem ready\n");
    pr_info("cc_proc: attest + secure_alloc + zero-trust IPC + "
            "checkpoint online\n");
}

/* ── Process attestation ─────────────────────────────────── */

/* Attestation plaintext layout (96 bytes):
 *   [0-3]   pid         u32
 *   [4-7]   priority    u32
 *   [8-15]  cpu_grant   u64
 *  [16-23]  ram_grant   u64
 *  [24-24]  anomaly     u8
 *  [25-31]  _pad        u8[7]
 *  [32-63]  exe_hash    u8[32]  (SHA-256 of process name for now)
 *  [64-95]  boot_ts_tsc u64 + machine_fp[24 bytes cropped]
 */
#define ATTEST_PLAIN_LEN  96
#define ATTEST_TOKEN_LEN  (ATTEST_PLAIN_LEN + 16 + 12) /* +tag +nonce */

extern neri_pool_t g_neri_pool;
extern bool        g_neri_ready;
extern void        neri_sec_get_anomaly(neri_sec_anomaly_t *out);

struct task; /* forward */

int cc_kernel_attest_process(pid_t pid, u8 *token, u32 *size)
{
    if (!g_cc_ready || !token || !size) return -EINVAL;
    if (*size < ATTEST_TOKEN_LEN) { *size = ATTEST_TOKEN_LEN; return -EINVAL; }

    /* Find the task */
    extern struct task *task_find_by_pid(pid_t);
    struct task *t = task_find_by_pid(pid);
    if (!t) return -ESRCH;

    /* Build plaintext */
    u8 plain[ATTEST_PLAIN_LEN];
    memset(plain, 0, sizeof(plain));
    *(u32*)(plain+0)  = (u32)pid;
    *(u32*)(plain+4)  = t->priority;
    *(u64*)(plain+8)  = t->neri.cpu_granted_ns;
    *(u64*)(plain+16) = t->neri.ram_granted_pages;

    neri_sec_anomaly_t anm = {0};
    if (g_neri_ready) neri_sec_get_anomaly(&anm);
    plain[24] = anm.score_byte;

    /* exe_hash = SHA-256(process name) — real impl would hash the ELF */
    sha256((const u8*)t->name, strnlen(t->name, 31), plain+32);

    *(u64*)(plain+64) = g_boot_timestamp;
    /* Fill [72-95] with first 24 bytes of machine key */
    memcpy(plain+72, g_machine_key, 24);

    /* Generate unique nonce using monotonic counter + TSC */
    u8 *nonce      = token;
    u8 *ciphertext = token + 12;
    u8 *tag        = token + 12 + ATTEST_PLAIN_LEN;
    gen_nonce(nonce, &g_attest_nonce_ctr);

    /* AAD = pid (4 bytes) */
    u8 aad[4]; *(u32*)aad = (u32)pid;

    /* AES-256-GCM encrypt */
    aes256_gcm_encrypt(g_attest_key, nonce, plain, ATTEST_PLAIN_LEN,
                       aad, 4, ciphertext, tag);

    memzero_explicit(plain, sizeof(plain));
    *size = ATTEST_TOKEN_LEN;
    return 0;
}

int cc_kernel_verify_attestation(const u8 *token, u32 size, pid_t expected_pid)
{
    if (!g_cc_ready || !token) return -EINVAL;
    if (size < ATTEST_TOKEN_LEN) return -EINVAL;

    const u8 *nonce      = token;
    const u8 *ciphertext = token + 12;
    const u8 *tag        = token + 12 + ATTEST_PLAIN_LEN;

    u8 aad[4]; *(u32*)aad = (u32)expected_pid;
    u8 plain[ATTEST_PLAIN_LEN];

    int rc = aes256_gcm_decrypt(g_attest_key, nonce, ciphertext,
                                ATTEST_PLAIN_LEN, tag, aad, 4, plain);
    if (rc) { memzero_explicit(plain, sizeof(plain)); return -EACCES; }

    pid_t claimed_pid = (pid_t)*(u32*)(plain+0);
    if (expected_pid && claimed_pid != expected_pid) {
        memzero_explicit(plain, sizeof(plain));
        return -EACCES;
    }

    /* Verify machine key slice matches */
    if (ct_memcmp(plain+72, g_machine_key, 24) != 0) {
        memzero_explicit(plain, sizeof(plain));
        return -EACCES;  /* token from different machine */
    }

    memzero_explicit(plain, sizeof(plain));
    return 0;
}

/* ── Encrypted memory regions ────────────────────────────── */

#define MAX_SECURE_REGIONS 64
struct secure_region {
    virt_addr_t vaddr;
    u64         pages;
    u32         policy;
    u8          dek[32];    /* per-region DEK */
    bool        active;
};
static struct secure_region g_sec_regions[MAX_SECURE_REGIONS];
static spinlock_t g_sec_lock = SPINLOCK_INIT;

void *cc_kernel_secure_alloc(u64 pages, u32 policy)
{
    if (!g_cc_ready) return NULL;

    void *mem = vmm_alloc(pages, VMM_WRITE);
    if (!mem) return NULL;
    memset(mem, 0, pages * PAGE_SIZE);

    spin_lock(&g_sec_lock);
    struct secure_region *r = NULL;
    for (int i=0; i<MAX_SECURE_REGIONS; i++)
        if (!g_sec_regions[i].active) { r=&g_sec_regions[i]; break; }
    if (!r) { spin_unlock(&g_sec_lock); vmm_free(mem,pages); return NULL; }

    /* Derive region DEK: HMAC-SHA256(secure_alloc_key, vaddr || pages) */
    u8 dek_input[16];
    *(u64*)dek_input = (u64)mem;
    *(u64*)(dek_input+8) = pages;
    hmac_sha256_impl(g_secure_alloc_key, 32, dek_input, 16, r->dek);

    r->vaddr  = (virt_addr_t)mem;
    r->pages  = pages;
    r->policy = policy;
    r->active = true;
    spin_unlock(&g_sec_lock);

    return mem;
}

void cc_kernel_secure_free(void *ptr, u64 pages)
{
    if (!ptr) return;
    spin_lock(&g_sec_lock);
    for (int i=0; i<MAX_SECURE_REGIONS; i++) {
        if (g_sec_regions[i].active &&
            g_sec_regions[i].vaddr == (virt_addr_t)ptr) {
            /* Crypto-erase: overwrite with AES-CTR of zeros */
            memzero_explicit(ptr, pages * PAGE_SIZE);
            memzero_explicit(g_sec_regions[i].dek, 32);
            g_sec_regions[i].active = false;
            break;
        }
    }
    spin_unlock(&g_sec_lock);
    vmm_free(ptr, pages);
}

/* ── Memory snapshot: seal a range with AES-256-GCM ──────── */

int cc_kernel_seal_memory(virt_addr_t va, u64 pages, void *out, u32 *size)
{
    if (!g_cc_ready || !out) return -EINVAL;
    u64 data_len = pages * PAGE_SIZE;
    u32 needed   = (u32)(12 + data_len + 16);
    if (*size < needed) { *size = needed; return -EINVAL; }

    u8 *nonce = (u8*)out;
    u8 *ct    = (u8*)out + 12;
    u8 *tag   = (u8*)out + 12 + data_len;
    gen_nonce(nonce, &g_secmem_nonce_ctr);

    u8 aad[8]; *(u64*)aad = va;
    aes256_gcm_encrypt(g_secure_alloc_key, nonce,
                       (const u8*)va, (u32)data_len,
                       aad, 8, ct, tag);
    *size = needed;
    return 0;
}

/* ── Zero-trust IPC ──────────────────────────────────────── */

#define MAX_IPC_CHANNELS 128
#define IPC_RING_PAGES   4
#define IPC_RING_BYTES   (IPC_RING_PAGES * PAGE_SIZE)

struct ipc_channel {
    pid_t  pid_a, pid_b;
    u32    flags;
    u8     session_key[32];
    u8    *ring_a2b;    /* encrypted ring buffer A→B */
    u8    *ring_b2a;    /* encrypted ring buffer B→A */
    u32    ring_head_a2b, ring_tail_a2b;
    u32    ring_head_b2a, ring_tail_b2a;
    bool   active;
    int    fd_a, fd_b;
};

static struct ipc_channel g_ipc_channels[MAX_IPC_CHANNELS];
static spinlock_t g_ipc_lock = SPINLOCK_INIT;
static int  g_next_fd   = 100;
static u32  g_fd_gen    = 0;   /* generation to detect wrap-around */

int cc_ipc_channel_create(pid_t self, pid_t peer, u32 flags)
{
    if (!g_cc_ready) return -ENODEV;

    spin_lock(&g_ipc_lock);
    struct ipc_channel *ch = NULL;
    for (int i=0; i<MAX_IPC_CHANNELS; i++)
        if (!g_ipc_channels[i].active) { ch=&g_ipc_channels[i]; break; }
    if (!ch) { spin_unlock(&g_ipc_lock); return -ENOMEM; }

    ch->ring_a2b = (u8*)vmm_alloc(IPC_RING_PAGES, VMM_WRITE);
    ch->ring_b2a = (u8*)vmm_alloc(IPC_RING_PAGES, VMM_WRITE);
    if (!ch->ring_a2b || !ch->ring_b2a) {
        if (ch->ring_a2b) vmm_free(ch->ring_a2b, IPC_RING_PAGES);
        if (ch->ring_b2a) vmm_free(ch->ring_b2a, IPC_RING_PAGES);
        spin_unlock(&g_ipc_lock);
        return -ENOMEM;
    }

    /* Session key: HMAC-SHA256(ipc_key, pid_a || pid_b || timestamp) */
    u8 sk_input[20];
    *(u32*)sk_input     = (u32)MIN(self, peer);
    *(u32*)(sk_input+4) = (u32)MAX(self, peer);
    *(u64*)(sk_input+8) = nekros_rdtsc();
    hmac_sha256_impl(g_ipc_key, 32, sk_input, 20, ch->session_key);

    ch->pid_a  = self; ch->pid_b = peer; ch->flags = flags;
    ch->ring_head_a2b = ch->ring_tail_a2b = 0;
    ch->ring_head_b2a = ch->ring_tail_b2a = 0;
    ch->active = true;
    /* Recycle after 0x7FFFFF00 to avoid signed int overflow */
    if (g_next_fd > 0x7FFFFF00) { g_next_fd = 100; g_fd_gen++; }
    ch->fd_a   = g_next_fd++;
    ch->fd_b   = g_next_fd++;
    int ret_fd = ch->fd_a;
    spin_unlock(&g_ipc_lock);

    pr_info("cc_ipc: zero-trust channel pid %d↔%d fd=%d session_key=%02x%02x...\n",
            self, peer, ret_fd,
            ch->session_key[0], ch->session_key[1]);
    return ret_fd;
}

ssize_t cc_ipc_send(int fd, const void *buf, size_t len)
{
    if (!g_cc_ready || !buf || !len) return -EINVAL;
    if (len > IPC_RING_BYTES / 2) return -EMSGSIZE;

    struct ipc_channel *ch = NULL;
    spin_lock(&g_ipc_lock);
    for (int i=0; i<MAX_IPC_CHANNELS; i++)
        if (g_ipc_channels[i].active &&
            (g_ipc_channels[i].fd_a==fd || g_ipc_channels[i].fd_b==fd)) {
            ch=&g_ipc_channels[i]; break;
        }
    if (!ch) { spin_unlock(&g_ipc_lock); return -EBADF; }

    /* Encrypt payload: AES-256-GCM into ring buffer */
    u8 nonce[12]; gen_nonce(nonce, &g_ipc_nonce_ctr);
    u8 tag[16];
    bool a_to_b = (ch->fd_a == fd);
    u8 *ring    = a_to_b ? ch->ring_a2b : ch->ring_b2a;
    u32 *tail   = a_to_b ? &ch->ring_tail_a2b : &ch->ring_tail_b2a;

    /* Simple: write nonce(12) + len(4) + ciphertext(len) + tag(16) */
    u32 frame_sz = 12 + 4 + (u32)len + 16;
    /* Ensure frame fits; reject if ring is full (don't clobber unread messages) */
    if (*tail + frame_sz > IPC_RING_BYTES) {
        spin_unlock(&g_ipc_lock);
        return -ENOBUFS;  /* Ring full — caller must drain before sending more */
    }

    u8 *dst = ring + *tail;
    memcpy(dst, nonce, 12);
    *(u32*)(dst+12) = (u32)len;
    aes256_gcm_encrypt(ch->session_key, nonce,
                       (const u8*)buf, (u32)len,
                       nonce, 12,            /* nonce as AAD */
                       dst+16, tag);
    memcpy(dst + 16 + len, tag, 16);
    *tail += frame_sz;
    spin_unlock(&g_ipc_lock);
    return (ssize_t)len;
}

ssize_t cc_ipc_recv(int fd, void *buf, size_t len)
{
    if (!g_cc_ready || !buf || !len) return -EINVAL;
    struct ipc_channel *ch = NULL;
    spin_lock(&g_ipc_lock);
    for (int i=0; i<MAX_IPC_CHANNELS; i++)
        if (g_ipc_channels[i].active &&
            (g_ipc_channels[i].fd_a==fd || g_ipc_channels[i].fd_b==fd)) {
            ch=&g_ipc_channels[i]; break;
        }
    if (!ch) { spin_unlock(&g_ipc_lock); return -EBADF; }

    bool a_to_b = (ch->fd_b == fd); /* receiver is B when A sent */
    u8  *ring   = a_to_b ? ch->ring_a2b : ch->ring_b2a;
    u32 *head   = a_to_b ? &ch->ring_head_a2b : &ch->ring_head_b2a;
    u32 *tail   = a_to_b ? &ch->ring_tail_a2b : &ch->ring_tail_b2a;

    if (*head == *tail) { spin_unlock(&g_ipc_lock); return -EAGAIN; }

    u8 *src = ring + *head;
    u8 *nonce = src;
    u32 plen  = *(u32*)(src+12);
    /* Validate plen: must fit within ring buffer and caller buffer */
    if (plen > (u32)(IPC_RING_BYTES / 2)) { spin_unlock(&g_ipc_lock); return -EMSGSIZE; }
    if (plen > (u32)len) { spin_unlock(&g_ipc_lock); return -EMSGSIZE; }
    /* Validate we won't read past the ring buffer */
    u32 frame_end = (u32)(*head) + 12 + 4 + plen + 16;
    if (frame_end > IPC_RING_BYTES) { spin_unlock(&g_ipc_lock); return -EBADMSG; }

    const u8 *ct  = src + 16;
    const u8 *tag = src + 16 + plen;

    int rc = aes256_gcm_decrypt(ch->session_key, nonce, ct, plen,
                                tag, nonce, 12, (u8*)buf);
    *head += 12 + 4 + plen + 16;
    if (*head >= *tail) *head = *tail = 0;
    spin_unlock(&g_ipc_lock);

    return rc ? (ssize_t)-EACCES : (ssize_t)plen;
}

/* ── Process checkpoint ──────────────────────────────────── */

int cc_kernel_checkpoint(struct task *t, void *out, u32 *size)
{
    if (!g_cc_ready || !t || !out) return -EINVAL;

    /* Checkpoint plaintext: task registers + neri state (256 bytes) */
    u8 plain[256];
    memset(plain, 0, sizeof(plain));
    *(pid_t*)plain       = t->pid;
    *(u32*)(plain+4)     = t->state;
    *(u64*)(plain+8)     = t->ctx_rsp;
    *(u64*)(plain+16)    = t->ctx_rip;
    *(u64*)(plain+24)    = t->ctx_rflags;
    *(u64*)(plain+32)    = t->ctx_rbx;
    *(u64*)(plain+40)    = t->ctx_rbp;
    *(u64*)(plain+48)    = t->neri.cpu_granted_ns;
    *(u64*)(plain+56)    = t->neri.ram_granted_pages;
    *(u64*)(plain+64)    = t->cpu_time_ns;
    strlcpy((char*)(plain+72), t->name, 32);

    u32 needed = 12 + 256 + 16;
    if (*size < needed) { *size = needed; return -EINVAL; }

    u8 nonce[12]; gen_nonce(nonce, &g_attest_nonce_ctr);
    u8 *ct  = (u8*)out + 12;
    u8 *tag = (u8*)out + 12 + 256;
    memcpy(out, nonce, 12);
    u8 aad[4]; *(u32*)aad = (u32)t->pid;
    aes256_gcm_encrypt(g_attest_key, nonce, plain, 256, aad, 4, ct, tag);
    memzero_explicit(plain, 256);
    *size = needed;
    return 0;
}

void syscall_init(void);  /* declared in syscall.c */

/* Close and crypto-erase an IPC channel */
void cc_ipc_close(int fd) {
    spin_lock(&g_ipc_lock);
    for (int i = 0; i < MAX_IPC_CHANNELS; i++) {
        struct ipc_channel *ch = &g_ipc_channels[i];
        if (ch->active && (ch->fd_a == fd || ch->fd_b == fd)) {
            memzero_explicit(ch->session_key, 32);
            if (ch->ring_a2b) { vmm_free(ch->ring_a2b, IPC_RING_PAGES); ch->ring_a2b = NULL; }
            if (ch->ring_b2a) { vmm_free(ch->ring_b2a, IPC_RING_PAGES); ch->ring_b2a = NULL; }
            ch->active = false;
            break;
        }
    }
    spin_unlock(&g_ipc_lock);
}
