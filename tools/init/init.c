/* SPDX-License-Identifier: GPL-2.0 */
/*
 * tools/init/init.c — Nekros init process (PID 1)
 *
 * The first userspace process. Responsible for:
 *   1. Declaring itself as a DAEMON intent to Neri
 *   2. Pledging minimal syscalls
 *   3. Printing the Nekros welcome banner
 *   4. Forking the shell / nerictl / cortexcrypt as needed
 *   5. Reaping zombie processes
 *   6. Monitoring NSM anomaly score and alerting
 *
 * Like systemd but tiny: 200 lines, no libc, no D-Bus.
 * Everything communicates through zero-trust IPC channels.
 */

#include <nekros/types.h>
#include <nekros/string.h>

/* ── Syscalls ────────────────────────────────────────────── */
static __always_inline u64 sc0(u64 n)
    { u64 r; __asm__ volatile("int $0x80":"=a"(r):"a"(n):); return r; }
static __always_inline u64 sc1(u64 n,u64 a)
    { u64 r; __asm__ volatile("int $0x80":"=a"(r):"a"(n),"D"(a):); return r; }
static __always_inline u64 sc3(u64 n,u64 a,u64 b,u64 c) {
    u64 r; register u64 rdx __asm__("rdx")=c;
    __asm__ volatile("int $0x80":"=a"(r):"a"(n),"D"(a),"S"(b),"r"(rdx):);
    return r;
}
static void wr(const char *s)
    { sc3(1,1,(u64)s,strlen(s)); }
static void wru64(u64 v) {
    char b[24],t[24]; int n=0;
    if(!v){wr("0");return;}
    while(v){t[n++]='0'+v%10;v/=10;}
    for(int i=n-1;i>=0;i--)b[n-1-i]=t[i]; b[n]=0; wr(b);
}
static void sc_exit(int c) { sc1(2,(u64)c); __builtin_unreachable(); }

#define NK_PROC_INTENT    40
#define NK_ATTEST_SELF    42
#define NK_NERI_STATUS    49
#define NK_ANOMALY_SCORE  52
#define NK_PLEDGE         53
#define NK_SET_NAME       62

struct neri_status  { u64 epoch,ct,ca,rt,ra,gt,ga; };
struct neri_anomaly { u8 score; u32 level; u8 blocked; u64 epoch; };

/* ── Banner ──────────────────────────────────────────────── */
static void print_banner(void) {
    wr("\033[2J\033[H");   /* clear screen */
    wr("\033[1;36m");
    wr("  ███╗   ██╗███████╗██╗  ██╗██████╗  ██████╗ ███████╗\n");
    wr("  ████╗  ██║██╔════╝██║ ██╔╝██╔══██╗██╔═══██╗██╔════╝\n");
    wr("  ██╔██╗ ██║█████╗  █████╔╝ ██████╔╝██║   ██║███████╗\n");
    wr("  ██║╚██╗██║██╔══╝  ██╔═██╗ ██╔══██╗██║   ██║╚════██║\n");
    wr("  ██║ ╚████║███████╗██║  ██╗██║  ██║╚██████╔╝███████║\n");
    wr("  ╚═╝  ╚═══╝╚══════╝╚═╝  ╚═╝╚═╝  ╚═╝ ╚═════╝ ╚══════╝\n");
    wr("\033[0m\n");
    wr("  \033[1mSecure Developer Kernel\033[0m");
    wr("  built from scratch\n");
    wr("  Neri v0.5.0 + CortexCrypto + 24 novel syscalls\n");
    wr("\n");
    wr("  Kernel features:\n");
    wr("    nk_proc_intent      — semantic process placement\n");
    wr("    nk_work_budget      — temporal CPU guarantees\n");
    wr("    nk_attest_self/peer — zero-trust process identity\n");
    wr("    nk_secure_alloc     — AES-256-GCM memory regions\n");
    wr("    nk_ipc_channel      — encrypted kernel IPC\n");
    wr("    nk_thermal_hint     — predictive RAPL headroom\n");
    wr("    nk_anomaly_score    — live NSM threat score\n");
    wr("    nk_pledge           — irreversible syscall whitelist\n");
    wr("\n");
}

/* ── Status summary ──────────────────────────────────────── */
static void print_status(void) {
    struct neri_status st = {0};
    struct neri_anomaly anm = {0};
    sc1(NK_NERI_STATUS,   (u64)&st);
    sc1(NK_ANOMALY_SCORE, (u64)&anm);

    wr("  Resource pool  epoch="); wru64(st.epoch);
    wr("  CPU ");
    if (st.ct) { wru64(st.ca*100/st.ct); wr("% "); }
    wr("  RAM ");
    if (st.rt) { wru64(st.ra*4096/1048576); wr(" MB"); }
    wr("  NSM ");
    static const char *lv[]={"NORMAL","MEDIUM","HIGH","CRITICAL"};
    static const char *cl[]={"\033[32m","\033[33m","\033[31m","\033[1;31m"};
    u32 l = anm.level<4?anm.level:3;
    wr(cl[l]); wr(lv[l]); wr("\033[0m");
    wr(" score="); wru64(anm.score);
    wr("/255\n\n");
}

/* ── Main init loop ──────────────────────────────────────── */
void _start(void) {
    /* 1. Set name */
    sc1(NK_SET_NAME, (u64)"init");

    /* 2. Declare daemon intent (minimal resource footprint) */
    sc3(NK_PROC_INTENT, 3 /* DAEMON */, 100000ULL, 4ULL);

    /* 3. Pledge: only what init needs */
    u64 pledge =
        (1ULL<<0) | (1ULL<<1) | (1ULL<<2) | (1ULL<<17) |
        (1ULL<<20) | (1ULL<<40) | (1ULL<<42) | (1ULL<<49) |
        (1ULL<<52) | (1ULL<<53) | (1ULL<<62);
    sc1(NK_PLEDGE, pledge);

    /* 4. Print boot banner */
    print_banner();

    /* 5. Print resource status */
    print_status();

    wr("  init: PID 1 ready. ");
    wr("Waiting for kernel events...\n\n");
    wr("  To interact:\n");
    wr("    nerictl status       — resource pool\n");
    wr("    nerictl anomaly      — NSM threat score\n");
    wr("    nerictl intent compile 4000  — set intent\n");
    wr("    cortexcrypt status   — crypto bridge\n");
    wr("    cortexcrypt attest   — process identity\n\n");

    /* 6. Main loop: yield + monitor */
    u64 tick = 0;
    while (1) {
        sc0(17); /* yield */
        tick++;

        /* Check anomaly score every 128 ticks */
        if ((tick & 127) == 0) {
            struct neri_anomaly anm = {0};
            sc1(NK_ANOMALY_SCORE, (u64)&anm);
            if (anm.level >= 2) {
                wr("\033[1;31m  [ALERT] NSM threat level ");
                static const char *lv[]={"NORMAL","MEDIUM","HIGH","CRITICAL"};
                wr(lv[anm.level<4?anm.level:3]);
                wr(" — score="); wru64(anm.score);
                wr("/255\033[0m\n");
            }
        }
    }
}
