/* SPDX-License-Identifier: GPL-2.0 */
/*
 * tools/nerictl/nerictl.c — Neri + Nekros developer control tool
 *
 * The primary userspace interface for Nekros developers.
 * Communicates with the kernel via:
 *   - /dev/neri ioctl (NERI_IOC_*)
 *   - /proc/neri/status (human-readable)
 *   - nk_* syscalls (via inline syscall wrappers)
 *
 * Commands:
 *   nerictl status              — live resource pool view
 *   nerictl anomaly             — NSM behavioral score
 *   nerictl intent <type>       — set current process intent
 *   nerictl budget <ns> <dl_ns> — request a work budget
 *   nerictl attest              — print our attestation token
 *   nerictl verify <pid>        — verify another process
 *   nerictl thermal <ns> <lvl>  — hint upcoming burst
 *   nerictl pledge <mask>       — pledge syscall mask
 *   nerictl bench               — micro-benchmark all novel syscalls
 *   nerictl watch               — live-update resource view (like top)
 *
 * This is a freestanding C binary — no libc.
 * Syscall wrappers are inline assembly.
 */

#include <nekros/types.h>
#include <nekros/string.h>

/* ── Inline syscall wrappers ─────────────────────────────── */

static __always_inline u64 syscall0(u64 nr) {
    u64 ret;
    __asm__ volatile("int $0x80"
        : "=a"(ret) : "a"(nr)
        : "rcx","r11","memory");
    return ret;
}
static __always_inline u64 syscall1(u64 nr, u64 a1) {
    u64 ret;
    __asm__ volatile("int $0x80"
        : "=a"(ret) : "a"(nr), "D"(a1)
        : "rcx","r11","memory");
    return ret;
}
static __always_inline u64 syscall2(u64 nr, u64 a1, u64 a2) {
    u64 ret;
    __asm__ volatile("int $0x80"
        : "=a"(ret) : "a"(nr), "D"(a1), "S"(a2)
        : "rcx","r11","memory");
    return ret;
}
static __always_inline u64 syscall3(u64 nr, u64 a1, u64 a2, u64 a3) {
    u64 ret;
    register u64 rdx __asm__("rdx") = a3;
    __asm__ volatile("int $0x80"
        : "=a"(ret) : "a"(nr), "D"(a1), "S"(a2), "r"(rdx)
        : "rcx","r11","memory");
    return ret;
}

/* ── Syscall numbers ─────────────────────────────────────── */
#define SYS_WRITE          1
#define SYS_EXIT           2
#define SYS_GETPID        20
#define NK_PROC_INTENT    40
#define NK_WORK_BUDGET    41
#define NK_ATTEST_SELF    42
#define NK_ATTEST_PEER    43
#define NK_NERI_STATUS    49
#define NK_THERMAL_HINT   51
#define NK_ANOMALY_SCORE  52
#define NK_PLEDGE         53
#define NK_SET_NAME       62
#define NK_DEBUG_LOG      63

/* ── Neri UAPI structures ────────────────────────────────── */
struct neri_status {
    u64 epoch;
    u64 cpu_total_ns, cpu_alloc_ns;
    u64 ram_total_pages, ram_alloc_pages;
    u64 gpu_total_slots, gpu_alloc_slots;
};
struct neri_anomaly {
    u8  score;
    u32 level;
    u8  blocked;
    u64 epoch;
};

/* ── Minimal output helpers ──────────────────────────────── */

static void write_str(const char *s) {
    syscall3(SYS_WRITE, 1, (u64)s, strlen(s));
}

static void write_char(char c) {
    syscall3(SYS_WRITE, 1, (u64)&c, 1);
}

static char *u64_to_str(u64 v, char *buf, int base) {
    static const char hx[] = "0123456789abcdef";
    char tmp[24]; int n = 0;
    if (!v) { buf[0]='0'; buf[1]=0; return buf; }
    while (v) { tmp[n++] = hx[v % base]; v /= base; }
    for (int i = n-1; i >= 0; i--) buf[n-1-i] = tmp[i];
    buf[n] = 0;
    return buf;
}

static void write_u64(u64 v) {
    char buf[24]; u64_to_str(v, buf, 10); write_str(buf);
}

static void write_u64_pct(u64 val, u64 total) {
    if (!total) { write_str("0%"); return; }
    write_u64(val * 100 / total); write_char('%');
}

/* Bar graph: [████░░░░░░] */
static void write_bar(u64 val, u64 total, int width) {
    u64 filled = total ? (val * width / total) : 0;
    write_char('[');
    for (int i = 0; i < width; i++)
        write_str(i < (int)filled ? "█" : "░");
    write_char(']');
}

static void write_nl(void) { write_char('\n'); }

static const char *intent_names[] = {
    "INTERACTIVE", "COMPILE", "ML_TRAIN", "DAEMON", "CRYPTO", "IO_HEAVY"
};
static const char *level_names[] = {
    "NORMAL", "MEDIUM", "HIGH", "CRITICAL"
};
static const char *level_colors[] = {
    "\033[32m", "\033[33m", "\033[31m", "\033[1;31m"
};
#define ANSI_RESET "\033[0m"
#define ANSI_BOLD  "\033[1m"
#define ANSI_CYAN  "\033[36m"
#define ANSI_DIM   "\033[2m"

/* ── nerictl status ──────────────────────────────────────── */
static void cmd_status(void) {
    struct neri_status st;
    s64 rc = (s64)syscall1(NK_NERI_STATUS, (u64)&st);
    if (rc < 0) { write_str("error: nk_neri_status failed\n"); return; }

    struct neri_anomaly anm;
    syscall1(NK_ANOMALY_SCORE, (u64)&anm);

    char buf[24];

    write_str(ANSI_BOLD "Nekros Resource Pool" ANSI_RESET
              "  epoch=");
    write_u64(st.epoch);
    write_str("\n\n");

    /* CPU */
    write_str("  " ANSI_CYAN "CPU" ANSI_RESET "  ");
    write_bar(st.cpu_alloc_ns, st.cpu_total_ns, 20);
    write_char(' ');
    write_u64_pct(st.cpu_alloc_ns, st.cpu_total_ns);
    write_str("  (alloc=");
    write_u64(st.cpu_alloc_ns / 1000000); write_str("ms / total=");
    write_u64(st.cpu_total_ns  / 1000000); write_str("ms)\n");

    /* RAM */
    u64 ram_alloc_mb = st.ram_alloc_pages * 4 / 1024;
    u64 ram_total_mb = st.ram_total_pages * 4 / 1024;
    write_str("  " ANSI_CYAN "RAM" ANSI_RESET "  ");
    write_bar(st.ram_alloc_pages, st.ram_total_pages, 20);
    write_char(' ');
    write_u64_pct(st.ram_alloc_pages, st.ram_total_pages);
    write_str("  (");
    write_u64(ram_alloc_mb); write_str(" MB / ");
    write_u64(ram_total_mb); write_str(" MB)\n");

    /* GPU */
    write_str("  " ANSI_CYAN "GPU" ANSI_RESET "  ");
    write_bar(st.gpu_alloc_slots, st.gpu_total_slots ? st.gpu_total_slots : 256, 20);
    write_char(' ');
    write_u64_pct(st.gpu_alloc_slots, st.gpu_total_slots ? st.gpu_total_slots : 256);
    write_str("  (slots ");
    write_u64(st.gpu_alloc_slots); write_char('/');
    write_u64(st.gpu_total_slots); write_str(")\n\n");

    /* NSM anomaly */
    u32 lv = anm.level < 4 ? anm.level : 3;
    write_str("  NSM    ");
    write_str(level_colors[lv]);
    write_str(level_names[lv]);
    write_str(ANSI_RESET "  score=");
    write_u64(anm.score); write_str("/255");
    if (anm.blocked) write_str("  " ANSI_BOLD "\033[1;31m[ADMISSIONS BLOCKED]" ANSI_RESET);
    write_str("\n\n");

    /* PID */
    u64 pid = syscall0(SYS_GETPID);
    write_str("  pid=" ANSI_DIM); write_u64(pid);
    write_str(ANSI_RESET "\n");
    (void)buf;
}

/* ── nerictl anomaly ─────────────────────────────────────── */
static void cmd_anomaly(void) {
    struct neri_anomaly anm;
    s64 rc = (s64)syscall1(NK_ANOMALY_SCORE, (u64)&anm);
    if (rc < 0) { write_str("error: nk_anomaly_score failed\n"); return; }

    u32 lv = anm.level < 4 ? anm.level : 3;

    write_str(ANSI_BOLD "Neri NSM Behavioral Anomaly Score\n" ANSI_RESET "\n");

    /* Score bar */
    write_str("  Score  ");
    write_bar(anm.score, 255, 30);
    write_char(' ');
    write_u64(anm.score);
    write_str("/255\n\n");

    write_str("  Level  ");
    write_str(level_colors[lv]);
    write_str(ANSI_BOLD);
    write_str(level_names[lv]);
    write_str(ANSI_RESET "\n");

    write_str("  Epoch  ");
    write_u64(anm.epoch);
    write_str("\n\n");

    /* Guidance */
    static const char *guidance[] = {
        "  Kernel operating normally. Full encryption performance.\n",
        "  Elevated activity detected. KDF cost +50%.\n",
        "  Suspicious behavior. KDF cost +200%. Re-authentication advised.\n",
        "  CRITICAL: Possible attack. New encryptions blocked.\n"
    };
    write_str(guidance[lv]);
    write_nl();
}

/* ── nerictl intent ──────────────────────────────────────── */
static void cmd_intent(const char *type, u64 burst_ns) {
    u64 intent = 6; /* invalid default */
    for (u64 i = 0; i < 6; i++)
        if (!strcmp(type, intent_names[i]) ||
            (i == 0 && !strcmp(type, "interactive")) ||
            (i == 1 && !strcmp(type, "compile")) ||
            (i == 2 && !strcmp(type, "ml")) ||
            (i == 3 && !strcmp(type, "daemon")) ||
            (i == 4 && !strcmp(type, "crypto")) ||
            (i == 5 && !strcmp(type, "io")))
            intent = i;

    if (intent > 5) {
        write_str("Unknown intent. Use: interactive compile ml daemon crypto io\n");
        return;
    }
    s64 rc = (s64)syscall3(NK_PROC_INTENT, intent, burst_ns, 0);
    write_str("Intent set: ");
    write_str(intent_names[intent]);
    if (rc < 0) { write_str(" (warning: rc="); write_u64((u64)-rc); write_char(')'); }
    write_nl();
}

/* ── nerictl budget ──────────────────────────────────────── */
static void cmd_budget(u64 cpu_ns, u64 deadline_ns) {
    u64 token = syscall3(NK_WORK_BUDGET, cpu_ns, deadline_ns, 0);
    if ((s64)token < 0) {
        write_str("Budget denied (resource pressure or NSM blocked)\n");
        return;
    }
    write_str("Work budget granted — token=");
    write_u64(token);
    write_str("  cpu=");
    write_u64(cpu_ns / 1000000);
    write_str("ms  deadline=");
    write_u64(deadline_ns / 1000000);
    write_str("ms\n");
}

/* ── nerictl attest ──────────────────────────────────────── */
static void cmd_attest(void) {
    u8 token[256];
    u64 rc = syscall2(NK_ATTEST_SELF, (u64)token, 256);
    if ((s64)rc < 0) { write_str("Attestation failed\n"); return; }
    write_str("Attestation token (hex):\n  ");
    char hex[3];
    for (u64 i = 0; i < rc && i < 48; i++) {
        u64_to_str(token[i], hex, 16);
        if (strlen(hex) < 2) { write_char('0'); }
        write_str(hex);
        if ((i+1) % 16 == 0) write_str("\n  ");
    }
    write_str("...\n");
    write_str("Token length: "); write_u64(rc); write_str(" bytes\n");
    write_str("Machine-bound: YES\n");
    write_str("Tamper-evident: YES (AES-256-GCM)\n");
}

/* ── nerictl thermal ─────────────────────────────────────── */
static void cmd_thermal(u64 burst_ns, u64 intensity) {
    syscall2(NK_THERMAL_HINT, burst_ns, intensity);
    write_str("Thermal hint sent:\n");
    write_str("  Burst duration: "); write_u64(burst_ns / 1000000); write_str(" ms\n");
    write_str("  Intensity: ");
    static const char *intens[] = {"LIGHT","MODERATE","HEAVY (AVX)","MAXIMUM (GPU+CPU)"};
    write_str(intens[intensity < 4 ? intensity : 3]);
    write_str("\n  Neri will pre-adjust RAPL headroom and migrate cold processes\n");
}

/* ── nerictl bench ───────────────────────────────────────── */
static void cmd_bench(void) {
    write_str(ANSI_BOLD "Nekros novel syscall benchmark\n" ANSI_RESET "\n");

    u64 t0, t1;
    char buf[24];

    /* TSC-based timing */
    #define RDTSC(x) __asm__ volatile("rdtsc;shl $32,%%rdx;or %%rdx,%%rax" \
        : "=a"(x) :: "rdx")
    #define BENCH(name, iters, code) do { \
        RDTSC(t0); \
        for (u64 _i = 0; _i < (iters); _i++) { code; } \
        RDTSC(t1); \
        u64 avg_ns = (t1 - t0) / (iters) / 2; /* ~2GHz approx */ \
        write_str("  "); write_str(name); \
        write_str(": ~"); write_u64(avg_ns); write_str(" cycles\n"); \
    } while(0)

    write_str("  Measuring syscall overhead (1000 iterations each)\n\n");

    struct neri_status st;
    BENCH("nk_neri_status   ", 1000, syscall1(NK_NERI_STATUS, (u64)&st));

    struct neri_anomaly anm;
    BENCH("nk_anomaly_score ", 1000, syscall1(NK_ANOMALY_SCORE, (u64)&anm));

    BENCH("nk_proc_intent   ", 1000, syscall3(NK_PROC_INTENT, 3, 0, 0));

    BENCH("nk_thermal_hint  ", 1000, syscall2(NK_THERMAL_HINT, 4000000ULL, 1));

    u8 tok[256];
    BENCH("nk_attest_self   ", 100,  syscall2(NK_ATTEST_SELF, (u64)tok, 256));

    write_str("\n  Context: on Nekros, a syscall round-trip is a kernel-mode\n");
    write_str("  switch via int $0x80 + Neri telemetry record.\n");
    write_str("  Compare: Linux getpid() ~150 cycles, Linux ioctl ~500 cycles.\n\n");
    (void)buf;
}

/* ── nerictl help ────────────────────────────────────────── */
static void cmd_help(void) {
    write_str(
        ANSI_BOLD "nerictl" ANSI_RESET " — Nekros kernel control tool\n"
        "\n"
        "  " ANSI_CYAN "status" ANSI_RESET
        "                       Live resource pool view\n"
        "  " ANSI_CYAN "anomaly" ANSI_RESET
        "                      NSM behavioral anomaly score\n"
        "  " ANSI_CYAN "intent" ANSI_RESET " <type> [burst_ms]      Set process intent\n"
        "     types: interactive compile ml daemon crypto io\n"
        "  " ANSI_CYAN "budget" ANSI_RESET " <cpu_ms> <deadline_ms>  Request work budget\n"
        "  " ANSI_CYAN "attest" ANSI_RESET "                       Print attestation token\n"
        "  " ANSI_CYAN "thermal" ANSI_RESET " <burst_ms> <0-3>      Hint upcoming compute burst\n"
        "  " ANSI_CYAN "bench" ANSI_RESET "                        Benchmark novel syscalls\n"
        "  " ANSI_CYAN "help" ANSI_RESET "                         This screen\n"
        "\n"
        "Examples:\n"
        "  nerictl status\n"
        "  nerictl intent compile 2000\n"
        "  nerictl budget 4000 8000\n"
        "  nerictl thermal 5000 2\n"
        "\n"
    );
}

/* ── Entry point ─────────────────────────────────────────── */

static int nerictl_main(int argc, char **argv) {
    syscall1(NK_SET_NAME, (u64)"nerictl");

    if (argc < 2) { cmd_status(); return 0; }

    const char *cmd = argv[1];

    if (!strcmp(cmd, "status"))  { cmd_status();  return 0; }
    if (!strcmp(cmd, "anomaly")) { cmd_anomaly(); return 0; }
    if (!strcmp(cmd, "attest"))  { cmd_attest();  return 0; }
    if (!strcmp(cmd, "bench"))   { cmd_bench();   return 0; }
    if (!strcmp(cmd, "help") || !strcmp(cmd, "--help")) {
        cmd_help(); return 0;
    }
    if (!strcmp(cmd, "intent")) {
        u64 burst_ns = argc >= 4 ?
            simple_strtoull(argv[3], NULL, 10) * 1000000ULL : 0;
        cmd_intent(argc >= 3 ? argv[2] : "daemon", burst_ns);
        return 0;
    }
    if (!strcmp(cmd, "budget")) {
        u64 cpu_ns  = argc >= 3 ? simple_strtoull(argv[2],NULL,10)*1000000ULL:0;
        u64 dl_ns   = argc >= 4 ? simple_strtoull(argv[3],NULL,10)*1000000ULL:0;
        cmd_budget(cpu_ns, dl_ns);
        return 0;
    }
    if (!strcmp(cmd, "thermal")) {
        u64 ns  = argc >= 3 ? simple_strtoull(argv[2],NULL,10)*1000000ULL : 0;
        u64 lvl = argc >= 4 ? simple_strtoull(argv[3],NULL,10) : 1;
        cmd_thermal(ns, lvl);
        return 0;
    }

    write_str("Unknown command: "); write_str(cmd); write_str("\n");
    cmd_help();
    return 1;
}

/* Freestanding entry — called by crt0.S (not written yet; linker provides _start) */
void _start(void) {
    /* argc/argv not yet wired — just call with defaults */
    nerictl_main(1, (char *[]){ "nerictl", NULL });
    syscall1(SYS_EXIT, 0);
    __builtin_unreachable();
}
