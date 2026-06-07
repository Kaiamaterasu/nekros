/* SPDX-License-Identifier: GPL-2.0 */
/*
 * arch/x86/kernel/sched_asm.S — Context switch for Nekros
 *
 * void __switch_to(struct task *prev, struct task *next)
 *
 * Saves prev's callee-saved registers + RSP + RIP,
 * restores next's, and returns into next's context.
 *
 * Register layout in task:
 *   ctx_rsp    — stack pointer saved/restored
 *   ctx_rbp    — base pointer
 *   ctx_rbx    — scratch preserved
 *   ctx_r12-r15— callee-saved
 *   ctx_rip    — instruction pointer (return address trick)
 *   ctx_rflags — RFLAGS
 *
 * RDI = prev task pointer
 * RSI = next task pointer
 *
 * Offsets match struct task layout in kernel/sched.c:
 *   +96  ctx_rsp
 *   +104 ctx_rbp
 *   +112 ctx_rbx
 *   +120 ctx_r12
 *   +128 ctx_r13
 *   +136 ctx_r14
 *   +144 ctx_r15
 *   +152 ctx_rip
 *   +160 ctx_rflags
 *
 * We use a compile-time constant here. If task layout changes,
 * update these offsets (or generate them from offsetof).
 */

    .section ".text"
    .code64
    .global __switch_to

/* Offsets into struct task for saved context */
#define TASK_CTX_RSP     96
#define TASK_CTX_RBP    104
#define TASK_CTX_RBX    112
#define TASK_CTX_R12    120
#define TASK_CTX_R13    128
#define TASK_CTX_R14    136
#define TASK_CTX_R15    144
#define TASK_CTX_RIP    152
#define TASK_CTX_RFLAGS 160

__switch_to:
    /* --- Save prev (RDI) ---
     * We save the return address as ctx_rip so when next switch
     * restores prev, it returns to whoever called __switch_to.    */
    testq   %rdi, %rdi
    jz      .Lrestore_next

    /* Save callee-saved registers */
    movq    %rsp, TASK_CTX_RSP(%rdi)
    movq    %rbp, TASK_CTX_RBP(%rdi)
    movq    %rbx, TASK_CTX_RBX(%rdi)
    movq    %r12, TASK_CTX_R12(%rdi)
    movq    %r13, TASK_CTX_R13(%rdi)
    movq    %r14, TASK_CTX_R14(%rdi)
    movq    %r15, TASK_CTX_R15(%rdi)

    /* Save return address as ctx_rip */
    movq    (%rsp), %rax
    movq    %rax, TASK_CTX_RIP(%rdi)

    /* Save RFLAGS */
    pushfq
    popq    %rax
    movq    %rax, TASK_CTX_RFLAGS(%rdi)

.Lrestore_next:
    /* --- Restore next (RSI) --- */
    movq    TASK_CTX_R15(%rsi), %r15
    movq    TASK_CTX_R14(%rsi), %r14
    movq    TASK_CTX_R13(%rsi), %r13
    movq    TASK_CTX_R12(%rsi), %r12
    movq    TASK_CTX_RBX(%rsi), %rbx
    movq    TASK_CTX_RBP(%rsi), %rbp

    /* Restore RFLAGS */
    movq    TASK_CTX_RFLAGS(%rsi), %rax
    pushq   %rax
    popfq

    /* Switch stack */
    movq    TASK_CTX_RSP(%rsi), %rsp

    /* Jump to next's saved RIP (return from __switch_to in next's context) */
    movq    TASK_CTX_RIP(%rsi), %rax
    jmpq    *%rax
    .section .note.GNU-stack,"",@progbits
