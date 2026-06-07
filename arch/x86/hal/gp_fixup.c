/* SPDX-License-Identifier: GPL-2.0 */
/*
 * arch/x86/hal/gp_fixup.c — __ex_table exception fixup dispatcher
 *
 * When wrmsr_safe (or future copy_from_user / copy_to_user) takes a
 * Ring-0 #GP fault, the CPU delivers exception vector 13 to
 * nekros_interrupt_dispatch().  That handler calls gp_fixup_find()
 * with the faulting RIP.
 *
 * gp_fixup_find() walks the __ex_table section, which is a compact
 * array of {insn_offset, fixup_offset} pairs emitted by .pushsection
 * directives in wrmsr_safe's inline assembly.  If the faulting RIP
 * matches an insn_offset entry, gp_fixup_find() returns the
 * corresponding fixup RIP so the dispatcher can redirect execution.
 *
 * This is the same mechanism used by Linux's EXTABLE infrastructure,
 * simplified for Nekros's single-address-space kernel.
 *
 * Linker script must provide:
 *   __start___ex_table   (start of __ex_table section)
 *   __stop___ex_table    (end   of __ex_table section)
 * Both are 4-byte-aligned relative-offset pairs.
 */

#include <nekros/types.h>
#include <nekros/printk.h>

/* Each entry: two 32-bit PC-relative offsets */
struct ex_entry {
    s32 insn_rel;   /* byte offset from &entry.insn_rel to faulting insn */
    s32 fixup_rel;  /* byte offset from &entry.fixup_rel to fixup label  */
};

/* Weak symbols — resolved by the linker script.
 * Defined as arrays of one entry so &__start___ex_table is valid even if
 * the section is empty (no fixup entries compiled in). */
extern struct ex_entry __start___ex_table[] __attribute__((weak));
extern struct ex_entry __stop___ex_table[]  __attribute__((weak));

/* gp_fixup_find — look up a recovery RIP for a faulting RIP.
 * Returns the fixup RIP on match, 0 if no entry found (genuine panic). */
u64 gp_fixup_find(u64 fault_rip)
{
    if (!__start___ex_table || !__stop___ex_table)
        return 0;  /* section not present — no fixup entries */

    struct ex_entry *start = __start___ex_table;
    struct ex_entry *stop  = __stop___ex_table;

    for (struct ex_entry *e = start; e < stop; e++) {
        /* Resolve insn address from PC-relative offset stored in entry */
        u64 insn_addr  = (u64)&e->insn_rel  + (s64)e->insn_rel;
        u64 fixup_addr = (u64)&e->fixup_rel + (s64)e->fixup_rel;

        if (insn_addr == fault_rip) {
            pr_debug("gp_fixup: RIP 0x%llx → fixup 0x%llx\\n",
                     fault_rip, fixup_addr);
            return fixup_addr;
        }
    }
    return 0;  /* no fixup for this RIP — caller should panic */
}
