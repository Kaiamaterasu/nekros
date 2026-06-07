/* SPDX-License-Identifier: GPL-2.0 */
/*
 * include/nekros/printk.h — kernel console output declarations
 */
#ifndef NEKROS_PRINTK_H
#define NEKROS_PRINTK_H

#include <nekros/types.h>

/* Log levels */
#define KERN_EMERG   "<0>"
#define KERN_ALERT   "<1>"
#define KERN_CRIT    "<2>"
#define KERN_ERR     "<3>"
#define KERN_WARNING "<4>"
#define KERN_NOTICE  "<5>"
#define KERN_INFO    "<6>"
#define KERN_DEBUG   "<7>"

void printk(const char *fmt, ...) __attribute__((format(printf, 1, 2)));
void panic(const char *fmt, ...) __attribute__((format(printf, 1, 2), noreturn));

#define pr_emerg(fmt, ...)   printk(KERN_EMERG   fmt, ##__VA_ARGS__)
#define pr_alert(fmt, ...)   printk(KERN_ALERT   fmt, ##__VA_ARGS__)
#define pr_crit(fmt, ...)    printk(KERN_CRIT    fmt, ##__VA_ARGS__)
#define pr_err(fmt, ...)     printk(KERN_ERR     fmt, ##__VA_ARGS__)
#define pr_warn(fmt, ...)    printk(KERN_WARNING fmt, ##__VA_ARGS__)
#define pr_notice(fmt, ...)  printk(KERN_NOTICE  fmt, ##__VA_ARGS__)
#define pr_info(fmt, ...)    printk(KERN_INFO    fmt, ##__VA_ARGS__)
#define pr_debug(fmt, ...)   printk(KERN_DEBUG   fmt, ##__VA_ARGS__)

#define BUG_ON(cond) do { \
    if (unlikely(cond)) panic("BUG: %s:%d condition failed: " #cond "\n", \
                               __FILE__, __LINE__); \
} while (0)

#define WARN_ON(cond) ({ \
    bool __w = !!(cond); \
    if (unlikely(__w)) pr_warn("WARN: %s:%d " #cond "\n", __FILE__, __LINE__); \
    __w; \
})

#endif /* NEKROS_PRINTK_H */
