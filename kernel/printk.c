/* SPDX-License-Identifier: GPL-2.0 */
/*
 * kernel/printk.c — Nekros kernel console output
 *
 * Writes to COM1 (serial port 0x3F8) which QEMU and real hardware
 * both expose. Also writes to VGA text buffer at 0xB8000 for
 * debugging on bare metal.
 *
 * printk() supports: %d %u %x %X %llx %llu %lld %s %c %p %%
 */

#include <nekros/types.h>
#include <nekros/printk.h>
#include <nekros/string.h>

/* ── COM1 serial port ─────────────────────────────────────── */
#define COM1_PORT  0x3F8

static inline void outb(u16 port, u8 val) {
    __asm__ volatile("outb %0, %1" :: "a"(val), "Nd"(port));
}
static inline u8 inb(u16 port) {
    u8 v;
    __asm__ volatile("inb %1, %0" : "=a"(v) : "Nd"(port));
    return v;
}

static spinlock_t printk_lock = SPINLOCK_INIT;
static bool serial_ready = false;

void serial_init(void)
{
    outb(COM1_PORT + 1, 0x00);  /* Disable interrupts */
    outb(COM1_PORT + 3, 0x80);  /* Enable DLAB */
    outb(COM1_PORT + 0, 0x01);  /* Divisor lo (115200 baud) */
    outb(COM1_PORT + 1, 0x00);  /* Divisor hi */
    outb(COM1_PORT + 3, 0x03);  /* 8N1 */
    outb(COM1_PORT + 2, 0xC7);  /* FIFO 14-byte */
    outb(COM1_PORT + 4, 0x0B);  /* RTS+DTR */
    serial_ready = true;
}

void serial_putc(char c)
{
    if (!serial_ready) return;
    while (!(inb(COM1_PORT + 5) & 0x20));
    outb(COM1_PORT, (u8)c);
    if (c == '\n') {
        while (!(inb(COM1_PORT + 5) & 0x20));
        outb(COM1_PORT, '\r');
    }
}

/* ── VGA text buffer (80×25) ─────────────────────────────── */
#define VGA_BASE  0xFFFFFFFF800B8000ULL
#define VGA_COLS  80
#define VGA_ROWS  25

static volatile u16 *vga_buf  = (volatile u16 *)VGA_BASE;
static u32 vga_col = 0, vga_row = 0;
static u8  vga_attr = 0x07;  /* light grey on black */

static void vga_scroll(void)
{
    for (u32 r = 0; r < VGA_ROWS - 1; r++)
        for (u32 c = 0; c < VGA_COLS; c++)
            vga_buf[r * VGA_COLS + c] = vga_buf[(r+1) * VGA_COLS + c];
    for (u32 c = 0; c < VGA_COLS; c++)
        vga_buf[(VGA_ROWS-1) * VGA_COLS + c] = ((u16)vga_attr << 8) | ' ';
    vga_row = VGA_ROWS - 1;
}

static void vga_putc(char c)
{
    if (c == '\n') { vga_col = 0; vga_row++; }
    else if (c == '\r') { vga_col = 0; }
    else {
        vga_buf[vga_row * VGA_COLS + vga_col] = ((u16)vga_attr << 8) | (u8)c;
        vga_col++;
        if (vga_col >= VGA_COLS) { vga_col = 0; vga_row++; }
    }
    if (vga_row >= VGA_ROWS) vga_scroll();
}

static void put_char(char c)
{
    serial_putc(c);
    vga_putc(c);
}

static void put_str(const char *s)
{
    while (*s) put_char(*s++);
}

/* ── Minimal printf engine ────────────────────────────────── */

static void put_u64_base(u64 v, int base, int upper, int width, char pad)
{
    static const char *digits_lo = "0123456789abcdef";
    static const char *digits_hi = "0123456789ABCDEF";
    const char *digits = upper ? digits_hi : digits_lo;
    char buf[24];
    int  n = 0;
    if (!v) buf[n++] = '0';
    while (v) { buf[n++] = digits[v % base]; v /= base; }
    /* Padding */
    for (int i = n; i < width; i++) put_char(pad);
    /* Reverse */
    for (int i = n - 1; i >= 0; i--) put_char(buf[i]);
}

static void put_s64(s64 v, int width, char pad)
{
    if (v < 0) { put_char('-'); v = -v; width--; }
    put_u64_base((u64)v, 10, 0, width, pad);
}

#include <stdarg.h>

void printk(const char *fmt, ...)
{
    if (!fmt) return;  /* NULL format string guard */
    va_list ap;
    va_start(ap, fmt);

    spin_lock(&printk_lock);

    /* Strip log level prefix if present */
    if (fmt[0] == '<' && fmt[2] == '>') fmt += 3;

    for (const char *f = fmt; *f; f++) {
        if (*f != '%') { put_char(*f); continue; }
        f++;
        /* Parse flags/width */
        char pad = ' ';
        int  width = 0;
        bool lng = false, llng = false;
        if (*f == '0') { pad = '0'; f++; }
        while (*f >= '0' && *f <= '9') { width = width*10 + (*f-'0'); f++; }
        if (*f == 'l') { lng = true;  f++; }
        if (*f == 'l') { llng = true; f++; }

        switch (*f) {
        case 'd': case 'i':
            put_s64(llng || lng ? va_arg(ap, s64) : va_arg(ap, s32), width, pad);
            break;
        case 'u':
            put_u64_base(llng||lng ? va_arg(ap,u64):va_arg(ap,u32), 10,0,width,pad);
            break;
        case 'x':
            put_u64_base(llng||lng ? va_arg(ap,u64):va_arg(ap,u32), 16,0,width,pad);
            break;
        case 'X':
            put_u64_base(llng||lng ? va_arg(ap,u64):va_arg(ap,u32), 16,1,width,pad);
            break;
        case 'p':
            put_str("0x");
            put_u64_base((u64)va_arg(ap, void *), 16, 0, 16, '0');
            break;
        case 's': {
            const char *s = va_arg(ap, const char *);
            put_str(s ? s : "(null)");
            break;
        }
        case 'c': put_char((char)va_arg(ap, int)); break;
        case '%': put_char('%'); break;
        default:  put_char('%'); put_char(*f); break;
        }
    }

    spin_unlock(&printk_lock);
    va_end(ap);
}

void __noreturn panic(const char *fmt, ...)
{
    __asm__ volatile("cli");
    put_str("\n\n*** NEKROS PANIC ***\n");

    va_list ap;
    va_start(ap, fmt);
    /* Reuse printk logic inline */
    /* Try to acquire printk_lock; if already held (e.g. panic from printk),
     * force-release it to avoid a dead-lock before halting. */
    spin_lock(&printk_lock);
    vga_attr = 0x4F;  /* white on red for panic */
    for (const char *f = fmt; *f; f++) put_char(*f);
    spin_unlock(&printk_lock);
    va_end(ap);

    put_str("\nSystem halted.\n");
    /* Halt all CPUs */
    __asm__ volatile("cli");
    for (;;) __asm__ volatile("hlt");
}

/* panic_raw: print a literal string without format interpretation.
 * Use this when the panic message comes from a potentially
 * untrusted source (e.g. a driver passing an error string).    */
void __noreturn panic_raw(const char *msg) {
    __asm__ volatile("cli");
    vga_attr = 0x4F; /* white on red */
    spin_lock(&printk_lock);
    put_str("\n\n*** NEKROS PANIC ***\n");
    put_str(msg);
    put_str("\nSystem halted.\n");
    spin_unlock(&printk_lock);
    for (;;) __asm__ volatile("cli; hlt");
}
