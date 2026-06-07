/* SPDX-License-Identifier: GPL-2.0 */
/*
 * include/nekros/string.h — kernel string and memory primitives
 * No libc. All implemented in pure C or compiler builtins.
 */
#ifndef NEKROS_STRING_H
#define NEKROS_STRING_H

#include <nekros/types.h>

/* ── Memory ───────────────────────────────────────────────── */
static __always_inline void *memset(void *dst, int c, size_t n) {
    return __builtin_memset(dst, c, n);
}
static __always_inline void *memcpy(void *dst, const void *src, size_t n) {
    return __builtin_memcpy(dst, src, n);
}
static __always_inline void *memmove(void *dst, const void *src, size_t n) {
    return __builtin_memmove(dst, src, n);
}
static __always_inline int memcmp(const void *a, const void *b, size_t n) {
    return __builtin_memcmp(a, b, n);
}
static __always_inline void memzero_explicit(void *s, size_t n) {
    memset(s, 0, n);
    barrier();   /* prevent compiler from eliding the clear */
}

/* ── String ───────────────────────────────────────────────── */
static inline size_t strlen(const char *s) {
    const char *e = s;
    while (*e) e++;
    return (size_t)(e - s);
}
static inline size_t strnlen(const char *s, size_t max) {
    size_t n = 0;
    while (n < max && s[n]) n++;
    return n;
}
static inline int strcmp(const char *a, const char *b) {
    while (*a && *a == *b) { a++; b++; }
    return (unsigned char)*a - (unsigned char)*b;
}
static inline int strncmp(const char *a, const char *b, size_t n) {
    while (n-- && *a && *a == *b) { a++; b++; }
    return n == (size_t)-1 ? 0 : (unsigned char)*a - (unsigned char)*b;
}
static inline char *strcpy(char *dst, const char *src) {
    char *d = dst;
    while ((*d++ = *src++));
    return dst;
}
static inline char *strncpy(char *dst, const char *src, size_t n) {
    size_t i;
    for (i = 0; i < n && src[i]; i++) dst[i] = src[i];
    for (; i < n; i++) dst[i] = '\0';
    return dst;
}
static inline size_t strlcpy(char *dst, const char *src, size_t size) {
    size_t len = strlen(src);
    if (size) {
        size_t n = len < size - 1 ? len : size - 1;
        memcpy(dst, src, n);
        dst[n] = '\0';
    }
    return len;
}
static inline char *strchr(const char *s, int c) {
    while (*s) { if (*s == (char)c) return (char *)s; s++; }
    return c ? NULL : (char *)s;
}
static inline char *strrchr(const char *s, int c) {
    const char *found = NULL;
    while (*s) { if (*s == (char)c) found = s; s++; }
    return c ? (char *)found : (char *)s;
}
static inline char *strstr(const char *haystack, const char *needle) {
    size_t nl = strlen(needle);
    if (!nl) return (char *)haystack;
    for (; *haystack; haystack++)
        if (!strncmp(haystack, needle, nl)) return (char *)haystack;
    return NULL;
}

/* ── Number conversion ────────────────────────────────────── */
static inline int isdigit(int c)  { return c >= '0' && c <= '9'; }
static inline int isxdigit(int c) {
    return isdigit(c) || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F');
}
static inline int isspace(int c)  { return c==' '||c=='\t'||c=='\n'||c=='\r'; }
static inline int toupper(int c)  { return c>='a'&&c<='z' ? c-32 : c; }
static inline int tolower(int c)  { return c>='A'&&c<='Z' ? c+32 : c; }

static inline u64 simple_strtoull(const char *s, char **end, int base) {
    u64 result = 0;
    while (isspace(*s)) s++;
    if (base == 0) {
        if (s[0] == '0' && (s[1] == 'x' || s[1] == 'X')) { base = 16; s += 2; }
        else if (s[0] == '0') { base = 8; s++; }
        else base = 10;
    }
    while (isxdigit(*s)) {
        int d = isdigit(*s) ? *s-'0' : toupper(*s)-'A'+10;
        if (d >= base) break;
        result = result * base + d;
        s++;
    }
    if (end) *end = (char *)s;
    return result;
}

/* ── Hex/byte utilities ───────────────────────────────────── */
static inline void bytes_to_hex(const u8 *in, size_t len, char *out) {
    static const char hx[] = "0123456789abcdef";
    for (size_t i = 0; i < len; i++) {
        out[i*2]   = hx[in[i] >> 4];
        out[i*2+1] = hx[in[i] & 0xf];
    }
    out[len * 2] = '\0';
}
static inline int hex_to_bytes(const char *hex, u8 *out, size_t len) {
    for (size_t i = 0; i < len; i++) {
        char hi = hex[i*2], lo = hex[i*2+1];
        if (!isxdigit(hi) || !isxdigit(lo)) return -EINVAL;
        out[i] = (u8)((isdigit(hi)?hi-'0':toupper(hi)-'A'+10)<<4 |
                      (isdigit(lo)?lo-'0':toupper(lo)-'A'+10));
    }
    return 0;
}

#endif /* NEKROS_STRING_H */
