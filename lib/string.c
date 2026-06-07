/* SPDX-License-Identifier: GPL-2.0 */
#include <nekros/types.h>
void *memset(void *dst, int c, size_t n) {
    u8 *d=(u8*)dst; while(n--) *d++=(u8)c; return dst; }
void *memcpy(void *dst, const void *src, size_t n) {
    u8 *d=(u8*)dst; const u8 *s=(const u8*)src;
    while(n--) *d++=*s++; return dst; }
void *memmove(void *dst, const void *src, size_t n) {
    u8 *d=(u8*)dst; const u8 *s=(const u8*)src;
    if(d<s){while(n--)*d++=*s++;}else{d+=n;s+=n;while(n--)*--d=*--s;}
    return dst; }
int memcmp(const void *a, const void *b, size_t n) {
    const u8 *x=(const u8*)a,*y=(const u8*)b;
    while(n--){if(*x!=*y)return *x-*y;x++;y++;} return 0; }
void memzero_explicit(void *s, size_t n) {
    volatile u8 *p=(volatile u8*)s; while(n--)*p++=0; }
