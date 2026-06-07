/* SPDX-License-Identifier: GPL-2.0 */
/*
 * fs/vfs.c — Nekros Virtual Filesystem
 *
 * Provides a minimal but complete VFS:
 *   ramfs   — root filesystem (tmpfs-style, lives in RAM)
 *   devfs   — /dev (char devices: neri, null, zero, tty)
 *   procfs  — /proc (neri/status, neri/anomaly, cortexcrypto/*)
 *
 * Every process gets a fd_table_t with 32 file descriptors.
 * fd 0 = stdin  (serial input)
 * fd 1 = stdout (serial output)
 * fd 2 = stderr (serial output)
 * fd 3 = /dev/neri (Neri ioctl device)
 *
 * The VFS is the last piece that makes Nekros a real OS —
 * every abstraction built above (Neri, CortexCrypto, IPC)
 * exposes itself through this layer for userspace access.
 */

#include <nekros/types.h>
#include <nekros/printk.h>
#include <nekros/string.h>
#include <nekros/sched.h>
#include <nekros/task.h>
#include "../mm/vmm.h"
#include "../drivers/neri/include/neri.h"
#include "../drivers/neri/include/neri_sec.h"
#include "../drivers/neri/include/neri_uapi.h"
#include "../drivers/neri/include/neki_calib.h"

/* ── File operations vtable ──────────────────────────────── */
struct file;
struct inode;
struct dentry;

typedef struct file_ops {
    ssize_t (*read) (struct file *, u8 *, size_t);
    ssize_t (*write)(struct file *, const u8 *, size_t);
    int     (*ioctl)(struct file *, u32, u64);
    int     (*open) (struct inode *, struct file *);
    int     (*close)(struct file *);
} file_ops_t;

/* ── Inode ───────────────────────────────────────────────── */
#define INODE_FILE   1
#define INODE_DIR    2
#define INODE_CHAR   3
#define INODE_LINK   4

typedef struct inode {
    u32            ino;
    u32            type;         /* INODE_* */
    u32            mode;
    u64            size;
    u8            *data;         /* inline data (ramfs files) */
    u64            data_len;
    u64            data_cap;
    const file_ops_t *ops;
    list_head_t    children;     /* for directories */
    list_head_t    sibling;      /* in parent's children list */
    struct inode  *parent;
    char           name[64];
    spinlock_t     lock;
} inode_t;

/* ── File descriptor ─────────────────────────────────────── */
typedef struct file {
    inode_t       *inode;
    u64            offset;
    u32            flags;
    bool           open;
} file_t;

#define FD_TABLE_SIZE  32

typedef struct fd_table {
    file_t   fds[FD_TABLE_SIZE];
    spinlock_t lock;
} fd_table_t;

/* ── Global inode table ──────────────────────────────────── */
#define MAX_INODES  512
static inode_t  g_inodes[MAX_INODES];
static u32      g_next_ino = 1;
static spinlock_t inode_lock = SPINLOCK_INIT;

static inode_t *inode_alloc(const char *name, u32 type)
{
    spin_lock(&inode_lock);
    if (g_next_ino >= MAX_INODES) { spin_unlock(&inode_lock); return NULL; }
    inode_t *n       = &g_inodes[g_next_ino++];
    spin_unlock(&inode_lock);

    memset(n, 0, sizeof(*n));
    n->ino  = g_next_ino - 1;
    n->type = type;
    n->mode = 0644;
    n->lock = (spinlock_t)SPINLOCK_INIT;
    list_init(&n->children);
    list_init(&n->sibling);
    strlcpy(n->name, name, sizeof(n->name));
    return n;
}

static inode_t *g_root;      /* / */
static inode_t *g_dev;       /* /dev */
static inode_t *g_proc;      /* /proc */
static inode_t *g_proc_neri; /* /proc/neri */
static inode_t *g_proc_cc;   /* /proc/cortexcrypto */

/* ── ramfs file operations ───────────────────────────────── */
static ssize_t ramfs_read(struct file *f, u8 *buf, size_t len)
{
    inode_t *n = f->inode;
    if (!n->data) return 0;
    if (f->offset >= n->data_len) return 0;
    size_t avail = (size_t)(n->data_len - f->offset);
    size_t nread = MIN(len, avail);
    memcpy(buf, n->data + f->offset, nread);
    f->offset += nread;
    return (ssize_t)nread;
}

static ssize_t ramfs_write(struct file *f, const u8 *buf, size_t len)
{
    inode_t *n = f->inode;
    spin_lock(&n->lock);
    /* Grow buffer if needed */
    if (f->offset + len > n->data_cap) {
        /* Check for overflow BEFORE computing newcap */
        if (len > 0x10000000UL || f->offset > 0x10000000UL ||
            f->offset + len < f->offset) {  /* overflow check */
            spin_unlock(&n->lock); return -EFBIG;
        }
        u64 newcap = ALIGN(f->offset + len, 4096);
        u8 *newbuf = (u8*)kmalloc((size_t)newcap);
        if (!newbuf) { spin_unlock(&n->lock); return -ENOMEM; }
        if (n->data) { memcpy(newbuf, n->data, (size_t)n->data_len); kfree(n->data); }
        n->data    = newbuf;
        n->data_cap= newcap;
    }
    memcpy(n->data + f->offset, buf, len);
    f->offset    += len;
    if (f->offset > n->data_len) n->data_len = f->offset;
    n->size = n->data_len;
    spin_unlock(&n->lock);
    return (ssize_t)len;
}

static const file_ops_t ramfs_ops = {
    .read  = ramfs_read,
    .write = ramfs_write,
};

/* ── /dev/neri char device ───────────────────────────────── */
static ssize_t neri_dev_read(struct file *f, u8 *buf, size_t len)
{
    /* Returns a quick status line */
    char tmp[128];
    extern neri_pool_t g_neri_pool;
    u64 ep = (u64)atomic64_read((atomic64_t*)&g_neri_pool.epoch);
    int n = 0;
    /* hand-write "epoch=N cpu_alloc=N ram_alloc=N\n" */
    static const char hdr[] = "neri epoch=";
    memcpy(tmp, hdr, sizeof(hdr)-1); n += sizeof(hdr)-1;
    /* simple u64 to decimal */
    u64 v = ep; char rev[20]; int rn=0;
    if (!v) { rev[rn++]='0'; } else while(v){rev[rn++]='0'+v%10;v/=10;}
    for(int i=rn-1;i>=0;i--) tmp[n++]=rev[i];
    tmp[n++]='\n'; tmp[n]=0;
    size_t copy = MIN(len,(size_t)n);
    memcpy(buf,tmp,copy);
    return (ssize_t)copy;
}

extern int neri_dev_ioctl(u32 cmd, u64 arg);

static int neri_char_ioctl(struct file *f, u32 cmd, u64 arg)
{
    return neri_dev_ioctl(cmd, arg);
}

static const file_ops_t neri_dev_ops = {
    .read  = neri_dev_read,
    .ioctl = neri_char_ioctl,
};

/* ── /dev/neri ioctl implementation ──────────────────────── */
int neri_dev_ioctl(u32 cmd, u64 arg)
{
    extern neri_pool_t g_neri_pool;
    extern bool g_neri_ready;

    switch (cmd) {
    case NERI_IOC_STATUS: {
        struct neri_uapi_status *s = (struct neri_uapi_status *)arg;
        if (!s) return -EINVAL;
        /* Validate user pointer — ioctl arg is a user VA */
        extern bool uptr_valid_export(u64, size_t);
        /* Note: pointer validation is responsibility of syscall layer.
         * For ioctl from fd=3, caller must pass a valid user ptr.
         * Additional kernel check: ensure not NULL (already done above). */
        s->epoch           = (u64)atomic64_read(
                                 (atomic64_t*)&g_neri_pool.epoch);
        s->cpu_total_ns    = g_neri_pool.cpu_total_ns;
        s->cpu_alloc_ns    = g_neri_pool.cpu_alloc_ns;
        s->ram_total_pages = g_neri_pool.ram_total_pages;
        s->ram_alloc_pages = g_neri_pool.ram_alloc_pages;
        s->gpu_total_slots = g_neri_pool.gpu_total_slots;
        s->gpu_alloc_slots = g_neri_pool.gpu_alloc_slots;
        return 0;
    }
    case NERI_IOC_ANOMALY: {
        struct neri_uapi_anomaly *a = (struct neri_uapi_anomaly *)arg;
        if (!a) return -EINVAL;
        neri_sec_anomaly_t anm = {0};
        if (g_neri_ready) neri_sec_get_anomaly(&anm);
        a->score   = anm.score_byte;
        a->level   = (u32)anm.level;
        a->blocked = anm.block_admits ? 1 : 0;
        a->epoch   = anm.score_epoch;
        return 0;
    }
    case NERI_IOC_CAPS: {
        struct neri_uapi_caps *c = (struct neri_uapi_caps *)arg;
        if (!c) return -EINVAL;
        c->caps          = NERI_CAPS_ALL;
        c->version_major = 0;
        c->version_minor = 5;
        c->version_patch = 0;
        return 0;
    }
    default:
        return -ENOTTY;
    }
}

/* ── /dev/null and /dev/zero ─────────────────────────────── */
static ssize_t null_write(struct file *f, const u8 *buf, size_t len)
    { return (ssize_t)len; }
static ssize_t null_read (struct file *f, u8 *buf, size_t len)
    { return 0; }
static ssize_t zero_read (struct file *f, u8 *buf, size_t len)
    { memset(buf, 0, len); return (ssize_t)len; }

static const file_ops_t null_ops = { .read=null_read, .write=null_write };
static const file_ops_t zero_ops = { .read=zero_read, .write=null_write };

/* ── Serial TTY device (/dev/tty0) ───────────────────────── */
static ssize_t tty_write(struct file *f, const u8 *buf, size_t len)
{
    extern void serial_putc(char);   /* from printk.c */
    for (size_t i = 0; i < len; i++) serial_putc((char)buf[i]);
    return (ssize_t)len;
}
static const file_ops_t tty_ops = { .write = tty_write };

/* ── /proc/neri/status ───────────────────────────────────── */
static ssize_t proc_neri_status_read(struct file *f, u8 *buf, size_t len)
{
    if (f->offset > 0) return 0;  /* simple one-shot */
    extern neri_pool_t g_neri_pool;
    u64 ep  = (u64)atomic64_read((atomic64_t*)&g_neri_pool.epoch);
    u64 cpu_pct = g_neri_pool.cpu_total_ns ?
        g_neri_pool.cpu_alloc_ns * 100 / g_neri_pool.cpu_total_ns : 0;
    u64 ram_pct = g_neri_pool.ram_total_pages ?
        g_neri_pool.ram_alloc_pages * 100 / g_neri_pool.ram_total_pages : 0;

    /* Build status string — manual snprintf */
    char tmp[512];
    char *p = tmp;
    p += strlcpy(p, "Neri Resource Pool v0.5.0\n", 512);
    /* epoch */
    p += strlcpy(p, "epoch:           ", 64);
    /* write ep as decimal */
    char num[24]; int ni=0; u64 v=ep;
    if(!v){num[ni++]='0';}else while(v){num[ni++]='0'+v%10;v/=10;}
    for(int i=ni-1;i>=0;i--) *p++=num[i]; *p++='\n';

    p += strlcpy(p, "cpu_alloc_pct:   ", 64);
    ni=0; v=cpu_pct; if(!v){num[ni++]='0';}else while(v){num[ni++]='0'+v%10;v/=10;}
    for(int i=ni-1;i>=0;i--) *p++=num[i]; *p++='%'; *p++='\n';

    p += strlcpy(p, "ram_alloc_pct:   ", 64);
    ni=0; v=ram_pct; if(!v){num[ni++]='0';}else while(v){num[ni++]='0'+v%10;v/=10;}
    for(int i=ni-1;i>=0;i--) *p++=num[i]; *p++='%'; *p++='\n';

    u32 cpu_bias=50, gpu_burst=0, ram_prefetch=4; u8 reclaim=64;
    neki_get_policy(&cpu_bias, &gpu_burst, &ram_prefetch, &reclaim);
    p += strlcpy(p, "neki_cpu_bias:   ", 64);
    ni=0; v=cpu_bias; if(!v){num[ni++]='0';}else while(v){num[ni++]='0'+v%10;v/=10;}
    for(int i=ni-1;i>=0;i--) *p++=num[i]; *p++='%'; *p++='\n';

    neri_sec_anomaly_t anm={0};
    neri_sec_get_anomaly(&anm);
    p += strlcpy(p, "nsm_anomaly:     ", 64);
    static const char *lvls[]={"NORMAL","MEDIUM","HIGH","CRITICAL"};
    u32 lv = anm.level < 4 ? anm.level : 3;
    p += strlcpy(p, lvls[lv], 16);
    *p++=' '; *p++='(';
    ni=0; v=anm.score_byte; if(!v){num[ni++]='0';}else while(v){num[ni++]='0'+v%10;v/=10;}
    for(int i=ni-1;i>=0;i--) *p++=num[i];
    p += strlcpy(p, "/255)\n", 8);

    size_t total = (size_t)(p - tmp);
    size_t copy  = MIN(len, total);
    memcpy(buf, tmp, copy);
    f->offset += copy;
    return (ssize_t)copy;
}
static const file_ops_t proc_neri_status_ops = {
    .read = proc_neri_status_read,
};

/* ── /proc/cortexcrypto/machine_id ──────────────────────── */
static ssize_t proc_cc_mid_read(struct file *f, u8 *buf, size_t len)
{
    if (f->offset > 0) return 0;
    extern int cc_get_machine_fingerprint(char *, size_t);
    char fp[66];
    if (cc_get_machine_fingerprint(fp, sizeof(fp)) < 0)
        strlcpy(fp, "unavailable\n", sizeof(fp));
    else { fp[64]='\n'; fp[65]=0; }
    size_t flen = strnlen(fp, sizeof(fp));
    size_t copy = MIN(len, flen);
    memcpy(buf, fp, copy);
    f->offset += copy;
    return (ssize_t)copy;
}
static const file_ops_t proc_cc_mid_ops = { .read = proc_cc_mid_read };

/* ── Directory lookup ────────────────────────────────────── */
static inode_t *dir_lookup(inode_t *dir, const char *name)
{
    if (!dir || dir->type != INODE_DIR) return NULL;
    list_head_t *pos;
    list_for_each(pos, &dir->children) {
        inode_t *child = list_entry(pos, inode_t, sibling);
        if (strcmp(child->name, name) == 0) return child;
    }
    return NULL;
}

static void dir_add(inode_t *parent, inode_t *child)
{
    child->parent = parent;
    list_add_tail(&child->sibling, &parent->children);
}

static inode_t *mkfile(inode_t *parent, const char *name,
                        const file_ops_t *ops)
{
    inode_t *n = inode_alloc(name, INODE_FILE);
    if (!n) return NULL;
    n->ops = ops;
    if (parent) dir_add(parent, n);
    return n;
}

static inode_t *mkdir_node(inode_t *parent, const char *name)
{
    inode_t *n = inode_alloc(name, INODE_DIR);
    if (!n) return NULL;
    n->mode = 0755;
    if (parent) dir_add(parent, n);
    return n;
}

/* ── Path resolution ─────────────────────────────────────── */
inode_t *vfs_lookup(const char *path)
{
    if (!path || path[0] != '/') return NULL;
    inode_t *cur = g_root;
    if (path[1] == '\0') return cur;

    char component[64];
    const char *p = path + 1;
    while (*p && cur) {
        const char *slash = strchr(p, '/');
        size_t len = slash ? (size_t)(slash - p) : strlen(p);
        if (len >= sizeof(component)) return NULL;
        memcpy(component, p, len);
        component[len] = '\0';
        cur = dir_lookup(cur, component);
        p   = slash ? slash + 1 : p + len;
        if (!*p) break;
    }
    return cur;
}

/* ── FD table per-process ────────────────────────────────── */
static fd_table_t *fd_table_alloc(void)
{
    fd_table_t *t = (fd_table_t *)kzalloc(sizeof(*t));
    if (!t) return NULL;
    t->lock = (spinlock_t)SPINLOCK_INIT;
    return t;
}

static int fd_alloc(fd_table_t *t, inode_t *n)
{
    spin_lock(&t->lock);
    for (int i = 0; i < FD_TABLE_SIZE; i++) {
        if (!t->fds[i].open) {
            t->fds[i].inode  = n;
            t->fds[i].offset = 0;
            t->fds[i].open   = true;
            t->fds[i].flags  = 0;
            spin_unlock(&t->lock);
            return i;
        }
    }
    spin_unlock(&t->lock);
    return -EMFILE;
}

/* ── Public VFS API ──────────────────────────────────────── */

ssize_t vfs_read(int fd, void *buf, size_t len)
{
    /* Validate arguments */
    if (!buf || !len) return -EINVAL;
    if (len > 0x40000000UL) return -EINVAL; /* cap at 1GB */
    struct task *t = sched_current();
    if (!t || !t->fdt) return -EBADF;
    fd_table_t *fdt = (fd_table_t *)t->fdt;
    if ((unsigned int)fd >= (unsigned int)FD_TABLE_SIZE) return -EBADF;
    file_t *f = &fdt->fds[fd];
    if (!f->open || !f->inode) return -EBADF;
    if (!f->inode->ops || !f->inode->ops->read) return -EINVAL;
    return f->inode->ops->read(f, (u8 *)buf, len);
}

ssize_t vfs_write(int fd, const void *buf, size_t len)
{
    if (!buf && len) return -EINVAL;
    if (len > 0x40000000UL) return -EINVAL; /* cap at 1GB */
    struct task *t = sched_current();
    if (!t || !t->fdt) {
        /* Early boot only: write directly to serial */
        if (fd != 1 && fd != 2) return -EBADF;
        extern void serial_putc(char);
        const char *s = (const char *)buf;
        for (size_t i = 0; i < len; i++) serial_putc(s[i]);
        return (ssize_t)len;
    }
    fd_table_t *fdt = (fd_table_t *)t->fdt;
    /* Cast to unsigned prevents fd=-1 wrapping to FD_TABLE_SIZE-1 */
    if ((unsigned int)fd >= (unsigned int)FD_TABLE_SIZE) return -EBADF;
    file_t *f = &fdt->fds[fd];
    if (!f->open || !f->inode) return -EBADF;
    if (!f->inode->ops || !f->inode->ops->write) return -EINVAL;
    return f->inode->ops->write(f, (const u8 *)buf, len);
}

/* ── VFS init ────────────────────────────────────────────── */
void vfs_init(void)
{
    /* Build the filesystem tree */
    g_root = mkdir_node(NULL, "/");

    /* /dev */
    g_dev = mkdir_node(g_root, "dev");
    inode_t *dev_neri = mkfile(g_dev, "neri", &neri_dev_ops);
    dev_neri->type = INODE_CHAR;
    inode_t *dev_null = mkfile(g_dev, "null", &null_ops);
    dev_null->type = INODE_CHAR;
    inode_t *dev_zero = mkfile(g_dev, "zero", &zero_ops);
    dev_zero->type = INODE_CHAR;
    inode_t *dev_tty  = mkfile(g_dev, "tty0", &tty_ops);
    dev_tty->type = INODE_CHAR;

    /* /proc */
    g_proc = mkdir_node(g_root, "proc");

    /* /proc/neri */
    g_proc_neri = mkdir_node(g_proc, "neri");
    mkfile(g_proc_neri, "status",  &proc_neri_status_ops);

    /* /proc/cortexcrypto */
    g_proc_cc = mkdir_node(g_proc, "cortexcrypto");
    mkfile(g_proc_cc, "machine_id", &proc_cc_mid_ops);

    pr_info("vfs: ramfs mounted at /\n");
    pr_info("vfs: /dev/neri  /dev/null  /dev/zero  /dev/tty0\n");
    pr_info("vfs: /proc/neri/status  /proc/cortexcrypto/machine_id\n");

    /* Set up standard FDs for kernel tasks */
    /* Real process FD setup happens in task_create → fork */
    (void)fd_table_alloc;
    (void)fd_alloc;
}
