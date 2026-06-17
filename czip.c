/*
 * czip 1.1.0  —  compress + authenticated-encrypt files and directories.
 *
 * Pipeline:  plaintext archive  ->  zstd (multithreaded)  ->  AEAD encrypt
 *   - Compression : zstd, worker threads scaled to the CPU count (like 7-Zip).
 *   - Encryption  : XChaCha20-Poly1305 via libsodium's "secretstream", which
 *                   chunks the data into an authenticated, ordered sequence.
 *   - Key         : derived from a password with Argon2id (libsodium pwhash).
 *
 * Everything is streamed: the archive is built, compressed, encrypted and
 * written chunk by chunk, so memory use stays flat (a few hundred KB) even for
 * terabyte-scale inputs. Progress is reported to stderr as it runs.
 *
 * Compress-then-encrypt is intentional: ciphertext is indistinguishable from
 * random and therefore cannot be compressed, so compression must come first.
 *
 * Build:  cc -O2 -o czip czip.c -lsodium -lzstd
 */

#define _XOPEN_SOURCE 700
#include <stdio.h>
#include <stdarg.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <unistd.h>
#include <dirent.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <errno.h>
#include <limits.h>
#include <time.h>
#include <fcntl.h>

#include <sodium.h>
#include <zstd.h>

#define CZIP_VER_MAJOR 1
#define CZIP_VER_MINOR 2
#define CZIP_VER_PATCH 0
#define CZIP_VERSION_STR "1.2.0"

/* On-disk container header. */
static const unsigned char CZIP_MAGIC[4] = { 'C', 'Z', 'I', 'P' };
#define CZIP_FORMAT     3   /* current container format (3 = per-entry mode+mtime) */
#define CZIP_FORMAT_MIN 2   /* oldest container format we can still read         */

#define ALG_XCHACHA  1                /* secretstream is XChaCha20-Poly1305 based */

/* Target size of one plaintext-compressed chunk before it is sealed. */
#define CZIP_CHUNK (256 * 1024)

/* Archive entry types (plaintext stream, before compression). */
#define ENT_FILE 'f'
#define ENT_DIR  'd'
#define ENT_LINK 'l'    /* symbolic link; payload is the link target string */

/* ---- small helpers ------------------------------------------------------ */

static int g_quiet = 0;   /* -q/--quiet: suppress informational output */

/* Informational output; silenced by --quiet. Errors always go via die(). */
static void info(const char *fmt, ...) {
    if (g_quiet) return;
    va_list ap;
    va_start(ap, fmt);
    vprintf(fmt, ap);
    va_end(ap);
}

static void die(const char *msg) {
    fprintf(stderr, "czip: %s\n", msg);
    exit(1);
}

/* For genuine syscall failures: append the current errno description. */
static void die_errno(const char *msg) {
    fprintf(stderr, "czip: %s (%s)\n", msg, strerror(errno));
    exit(1);
}

static void *xmalloc(size_t n) {
    void *p = malloc(n ? n : 1);
    if (!p) die("out of memory");
    return p;
}

/* A growable byte buffer. */
typedef struct {
    unsigned char *data;
    size_t len, cap;
} Buf;

static void buf_init(Buf *b) { b->data = NULL; b->len = b->cap = 0; }
static void buf_free(Buf *b) { free(b->data); b->data = NULL; b->len = b->cap = 0; }

static void buf_reserve(Buf *b, size_t extra) {
    if (b->len + extra <= b->cap) return;
    size_t cap = b->cap ? b->cap : 4096;
    while (cap < b->len + extra) cap *= 2;
    b->data = realloc(b->data, cap);
    if (!b->data) die("out of memory");
    b->cap = cap;
}

static void buf_append(Buf *b, const void *src, size_t n) {
    buf_reserve(b, n);
    memcpy(b->data + b->len, src, n);
    b->len += n;
}

static void buf_u8(Buf *b, uint8_t v)  { buf_append(b, &v, 1); }

static void buf_u64(Buf *b, uint64_t v) {
    unsigned char t[8];
    for (int i = 0; i < 8; i++) t[i] = (unsigned char)(v >> (8 * i));
    buf_append(b, t, 8);
}

static void wr_u32(unsigned char *p, uint32_t v) {
    p[0] = v; p[1] = v >> 8; p[2] = v >> 16; p[3] = v >> 24;
}
static uint32_t rd_u32(const unsigned char *p) {
    return (uint32_t)p[0] | (uint32_t)p[1] << 8 |
           (uint32_t)p[2] << 16 | (uint32_t)p[3] << 24;
}
static uint64_t rd_u64(const unsigned char *p) {
    uint64_t v = 0;
    for (int i = 0; i < 8; i++) v |= (uint64_t)p[i] << (8 * i);
    return v;
}

/* Format a byte count into a human-friendly string, e.g. "3.0 MB". */
static void human_size(double bytes, char *out, size_t outsz) {
    const char *u[] = { "B", "KB", "MB", "GB", "TB" };
    int i = 0;
    while (bytes >= 1024.0 && i < 4) { bytes /= 1024.0; i++; }
    if (i == 0) snprintf(out, outsz, "%.0f %s", bytes, u[i]);
    else        snprintf(out, outsz, "%.2f %s", bytes, u[i]);
}

static int file_exists(const char *path) {
    struct stat st;
    return stat(path, &st) == 0;
}

static long cpu_count(void) {
    long n = sysconf(_SC_NPROCESSORS_ONLN);
    return n > 0 ? n : 1;
}

/* basename without trailing slash, for the archive root name. */
static const char *base_name(const char *path) {
    const char *b = path, *p;
    for (p = path; *p; p++) if (*p == '/' && p[1]) b = p + 1;
    return b;
}

/* ---- key derivation ----------------------------------------------------- */

static void derive_key(unsigned char *key, const char *password,
                       const unsigned char *salt,
                       unsigned long long ops, size_t mem) {
    if (crypto_pwhash(key, crypto_secretstream_xchacha20poly1305_KEYBYTES,
                      password, strlen(password), salt, ops, mem,
                      crypto_pwhash_ALG_ARGON2ID13) != 0)
        die("key derivation failed (out of memory?)");
}

/* ---- output stream (single file or split parts) ------------------------- */

typedef struct {
    char      base[PATH_MAX];
    size_t    split;          /* 0 = single file, else bytes per part */
    FILE     *f;
    size_t    part_index;     /* 1-based, only meaningful when split > 0 */
    size_t    part_written;   /* bytes in the current part */
    char      cur_name[PATH_MAX + 16];
    uint64_t  total;          /* total bytes written across all parts */
} OutStream;

static void out_open_part(OutStream *o) {
    if (o->split == 0)
        snprintf(o->cur_name, sizeof o->cur_name, "%s", o->base);
    else
        snprintf(o->cur_name, sizeof o->cur_name, "%s.%03zu",
                 o->base, o->part_index);
    o->f = fopen(o->cur_name, "wb");
    if (!o->f) die_errno("cannot open output file");
    o->part_written = 0;
}

static void out_open(OutStream *o, const char *base, size_t split) {
    snprintf(o->base, sizeof o->base, "%s", base);
    o->split = split;
    o->part_index = 1;
    o->total = 0;
    out_open_part(o);
}

static void out_write(OutStream *o, const void *buf, size_t n) {
    const unsigned char *p = buf;
    if (o->split == 0) {
        if (n && fwrite(p, 1, n, o->f) != n) die_errno("write failed");
        o->total += n;
        return;
    }
    while (n) {
        if (o->part_written == o->split) {
            if (fclose(o->f) != 0) die_errno("close failed");
            info("czip: wrote %s (%zu bytes)\n", o->cur_name, o->part_written);
            o->part_index++;
            out_open_part(o);
        }
        size_t room = o->split - o->part_written;
        size_t w = n < room ? n : room;
        if (fwrite(p, 1, w, o->f) != w) die_errno("write failed");
        o->part_written += w;
        o->total += w;
        p += w;
        n -= w;
    }
}

static void out_close(OutStream *o) {
    if (fclose(o->f) != 0) die_errno("close failed");
    if (o->split == 0)
        info("czip: wrote %s (%zu bytes)\n", o->cur_name, (size_t)o->total);
    else {
        info("czip: wrote %s (%zu bytes)\n", o->cur_name, o->part_written);
        info("czip: split into %zu parts\n", o->part_index);
    }
}

/* ---- input stream (single file or split parts) -------------------------- */

typedef struct {
    char   base[PATH_MAX];
    FILE  *f;
    size_t part_index;   /* 0 = single file; >=1 = current split part */
} InStream;

static void in_open(InStream *s, const char *name) {
    /* If handed a ".001" part directly, fall back to its base name. */
    size_t n = strlen(name);
    if (n > 4 && name[n - 4] == '.' &&
        name[n-3] >= '0' && name[n-3] <= '9' &&
        name[n-2] >= '0' && name[n-2] <= '9' &&
        name[n-1] >= '0' && name[n-1] <= '9' &&
        file_exists(name)) {
        snprintf(s->base, sizeof s->base, "%.*s", (int)(n - 4), name);
    } else {
        snprintf(s->base, sizeof s->base, "%s", name);
    }

    if (file_exists(s->base)) {
        s->part_index = 0;
        s->f = fopen(s->base, "rb");
        if (!s->f) die_errno("cannot read input");
        return;
    }
    /* Try split parts <base>.001, .002, ... */
    char part[PATH_MAX + 16];
    snprintf(part, sizeof part, "%s.001", s->base);
    if (!file_exists(part)) die("input file not found");
    s->part_index = 1;
    s->f = fopen(part, "rb");
    if (!s->f) die_errno("cannot read part");
}

/* Read up to n bytes, transparently crossing split-part boundaries.
 * Returns the number of bytes read; 0 means end of the whole container. */
static size_t in_read(InStream *s, void *buf, size_t n) {
    unsigned char *p = buf;
    size_t got = 0;
    while (got < n) {
        size_t r = fread(p + got, 1, n - got, s->f);
        got += r;
        if (got == n) break;
        if (ferror(s->f)) die_errno("read failed");
        /* hit EOF on this file */
        if (s->part_index == 0) break;           /* single file: done */
        fclose(s->f);
        s->part_index++;
        char part[PATH_MAX + 16];
        snprintf(part, sizeof part, "%s.%03zu", s->base, s->part_index);
        if (!file_exists(part)) break;            /* no more parts: done */
        s->f = fopen(part, "rb");
        if (!s->f) die_errno("cannot read part");
    }
    return got;
}

static void in_readfull(InStream *s, void *buf, size_t n) {
    if (in_read(s, buf, n) != n) die("corrupt or truncated container");
}

static void in_close(InStream *s) {
    if (s->f) fclose(s->f);
    s->f = NULL;
}

/* ---- progress reporting ------------------------------------------------- */

typedef struct {
    const char *verb;       /* "compressing" / "extracting" */
    uint64_t    total;      /* expected total, 0 if unknown */
    uint64_t    done;
    uint64_t    last_shown; /* bytes at last redraw */
    time_t      last_time;
} Progress;

static void progress_init(Progress *p, const char *verb, uint64_t total) {
    p->verb = verb;
    p->total = total;
    p->done = p->last_shown = 0;
    p->last_time = 0;
}

static void progress_draw(Progress *p, int final) {
    if (g_quiet) return;
    char hd[32];
    human_size((double)p->done, hd, sizeof hd);
    if (p->total) {
        char ht[32];
        human_size((double)p->total, ht, sizeof ht);
        double pct = 100.0 * (double)p->done / (double)p->total;
        if (pct > 100.0) pct = 100.0;
        fprintf(stderr, "\rczip: %s %5.1f%% (%s / %s)        ",
                p->verb, pct, hd, ht);
    } else {
        fprintf(stderr, "\rczip: %s %s        ", p->verb, hd);
    }
    if (final) fputc('\n', stderr);
    fflush(stderr);
}

/* Redraw at most a few times a second, plus once when finishing. */
static void progress_add(Progress *p, uint64_t n) {
    p->done += n;
    if (g_quiet) return;
    if (p->done - p->last_shown < 1u << 20) return;   /* < 1 MB since last */
    time_t now = time(NULL);
    if (now == p->last_time) return;
    p->last_time = now;
    p->last_shown = p->done;
    progress_draw(p, 0);
}

/* ---- streaming encoder (zstd -> secretstream -> output) ----------------- */

typedef struct {
    OutStream *out;
    ZSTD_CCtx *cctx;
    crypto_secretstream_xchacha20poly1305_state st;
    unsigned char *zbuf;     /* scratch for zstd output */
    size_t         zcap;
    Buf            cbuf;      /* pending compressed bytes awaiting a chunk */
    unsigned char *ad;        /* header bytes, bound into the first chunk */
    size_t         adlen;
    uint64_t       plain_total; /* total plaintext archive bytes emitted */
    Progress      *prog;
} Enc;

/* Seal one chunk of compressed plaintext and write it: u32 len + ciphertext. */
static void enc_seal(Enc *e, const unsigned char *p, size_t n, unsigned char tag) {
    unsigned char *ct = xmalloc(n + crypto_secretstream_xchacha20poly1305_ABYTES);
    unsigned long long clen = 0;
    crypto_secretstream_xchacha20poly1305_push(
        &e->st, ct, &clen, p, n, e->ad, e->adlen, tag);
    e->ad = NULL; e->adlen = 0;   /* AD only binds the first chunk */
    unsigned char lp[4];
    wr_u32(lp, (uint32_t)clen);
    out_write(e->out, lp, 4);
    out_write(e->out, ct, (size_t)clen);
    free(ct);
}

/* Accumulate compressed bytes, sealing whole CZIP_CHUNK pieces as they fill. */
static void enc_add_compressed(Enc *e, const unsigned char *p, size_t n) {
    buf_append(&e->cbuf, p, n);
    size_t off = 0;
    while (e->cbuf.len - off >= CZIP_CHUNK) {
        enc_seal(e, e->cbuf.data + off, CZIP_CHUNK,
                 crypto_secretstream_xchacha20poly1305_TAG_MESSAGE);
        off += CZIP_CHUNK;
    }
    if (off) {
        memmove(e->cbuf.data, e->cbuf.data + off, e->cbuf.len - off);
        e->cbuf.len -= off;
    }
}

/* Feed plaintext archive bytes into the pipeline. */
static void enc_plain(Enc *e, const void *buf, size_t n) {
    e->plain_total += n;
    ZSTD_inBuffer in = { buf, n, 0 };
    while (in.pos < in.size) {
        ZSTD_outBuffer out = { e->zbuf, e->zcap, 0 };
        size_t r = ZSTD_compressStream2(e->cctx, &out, &in, ZSTD_e_continue);
        if (ZSTD_isError(r)) die(ZSTD_getErrorName(r));
        if (out.pos) enc_add_compressed(e, e->zbuf, out.pos);
    }
}

static void enc_u8(Enc *e, uint8_t v)  { enc_plain(e, &v, 1); }
static void enc_u32(Enc *e, uint32_t v) {
    unsigned char t[4]; wr_u32(t, v); enc_plain(e, t, 4);
}
static void enc_u64(Enc *e, uint64_t v) {
    unsigned char t[8];
    for (int i = 0; i < 8; i++) t[i] = (unsigned char)(v >> (8 * i));
    enc_plain(e, t, 8);
}

/* Flush zstd and seal the trailing data with the FINAL tag. */
static void enc_finish(Enc *e) {
    for (;;) {
        ZSTD_inBuffer in = { NULL, 0, 0 };
        ZSTD_outBuffer out = { e->zbuf, e->zcap, 0 };
        size_t r = ZSTD_compressStream2(e->cctx, &out, &in, ZSTD_e_end);
        if (ZSTD_isError(r)) die(ZSTD_getErrorName(r));
        if (out.pos) enc_add_compressed(e, e->zbuf, out.pos);
        if (r == 0) break;
    }
    enc_seal(e, e->cbuf.data, e->cbuf.len,
             crypto_secretstream_xchacha20poly1305_TAG_FINAL);
    e->cbuf.len = 0;
}

/* ---- archive building (directory walk, streamed) ------------------------ */

/* Sum the sizes of regular files under a path, for the progress total. */
static uint64_t sum_size(const char *fullpath) {
    struct stat st;
    if (lstat(fullpath, &st) != 0) return 0;
    if (S_ISLNK(st.st_mode)) return (uint64_t)st.st_size;
    if (S_ISREG(st.st_mode)) return (uint64_t)st.st_size;
    if (!S_ISDIR(st.st_mode)) return 0;
    uint64_t total = 0;
    DIR *d = opendir(fullpath);
    if (!d) return 0;
    struct dirent *de;
    while ((de = readdir(d)) != NULL) {
        if (!strcmp(de->d_name, ".") || !strcmp(de->d_name, "..")) continue;
        char fp[PATH_MAX];
        snprintf(fp, sizeof fp, "%s/%s", fullpath, de->d_name);
        total += sum_size(fp);
    }
    closedir(d);
    return total;
}

static void add_path(Enc *e, const char *fullpath, const char *relpath);

/* Emit the per-entry name and metadata (mode + mtime) shared by all types. */
static void enc_name_meta(Enc *e, const char *relpath, const struct stat *st) {
    enc_u32(e, (uint32_t)strlen(relpath));
    enc_plain(e, relpath, strlen(relpath));
    enc_u32(e, (uint32_t)(st->st_mode & 07777));
    enc_u64(e, (uint64_t)(int64_t)st->st_mtime);
}

static void add_dir(Enc *e, const char *fullpath, const char *relpath,
                    const struct stat *st) {
    /* Record the directory itself so empty dirs survive. */
    enc_u8(e, ENT_DIR);
    enc_name_meta(e, relpath, st);

    DIR *d = opendir(fullpath);
    if (!d) die_errno("cannot open directory");
    struct dirent *de;
    while ((de = readdir(d)) != NULL) {
        if (!strcmp(de->d_name, ".") || !strcmp(de->d_name, "..")) continue;
        char fp[PATH_MAX], rp[PATH_MAX];
        snprintf(fp, sizeof fp, "%s/%s", fullpath, de->d_name);
        snprintf(rp, sizeof rp, "%s/%s", relpath, de->d_name);
        add_path(e, fp, rp);
    }
    closedir(d);
}

static void add_file(Enc *e, const char *fullpath, const char *relpath,
                     const struct stat *st) {
    uint64_t size = (uint64_t)st->st_size;

    enc_u8(e, ENT_FILE);
    enc_name_meta(e, relpath, st);
    enc_u64(e, size);

    FILE *f = fopen(fullpath, "rb");
    if (!f) die_errno("cannot read file");
    unsigned char tmp[1 << 16];
    uint64_t remaining = size;
    while (remaining > 0) {
        size_t want = remaining < sizeof tmp ? (size_t)remaining : sizeof tmp;
        size_t n = fread(tmp, 1, want, f);
        if (n == 0) {
            /* File shrank since stat; pad with zeros to honour the header. */
            memset(tmp, 0, want);
            n = want;
        }
        enc_plain(e, tmp, n);
        progress_add(e->prog, n);
        remaining -= n;
    }
    fclose(f);
}

static void add_link(Enc *e, const char *fullpath, const char *relpath,
                     const struct stat *st) {
    char target[PATH_MAX];
    ssize_t n = readlink(fullpath, target, sizeof target - 1);
    if (n < 0) die_errno("cannot read symlink");
    target[n] = 0;
    enc_u8(e, ENT_LINK);
    enc_name_meta(e, relpath, st);
    enc_u64(e, (uint64_t)n);
    enc_plain(e, target, (size_t)n);
    progress_add(e->prog, (uint64_t)n);
}

static void add_path(Enc *e, const char *fullpath, const char *relpath) {
    struct stat st;
    if (lstat(fullpath, &st) != 0) die_errno("cannot stat path");
    if (S_ISLNK(st.st_mode))       add_link(e, fullpath, relpath, &st);
    else if (S_ISDIR(st.st_mode))  add_dir(e, fullpath, relpath, &st);
    else if (S_ISREG(st.st_mode))  add_file(e, fullpath, relpath, &st);
    else fprintf(stderr, "czip: skipping special file %s\n", relpath);
}

/* ---- archive extraction (streamed) -------------------------------------- */

static void mkdirs(const char *path) {
    char tmp[PATH_MAX];
    snprintf(tmp, sizeof tmp, "%s", path);
    for (char *p = tmp + 1; *p; p++) {
        if (*p == '/') {
            *p = 0;
            if (mkdir(tmp, 0755) != 0 && errno != EEXIST) die_errno("mkdir failed");
            *p = '/';
        }
    }
    if (mkdir(tmp, 0755) != 0 && errno != EEXIST) die_errno("mkdir failed");
}

static void parent_dirs(const char *path) {
    char tmp[PATH_MAX];
    snprintf(tmp, sizeof tmp, "%s", path);
    char *slash = strrchr(tmp, '/');
    if (!slash) return;
    *slash = 0;
    if (tmp[0]) mkdirs(tmp);
}

/* True if the path is absolute or contains a ".." component (traversal).
 * Unlike a plain substring test, this allows legitimate names like "a..b". */
static int path_is_unsafe(const char *path) {
    if (path[0] == '/') return 1;
    for (const char *p = path; *p; p++) {
        if ((p == path || p[-1] == '/') &&
            p[0] == '.' && p[1] == '.' && (p[2] == '/' || p[2] == '\0'))
            return 1;
    }
    return 0;
}

static void check_path(const char *path) {
    if (path_is_unsafe(path)) die("unsafe path in archive");
}

/* Best-effort restore of a path's modification time (atime set to match). */
static void set_times(const char *path, int64_t mtime, int nofollow) {
    struct timespec ts[2];
    ts[0].tv_sec = (time_t)mtime; ts[0].tv_nsec = 0;
    ts[1].tv_sec = (time_t)mtime; ts[1].tv_nsec = 0;
    utimensat(AT_FDCWD, path, ts, nofollow ? AT_SYMLINK_NOFOLLOW : 0);
}

/* Incremental archive parser: bytes are fed in as they decompress. */
enum { S_TYPE, S_NLEN, S_NAME, S_META, S_SIZE, S_FILE, S_LINK };

/* Deferred directory metadata: applied at the end, deepest-first, so that
 * writing children never clobbers a directory's restored mode/mtime. */
typedef struct { char *path; uint32_t mode; int64_t mtime; } DirFix;

typedef struct {
    int           state;
    int           has_meta;     /* format >= 3 carries per-entry mode + mtime */
    unsigned char type;
    unsigned char field[12];    /* staging for nlen (4), meta (12) or size (8) */
    size_t        field_need, field_have;
    char          name[PATH_MAX];
    uint32_t      nlen, nhave;
    uint32_t      mode;         /* current entry mode (0 if absent) */
    int64_t       mtime;        /* current entry mtime (0 if absent) */
    uint64_t      payload;      /* remaining payload bytes */
    FILE         *cur;          /* open output file for ENT_FILE */
    Buf           link;         /* accumulates an ENT_LINK target */
    DirFix       *dirs;         /* pending directory fixups */
    size_t        ndirs, dirs_cap;
    Progress     *prog;
} Ext;

static void ext_init(Ext *x, Progress *prog, int has_meta) {
    memset(x, 0, sizeof *x);
    x->state = S_TYPE;
    x->has_meta = has_meta;
    buf_init(&x->link);
    x->prog = prog;
}

static void ext_defer_dir(Ext *x) {
    if (x->ndirs == x->dirs_cap) {
        x->dirs_cap = x->dirs_cap ? x->dirs_cap * 2 : 16;
        x->dirs = realloc(x->dirs, x->dirs_cap * sizeof *x->dirs);
        if (!x->dirs) die("out of memory");
    }
    DirFix *df = &x->dirs[x->ndirs++];
    df->path = xmalloc(strlen(x->name) + 1);
    strcpy(df->path, x->name);
    df->mode = x->mode;
    df->mtime = x->mtime;
}

/* Apply a regular file's restored mode and mtime (best effort). */
static void apply_file_meta(Ext *x, const char *path) {
    if (!x->has_meta) return;
    if (x->mode) chmod(path, x->mode & 07777);
    set_times(path, x->mtime, 0);
}

/* Called once a full entry header (name, and size for file/link) is parsed. */
static void ext_begin_entry(Ext *x) {
    x->name[x->nlen] = 0;
    check_path(x->name);
    if (x->type == ENT_DIR) {
        mkdirs(x->name);
        if (x->has_meta) ext_defer_dir(x);   /* mode/mtime restored at the end */
        x->state = S_TYPE;
    } else if (x->type == ENT_FILE) {
        parent_dirs(x->name);
        unlink(x->name);                 /* never write through a symlink */
        x->cur = fopen(x->name, "wb");
        if (!x->cur) die_errno("cannot open output file");
        if (x->payload == 0) {
            fclose(x->cur); x->cur = NULL;
            apply_file_meta(x, x->name);
            x->state = S_TYPE;
        }
        else x->state = S_FILE;
    } else { /* ENT_LINK */
        x->link.len = 0;
        if (x->payload == 0) {
            fprintf(stderr, "czip: skipping symlink with empty target %s\n", x->name);
            x->state = S_TYPE;
        } else x->state = S_LINK;
    }
}

static void ext_finish_link(Ext *x) {
    if (x->link.len >= PATH_MAX) die("symlink target too long");
    char target[PATH_MAX];
    memcpy(target, x->link.data, x->link.len);
    target[x->link.len] = 0;
    parent_dirs(x->name);
    /* Never create a link that escapes the tree. */
    if (path_is_unsafe(target)) {
        fprintf(stderr, "czip: skipping unsafe symlink %s -> %s\n", x->name, target);
    } else {
        unlink(x->name);
        if (symlink(target, x->name) != 0) die_errno("cannot create symlink");
        set_times(x->name, x->mtime, 1);
    }
}

static void ext_feed(Ext *x, const unsigned char *p, size_t n) {
    size_t i = 0;
    while (i < n) {
        switch (x->state) {
        case S_TYPE:
            x->type = p[i++];
            if (x->type != ENT_FILE && x->type != ENT_DIR && x->type != ENT_LINK)
                die("corrupt archive (bad entry type)");
            x->field_need = 4; x->field_have = 0;
            x->state = S_NLEN;
            break;
        case S_NLEN: {
            size_t take = x->field_need - x->field_have;
            if (take > n - i) take = n - i;
            memcpy(x->field + x->field_have, p + i, take);
            x->field_have += take; i += take;
            if (x->field_have < x->field_need) break;
            x->nlen = rd_u32(x->field);
            if (x->nlen == 0) die("corrupt archive (empty path)");
            if (x->nlen >= PATH_MAX) die("path too long");
            x->nhave = 0;
            x->state = S_NAME;
            break;
        }
        case S_NAME: {
            size_t take = x->nlen - x->nhave;
            if (take > n - i) take = n - i;
            memcpy(x->name + x->nhave, p + i, take);
            x->nhave += take; i += take;
            if (x->nhave < x->nlen) break;
            x->name[x->nlen] = 0;
            x->mode = 0; x->mtime = 0;
            if (x->has_meta) {
                x->field_need = 12; x->field_have = 0;
                x->state = S_META;
            } else if (x->type == ENT_DIR) {
                ext_begin_entry(x);
            } else {
                x->field_need = 8; x->field_have = 0;
                x->state = S_SIZE;
            }
            break;
        }
        case S_META: {
            size_t take = x->field_need - x->field_have;
            if (take > n - i) take = n - i;
            memcpy(x->field + x->field_have, p + i, take);
            x->field_have += take; i += take;
            if (x->field_have < x->field_need) break;
            x->mode = rd_u32(x->field);
            x->mtime = (int64_t)rd_u64(x->field + 4);
            if (x->type == ENT_DIR) {
                ext_begin_entry(x);
            } else {
                x->field_need = 8; x->field_have = 0;
                x->state = S_SIZE;
            }
            break;
        }
        case S_SIZE: {
            size_t take = x->field_need - x->field_have;
            if (take > n - i) take = n - i;
            memcpy(x->field + x->field_have, p + i, take);
            x->field_have += take; i += take;
            if (x->field_have < x->field_need) break;
            x->payload = rd_u64(x->field);
            ext_begin_entry(x);
            break;
        }
        case S_FILE: {
            size_t take = x->payload < n - i ? (size_t)x->payload : n - i;
            if (take && fwrite(p + i, 1, take, x->cur) != take)
                die_errno("write failed");
            i += take; x->payload -= take;
            progress_add(x->prog, take);
            if (x->payload == 0) {
                fclose(x->cur); x->cur = NULL;
                apply_file_meta(x, x->name);
                x->state = S_TYPE;
            }
            break;
        }
        case S_LINK: {
            size_t take = x->payload < n - i ? (size_t)x->payload : n - i;
            buf_append(&x->link, p + i, take);
            i += take; x->payload -= take;
            progress_add(x->prog, take);
            if (x->payload == 0) {
                ext_finish_link(x);
                x->state = S_TYPE;
            }
            break;
        }
        }
    }
}

static void ext_done(Ext *x) {
    if (x->state != S_TYPE) die("corrupt archive (truncated entry)");
    if (x->cur) fclose(x->cur);
    /* Restore directory metadata last, deepest-first, so neither child writes
     * nor a read-only parent mode can interfere. */
    for (size_t i = x->ndirs; i-- > 0; ) {
        DirFix *df = &x->dirs[i];
        if (df->mode) chmod(df->path, df->mode & 07777);
        set_times(df->path, df->mtime, 0);
        free(df->path);
    }
    free(x->dirs);
    buf_free(&x->link);
}

/* ---- output naming ------------------------------------------------------ */

/* Pick "<base>.cz", or "<base>.czip" if the .cz already exists. */
static void choose_output_name(const char *base, char *out, size_t outsz) {
    snprintf(out, outsz, "%s.cz", base);
    if (file_exists(out)) snprintf(out, outsz, "%s.czip", base);
}

/* ---- compress command --------------------------------------------------- */

static void cmd_compress(const char *input, const char *password,
                         int level, int workers, size_t split,
                         const char *out_override) {
    struct stat st;
    if (lstat(input, &st) != 0) die_errno("input path not found");

    /* Output name. */
    char outname[PATH_MAX];
    if (out_override) {
        snprintf(outname, sizeof outname, "%s", out_override);
    } else {
        /* Strip trailing slashes so "dir/" yields "dir.cz", not "dir/.cz". */
        char clean[PATH_MAX];
        snprintf(clean, sizeof clean, "%s", input);
        size_t cl = strlen(clean);
        while (cl > 1 && clean[cl - 1] == '/') clean[--cl] = 0;
        choose_output_name(clean, outname, sizeof outname);
    }

    /* Derive key from password. */
    unsigned char salt[crypto_pwhash_SALTBYTES];
    randombytes_buf(salt, sizeof salt);
    unsigned long long ops = crypto_pwhash_OPSLIMIT_MODERATE;
    size_t mem = crypto_pwhash_MEMLIMIT_MODERATE;
    unsigned char key[crypto_secretstream_xchacha20poly1305_KEYBYTES];
    derive_key(key, password, salt, ops, mem);

    /* Build the on-disk header (also bound into the first encrypted chunk). */
    Buf hdr; buf_init(&hdr);
    buf_append(&hdr, CZIP_MAGIC, 4);
    buf_u8(&hdr, CZIP_FORMAT);
    buf_u8(&hdr, CZIP_VER_MAJOR);
    buf_u8(&hdr, CZIP_VER_MINOR);
    buf_u8(&hdr, CZIP_VER_PATCH);
    buf_u8(&hdr, (uint8_t)ALG_XCHACHA);
    buf_u64(&hdr, ops);
    buf_u64(&hdr, mem);
    buf_append(&hdr, salt, sizeof salt);

    OutStream out;
    out_open(&out, outname, split);

    Enc e;
    memset(&e, 0, sizeof e);
    e.out = &out;
    buf_init(&e.cbuf);
    e.cctx = ZSTD_createCCtx();
    if (!e.cctx) die("zstd init failed");
    ZSTD_CCtx_setParameter(e.cctx, ZSTD_c_compressionLevel, level);
    /* nbWorkers > 0 enables multithreaded compression; ignored gracefully
     * if this libzstd was built without thread support. */
    ZSTD_CCtx_setParameter(e.cctx, ZSTD_c_nbWorkers, workers);
    e.zcap = ZSTD_CStreamOutSize();
    e.zbuf = xmalloc(e.zcap);

    /* Secretstream header goes right after our header, then the chunk stream. */
    unsigned char ss_header[crypto_secretstream_xchacha20poly1305_HEADERBYTES];
    crypto_secretstream_xchacha20poly1305_init_push(&e.st, ss_header, key);
    sodium_memzero(key, sizeof key);
    buf_append(&hdr, ss_header, sizeof ss_header);

    out_write(&out, hdr.data, hdr.len);
    /* The whole header authenticates the stream via the first chunk's AD. */
    e.ad = hdr.data;
    e.adlen = hdr.len;

    Progress prog;
    progress_init(&prog, "compressing", sum_size(input));
    e.prog = &prog;

    /* Stream: walk -> zstd -> secretstream -> output. */
    add_path(&e, input, base_name(input));
    enc_finish(&e);
    progress_draw(&prog, 1);

    out_close(&out);
    uint64_t original_size = e.plain_total;
    uint64_t output_size = out.total;

    ZSTD_freeCCtx(e.cctx);
    free(e.zbuf);
    buf_free(&e.cbuf);
    buf_free(&hdr);

    char hin[32], hout[32];
    human_size((double)original_size, hin, sizeof hin);
    human_size((double)output_size, hout, sizeof hout);
    info("czip: %s -> %s [XChaCha20-Poly1305]\n", input, outname);
    if (output_size <= original_size && original_size > 0) {
        double saved = (1.0 - (double)output_size / (double)original_size) * 100.0;
        info("czip: before %s (%llu bytes)  after %s (%llu bytes)  saved %.1f%%\n",
             hin, (unsigned long long)original_size,
             hout, (unsigned long long)output_size, saved);
    } else {
        double grew = original_size
            ? ((double)output_size / (double)original_size - 1.0) * 100.0 : 0.0;
        info("czip: before %s (%llu bytes)  after %s (%llu bytes)  grew %.1f%% (overhead)\n",
             hin, (unsigned long long)original_size,
             hout, (unsigned long long)output_size, grew);
    }
}

/* ---- decompress command ------------------------------------------------- */

static void cmd_decompress(const char *input, const char *password) {
    InStream in;
    in_open(&in, input);

    /* Fixed header prefix: magic, format, version, algo, argon params, salt. */
    const size_t PREFIX = 4 + 1 + 3 + 1 + 8 + 8 + crypto_pwhash_SALTBYTES;
    unsigned char hdr[4 + 1 + 3 + 1 + 8 + 8 + crypto_pwhash_SALTBYTES
                      + crypto_secretstream_xchacha20poly1305_HEADERBYTES];
    in_readfull(&in, hdr, PREFIX);

    size_t off = 0;
    if (memcmp(hdr, CZIP_MAGIC, 4) != 0) die("not a czip file");
    off = 4;
    uint8_t fmt = hdr[off++];
    if (fmt < CZIP_FORMAT_MIN || fmt > CZIP_FORMAT)
        die("unsupported container format");
    int has_meta = (fmt >= 3);   /* format 3 added per-entry mode + mtime */
    off += 3;                              /* writer version (informational) */
    uint8_t algo = hdr[off++];
    if (algo != ALG_XCHACHA) die("unknown cipher in header");
    uint64_t ops = rd_u64(hdr + off); off += 8;
    uint64_t mem = rd_u64(hdr + off); off += 8;
    const unsigned char *salt = hdr + off; off += crypto_pwhash_SALTBYTES;

    /* Secretstream header follows; it is part of the authenticated AD. */
    in_readfull(&in, hdr + PREFIX,
                crypto_secretstream_xchacha20poly1305_HEADERBYTES);
    const unsigned char *ss_header = hdr + PREFIX;
    size_t hdr_len = PREFIX + crypto_secretstream_xchacha20poly1305_HEADERBYTES;

    unsigned char key[crypto_secretstream_xchacha20poly1305_KEYBYTES];
    derive_key(key, password, salt, ops, mem);

    crypto_secretstream_xchacha20poly1305_state st;
    if (crypto_secretstream_xchacha20poly1305_init_pull(&st, ss_header, key) != 0) {
        sodium_memzero(key, sizeof key);
        die("corrupt container (bad stream header)");
    }
    sodium_memzero(key, sizeof key);

    ZSTD_DCtx *dctx = ZSTD_createDCtx();
    if (!dctx) die("zstd init failed");
    size_t dcap = ZSTD_DStreamOutSize();
    unsigned char *dbuf = xmalloc(dcap);

    Progress prog;
    progress_init(&prog, "extracting", 0);
    Ext ext;
    ext_init(&ext, &prog, has_meta);

    const unsigned char *ad = hdr;     /* bind header to the first chunk */
    size_t adlen = hdr_len;
    const size_t MAXCT = CZIP_CHUNK + crypto_secretstream_xchacha20poly1305_ABYTES;
    unsigned char *ct = xmalloc(MAXCT);
    unsigned char *plain = xmalloc(CZIP_CHUNK);

    int saw_final = 0;
    for (;;) {
        unsigned char lp[4];
        if (in_read(&in, lp, 4) != 4) die("corrupt or truncated container");
        uint32_t clen = rd_u32(lp);
        if (clen < crypto_secretstream_xchacha20poly1305_ABYTES || clen > MAXCT)
            die("corrupt container (bad chunk size)");
        in_readfull(&in, ct, clen);

        unsigned long long plen = 0;
        unsigned char tag = 0;
        if (crypto_secretstream_xchacha20poly1305_pull(
                &st, plain, &plen, &tag, ct, clen, ad, adlen) != 0)
            die("decryption failed: wrong password or corrupted/tampered file");
        ad = NULL; adlen = 0;

        /* Decompress this chunk and feed the archive parser. */
        ZSTD_inBuffer zin = { plain, (size_t)plen, 0 };
        while (zin.pos < zin.size) {
            ZSTD_outBuffer zout = { dbuf, dcap, 0 };
            size_t r = ZSTD_decompressStream(dctx, &zout, &zin);
            if (ZSTD_isError(r)) die(ZSTD_getErrorName(r));
            if (zout.pos) ext_feed(&ext, dbuf, zout.pos);
        }

        if (tag == crypto_secretstream_xchacha20poly1305_TAG_FINAL) {
            saw_final = 1;
            break;
        }
    }
    if (!saw_final) die("corrupt container (missing final chunk)");

    progress_draw(&prog, 1);
    ext_done(&ext);

    ZSTD_freeDCtx(dctx);
    free(dbuf); free(ct); free(plain);
    in_close(&in);
    info("czip: extracted %s\n", input);
}

/* ---- CLI ---------------------------------------------------------------- */

static void usage(void) {
    printf(
"czip " CZIP_VERSION_STR " - compress + XChaCha20-Poly1305 authenticated encryption\n\n"
"USAGE:\n"
"  czip [options] <file-or-directory>      compress & encrypt\n"
"  czip -d [options] <archive.cz>          decrypt & extract\n\n"
"OPTIONS:\n"
"  -p, --password <pw>   password (required; or set CZIP_PASSWORD env var)\n"
"  -d, --decompress      extract mode\n"
"  -l, --level <1-22>    zstd compression level (default 19)\n"
"  -T, --threads <n>     worker threads (default: all CPU cores)\n"
"      --split <MB>      split output into parts of <MB> megabytes each\n"
"  -o, --output <name>   output file name (compress mode)\n"
"  -q, --quiet           suppress informational output (for scripting)\n"
"  -h, --help            show this help\n"
"  -v, --version         show version\n\n"
"NOTES:\n"
"  Compression, encryption and writing are fully streamed, so memory use stays\n"
"  flat regardless of input size; progress is shown on stderr.\n"
"  Output extension is .cz, or .czip if a .cz file already exists.\n"
"  Split parts are named <out>.001, <out>.002, ...; extraction auto-reassembles.\n");
}

int main(int argc, char **argv) {
    if (sodium_init() < 0) die("libsodium init failed");

    const char *password = getenv("CZIP_PASSWORD");
    const char *input = NULL, *output = NULL;
    int decompress = 0, level = 19;
    int workers = (int)cpu_count();
    size_t split = 0;

    for (int i = 1; i < argc; i++) {
        const char *a = argv[i];
        if (!strcmp(a, "-h") || !strcmp(a, "--help")) { usage(); return 0; }
        else if (!strcmp(a, "-v") || !strcmp(a, "--version")) {
            printf("czip " CZIP_VERSION_STR "\n"
                   "Author: Jean-Francois Lachance-Caumartin\n"); return 0;
        }
        else if (!strcmp(a, "-d") || !strcmp(a, "--decompress")) decompress = 1;
        else if (!strcmp(a, "-q") || !strcmp(a, "--quiet")) g_quiet = 1;
        else if (!strcmp(a, "--xchacha")) { /* accepted for compatibility; always on */ }
        else if (!strcmp(a, "-p") || !strcmp(a, "--password")) {
            if (++i >= argc) die("missing value for --password");
            password = argv[i];
        }
        else if (!strcmp(a, "-l") || !strcmp(a, "--level")) {
            if (++i >= argc) die("missing value for --level");
            level = atoi(argv[i]);
            if (level < 1 || level > 22) die("level must be 1-22");
        }
        else if (!strcmp(a, "-T") || !strcmp(a, "--threads")) {
            if (++i >= argc) die("missing value for --threads");
            workers = atoi(argv[i]);
            if (workers < 0) die("threads must be >= 0");
        }
        else if (!strcmp(a, "--split")) {
            if (++i >= argc) die("missing value for --split");
            long mb = atol(argv[i]);
            if (mb <= 0) die("split size must be a positive number of MB");
            split = (size_t)mb * 1024 * 1024;
        }
        else if (!strcmp(a, "-o") || !strcmp(a, "--output")) {
            if (++i >= argc) die("missing value for --output");
            output = argv[i];
        }
        else if (a[0] == '-' && a[1]) { fprintf(stderr, "czip: unknown option %s\n", a); return 2; }
        else input = a;
    }

    if (!input) { usage(); return 2; }
    if (!password || !*password)
        die("a password is required (use -p <pw> or the CZIP_PASSWORD env var)");

    if (decompress) cmd_decompress(input, password);
    else cmd_compress(input, password, level, workers, split, output);
    return 0;
}
