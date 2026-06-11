/*
 * czip 1.0.5  —  compress + authenticated-encrypt files and directories.
 *
 * Pipeline:  plaintext archive  ->  zstd (multithreaded)  ->  AEAD encrypt
 *   - Compression : zstd, worker threads scaled to the CPU count (like 7-Zip).
 *   - Encryption  : ChaCha20-Poly1305 (IETF) by default,
 *                   XChaCha20-Poly1305 with --xchacha (bigger nonce, safer).
 *   - Key         : derived from a password with Argon2id (libsodium pwhash).
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

#include <sodium.h>
#include <zstd.h>

#define CZIP_VER_MAJOR 1
#define CZIP_VER_MINOR 0
#define CZIP_VER_PATCH 5
#define CZIP_VERSION_STR "1.0.5"

/* On-disk container header. */
static const unsigned char CZIP_MAGIC[4] = { 'C', 'Z', 'I', 'P' };
#define CZIP_FORMAT 1                 /* container format version */

#define ALG_CHACHA   0                /* crypto_aead_chacha20poly1305_ietf  */
#define ALG_XCHACHA  1                /* crypto_aead_xchacha20poly1305_ietf */

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

static void buf_u32(Buf *b, uint32_t v) {
    unsigned char t[4] = { v, v >> 8, v >> 16, v >> 24 };
    buf_append(b, t, 4);
}

static void buf_u64(Buf *b, uint64_t v) {
    unsigned char t[8];
    for (int i = 0; i < 8; i++) t[i] = (unsigned char)(v >> (8 * i));
    buf_append(b, t, 8);
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

/* ---- file IO ------------------------------------------------------------ */

static int read_whole_file(const char *path, Buf *out) {
    FILE *f = fopen(path, "rb");
    if (!f) return -1;
    unsigned char tmp[1 << 16];
    size_t n;
    while ((n = fread(tmp, 1, sizeof tmp, f)) > 0) buf_append(out, tmp, n);
    int err = ferror(f);
    fclose(f);
    return err ? -1 : 0;
}

static void write_whole_file(const char *path, const void *data, size_t n) {
    FILE *f = fopen(path, "wb");
    if (!f) die_errno("cannot open output file");
    if (n && fwrite(data, 1, n, f) != n) die_errno("write failed");
    if (fclose(f) != 0) die_errno("close failed");
}

/* ---- archive building (directory walk) ---------------------------------- */

static void add_path(Buf *ar, const char *fullpath, const char *relpath);

static void add_dir(Buf *ar, const char *fullpath, const char *relpath) {
    /* Record the directory itself so empty dirs survive. */
    buf_u8(ar, ENT_DIR);
    buf_u32(ar, (uint32_t)strlen(relpath));
    buf_append(ar, relpath, strlen(relpath));

    DIR *d = opendir(fullpath);
    if (!d) die_errno("cannot open directory");
    struct dirent *de;
    while ((de = readdir(d)) != NULL) {
        if (!strcmp(de->d_name, ".") || !strcmp(de->d_name, "..")) continue;
        char fp[PATH_MAX], rp[PATH_MAX];
        snprintf(fp, sizeof fp, "%s/%s", fullpath, de->d_name);
        snprintf(rp, sizeof rp, "%s/%s", relpath, de->d_name);
        add_path(ar, fp, rp);
    }
    closedir(d);
}

static void add_file(Buf *ar, const char *fullpath, const char *relpath) {
    Buf content; buf_init(&content);
    if (read_whole_file(fullpath, &content) != 0) die_errno("cannot read file");
    buf_u8(ar, ENT_FILE);
    buf_u32(ar, (uint32_t)strlen(relpath));
    buf_append(ar, relpath, strlen(relpath));
    buf_u64(ar, content.len);
    buf_append(ar, content.data, content.len);
    buf_free(&content);
}

static void add_link(Buf *ar, const char *fullpath, const char *relpath) {
    char target[PATH_MAX];
    ssize_t n = readlink(fullpath, target, sizeof target - 1);
    if (n < 0) die_errno("cannot read symlink");
    target[n] = 0;
    buf_u8(ar, ENT_LINK);
    buf_u32(ar, (uint32_t)strlen(relpath));
    buf_append(ar, relpath, strlen(relpath));
    buf_u64(ar, (uint64_t)n);
    buf_append(ar, target, (size_t)n);
}

static void add_path(Buf *ar, const char *fullpath, const char *relpath) {
    struct stat st;
    if (lstat(fullpath, &st) != 0) die_errno("cannot stat path");
    if (S_ISLNK(st.st_mode))       add_link(ar, fullpath, relpath);
    else if (S_ISDIR(st.st_mode))  add_dir(ar, fullpath, relpath);
    else if (S_ISREG(st.st_mode))  add_file(ar, fullpath, relpath);
    else fprintf(stderr, "czip: skipping special file %s\n", relpath);
}

/* basename without trailing slash, for the archive root name. */
static const char *base_name(const char *path) {
    const char *b = path, *p;
    for (p = path; *p; p++) if (*p == '/' && p[1]) b = p + 1;
    return b;
}

/* ---- archive extraction ------------------------------------------------- */

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

static void extract_archive(const unsigned char *ar, size_t len) {
    size_t off = 0;
    while (off < len) {
        uint8_t type = ar[off++];
        if (len - off < 4) die("corrupt archive");
        uint32_t nlen = rd_u32(ar + off); off += 4;
        if (nlen > len - off) die("corrupt archive");
        char path[PATH_MAX];
        if (nlen >= sizeof path) die("path too long");
        memcpy(path, ar + off, nlen); path[nlen] = 0; off += nlen;

        /* Reject path traversal and empty names. */
        if (nlen == 0) die("corrupt archive (empty path)");
        if (path[0] == '/' || strstr(path, "..")) die("unsafe path in archive");

        if (type == ENT_DIR) {
            mkdirs(path);
        } else if (type == ENT_FILE || type == ENT_LINK) {
            if (len - off < 8) die("corrupt archive");
            uint64_t fsz = rd_u64(ar + off); off += 8;
            if (fsz > len - off) die("corrupt archive");
            parent_dirs(path);
            if (type == ENT_FILE) {
                unlink(path);   /* never write through a pre-existing symlink */
                write_whole_file(path, ar + off, (size_t)fsz);
            } else if (fsz == 0) {
                fprintf(stderr, "czip: skipping symlink with empty target %s\n", path);
            } else {
                if (fsz >= PATH_MAX) die("symlink target too long");
                char target[PATH_MAX];
                memcpy(target, ar + off, (size_t)fsz);
                target[fsz] = 0;
                /* Skip absolute or traversing targets: never create a link
                 * that escapes the tree, so later writes can't follow one
                 * out. Skip-and-warn rather than abort the whole extraction. */
                if (target[0] == '/' || strstr(target, "..")) {
                    fprintf(stderr,
                        "czip: skipping unsafe symlink %s -> %s\n", path, target);
                } else {
                    unlink(path);   /* replace any existing entry */
                    if (symlink(target, path) != 0)
                        die_errno("cannot create symlink");
                }
            }
            off += fsz;
        } else {
            die("corrupt archive (bad entry type)");
        }
    }
}

/* ---- compression (multithreaded zstd) ----------------------------------- */

static long cpu_count(void) {
    long n = sysconf(_SC_NPROCESSORS_ONLN);
    return n > 0 ? n : 1;
}

static void zstd_compress(const Buf *in, Buf *out, int level, int workers) {
    ZSTD_CCtx *c = ZSTD_createCCtx();
    if (!c) die("zstd init failed");
    ZSTD_CCtx_setParameter(c, ZSTD_c_compressionLevel, level);
    /* nbWorkers > 0 enables multithreaded compression; ignored gracefully
     * if this libzstd was built without thread support. */
    ZSTD_CCtx_setParameter(c, ZSTD_c_nbWorkers, workers);

    size_t bound = ZSTD_compressBound(in->len);
    buf_reserve(out, bound);
    size_t r = ZSTD_compress2(c, out->data + out->len, bound, in->data, in->len);
    if (ZSTD_isError(r)) die(ZSTD_getErrorName(r));
    out->len += r;
    ZSTD_freeCCtx(c);
}

static void zstd_decompress(const unsigned char *in, size_t inlen, Buf *out) {
    unsigned long long sz = ZSTD_getFrameContentSize(in, inlen);
    if (sz == ZSTD_CONTENTSIZE_ERROR || sz == ZSTD_CONTENTSIZE_UNKNOWN)
        die("not a valid zstd stream");
    buf_reserve(out, (size_t)sz);
    size_t r = ZSTD_decompress(out->data, (size_t)sz, in, inlen);
    if (ZSTD_isError(r)) die(ZSTD_getErrorName(r));
    out->len += r;
}

/* ---- key derivation ----------------------------------------------------- */

static void derive_key(unsigned char *key, const char *password,
                       const unsigned char *salt,
                       unsigned long long ops, size_t mem) {
    if (crypto_pwhash(key, crypto_aead_xchacha20poly1305_ietf_KEYBYTES,
                      password, strlen(password), salt, ops, mem,
                      crypto_pwhash_ALG_ARGON2ID13) != 0)
        die("key derivation failed (out of memory?)");
}

/* ---- output naming and splitting ---------------------------------------- */

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

/* Pick "<base>.cz", or "<base>.czip" if the .cz already exists. */
static void choose_output_name(const char *base, char *out, size_t outsz) {
    snprintf(out, outsz, "%s.cz", base);
    if (file_exists(out)) snprintf(out, outsz, "%s.czip", base);
}

/* Write the blob as one file, or as <name>.001/.002/... if split > 0 bytes. */
static void write_output(const char *name, const unsigned char *data,
                         size_t len, size_t split) {
    if (split == 0 || len <= split) {
        write_whole_file(name, data, len);
        info("czip: wrote %s (%zu bytes)\n", name, len);
        return;
    }
    size_t parts = (len + split - 1) / split;
    for (size_t i = 0; i < parts; i++) {
        char part[PATH_MAX + 32];
        snprintf(part, sizeof part, "%s.%03zu", name, i + 1);
        size_t chunk = (i + 1 == parts) ? len - i * split : split;
        write_whole_file(part, data + i * split, chunk);
        info("czip: wrote %s (%zu bytes)\n", part, chunk);
    }
    info("czip: split into %zu parts\n", parts);
}

/* Load a container: either <name> directly, or reassemble <name>.001.. parts.
 * Accepts being given the base name or a ".001" part name. */
static void read_container(const char *name, Buf *out) {
    if (file_exists(name)) {
        /* Did the user hand us the first part directly? */
        size_t n = strlen(name);
        if (n > 4 && name[n - 4] == '.' &&
            name[n-3] >= '0' && name[n-3] <= '9' &&
            name[n-2] >= '0' && name[n-2] <= '9' &&
            name[n-1] >= '0' && name[n-1] <= '9') {
            char base[PATH_MAX];
            snprintf(base, sizeof base, "%.*s", (int)(n - 4), name);
            if (file_exists(name)) { read_container(base, out); return; }
        }
        if (read_whole_file(name, out) != 0) die_errno("cannot read input");
        return;
    }
    /* Try split parts <name>.001, .002, ... */
    char part[PATH_MAX + 32];
    snprintf(part, sizeof part, "%s.001", name);
    if (!file_exists(part)) die("input file not found");
    for (size_t i = 1; ; i++) {
        snprintf(part, sizeof part, "%s.%03zu", name, i);
        if (!file_exists(part)) break;
        if (read_whole_file(part, out) != 0) die_errno("cannot read part");
    }
}

/* ---- compress command --------------------------------------------------- */

static void cmd_compress(const char *input, const char *password,
                         int algo, int level, int workers, size_t split,
                         const char *out_override) {
    struct stat st;
    if (lstat(input, &st) != 0) die_errno("input path not found");

    /* 1. Build plaintext archive. */
    Buf archive; buf_init(&archive);
    add_path(&archive, input, base_name(input));
    size_t original_size = archive.len;

    /* 2. Compress. */
    Buf comp; buf_init(&comp);
    zstd_compress(&archive, &comp, level, workers);
    buf_free(&archive);

    /* 3. Derive key from password. */
    unsigned char salt[crypto_pwhash_SALTBYTES];
    randombytes_buf(salt, sizeof salt);
    unsigned long long ops = crypto_pwhash_OPSLIMIT_MODERATE;
    size_t mem = crypto_pwhash_MEMLIMIT_MODERATE;
    unsigned char key[crypto_aead_xchacha20poly1305_ietf_KEYBYTES];
    derive_key(key, password, salt, ops, mem);

    /* 4. Encrypt. */
    size_t npub = (algo == ALG_XCHACHA)
        ? crypto_aead_xchacha20poly1305_ietf_NPUBBYTES
        : crypto_aead_chacha20poly1305_ietf_NPUBBYTES;
    unsigned char nonce[crypto_aead_xchacha20poly1305_ietf_NPUBBYTES];
    randombytes_buf(nonce, npub);

    /* Build the on-disk container: header (authenticated as AD) + ciphertext. */
    Buf hdr; buf_init(&hdr);
    buf_append(&hdr, CZIP_MAGIC, 4);
    buf_u8(&hdr, CZIP_FORMAT);
    buf_u8(&hdr, CZIP_VER_MAJOR);
    buf_u8(&hdr, CZIP_VER_MINOR);
    buf_u8(&hdr, CZIP_VER_PATCH);
    buf_u8(&hdr, (uint8_t)algo);
    buf_u64(&hdr, ops);
    buf_u64(&hdr, mem);
    buf_append(&hdr, salt, sizeof salt);
    buf_u8(&hdr, (uint8_t)npub);
    buf_append(&hdr, nonce, npub);

    unsigned char *ct = xmalloc(comp.len + crypto_aead_xchacha20poly1305_ietf_ABYTES);
    unsigned long long ct_len = 0;
    if (algo == ALG_XCHACHA) {
        crypto_aead_xchacha20poly1305_ietf_encrypt(
            ct, &ct_len, comp.data, comp.len,
            hdr.data, hdr.len, NULL, nonce, key);
    } else {
        crypto_aead_chacha20poly1305_ietf_encrypt(
            ct, &ct_len, comp.data, comp.len,
            hdr.data, hdr.len, NULL, nonce, key);
    }
    sodium_memzero(key, sizeof key);
    buf_free(&comp);

    Buf container; buf_init(&container);
    buf_append(&container, hdr.data, hdr.len);
    buf_u64(&container, ct_len);
    buf_append(&container, ct, ct_len);
    buf_free(&hdr);
    free(ct);

    /* 5. Name + write (with optional splitting). */
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

    size_t output_size = container.len;
    write_output(outname, container.data, container.len, split);
    buf_free(&container);

    char hin[32], hout[32];
    human_size((double)original_size, hin, sizeof hin);
    human_size((double)output_size, hout, sizeof hout);
    info("czip: %s -> %s [%s]\n", input, outname,
           algo == ALG_XCHACHA ? "XChaCha20-Poly1305" : "ChaCha20-Poly1305");
    if (output_size <= original_size && original_size > 0) {
        double saved = (1.0 - (double)output_size / original_size) * 100.0;
        info("czip: before %s (%zu bytes)  after %s (%zu bytes)  saved %.1f%%\n",
             hin, original_size, hout, output_size, saved);
    } else {
        /* Incompressible or tiny input: crypto/header overhead dominates. */
        double grew = original_size
            ? ((double)output_size / original_size - 1.0) * 100.0 : 0.0;
        info("czip: before %s (%zu bytes)  after %s (%zu bytes)  grew %.1f%% (overhead)\n",
             hin, original_size, hout, output_size, grew);
    }
}

/* ---- decompress command ------------------------------------------------- */

static void cmd_decompress(const char *input, const char *password) {
    Buf c; buf_init(&c);
    read_container(input, &c);

    const unsigned char *p = c.data;
    size_t len = c.len, off = 0;

    /* Fixed-size header prefix up to and including the npub-length byte. */
    const size_t FIXED = 4 + 1 + 3 + 1 + 8 + 8 + crypto_pwhash_SALTBYTES + 1;
    if (len < FIXED) die("not a czip file (too short)");
    if (memcmp(p, CZIP_MAGIC, 4) != 0) die("not a czip file");
    off = 4;
    uint8_t fmt   = p[off++];
    if (fmt != CZIP_FORMAT) die("unsupported container format");
    off += 3;                              /* writer version (informational) */
    uint8_t algo  = p[off++];
    if (algo != ALG_CHACHA && algo != ALG_XCHACHA) die("unknown cipher in header");
    uint64_t ops  = rd_u64(p + off); off += 8;
    uint64_t mem  = rd_u64(p + off); off += 8;
    const unsigned char *salt = p + off; off += crypto_pwhash_SALTBYTES;
    uint8_t npub  = p[off++];

    /* npub must match the cipher; reject anything else before using it. */
    size_t expect_npub = (algo == ALG_XCHACHA)
        ? crypto_aead_xchacha20poly1305_ietf_NPUBBYTES
        : crypto_aead_chacha20poly1305_ietf_NPUBBYTES;
    if (npub != expect_npub) die("corrupt header (nonce size mismatch)");
    if (len - off < (size_t)npub + 8) die("corrupt or truncated container");
    const unsigned char *nonce = p + off; off += npub;

    size_t hdr_len = off;                  /* header was the AD */
    uint64_t ct_len = rd_u64(p + off); off += 8;
    const unsigned char *ct = p + off;
    if (ct_len > len - off) die("corrupt or truncated container");
    if (ct_len < crypto_aead_chacha20poly1305_ietf_ABYTES)
        die("corrupt container (ciphertext too short)");

    unsigned char key[crypto_aead_xchacha20poly1305_ietf_KEYBYTES];
    derive_key(key, password, salt, ops, mem);

    Buf comp; buf_init(&comp);
    buf_reserve(&comp, ct_len);
    unsigned long long out_len = 0;
    int ok;
    if (algo == ALG_XCHACHA) {
        ok = crypto_aead_xchacha20poly1305_ietf_decrypt(
            comp.data, &out_len, NULL, ct, ct_len,
            p, hdr_len, nonce, key);
    } else {
        ok = crypto_aead_chacha20poly1305_ietf_decrypt(
            comp.data, &out_len, NULL, ct, ct_len,
            p, hdr_len, nonce, key);
    }
    sodium_memzero(key, sizeof key);
    if (ok != 0) die("decryption failed: wrong password or corrupted/tampered file");
    comp.len = out_len;

    Buf archive; buf_init(&archive);
    zstd_decompress(comp.data, comp.len, &archive);
    buf_free(&comp);

    extract_archive(archive.data, archive.len);
    info("czip: extracted %s\n", input);
    buf_free(&archive);
    buf_free(&c);
}

/* ---- CLI ---------------------------------------------------------------- */

static void usage(void) {
    printf(
"czip " CZIP_VERSION_STR " - compress + ChaCha20-Poly1305 authenticated encryption\n\n"
"USAGE:\n"
"  czip [options] <file-or-directory>      compress & encrypt\n"
"  czip -d [options] <archive.cz>          decrypt & extract\n\n"
"OPTIONS:\n"
"  -p, --password <pw>   password (required; or set CZIP_PASSWORD env var)\n"
"  -d, --decompress      extract mode\n"
"      --xchacha         use XChaCha20-Poly1305 (24-byte nonce, safer)\n"
"  -l, --level <1-22>    zstd compression level (default 19)\n"
"  -T, --threads <n>     worker threads (default: all CPU cores)\n"
"      --split <MB>      split output into parts of <MB> megabytes each\n"
"  -o, --output <name>   output file name (compress mode)\n"
"  -q, --quiet           suppress informational output (for scripting)\n"
"  -h, --help            show this help\n"
"  -v, --version         show version\n\n"
"NOTES:\n"
"  Output extension is .cz, or .czip if a .cz file already exists.\n"
"  Split parts are named <out>.001, <out>.002, ...; extraction auto-reassembles.\n");
}

int main(int argc, char **argv) {
    if (sodium_init() < 0) die("libsodium init failed");

    const char *password = getenv("CZIP_PASSWORD");
    const char *input = NULL, *output = NULL;
    int decompress = 0, algo = ALG_CHACHA, level = 19;
    int workers = (int)cpu_count();
    size_t split = 0;

    for (int i = 1; i < argc; i++) {
        const char *a = argv[i];
        if (!strcmp(a, "-h") || !strcmp(a, "--help")) { usage(); return 0; }
        else if (!strcmp(a, "-v") || !strcmp(a, "--version")) {
            printf("czip " CZIP_VERSION_STR "\n"); return 0;
        }
        else if (!strcmp(a, "-d") || !strcmp(a, "--decompress")) decompress = 1;
        else if (!strcmp(a, "-q") || !strcmp(a, "--quiet")) g_quiet = 1;
        else if (!strcmp(a, "--xchacha")) algo = ALG_XCHACHA;
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
    else cmd_compress(input, password, algo, level, workers, split, output);
    return 0;
}
