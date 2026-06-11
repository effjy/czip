# czip

[![Release](https://img.shields.io/github/v/release/effjy/czip?sort=semver)](https://github.com/effjy/czip/releases)
[![License](https://img.shields.io/github/license/effjy/czip)](https://github.com/effjy/czip/blob/main/LICENSE)
[![Language](https://img.shields.io/badge/language-C-blue.svg)](https://github.com/effjy/czip)
[![Crypto](https://img.shields.io/badge/crypto-ChaCha20--Poly1305-green.svg)](https://doc.libsodium.org/secret-key_cryptography/aead)
[![Compression](https://img.shields.io/badge/compression-zstd-orange.svg)](https://facebook.github.io/zstd/)
[![Platform](https://img.shields.io/badge/platform-Linux%20%7C%20macOS-lightgrey.svg)](https://github.com/effjy/czip)

**czip** compresses **and** authenticated-encrypts files or directories in a single
step. It is the first archiver to combine [zstd](https://facebook.github.io/zstd/)
multithreaded compression with **ChaCha20-Poly1305** / **XChaCha20-Poly1305**
authenticated encryption.

- 🗜️ **Compression** — zstd, with worker threads scaled to your CPU core count
  automatically (just like 7-Zip).
- 🔐 **Encryption** — ChaCha20-Poly1305 (IETF) by default, or XChaCha20-Poly1305 with
  `--xchacha` for a 24-byte random nonce (safer when you produce a huge number of
  archives).
- 🔑 **Key derivation** — your password is turned into a key with Argon2id, a
  memory-hard function that resists brute force.
- ✂️ **Splitting** — break the output into equal-sized parts you choose, in MB.
- 📊 **Stats** — prints total size before and after compression, with the savings.

Data is **compressed first, then encrypted** — the only correct order, because
ciphertext is indistinguishable from random noise and cannot be compressed afterward.

---

## Table of contents

- [Prerequisites](#prerequisites)
- [Build & install](#build--install)
- [Uninstall](#uninstall)
- [Usage](#usage)
  - [Compress a file](#compress-a-file)
  - [Compress a directory](#compress-a-directory)
  - [Extract](#extract)
  - [Choosing the cipher](#choosing-the-cipher)
  - [Compression level](#compression-level)
  - [Threads](#threads)
  - [Splitting into parts](#splitting-into-parts)
  - [Passwords without shell history](#passwords-without-shell-history)
  - [Quiet mode for scripting](#quiet-mode-for-scripting)
  - [Output naming rules](#output-naming-rules)
- [Command reference](#command-reference)
- [How it works](#how-it-works)
- [Security notes](#security-notes)
- [Container format](#container-format-v1)

---

## Prerequisites

czip needs a C compiler plus the **libsodium** and **libzstd** development headers.

**Debian / Ubuntu**

```sh
sudo apt update
sudo apt install build-essential libsodium-dev libzstd-dev
```

**Fedora / RHEL**

```sh
sudo dnf install gcc make libsodium-devel libzstd-devel
```

**Arch Linux**

```sh
sudo pacman -S base-devel libsodium zstd
```

**macOS** (Homebrew)

```sh
brew install libsodium zstd
```

---

## Build & install

```sh
git clone https://github.com/effjy/czip.git
cd czip
make
sudo make install        # installs the binary to /usr/local/bin/czip
```

Install to a different prefix if you like:

```sh
sudo make install PREFIX=/usr          # -> /usr/bin/czip
make install PREFIX=$HOME/.local       # no sudo needed for a user prefix
```

Verify:

```sh
czip --version
# czip 1.0.5
```

## Uninstall

```sh
sudo make uninstall                    # removes /usr/local/bin/czip
sudo make uninstall PREFIX=/usr        # match the prefix you installed with
```

---

## Usage

```
czip [options] <file-or-directory>      compress & encrypt
czip -d [options] <archive.cz>          decrypt & extract
```

### Compress a file

```sh
czip -p 'my secret pw' report.pdf
```

Output:

```
czip: wrote report.pdf.cz (1.85 MB)
czip: report.pdf -> report.pdf.cz [ChaCha20-Poly1305]
czip: before 4.20 MB (4404019 bytes)  after 1.85 MB (1939276 bytes)  ratio 44.0% (saved 56.0%)
```

### Compress a directory

Directories are archived recursively — subfolders and even empty folders are
preserved.

```sh
czip -p 'my secret pw' ~/Photos
# -> Photos.cz
```

### Extract

Use `-d`. Files are restored relative to the current directory, so `cd` to where you
want them first.

```sh
mkdir restored && cd restored
czip -d -p 'my secret pw' ../Photos.cz
```

A wrong password or any tampering is detected and refused — czip never writes
unverified data:

```
czip: decryption failed: wrong password or corrupted/tampered file
```

### Choosing the cipher

Default is **ChaCha20-Poly1305**. Add `--xchacha` for **XChaCha20-Poly1305**, which
uses a larger 24-byte random nonce — recommended if you generate very large numbers
of archives with the same password.

```sh
czip --xchacha -p 'my secret pw' backup/
```

### Compression level

zstd levels run from `1` (fastest) to `22` (smallest). Default is `19`.

```sh
czip -l 22 -p pw bigdata/       # maximum compression
czip -l 3  -p pw bigdata/       # fast, lighter compression
```

### Threads

By default czip uses **all available CPU cores**. Pin it to a specific count with
`-T`:

```sh
czip -T 4 -p pw bigdata/        # use 4 worker threads
czip -T 1 -p pw bigdata/        # single-threaded
```

### Splitting into parts

Use `--split <MB>` to break the output into equal-sized parts (the last part holds
the remainder). Handy for size-limited media or uploads.

```sh
czip --split 100 -p pw movie.mkv
# czip: wrote movie.mkv.cz.001 (104857600 bytes)
# czip: wrote movie.mkv.cz.002 (104857600 bytes)
# czip: wrote movie.mkv.cz.003 (51211840 bytes)
# czip: split into 3 parts
```

Extraction **auto-reassembles** the parts. Point it at either the base name or the
first part — both work:

```sh
czip -d -p pw movie.mkv.cz          # base name
czip -d -p pw movie.mkv.cz.001      # first part
```

### Passwords without shell history

Anything you type after `-p` lands in your shell history. To avoid that, set the
`CZIP_PASSWORD` environment variable instead:

```sh
read -rs CZIP_PASSWORD            # prompts silently
export CZIP_PASSWORD
czip secret_folder/
czip -d secret_folder.cz
```

### Quiet mode for scripting

Pass `-q` (or `--quiet`) to suppress all informational output. czip prints nothing on
success and only writes real errors to stderr, so it behaves well in scripts and
pipelines. The exit code is `0` on success and non-zero on failure.

```sh
if czip -q -p "$CZIP_PASSWORD" ~/Documents; then
    echo "backup ok"
else
    echo "backup failed" >&2
fi
```

```sh
czip -q -p pw backup/          # no output, exit 0 on success
czip -d -q -p pw backup.cz     # silent extract
```

### Output naming rules

- The archive extension is **`.cz`**.
- If a file with that `.cz` name already exists, czip uses **`.czip`** instead, so it
  never silently overwrites your data.
- Override the name entirely with `-o`:

  ```sh
  czip -p pw -o my-backup.cz ~/Documents
  ```

---

## Command reference

| Option | Description |
| --- | --- |
| `-p`, `--password <pw>` | Password (required, or set `CZIP_PASSWORD`). |
| `-d`, `--decompress` | Extract mode. |
| `--xchacha` | Use XChaCha20-Poly1305 (24-byte nonce) instead of ChaCha20-Poly1305. |
| `-l`, `--level <1-22>` | zstd compression level (default `19`). |
| `-T`, `--threads <n>` | Worker threads (default: all CPU cores). |
| `--split <MB>` | Split output into parts of `<MB>` megabytes each. |
| `-o`, `--output <name>` | Output file name (compress mode). |
| `-q`, `--quiet` | Suppress informational output (for scripting). |
| `-h`, `--help` | Show help. |
| `-v`, `--version` | Show version. |

---

## How it works

```
            ┌───────────┐     ┌──────────────┐     ┌────────────────────────┐
  files/    │  archive  │ --> │ zstd compress│ --> │ ChaCha20/XChaCha20      │ --> .cz
  directory │ (in-mem)  │     │ (multithread)│     │ Poly1305 AEAD encrypt   │
            └───────────┘     └──────────────┘     └────────────────────────┘
                                                          ▲
                                              Argon2id( your password + salt )
```

## Security notes

- Each archive embeds the Argon2 **salt**, the AEAD **nonce**, and the KDF
  parameters in an authenticated header, so the file is self-describing and
  tamper-evident.
- The header is authenticated as associated data; any modification to the file fails
  the Poly1305 tag check and is rejected.
- Keys are wiped from memory with `sodium_memzero` after use.
- Extraction rejects absolute paths and `..` components, preventing zip-slip path
  traversal.
- Symbolic links are archived and restored, but on extraction any link whose target
  is absolute or escapes the archive (`..`) is skipped with a warning, so a hostile
  archive cannot redirect writes outside the destination directory.

> **Note:** czip currently holds the archive in memory during processing, so a single
> archive must fit in available RAM. Streaming support for very large files is planned.

## Container format (v1)

```
"CZIP" | fmt(1) | version major/minor/patch(3) | algo(1)
opslimit(8) | memlimit(8) | salt(16) | nonce_len(1) | nonce(12 or 24)
ciphertext_len(8) | ciphertext (zstd-compressed archive + 16-byte Poly1305 tag)
```

The header is authenticated as associated data; the ciphertext is the AEAD-sealed,
zstd-compressed archive stream.

---

## License

See [LICENSE](https://github.com/effjy/czip/blob/main/LICENSE).
