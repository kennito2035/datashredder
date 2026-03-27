# DataShredder v3.0.0

A full-featured Java Swing file and directory shredder with cryptographic erase, filename scrubbing, metadata scrubbing, dark-mode theming, and live ETA. Requires Java 11 or later.

---

## Features

- **Six shred algorithms** including ChaCha20 cryptographic erase (see table below)
- **Filename scrubbing** — renames each file three times to random names before deletion to frustrate directory-entry recovery
- **Metadata scrubbing** — resets all file timestamps to Unix epoch (1970-01-01) before deletion
- **Directory support** — recursively expands folders; removes empty parent directories deepest-first after all files are shredded
- **Dark mode theming** — full dark colour palette applied via `UIManager`; hardcoded `true` with a comment explaining how to wire automatic OS detection
- **Transient progress messages** — per-file status flashes for 2.5 s then reverts to ETA display using a non-repeating `javax.swing.Timer`
- **Progress bar colour feedback** — green during shredding, red on cancel, grey when idle
- **Spinner input validation** — `NumberFormatter.setAllowsInvalid(false)` prevents non-numeric input
- **1 MB write buffer** — 16× larger than v1/v2 for higher throughput on modern drives
- **Cancel button** with confirmation dialog and visual reset
- **Live ETA** displayed as `XX% — HH:MM:SS remaining…`
- **File locking** via `FileChannel.tryLock()` — refuses to shred files held by another process
- **Safe-close guard** — confirms exit while shredding is in progress
- **Global uncaught-exception handler** — unexpected crashes surface a dialog

---

## Algorithms

| Algorithm | Passes | Description |
|---|---|---|
| **RANDOM** | 1 – 100 (configurable) | Cryptographically random data via `SecureRandom` |
| **DOD3** | 3 (fixed) | DoD 5220.22-M: zeros → ones → random |
| **GUTMANN** | 35 (fixed) | Gutmann method — all 35 patterns in paper order |
| **ZERO** | 1 (fixed) | Single zero-fill pass with byte-level verification |
| **NVME_PURGE** | 4 (fixed) | NIST SP 800-88 inspired: random key → complement → random → zeros + verification |
| **CRYPTO_ERASE** | 1 (fixed) | ChaCha20 in-place encryption; 256-bit key and 96-bit nonce discarded immediately after use — content becomes computationally unrecoverable without the key |

> **CRYPTO_ERASE behaviour:** The encrypted file is left on disk (content unrecoverable); standard deletion is skipped. The key and nonce are zeroed in a `finally` block to prevent heap retention.

> **Note on Gutmann:** Pattern order is deterministic as the paper specifies. Shuffling defeats the algorithm and was deliberately removed.

---

## Requirements

| Requirement | Version |
|---|---|
| Java | **11 or later** (ChaCha20 cipher requires JDK 11+) |
| External libraries | None |

---

## How to Build & Run

```bash
# Compile
javac DataShredderV3.java

# Run
java DataShredderV3
```

---

## Usage

1. Launch the application (dark theme active by default).
2. Select an **Algorithm** from the drop-down. The pass count updates automatically.
3. For RANDOM mode, adjust the **Passes** spinner (only numeric input accepted).
4. Click **Browse Files/Dirs** and choose files or directories (symbolic links are excluded).
5. Click **Secure Shred** and confirm the warning dialog.
6. Watch the progress bar (colour = green, label = `X% — HH:MM:SS remaining…`).
7. Per-file "Obliterated: …" / "Encrypted: …" flashes appear briefly, then ETA resumes.
8. On completion a result dialog summarises successes and any issues.

> **Warning:** Shredding is irreversible. Files and directories cannot be recovered after this operation.

---

## Algorithm Detail

### Overwrite primitives

| Primitive | Behaviour |
|---|---|
| `overwriteRandom` | Fills file with `SecureRandom` bytes; calls `fd.sync()` |
| `overwritePattern` | Fills file with a repeating single byte; calls `fd.sync()` |
| `overwriteCustomPattern` | Tiles an arbitrary byte array across the file; calls `fd.sync()` |
| `performCryptoErase` | Reads file in chunks, encrypts in-place with ChaCha20, writes back; key+nonce zeroed in `finally` |

### Filename & metadata scrubbing

- **`scrubFilename()`** — performs 3 sequential `Files.move()` renames to random names (`ATOMIC_MOVE` with non-atomic fallback). This overwrites the directory entry multiple times to frustrate inode-level recovery.
- **`scrubMetadata()`** — sets creation, modification, and access times to `FileTime.fromMillis(0)` via `BasicFileAttributeView`.

### Directory deletion

`collectDirectories()` enumerates all sub-directories and sorts them by absolute-path length descending (deepest first), ensuring child directories are removed before their parents can be.

### Deletion strategy

1. Set the file writable (`file.setWritable(true)`).
2. Try `Files.deleteIfExists` up to 3 times with 200 ms delays.
3. If all attempts fail, report the error (no `deleteOnExit` fallback unlike v2).

---

## Architecture

```
DataShredderV3 (JFrame)
├── Algorithm enum       — ShredAlgorithm (6 values, display name, zero-verify flag)
├── Dark mode            — isDarkModeEnabled() + UIManager palette applied in main()
├── UI setup             — GridBagLayout, validated spinner, colour-coded progress bar
├── File selection       — JFileChooser (FILES_AND_DIRECTORIES, symlink-filtered)
├── Directory expansion  — collectFiles() / collectDirectories() via Files.walk()
├── Orchestration        — startShreddingProcess() → new Thread(runShredding)
├── Shred dispatch       — shredFile() acquires FileLock, dispatches algorithm
├── Overwrite methods    — overwriteRandom / overwritePattern / overwriteCustomPattern
├── Algorithm methods    — overwriteDoD3 / overwriteGutmann / overwriteNVMePurge
├── Crypto erase         — performCryptoErase() (ChaCha20 via JCA)
├── Verification         — verifyZeroFill() (ZERO and NVME_PURGE only)
├── Scrubbing            — scrubFilename() × 3 renames + scrubMetadata() epoch reset
├── Deletion             — deleteFilePermanently() with 3-retry strategy
└── Progress & timers    — recordProgress() synchronized; showTransientMessage() non-repeating Timer
```

All UI updates from the background thread are marshalled through `SwingUtilities.invokeLater`.

---

## Key Constants

| Constant | Value | Purpose |
|---|---|---|
| `BUFFER_SIZE` | 1 048 576 bytes (1 MB) | Write chunk size — 16× larger than v1/v2 |
| `DEFAULT_PASSES` | 3 | Pre-filled spinner value for RANDOM mode |

---

## Limitations

- **Dark mode is hardcoded on.** Replace `isDarkModeEnabled()` body with `OsThemeDetector.getDetector().isDark()` (plus the `com.jthemedetecor` dependency) for automatic OS-level detection.
- **CRYPTO_ERASE leaves the file on disk.** Its content is computationally unrecoverable, but directory metadata (name, size, path) persists. Run a second pass with a destructive algorithm if directory-entry privacy is also required.
- **SSD caveat** — software overwrite cannot guarantee physical erasure on SSDs with wear leveling or out-of-band spare sectors. Use firmware-level commands (ATA Secure Erase / NVMe Format NVM) for those.
- **Timestamp scrubbing is best-effort** — some file systems or OS configurations restrict timestamp modification; `scrubMetadata()` silently ignores failures.
- **Java 11 minimum** — the ChaCha20 cipher is not available in Java 8 or 9. If ChaCha20 support is not needed, `CRYPTO_ERASE` can be removed and the minimum drops back to Java 8.


