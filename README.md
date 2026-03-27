# DataShredder v2.0.0

A multi-algorithm Java Swing file and directory shredder with cancellation support, live ETA tracking, and file-locking to prevent concurrent access.

---

## Features

- **Five shred algorithms** selectable from a drop-down (see table below)
- **Directory support** — recursively expands folders into constituent files
- **Cancel button** with confirmation dialog
- **Live ETA** displayed in the progress bar (`XX% — HH:MM:SS remaining`)
- **File locking** via `FileChannel.tryLock()` — refuses to shred files open in another process
- **Correct zero-fill verification** for algorithms that end with a zero pass (ZERO, NVME_PURGE)
- **Global uncaught-exception handler** — unexpected crashes surface a dialog instead of silently exiting
- **Safe-close guard** — warns before exiting while shredding is in progress

---

## Algorithms

| Algorithm | Passes | Description |
|---|---|---|
| **RANDOM** | 1 – 100 (configurable) | Cryptographically random data via `SecureRandom` |
| **DOD3** | 3 (fixed) | DoD 5220.22-M: zeros → ones → random |
| **GUTMANN** | 35 (fixed) | Gutmann method with all 35 deterministic patterns in paper order |
| **ZERO** | 1 (fixed) | Single zero-fill pass followed by byte-level verification |
| **NVME_PURGE** | 4 (fixed) | NIST SP 800-88 inspired: random key pattern → complement → random → zeros + verification |

> **Note on Gutmann:** Patterns are applied in the original deterministic order specified by the paper. Shuffling the patterns (a common mistake) defeats the algorithm.

> **Note on DoD3:** Correct order is zeros → ones → random. Inverted orderings seen in other implementations are incorrect.

---

## Requirements

| Requirement | Version |
|---|---|
| Java | 8 or later |
| External libraries | None |

---

## How to Build & Run

```bash
# Compile
javac DataShredderV2.java

# Run
java DataShredderV2
```

---

## Usage

1. Launch the application.
2. Select an **Algorithm** from the drop-down. The pass count updates automatically for fixed-pass algorithms.
3. For RANDOM mode, adjust the **Passes** spinner as needed.
4. Click **Browse Files/Dirs** and select one or more files or directories.
5. Click **Secure Shred** and confirm the warning dialog.
6. Monitor progress via the progress bar (percentage + ETA).
7. Use **Cancel** at any time to abort; already-shredded files are not restored.

> **Warning:** Shredding is irreversible. Files and directories cannot be recovered after this operation.

---

## Algorithm Detail

### Overwrite primitives

| Primitive | Behaviour |
|---|---|
| `overwriteRandom` | Fills file with `SecureRandom` bytes; calls `fd.sync()` after each pass |
| `overwritePattern` | Fills file with a repeating single byte; calls `fd.sync()` |
| `overwriteCustomPattern` | Fills file by tiling an arbitrary byte array; calls `fd.sync()` |

### Deletion strategy

1. Try `Files.deleteIfExists` up to 3 times with 200 ms delays between attempts.
2. If all attempts fail, rename the file to a random name and schedule `deleteOnExit()`.

### Directory handling

`collectFiles()` uses `Files.walk()` in a try-with-resources block to recursively enumerate regular files while skipping symbolic links. Directories themselves are not explicitly deleted in this version.

---

## Architecture

```
DataShredderV2 (JFrame)
├── Algorithm enum      — ShredAlgorithm (5 values, display name, zero-verify flag)
├── UI setup            — GridBagLayout, algorithm combo, passes spinner, 3 buttons, progress bar
├── File selection      — JFileChooser (FILES_AND_DIRECTORIES, multi-select)
├── Directory expansion — collectFiles() via Files.walk()
├── Orchestration       — startShreddingProcess() → new Thread(runShredding)
├── Shred dispatch      — shredFile() acquires FileLock then dispatches to algorithm method
├── Overwrite methods   — overwriteRandom / overwritePattern / overwriteCustomPattern
├── Algorithm methods   — overwriteDoD3 / overwriteGutmann / overwriteNVMePurge
├── Verification        — verifyZeroFill() (ZERO and NVME_PURGE only)
├── Deletion            — deleteFilePermanently() with 3-retry + rename fallback
└── Progress            — recordProgress() synchronized; formatTime() for ETA
```

All UI updates from the background thread are marshalled through `SwingUtilities.invokeLater`.

---

## Key Constants

| Constant | Value | Purpose |
|---|---|---|
| `BUFFER_SIZE` | 65 536 bytes | Write chunk size per I/O call |
| `DEFAULT_PASSES` | 3 | Pre-filled spinner value for RANDOM mode |

---

## Limitations

- **No filename or metadata scrubbing** — original filenames and timestamps remain in directory entries until the OS reclaims them.
- **SSD caveat** — software overwrite cannot guarantee physical erasure on SSDs with wear leveling or out-of-band spare sectors. Use firmware-level commands (ATA Secure Erase / NVMe Format NVM) for those.
- **Symbolic links** are skipped silently during shredding but not filtered at selection time.
- **Empty-file handling** — files of zero length are skipped (nothing to overwrite); they are still deleted.
- **No post-shred directory deletion** — parent directories are left on disk after their contents are shredded.
