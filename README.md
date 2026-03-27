# DataShredder v1.0.0

A minimal Java Swing desktop application that permanently destroys files by overwriting them with cryptographically random data before deletion.

---

## Features

- **Random-data overwrite** using `SecureRandom` — the only available algorithm
- **Configurable pass count** — 1 to 100 passes (default: 3)
- **Multi-file selection** via a standard file chooser dialog (files only, no directories)
- **Progress bar** showing completion percentage in real time
- **Post-shred deletion** with a rename-then-delete fallback to release OS name-cache locks
- **Safe-close guard** — warns before exiting while shredding is in progress
- **Background thread** — shredding runs off the EDT; UI remains responsive

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
javac DataShredderV1.java

# Run
java DataShredderV1
```

Or package into a runnable JAR with any standard build tool.

---

## Usage

1. Launch the application.
2. Set the desired number of **passes** using the spinner (higher = more thorough, slower).
3. Click **Browse** and select one or more files.
4. Click **Shred** and confirm the warning dialog.
5. Wait for the progress bar to complete; a results summary is shown when done.

> **Warning:** Shredding is irreversible. Files cannot be recovered after this operation.

---

## Algorithm Detail

| Step | Action |
|---|---|
| For each pass | Seek to byte 0, fill the file with `SecureRandom` bytes in 64 KB chunks, call `fd.sync()` |
| After all passes | Attempt `File.delete()`; if that fails, rename the file to a random 12-character name and retry deletion |

The 64 KB write buffer (`BUFFER_SIZE = 65536`) balances memory usage against I/O efficiency.

---

## Limitations

- **Files only** — directories cannot be selected or processed.
- **Single algorithm** — only random-data overwrite is available; no DoD, Gutmann, or zero-fill modes.
- **No cancel button** — once shredding starts it cannot be stopped mid-run (closing the window prompts a confirmation).
- **No ETA** — the progress bar shows percentage only, not time remaining.
- **No directory support** — recursive shredding of folder trees is not supported.
- **No symbolic-link guard at selection time** — symbolic links are filtered during shredding, not during file selection.
- **SSD caveat** — like all software-based shredders, this tool cannot guarantee physical erasure on SSDs or drives with hardware-level wear leveling. Use manufacturer firmware tools (e.g., ATA Secure Erase) for those.

---

## Architecture

```
DataShredderV1 (JFrame)
├── UI setup        — FlowLayout, JSpinner, JLabel, JButton × 2, JProgressBar
├── File selection  — JFileChooser (FILES_ONLY, multi-select)
├── Orchestration   — startShreddingProcess() → new Thread(runShredding)
├── Core logic      — shredFile() loops passes, writes random bytes, syncs
└── Deletion        — deleteFilePermanently() with rename fallback
```

All UI updates from the background thread are marshalled through `SwingUtilities.invokeLater`.

---

## Key Constants

| Constant | Value | Purpose |
|---|---|---|
| `BUFFER_SIZE` | 65 536 bytes | Write chunk size per I/O call |
| `DEFAULT_PASSES` | 3 | Pre-filled spinner value |
| `MIN_PASSES` | 1 | Spinner lower bound |
| `MAX_PASSES` | 100 | Spinner upper bound |
