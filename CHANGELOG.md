# Changelog — DataShredder v2.0.0

All changes relative to **v1.0.0**.

---

## New Features

### Multiple shred algorithms
A `ShredAlgorithm` enum was introduced with five selectable options, exposed via a `JComboBox` in the UI:

| Algorithm | Passes | Notes |
|---|---|---|
| RANDOM | 1 – 100 (configurable) | Carried over from v1 |
| DOD3 | 3 (fixed) | DoD 5220.22-M: zeros → ones → random |
| GUTMANN | 35 (fixed) | All 35 patterns in deterministic paper order |
| ZERO | 1 (fixed) | Zero-fill with post-write byte verification |
| NVME_PURGE | 4 (fixed) | NIST SP 800-88 inspired; ends with zeros + verification |

Selecting a fixed-pass algorithm automatically locks the passes spinner and sets the correct value.

### Directory support
`JFileChooser` mode changed from `FILES_ONLY` to `FILES_AND_DIRECTORIES`. A new `collectFiles()` method uses `Files.walk()` inside a try-with-resources block to recursively enumerate all regular files inside selected directories, skipping symbolic links via `LinkOption.NOFOLLOW_LINKS`.

### Cancel button
A **Cancel** button was added to the toolbar. Clicking it prompts a confirmation dialog, then sets `shreddingActive = false`. The background thread checks this flag between write chunks and after each file, stopping cleanly without abrupt interruption.

### Live ETA in progress bar
Progress reporting was upgraded from a bare percentage to `XX% — HH:MM:SS remaining`. Speed (`averageSpeedKBs`) is computed from elapsed time and bytes processed. A `formatTime()` helper converts remaining seconds to `HH:MM:SS`, guarding against `NaN` and `Infinity`. Progress state (`totalBytes`, `processedBytes`, `startTimeMs`, `averageSpeedKBs`) is tracked as `volatile` class fields rather than local lambda captures.

### File locking
`shredFile()` now opens a `FileChannel` alongside the `RandomAccessFile` and calls `channel.tryLock()`. If another process holds the file, `lock` is `null` and an `IOException` is thrown immediately, reporting the conflict to the user instead of silently overwriting a partially-locked file.

### Global uncaught-exception handler
`Thread.setDefaultUncaughtExceptionHandler` is registered in `main()` to catch any unhandled exception and show an error dialog rather than letting the JVM exit silently.

### `channel.force(true)` flush
After all passes, `channel.force(true)` is called to flush both file data and metadata to the storage device, supplementing the per-pass `fd.sync()` already present in v1.

---

## Bug Fixes

### Zero-fill verification now correctly scoped
In a prior version, `verifyZeroFill()` was called after every algorithm — including RANDOM, DOD3, and GUTMANN — which always threw an `IOException` because those algorithms do not end with a zero pass. Verification is now gated on `algo.requiresZeroVerification`, a flag that is `true` only for ZERO and NVME_PURGE.

### `overwritePattern` progress now recorded
The `overwritePattern()` method was missing a `recordProgress()` call, causing the progress bar to stall during zero-fill and ones-fill passes. The call was added inside the write loop.

### DoD3 pass order corrected
The original DoD3 implementation wrote in the wrong order. The correct DoD 5220.22-M sequence (zeros → ones → random) is now applied.

### `Files.walk` stream leak fixed
`Files.walk()` in `collectFiles()` is now wrapped in try-with-resources, ensuring the underlying directory stream is closed even if an `IOException` is thrown mid-walk.

### Deletion retry window reduced
The original deletion retry logic had delays that could accumulate to roughly 102 seconds. v2 retries up to 3 times with 200 ms between attempts. The last-resort fallback renames the file and schedules `deleteOnExit()`.

### `generateRandomName` uses shared `SecureRandom`
The utility now uses the class-level `RANDOM` instance instead of allocating a fresh `SecureRandom` per call, avoiding the cost of repeated entropy seeding.

---

## UI Changes

- Layout upgraded from `FlowLayout` to `GridBagLayout` for cleaner alignment.
- Window width increased from 585 px to 700 px; `setResizable(false)` added.
- **Browse** button label changed to **Browse Files/Dirs** to reflect directory support.
- **Shred** button label changed to **Secure Shred**.
- **Cancel** button added (initially disabled; enabled only during shredding).
- Progress bar label format changed from `"XX%"` to `"XX% — HH:MM:SS remaining"`.
- File-path label supports both files and directories in its preview text.
- `showFinalReport()` gains a `wasCanceled` parameter; shows a `WARNING_MESSAGE` icon when the run was cancelled or had errors.
- `showError()` helper added for displaying formatted error dialogs from the background thread.
