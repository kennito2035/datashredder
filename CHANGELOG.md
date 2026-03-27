# Changelog — DataShredder v3.0.0

All changes relative to **v2.0.0**.

---

## New Features

### ChaCha20 cryptographic erase (`CRYPTO_ERASE`)
A sixth algorithm was added that encrypts the file in-place using ChaCha20 (standard JCA, Java 11+, no third-party library). A 256-bit key and 96-bit nonce are generated with `SecureRandom`, used to stream-encrypt the file chunk by chunk via `Cipher.update()` / `Cipher.doFinal()`, and then immediately zeroed in a `finally` block with `Arrays.fill`. Without the key, the ciphertext is computationally indistinguishable from random noise.

Unlike every other algorithm, CRYPTO_ERASE does **not** delete the file after encryption — the content is already unrecoverable.

> This replaces a broken Kyber implementation from an earlier branch that cast a JCA `PublicKey` to `KyberPublicKeyParameters` (causing `ClassCastException`), mixed raw and JCA API usage, and required a BouncyCastle PQC dependency that was never included.

### Filename scrubbing
Before deletion, `scrubFilename()` performs three sequential `Files.move()` renames to randomly generated names. `ATOMIC_MOVE` is requested first; a non-atomic fallback is used if the file system does not support it. Overwriting the directory entry multiple times frustrates inode-level name recovery.

> Fixed from a prior version where a dummy file was created at the destination path, the real file was moved onto it with `ATOMIC_MOVE`, and then `currentPath` was deleted — deleting the file that had just been moved. The method now does a pure rename chain with no dummy file.

### Metadata scrubbing
After filename scrubbing, `scrubMetadata()` sets all three file timestamps (creation, last-modified, last-access) to `FileTime.fromMillis(0)` (Unix epoch) via `BasicFileAttributeView`. Failures are silently ignored since not all file systems support all timestamp fields.

### Post-shred directory deletion
`collectDirectories()` enumerates all sub-directories of selected inputs and sorts them by absolute-path length descending, ensuring deepest children are processed before their parents. After all files are shredded, each directory is scrubbed and deleted in this order.

### Dark mode theming
`isDarkModeEnabled()` returns `true` (hardcoded). When enabled, `main()` applies a full `UIManager` colour palette covering panels, labels, buttons, combo boxes, spinners, option panes, and formatted text fields. A comment in the method explains how to replace the hardcoded value with automatic OS-level detection using `com.jthemedetecor`.

### Transient per-file progress messages
`showTransientMessage()` temporarily replaces the ETA string on the progress bar with a per-file status ("Obliterated: …" / "Encrypted: …"), then reverts to the ETA display after 2.5 seconds using a non-repeating `javax.swing.Timer`. A `stopMessageTimer()` guard prevents overlapping timers.

> Fixed from a prior version where the timer rescheduled itself on every fire, creating an unbounded chain of nested timers.

### Progress bar colour feedback
The progress bar changes colour to reflect state: **green** while shredding, **red** on cancel, **grey** when idle or after reset. A `resetTimer` (non-repeating, 3 s) restores the idle appearance after cancellation or completion.

### Spinner input validation
`NumberFormatter.setAllowsInvalid(false)` is applied to the passes spinner's editor, blocking any non-numeric characters from being typed.

### 1 MB write buffer
`BUFFER_SIZE` increased from 65 536 bytes (64 KB) to 1 048 576 bytes (1 MB), reducing I/O overhead on modern drives with large sector sizes and write-combining hardware.

---

## Bug Fixes

### `scrubFilename` no longer deletes the file being renamed
The prior implementation created a dummy file at the rename target, moved the real file onto it with `ATOMIC_MOVE`, then deleted `currentPath` — which was now pointing at the file that had just been moved away. The fix uses a plain rename chain: `current → next → next → next`, with no dummy file created at any step.

### Progress bar no longer updates when canceled
`recordProgress()` now checks `shreddingActive` before posting to the EDT, preventing stale percentage updates from appearing after the user cancels.

### Timer leak eliminated
The self-rescheduling progress timer from a prior version has been replaced with direct `SwingUtilities.invokeLater` calls from `recordProgress()`, with a separate non-repeating `messageTimer` for transient messages only.

### `Files.walk` stream leak (carried from v2, confirmed closed)
`collectFiles()` and the new `collectDirectories()` both use try-with-resources to guarantee the `Stream<Path>` is closed on any exit path.

---

## UI Changes

- Progress bar text colour forced to black on both themes via a custom `BasicProgressBarUI` subclass overriding `getSelectionForeground` / `getSelectionBackground`.
- Progress bar foreground is green during shredding, red on cancel, grey when idle.
- Transient "Obliterated: …" / "Encrypted: …" labels flash per file, reverting to ETA after 2.5 s.
- Result dialog is **non-modal** on a clean run so the `resetTimer` can still fire behind it; remains modal when there are errors or a cancellation.
- Cancel button turns the progress bar red and schedules a 3-second visual reset.
- Window title changed from **"File Shredder v2.0.0"** to **"Data Shredder v3.0.0"**.
- `showFinalReport()` calls `stopMessageTimer()` before displaying the dialog to avoid a stale message overwriting the final result string.

---

## Internal / Non-Visible Changes

- `main()` moved `UIManager.setLookAndFeel` and dark-mode setup outside `invokeLater` so the palette is applied before any Swing component is created.
- `runShredding` is split into a files loop and a separate directories loop, both inside a single method (no longer uses a `finally` block for UI reset — reset is done inline after both loops complete).
- `getTotalPasses` updated to handle `CRYPTO_ERASE` returning `1`; the progress multiplier in `startShreddingProcess` is capped at `1` for `CRYPTO_ERASE` regardless.
- `generateRandomName` generates names of variable length (8–16 characters) instead of a fixed 12 characters.
