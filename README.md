# DataShredder v4.1.0

A Java file and directory shredder with a queue interface, per-item and overall progress, pause and resume, free-space wiping, an opt-in erasure report, and a headless command line mode. Six overwrite algorithms including ChaCha20 cryptographic erase. Zero external dependencies. Requires Java 11 or later.

---

## Features

- **Six shred algorithms** including ChaCha20 cryptographic erase (see table below)
- **File queue** - a table of the items you selected, with Name (tooltip shows the full path), Size, and a live Status column; add, remove selected, or clear
- **Drag and drop** - drop files and folders onto the window or the table; the Add button does the same thing through a file chooser
- **Two progress bars** - one for the file being written, one for the run as a whole, labelled `X% - HH:MM:SS remaining`
- **Pause and resume** - the worker parks between chunk writes and resumes where it stopped; the estimate ignores paused time
- **Cancel that never deletes** - a cancelled file is never renamed, timestamp-scrubbed, or deleted, whichever pass it was on; when the cancel lands part way through a file, that sentence leads the row detail and names the file and the phase, because a file that was part way through is not intact, and a cancel taken between items says so instead of claiming one
- **Free-space wipe** - fills the free space of a volume with one random pass, then removes what it wrote, with an optional size cap
- **Erasure report** - opt-in plain-text record of what ran, what was destroyed, and how each item ended
- **Headless command line mode** - any argument switches the process to the CLI; Swing is never loaded on that path
- **Dark mode auto-detection** - read from the Windows registry at startup, with a system property override
- **Links and junctions are never followed** - symbolic links and NTFS directory junctions are excluded from the queue and skipped during a walk, so a junction inside a folder cannot take the shredder outside it
- **Duplicate work removed** - the expanded queue is deduplicated by canonical path, so queueing a folder and a file inside it shreds that file once
- **Unreadable entries do not abort a scan** - a folder that cannot be read is recorded against its row and the rest of the tree is still processed
- **Filename scrubbing** - renames to random names before deletion, so the live directory entry no longer carries the original name
- **Metadata scrubbing** - all timestamps reset to the Unix epoch before deletion
- **File locking** via `FileChannel.tryLock()` - refuses to shred a file another process holds open
- **One shared 1 MiB read and write buffer** per run, `fd.sync()` after every pass
- **Safe-close guard**, destroy-confirm dialog, and a global uncaught-exception handler

---

## Algorithms

| Algorithm | CLI name | Passes | Description |
|---|---|---|---|
| **RANDOM** | `random` | 1 to 100 (configurable) | Cryptographically random data via `SecureRandom` |
| **DOD3** | `dod3` | 3 (fixed) | The classic three-pass sequence historically attributed to DoD 5220.22-M: zeros, then ones, then random |
| **GUTMANN** | `gutmann` | 35 (fixed) | 4 random passes, the 27 deterministic patterns in a fresh random permutation, then 4 random passes |
| **ZERO** | `zero` | 1 (fixed) | Single zero-fill pass with byte-level verification |
| **NVME_PURGE** | `nvme` | 4 (fixed) | A 4-pass scheme of this tool's own design: random pattern, complement, random, zeros, then byte-level verification |
| **CRYPTO_ERASE** | `crypto` | 1 (fixed) | ChaCha20 in-place encryption; the local 256-bit key and 96-bit nonce arrays are zeroed immediately after use, so the content is computationally unrecoverable |

> **CRYPTO_ERASE behaviour:** the encrypted file stays on disk under its original name, with its original timestamps. It is never renamed, never timestamp-scrubbed, and never deleted, and the folders holding those files are left in place too. The local key and nonce arrays are zeroed in a `finally` block. Copies of the key inside `SecretKeySpec` and inside the cipher's expanded key schedule stay on the JVM heap until garbage collection; neither can be reached from pure Java, so that is a limitation of the implementation and not something the zeroing removes.

> **Note on DoD 5220.22-M:** the three-pass sequence is the one historically attributed to that standard. The current NISPOM specifies no overwrite method, and this implementation does not verify what it wrote.

> **Note on NIST SP 800-88:** `NVME_PURGE` is a scheme of this tool's own design, loosely motivated by the discussion in SP 800-88. It is not a NIST technique and the document does not describe it.

> **Note on Gutmann:** the 27 deterministic passes are written in a fresh random permutation per file, which is what the paper specifies. The paper's author has since noted that the full 35-pass scheme targets encodings used by drives that are long obsolete, and that on a modern drive a few random passes are what actually matters.

---

## Requirements

| Requirement | Version |
|---|---|
| Java | **11 or later** (the ChaCha20 cipher requires JDK 11+) |
| External libraries | None |
| Operating system | Any platform with Java 11. Dark-mode auto-detection is Windows only; see Limitations |

---

## How to Build and Run

```bash
# Compile the application
javac --release 11 -d ./build DataShredderV4.java

# Package (from the build directory)
cd build
jar cfe DataShredderV4.jar DataShredderV4 *.class

# Run the graphical interface
java -jar DataShredderV4.jar

# Run the command line mode
java -jar DataShredderV4.jar --help
```

To build and run the shipped engine test, compile into a separate directory so the test classes stay out of the jar:

```bash
javac --release 11 -d ./test-build DataShredderV4.java DataShredderV4EngineTest.java
java -cp ./test-build DataShredderV4EngineTest
```

The test prints a `PASS` or `FAIL` line per check, a final count, and exits non-zero if anything failed. It needs no libraries and works headless; it writes only inside a temporary directory under `java.io.tmpdir` and deletes it afterwards.

---

## Usage (graphical interface)

1. Launch the application with no arguments. The theme follows the Windows setting.
2. Add work to the queue: click **Add**, or drag files and folders onto the window.
3. Pick an **Algorithm**. The **Passes** spinner enables itself only for RANDOM and shows the fixed count otherwise.
4. Tick **Write erasure report** if you want a record. It is off by default.
5. Click **Secure Shred** and confirm the warning dialog.
6. Watch the two bars. The upper one tracks the current file, the lower one the whole run with a remaining-time estimate.
7. **Pause** parks the run and turns into **Resume**. **Cancel** works while paused.
8. Each queue row shows its own outcome: Done, Done (crypto erased), Partial, Skipped, Failed, or Canceled, with the reason. Rows that finished cleanly are removed from the queue when the run ends; anything you should look at stays.
9. If the report checkbox was ticked, a save dialog appears when the run finishes.

To wipe free space instead, click **Wipe Free Space**, pick a folder on the volume you want cleaned, and read the confirmation dialog before proceeding.

> **Warning:** shredding is irreversible. Files and directories cannot be restored by this tool after this operation. Both confirmation dialogs also state that on SSDs and other flash storage an overwrite may not reach every physical copy of the data.

---

## Usage (command line)

Any argument at all puts the process into command line mode. Only the CLI and engine classes load on that path, so it runs on a headless machine.

```
java -jar DataShredderV4.jar --algo <name> [--passes N] [--report <path>] --yes <paths...>
java -jar DataShredderV4.jar --wipe-free <dir> [--limit <MB>] [--report <path>] --yes
java -jar DataShredderV4.jar --help
```

| Option | Meaning |
|---|---|
| `--algo <name>` | `random`, `dod3`, `gutmann`, `zero`, `nvme`, or `crypto`. Default: `random` |
| `--passes N` | Pass count for `random`, 1 to 100. Default: 3. Ignored with a printed note for the fixed-pass algorithms |
| `--report <path>` | Write the plain-text erasure report to this path, creating parent directories as needed |
| `--wipe-free <dir>` | Wipe the free space of the volume holding this folder. Cannot be combined with file paths |
| `--limit <MB>` | Cap the free-space wipe at this many megabytes |
| `--yes` | Required before anything is destroyed |
| `--help`, `-h` | Print the usage text |

Without `--yes` the CLI prints what would be destroyed (and, for a wipe, the target and the limit) and exits 2 without touching anything.

Progress is printed at item boundaries and every 5 percent.

| Exit code | Meaning |
|---|---|
| `0` | Everything succeeded |
| `1` | Some items failed, or a requested erasure report could not be written |
| `2` | Usage error, or the run was refused because `--yes` was missing |

A report that was asked for and could not be written turns the run into exit code 1, so a script collecting audit evidence never reads a missing report as a success.

---

## Erasure report

Off by default. Turn it on with the **Write erasure report** checkbox or `--report <path>`. The report is plain UTF-8 text and contains:

- Tool name and version
- Timestamp of the run
- Mode (file and directory shred, or free space wipe)
- Algorithm and effective pass count
- Total bytes processed
- One block per queue item: absolute path, size, and the outcome with per-file done, skipped, and failed counts plus any notes
- A closing note about the limits of overwriting on flash storage

The report names the paths of destroyed files, which is why it is opt-in. See Limitations.

---

## Free-space wipe

The wipe creates a `wipe-<random>` working folder inside the folder you picked, rather than at the drive root, which avoids the permission problems of writing to `C:\`. Inside it, `wipe-<n>.tmp` files of at most 1 GiB each are filled with `SecureRandom` data in 1 MiB chunks and synced to disk.

It stops when the `--limit` byte cap is reached, when the volume reports a usable figure above zero but below 1 MiB, or when a write fails after at least one chunk has already been written successfully. A reported zero is treated as unknown rather than as a full volume, because that is what some network and substituted volumes return, and reading it as full would end the wipe before a single byte was written. Java exposes no portable out-of-space error code, so a failure on the very first chunk is reported as a real error instead of being read as a full disk.

Cleanup runs in a `finally` block, including after a cancel, and every delete is checked. Anything that could not be removed is named in the result line, in the report, and in a dialog, so a run never claims disk space was released when it was not. The working folder and each wipe file are also registered with `deleteOnExit()`.

Only a single random pass is written. That is the design, not a configurable setting.

---

## Algorithm detail

### Overwrite primitives

| Primitive | Behaviour |
|---|---|
| `overwriteRandom` | Fills the file with `SecureRandom` bytes, then `fd.sync()` |
| `overwritePattern` | Fills the file with a repeating single byte, then `fd.sync()` |
| `overwriteCustomPattern` | Tiles an arbitrary byte array across the file, then `fd.sync()` |
| `performCryptoErase` | Reads the file in chunks, encrypts in place with ChaCha20, writes back; key and nonce zeroed in `finally` |
| `verifyZeroFill` | Reads the file back and fails on the first non-zero byte. Only called for ZERO and NVME_PURGE, and reported as progress like any pass |

Every primitive calls a pause and cancel checkpoint between chunks, so both controls respond mid-pass on a large file.

### Filename and metadata scrubbing

- **`scrubFilename()`** performs three sequential `Files.move()` renames to random 8 to 16 character names, `ATOMIC_MOVE` with a non-atomic fallback. A name that is already taken is retried with a fresh random name, up to 100 times, rather than aborting part way through the chain; `REPLACE_EXISTING` is never used. The point is that the live directory entry no longer carries the original name. Freed directory entries and the file system journal may still retain it.
- **`scrubMetadata()`** sets creation, modification, and access times to `FileTime.fromMillis(0)` through `BasicFileAttributeView`.

### Directory expansion and deletion

`collectTree()` gathers the files and the sub-directories of a queued folder in a single `Files.walkFileTree` pass, not `Files.walk`, because a subtree that must not be entered has to be skipped rather than filtered. Symbolic links and junctions are detected by resolving the entry's real path against its parent's real path, since `Files.isSymbolicLink` returns false for an NTFS junction. Directories are sorted deepest first for removal.

A directory that still holds entries when its turn comes is kept, not forced. Whatever is inside it is something the run was never going to remove: a link or junction, a read-only file that was skipped, or an entry whose own failure has already been counted. The row records that as a skip and names the directory.

### Row status precedence

A queue row can expand into many files, so its status is decided by the counts: any failure makes the row **Failed**; otherwise any skip with nothing done makes it **Skipped**; otherwise any skip makes it **Partial**; otherwise the row is **Done**, or **Done (crypto erased)** for CRYPTO_ERASE.

### Deletion strategy

1. Set the file writable (`file.setWritable(true)`).
2. Try `Files.deleteIfExists` up to 3 times with 200 ms between attempts.
3. If all attempts fail, report it. The content is already gone, so the note names the random name the file now carries and where it sits.

---

## Architecture

```
DataShredderV4                        plain class: only main() and nested statics.
│                                     Deliberately not a JFrame subclass, so the CLI
│                                     path never forces AWT class initialisation.
├── main(String[])                    arguments -> Cli.run(), none -> Gui.launch()
├── ItemResult                        outcome of one queue row: kind + done/skipped/failed counts
├── ShredEngine                       no Swing or AWT anywhere in this class
│   ├── Algorithm enum                6 values: display name, CLI name, zero-verify flag
│   ├── Options                       algorithm, passes, report flag and path, wipe limit
│   ├── Listener                      6 callbacks, all fired on the worker thread
│   ├── checkpoint()                  pause wait loop and cancel throw, called between chunks
│   ├── collectTree()                 one walk per queued folder: files, dirs, link filtering
│   ├── expand()                      queue expansion, hard-link notes, canonical-path dedupe
│   ├── run()                         shreds the queue; onFinished always fires from finally
│   ├── overwrite primitives          random / pattern / custom pattern / crypto erase
│   ├── algorithm methods             3-pass / Gutmann (permuted) / 4-pass ending in zeros
│   ├── verifyZeroFill()              ZERO and NVME_PURGE only, reported as progress
│   ├── scrubFilename() x3            plus scrubMetadata() epoch reset
│   ├── deleteFilePermanently()       3 attempts, 200 ms apart
│   ├── wipeFreeSpace()               fill, stop conditions, checked cleanup in finally
│   └── writeErasureReport()          plain-text output
├── Cli                               headless; argument parsing, confirmation gate,
│   └── CliListener                   progress at item boundaries and every 5 percent
└── Gui (JFrame)                      all Swing and AWT usage lives here
    ├── isDarkModeEnabled()           property override, else the Windows registry
    ├── applyDarkPalette()            UIManager keys, including the queue table
    ├── applyChooserLabelColors()     per-component recolouring of chooser labels
    ├── queue table + TransferHandler  drag and drop, add, remove, clear
    ├── startShreddingProcess()       reads every Swing value on the EDT, then a worker
    ├── startFreeSpaceWipe()          folder chooser, warning dialog, then a worker
    └── GuiListener                   throttles progress before invokeLater
```

Every engine callback fires on the worker thread. The GUI adapter marshals to the EDT itself, and throttles the two progress callbacks to one post per percent step or per 100 ms, whichever comes first, applied before `invokeLater` so the event queue cannot flood. All Swing values the worker needs are captured on the EDT before it starts.

---

## Key constants

| Constant | Value | Purpose |
|---|---|---|
| `BUFFER_SIZE` | 1 048 576 bytes (1 MiB) | Read and write chunk size |
| `MAX_WIPE_FILE_SIZE` | 1 073 741 824 bytes (1 GiB) | Largest single wipe file |
| `MIN_FREE_BYTES` | 1 048 576 bytes (1 MiB) | Free-space wipe stop threshold |
| Default passes | 3 | Pre-filled spinner value and CLI default for RANDOM |
| Passes range | 1 to 100 | Spinner bounds and `--passes` bounds |
| Progress throttle | 1 percent or 100 ms | Applied before posting to the EDT |
| Window size | 880 x 560, minimum 720 x 480 | Resizable |

---

## Theme

`isDarkModeEnabled()` checks the system property `datashredder.theme` first: `dark` or `light` wins outright. Otherwise, on Windows, it runs `reg query "HKCU\Software\Microsoft\Windows\CurrentVersion\Themes\Personalize" /v AppsUseLightTheme`, draining the child's output on a daemon thread and waiting at most 2 seconds before forcibly destroying it. A value of `0x0` means dark. On any other platform, or on any failure or timeout, the theme is light.

```bash
java -Ddatashredder.theme=dark  -jar DataShredderV4.jar
java -Ddatashredder.theme=light -jar DataShredderV4.jar
```

Light mode applies no `UIManager` overrides at all, so it is the plain system look and feel. Dark mode sets a palette that includes the queue table, its header, and the scroll pane. The file chooser labels are recoloured one component at a time rather than through a global `Label.foreground` key: a global white breaks the chooser's "Look in:" label, which the look and feel paints on a light strip.

---

## Tests

`DataShredderV4EngineTest.java` ships with the source and is meant to be run by anyone reviewing it. It is a plain `main()` with no test framework, and covers 19 groups:

1. Pattern primitives, custom-pattern tiling, and the Gutmann table checked against the paper order
2. Zero-fill verification passing on zeros and failing on a corrupted byte
3. CRYPTO_ERASE: content changed, length preserved, file still present under its original name
4. A full RANDOM run: file gone, monotonic progress, final processed equals the final total
5. Cancel mid-file: the file survives, the row is Canceled, nothing was deleted, and the detail leads with the file and the phase it was interrupted in
6. Pause: no further progress during a fixed window, then resume and completion
7. Cancel while paused: the run returns promptly and the file is intact
8. A read-only file: skipped, with the byte total adjusted downward
9. A zero-length file: shredded and deleted
10. A byte-limited free-space wipe: the exact byte count, and every wipe file and the working folder removed afterwards
11. Deduplication: a folder plus a file inside it shreds that file once
12. CLI parsing in process: `--help` exits 0, a missing `--yes` exits 2, a bad algorithm exits 2
13. A directory junction is not followed
14. A read-only leftover leaves its row Partial
15. An unreadable subdirectory is recorded without aborting the scan
16. A ZERO run: the byte total covers the write pass and the verification read, and the final processed count lands exactly on it
17. HTML escaping of text that is shown inside an `<html>` dialog
18. A row already holding more notes than the 400-character detail cap still leads its canceled detail with the phase note
19. A cancel taken between items: the finished item is destroyed, the item never reached is byte for byte unchanged, and the row claims no half destroyed file

---

## Limitations

- **SSD caveat.** A software overwrite cannot guarantee physical erasure on solid state drives, USB flash media, or SD cards. Wear levelling and over-provisioning mean the drive may keep copies the file system never exposed. Use full-disk encryption from the start, or the drive's own secure erase command (ATA Secure Erase, NVMe Format NVM), when that matters. Both confirmation dialogs, the CLI preview, and the CLI run banner state this at the moment of destruction, not only here and in the report footer.
- **Alternate data streams, cluster slack, ACLs, and extended attributes are not wiped.** Only the file's own data is overwritten. NTFS alternate data streams attached to a file, the slack space between the end of the file and the end of its last cluster, access control lists, and extended attributes are all left as they are. Deliberately out of scope for this version.
- **Names and timestamps already recorded elsewhere cannot be removed.** The pre-deletion rename and timestamp scrub change the live directory entry only. Copies of the original name and times can survive in freed directory entries and in the file system journal (`$LogFile` and `$UsnJrnl` on NTFS, the journal on ext4), and nothing in user space can reach them. The free-space wipe is a partial mitigation for directory slack, not a fix for the journal.
- **Verification confirms what the operating system committed.** `verifyZeroFill` reads the file back through the normal file API after `force(true)`. That proves the operating system accepted and returned the zeros; it does not prove what the physical medium now holds, and on flash storage the two are not the same thing.
- **Hard links are detected only where the platform allows it.** Shredding a file that carries other hard-linked names destroys the shared content but removes only the queued name; the other names then point at a wiped file. The scan reports a note when it can read a link count above one, which works on Unix-like file systems and is silently unavailable on Windows, so absence of a note is not proof that a file has only one name.
- **The erasure report names what was destroyed.** It lists absolute paths, sizes, and per-item notes, which can itself be sensitive. That is why it is off by default and why you choose where it is written.
- **Dark-mode auto-detection is Windows only.** Every other platform starts in light mode. `-Ddatashredder.theme=dark` forces the dark palette there, but the palette is tuned for the Windows look and feel: other look and feels honour a different set of `UIManager` keys and can end up painting dark text on dark chrome. Prefer the default light theme on those platforms.
- **Theme detection may briefly flash a console window.** The registry probe starts `reg.exe`, a console-subsystem program, and when the parent is a console-less `javaw` process Windows can show a console window for the moment it runs. There is no way to suppress that without adding a dependency. Setting `-Ddatashredder.theme` skips the probe entirely.
- **Drag and drop does not work into an elevated window.** Windows UIPI silently blocks a drop from a normal Explorer window onto a process running as administrator. Nothing appears to happen and no error is shown. Use the Add button instead.
- **Pausing holds the file open.** The paused worker keeps the exclusive `FileLock` on the file it was writing, so no other program can touch that file until you resume or cancel. A paused free-space wipe also keeps the disk filled for as long as it stays paused.
- **A crash or a kill leaves `wipe-*` behind.** Cleanup runs in a `finally` block and `deleteOnExit()` is registered as a backstop, but neither survives a process kill, a power loss, or a hard shutdown. What is left is a `wipe-<random>` folder of `wipe-<n>.tmp` files inside the folder you picked, holding random data and nothing else. Delete it normally to get the space back.
- **Never point a free-space wipe at a cloud-synced folder.** OneDrive, Dropbox, and similar clients would treat the wipe files as new documents and upload gigabytes of random data before the wipe removes them again. Pick a folder outside any synced tree.
- **The free-space wipe was exercised only with byte-limited runs.** Testing on the development machine used `--limit` capped runs and the shipped test's 20 MiB case. An uncapped run that genuinely fills a volume to its stop threshold has not been executed, so the behaviour of that path is claimed from the code and not from a full-volume run.
- **CRYPTO_ERASE leaves the file on disk.** The content is computationally unrecoverable, but the name, size, path, and timestamps remain, and the folders holding those files are not removed. Run a second pass with a destructive algorithm if directory-entry privacy also matters.
- **Timestamp scrubbing is best-effort.** Some file systems and configurations refuse timestamp changes; `scrubMetadata()` ignores those failures rather than failing the file.
- **Java 11 minimum.** ChaCha20 is not available in Java 8 or 9.

---

## Out of scope for this version

Alternate data stream and cluster slack wiping, Explorer context-menu integration, any external look-and-feel dependency, a `jpackage` installer, and parallel wiping across multiple drives.

---

## License

See [LICENSE](LICENSE).
