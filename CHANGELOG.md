# Changelog - DataShredder v4

## v4.0.1 (2026-08-30)

### Bug Fixes

- **Queue table fully themed in dark mode.** The Windows look and feel paints table headers itself and ignores the TableHeader colour keys, so the header row stayed light while everything around it was dark. The header now uses an explicit renderer (dark background, white text, thin separator lines), and the scroll pane viewport is matched to the table surface so the area past the table stays dark too. Light mode is untouched.

---

## v4.0.0 (2026-08-30)

All changes relative to **v3.0.2**. The source file `DataShredderV3.java` is replaced by
`DataShredderV4.java`, and a runnable engine test, `DataShredderV4EngineTest.java`, ships
alongside it. Zero external dependencies and a Java 11 minimum are unchanged.

---

### New Features

#### File queue with a table UI

The window no longer works on one selection at a time. Selected files and folders become rows
in a `JTable` with three columns: Name (tooltip shows the full path), Size ("12.3 MB" for a
file, "folder" for a directory) and Status, which moves from "Queued" through "Working: <name>"
to a per row outcome (Done, Done (crypto erased), Partial with counts, Skipped, Failed with the
reason, or Canceled). Rows that finished cleanly are removed when the run ends; anything the
user still needs to see stays on screen.

Queue management is done with Add, Remove Selected and Clear. The window is resizable with a
minimum size of 720 by 480; v3's window was fixed.

#### Drag and drop

A `TransferHandler` accepting `DataFlavor.javaFileListFlavor` is installed on both the table and
the frame, so files can be dropped anywhere on the window. `setFillsViewportHeight(true)` makes
drops below the last row land on the table rather than on the viewport behind it. Drops are
refused while a run is in progress. Windows blocks Explorer to application drops when the
application runs elevated, so the Add button remains the fallback.

#### Per item and overall progress bars with ETA

Two bars replace v3's single bar and its transient per file messages. The upper bar tracks the
file currently being written; the lower bar tracks the run, labelled `X% - HH:MM:SS remaining`.
Speed and the estimate are computed from `getActiveElapsedMillis()`, which subtracts paused
time, so pausing does not inflate the remaining estimate. When the byte total cannot be
determined the bar switches to indeterminate instead of showing a wrong percentage.

#### Pause and resume

A Pause/Resume button is enabled while a run is in progress. The engine parks between chunk
writes in `checkpoint()`, using a `wait`/`notifyAll` loop that re-tests both the pause and the
cancel flag, so it is safe against spurious wakeups and against a cancel that arrives while
paused. Cancel still works while paused, and returns promptly.

A paused run holds the exclusive file lock on the file it stopped inside, and during a free
space wipe it holds the disk it has filled so far, until it is resumed or canceled.

#### Free space wipe

A Wipe Free Space button (CLI: `--wipe-free <dir>`) fills the free space of the volume holding a
chosen folder with a single random pass and then releases it, so previously deleted file content
is overwritten. Work happens in a `wipe-<random>` sub folder of the picked folder, which avoids
the permission problems of writing at a drive root. Files are written up to 1 GiB each in 1 MiB
`SecureRandom` chunks and synced per file.

The fill stops when the byte limit is reached, when usable space is reported above zero but below
1 MiB, or on an `IOException` raised after at least one chunk was written successfully. A reported
zero is read as unknown rather than as a full volume, because some network and substituted volumes
return it, and treating it as full would stop the fill before a single byte was written. Java
exposes no portable out of space error code, so a failure on the very first chunk is treated as a
real error and reported as one. A run that writes nothing at all is reported as failed rather than
as a success.

Cleanup runs in a `finally` block, including after a cancel, and every delete is checked. Wipe
files that could not be removed are named in the result line, with the total size they are still
occupying, so the outcome never claims disk space was given back when it was not. Files and the
working folder are also registered with `deleteOnExit()`.

The confirmation dialog states that the disk briefly reads as full, that other programs may fail
to write, that a cloud synced folder would make the sync client upload the random data, and that
`wipe-*` leftovers remain if the program is killed part way. The wipe is single pass random only.

#### Headless command line mode

Running the jar with arguments runs headless and never touches Swing:

```
java -jar DataShredderV4.jar --algo <random|dod3|gutmann|zero|nvme|crypto> [--passes N] [--report <path>] --yes <paths...>
java -jar DataShredderV4.jar --wipe-free <dir> [--limit <MB>] [--report <path>] --yes
java -jar DataShredderV4.jar --help
```

Without `--yes` the command prints what would be destroyed and exits 2 without touching
anything. Exit codes are 0 for a clean run, 1 when items failed, 2 for a usage error or a
refused run. Progress prints at item boundaries and every 5 percent. `--limit` is bounds checked
so the megabytes to bytes multiplication cannot overflow into a negative value, which the engine
would otherwise read as "no limit" and turn a capped wipe into a full volume fill.

Running with no arguments at all still starts the graphical interface.

#### Opt in erasure report

A "Write erasure report" checkbox (CLI: `--report <path>`) produces a plain text record of the
run: tool and version, timestamp, mode, algorithm, pass count, total bytes processed, and one
block per queue item giving the absolute path, size and outcome with per file counts. The footer
repeats the flash storage caveat. In the GUI the report is offered through a save dialog when the
run finishes; in the CLI it is written to the given path.

The report is off by default because it lists the names and paths of destroyed files. When a
report was asked for and could not be written, the CLI says so and exits non-zero, so a script
collecting audit evidence cannot read the run as a success.

#### Automatic dark mode detection

`isDarkModeEnabled()` replaces v3's hardcoded `true`. On Windows it reads
`HKCU\Software\Microsoft\Windows\CurrentVersion\Themes\Personalize\AppsUseLightTheme` through
`reg query`, draining the child's output on a daemon thread and bounding the wait at two seconds
with `destroyForcibly()` on timeout; `0x0` means dark. Any other platform, and any failure,
means light. The system property `datashredder.theme=dark|light` overrides the probe. Detection
is called only from the GUI launch path, never from a static initializer, so the headless path
never runs it.

---

### Changes

#### Structure: engine, CLI and UI split

`DataShredderV4` is a plain class holding only `main()` and nested static classes:
`ShredEngine` (no Swing or AWT usage at all), `Cli`, `Gui` and `ItemResult`. It deliberately
does not extend `JFrame`, because subclassing a Swing type would force AWT class initialisation
even on the headless CLI path. All Swing lives in `Gui`.

The engine reports through a `Listener` interface (`onTotalBytes`, `onProgress`, `onFileStart`,
`onFileProgress`, `onItemResult`, `onFinished`). Every callback fires on the engine's worker
thread; the GUI adapter marshals to the event dispatch thread and throttles the two progress
callbacks to one post per percent step or per 100 ms, before `invokeLater`, so the event queue
never floods.

#### Symbolic links and NTFS junctions are never followed

v3 excluded symbolic links only. `Files.isSymbolicLink` returns false for a directory junction
made with `mklink /J`, so a plain walk would have entered it and shredded files far outside the
selected folder; junctions exist in every Windows user profile by default. `isLinkOrJunction()`
now compares where a directory resolves to against where it sits, resolving the parent for real
as well so that an ancestor junction, a substituted drive letter or a differently cased path
does not make ordinary entries look redirected. Redirected entries are skipped by the queue, by
the file walk and by the directory walk, and are left exactly as they were found.

#### Directory scans survive unreadable entries

`collectFiles()` and `collectDirectories()` moved from `Files.walk` to `walkFileTree` with a
visitor that records an unreadable entry and carries on. The previous behaviour let a single
ACL restricted subfolder, a System Volume Information directory or a folder locked by another
process abort the whole scan and leave every readable file in the tree untouched. Recorded scan
problems are counted against their own row and appear in its status text and in the report.
Both walks also honour pause and cancel, so a scan of a large tree can be stopped.

#### Queue entries are de-duplicated

The expanded file list is de-duplicated by canonical path, so a queue holding both a folder and a
file inside it processes that file exactly once instead of shredding it twice and then reporting
"Not found" for the second attempt. The first row to claim a path keeps it; the later row is
reported as skipped.

#### Per item outcomes replace a single run summary

`ItemResult` carries a kind plus files done, skipped and failed counts and a detail string. Row
status precedence is: any failure gives FAILED, otherwise any skip with nothing done gives
SKIPPED, any skip with work done gives PARTIAL, and a clean row gives SHREDDED or CRYPTO_ERASED.
This is what makes a partly successful folder legible, which v3's single end of run dialog could
not express.

#### Non-empty directories are kept, not renamed

Directories are still processed deepest first, but a directory that still has children is left
alone with its name intact and recorded as a skip. Its remaining children are always things the
run was never going to remove: a link or junction that is not followed, a read only file skipped
on purpose, or an entry whose own failure was already counted with its own note. Renaming such a
directory would hide those leftovers under a random string and the report would then name a
directory that no longer exists. Counting it as a failure would make a correct run exit non-zero.

#### Overlapping file locks are caught

The per item catch is `catch (IOException | OverlappingFileLockException ex)`. `tryLock` throws
the latter unchecked, and a queue holding both a folder and a file inside it makes a same JVM
overlap reachable.

#### Invalid paths fail their own row only

`File.toPath()` rejects characters the platform does not allow in a path with an unchecked
`InvalidPathException`. It is now caught per row, so an argument such as `report<1>.txt` no
longer unwinds out of the whole run and leaves every other queued item untouched.

#### A file that was overwritten but could not be deleted says where it is

Such a file no longer carries its original name anywhere on disk, because filename scrubbing has
already renamed it. The note now gives both the original name and the absolute path the file
currently sits at.

#### Cancel is checked after the final pass

The write loops check only between chunks, so a cancel arriving during the final chunk of the
final pass previously fell straight through to the rename, the timestamp scrub and the delete.
A checkpoint after the passes and the zero-fill verification closes that window: a cancel means
the file stays where it is, whichever chunk it landed on.

#### Cancel confirmation re-checks the run

The cancel confirmation dialog runs a nested event loop, so the run can finish while it is open.
The engine reference and the running flag are re-checked after the dialog closes, so a run that
already completed is not left showing a red "Canceling..." over destroyed files with nothing to
replace it.

#### Progress text is not painted over by in flight posts

The UI tracks whether it is running, paused or canceling. A progress post that was already in
flight when the user paused or cancelled no longer paints an ordinary percentage over the
sentence explaining what the run is doing. This matters most for the pause banner: once the
worker parks in `checkpoint()` no later post would correct it.

#### Transient per file messages and the reset timer are gone

v3's `showTransientMessage()`, `stopMessageTimer()` and the 3 second `resetTimer` are removed.
Their job, saying what is being worked on right now, is done by the current item bar and the
Status column. The end of run dialog is replaced by the overall bar's final text, except for a
free space wipe that ends partial, failed or canceled, which still raises a dialog because the
path of a leftover wipe file does not fit in the bar.

#### Dark mode palette extended

The v3 palette is carried over, including the deliberate choice to leave `Label.foreground`
dark: a global white breaks the file chooser's "Look in:" label, which the look and feel paints
on a light strip. `applyChooserLabelColors` now also matches `FileChooser.folderNameLabelText`,
so the directories only chooser used by the free space wipe is covered as well. Table, table
header, scroll pane and viewport keys were added for the queue, and the "Queue" titled border
sets its own title colour rather than going through a global key.

#### Report and result wording

Error text names the exception type as well as its message. A `java.nio.file.FileSystemException`
often carries nothing but the path, and the bare message would otherwise read like a line
announcing where the report had been written.

#### Version and title

The window title is now "Data Shredder v4.0.0".
