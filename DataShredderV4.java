/**
 * DataShredder v4.1.0
 *
 * File and directory shredder with a queue UI, per-item and overall progress,
 * pause/resume, free-space wiping, an opt-in erasure report and a headless CLI.
 * Zero external dependencies; Java 11 or newer.
 *
 * Algorithms:
 *  - RANDOM      : Configurable passes of cryptographically random data
 *  - DOD3        : The classic three-pass sequence historically attributed to
 *                  DoD 5220.22-M (zeros -> ones -> random). The current NISPOM
 *                  specifies no overwrite method, and this implementation does
 *                  not verify.
 *  - GUTMANN     : Gutmann 35-pass; the 27 deterministic patterns are randomly
 *                  permuted per file, which is what the paper specifies.
 *  - ZERO        : Single zero-fill pass with post-write verification
 *  - NVME_PURGE  : A 4-pass scheme of this tool's own design, ending in zeros
 *                  with verification. Loosely motivated by the discussion in
 *                  SP 800-88; it is not a NIST technique.
 *  - CRYPTO_ERASE: ChaCha20 in-place encryption; the local key and nonce arrays
 *                  are zeroed after use, but copies inside SecretKeySpec and the
 *                  cipher's expanded key schedule stay on the JVM heap until
 *                  garbage collection, which pure Java cannot prevent. The file
 *                  keeps its name, timestamps and place on disk.
 *
 * Structure: this is a plain class holding only main() and nested static
 * classes. It deliberately does NOT extend JFrame, because subclassing a Swing
 * type would force AWT class initialisation even on the headless CLI path.
 */

import javax.crypto.Cipher;
import javax.crypto.spec.ChaCha20ParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import javax.swing.*;
import javax.swing.table.DefaultTableModel;
import javax.swing.text.NumberFormatter;
import java.awt.*;
import java.awt.datatransfer.DataFlavor;
import java.io.BufferedReader;
import java.io.File;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.RandomAccessFile;
import java.io.UncheckedIOException;
import java.nio.channels.FileChannel;
import java.nio.channels.FileLock;
import java.nio.charset.Charset;
import java.nio.file.AtomicMoveNotSupportedException;
import java.nio.file.FileAlreadyExistsException;
import java.nio.file.FileVisitOption;
import java.nio.file.FileVisitResult;
import java.nio.file.Files;
import java.nio.file.InvalidPathException;
import java.nio.file.LinkOption;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.nio.file.SimpleFileVisitor;
import java.nio.file.StandardCopyOption;
import java.nio.file.attribute.BasicFileAttributeView;
import java.nio.file.attribute.BasicFileAttributes;
import java.nio.file.attribute.FileTime;
import java.security.GeneralSecurityException;
import java.security.SecureRandom;
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.Collections;
import java.util.Date;
import java.util.EnumSet;
import java.util.HashMap;
import java.util.HashSet;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;

public class DataShredderV4 {

    static final String APP_NAME    = "Data Shredder";
    static final String APP_VERSION = "v4.1.0";

    /**
     * Stated at the moment of destruction, in the confirmation dialogs and the
     * CLI, rather than only in the opt-in report footer and the README.
     */
    static final String FLASH_CAVEAT =
            "On SSDs and other flash storage an overwrite may not reach every"
            + " physical copy of the data.";

    private DataShredderV4() { }

    /**
     * Escapes the three characters Swing's HTML renderer treats as markup, so
     * exception text and file paths cannot inject tags into an html label. It
     * lives on the outer class rather than inside Gui so it can be exercised
     * headlessly by the engine test.
     */
    static String escapeHtml(String s) {
        return String.valueOf(s)
                .replace("&", "&amp;")
                .replace("<", "&lt;")
                .replace(">", "&gt;");
    }

    /**
     * With arguments the process runs headless through {@link Cli}; without
     * arguments it starts the Swing front end. This is the only place that
     * decides between the two, and Gui is the only class that touches Swing.
     */
    public static void main(String[] args) {
        if (args.length > 0) {
            System.exit(Cli.run(args));
        } else {
            Gui.launch();
        }
    }

    // =========================================================================
    // Result of one top-level queue item
    // =========================================================================

    /**
     * Outcome of a single top-level queue row. A row may expand into many
     * files, so the counts express partial directory outcomes.
     */
    static final class ItemResult {

        enum Kind { SHREDDED, CRYPTO_ERASED, PARTIAL, SKIPPED, FAILED, CANCELED }

        final Kind   kind;
        final int    filesDone;
        final int    filesSkipped;
        final int    filesFailed;
        final String detail;

        /**
         * CANCELED only: an item was part way through being destroyed when the
         * cancel arrived, so the detail names the phase it was interrupted in.
         * A cancel taken at one of the checkpoints between items leaves this
         * false, and nothing is then half destroyed. Always false for every
         * other kind.
         */
        final boolean itemInFlight;

        ItemResult(Kind kind, int filesDone, int filesSkipped, int filesFailed, String detail) {
            this(kind, filesDone, filesSkipped, filesFailed, detail, false);
        }

        ItemResult(Kind kind, int filesDone, int filesSkipped, int filesFailed, String detail,
                   boolean itemInFlight) {
            this.kind         = kind;
            this.filesDone    = filesDone;
            this.filesSkipped = filesSkipped;
            this.filesFailed  = filesFailed;
            this.detail       = (detail == null) ? "" : detail;
            this.itemInFlight = itemInFlight;
        }

        /**
         * Short text for the queue table's Status column and the CLI.
         *
         * Every kind carries its detail, including the two successful ones. A
         * row can succeed and still have something the user has to know about:
         * a hard-linked file destroys content that another name still points
         * at, and that warning would otherwise reach only the opt-in erasure
         * report. For a free-space wipe the detail is the only place the
         * leftover wipe files are named, and the counts on their own ("0 done,
         * 0 skipped, 1 failed") say nothing about how much disk is still
         * occupied or where.
         */
        String statusText() {
            switch (kind) {
                case SHREDDED:      return detail.isEmpty() ? "Done" : "Done: " + detail;
                case CRYPTO_ERASED: return detail.isEmpty()
                        ? "Done (crypto erased)" : "Done (crypto erased): " + detail;
                case PARTIAL: {
                    String head = "Partial (" + filesDone + " done, "
                            + filesSkipped + " skipped, " + filesFailed + " failed)";
                    return detail.isEmpty() ? head : head + ": " + detail;
                }
                case SKIPPED:       return detail.isEmpty() ? "Skipped" : "Skipped: " + detail;
                case FAILED:        return detail.isEmpty() ? "Failed"  : "Failed: "  + detail;
                case CANCELED:      return detail.isEmpty() ? "Canceled" : "Canceled: " + detail;
                default:            return kind.name();
            }
        }

        /** Longer text used by the erasure report. */
        String reportText() {
            StringBuilder sb = new StringBuilder(kind.name());
            sb.append(" (files done ").append(filesDone)
              .append(", skipped ").append(filesSkipped)
              .append(", failed ").append(filesFailed).append(')');
            if (!detail.isEmpty()) sb.append(" - ").append(detail);
            return sb.toString();
        }
    }

    // =========================================================================
    // Engine: no Swing or AWT usage anywhere in this class
    // =========================================================================

    static final class ShredEngine {

        static final int  BUFFER_SIZE        = 1048576;            // 1 MiB
        static final long MAX_WIPE_FILE_SIZE = 1024L * 1024L * 1024L; // 1 GiB
        static final long MIN_FREE_BYTES     = 1048576L;           // stop threshold

        private static final SecureRandom RANDOM = new SecureRandom();

        // ---------------------------------------------------------------------
        // Public engine types
        // ---------------------------------------------------------------------

        enum Algorithm {
            RANDOM      ("Random Data Overwrite (Custom Passes)",        "random", false),
            DOD3        ("3-Pass Overwrite (Zeros, Ones, Random)",       "dod3",   false),
            GUTMANN     ("Gutmann Method (35 Passes)",                   "gutmann",false),
            ZERO        ("Zero Overwrite (1 Pass + Verify)",             "zero",   true),
            NVME_PURGE  ("4-Pass Overwrite + Verify (Ends in Zeros)",    "nvme",   true),
            CRYPTO_ERASE("ChaCha20 Cryptographic Erase (1 Pass)",        "crypto", false);

            final String displayName;
            final String cliName;
            /** True when the algorithm's final pass writes zeros and should be verified. */
            final boolean requiresZeroVerification;

            Algorithm(String displayName, String cliName, boolean requiresZeroVerification) {
                this.displayName              = displayName;
                this.cliName                  = cliName;
                this.requiresZeroVerification = requiresZeroVerification;
            }

            /**
             * How many times each byte is written. The byte total adds the
             * verification read on top of this; the user-facing pass count
             * stays the write-pass count alone.
             */
            int passMultiplier(int randomPasses) {
                switch (this) {
                    case GUTMANN:      return 35;
                    case DOD3:         return 3;
                    case NVME_PURGE:   return 4;
                    case ZERO:         return 1;
                    case CRYPTO_ERASE: return 1;   // reads and writes each byte once
                    case RANDOM:       return Math.max(1, randomPasses);
                    default:           throw new IllegalStateException("Unhandled algorithm: " + name());
                }
            }

            /** Fixed pass count for the UI spinner, or -1 when user configurable. */
            int fixedPasses() {
                switch (this) {
                    case GUTMANN:      return 35;
                    case DOD3:         return 3;
                    case NVME_PURGE:   return 4;
                    case ZERO:         return 1;
                    case CRYPTO_ERASE: return 1;
                    case RANDOM:       return -1;
                    default:           throw new IllegalStateException("Unhandled algorithm: " + name());
                }
            }

            static Algorithm fromCliName(String name) {
                if (name == null) return null;
                for (Algorithm a : values()) {
                    if (a.cliName.equalsIgnoreCase(name.trim())) return a;
                }
                return null;
            }

            @Override public String toString() { return displayName; }
        }

        static final class Options {
            Algorithm algo           = Algorithm.RANDOM;
            int       randomPasses   = 3;
            boolean   writeReport    = false;
            Path      reportPath     = null;
            /** Cap for a free-space wipe, in bytes. 0 means unlimited. */
            long      wipeLimitBytes = 0L;
        }

        /**
         * Every callback fires on the engine's worker thread, never on the EDT.
         * A Swing listener must marshal to the EDT itself; the Gui adapter
         * throttles onProgress before posting and lets the others through.
         */
        interface Listener {
            /** Initial byte total plus later adjustments (skips, end of a wipe). */
            void onTotalBytes(long newTotal);
            /** Cumulative processed bytes; fired unthrottled by the engine. */
            void onProgress(long processedBytes);
            /** Start of one physical file; rowIndex is -1 during a free-space wipe. */
            void onFileStart(int rowIndex, String fileName, long plannedBytes);
            /** Bytes done within the current file. */
            void onFileProgress(long fileProcessedBytes);
            /** One top-level queue row finished. */
            void onItemResult(int rowIndex, ItemResult r);
            /** Always fired, from the engine's finally block. */
            void onFinished(int failures, boolean canceled);
        }

        /** Listener that does nothing, so the engine never has to null-check. */
        static final Listener NULL_LISTENER = new Listener() {
            @Override public void onTotalBytes(long newTotal) { }
            @Override public void onProgress(long processedBytes) { }
            @Override public void onFileStart(int rowIndex, String fileName, long plannedBytes) { }
            @Override public void onFileProgress(long fileProcessedBytes) { }
            @Override public void onItemResult(int rowIndex, ItemResult r) { }
            @Override public void onFinished(int failures, boolean canceled) { }
        };

        /**
         * Thrown by checkpoint() once cancellation is requested. It unwinds
         * through try-with-resources, so the exclusive file lock is released
         * even when the cancel arrives while the worker is paused, and it is
         * caught per item, which records CANCELED and leaves the file alone.
         */
        private static final class CancelException extends RuntimeException {
            private static final long serialVersionUID = 4001L;
            CancelException() { super("canceled", null, false, false); }
        }

        // ---------------------------------------------------------------------
        // Engine state
        // ---------------------------------------------------------------------

        private final Object        pauseLock       = new Object();
        private final AtomicBoolean cancelRequested = new AtomicBoolean(false);
        private volatile boolean    paused          = false;

        private volatile Listener listener = NULL_LISTENER;

        /**
         * The one read and write buffer for a whole run. A run uses a single
         * engine on a single worker thread, so shredFile, verifyZeroFill and
         * performCryptoErase can share it instead of allocating 1 MiB per file.
         */
        private final byte[] ioBuffer = new byte[BUFFER_SIZE];

        /** Phase of the file currently in flight; used to word a cancel accurately. */
        private static final int PHASE_IDLE         = 0;
        private static final int PHASE_BEFORE_WRITE = 1;
        private static final int PHASE_OVERWRITE    = 2;
        private static final int PHASE_VERIFY       = 3;
        /** Every write and any verification finished; only the rename and delete are left. */
        private static final int PHASE_DONE         = 4;
        private int filePhase = PHASE_IDLE;

        private volatile long totalBytes         = 0L;
        private volatile long processedBytes     = 0L;
        private volatile long fileProcessedBytes = 0L;

        private volatile long startTimeMs   = 0L;
        private long          pausedTotalMs = 0L;   // guarded by pauseLock
        private long          pauseStartMs  = 0L;   // guarded by pauseLock

        // Erasure report material
        private final List<String[]> reportRows = new ArrayList<>();
        private String  reportAlgoLine  = "";
        private String  reportPassLine  = "";
        private String  reportModeLine  = "";
        private String  reportStartedAt = "";
        private String  lastReportError = null;

        // ---------------------------------------------------------------------
        // Control
        // ---------------------------------------------------------------------

        void requestCancel() {
            synchronized (pauseLock) {
                cancelRequested.set(true);
                if (paused) {
                    paused = false;
                    pausedTotalMs += System.currentTimeMillis() - pauseStartMs;
                }
                pauseLock.notifyAll();
            }
        }

        void setPaused(boolean p) {
            synchronized (pauseLock) {
                if (p == paused) return;
                paused = p;
                if (p) {
                    pauseStartMs = System.currentTimeMillis();
                } else {
                    pausedTotalMs += System.currentTimeMillis() - pauseStartMs;
                    pauseLock.notifyAll();
                }
            }
        }

        boolean isPaused()          { return paused; }
        boolean isCancelRequested() { return cancelRequested.get(); }
        long    getTotalBytes()     { return totalBytes; }
        long    getProcessedBytes() { return processedBytes; }
        String  getLastReportError(){ return lastReportError; }

        /**
         * Names the exception type as well as its message. A java.nio
         * FileSystemException often carries nothing but the path, so the bare
         * message reads like a line announcing where the report was written.
         */
        private static String reportErrorText(IOException ex) {
            String msg = ex.getMessage();
            return (msg == null || msg.isEmpty())
                    ? ex.getClass().getSimpleName()
                    : ex.getClass().getSimpleName() + ": " + msg;
        }

        /** Elapsed time with paused intervals removed; speed and ETA use this. */
        long getActiveElapsedMillis() {
            long start = startTimeMs;
            if (start == 0L) return 0L;
            synchronized (pauseLock) {
                long elapsed = System.currentTimeMillis() - start;
                long idle    = pausedTotalMs;
                if (paused) idle += System.currentTimeMillis() - pauseStartMs;
                return Math.max(0L, elapsed - idle);
            }
        }

        /**
         * Pause and cancel checkpoint, called between chunk writes. The wait
         * loop re-tests both flags, so it is safe against spurious wakeups, and
         * requestCancel notifies under the same monitor, so a cancel that
         * arrives while paused is never missed.
         */
        private void checkpoint() {
            if (cancelRequested.get()) throw new CancelException();
            synchronized (pauseLock) {
                while (paused && !cancelRequested.get()) {
                    try {
                        pauseLock.wait();
                    } catch (InterruptedException ie) {
                        Thread.currentThread().interrupt();
                        throw new CancelException();
                    }
                }
            }
            if (cancelRequested.get()) throw new CancelException();
        }

        private void resetRun(Listener l) {
            this.listener           = (l == null) ? NULL_LISTENER : l;
            this.cancelRequested.set(false);
            synchronized (pauseLock) {
                paused        = false;
                pausedTotalMs = 0L;
                pauseStartMs  = 0L;
            }
            totalBytes         = 0L;
            processedBytes     = 0L;
            fileProcessedBytes = 0L;
            filePhase          = PHASE_IDLE;
            startTimeMs        = System.currentTimeMillis();
            lastReportError    = null;
            reportRows.clear();
            reportStartedAt = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss Z", Locale.ROOT)
                    .format(new Date());
        }

        private void recordProgress(int bytes) {
            // The first recorded chunk of a file is the point where its old
            // contents stop being intact, which is what a cancel note reports.
            if (filePhase == PHASE_BEFORE_WRITE) filePhase = PHASE_OVERWRITE;
            processedBytes     += bytes;
            fileProcessedBytes += bytes;
            listener.onProgress(processedBytes);
            listener.onFileProgress(fileProcessedBytes);
        }

        private void adjustTotal(long delta) {
            totalBytes += delta;
            if (totalBytes < 0L) totalBytes = 0L;
            listener.onTotalBytes(totalBytes);
        }

        // ---------------------------------------------------------------------
        // Queue expansion
        // ---------------------------------------------------------------------

        /** One top-level queue row plus the physical work it expands into. */
        private static final class Row {
            final File       item;
            final List<File> files = new ArrayList<>();
            final List<File> dirs  = new ArrayList<>();
            /**
             * Entries the scan could not read, one message each. These are
             * per-entry problems, so they are carried through to the row's
             * counters instead of aborting the whole scan; the readable files
             * beside them still get shredded. A set, so an entry that fails in
             * more than one way is still reported once.
             */
            final Set<String> scanFailures = new LinkedHashSet<>();
            /**
             * Advisory notes from the scan, such as a file that carries more
             * than one hard-linked name. These are not failures: they are
             * carried into the row's detail without touching its counters.
             */
            final Set<String> scanNotes = new LinkedHashSet<>();
            boolean  missing   = false;
            boolean  duplicate = false;
            String   scanError = null;
            long     sizeBytes = 0L;
            boolean  isDir     = false;
            Row(File item) { this.item = item; }
        }

        /**
         * True when the path points somewhere else on disk: a symbolic link, an
         * NTFS directory junction, or any other redirecting reparse point.
         *
         * Files.isSymbolicLink is not enough on Windows. It only reports true for
         * the symlink reparse tag, so a junction made with "mklink /J" reports
         * false while its attributes still say "directory". A plain directory
         * walk therefore opens it and enumerates the target's contents, which
         * would shred files far outside the selected folder. Junctions exist in
         * every user profile by default, so this is not an exotic case.
         *
         * The test compares where the entry resolves to against where it sits:
         * the parent is resolved for real too, so an ancestor that is itself a
         * junction, a substituted drive letter, or a differently cased path does
         * not make ordinary entries look redirected. Only directories are
         * resolved this way; a redirecting file is already excluded by the
         * regular-file check, and resolving one could pull a cloud placeholder
         * down needlessly.
         */
        static boolean isLinkOrJunction(Path p) throws IOException {
            if (Files.isSymbolicLink(p)) return true;
            if (!Files.isDirectory(p, LinkOption.NOFOLLOW_LINKS)) return false;
            Path abs    = p.toAbsolutePath().normalize();
            Path parent = abs.getParent();
            if (parent == null) return false;   // a drive or filesystem root
            return !abs.toRealPath().equals(parent.toRealPath().resolve(abs.getFileName()));
        }

        /** The regular files and the sub-directories of one tree, from one walk. */
        static final class Scan {
            final List<File> files = new ArrayList<>();
            final List<File> dirs  = new ArrayList<>();
        }

        /**
         * Recursively expands a directory into its regular files and its
         * sub-directories in a single walk. Links and junctions are never
         * entered, which needs walkFileTree: Files.walk has no way to skip a
         * subtree. Directories come back deepest first, ready for post-shred
         * deletion, and are neither entered nor listed when they redirect.
         *
         * An entry that cannot be read is recorded and the walk carries on. The
         * default SimpleFileVisitor rethrows instead, which would let a single
         * ACL-restricted subfolder, a System Volume Information directory or a
         * folder locked by another process abort the whole scan and leave every
         * readable file in the tree untouched.
         *
         * scanNotes, when given, collects advisory findings such as hard links.
         */
        Scan collectTree(File dir, Collection<String> scanFailures,
                         Collection<String> scanNotes) throws IOException {
            final Scan scan = new Scan();
            Files.walkFileTree(dir.toPath(), EnumSet.noneOf(FileVisitOption.class),
                    Integer.MAX_VALUE, new SimpleFileVisitor<Path>() {

                @Override public FileVisitResult preVisitDirectory(Path p, BasicFileAttributes a) {
                    // Walking a large tree can take minutes, so pause and cancel
                    // have to be honoured here as well. The CancelException
                    // unwinds straight out of walkFileTree; it is deliberately
                    // raised before the try below, which swallows runtime
                    // exceptions from the link test.
                    checkpoint();
                    // isLinkOrJunction resolves the real path, which can fail on
                    // a directory that opens but will not resolve. Letting that
                    // out would abort the walk through a second door.
                    try {
                        if (isLinkOrJunction(p)) return FileVisitResult.SKIP_SUBTREE;
                    } catch (IOException | RuntimeException ex) {
                        scanFailures.add(scanNote("Could not resolve", p, ex));
                        return FileVisitResult.SKIP_SUBTREE;
                    }
                    scan.dirs.add(p.toFile());
                    return FileVisitResult.CONTINUE;
                }

                @Override public FileVisitResult visitFile(Path p, BasicFileAttributes a) {
                    checkpoint();
                    if (!Files.isSymbolicLink(p)
                            && Files.isRegularFile(p, LinkOption.NOFOLLOW_LINKS)) {
                        scan.files.add(p.toFile());
                        if (scanNotes != null) {
                            String note = hardLinkNote(p);
                            if (note != null) scanNotes.add(note);
                        }
                    }
                    return FileVisitResult.CONTINUE;
                }

                @Override public FileVisitResult visitFileFailed(Path p, IOException ex) {
                    scanFailures.add(scanNote("Could not read", p, ex));
                    return FileVisitResult.CONTINUE;
                }

                @Override public FileVisitResult postVisitDirectory(Path p, IOException ex) {
                    if (ex != null) scanFailures.add(scanNote("Could not finish reading", p, ex));
                    return FileVisitResult.CONTINUE;
                }
            });
            scan.dirs.sort((a, b) -> Integer.compare(
                    b.getAbsolutePath().length(), a.getAbsolutePath().length()));
            return scan;
        }

        /** The regular files of a tree; the walk itself is collectTree. */
        List<File> collectFiles(File dir) throws IOException {
            return collectFiles(dir, new ArrayList<String>());
        }

        List<File> collectFiles(File dir, Collection<String> scanFailures) throws IOException {
            return collectTree(dir, scanFailures, null).files;
        }

        /**
         * Best-effort warning that a file carries more than one name. Only the
         * queued name is removed, while the shared content is destroyed for
         * every other name too. The unix:nlink attribute is unavailable on
         * Windows and on some file systems, so a failure here is silent: this
         * can warn, it cannot make the operation safe.
         */
        private static String hardLinkNote(Path p) {
            try {
                Object value = Files.getAttribute(p, "unix:nlink");
                if (value instanceof Number) {
                    long links = ((Number) value).longValue();
                    if (links > 1L) {
                        return p.getFileName() + " has " + links + " hard-linked names;"
                                + " shredding destroys the shared content but removes"
                                + " only this name";
                    }
                }
            } catch (UnsupportedOperationException | IOException ignored) {
                // Not available on this platform or file system.
            }
            return null;
        }

        /** One scan problem, worded the same way wherever it is discovered. */
        private static String scanNote(String what, Path p, Exception ex) {
            String reason = (ex == null || ex.getMessage() == null)
                    ? (ex == null ? "unknown error" : ex.getClass().getSimpleName())
                    : ex.getMessage();
            return what + ": " + p + " (" + reason + ")";
        }

        private static String canonicalKey(File f) {
            try {
                return f.getCanonicalPath();
            } catch (IOException ex) {
                return f.getAbsolutePath();
            }
        }

        /**
         * Expands the queue and removes duplicates by canonical path, so a queue
         * holding both a folder and a file inside it processes that file once.
         * The first row that claims a path keeps it.
         */
        private List<Row> expand(List<File> topLevelItems) {
            List<Row>   rows      = new ArrayList<>();
            Set<String> seenFiles = new HashSet<>();
            Set<String> seenDirs  = new HashSet<>();

            for (File item : topLevelItems) {
                Row row = new Row(item);
                try {
                    boolean link = isLinkOrJunction(item.toPath());
                    if (!item.exists()) {
                        row.missing = true;
                    } else if (link) {
                        row.duplicate = true;   // links and junctions are never followed
                        row.scanError = "Link or junction, not followed";
                    } else if (item.isDirectory()) {
                        row.isDir = true;
                        Scan scan = collectTree(item, row.scanFailures, row.scanNotes);
                        for (File f : scan.files) {
                            if (seenFiles.add(canonicalKey(f))) {
                                row.files.add(f);
                                row.sizeBytes += f.length();
                            }
                        }
                        for (File d : scan.dirs) {
                            if (seenDirs.add(canonicalKey(d))) row.dirs.add(d);
                        }
                    } else if (item.isFile()) {
                        if (seenFiles.add(canonicalKey(item))) {
                            row.files.add(item);
                            row.sizeBytes = item.length();
                            String note = hardLinkNote(item.toPath());
                            if (note != null) row.scanNotes.add(note);
                        } else {
                            row.duplicate = true;
                            row.scanError = "Already covered by an earlier queue item";
                        }
                    } else {
                        row.missing = true;
                    }
                } catch (IOException | UncheckedIOException ex) {
                    row.scanError = "Scan error: " + ex.getMessage();
                } catch (InvalidPathException ex) {
                    // File.toPath rejects characters the platform does not allow
                    // in a path, and it does so with an unchecked exception. A
                    // CLI argument such as "report<1>.txt" would otherwise unwind
                    // out of the whole run and leave every other queued item
                    // untouched, so it is recorded as this row's own failure.
                    row.scanError = "Invalid path: " + ex.getMessage();
                }
                rows.add(row);
            }
            return rows;
        }

        // ---------------------------------------------------------------------
        // Main shred run
        // ---------------------------------------------------------------------

        /**
         * Shreds every top-level item in order. Returns the number of rows that
         * failed. onFinished always fires from the finally block.
         */
        int run(List<File> topLevelItems, Options o, Listener l) {
            resetRun(l);
            final Listener out  = this.listener;
            final Options  opts = (o == null) ? new Options() : o;

            reportAlgoLine = opts.algo.displayName;
            reportPassLine = String.valueOf(opts.algo.passMultiplier(opts.randomPasses));
            reportModeLine = "File and directory shred";

            int     failures = 0;
            boolean canceled = false;

            try {
                List<Row> rows = expand(topLevelItems);

                // Every byte the run will move, not just the ones it writes: an
                // algorithm that verifies reads the whole file back afterwards,
                // and that read reports progress like any pass. The user-facing
                // pass count above stays the write-pass count alone.
                final int multiplier = opts.algo.passMultiplier(opts.randomPasses)
                        + (opts.algo.requiresZeroVerification ? 1 : 0);
                long planned = 0L;
                for (Row r : rows) {
                    for (File f : r.files) planned += f.length() * (long) multiplier;
                }
                totalBytes = planned;
                out.onTotalBytes(totalBytes);

                for (int i = 0; i < rows.size(); i++) {
                    Row row = rows.get(i);
                    Counters c = new Counters();
                    ItemResult result;
                    try {
                        result = processRow(i, row, opts, multiplier, c);
                    } catch (CancelException ce) {
                        canceled = true;
                        // The notes gathered before the cancel are kept. One of
                        // them can be the only record of where a destroyed file
                        // now sits, because a file that was overwritten and
                        // renamed but could not be deleted no longer carries its
                        // original name anywhere on disk.
                        result = new ItemResult(ItemResult.Kind.CANCELED,
                                c.done, c.skipped, c.failed, cancelDetail(c),
                                c.cancelNote != null);
                        recordReportRow(row, result);
                        out.onItemResult(i, result);
                        break;
                    }
                    if (result.kind == ItemResult.Kind.FAILED) failures++;
                    recordReportRow(row, result);
                    out.onItemResult(i, result);
                }

            } catch (CancelException ce) {
                // Raised by the checkpoints inside the queue scan, before any
                // row was started and before anything on disk was touched.
                canceled = true;
            } finally {
                if (opts.writeReport && opts.reportPath != null) {
                    try {
                        writeErasureReport(opts.reportPath);
                    } catch (IOException ex) {
                        lastReportError = reportErrorText(ex);
                    }
                }
                out.onFinished(failures, canceled);
            }
            return failures;
        }

        /** Package-private so the cancel wording can be checked headlessly. */
        static final class Counters {
            int done, skipped, failed;
            final List<String> notes = new ArrayList<>();

            /**
             * What a cancel did to the file that was in flight, if one was.
             * It is held apart from the notes because it must survive the
             * 400-character cap that joinNotes puts on them, and because its
             * absence is what tells a cancel taken between items from one
             * taken part way through destroying a file.
             */
            String cancelNote = null;
        }

        /** The row's notes as one bounded string, worded the same way everywhere. */
        private static String joinNotes(Counters c) {
            String detail = String.join("; ", c.notes);
            if (detail.length() > 400) detail = detail.substring(0, 397) + "...";
            return detail;
        }

        /**
         * Detail for a row that was cut short, keeping whatever it had recorded.
         * The phase note carries the state of the file that was in flight, so
         * the closing sentence only speaks for the items the run never reached:
         * those are untouched, which is not the same as the interrupted file
         * being intact.
         *
         * The phase note leads and is exempt from the 400-character cap. It is
         * the one sentence that says what happened to the file the cancel
         * landed on, and a row that had already gathered a screenful of notes
         * (a folder of read-only files, say) would otherwise push it out of the
         * capped text entirely and leave only wording that reads as if nothing
         * had been destroyed.
         */
        static String cancelDetail(Counters c) {
            String notes = joinNotes(c);
            StringBuilder sb = new StringBuilder();
            if (c.cancelNote != null) sb.append(c.cancelNote);
            if (!notes.isEmpty()) {
                if (sb.length() > 0) sb.append("; ");
                sb.append(notes);
            }
            if (sb.length() > 0) sb.append("; ");
            sb.append("items not yet reached were not touched");
            return sb.toString();
        }

        /**
         * What a cancel did to the file that was in flight, worded from the
         * phase it was interrupted in rather than from an assumption that a
         * file the run did not delete is still intact.
         *
         * Each note starts at the phase, not at the word "canceled": the kind
         * is printed ahead of the detail by both the status text and the
         * report, so repeating it would produce "Canceled: Canceled while...".
         */
        private static String cancelPhaseNote(File file, int phase) {
            switch (phase) {
                case PHASE_OVERWRITE:
                    return "Overwriting " + file.getName()
                            + " was interrupted: contents partially destroyed, file kept";
                case PHASE_VERIFY:
                    return "Verifying " + file.getName()
                            + " was interrupted: overwrite complete,"
                            + " verification incomplete, file kept";
                case PHASE_DONE:
                    // The checkpoint that guards the rename and the delete. Every
                    // pass, and any verification, already finished and passed, so
                    // reporting this as an interrupted overwrite would understate
                    // what happened to the contents.
                    return "Interrupted after " + file.getName() + " was processed"
                            + ": overwrite complete, file kept";
                default:
                    return "Interrupted before anything was written to " + file.getName()
                            + ": file untouched";
            }
        }

        private ItemResult processRow(int rowIndex, Row row, Options opts,
                                      int multiplier, Counters c) {
            final Listener out = this.listener;

            if (row.missing) {
                return new ItemResult(ItemResult.Kind.FAILED, 0, 0, 1, "Not found");
            }
            if (row.duplicate) {
                return new ItemResult(ItemResult.Kind.SKIPPED, 0, 1, 0,
                        row.scanError == null ? "Duplicate queue item" : row.scanError);
            }
            if (row.scanError != null) {
                return new ItemResult(ItemResult.Kind.FAILED, 0, 0, 1, row.scanError);
            }

            // Entries the scan could not read are real failures, but only for
            // themselves. They are counted here so the rest of the tree is
            // still processed and the row lands on FAILED with counts rather
            // than on the all-or-nothing scan-error path.
            for (String note : row.scanFailures) {
                c.failed++;
                c.notes.add(note);
            }

            for (File file : row.files) {
                checkpoint();
                long planned = file.length() * (long) multiplier;

                if (!file.exists()) {
                    c.failed++;
                    c.notes.add("Not found: " + file.getName());
                    continue;
                }
                if (!file.canWrite()) {
                    c.skipped++;
                    c.notes.add("Read-only: " + file.getName());
                    adjustTotal(-planned);   // keeps the overall bar able to reach 100%
                    continue;
                }

                fileProcessedBytes = 0L;
                out.onFileStart(rowIndex, file.getName(), planned);
                out.onFileProgress(0L);

                filePhase = PHASE_BEFORE_WRITE;
                try {
                    shredFile(file, opts.algo, opts.randomPasses);

                    if (opts.algo.requiresZeroVerification) {
                        filePhase = PHASE_VERIFY;
                        verifyZeroFill(file);
                    }

                    // The write loops only check between chunks, so a cancel that
                    // arrives during the final chunk of the final pass would
                    // otherwise fall straight through to the rename, the
                    // timestamp scrub and the delete, and the row would be
                    // reported as Done. A cancel means the file stays where it
                    // is, whichever chunk it landed on. The phase moves first so
                    // the note reports a finished overwrite rather than an
                    // interrupted one.
                    filePhase = PHASE_DONE;
                    checkpoint();

                    if (opts.algo == Algorithm.CRYPTO_ERASE) {
                        // The plaintext is gone from the file. Reading it back
                        // means recovering the key, whose local arrays were
                        // zeroed, though copies inside SecretKeySpec and the
                        // cipher's expanded key schedule stay on the JVM heap
                        // until garbage collection. The file keeps its name and
                        // timestamps and is never deleted.
                        c.done++;
                    } else {
                        File scrubbed = scrubFilename(file);
                        scrubMetadata(scrubbed);
                        if (deleteFilePermanently(scrubbed)) {
                            c.done++;
                        } else {
                            // The content is gone but the entry survives under the
                            // random name the scrub gave it, so the note has to
                            // point at what is really on disk.
                            c.failed++;
                            c.notes.add("Shredded but could not delete: " + file.getName()
                                    + ", now at " + scrubbed.getAbsolutePath());
                        }
                    }
                } catch (CancelException ce) {
                    // Cancel is not a per-file failure, it is the user stopping
                    // the run, so it has to leave this loop. The note is
                    // recorded first because the row is closed by the caller and
                    // this is the only place that still knows what state the
                    // file is in. It goes in its own field rather than into the
                    // notes so that cancelDetail can put it first and keep it
                    // whole, and so the GUI can tell that an item really was in
                    // flight when the cancel arrived.
                    c.cancelNote = cancelPhaseNote(file, filePhase);
                    throw ce;
                } catch (IOException | RuntimeException ex) {
                    // The exception class is named as well as its message: an
                    // unchecked exception often carries no message at all, and
                    // "file.bin: null" says nothing about what went wrong.
                    c.failed++;
                    c.notes.add(file.getName() + ": " + ex);
                } finally {
                    filePhase = PHASE_IDLE;
                }
            }

            // Crypto erase leaves every file in place, so its directories are not
            // empty and must not be removed.
            if (opts.algo != Algorithm.CRYPTO_ERASE) {
                for (File dir : row.dirs) {
                    checkpoint();
                    if (!dir.exists()) continue;

                    // Deepest first, so anything still in here is a leftover: a
                    // read-only file that was skipped, a file that failed to
                    // delete, or a link or junction that is never followed. Such
                    // a directory must keep its name, because renaming it would
                    // hide those leftovers under a random string and the report
                    // would then name a directory that no longer exists.
                    String[] kids = dir.list();
                    if (kids == null) {
                        c.failed++;
                        c.notes.add("Could not read directory: " + dir.getAbsolutePath());
                        continue;
                    }
                    if (kids.length > 0) {
                        // Everything still in here is something this run was
                        // never going to remove: a link or junction that is
                        // never followed, a read-only file that was skipped on
                        // purpose, or an entry whose own failure has already
                        // been counted above with its own note. Keeping the
                        // directory is the designed behaviour in all three
                        // cases, so it is recorded as a skip. Counting it as a
                        // failure would turn a correct run into FAILED, make
                        // the CLI exit non-zero and hide the fact that every
                        // file that was meant to be destroyed was destroyed.
                        c.skipped++;
                        c.notes.add("Directory kept, holds " + kids.length
                                + " item(s) that were deliberately left: "
                                + dir.getAbsolutePath());
                        continue;
                    }

                    try {
                        File scrubbed = scrubFilename(dir);
                        scrubMetadata(scrubbed);
                        if (!deleteFilePermanently(scrubbed)) {
                            c.failed++;
                            c.notes.add("Could not remove directory: " + dir.getAbsolutePath()
                                    + ", now at " + scrubbed.getAbsolutePath());
                        }
                    } catch (CancelException ce) {
                        throw ce;
                    } catch (IOException | RuntimeException ex) {
                        c.failed++;
                        c.notes.add("Directory error " + dir.getAbsolutePath() + ": " + ex);
                    }
                }
            }

            // Advisory findings from the scan. They describe the work rather
            // than a problem with it, so they are reported without touching the
            // counters that decide the row's status. They are added last on
            // purpose: joinNotes caps the detail at 400 characters, and a
            // handful of hard-linked files would otherwise spend that whole
            // budget on advice and push out the notes the loop produced, one of
            // which names where a destroyed but undeleted file now sits.
            c.notes.addAll(row.scanNotes);

            String detail = joinNotes(c);

            // Row-status precedence: any failure wins, then any skip, then success.
            if (c.failed > 0) {
                return new ItemResult(ItemResult.Kind.FAILED, c.done, c.skipped, c.failed, detail);
            }
            if (c.skipped > 0 && c.done == 0) {
                return new ItemResult(ItemResult.Kind.SKIPPED, c.done, c.skipped, c.failed, detail);
            }
            if (c.skipped > 0) {
                return new ItemResult(ItemResult.Kind.PARTIAL, c.done, c.skipped, c.failed, detail);
            }
            ItemResult.Kind ok = (opts.algo == Algorithm.CRYPTO_ERASE)
                    ? ItemResult.Kind.CRYPTO_ERASED : ItemResult.Kind.SHREDDED;
            return new ItemResult(ok, c.done, c.skipped, c.failed, detail);
        }

        // ---------------------------------------------------------------------
        // Shred dispatch
        // ---------------------------------------------------------------------

        void shredFile(File file, Algorithm algo, int randomPasses) throws IOException {
            if (!file.exists()) throw new IOException("File does not exist.");

            final long fileSize = file.length();
            if (fileSize == 0) return; // nothing to overwrite; caller handles deletion

            final byte[] buffer = ioBuffer;

            try (RandomAccessFile raf     = new RandomAccessFile(file, "rw");
                 FileChannel      channel = raf.getChannel();
                 FileLock         lock    = channel.tryLock()) {

                if (lock == null) throw new IOException("File is locked by another process.");

                switch (algo) {
                    case RANDOM:
                        for (int i = 0; i < Math.max(1, randomPasses); i++) {
                            overwriteRandom(raf, buffer, fileSize);
                        }
                        break;
                    case DOD3:
                        overwriteDoD3(raf, buffer, fileSize);
                        break;
                    case GUTMANN:
                        overwriteGutmann(raf, buffer, fileSize);
                        break;
                    case ZERO:
                        overwritePattern(raf, buffer, fileSize, (byte) 0x00);
                        break;
                    case NVME_PURGE:
                        overwriteNVMePurge(raf, buffer, fileSize);
                        break;
                    case CRYPTO_ERASE:
                        performCryptoErase(raf, fileSize, buffer);
                        break;
                    default:
                        // A new algorithm that reaches this point would be
                        // renamed, scrubbed and deleted without a single
                        // overwrite pass, and reported as done.
                        throw new IllegalStateException("Unhandled algorithm: " + algo.name());
                }
                channel.force(true);
            }
        }

        // ---------------------------------------------------------------------
        // Overwrite primitives
        // ---------------------------------------------------------------------

        /**
         * The chunk size is decided before the random bytes are generated, so a
         * short final chunk costs only the bytes it writes. Filling the whole
         * 1 MiB buffer first made a 1 KB file pay for 1 MiB of SecureRandom
         * output on every pass, eight times over under Gutmann.
         */
        void overwriteRandom(RandomAccessFile raf, byte[] buffer, long length) throws IOException {
            raf.seek(0);
            long written = 0;
            while (written < length) {
                checkpoint();
                int writeSize = (int) Math.min(buffer.length, length - written);
                if (writeSize == buffer.length) {
                    RANDOM.nextBytes(buffer);
                    raf.write(buffer, 0, writeSize);
                } else {
                    byte[] tail = new byte[writeSize];
                    RANDOM.nextBytes(tail);
                    raf.write(tail);
                }
                written += writeSize;
                recordProgress(writeSize);
            }
            raf.getFD().sync();
        }

        void overwritePattern(RandomAccessFile raf, byte[] buffer, long length, byte pattern)
                throws IOException {
            raf.seek(0);
            Arrays.fill(buffer, pattern);
            long written = 0;
            while (written < length) {
                checkpoint();
                int writeSize = (int) Math.min(buffer.length, length - written);
                raf.write(buffer, 0, writeSize);
                written += writeSize;
                recordProgress(writeSize);
            }
            raf.getFD().sync();
        }

        void overwriteCustomPattern(RandomAccessFile raf, byte[] buffer,
                                    long length, byte[] pattern) throws IOException {
            raf.seek(0);
            for (int i = 0; i < buffer.length; i++) buffer[i] = pattern[i % pattern.length];
            long written = 0;
            while (written < length) {
                checkpoint();
                int writeSize = (int) Math.min(buffer.length, length - written);
                raf.write(buffer, 0, writeSize);
                written += writeSize;
                recordProgress(writeSize);
            }
            raf.getFD().sync();
        }

        /**
         * The classic three-pass sequence historically attributed to
         * DoD 5220.22-M: zeros, then ones, then random. The current NISPOM
         * specifies no overwrite method, and this implementation does not
         * verify what it wrote.
         */
        void overwriteDoD3(RandomAccessFile raf, byte[] buffer, long length) throws IOException {
            overwritePattern(raf, buffer, length, (byte) 0x00);
            overwritePattern(raf, buffer, length, (byte) 0xFF);
            overwriteRandom (raf, buffer, length);
        }

        /**
         * Deterministic pattern passes 5 to 31 of the Gutmann method, listed in
         * the order the paper prints them. Passes 1 to 4 and 32 to 35 are
         * random. The paper specifies that passes 5 to 31 are written in a
         * random permutation, which overwriteGutmann performs per file; this
         * table itself stays in paper order.
         */
        static final byte[][] GUTMANN_PATTERNS = {
            {0x55, 0x55, 0x55},                              // 5
            {(byte) 0xAA, (byte) 0xAA, (byte) 0xAA},         // 6
            {(byte) 0x92, 0x49, 0x24},                       // 7
            {0x49, 0x24, (byte) 0x92},                       // 8
            {0x24, (byte) 0x92, 0x49},                       // 9
            {0x00},                                          // 10
            {0x11},                                          // 11
            {0x22},                                          // 12
            {0x33},                                          // 13
            {0x44},                                          // 14
            {0x55},                                          // 15
            {0x66},                                          // 16
            {0x77},                                          // 17
            {(byte) 0x88},                                   // 18
            {(byte) 0x99},                                   // 19
            {(byte) 0xAA},                                   // 20
            {(byte) 0xBB},                                   // 21
            {(byte) 0xCC},                                   // 22
            {(byte) 0xDD},                                   // 23
            {(byte) 0xEE},                                   // 24
            {(byte) 0xFF},                                   // 25
            {(byte) 0x92, 0x49, 0x24},                       // 26
            {0x49, 0x24, (byte) 0x92},                       // 27
            {0x24, (byte) 0x92, 0x49},                       // 28
            {(byte) 0x6D, (byte) 0xB6, (byte) 0xDB},         // 29
            {(byte) 0xB6, (byte) 0xDB, 0x6D},                // 30
            {(byte) 0xDB, 0x6D, (byte) 0xB6},                // 31
        };

        /**
         * Four random passes, the 27 deterministic patterns in a fresh random
         * permutation, then four more random passes. Permuting the pattern
         * passes is what the paper specifies, so the order differs from file to
         * file while the table above stays in paper order.
         */
        void overwriteGutmann(RandomAccessFile raf, byte[] buffer, long length) throws IOException {
            for (int i = 0; i < 4; i++) overwriteRandom(raf, buffer, length);
            List<byte[]> shuffled = new ArrayList<>(Arrays.asList(GUTMANN_PATTERNS));
            Collections.shuffle(shuffled, RANDOM);
            for (byte[] p : shuffled) overwriteCustomPattern(raf, buffer, length, p);
            for (int i = 0; i < 4; i++) overwriteRandom(raf, buffer, length);
        }

        /**
         * A 4-pass scheme of this tool's own design: a random 32-byte pattern,
         * its complement, random, then zeros. It is loosely motivated by the
         * discussion in SP 800-88 and is not a NIST technique. The last pass is
         * zeros, which enables post-write verification.
         */
        void overwriteNVMePurge(RandomAccessFile raf, byte[] buffer, long length) throws IOException {
            byte[] key        = new byte[32];
            byte[] complement = new byte[32];
            try {
                RANDOM.nextBytes(key);
                overwriteCustomPattern(raf, buffer, length, key);

                for (int i = 0; i < 32; i++) complement[i] = (byte) ~key[i];
                overwriteCustomPattern(raf, buffer, length, complement);

                overwriteRandom(raf, buffer, length);
                overwritePattern(raf, buffer, length, (byte) 0x00);
            } finally {
                // The patterns say nothing about the file, but leaving them on
                // the heap costs nothing to avoid.
                Arrays.fill(key,        (byte) 0);
                Arrays.fill(complement, (byte) 0);
            }
        }

        /**
         * ChaCha20 in-place cryptographic erase.
         *
         * A random 256-bit key and 96-bit nonce encrypt the file in place.
         * Without the key the ciphertext is computationally indistinguishable
         * from random noise. ChaCha20 ships in the standard JDK from Java 11, so
         * no extra dependency is needed.
         *
         * The local key and nonce arrays are zeroed in the finally block, but
         * copies inside SecretKeySpec and the cipher's expanded key schedule
         * stay on the JVM heap until garbage collection. Neither can be reached
         * from pure Java, so this is a limitation of the implementation and not
         * something the zeroing here removes.
         */
        void performCryptoErase(RandomAccessFile raf, long fileSize, byte[] inBuf)
                throws IOException {
            byte[] key   = new byte[32]; // 256-bit key
            byte[] nonce = new byte[12]; // 96-bit nonce required by ChaCha20

            try {
                RANDOM.nextBytes(key);
                RANDOM.nextBytes(nonce);

                Cipher cipher = Cipher.getInstance("ChaCha20");
                cipher.init(
                        Cipher.ENCRYPT_MODE,
                        new SecretKeySpec(key, "ChaCha20"),
                        new ChaCha20ParameterSpec(nonce, 0));

                raf.seek(0);
                long processed = 0;

                while (processed < fileSize) {
                    checkpoint();
                    raf.seek(processed);
                    int read = raf.read(inBuf, 0, (int) Math.min(inBuf.length, fileSize - processed));
                    if (read == -1) break;

                    byte[] encrypted = cipher.update(inBuf, 0, read);
                    // A provider that buffers instead of returning one output
                    // byte per input byte would leave a gap of untouched
                    // plaintext behind and put the rest of the file at the
                    // wrong offset. ChaCha20 is a stream cipher, so this cannot
                    // happen with the JDK provider, and a provider where it can
                    // must not be allowed to half-erase the file in silence.
                    if (encrypted == null || encrypted.length != read) {
                        throw new IOException("ChaCha20 provider returned "
                                + (encrypted == null ? 0 : encrypted.length)
                                + " bytes for " + read + " input bytes;"
                                + " refusing to leave plaintext behind");
                    }
                    raf.seek(processed);
                    raf.write(encrypted);
                    processed += read;
                    recordProgress(read);
                }

                byte[] finalBlock = cipher.doFinal();
                if (finalBlock != null && finalBlock.length > 0) {
                    // Every input byte has already been accounted for above, so
                    // a trailing block would be written past the end of the
                    // file and change its length. Same reasoning as above.
                    throw new IOException("ChaCha20 provider returned a final block of "
                            + finalBlock.length + " bytes past the end of the file;"
                            + " refusing to leave plaintext behind");
                }
                raf.getFD().sync();

            } catch (GeneralSecurityException ex) {
                throw new IOException("ChaCha20 crypto erase failed: " + ex.getMessage(), ex);
            } finally {
                // Wipe the key material and the last block of plaintext whatever
                // happened. The buffer is shared with the rest of the run, which
                // is safe: every later use fills it before reading it.
                Arrays.fill(key,   (byte) 0);
                Arrays.fill(nonce, (byte) 0);
                Arrays.fill(inBuf, (byte) 0);
            }
        }

        // ---------------------------------------------------------------------
        // Post-write zero-fill verification
        // ---------------------------------------------------------------------

        /**
         * Verifies that every byte in the file is 0x00. Only called after ZERO
         * and NVME_PURGE, both of which end with a zero-fill pass. The read is
         * reported as progress like any pass, and the run's byte total budgets
         * for it, so the bar keeps moving through a large file.
         *
         * The read goes back through the operating system after force(true), so
         * it confirms what the OS committed rather than what the physical
         * medium now holds.
         */
        void verifyZeroFill(File file) throws IOException {
            byte[] buffer = ioBuffer;
            try (RandomAccessFile raf = new RandomAccessFile(file, "r")) {
                long remaining = raf.length();
                long offset    = 0;
                while (remaining > 0) {
                    checkpoint();
                    int read = raf.read(buffer, 0, (int) Math.min(buffer.length, remaining));
                    if (read == -1) break;
                    for (int i = 0; i < read; i++) {
                        if (buffer[i] != 0) {
                            throw new IOException(
                                    "Zero-fill verification failed at byte offset " + (offset + i));
                        }
                    }
                    remaining -= read;
                    offset    += read;
                    recordProgress(read);
                }
            }
        }

        // ---------------------------------------------------------------------
        // Filename and metadata scrubbing, deletion
        // ---------------------------------------------------------------------

        /** Sets the file's timestamps to the Unix epoch. */
        void scrubMetadata(File file) {
            try {
                BasicFileAttributeView attrs = Files.getFileAttributeView(
                        file.toPath(), BasicFileAttributeView.class);
                FileTime epoch = FileTime.fromMillis(0);
                attrs.setTimes(epoch, epoch, epoch);
            } catch (IOException ignored) {
                // Non-fatal: some file systems do not support all timestamp attributes
            }
        }

        /**
         * Renames to random names before deletion, so the live directory entry
         * no longer carries the original name. Freed directory entries and the
         * file system journal may still retain it; renaming cannot remove those.
         */
        File scrubFilename(File file) throws IOException {
            Path current = file.toPath();
            for (int i = 0; i < 3; i++) {
                current = moveToRandomName(current);
            }
            return current.toFile();
        }

        /**
         * One rename to a free random name. A name that is already taken is not
         * a reason to stop: the item would then be left sitting under whichever
         * random name the previous rename gave it, and the caller's note would
         * still be naming the original. REPLACE_EXISTING is deliberately not
         * used, because it would destroy whatever already holds that name.
         */
        private Path moveToRandomName(Path current) throws IOException {
            for (int attempt = 0; attempt < 100; attempt++) {
                Path next = current.resolveSibling(generateRandomName());
                if (Files.exists(next)) continue;
                try {
                    try {
                        Files.move(current, next, StandardCopyOption.ATOMIC_MOVE);
                    } catch (AtomicMoveNotSupportedException ex) {
                        Files.move(current, next);
                    }
                    return next;
                } catch (FileAlreadyExistsException ex) {
                    // The exists() check above is racy, so the collision has to
                    // be handled here too. A fresh name is tried.
                    continue;
                } catch (IOException ex) {
                    throw new IOException("Could not rename " + current
                            + " to a random name: " + ex, ex);
                }
            }
            throw new IOException("Could not find a free random name for " + current
                    + " after 100 attempts");
        }

        boolean deleteFilePermanently(File file) {
            for (int i = 0; i < 3; i++) {
                try {
                    file.setWritable(true);
                    if (!Files.deleteIfExists(file.toPath())) {
                        // Nothing was there to delete. Both callers pass a path a
                        // rename has just created, so this means something else
                        // removed the entry first; the entry being gone is still
                        // the outcome that was asked for.
                        System.err.println("Delete target was already absent: " + file);
                    }
                    return true;
                } catch (IOException ex) {
                    System.err.println("Delete attempt " + (i + 1) + " failed: " + ex.getMessage());
                    try {
                        Thread.sleep(200);
                    } catch (InterruptedException ie) {
                        Thread.currentThread().interrupt();
                        return false;
                    }
                }
            }
            return false;
        }

        static String generateRandomName() {
            final String chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
            int length = 8 + RANDOM.nextInt(9); // 8 to 16 characters
            StringBuilder sb = new StringBuilder(length);
            for (int i = 0; i < length; i++) {
                sb.append(chars.charAt(RANDOM.nextInt(chars.length())));
            }
            return sb.toString();
        }

        // ---------------------------------------------------------------------
        // Free-space wipe
        // ---------------------------------------------------------------------

        /**
         * Fills the free space of the volume holding targetDir with a single
         * random pass, then removes everything it wrote. Work happens inside a
         * wipe-<random> sub-directory of the picked folder, which avoids the
         * permission problems of writing at a drive root.
         *
         * Stop conditions: the byte limit is reached, usable space drops below
         * 1 MiB, or an IOException arrives after at least one chunk has been
         * written. Java exposes no portable out-of-space errno, so a failure on
         * the very first chunk is treated as a real error instead.
         *
         * Cleanup always runs, and its outcome is checked. Anything that could
         * not be removed is named in the result, so the queue, the CLI output
         * and the erasure report never claim disk space was given back when it
         * was not.
         */
        void wipeFreeSpace(File targetDir, Options o, Listener l) {
            resetRun(l);
            final Listener out  = this.listener;
            final Options  opts = (o == null) ? new Options() : o;

            reportAlgoLine = "Single pass random fill of free space";
            reportPassLine = "1";
            reportModeLine = "Free space wipe";

            final long limit = Math.max(0L, opts.wipeLimitBytes);

            List<File> created  = new ArrayList<>();
            File       wipeDir  = null;
            long       written  = 0L;
            int        failures = 0;
            boolean    canceled = false;
            String     failNote = null;

            try {
                if (targetDir == null || !targetDir.isDirectory()) {
                    throw new IOException("Wipe target is not a directory.");
                }

                wipeDir = new File(targetDir, "wipe-" + generateRandomName());
                if (!wipeDir.mkdirs()) {
                    throw new IOException("Could not create the working folder: "
                            + wipeDir.getAbsolutePath());
                }
                wipeDir.deleteOnExit();   // registered first so it is removed last

                // getUsableSpace reports 0 for a volume that is genuinely full,
                // but also when the size cannot be determined, which is what
                // happens on some network and substituted volumes. Reading that
                // as "already full" would stop the fill before a single byte was
                // written, so 0 is treated as unknown: the run goes ahead with an
                // indeterminate total and no percentage.
                long usable = targetDir.getUsableSpace();
                long total  = (usable > 0L)
                        ? ((limit > 0) ? Math.min(usable, limit) : usable)
                        : 0L;
                totalBytes = Math.max(0L, total);
                out.onTotalBytes(totalBytes);

                final byte[] buffer = new byte[BUFFER_SIZE];
                int  index    = 0;
                boolean stop  = false;

                while (!stop) {
                    checkpoint();
                    if (limit > 0 && written >= limit) break;

                    // Only a positive reading proves the volume is nearly full. A
                    // zero reading is unknown, and the fill then stops on the
                    // first write failure after a successful chunk instead.
                    long freeNow = targetDir.getUsableSpace();
                    if (freeNow > 0L && freeNow < MIN_FREE_BYTES) break;

                    long fileTarget = MAX_WIPE_FILE_SIZE;
                    if (limit > 0) fileTarget = Math.min(fileTarget, limit - written);
                    if (fileTarget <= 0) break;

                    File wipeFile = new File(wipeDir, "wipe-" + index++ + ".tmp");
                    wipeFile.deleteOnExit();
                    created.add(wipeFile);

                    fileProcessedBytes = 0L;
                    out.onFileStart(-1, wipeFile.getName(), fileTarget);
                    out.onFileProgress(0L);

                    try (RandomAccessFile raf = new RandomAccessFile(wipeFile, "rw")) {
                        long fileWritten = 0L;
                        while (fileWritten < fileTarget) {
                            checkpoint();
                            // Same reorder as overwriteRandom: the chunk size is
                            // known before the random bytes are generated, so a
                            // short final chunk costs only what it writes.
                            int chunk = (int) Math.min(buffer.length, fileTarget - fileWritten);
                            if (chunk == buffer.length) {
                                RANDOM.nextBytes(buffer);
                                raf.write(buffer, 0, chunk);
                            } else {
                                byte[] tail = new byte[chunk];
                                RANDOM.nextBytes(tail);
                                raf.write(tail);
                            }
                            fileWritten += chunk;
                            written     += chunk;
                            recordProgress(chunk);
                        }
                        raf.getFD().sync();
                    } catch (IOException ex) {
                        if (written > 0L) {
                            stop = true;      // treated as the volume being full
                        } else {
                            failures = 1;
                            failNote = ex.getMessage();
                            stop = true;
                        }
                    }

                    // Re-adjust the total as the real free space drifts
                    if (!stop) {
                        long nowUsable = targetDir.getUsableSpace();
                        long newTotal;
                        if (nowUsable > 0L) {
                            long remaining = (limit > 0) ? (limit - written) : nowUsable;
                            newTotal = written + Math.max(0L, Math.min(nowUsable, remaining));
                        } else {
                            newTotal = 0L;   // still unknown, so stay indeterminate
                        }
                        if (newTotal != totalBytes) {
                            totalBytes = newTotal;
                            out.onTotalBytes(totalBytes);
                        }
                    }
                }

            } catch (CancelException ce) {
                canceled = true;
            } catch (IOException ex) {
                failures = 1;
                failNote = ex.getMessage();
            } finally {
                // Always clean up, including after a cancel. Every delete is
                // checked: a wipe file that survives is up to 1 GiB of disk the
                // user does not get back, and an open handle held by a virus
                // scanner or the search indexer is the ordinary way that
                // happens. Reporting a clean run in that state would put a
                // false statement in the erasure report.
                int    leftFiles     = 0;
                long   leftBytes     = 0L;
                String firstLeftover = null;
                for (int i = created.size() - 1; i >= 0; i--) {
                    File f    = created.get(i);
                    long size = f.length();
                    try {
                        Files.deleteIfExists(f.toPath());
                    } catch (IOException ignored) {
                        f.delete();
                    }
                    if (f.exists()) {
                        leftFiles++;
                        leftBytes += size;
                        if (firstLeftover == null) firstLeftover = f.getAbsolutePath();
                    }
                }
                boolean dirLeft = false;
                if (wipeDir != null) {
                    try {
                        Files.deleteIfExists(wipeDir.toPath());
                    } catch (IOException ignored) {
                        wipeDir.delete();
                    }
                    dirLeft = wipeDir.exists();
                }

                String leftoverNote = null;
                if (leftFiles > 0) {
                    leftoverNote = leftFiles + " wipe file(s) could not be removed, still using "
                            + formatSize(leftBytes) + " at " + firstLeftover;
                } else if (dirLeft) {
                    leftoverNote = "The working folder could not be removed: "
                            + wipeDir.getAbsolutePath();
                }

                // Land the bar exactly on what was really written
                totalBytes = written;
                out.onTotalBytes(totalBytes);

                ItemResult.Kind kind;
                String          detail;
                if (canceled) {
                    kind   = ItemResult.Kind.CANCELED;
                    detail = (failNote != null) ? failNote
                            : (formatSize(written) + " of random data written"
                               + (leftoverNote == null ? " and removed" : ""));
                    if (leftoverNote != null) detail = detail + ". " + leftoverNote;
                } else if (failures > 0) {
                    kind   = ItemResult.Kind.FAILED;
                    detail = (failNote != null) ? failNote : "Free space wipe failed";
                    if (leftoverNote != null) detail = detail + ". " + leftoverNote;
                } else if (written == 0L) {
                    // Nothing was overwritten, so this is not a success no matter
                    // what the volume reported. Saying otherwise would tell a user
                    // or a script that the sanitisation ran when it did not.
                    failures = 1;
                    kind     = ItemResult.Kind.FAILED;
                    detail   = "Nothing was written: the volume reported no usable free"
                             + " space to overwrite. Check the target folder and the drive.";
                    if (leftoverNote != null) detail = detail + ". " + leftoverNote;
                } else if (leftoverNote != null) {
                    // The fill itself worked, so this is not a plain failure,
                    // but the volume is still holding the wipe data and the
                    // caller has to be told exactly what is left where.
                    failures = 1;
                    kind     = ItemResult.Kind.PARTIAL;
                    detail   = formatSize(written) + " of random data written, but cleanup"
                             + " did not finish: " + leftoverNote;
                } else {
                    kind   = ItemResult.Kind.SHREDDED;
                    detail = formatSize(written) + " of random data written and removed";
                }
                ItemResult r = new ItemResult(kind, 0, 0, failures, detail);
                reportRows.add(new String[]{
                        targetDir == null ? "(no target)" : targetDir.getAbsolutePath(),
                        formatSize(written) + " (" + written + " bytes)",
                        r.reportText() });
                out.onItemResult(-1, r);

                if (opts.writeReport && opts.reportPath != null) {
                    try {
                        writeErasureReport(opts.reportPath);
                    } catch (IOException ex) {
                        lastReportError = reportErrorText(ex);
                    }
                }
                out.onFinished(failures, canceled);
            }
        }

        // ---------------------------------------------------------------------
        // Erasure report
        // ---------------------------------------------------------------------

        private void recordReportRow(Row row, ItemResult r) {
            String size = row.isDir
                    ? (formatSize(row.sizeBytes) + " in " + row.files.size() + " file(s)")
                    : (formatSize(row.sizeBytes) + " (" + row.sizeBytes + " bytes)");
            reportRows.add(new String[]{ row.item.getAbsolutePath(), size, r.reportText() });
        }

        /** Writes the plain-text erasure report for the run that just finished. */
        void writeErasureReport(Path path) throws IOException {
            StringBuilder sb = new StringBuilder();
            sb.append(APP_NAME).append(' ').append(APP_VERSION).append(" erasure report\n");
            sb.append("Generated: ").append(reportStartedAt).append('\n');
            sb.append("Mode: ").append(reportModeLine).append('\n');
            sb.append("Algorithm: ").append(reportAlgoLine).append('\n');
            sb.append("Passes: ").append(reportPassLine).append('\n');
            sb.append("Bytes processed: ").append(processedBytes).append('\n');
            sb.append('\n');
            sb.append("Items:\n");
            if (reportRows.isEmpty()) {
                sb.append("  (none)\n");
            } else {
                for (String[] row : reportRows) {
                    sb.append("  ").append(row[0]).append('\n');
                    sb.append("    Size:   ").append(row[1]).append('\n');
                    sb.append("    Result: ").append(row[2]).append('\n');
                }
            }
            sb.append('\n');
            sb.append("Note: on solid state drives, USB flash media, SD cards and other\n");
            sb.append("flash storage, wear levelling and over-provisioning mean an overwrite\n");
            sb.append("may not reach every physical copy of the data. Full-disk encryption or\n");
            sb.append("the drive's own secure erase command is the reliable option there.\n");

            Path parent = path.toAbsolutePath().getParent();
            if (parent != null) Files.createDirectories(parent);
            Files.write(path, sb.toString().getBytes(java.nio.charset.StandardCharsets.UTF_8));
        }

        // ---------------------------------------------------------------------
        // Formatting helpers
        // ---------------------------------------------------------------------

        static String formatSize(long bytes) {
            if (bytes < 1024L) return bytes + " B";
            double kb = bytes / 1024.0;
            if (kb < 1024.0) return String.format(Locale.ROOT, "%.1f KB", kb);
            double mb = kb / 1024.0;
            if (mb < 1024.0) return String.format(Locale.ROOT, "%.1f MB", mb);
            return String.format(Locale.ROOT, "%.1f GB", mb / 1024.0);
        }

        static String formatTime(double seconds) {
            if (Double.isNaN(seconds) || Double.isInfinite(seconds) || seconds < 0) {
                return "--:--:--";
            }
            if (seconds > 359999) return "99:59:59";
            int h = (int) (seconds / 3600);
            int m = (int) ((seconds % 3600) / 60);
            int s = (int) (seconds % 60);
            return String.format(Locale.ROOT, "%02d:%02d:%02d", h, m, s);
        }
    }

    // =========================================================================
    // Headless command line front end. Never touches Swing or AWT.
    // =========================================================================

    static final class Cli {

        private Cli() { }

        static final int EXIT_OK      = 0;
        static final int EXIT_FAILURE = 1;
        static final int EXIT_USAGE   = 2;

        static void printUsage(java.io.PrintStream o) {
            o.println(APP_NAME + " " + APP_VERSION);
            o.println();
            o.println("Usage:");
            o.println("  java -jar DataShredderV4.jar --algo <name> [--passes N] [--report <path>] --yes <paths...>");
            o.println("  java -jar DataShredderV4.jar --wipe-free <dir> [--limit <MB>] [--report <path>] --yes");
            o.println("  java -jar DataShredderV4.jar --help");
            o.println();
            o.println("Algorithms:");
            for (ShredEngine.Algorithm a : ShredEngine.Algorithm.values()) {
                o.println(String.format(Locale.ROOT, "  %-8s %s", a.cliName, a.displayName));
            }
            o.println();
            o.println("Options:");
            o.println("  --algo <name>     Overwrite algorithm. Default: random");
            o.println("  --passes N        Pass count for the random algorithm (1 to 100). Default: 3");
            o.println("  --report <path>   Write a plain text erasure report to <path>");
            o.println("  --wipe-free <dir> Fill the free space of the volume holding <dir>, then clean up");
            o.println("  --limit <MB>      Cap the free space wipe at <MB> megabytes");
            o.println("  --yes             Required to actually destroy anything");
            o.println("  --help            Show this text");
            o.println();
            o.println("Exit codes: 0 all ok, 1 some items failed, 2 usage error or refused");
            o.println();
            o.println("Running with no arguments at all starts the graphical interface.");
        }

        static int run(String[] args) {
            ShredEngine.Options opts = new ShredEngine.Options();
            List<String> paths       = new ArrayList<>();
            boolean      confirmed   = false;
            String       wipeTarget  = null;
            boolean      passesGiven = false;

            for (int i = 0; i < args.length; i++) {
                String a = args[i];
                switch (a) {
                    case "--help":
                    case "-h":
                        printUsage(System.out);
                        return EXIT_OK;
                    case "--yes":
                        confirmed = true;
                        break;
                    case "--algo": {
                        if (++i >= args.length) return usageError("--algo needs a value");
                        ShredEngine.Algorithm parsed = ShredEngine.Algorithm.fromCliName(args[i]);
                        if (parsed == null) return usageError("Unknown algorithm: " + args[i]);
                        opts.algo = parsed;
                        break;
                    }
                    case "--passes": {
                        if (++i >= args.length) return usageError("--passes needs a value");
                        try {
                            int n = Integer.parseInt(args[i].trim());
                            if (n < 1 || n > 100) return usageError("--passes must be 1 to 100");
                            opts.randomPasses = n;
                            passesGiven = true;
                        } catch (NumberFormatException ex) {
                            return usageError("--passes must be a whole number");
                        }
                        break;
                    }
                    case "--report": {
                        if (++i >= args.length) return usageError("--report needs a path");
                        try {
                            opts.reportPath  = Paths.get(args[i]);
                            opts.writeReport = true;
                        } catch (RuntimeException ex) {
                            return usageError("Invalid report path: " + args[i]);
                        }
                        break;
                    }
                    case "--wipe-free": {
                        if (++i >= args.length) return usageError("--wipe-free needs a directory");
                        wipeTarget = args[i];
                        break;
                    }
                    case "--limit": {
                        if (++i >= args.length) return usageError("--limit needs a value in MB");
                        try {
                            // The upper bound matters: without it the multiply
                            // below overflows to a negative value, which the
                            // engine reads back as "no limit" and turns a capped
                            // wipe into one that fills the whole volume.
                            final long maxMb = Long.MAX_VALUE / (1024L * 1024L);
                            long mb = Long.parseLong(args[i].trim());
                            if (mb < 1 || mb > maxMb) {
                                return usageError("--limit must be 1 to " + maxMb + " MB");
                            }
                            opts.wipeLimitBytes = mb * 1024L * 1024L;
                        } catch (NumberFormatException ex) {
                            return usageError("--limit must be a whole number of MB");
                        }
                        break;
                    }
                    default:
                        if (a.startsWith("--")) return usageError("Unknown option: " + a);
                        paths.add(a);
                        break;
                }
            }

            if (wipeTarget != null && !paths.isEmpty()) {
                return usageError("--wipe-free cannot be combined with file paths");
            }
            if (wipeTarget == null && paths.isEmpty()) {
                System.err.println("Nothing to do: give one or more paths, or --wipe-free <dir>.");
                System.err.println();
                printUsage(System.err);
                return EXIT_USAGE;
            }
            if (passesGiven && opts.algo != ShredEngine.Algorithm.RANDOM) {
                System.out.println("Note: --passes only applies to the random algorithm; "
                        + "using the fixed pass count for " + opts.algo.cliName + ".");
            }

            return (wipeTarget != null)
                    ? runWipe(wipeTarget, opts, confirmed)
                    : runShred(paths, opts, confirmed);
        }

        private static int usageError(String message) {
            System.err.println("Error: " + message);
            System.err.println();
            printUsage(System.err);
            return EXIT_USAGE;
        }

        private static int runShred(List<String> paths, ShredEngine.Options opts, boolean confirmed) {
            List<File> items = new ArrayList<>();
            for (String p : paths) items.add(new File(p));

            if (!confirmed) {
                System.out.println("Refusing to destroy anything without --yes.");
                System.out.println("Algorithm: " + opts.algo.displayName);
                System.out.println("Passes:    " + opts.algo.passMultiplier(opts.randomPasses));
                System.out.println("These items would be destroyed:");
                for (File f : items) {
                    String kind = f.isDirectory() ? "folder (including everything inside)"
                                : f.isFile()      ? ShredEngine.formatSize(f.length())
                                : "not found";
                    System.out.println("  " + f.getAbsolutePath() + "  [" + kind + "]");
                }
                System.out.println(FLASH_CAVEAT);
                System.out.println("Add --yes to proceed.");
                return EXIT_USAGE;
            }

            System.out.println(APP_NAME + " " + APP_VERSION);
            System.out.println("Algorithm: " + opts.algo.displayName);
            System.out.println("Passes:    " + opts.algo.passMultiplier(opts.randomPasses));
            System.out.println(FLASH_CAVEAT);

            ShredEngine engine  = new ShredEngine();
            CliListener printer = new CliListener(items);
            int failures = engine.run(items, opts, printer);

            boolean reportFailed = reportOutcome(engine, opts);
            System.out.println(failures == 0 ? "Finished with no failures."
                                             : ("Finished with " + failures + " failed item(s)."));
            if (reportFailed) {
                // The report was asked for and is not on disk. A script that runs
                // this for audit evidence must not read the run as a success.
                System.out.println("The erasure report could not be written, "
                        + "so this run is reported as failed.");
                return EXIT_FAILURE;
            }
            return failures == 0 ? EXIT_OK : EXIT_FAILURE;
        }

        private static int runWipe(String target, ShredEngine.Options opts, boolean confirmed) {
            File dir = new File(target);

            if (!confirmed) {
                System.out.println("Refusing to wipe free space without --yes.");
                System.out.println("Target folder: " + dir.getAbsolutePath());
                System.out.println("The free space of the volume holding that folder would be filled");
                System.out.println("with random data and then released. While it runs the disk reads");
                System.out.println("as full and other programs may fail to write. Do not point this at");
                System.out.println("a cloud synced folder: the sync client would upload the random data.");
                // Always stated, so the preview cannot stay silent about how
                // much of the volume the run is allowed to fill.
                System.out.println("Limit: " + (opts.wipeLimitBytes > 0
                        ? ShredEngine.formatSize(opts.wipeLimitBytes)
                        : "none, all free space will be filled"));
                System.out.println("Add --yes to proceed.");
                return EXIT_USAGE;
            }
            if (!dir.isDirectory()) {
                System.err.println("Error: not a directory: " + dir.getAbsolutePath());
                return EXIT_USAGE;
            }

            System.out.println(APP_NAME + " " + APP_VERSION);
            System.out.println("Wiping free space on the volume holding: " + dir.getAbsolutePath());
            System.out.println("Limit: " + (opts.wipeLimitBytes > 0
                    ? ShredEngine.formatSize(opts.wipeLimitBytes)
                    : "none, all free space will be filled"));

            ShredEngine engine  = new ShredEngine();
            List<File>  single  = new ArrayList<>();
            single.add(dir);
            CliListener printer = new CliListener(single);
            engine.wipeFreeSpace(dir, opts, printer);

            boolean reportFailed = reportOutcome(engine, opts);
            int failures = printer.failures;
            // Only claim the cleanup when the engine actually completed it.
            if (failures == 0 && printer.wipeResult != null
                    && printer.wipeResult.kind == ItemResult.Kind.SHREDDED) {
                System.out.println("Wrote and removed "
                        + ShredEngine.formatSize(engine.getProcessedBytes()) + " of random data.");
            } else {
                System.out.println("Wrote "
                        + ShredEngine.formatSize(engine.getProcessedBytes()) + " of random data.");
            }
            if (reportFailed) {
                System.out.println("The erasure report could not be written, "
                        + "so this run is reported as failed.");
                return EXIT_FAILURE;
            }
            return failures == 0 ? EXIT_OK : EXIT_FAILURE;
        }

        /**
         * Prints where the erasure report went, or why it did not. Returns true
         * when a report was asked for and could not be written, which the callers
         * turn into a non-zero exit code.
         */
        private static boolean reportOutcome(ShredEngine engine, ShredEngine.Options opts) {
            if (!opts.writeReport || opts.reportPath == null) return false;
            if (engine.getLastReportError() != null) {
                // Both the path and the exception type are printed: the message
                // of a filesystem exception is often the path on its own, which
                // would read like a line saying the report had been written.
                System.err.println("Could not write the erasure report to "
                        + opts.reportPath.toAbsolutePath() + ": "
                        + engine.getLastReportError());
                return true;
            }
            System.out.println("Erasure report written to " + opts.reportPath.toAbsolutePath());
            return false;
        }

        /** Prints progress at item boundaries and every 5 percent. */
        static final class CliListener implements ShredEngine.Listener {
            private final List<File> items;
            private long total      = 0L;
            private int  lastBucket = -1;
            int        failures   = 0;
            ItemResult wipeResult = null;

            CliListener(List<File> items) { this.items = items; }

            @Override public void onTotalBytes(long newTotal) { total = newTotal; }

            @Override public void onProgress(long processedBytes) {
                if (total <= 0L) return;
                int pct    = (int) Math.max(0, Math.min(100, (processedBytes * 100L) / total));
                int bucket = pct / 5;
                if (bucket > lastBucket) {
                    lastBucket = bucket;
                    System.out.println("  progress: " + pct + "%");
                }
            }

            @Override public void onFileStart(int rowIndex, String fileName, long plannedBytes) { }
            @Override public void onFileProgress(long fileProcessedBytes) { }

            @Override public void onItemResult(int rowIndex, ItemResult r) {
                if (rowIndex >= 0 && rowIndex < items.size()) {
                    System.out.println("[" + (rowIndex + 1) + "/" + items.size() + "] "
                            + items.get(rowIndex).getAbsolutePath() + " : " + r.statusText());
                } else {
                    System.out.println("Free space wipe: " + r.statusText());
                    wipeResult = r;
                }
                if (r.kind == ItemResult.Kind.FAILED) failures++;
            }

            @Override public void onFinished(int engineFailures, boolean canceled) {
                // The engine counts outcomes this listener does not classify as
                // failures on its own, such as a wipe whose fill worked but
                // whose cleanup left files behind. Its count is authoritative.
                if (engineFailures > failures) failures = engineFailures;
                if (canceled) System.out.println("Canceled.");
            }
        }
    }

    // =========================================================================
    // Swing front end. All Swing and AWT usage lives inside this class.
    // =========================================================================

    static final class Gui extends JFrame {

        private static final long serialVersionUID = 4000L;

        private static final int COL_NAME   = 0;
        private static final int COL_SIZE   = 1;
        private static final int COL_STATUS = 2;

        private static boolean darkMode = false;

        // ---------------------------------------------------------------------
        // Theme
        // ---------------------------------------------------------------------

        /**
         * Decides whether the dark theme should be used. The system property
         * datashredder.theme=dark|light wins when present. Otherwise Windows is
         * asked through the registry; anything else, or any failure, means light.
         * Only ever called from the GUI launch path.
         */
        static boolean isDarkModeEnabled() {
            String override = System.getProperty("datashredder.theme");
            if (override != null) {
                String v = override.trim();
                if (v.equalsIgnoreCase("dark"))  return true;
                if (v.equalsIgnoreCase("light")) return false;
            }

            String os = System.getProperty("os.name", "");
            if (!os.toLowerCase(Locale.ROOT).startsWith("windows")) return false;

            Process proc = null;
            try {
                ProcessBuilder pb = new ProcessBuilder("reg", "query",
                        "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Themes\\Personalize",
                        "/v", "AppsUseLightTheme");
                pb.redirectErrorStream(true);
                proc = pb.start();

                // The output is drained on a separate daemon thread so that
                // waitFor below is the only thing that decides how long this
                // call may take. Reading to end of stream on this thread would
                // be an unbounded wait instead: readLine returns null only once
                // the child closes its stdout, which in practice means once it
                // exits, so a child that hangs while holding that handle would
                // block here forever. This runs on the launch path before the
                // window is created, so blocking here means no window at all.
                final Process       child   = proc;
                final StringBuilder outText = new StringBuilder();
                Thread drain = new Thread(() -> {
                    try (BufferedReader reader = new BufferedReader(
                            new InputStreamReader(child.getInputStream(),
                                    Charset.defaultCharset()))) {
                        String line;
                        while ((line = reader.readLine()) != null) {
                            outText.append(line).append('\n');
                        }
                    } catch (IOException ignored) {
                        // A destroyed child closes the pipe; there is nothing
                        // more to collect and light is the documented fallback.
                    }
                }, "datashredder-theme-probe");
                drain.setDaemon(true);
                drain.start();

                if (!proc.waitFor(2, TimeUnit.SECONDS)) {
                    proc.destroyForcibly();
                    return false;
                }

                // The child has exited, so the pipe reaches end of stream almost
                // at once. Joining also publishes the buffer safely to this
                // thread; without that edge the text below could be read while
                // the drain thread is still appending to it.
                drain.join(200);
                if (drain.isAlive()) return false;

                String text = outText.toString();
                int keyAt = text.indexOf("AppsUseLightTheme");
                if (keyAt < 0) return false;
                String tail = text.substring(keyAt);
                int hexAt = tail.indexOf("0x");
                if (hexAt < 0) return false;
                String rest = tail.substring(hexAt + 2);
                int end = 0;
                while (end < rest.length() && Character.digit(rest.charAt(end), 16) >= 0) end++;
                if (end == 0) return false;
                return Integer.parseInt(rest.substring(0, end), 16) == 0;   // 0x0 means dark
            } catch (InterruptedException ie) {
                Thread.currentThread().interrupt();
                if (proc != null) proc.destroyForcibly();
                return false;
            } catch (RuntimeException | IOException ex) {
                if (proc != null) proc.destroyForcibly();
                return false;
            }
        }

        private static void applyDarkPalette() {
            Color darkBg      = new Color(50, 50, 50);
            Color componentBg = new Color(85, 85, 85);
            Color white       = Color.WHITE;
            Color black       = Color.BLACK;

            UIManager.put("Panel.background",                darkBg);
            // Label.foreground stays dark on purpose. A global white breaks the
            // file chooser's "Look in:" label, which the LAF paints on a light
            // strip; the labels this app owns are recoloured one by one instead.
            UIManager.put("Label.foreground",                black);
            UIManager.put("Button.foreground",               black);
            UIManager.put("Button.background",               new Color(70, 70, 70));
            UIManager.put("Button.focus",                    new Color(0, 0, 0, 0));
            UIManager.put("Button.select",                   new Color(100, 100, 100));
            UIManager.put("ComboBox.foreground",             black);
            UIManager.put("ComboBox.background",             componentBg);
            UIManager.put("ComboBox.selectionForeground",    white);
            UIManager.put("Spinner.foreground",              white);
            UIManager.put("Spinner.background",              componentBg);
            UIManager.put("FormattedTextField.foreground",   black);
            UIManager.put("CheckBox.background",             darkBg);
            UIManager.put("CheckBox.foreground",             white);
            UIManager.put("OptionPane.background",           darkBg);
            UIManager.put("OptionPane.messageForeground",    white);
            UIManager.put("OptionPane.buttonAreaBackground", darkBg);
            UIManager.put("OptionPane.messageFont",          new Font("Segoe UI", Font.PLAIN, 13));
            UIManager.put("OptionPane.messageAlignment",     SwingConstants.CENTER);

            // Queue table and its container
            UIManager.put("Table.background",                componentBg);
            UIManager.put("Table.foreground",                white);
            UIManager.put("Table.gridColor",                 new Color(115, 115, 115));
            UIManager.put("Table.selectionBackground",       new Color(0, 92, 140));
            UIManager.put("Table.selectionForeground",       white);
            UIManager.put("TableHeader.background",          new Color(70, 70, 70));
            UIManager.put("TableHeader.foreground",          white);
            UIManager.put("ScrollPane.background",           darkBg);
            UIManager.put("Viewport.background",             componentBg);
        }

        /**
         * Recolours the chooser labels that sit on the dark panel background:
         * "File name:", "Files of type:" and, for the directories-only chooser,
         * "Folder name:".
         */
        static void applyChooserLabelColors(Container container) {
            String fileName   = UIManager.getString("FileChooser.fileNameLabelText");
            String fileType   = UIManager.getString("FileChooser.filesOfTypeLabelText");
            String folderName = UIManager.getString("FileChooser.folderNameLabelText");
            for (Component comp : container.getComponents()) {
                if (comp instanceof JLabel) {
                    String text = ((JLabel) comp).getText();
                    if (text != null && (text.equals(fileName)
                                      || text.equals(fileType)
                                      || text.equals(folderName))) {
                        comp.setForeground(Color.WHITE);
                    }
                } else if (comp instanceof Container) {
                    applyChooserLabelColors((Container) comp);
                }
            }
        }

        /**
         * Dark styling the palette cannot deliver through UIManager keys: the
         * Windows look and feel paints table headers itself and ignores the
         * TableHeader colour keys, so the header gets an explicit renderer.
         * The scroll pane's viewport is matched to the table surface so the
         * area past the table never flashes light.
         */
        private void styleTableDark(JScrollPane scroll) {
            final Color headerBg   = new Color(64, 64, 64);
            final Color headerLine = new Color(110, 110, 110);
            javax.swing.table.JTableHeader header = table.getTableHeader();
            header.setDefaultRenderer(new javax.swing.table.DefaultTableCellRenderer() {
                private static final long serialVersionUID = 4006L;
                @Override public Component getTableCellRendererComponent(
                        JTable t, Object value, boolean selected, boolean focused, int row, int column) {
                    super.getTableCellRendererComponent(t, value, selected, focused, row, column);
                    setBackground(headerBg);
                    setForeground(Color.WHITE);
                    setOpaque(true);
                    setBorder(BorderFactory.createCompoundBorder(
                            BorderFactory.createMatteBorder(0, 0, 1, 1, headerLine),
                            BorderFactory.createEmptyBorder(2, 6, 2, 6)));
                    return this;
                }
            });
            header.setBackground(headerBg);
            scroll.getViewport().setBackground(table.getBackground());
        }

        // ---------------------------------------------------------------------
        // Fields
        // ---------------------------------------------------------------------

        private final List<File>         queue      = new ArrayList<>();
        private final List<ItemResult>   lastResults = new ArrayList<>();

        /**
         * The outcome of each queue row of the run that just finished, keyed by
         * its row index. finishUp decides which rows to drop from that outcome
         * rather than from the Status text, which carries the row's detail
         * alongside the word "Done" whenever there is something to say about a
         * successful row, such as a file that had another hard-linked name.
         * Cleared at the start of every run, so an index can never be stale.
         */
        private final Map<Integer, ItemResult> rowResults = new HashMap<>();
        private final DefaultTableModel  model;
        private final JTable             table;

        private final JComboBox<ShredEngine.Algorithm> algorithmComboBox;
        private final JSpinner   passesSpinner;
        private final JCheckBox  reportCheckBox;

        private final JButton addButton;
        private final JButton removeButton;
        private final JButton clearButton;
        private final JButton shredButton;
        private final JButton pauseButton;
        private final JButton cancelButton;
        private final JButton wipeButton;

        private final JProgressBar itemBar;
        private final JProgressBar overallBar;

        private volatile boolean     running = false;
        private volatile ShredEngine engine  = null;

        /** What the overall bar is currently saying about the run as a whole. */
        private static final int UI_RUNNING   = 0;
        private static final int UI_PAUSED    = 1;
        private static final int UI_CANCELING = 2;

        /**
         * Set on the EDT, read on the EDT inside the posted progress runnables.
         * Progress posts that were already in flight when the user paused or
         * cancelled must not paint an ordinary percentage over the sentence
         * explaining what the run is doing, especially the pause banner: once the
         * worker parks in checkpoint() no later post would correct it.
         */
        private volatile int uiState = UI_RUNNING;

        /**
         * The last result delivered for a free-space wipe, which uses row index
         * -1 and therefore never reaches the queue table. onFinished is the last
         * writer of the overall bar, so it has to carry this text as well.
         */
        private ItemResult lastWipeResult = null;

        // ---------------------------------------------------------------------
        // Construction
        // ---------------------------------------------------------------------

        Gui() {
            setTitle(APP_NAME + " " + APP_VERSION);
            setDefaultCloseOperation(JFrame.DO_NOTHING_ON_CLOSE);
            setLayout(new BorderLayout(8, 8));
            setMinimumSize(new Dimension(720, 480));
            setSize(880, 560);

            Color labelFg = darkMode ? Color.WHITE : Color.BLACK;

            model = new DefaultTableModel(new Object[]{ "Name", "Size", "Status" }, 0) {
                private static final long serialVersionUID = 4002L;
                @Override public boolean isCellEditable(int row, int column) { return false; }
            };
            table = new JTable(model) {
                private static final long serialVersionUID = 4003L;
                @Override public String getToolTipText(java.awt.event.MouseEvent e) {
                    int r = rowAtPoint(e.getPoint());
                    if (r >= 0 && r < queue.size()) return queue.get(r).getAbsolutePath();
                    return super.getToolTipText(e);
                }
            };
            table.setFillsViewportHeight(true);   // drops below the last row still land on the table
            table.setRowHeight(22);

            // Cell text is file names, paths and exception messages, none of
            // which is markup. Swing renders a string starting with <html> as
            // markup by default, so HTML interpretation is turned off for every
            // column rather than trusting the content.
            javax.swing.table.DefaultTableCellRenderer plainCells =
                    new javax.swing.table.DefaultTableCellRenderer();
            plainCells.putClientProperty("html.disable", Boolean.TRUE);
            table.setDefaultRenderer(Object.class, plainCells);

            table.getColumnModel().getColumn(COL_NAME).setPreferredWidth(320);
            table.getColumnModel().getColumn(COL_SIZE).setPreferredWidth(110);
            table.getColumnModel().getColumn(COL_STATUS).setPreferredWidth(360);

            // --- Options row ---
            JPanel top = new JPanel(new FlowLayout(FlowLayout.LEFT, 8, 6));
            JLabel algorithmLabel = new JLabel("Algorithm:");
            algorithmLabel.setForeground(labelFg);
            top.add(algorithmLabel);

            algorithmComboBox = new JComboBox<>(ShredEngine.Algorithm.values());
            top.add(algorithmComboBox);

            JLabel passesLabel = new JLabel("Passes:");
            passesLabel.setForeground(labelFg);
            top.add(passesLabel);

            passesSpinner = new JSpinner(new SpinnerNumberModel(3, 1, 100, 1));
            JSpinner.NumberEditor editor = new JSpinner.NumberEditor(passesSpinner, "#");
            passesSpinner.setEditor(editor);
            ((NumberFormatter) editor.getTextField().getFormatter()).setAllowsInvalid(false);
            top.add(passesSpinner);

            reportCheckBox = new JCheckBox("Write erasure report");
            reportCheckBox.setForeground(labelFg);
            top.add(reportCheckBox);

            add(top, BorderLayout.NORTH);

            // --- Queue ---
            JScrollPane scroll = new JScrollPane(table);
            // The title colour is set on this border rather than through the
            // UIManager, matching how the other labels are handled: a global
            // key would reach every component the look and feel builds,
            // including the file chooser. Left alone the border takes the
            // look and feel's black, which the dark scroll pane paints behind,
            // and the word becomes unreadable.
            javax.swing.border.TitledBorder queueBorder =
                    BorderFactory.createTitledBorder("Queue");
            queueBorder.setTitleColor(labelFg);
            scroll.setBorder(queueBorder);
            add(scroll, BorderLayout.CENTER);

            if (darkMode) styleTableDark(scroll);

            // --- Buttons and progress ---
            JPanel bottom = new JPanel(new BorderLayout(6, 6));

            JPanel buttons = new JPanel(new FlowLayout(FlowLayout.CENTER, 6, 4));
            addButton    = new JButton("Add");
            removeButton = new JButton("Remove Selected");
            clearButton  = new JButton("Clear");
            shredButton  = new JButton("Secure Shred");
            pauseButton  = new JButton("Pause");
            cancelButton = new JButton("Cancel");
            wipeButton   = new JButton("Wipe Free Space");
            pauseButton.setEnabled(false);
            cancelButton.setEnabled(false);
            buttons.add(addButton);
            buttons.add(removeButton);
            buttons.add(clearButton);
            buttons.add(shredButton);
            buttons.add(pauseButton);
            buttons.add(cancelButton);
            buttons.add(wipeButton);
            bottom.add(buttons, BorderLayout.NORTH);

            JPanel bars = new JPanel(new GridLayout(2, 1, 0, 4));
            itemBar    = makeProgressBar("Current item");
            overallBar = makeProgressBar("Ready.");
            bars.add(itemBar);
            bars.add(overallBar);
            bottom.add(bars, BorderLayout.CENTER);

            add(bottom, BorderLayout.SOUTH);

            // --- Behaviour ---
            algorithmComboBox.addActionListener(e -> updatePassesState());
            addButton   .addActionListener(e -> handleFileSelection());
            removeButton.addActionListener(e -> removeSelected());
            clearButton .addActionListener(e -> clearQueue());
            shredButton .addActionListener(e -> startShreddingProcess());
            wipeButton  .addActionListener(e -> startFreeSpaceWipe());
            pauseButton .addActionListener(e -> togglePause());
            cancelButton.addActionListener(e -> confirmCancel());

            TransferHandler dropHandler = new TransferHandler() {
                private static final long serialVersionUID = 4004L;
                @Override public boolean canImport(TransferSupport support) {
                    return !running && support.isDataFlavorSupported(DataFlavor.javaFileListFlavor);
                }
                @Override public boolean importData(TransferSupport support) {
                    if (!canImport(support)) return false;
                    try {
                        Object data = support.getTransferable()
                                .getTransferData(DataFlavor.javaFileListFlavor);
                        List<?> raw = (List<?>) data;
                        List<File> dropped = new ArrayList<>();
                        for (Object o : raw) if (o instanceof File) dropped.add((File) o);
                        addToQueue(dropped);
                        return true;
                    } catch (Exception ex) {
                        return false;
                    }
                }
            };
            table.setTransferHandler(dropHandler);
            setTransferHandler(dropHandler);

            addWindowListener(new java.awt.event.WindowAdapter() {
                @Override public void windowClosing(java.awt.event.WindowEvent e) {
                    if (running) {
                        int choice = JOptionPane.showConfirmDialog(Gui.this,
                                "Work is in progress. Really exit?",
                                "Confirm Exit",
                                JOptionPane.YES_NO_OPTION,
                                JOptionPane.WARNING_MESSAGE);
                        if (choice != JOptionPane.YES_OPTION) return;
                    }
                    System.exit(0);
                }
            });

            updatePassesState();
            setLocationRelativeTo(null);
        }

        private static JProgressBar makeProgressBar(String initialText) {
            JProgressBar bar = new JProgressBar(0, 100) {
                private static final long serialVersionUID = 4005L;
                @Override public void updateUI() {
                    super.updateUI();
                    setUI(new javax.swing.plaf.basic.BasicProgressBarUI() {
                        @Override protected Color getSelectionBackground() { return Color.DARK_GRAY; }
                        @Override protected Color getSelectionForeground() { return Color.BLACK; }
                    });
                }
            };
            bar.setStringPainted(true);
            bar.setPreferredSize(new Dimension(650, 24));
            bar.setForeground(Color.GRAY);
            bar.setString(initialText);
            return bar;
        }

        // ---------------------------------------------------------------------
        // Queue management
        // ---------------------------------------------------------------------

        private void updatePassesState() {
            ShredEngine.Algorithm algo =
                    (ShredEngine.Algorithm) algorithmComboBox.getSelectedItem();
            if (algo == null) return;
            int fixed = algo.fixedPasses();
            if (fixed < 0) {
                passesSpinner.setValue(3);
                passesSpinner.setEnabled(true);
            } else {
                passesSpinner.setValue(fixed);
                passesSpinner.setEnabled(false);
            }
        }

        private void handleFileSelection() {
            JFileChooser chooser = new JFileChooser();
            chooser.setMultiSelectionEnabled(true);
            chooser.setFileSelectionMode(JFileChooser.FILES_AND_DIRECTORIES);
            chooser.setDialogTitle("Add files or folders");
            if (darkMode) applyChooserLabelColors(chooser);

            if (chooser.showOpenDialog(this) == JFileChooser.APPROVE_OPTION) {
                addToQueue(Arrays.asList(chooser.getSelectedFiles()));
            }
        }

        private void addToQueue(List<File> candidates) {
            if (running || candidates == null) return;
            Set<String> present = new HashSet<>();
            for (File f : queue) present.add(f.getAbsolutePath());

            int added = 0;
            for (File f : candidates) {
                if (f == null || !f.exists()) continue;
                try {
                    // Junctions are excluded here as well, not just symlinks:
                    // queueing one would put the target's tree at risk.
                    if (ShredEngine.isLinkOrJunction(f.toPath())) continue;
                } catch (IOException | RuntimeException ex) {
                    continue;
                }
                if (!present.add(f.getAbsolutePath())) continue;
                queue.add(f);
                model.addRow(new Object[]{
                        f.getName(),
                        f.isDirectory() ? "folder" : ShredEngine.formatSize(f.length()),
                        "Queued" });
                added++;
            }
            if (added == 0 && !candidates.isEmpty()) {
                overallBar.setString(
                        "Nothing added: already in the queue, missing, or a link or junction.");
            }
        }

        private void removeSelected() {
            if (running) return;
            int[] rows = table.getSelectedRows();
            Arrays.sort(rows);
            for (int i = rows.length - 1; i >= 0; i--) {
                int r = rows[i];
                if (r >= 0 && r < queue.size()) {
                    queue.remove(r);
                    model.removeRow(r);
                }
            }
        }

        private void clearQueue() {
            if (running) return;
            queue.clear();
            model.setRowCount(0);
            lastResults.clear();
            rowResults.clear();
            resetBars();
        }

        private void resetBars() {
            itemBar.setIndeterminate(false);
            itemBar.setValue(0);
            itemBar.setString("Current item");
            itemBar.setForeground(Color.GRAY);
            overallBar.setIndeterminate(false);
            overallBar.setValue(0);
            overallBar.setString("Ready.");
            overallBar.setToolTipText(null);
            overallBar.setForeground(Color.GRAY);
            lastWipeResult = null;
            uiState        = UI_RUNNING;
        }

        private void setRunning(boolean r) {
            running = r;
            addButton   .setEnabled(!r);
            removeButton.setEnabled(!r);
            clearButton .setEnabled(!r);
            shredButton .setEnabled(!r);
            wipeButton  .setEnabled(!r);
            algorithmComboBox.setEnabled(!r);
            reportCheckBox.setEnabled(!r);
            passesSpinner.setEnabled(!r && ((ShredEngine.Algorithm)
                    algorithmComboBox.getSelectedItem()).fixedPasses() < 0);
            pauseButton .setEnabled(r);
            cancelButton.setEnabled(r);
            if (!r) {
                pauseButton.setText("Pause");
                uiState = UI_RUNNING;
            }
        }

        private void togglePause() {
            ShredEngine e = engine;
            if (e == null || !running) return;
            boolean nowPaused = !e.isPaused();
            e.setPaused(nowPaused);
            pauseButton.setText(nowPaused ? "Resume" : "Pause");
            if (nowPaused) {
                if (uiState != UI_CANCELING) uiState = UI_PAUSED;
                overallBar.setString("Paused. The file stays locked until you resume or cancel.");
            } else if (uiState == UI_PAUSED) {
                uiState = UI_RUNNING;
            }
        }

        private void confirmCancel() {
            ShredEngine e = engine;
            if (e == null || !running) return;
            int confirm = JOptionPane.showConfirmDialog(this,
                    "Cancel the operation?", "Confirm Cancel", JOptionPane.YES_NO_OPTION);
            if (confirm != JOptionPane.YES_OPTION) return;

            // The dialog runs a nested event loop, so the run can finish while it
            // is open: onFinished paints the final bar and the worker's finally
            // clears the engine. Acting on the engine captured before the dialog
            // would then leave a red "Canceling..." over a run whose files are
            // already destroyed, and nothing would ever replace it.
            if (!running || engine != e) return;

            uiState = UI_CANCELING;
            // Cancel stays clickable until onFinished arrives. The queue scan has
            // no work-in-progress to stop instantly, so disabling it here would
            // leave the window with no live control for as long as the scan runs.
            pauseButton.setEnabled(false);
            overallBar.setString("Canceling...");
            overallBar.setForeground(Color.RED);
            e.requestCancel();
        }

        // ---------------------------------------------------------------------
        // Operations
        // ---------------------------------------------------------------------

        private void startShreddingProcess() {
            if (running) return;
            if (queue.isEmpty()) {
                JOptionPane.showMessageDialog(this, "Add files or folders to the queue first.");
                return;
            }

            // Every Swing value the worker needs is read here, on the EDT.
            final ShredEngine.Options opts = new ShredEngine.Options();
            opts.algo         = (ShredEngine.Algorithm) algorithmComboBox.getSelectedItem();
            opts.randomPasses = (Integer) passesSpinner.getValue();
            opts.writeReport  = reportCheckBox.isSelected();
            final List<File> items = new ArrayList<>(queue);

            int confirm = JOptionPane.showConfirmDialog(this,
                    "This will permanently destroy " + items.size() + " queue item(s),\n"
                    + "including everything inside any folders listed.\n"
                    + "Nothing listed can be restored by this tool afterwards.\n\n"
                    + FLASH_CAVEAT + "\n\nProceed?",
                    "Confirmation", JOptionPane.YES_NO_OPTION, JOptionPane.WARNING_MESSAGE);
            if (confirm != JOptionPane.YES_OPTION) return;

            for (int i = 0; i < model.getRowCount(); i++) model.setValueAt("Queued", i, COL_STATUS);
            lastResults.clear();
            rowResults.clear();
            lastWipeResult = null;
            uiState        = UI_RUNNING;
            itemBar.setValue(0);
            itemBar.setForeground(Color.GREEN);
            overallBar.setValue(0);
            overallBar.setForeground(Color.GREEN);
            overallBar.setString("Starting...");

            final ShredEngine e = new ShredEngine();
            engine = e;
            setRunning(true);
            startWorker(() -> e.run(items, opts, new GuiListener(e)), opts, false);
        }

        private void startFreeSpaceWipe() {
            if (running) return;

            JFileChooser chooser = new JFileChooser();
            chooser.setFileSelectionMode(JFileChooser.DIRECTORIES_ONLY);
            chooser.setDialogTitle("Pick a folder on the volume to wipe");
            File[] roots = File.listRoots();
            if (roots != null && roots.length > 0) chooser.setCurrentDirectory(roots[0]);
            if (darkMode) applyChooserLabelColors(chooser);
            if (chooser.showOpenDialog(this) != JFileChooser.APPROVE_OPTION) return;

            final File target = chooser.getSelectedFile();
            if (target == null || !target.isDirectory()) {
                JOptionPane.showMessageDialog(this, "Pick an existing folder.");
                return;
            }

            int confirm = JOptionPane.showConfirmDialog(this,
                    "Wipe the free space of the volume holding:\n" + target.getAbsolutePath()
                    + "\n\nThis fills the free space with random data, then releases it.\n"
                    + "While it runs:\n"
                    + "- the disk briefly reads as full and other programs may fail to write\n"
                    + "- a cloud synced folder (OneDrive, Dropbox and similar) would make the\n"
                    + "  sync client upload the random data\n"
                    + "- wipe-* leftovers remain if this program is killed part way, or if\n"
                    + "  another program is holding a wipe file open when cleanup runs; the\n"
                    + "  result line names anything that could not be removed\n\n"
                    + FLASH_CAVEAT + "\n\n"
                    + "Proceed?",
                    "Confirm Free Space Wipe", JOptionPane.YES_NO_OPTION, JOptionPane.WARNING_MESSAGE);
            if (confirm != JOptionPane.YES_OPTION) return;

            final ShredEngine.Options opts = new ShredEngine.Options();
            opts.writeReport = reportCheckBox.isSelected();

            lastResults.clear();
            rowResults.clear();
            lastWipeResult = null;
            uiState        = UI_RUNNING;
            itemBar.setValue(0);
            itemBar.setForeground(Color.GREEN);
            overallBar.setValue(0);
            overallBar.setForeground(Color.GREEN);
            overallBar.setString("Starting...");

            final ShredEngine e = new ShredEngine();
            engine = e;
            setRunning(true);
            startWorker(() -> e.wipeFreeSpace(target, opts, new GuiListener(e)), opts, true);
        }

        /**
         * Runs the engine off the EDT. The finally block re-enables the controls
         * on its own, so the UI recovers even if the engine throws.
         */
        private void startWorker(Runnable body, ShredEngine.Options opts, boolean wipe) {
            final ShredEngine e = engine;
            new Thread(() -> {
                Throwable error = null;
                try {
                    body.run();
                } catch (Throwable t) {
                    error = t;
                } finally {
                    final Throwable finalError = error;
                    SwingUtilities.invokeLater(() -> {
                        setRunning(false);
                        engine = null;
                        if (finalError != null) {
                            showError(String.valueOf(finalError.getMessage()));
                        }
                        finishUp(e, opts, wipe);
                    });
                }
            }, "shredder-thread").start();
        }

        private void finishUp(ShredEngine e, ShredEngine.Options opts, boolean wipe) {
            if (opts.writeReport && e != null) {
                JFileChooser saver = new JFileChooser();
                saver.setDialogTitle("Save erasure report");
                saver.setSelectedFile(new File("datashredder-report.txt"));
                if (darkMode) applyChooserLabelColors(saver);
                if (saver.showSaveDialog(this) == JFileChooser.APPROVE_OPTION) {
                    try {
                        e.writeErasureReport(saver.getSelectedFile().toPath());
                    } catch (IOException ex) {
                        showError("Could not write the report: " + ex.getMessage());
                    }
                }
            }

            if (!wipe) {
                // Drop rows that finished cleanly; leave anything the user
                // should see. The kind decides, not the Status text: a row that
                // succeeded can still carry a detail after the word "Done", for
                // instance when one of its files had another hard-linked name,
                // and matching text would then keep a row whose path has just
                // been destroyed and leave a second Shred press to report it as
                // missing.
                for (int i = queue.size() - 1; i >= 0; i--) {
                    ItemResult r = rowResults.get(i);
                    if (r != null && (r.kind == ItemResult.Kind.SHREDDED
                                      || r.kind == ItemResult.Kind.CRYPTO_ERASED)) {
                        queue.remove(i);
                        model.removeRow(i);
                    }
                }
            }
            itemBar.setValue(0);
            itemBar.setString("Current item");
            itemBar.setIndeterminate(false);

            // A wipe that could not clean up has left real data on the volume,
            // and the bar alone is easy to miss and too narrow for a full path.
            // This runs after the bar has been written, so the text stays on
            // screen behind the dialog.
            ItemResult wipeOutcome = lastWipeResult;
            if (wipe && wipeOutcome != null
                    && (wipeOutcome.kind == ItemResult.Kind.PARTIAL
                        || wipeOutcome.kind == ItemResult.Kind.FAILED
                        || wipeOutcome.kind == ItemResult.Kind.CANCELED)) {
                JOptionPane.showMessageDialog(this,
                        "Free space wipe result:\n\n" + wipeOutcome.statusText(),
                        "Free Space Wipe", JOptionPane.WARNING_MESSAGE);
            }
        }

        /**
         * The text is escaped before the line breaks are turned into markup:
         * exception messages carry file paths, and a path can contain angle
         * brackets, which Swing's HTML renderer would otherwise treat as tags.
         */
        private void showError(String message) {
            JOptionPane.showMessageDialog(this,
                    "<html><b>Error:</b><br>"
                    + escapeHtml(message).replace("\n", "<br>") + "</html>",
                    "Error", JOptionPane.ERROR_MESSAGE);
        }

        // ---------------------------------------------------------------------
        // Engine listener adapter
        // ---------------------------------------------------------------------

        /**
         * Bridges engine callbacks to the EDT. onProgress and onFileProgress are
         * both throttled to one post per percent step or per 100 ms, whichever
         * comes first, and the throttle is applied before invokeLater so the
         * queue never floods. Both fire once per 1 MiB chunk, which on a fast
         * drive is thousands of posts a second without the gate. The remaining
         * callbacks are rare and go straight through.
         *
         * All of these fields are touched only from the engine's worker thread,
         * except total, so no further synchronisation is needed.
         */
        private final class GuiListener implements ShredEngine.Listener {

            private final ShredEngine source;
            private volatile long total          = 0L;
            private long          currentPlanned = 0L;
            private long          lastPostedPct  = -1L;
            private long          lastPostedAtMs = 0L;
            private long          lastItemPct    = -1L;
            private long          lastItemAtMs   = 0L;

            GuiListener(ShredEngine source) { this.source = source; }

            @Override public void onTotalBytes(long newTotal) {
                total = newTotal;
            }

            @Override public void onProgress(long processedBytes) {
                long t   = total;
                long pct = (t > 0L) ? Math.max(0L, Math.min(100L, processedBytes * 100L / t)) : -1L;
                long now = System.currentTimeMillis();
                if (pct == lastPostedPct && now - lastPostedAtMs < 100L) return;
                lastPostedPct  = pct;
                lastPostedAtMs = now;

                final long   value = pct;
                final String label = buildOverallLabel(processedBytes, t, pct);
                SwingUtilities.invokeLater(() -> {
                    if (value < 0L) {
                        overallBar.setIndeterminate(true);
                    } else {
                        overallBar.setIndeterminate(false);
                        overallBar.setValue((int) value);
                    }
                    // A post that was already in flight when the user paused or
                    // cancelled must not overwrite the sentence that explains it.
                    if (uiState == UI_RUNNING) overallBar.setString(label);
                });
            }

            private String buildOverallLabel(long processed, long t, long pct) {
                if (t <= 0L) return "Working, " + ShredEngine.formatSize(processed) + " done";
                long   activeMs = source.getActiveElapsedMillis();
                double bytesPerSec = (activeMs > 0L) ? (processed * 1000.0 / activeMs) : 0.0;
                String eta = (bytesPerSec > 0.0)
                        ? ShredEngine.formatTime((t - processed) / bytesPerSec)
                        : "--:--:--";
                return pct + "% - " + eta + " remaining";
            }

            @Override public void onFileStart(int rowIndex, String fileName, long plannedBytes) {
                currentPlanned = plannedBytes;
                lastItemPct    = -1L;   // each file starts the item throttle fresh
                lastItemAtMs   = 0L;
                final String name = fileName;
                final int    row  = rowIndex;
                final long   plan = plannedBytes;
                SwingUtilities.invokeLater(() -> {
                    itemBar.setIndeterminate(plan <= 0L);
                    itemBar.setValue(0);
                    itemBar.setString(name);
                    if (row >= 0 && row < model.getRowCount()) {
                        model.setValueAt("Working: " + name, row, COL_STATUS);
                    }
                });
            }

            @Override public void onFileProgress(long fileProcessedBytes) {
                final long plan = currentPlanned;
                if (plan <= 0L) return;
                final int pct = (int) Math.max(0L,
                        Math.min(100L, fileProcessedBytes * 100L / plan));
                long now = System.currentTimeMillis();
                if (pct == lastItemPct && now - lastItemAtMs < 100L) return;
                lastItemPct  = pct;
                lastItemAtMs = now;
                SwingUtilities.invokeLater(() -> {
                    itemBar.setIndeterminate(false);
                    itemBar.setValue(pct);
                });
            }

            @Override public void onItemResult(int rowIndex, ItemResult r) {
                final int        row    = rowIndex;
                final ItemResult result = r;
                SwingUtilities.invokeLater(() -> {
                    lastResults.add(result);
                    if (row >= 0) rowResults.put(row, result);
                    if (row >= 0 && row < model.getRowCount()) {
                        model.setValueAt(result.statusText(), row, COL_STATUS);
                    } else if (row < 0) {
                        // A free-space wipe has no table row, so this text is the
                        // only place the outcome appears. onFinished is posted
                        // right behind it from the same thread and is therefore
                        // the last writer of this bar, so the result is kept for
                        // it to include rather than left here to be painted over.
                        lastWipeResult = result;
                        overallBar.setString(result.statusText());
                        overallBar.setToolTipText(result.statusText());
                    }
                });
            }

            /**
             * What a cancel actually did, which is not the same sentence on
             * every path. Read on the event dispatch thread, from inside the
             * runnable onFinished posts, so it sees the results onItemResult
             * posted ahead of it.
             *
             * A free-space wipe never opens a file of the user's, so nothing of
             * theirs can have been destroyed. A cancel taken while the queue was
             * still being expanded never reached a row either, and the engine
             * reports it without emitting a canceled row, which is what tells
             * that case apart.
             *
             * The remaining two cases both produce a canceled row, so the row's
             * own itemInFlight flag decides between them rather than its mere
             * existence: a cancel can also land on one of the checkpoints
             * between files or between directory removals, where no file was
             * open and nothing is half destroyed. Only a cancel taken inside
             * the work on a file carries the phase note this banner points the
             * user at.
             */
            private String canceledBannerText() {
                if (lastWipeResult != null) {
                    return "Canceled. The wipe wrote only its own temporary files,"
                            + " and nothing of yours was touched.";
                }
                boolean itemStarted  = false;
                boolean itemInFlight = false;
                for (ItemResult r : lastResults) {
                    if (r.kind == ItemResult.Kind.CANCELED) {
                        itemStarted  = true;
                        itemInFlight = r.itemInFlight;
                        break;
                    }
                }
                if (!itemStarted) {
                    return "Canceled while the queue was still being read."
                            + " Nothing on disk was changed.";
                }
                if (!itemInFlight) {
                    return "Canceled between items. Nothing was left part way"
                            + " destroyed: files already finished were destroyed"
                            + " as asked, and items not yet reached were not"
                            + " touched.";
                }
                return "Canceled. The item that was interrupted may be partly or"
                        + " completely destroyed, and its row says how far it got;"
                        + " items not yet reached were not touched.";
            }

            @Override public void onFinished(int failures, boolean canceled) {
                final int     f = failures;
                final boolean c = canceled;
                SwingUtilities.invokeLater(() -> {
                    uiState = UI_RUNNING;
                    itemBar.setIndeterminate(false);
                    itemBar.setValue(0);
                    overallBar.setIndeterminate(false);
                    String text;
                    if (c) {
                        overallBar.setForeground(Color.RED);
                        text = canceledBannerText();
                    } else if (f > 0) {
                        overallBar.setForeground(Color.ORANGE);
                        text = "Finished with " + f + " failed item(s).";
                    } else {
                        overallBar.setValue(100);
                        overallBar.setForeground(Color.GREEN);
                        text = "Finished.";
                    }
                    // The wipe result names how much random data was written and,
                    // when cleanup could not finish, which wipe file is still
                    // occupying the disk and where. Losing that would leave the
                    // user with no way to find it.
                    if (lastWipeResult != null) {
                        text = text + " " + lastWipeResult.statusText();
                    }
                    overallBar.setString(text);
                    overallBar.setToolTipText(text);
                });
            }
        }

        // ---------------------------------------------------------------------
        // Launch
        // ---------------------------------------------------------------------

        static void launch() {
            try {
                UIManager.setLookAndFeel(UIManager.getSystemLookAndFeelClassName());
                darkMode = isDarkModeEnabled();
                if (darkMode) applyDarkPalette();
            } catch (Exception ex) {
                ex.printStackTrace();
            }

            // The dialog is posted to the event dispatch thread rather than
            // built on whichever thread died: showing it from a non-Swing
            // thread breaks the single-thread rule. invokeLater is legal from
            // the event dispatch thread too, so no thread test is needed.
            Thread.setDefaultUncaughtExceptionHandler((t, ex) ->
                    SwingUtilities.invokeLater(() ->
                            JOptionPane.showMessageDialog(null,
                                    "Unhandled error: " + ex.getMessage(),
                                    "Fatal Error", JOptionPane.ERROR_MESSAGE)));

            SwingUtilities.invokeLater(() -> new Gui().setVisible(true));
        }
    }
}
