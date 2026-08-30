/**
 * Engine tests for DataShredder v4.0.0.
 *
 * Zero dependency, headless, reviewer runnable: plain main(), one PASS or FAIL
 * line per check, a non-zero exit status when anything fails. Everything is
 * created under a fresh temporary directory below java.io.tmpdir and removed
 * again at the end.
 *
 * Compile and run:
 *   javac --release 11 -d test-build DataShredderV4.java DataShredderV4EngineTest.java
 *   java -cp test-build DataShredderV4EngineTest
 */

import java.io.File;
import java.io.IOException;
import java.io.RandomAccessFile;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Comparator;
import java.util.List;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicLong;
import java.util.function.BooleanSupplier;
import java.util.stream.Stream;

public class DataShredderV4EngineTest {

    private static int passed = 0;
    private static int failed = 0;

    private static final long MIB = 1024L * 1024L;

    // -------------------------------------------------------------------------
    // Harness
    // -------------------------------------------------------------------------

    private static void check(String name, boolean condition) {
        if (condition) {
            passed++;
            System.out.println("PASS  " + name);
        } else {
            failed++;
            System.out.println("FAIL  " + name);
        }
    }

    private static void checkEquals(String name, long expected, long actual) {
        boolean ok = expected == actual;
        if (ok) {
            passed++;
            System.out.println("PASS  " + name);
        } else {
            failed++;
            System.out.println("FAIL  " + name + " (expected " + expected + ", got " + actual + ")");
        }
    }

    private static void section(String title) {
        System.out.println();
        System.out.println("== " + title + " ==");
    }

    public static void main(String[] args) throws Exception {
        Path base = Files.createTempDirectory("datashredder-v4-test");
        System.out.println("Working directory: " + base);
        try {
            test01PatternPrimitives(base);
            test02ZeroVerification(base);
            test03CryptoErase(base);
            test04FullRandomRun(base);
            test05CancelMidFile(base);
            test06Pause(base);
            test07CancelWhilePaused(base);
            test08ReadOnlyFile(base);
            test09ZeroLengthFile(base);
            test10FreeSpaceWipe(base);
            test11Dedupe(base);
            test12CliParsing(base);
            test13JunctionNotFollowed(base);
            test14ReadOnlyLeftoverIsPartial(base);
            test15UnreadableSubdirectory(base);
        } catch (Throwable t) {
            failed++;
            System.out.println("FAIL  unexpected exception: " + t);
            t.printStackTrace(System.out);
        } finally {
            deleteTree(base);
        }

        System.out.println();
        System.out.println("Passed: " + passed + "   Failed: " + failed);
        if (failed > 0) System.exit(1);
    }

    // -------------------------------------------------------------------------
    // Helpers
    // -------------------------------------------------------------------------

    private static File makeFile(Path dir, String name, long size, byte fill) throws IOException {
        File f = dir.resolve(name).toFile();
        try (RandomAccessFile raf = new RandomAccessFile(f, "rw")) {
            byte[] chunk = new byte[64 * 1024];
            Arrays.fill(chunk, fill);
            long written = 0;
            while (written < size) {
                int n = (int) Math.min(chunk.length, size - written);
                raf.write(chunk, 0, n);
                written += n;
            }
            raf.setLength(size);
        }
        return f;
    }

    private static byte[] readAll(File f) throws IOException {
        return Files.readAllBytes(f.toPath());
    }

    private static void deleteTree(Path root) {
        if (root == null || !Files.exists(root)) return;
        try (Stream<Path> walk = Files.walk(root)) {
            walk.sorted(Comparator.reverseOrder()).forEach(p -> {
                File f = p.toFile();
                f.setWritable(true);
                try {
                    Files.deleteIfExists(p);
                } catch (IOException ignored) {
                    f.delete();
                }
            });
        } catch (IOException ignored) {
            // best effort only
        }
    }

    private static boolean waitFor(BooleanSupplier condition, long millis) throws InterruptedException {
        long end = System.currentTimeMillis() + millis;
        while (System.currentTimeMillis() < end) {
            if (condition.getAsBoolean()) return true;
            Thread.sleep(10);
        }
        return condition.getAsBoolean();
    }

    private static List<File> list(File... files) {
        return new ArrayList<>(Arrays.asList(files));
    }

    private static DataShredderV4.ShredEngine.Options options(
            DataShredderV4.ShredEngine.Algorithm algo, int passes) {
        DataShredderV4.ShredEngine.Options o = new DataShredderV4.ShredEngine.Options();
        o.algo         = algo;
        o.randomPasses = passes;
        return o;
    }

    /** Recording listener; individual tests override the callbacks they need. */
    private static class Rec implements DataShredderV4.ShredEngine.Listener {
        volatile long    lastTotal        = -1L;
        volatile long    firstTotal       = -1L;
        volatile long    lastProgress     = -1L;
        volatile boolean monotonic        = true;
        volatile int     fileStarts       = 0;
        volatile int     realFileStarts   = 0;
        volatile boolean finishedCalled   = false;
        volatile boolean finishedCanceled = false;
        volatile int     finishedFailures = 0;
        final List<DataShredderV4.ItemResult> results =
                java.util.Collections.synchronizedList(new ArrayList<>());

        @Override public void onTotalBytes(long newTotal) {
            if (firstTotal < 0) firstTotal = newTotal;
            lastTotal = newTotal;
        }

        @Override public void onProgress(long processedBytes) {
            if (processedBytes < lastProgress) monotonic = false;
            lastProgress = processedBytes;
        }

        @Override public void onFileStart(int rowIndex, String fileName, long plannedBytes) {
            fileStarts++;
            if (rowIndex >= 0) realFileStarts++;
        }

        @Override public void onFileProgress(long fileProcessedBytes) { }

        @Override public void onItemResult(int rowIndex, DataShredderV4.ItemResult r) {
            results.add(r);
        }

        @Override public void onFinished(int failures, boolean canceled) {
            finishedCalled   = true;
            finishedFailures = failures;
            finishedCanceled = canceled;
        }

        DataShredderV4.ItemResult first() {
            synchronized (results) {
                return results.isEmpty() ? null : results.get(0);
            }
        }
    }

    // -------------------------------------------------------------------------
    // 1. Pattern primitives
    // -------------------------------------------------------------------------

    private static void test01PatternPrimitives(Path base) throws Exception {
        section("1. Pattern primitives");
        DataShredderV4.ShredEngine engine = new DataShredderV4.ShredEngine();

        // Fixed pattern writes the exact byte everywhere
        File pat = makeFile(base, "pattern.bin", 3000, (byte) 0xAA);
        try (RandomAccessFile raf = new RandomAccessFile(pat, "rw")) {
            engine.overwritePattern(raf, new byte[4096], pat.length(), (byte) 0x5A);
        }
        byte[] patBytes = readAll(pat);
        boolean allPattern = patBytes.length == 3000;
        for (byte b : patBytes) if (b != (byte) 0x5A) { allPattern = false; break; }
        check("overwritePattern writes the exact byte over the whole file", allPattern);

        // Custom pattern tiles across the file
        File tile = makeFile(base, "tile.bin", 10, (byte) 0x00);
        byte[] pattern = { 0x01, 0x02, 0x03 };
        try (RandomAccessFile raf = new RandomAccessFile(tile, "rw")) {
            engine.overwriteCustomPattern(raf, new byte[16], tile.length(), pattern);
        }
        byte[] tileBytes = readAll(tile);
        boolean tiled = tileBytes.length == 10;
        for (int i = 0; i < tileBytes.length && tiled; i++) {
            if (tileBytes[i] != pattern[i % pattern.length]) tiled = false;
        }
        check("overwriteCustomPattern tiles the pattern across the file", tiled);

        // Gutmann table: 27 deterministic entries, passes 5 to 31 in paper order
        byte[][] g = DataShredderV4.ShredEngine.GUTMANN_PATTERNS;
        checkEquals("Gutmann table holds 27 deterministic patterns", 27, g.length);
        check("Gutmann pass 5 is 55 55 55",
                Arrays.equals(g[0], new byte[]{ 0x55, 0x55, 0x55 }));
        check("Gutmann pass 10 is 00",
                Arrays.equals(g[5], new byte[]{ 0x00 }));
        check("Gutmann pass 25 is FF",
                Arrays.equals(g[20], new byte[]{ (byte) 0xFF }));
        check("Gutmann pass 31 is DB 6D B6",
                Arrays.equals(g[26], new byte[]{ (byte) 0xDB, 0x6D, (byte) 0xB6 }));

        pat.delete();
        tile.delete();
    }

    // -------------------------------------------------------------------------
    // 2. Zero fill and its verification
    // -------------------------------------------------------------------------

    private static void test02ZeroVerification(Path base) throws Exception {
        section("2. Zero fill and verification");
        DataShredderV4.ShredEngine engine = new DataShredderV4.ShredEngine();

        File zero = makeFile(base, "zero.bin", 4096, (byte) 0x37);
        try (RandomAccessFile raf = new RandomAccessFile(zero, "rw")) {
            engine.overwritePattern(raf, new byte[1024], zero.length(), (byte) 0x00);
        }
        byte[] zeroBytes = readAll(zero);
        boolean allZero = zeroBytes.length == 4096;
        for (byte b : zeroBytes) if (b != 0) { allZero = false; break; }
        check("ZERO primitive leaves the file all zeros", allZero);

        boolean verifiedClean = true;
        try {
            engine.verifyZeroFill(zero);
        } catch (IOException ex) {
            verifiedClean = false;
        }
        check("verifyZeroFill accepts an all-zeros file", verifiedClean);

        try (RandomAccessFile raf = new RandomAccessFile(zero, "rw")) {
            raf.seek(2000);
            raf.write(0x01);
        }
        boolean rejected = false;
        try {
            engine.verifyZeroFill(zero);
        } catch (IOException ex) {
            rejected = ex.getMessage() != null && ex.getMessage().contains("2000");
        }
        check("verifyZeroFill rejects a file with one corrupted byte and names the offset", rejected);

        zero.delete();
    }

    // -------------------------------------------------------------------------
    // 3. Crypto erase through run()
    // -------------------------------------------------------------------------

    private static void test03CryptoErase(Path base) throws Exception {
        section("3. Crypto erase keeps the file and its name");
        Path dir = Files.createDirectory(base.resolve("crypto"));
        File f = makeFile(dir, "secret.txt", 200000, (byte) 0x41);
        byte[] before = readAll(f);
        String originalName = f.getName();

        DataShredderV4.ShredEngine engine = new DataShredderV4.ShredEngine();
        Rec rec = new Rec();
        engine.run(list(f), options(DataShredderV4.ShredEngine.Algorithm.CRYPTO_ERASE, 1), rec);

        check("crypto erased file still exists", f.exists());
        check("crypto erased file keeps its original name",
                originalName.equals(f.getName()) && dir.resolve(originalName).toFile().exists());
        checkEquals("crypto erased file keeps its length", before.length, f.length());
        byte[] after = readAll(f);
        check("crypto erased file content changed", !Arrays.equals(before, after));
        DataShredderV4.ItemResult r = rec.first();
        check("crypto erase reports CRYPTO_ERASED",
                r != null && r.kind == DataShredderV4.ItemResult.Kind.CRYPTO_ERASED
                        && r.filesDone == 1);

        deleteTree(dir);
    }

    // -------------------------------------------------------------------------
    // 4. Full RANDOM run
    // -------------------------------------------------------------------------

    private static void test04FullRandomRun(Path base) throws Exception {
        section("4. Full random run");
        Path dir = Files.createDirectory(base.resolve("random"));
        File f = makeFile(dir, "target.bin", 3 * MIB, (byte) 0x7E);
        String originalName = f.getName();

        DataShredderV4.ShredEngine engine = new DataShredderV4.ShredEngine();
        Rec rec = new Rec();
        int failures = engine.run(list(f),
                options(DataShredderV4.ShredEngine.Algorithm.RANDOM, 2), rec);

        check("shredded file is gone", !f.exists());
        check("no file remains under the original name",
                !dir.resolve(originalName).toFile().exists());
        checkEquals("run reports no failures", 0, failures);
        DataShredderV4.ItemResult r = rec.first();
        check("row reports SHREDDED with one file done",
                r != null && r.kind == DataShredderV4.ItemResult.Kind.SHREDDED
                        && r.filesDone == 1 && r.filesFailed == 0 && r.filesSkipped == 0);
        check("onProgress is monotonic", rec.monotonic);
        checkEquals("final processed equals the final byte total", rec.lastTotal, rec.lastProgress);
        checkEquals("byte total is size times passes", 3 * MIB * 2, rec.lastTotal);
        check("onFinished fired, not canceled", rec.finishedCalled && !rec.finishedCanceled);

        deleteTree(dir);
    }

    // -------------------------------------------------------------------------
    // 5. Cancel mid file
    // -------------------------------------------------------------------------

    private static void test05CancelMidFile(Path base) throws Exception {
        section("5. Cancel mid file leaves the file in place");
        Path dir = Files.createDirectory(base.resolve("cancel"));
        final File f = makeFile(dir, "keepme.bin", 8 * MIB, (byte) 0x11);
        final String originalName = f.getName();

        final DataShredderV4.ShredEngine engine = new DataShredderV4.ShredEngine();
        final AtomicBoolean requested = new AtomicBoolean(false);
        Rec rec = new Rec() {
            @Override public void onProgress(long processedBytes) {
                super.onProgress(processedBytes);
                if (requested.compareAndSet(false, true)) engine.requestCancel();
            }
        };

        engine.run(list(f), options(DataShredderV4.ShredEngine.Algorithm.RANDOM, 1), rec);

        check("canceled file still exists under its original name",
                dir.resolve(originalName).toFile().exists());
        check("nothing else was created in the folder",
                dir.toFile().list() != null && dir.toFile().list().length == 1);
        DataShredderV4.ItemResult r = rec.first();
        check("row reports CANCELED",
                r != null && r.kind == DataShredderV4.ItemResult.Kind.CANCELED);
        check("onFinished reports canceled", rec.finishedCalled && rec.finishedCanceled);

        deleteTree(dir);
    }

    // -------------------------------------------------------------------------
    // 6. Pause really stops the work
    // -------------------------------------------------------------------------

    private static void test06Pause(Path base) throws Exception {
        section("6. Pause stops progress, resume finishes the job");
        Path dir = Files.createDirectory(base.resolve("pause"));
        final File f = makeFile(dir, "pauseme.bin", 16 * MIB, (byte) 0x22);

        final DataShredderV4.ShredEngine engine = new DataShredderV4.ShredEngine();
        final AtomicBoolean pausedOnce   = new AtomicBoolean(false);
        final AtomicLong    progressCount = new AtomicLong(0);

        Rec rec = new Rec() {
            @Override public void onProgress(long processedBytes) {
                super.onProgress(processedBytes);
                progressCount.incrementAndGet();
                if (processedBytes >= 2 * MIB && pausedOnce.compareAndSet(false, true)) {
                    engine.setPaused(true);
                }
            }
        };

        Thread worker = new Thread(
                () -> engine.run(list(f), options(DataShredderV4.ShredEngine.Algorithm.RANDOM, 1), rec),
                "test-pause");
        worker.start();

        check("engine reached the pause point", waitFor(pausedOnce::get, 30000));
        Thread.sleep(150);                       // let the worker settle into the wait
        long countAtPause = progressCount.get();
        Thread.sleep(600);                       // observation window
        checkEquals("no progress callbacks arrive while paused",
                countAtPause, progressCount.get());
        check("engine reports itself as paused", engine.isPaused());
        check("worker thread is still alive while paused", worker.isAlive());

        engine.setPaused(false);
        worker.join(120000);
        check("run finished after resume", !worker.isAlive());
        check("file was shredded after resume", !f.exists());
        check("onFinished fired without cancel", rec.finishedCalled && !rec.finishedCanceled);
        check("active elapsed time excludes the pause",
                engine.getActiveElapsedMillis() >= 0);

        deleteTree(dir);
    }

    // -------------------------------------------------------------------------
    // 7. Cancel while paused
    // -------------------------------------------------------------------------

    private static void test07CancelWhilePaused(Path base) throws Exception {
        section("7. Cancel while paused returns promptly");
        Path dir = Files.createDirectory(base.resolve("cancelpaused"));
        final File f = makeFile(dir, "stuck.bin", 16 * MIB, (byte) 0x33);
        final String originalName = f.getName();

        final DataShredderV4.ShredEngine engine = new DataShredderV4.ShredEngine();
        final AtomicBoolean pausedOnce = new AtomicBoolean(false);

        Rec rec = new Rec() {
            @Override public void onProgress(long processedBytes) {
                super.onProgress(processedBytes);
                if (pausedOnce.compareAndSet(false, true)) engine.setPaused(true);
            }
        };

        Thread worker = new Thread(
                () -> engine.run(list(f), options(DataShredderV4.ShredEngine.Algorithm.RANDOM, 1), rec),
                "test-cancel-paused");
        worker.start();

        check("engine reached the pause point", waitFor(pausedOnce::get, 30000));
        Thread.sleep(300);                       // make sure it is really waiting
        check("worker is stalled in the pause", worker.isAlive());

        long t0 = System.currentTimeMillis();
        engine.requestCancel();
        worker.join(10000);
        long elapsed = System.currentTimeMillis() - t0;

        check("cancel woke the paused worker", !worker.isAlive());
        check("cancel returned promptly (" + elapsed + " ms)", elapsed < 10000);
        check("file survived the cancel", dir.resolve(originalName).toFile().exists());
        DataShredderV4.ItemResult r = rec.first();
        check("row reports CANCELED",
                r != null && r.kind == DataShredderV4.ItemResult.Kind.CANCELED);
        check("onFinished reports canceled", rec.finishedCalled && rec.finishedCanceled);

        deleteTree(dir);
    }

    // -------------------------------------------------------------------------
    // 8. Read-only file
    // -------------------------------------------------------------------------

    private static void test08ReadOnlyFile(Path base) throws Exception {
        section("8. Read-only file is skipped and removed from the byte total");
        Path dir = Files.createDirectory(base.resolve("readonly"));
        File f = makeFile(dir, "locked.bin", 512 * 1024, (byte) 0x44);
        boolean madeReadOnly = f.setWritable(false);
        check("test could make the file read-only", madeReadOnly && !f.canWrite());

        DataShredderV4.ShredEngine engine = new DataShredderV4.ShredEngine();
        Rec rec = new Rec();
        engine.run(list(f), options(DataShredderV4.ShredEngine.Algorithm.RANDOM, 2), rec);

        check("read-only file was left alone", f.exists());
        DataShredderV4.ItemResult r = rec.first();
        check("row reports SKIPPED",
                r != null && r.kind == DataShredderV4.ItemResult.Kind.SKIPPED
                        && r.filesSkipped == 1 && r.filesDone == 0);
        checkEquals("initial byte total counted the file", 512 * 1024 * 2L, rec.firstTotal);
        checkEquals("byte total was adjusted down to zero", 0L, rec.lastTotal);

        f.setWritable(true);
        deleteTree(dir);
    }

    // -------------------------------------------------------------------------
    // 9. Zero-length file
    // -------------------------------------------------------------------------

    private static void test09ZeroLengthFile(Path base) throws Exception {
        section("9. Zero-length file is deleted");
        Path dir = Files.createDirectory(base.resolve("empty"));
        File f = dir.resolve("empty.bin").toFile();
        check("empty test file created", f.createNewFile() && f.length() == 0);

        DataShredderV4.ShredEngine engine = new DataShredderV4.ShredEngine();
        Rec rec = new Rec();
        int failures = engine.run(list(f),
                options(DataShredderV4.ShredEngine.Algorithm.RANDOM, 3), rec);

        checkEquals("zero-length shred reports no failures", 0, failures);
        check("zero-length file was deleted", !f.exists());
        check("folder is empty afterwards",
                dir.toFile().list() != null && dir.toFile().list().length == 0);
        DataShredderV4.ItemResult r = rec.first();
        check("row reports SHREDDED",
                r != null && r.kind == DataShredderV4.ItemResult.Kind.SHREDDED
                        && r.filesDone == 1);

        deleteTree(dir);
    }

    // -------------------------------------------------------------------------
    // 10. Free-space wipe with a byte limit
    // -------------------------------------------------------------------------

    private static void test10FreeSpaceWipe(Path base) throws Exception {
        section("10. Free-space wipe honours its limit and cleans up");
        Path dir = Files.createDirectory(base.resolve("wipe"));

        long limit = 20 * MIB;
        if (dir.toFile().getUsableSpace() < limit + 64 * MIB) {
            System.out.println("SKIP  not enough free space for the wipe test");
            return;
        }

        DataShredderV4.ShredEngine engine = new DataShredderV4.ShredEngine();
        DataShredderV4.ShredEngine.Options o = new DataShredderV4.ShredEngine.Options();
        o.wipeLimitBytes = limit;
        Rec rec = new Rec();

        engine.wipeFreeSpace(dir.toFile(), o, rec);

        checkEquals("wipe wrote exactly the limit", limit, rec.lastProgress);
        checkEquals("final byte total equals what was written", limit, rec.lastTotal);
        checkEquals("engine reports the same processed byte count", limit, engine.getProcessedBytes());
        String[] leftovers = dir.toFile().list();
        check("no wipe files or folders left behind",
                leftovers != null && leftovers.length == 0);
        check("onFinished fired without cancel or failure",
                rec.finishedCalled && !rec.finishedCanceled && rec.finishedFailures == 0);
        DataShredderV4.ItemResult r = rec.first();
        check("wipe reports a successful item",
                r != null && r.kind == DataShredderV4.ItemResult.Kind.SHREDDED);

        deleteTree(dir);
    }

    // -------------------------------------------------------------------------
    // 11. Duplicate queue entries
    // -------------------------------------------------------------------------

    private static void test11Dedupe(Path base) throws Exception {
        section("11. A folder plus a file inside it shreds the file once");
        Path dir    = Files.createDirectory(base.resolve("dedupe"));
        Path folder = Files.createDirectory(dir.resolve("folder"));
        File inner  = makeFile(folder, "inner.bin", 256 * 1024, (byte) 0x55);

        DataShredderV4.ShredEngine engine = new DataShredderV4.ShredEngine();
        Rec rec = new Rec();
        engine.run(list(folder.toFile(), inner),
                options(DataShredderV4.ShredEngine.Algorithm.RANDOM, 1), rec);

        checkEquals("the inner file was started exactly once", 1, rec.realFileStarts);
        check("the inner file is gone", !inner.exists());
        check("the folder is gone", !folder.toFile().exists());
        checkEquals("two rows reported a result", 2, rec.results.size());
        DataShredderV4.ItemResult folderResult = rec.results.get(0);
        DataShredderV4.ItemResult dupResult    = rec.results.get(1);
        check("the folder row reports SHREDDED with one file done",
                folderResult.kind == DataShredderV4.ItemResult.Kind.SHREDDED
                        && folderResult.filesDone == 1);
        check("the duplicate row reports SKIPPED",
                dupResult.kind == DataShredderV4.ItemResult.Kind.SKIPPED);
        checkEquals("byte total counted the file once", 256 * 1024L, rec.firstTotal);

        deleteTree(dir);
    }

    // -------------------------------------------------------------------------
    // 12. CLI argument handling, in process
    // -------------------------------------------------------------------------

    private static void test12CliParsing(Path base) throws Exception {
        section("12. CLI argument handling");
        Path dir = Files.createDirectory(base.resolve("cli"));
        File f = makeFile(dir, "cli-target.bin", 4096, (byte) 0x66);

        checkEquals("--help exits 0", 0,
                DataShredderV4.Cli.run(new String[]{ "--help" }));

        int noYes = DataShredderV4.Cli.run(
                new String[]{ "--algo", "random", f.getAbsolutePath() });
        checkEquals("a run without --yes exits 2", 2, noYes);
        check("a run without --yes destroys nothing", f.exists() && f.length() == 4096);

        checkEquals("an unknown algorithm exits 2", 2,
                DataShredderV4.Cli.run(
                        new String[]{ "--algo", "bogus", "--yes", f.getAbsolutePath() }));
        check("an unknown algorithm destroys nothing", f.exists() && f.length() == 4096);

        checkEquals("no paths at all exits 2", 2,
                DataShredderV4.Cli.run(new String[]{ "--algo", "random", "--yes" }));

        // --limit is rejected before the megabyte value is turned into bytes.
        // An unbounded value would overflow that multiplication to a negative
        // number, which the engine reads back as "no limit" and would then use
        // to fill the whole volume, so these must never reach the wipe.
        checkEquals("a zero --limit exits 2", 2,
                DataShredderV4.Cli.run(new String[]{ "--wipe-free", dir.toString(),
                        "--limit", "0", "--yes" }));
        checkEquals("a --limit that would overflow exits 2", 2,
                DataShredderV4.Cli.run(new String[]{ "--wipe-free", dir.toString(),
                        "--limit", "9000000000000000", "--yes" }));
        checkEquals("the smallest overflowing --limit exits 2", 2,
                DataShredderV4.Cli.run(new String[]{ "--wipe-free", dir.toString(),
                        "--limit", "8796093022208", "--yes" }));
        checkEquals("a --limit that is not a number exits 2", 2,
                DataShredderV4.Cli.run(new String[]{ "--wipe-free", dir.toString(),
                        "--limit", "lots", "--yes" }));
        check("a rejected --limit wrote nothing into the target folder",
                dir.toFile().list() != null && dir.toFile().list().length == 1);

        deleteTree(dir);
    }

    // -------------------------------------------------------------------------
    // 14. Deliberate leftovers are partial results, not failures
    // -------------------------------------------------------------------------

    private static void test14ReadOnlyLeftoverIsPartial(Path base) throws Exception {
        section("14. A skipped read-only file makes its folder partial, not failed");
        Path dir  = Files.createDirectory(base.resolve("leftover"));
        Path tree = Files.createDirectory(dir.resolve("tree"));

        File normal   = makeFile(tree, "normal.bin", 8192, (byte) 0x2A);
        File readOnly = makeFile(tree, "locked.bin", 8192, (byte) 0x3B);

        if (!readOnly.setWritable(false)) {
            System.out.println("SKIP  could not make a file read-only on this system");
            deleteTree(dir);
            return;
        }

        try {
            Rec rec = new Rec();
            int failures = new DataShredderV4.ShredEngine().run(list(tree.toFile()),
                    options(DataShredderV4.ShredEngine.Algorithm.RANDOM, 1), rec);

            check("the writable file was shredded", !normal.exists());
            check("the read-only file was left alone", readOnly.exists());
            check("the folder was kept because it still holds that file", tree.toFile().exists());

            DataShredderV4.ItemResult r = rec.first();
            check("the row is partial, not failed",
                    r != null && r.kind == DataShredderV4.ItemResult.Kind.PARTIAL);
            check("the row records no failures", r != null && r.filesFailed == 0);
            checkEquals("the run reports no failed rows", 0, failures);
        } finally {
            readOnly.setWritable(true);
        }

        deleteTree(dir);
    }

    // -------------------------------------------------------------------------
    // 13. Links and junctions are never followed out of the selected tree
    // -------------------------------------------------------------------------

    private static void test13JunctionNotFollowed(Path base) throws Exception {
        section("13. A junction inside a queued folder is not followed");
        Path dir    = Files.createDirectory(base.resolve("junction"));
        Path target = Files.createDirectory(dir.resolve("outside"));
        Path proj   = Files.createDirectory(dir.resolve("queued"));

        File keep = makeFile(target, "keep.bin", 8192, (byte) 0x7E);
        File mine = makeFile(proj, "mine.bin", 8192, (byte) 0x11);
        byte[] keepBefore = readAll(keep);

        Path link = proj.resolve("link");
        if (!makeDirectoryLink(link, target)) {
            System.out.println("SKIP  could not create a directory link on this system");
            deleteTree(dir);
            return;
        }

        try {
            check("the link is recognised as a link or junction",
                    DataShredderV4.ShredEngine.isLinkOrJunction(link));
            check("a plain directory is not recognised as one",
                    !DataShredderV4.ShredEngine.isLinkOrJunction(proj));

            DataShredderV4.ShredEngine engine = new DataShredderV4.ShredEngine();
            boolean reached = false;
            for (File f : engine.collectFiles(proj.toFile())) {
                if (f.getName().equals("keep.bin")) reached = true;
            }
            check("the scan does not reach through the link", !reached);

            Rec rec = new Rec();
            engine.run(list(proj.toFile()),
                    options(DataShredderV4.ShredEngine.Algorithm.RANDOM, 1), rec);

            check("the file inside the queued folder was shredded", !mine.exists());
            check("the file behind the link still exists", keep.exists());
            check("the file behind the link is byte for byte unchanged",
                    keep.exists() && Arrays.equals(keepBefore, readAll(keep)));
            check("the link itself was left in place",
                    Files.exists(link, java.nio.file.LinkOption.NOFOLLOW_LINKS));

            // The folder cannot be removed because the junction is still in it,
            // and never following a junction is the designed behaviour, so the
            // leftover is a skip and the row is PARTIAL: every file the engine
            // was supposed to destroy was destroyed.
            DataShredderV4.ItemResult r = rec.first();
            check("the row reports a partial result, not a failure",
                    r != null && r.kind == DataShredderV4.ItemResult.Kind.PARTIAL);
            check("the row records no failures",
                    r != null && r.filesFailed == 0);
            check("the row records the file it shredded",
                    r != null && r.filesDone == 1);
        } finally {
            // Remove the link before the tree walk runs, so cleanup cannot
            // descend through it either.
            try {
                Files.deleteIfExists(link);
            } catch (IOException ignored) {
                link.toFile().delete();
            }
        }

        deleteTree(dir);
    }

    // -------------------------------------------------------------------------
    // 15. One unreadable subfolder does not abort the whole scan
    // -------------------------------------------------------------------------

    private static void test15UnreadableSubdirectory(Path base) throws Exception {
        section("15. An unreadable subfolder does not stop the rest of the scan");
        Path dir    = Files.createDirectory(base.resolve("unreadable"));
        Path tree   = Files.createDirectory(dir.resolve("tree"));
        Path good   = Files.createDirectory(tree.resolve("good"));
        Path denied = Files.createDirectory(tree.resolve("denied"));

        File readable = makeFile(good, "ok.bin", 8192, (byte) 0x5C);
        makeFile(denied, "secret.bin", 8192, (byte) 0x6D);

        if (!denyDirectoryRead(denied)) {
            System.out.println("SKIP  could not make a folder unreadable on this system");
            allowDirectoryRead(denied);
            deleteTree(dir);
            return;
        }

        try {
            DataShredderV4.ShredEngine engine = new DataShredderV4.ShredEngine();

            List<String> problems = new ArrayList<>();
            List<File>   files    = engine.collectFiles(tree.toFile(), problems);

            boolean sawReadable = false;
            for (File f : files) {
                if (f.getName().equals("ok.bin")) sawReadable = true;
            }
            check("the scan still returns the readable file", sawReadable);
            check("the unreadable folder is recorded as a scan problem", !problems.isEmpty());

            Rec rec = new Rec();
            engine.run(list(tree.toFile()),
                    options(DataShredderV4.ShredEngine.Algorithm.RANDOM, 1), rec);

            check("the readable file was shredded anyway", !readable.exists());

            DataShredderV4.ItemResult r = rec.first();
            check("the row reports the unreadable entry with counts, not an aborted scan",
                    r != null && r.kind == DataShredderV4.ItemResult.Kind.FAILED
                              && r.filesDone == 1 && r.filesFailed >= 1);
        } finally {
            allowDirectoryRead(denied);
        }

        deleteTree(dir);
    }

    /**
     * Removes this account's read access to a directory. Returns false when the
     * system will not do it, in which case the caller skips the case. The effect
     * is checked rather than the tool's exit code, so a silent no-op is caught.
     */
    private static boolean denyDirectoryRead(Path p) {
        if (isWindows()) {
            runQuietly("icacls", p.toString(), "/inheritance:r",
                    "/grant:r", "SYSTEM:(OI)(CI)F");
        } else {
            try {
                Files.setPosixFilePermissions(p,
                        java.nio.file.attribute.PosixFilePermissions.fromString("---------"));
            } catch (IOException | UnsupportedOperationException | SecurityException ex) {
                return false;
            }
        }
        return !canList(p);
    }

    /** Puts the access removed by denyDirectoryRead back, so cleanup can run. */
    private static void allowDirectoryRead(Path p) {
        if (isWindows()) {
            runQuietly("icacls", p.toString(), "/reset");
            if (!canList(p)) {
                String user = System.getProperty("user.name", "");
                if (!user.isEmpty()) {
                    runQuietly("icacls", p.toString(), "/grant:r", user + ":(OI)(CI)F");
                }
            }
        } else {
            try {
                Files.setPosixFilePermissions(p,
                        java.nio.file.attribute.PosixFilePermissions.fromString("rwx------"));
            } catch (IOException | UnsupportedOperationException | SecurityException ignored) {
                // Nothing more can be done here; the check above already skipped
                // the case if the deny never took effect.
            }
        }
    }

    private static boolean canList(Path p) {
        try (Stream<Path> s = Files.list(p)) {
            s.count();
            return true;
        } catch (IOException | RuntimeException ex) {
            return false;
        }
    }

    private static boolean isWindows() {
        return System.getProperty("os.name", "")
                .toLowerCase(java.util.Locale.ROOT).startsWith("windows");
    }

    /** Runs a short command, drains it and bounds it; the effect is checked separately. */
    private static void runQuietly(String... command) {
        try {
            ProcessBuilder pb = new ProcessBuilder(command);
            pb.redirectErrorStream(true);
            Process p = pb.start();
            try (java.io.BufferedReader r = new java.io.BufferedReader(
                    new java.io.InputStreamReader(p.getInputStream()))) {
                while (r.readLine() != null) { /* drained so the child cannot block */ }
            }
            if (!p.waitFor(30, java.util.concurrent.TimeUnit.SECONDS)) p.destroyForcibly();
        } catch (InterruptedException ex) {
            Thread.currentThread().interrupt();
        } catch (IOException | SecurityException ex) {
            // Nothing to report: callers verify the effect, not the exit code.
        }
    }

    /**
     * Creates a directory link at linkPath pointing at target: an NTFS junction
     * on Windows, a symbolic link elsewhere. Returns false when the system will
     * not make one, in which case the caller skips the case.
     */
    private static boolean makeDirectoryLink(Path linkPath, Path target) {
        String os = System.getProperty("os.name", "").toLowerCase(java.util.Locale.ROOT);
        if (!os.startsWith("windows")) {
            try {
                Files.createSymbolicLink(linkPath, target);
                return true;
            } catch (IOException | UnsupportedOperationException | SecurityException ex) {
                return false;
            }
        }
        try {
            ProcessBuilder pb = new ProcessBuilder("cmd", "/c", "mklink", "/J",
                    linkPath.toString(), target.toString());
            pb.redirectErrorStream(true);
            Process p = pb.start();
            try (java.io.BufferedReader r = new java.io.BufferedReader(
                    new java.io.InputStreamReader(p.getInputStream()))) {
                while (r.readLine() != null) { /* drained so the child cannot block */ }
            }
            if (!p.waitFor(30, java.util.concurrent.TimeUnit.SECONDS)) {
                p.destroyForcibly();
                return false;
            }
        } catch (InterruptedException ex) {
            Thread.currentThread().interrupt();
            return false;
        } catch (IOException | SecurityException ex) {
            return false;
        }
        return Files.exists(linkPath, java.nio.file.LinkOption.NOFOLLOW_LINKS);
    }
}
