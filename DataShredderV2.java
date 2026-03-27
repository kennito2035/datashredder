/**
 * DataShredder v2.0.0
 *
 * Multi-algorithm file/directory shredder with cancel and ETA.
 *
 * Algorithms:
 *  - RANDOM     : Configurable passes of cryptographically random data
 *  - DOD3       : DoD 5220.22-M  (zeros -> ones -> random)
 *  - GUTMANN    : Gutmann 35-pass (deterministic pattern order, not shuffled)
 *  - ZERO       : Single zero-fill pass with post-write verification
 *  - NVME_PURGE : NIST SP 800-88 inspired 4-pass ending in zeros, with verification
 */

import javax.swing.*;
import java.awt.*;
import java.io.File;
import java.io.IOException;
import java.io.RandomAccessFile;
import java.nio.channels.FileChannel;
import java.nio.channels.FileLock;
import java.nio.file.Files;
import java.nio.file.LinkOption;
import java.nio.file.Path;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.stream.Stream;

public class DataShredderV2 extends JFrame {

    private static final long serialVersionUID = 2000L;
    private static final SecureRandom RANDOM = new SecureRandom();
    private static final int BUFFER_SIZE = 65536; // 64 KB
    private static final int DEFAULT_PASSES = 3;

    // -------------------------------------------------------------------------
    // Algorithm definitions
    // -------------------------------------------------------------------------

    private enum ShredAlgorithm {
        RANDOM    ("Random Data Overwrite (Custom Passes)",		false),
        DOD3      ("DoD 5220.22-M Standard (3 Passes)",			false),
        GUTMANN   ("Gutmann Method (35 Passes)",				false),
        ZERO      ("Zero Overwrite (1 Pass + Verify)",			true),
        NVME_PURGE("NIST SP 800-88 Purge (4 Passes + Verify)",	true);

        final String displayName;
        /** True only when the algorithm's final pass writes zeros and we should verify. */
        final boolean requiresZeroVerification;

        ShredAlgorithm(String displayName, boolean requiresZeroVerification) {
            this.displayName = displayName;
            this.requiresZeroVerification = requiresZeroVerification;
        }

        @Override public String toString() { return displayName; }
    }

    // -------------------------------------------------------------------------
    // UI fields
    // -------------------------------------------------------------------------

    private JLabel                     filePathLabel;
    private JButton                    browseButton;
    private JButton                    shredButton;
    private JButton                    cancelButton;
    private JProgressBar               progressBar;
    private JSpinner                   passesSpinner;
    private JComboBox<ShredAlgorithm>  algorithmComboBox;

    // -------------------------------------------------------------------------
    // Runtime state
    // -------------------------------------------------------------------------

    private final List<File>  selectedFiles    = new ArrayList<>();
    private volatile boolean  shreddingActive  = false;
    private volatile long     totalBytes       = 0;
    private volatile long     processedBytes   = 0;
    private volatile long     startTimeMs      = 0;
    private volatile double   averageSpeedKBs  = 0; // KB per second

    // -------------------------------------------------------------------------
    // Construction
    // -------------------------------------------------------------------------

    public DataShredderV2() {
        initializeUI();
        setupWindowListener();
        setupEventHandlers();
        updatePassesState();
    }

    // -------------------------------------------------------------------------
    // UI setup
    // -------------------------------------------------------------------------

    private void initializeUI() {
        setTitle("File Shredder v2.0.0");
        setSize(700, 300);
        setResizable(false);
        setDefaultCloseOperation(JFrame.DO_NOTHING_ON_CLOSE);
        setLayout(new GridBagLayout());

        GridBagConstraints gbc = new GridBagConstraints();
        gbc.insets = new Insets(5, 5, 5, 5);
        gbc.fill   = GridBagConstraints.HORIZONTAL;

        // Row 0: Algorithm
        gbc.gridx = 0; gbc.gridy = 0; gbc.gridwidth = 1;
        add(new JLabel("Algorithm:"), gbc);
        gbc.gridx = 1;
        algorithmComboBox = new JComboBox<>(ShredAlgorithm.values());
        add(algorithmComboBox, gbc);

        // Row 1: Passes
        gbc.gridx = 0; gbc.gridy = 1;
        add(new JLabel("Passes:"), gbc);
        gbc.gridx = 1;
        passesSpinner = new JSpinner(new SpinnerNumberModel(DEFAULT_PASSES, 1, 100, 1));
        add(passesSpinner, gbc);

        // Row 2: Buttons
        gbc.gridx = 0; gbc.gridy = 2; gbc.gridwidth = 2;
        JPanel btnPanel = new JPanel(new FlowLayout(FlowLayout.CENTER, 8, 0));
        browseButton = new JButton("Browse Files/Dirs");
        shredButton  = new JButton("Secure Shred");
        cancelButton = new JButton("Cancel");
        cancelButton.setEnabled(false);
        btnPanel.add(browseButton);
        btnPanel.add(shredButton);
        btnPanel.add(cancelButton);
        add(btnPanel, gbc);

        // Row 3: File path label
        gbc.gridy = 3;
        filePathLabel = new JLabel("No files selected.");
        add(filePathLabel, gbc);

        // Row 4: Progress bar
        gbc.gridy = 4;
        progressBar = new JProgressBar(0, 100);
        progressBar.setStringPainted(true);
        progressBar.setPreferredSize(new Dimension(650, 25));
        progressBar.setString("Ready.");
        add(progressBar, gbc);

        setLocationRelativeTo(null);
    }

    private void setupWindowListener() {
        addWindowListener(new java.awt.event.WindowAdapter() {
            @Override
            public void windowClosing(java.awt.event.WindowEvent e) {
                if (shreddingActive) {
                    int choice = JOptionPane.showConfirmDialog(
                            DataShredderV2.this,
                            "Shredding is in progress! Really exit?",
                            "Confirm Exit",
                            JOptionPane.YES_NO_OPTION,
                            JOptionPane.WARNING_MESSAGE);
                    if (choice != JOptionPane.YES_OPTION) return;
                }
                System.exit(0);
            }
        });
    }

    private void setupEventHandlers() {
        algorithmComboBox.addActionListener(e -> updatePassesState());
        browseButton.addActionListener(e -> handleFileSelection());
        shredButton .addActionListener(e -> startShreddingProcess());
        cancelButton.addActionListener(e -> {
            int confirm = JOptionPane.showConfirmDialog(DataShredderV2.this,
                    "Cancel the shredding operation?", "Confirm Cancel",
                    JOptionPane.YES_NO_OPTION);
            if (confirm == JOptionPane.YES_OPTION) {
                shreddingActive = false;
                cancelButton.setEnabled(false);
                progressBar.setString("Canceling...");
            }
        });
    }

    private void updatePassesState() {
        ShredAlgorithm algo = (ShredAlgorithm) algorithmComboBox.getSelectedItem();
        switch (algo) {
            case RANDOM:     passesSpinner.setValue(DEFAULT_PASSES); passesSpinner.setEnabled(true);  break;
            case DOD3:       passesSpinner.setValue(3);              passesSpinner.setEnabled(false); break;
            case GUTMANN:    passesSpinner.setValue(35);             passesSpinner.setEnabled(false); break;
            case ZERO:       passesSpinner.setValue(1);              passesSpinner.setEnabled(false); break;
            case NVME_PURGE: passesSpinner.setValue(4);              passesSpinner.setEnabled(false); break;
        }
    }

    // -------------------------------------------------------------------------
    // File selection
    // -------------------------------------------------------------------------

    private void handleFileSelection() {
        JFileChooser chooser = new JFileChooser();
        chooser.setMultiSelectionEnabled(true);
        chooser.setFileSelectionMode(JFileChooser.FILES_AND_DIRECTORIES);

        if (chooser.showOpenDialog(this) == JFileChooser.APPROVE_OPTION) {
            selectedFiles.clear();
            for (File f : chooser.getSelectedFiles()) {
                if (f.exists() && !Files.isSymbolicLink(f.toPath())) {
                    selectedFiles.add(f);
                }
            }
            updateFilePathLabel();
        }
    }

    /**
     * Recursively expands directories into their constituent regular files.
     * Uses try-with-resources to guarantee the Files.walk stream is closed.
     */
    private List<File> collectFiles(List<File> inputs) {
        List<File> result = new ArrayList<>();
        for (File f : inputs) {
            if (f.isDirectory()) {
                try (Stream<Path> walk = Files.walk(f.toPath())) {
                    walk.filter(p -> !Files.isSymbolicLink(p))
                        .filter(p -> Files.isRegularFile(p, LinkOption.NOFOLLOW_LINKS))
                        .map(Path::toFile)
                        .forEach(result::add);
                } catch (IOException ex) {
                    showError("Error scanning directory: " + ex.getMessage());
                }
            } else if (f.isFile()) {
                result.add(f);
            }
        }
        return result;
    }

    // -------------------------------------------------------------------------
    // Shredding orchestration
    // -------------------------------------------------------------------------

    private void startShreddingProcess() {
        List<File> filesToProcess = collectFiles(selectedFiles);

        if (filesToProcess.isEmpty()) {
            JOptionPane.showMessageDialog(this, "Please select files or directories first!");
            return;
        }

        // NOTE: containsSSDLocation is intentionally a stub.
        // Real SSD detection requires native OS calls (WMI on Windows, diskutil on macOS).
        // Path-name heuristics produce too many false positives to be useful.

        int confirm = JOptionPane.showConfirmDialog(this,
                "This will permanently destroy " + filesToProcess.size() + " file(s).\nProceed?",
                "Confirmation", JOptionPane.YES_NO_OPTION, JOptionPane.WARNING_MESSAGE);
        if (confirm != JOptionPane.YES_OPTION) return;

        ShredAlgorithm algo = (ShredAlgorithm) algorithmComboBox.getSelectedItem();

        shreddingActive = true;
        shredButton .setEnabled(false);
        browseButton.setEnabled(false);
        cancelButton.setEnabled(true);
        progressBar.setValue(0);
        progressBar.setString("Starting...");
        startTimeMs     = System.currentTimeMillis();
        averageSpeedKBs = 0;

        totalBytes     = filesToProcess.stream().mapToLong(File::length).sum() * getTotalPasses(algo);
        processedBytes = 0;

        new Thread(() -> runShredding(filesToProcess, algo), "shredder-thread").start();
    }

    private void runShredding(List<File> files, ShredAlgorithm algo) {
        List<String> errors    = new ArrayList<>();
        int successCount       = 0;
        boolean wasCanceled    = false;

        try {
            for (File file : files) {
                if (!shreddingActive) { wasCanceled = true; break; }

                try {
                    if (!file.exists()) {
                        errors.add("Not found: " + file.getName()); continue;
                    }
                    if (!file.canWrite()) {
                        errors.add("Skipped (read-only): " + file.getName()); continue;
                    }
                    if (Files.isSymbolicLink(file.toPath())) {
                        errors.add("Skipped (symbolic link): " + file.getName()); continue;
                    }

                    shredFile(file, algo);

                    if (algo.requiresZeroVerification) {
                        verifyZeroFill(file);
                    }

                    boolean deleted = deleteFilePermanently(file);
                    if (deleted) {
                        successCount++;
                        final String name = file.getName();
                        SwingUtilities.invokeLater(() ->
                                progressBar.setString("Shredded: " + name));
                    } else {
                        errors.add("Shredded but could not delete: " + file.getName());
                    }

                } catch (IOException ex) {
                    errors.add(file.getName() + ": " + ex.getMessage());
                }
            }
        } finally {
            final int          finalSuccess  = successCount;
            final int          finalTotal    = files.size();
            final boolean      finalCanceled = wasCanceled || !shreddingActive;
            final List<String> finalErrors   = new ArrayList<>(errors);

            shreddingActive = false;
            SwingUtilities.invokeLater(() -> {
                selectedFiles.clear();
                filePathLabel.setText("No files selected.");
                progressBar.setValue(0);
                progressBar.setString("Ready.");
                shredButton .setEnabled(true);
                browseButton.setEnabled(true);
                cancelButton.setEnabled(false);
                showFinalReport(finalErrors, finalSuccess, finalTotal, finalCanceled);
            });
        }
    }

    private int getTotalPasses(ShredAlgorithm algo) {
        switch (algo) {
            case GUTMANN:    return 35;
            case DOD3:       return 3;
            case NVME_PURGE: return 4;
            case ZERO:       return 1;
            default:         return (Integer) passesSpinner.getValue();
        }
    }

    // -------------------------------------------------------------------------
    // Shred dispatch
    // -------------------------------------------------------------------------

    private void shredFile(File file, ShredAlgorithm algo) throws IOException {
        if (!file.exists()) throw new IOException("File does not exist.");
        if (file.length() == 0) return; // nothing to overwrite in an empty file

        final long   fileSize = file.length();
        final byte[] buffer   = new byte[BUFFER_SIZE];

        try (RandomAccessFile raf     = new RandomAccessFile(file, "rw");
             FileChannel       channel = raf.getChannel();
             FileLock           lock    = channel.tryLock()) {

            if (lock == null) throw new IOException("File is locked by another process.");

            switch (algo) {
                case RANDOM:
                    int passes = (Integer) passesSpinner.getValue();
                    for (int i = 0; i < passes && shreddingActive; i++) {
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
            }

            channel.force(true);
        }
    }

    // -------------------------------------------------------------------------
    // Overwrite methods
    // -------------------------------------------------------------------------

    private void overwriteRandom(RandomAccessFile raf, byte[] buffer, long length)
            throws IOException {
        raf.seek(0);
        long written = 0;
        while (written < length && shreddingActive) {
            RANDOM.nextBytes(buffer);
            int writeSize = (int) Math.min(buffer.length, length - written);
            raf.write(buffer, 0, writeSize);
            written += writeSize;
            recordProgress(writeSize);
        }
        raf.getFD().sync();
    }

    private void overwritePattern(RandomAccessFile raf, byte[] buffer, long length, byte pattern)
            throws IOException {
        raf.seek(0);
        Arrays.fill(buffer, pattern);
        long written = 0;
        while (written < length && shreddingActive) {
            int writeSize = (int) Math.min(buffer.length, length - written);
            raf.write(buffer, 0, writeSize);
            written += writeSize;
            recordProgress(writeSize); // was missing in original, causing stalled progress
        }
        raf.getFD().sync();
    }

    private void overwriteCustomPattern(RandomAccessFile raf, byte[] buffer,
                                        long length, byte[] pattern) throws IOException {
        raf.seek(0);
        // Fill buffer by repeating the pattern
        for (int i = 0; i < buffer.length; i++) {
            buffer[i] = pattern[i % pattern.length];
        }
        long written = 0;
        while (written < length && shreddingActive) {
            int writeSize = (int) Math.min(buffer.length, length - written);
            raf.write(buffer, 0, writeSize);
            written += writeSize;
            recordProgress(writeSize);
        }
        raf.getFD().sync();
    }

    /**
     * DoD 5220.22-M three-pass wipe.
     * Correct order: zeros -> ones -> random  (was inverted in original).
     */
    private void overwriteDoD3(RandomAccessFile raf, byte[] buffer, long length)
            throws IOException {
        overwritePattern(raf, buffer, length, (byte) 0x00); // pass 1: zeros
        if (!shreddingActive) return;
        overwritePattern(raf, buffer, length, (byte) 0xFF); // pass 2: ones
        if (!shreddingActive) return;
        overwriteRandom (raf, buffer, length);               // pass 3: random
    }

    /**
     * Gutmann 35-pass wipe.
     * Patterns are applied in the original deterministic order specified by the paper.
     * Shuffling the patterns (as seen in some versions) defeats the algorithm entirely.
     */
    private void overwriteGutmann(RandomAccessFile raf, byte[] buffer, long length)
            throws IOException {

        // Passes 1-4: random
        for (int i = 0; i < 4 && shreddingActive; i++) {
            overwriteRandom(raf, buffer, length);
        }

        // Passes 5-31: deterministic encoding patterns
        byte[][] patterns = {
            {0x55, 0x55, 0x55},                              // 5
            {(byte)0xAA, (byte)0xAA, (byte)0xAA},           // 6
            {(byte)0x92, 0x49, 0x24},                        // 7
            {0x49, 0x24, (byte)0x92},                        // 8
            {0x24, (byte)0x92, 0x49},                        // 9
            {0x00},                                          // 10
            {0x11},                                          // 11
            {0x22},                                          // 12
            {0x33},                                          // 13
            {0x44},                                          // 14
            {0x55},                                          // 15
            {0x66},                                          // 16
            {0x77},                                          // 17
            {(byte)0x88},                                    // 18
            {(byte)0x99},                                    // 19
            {(byte)0xAA},                                    // 20
            {(byte)0xBB},                                    // 21
            {(byte)0xCC},                                    // 22
            {(byte)0xDD},                                    // 23
            {(byte)0xEE},                                    // 24
            {(byte)0xFF},                                    // 25
            {(byte)0x92, 0x49, 0x24},                        // 26
            {0x49, 0x24, (byte)0x92},                        // 27
            {0x24, (byte)0x92, 0x49},                        // 28
            {(byte)0x6D, (byte)0xB6, (byte)0xDB},            // 29
            {(byte)0xB6, (byte)0xDB, 0x6D},                  // 30
            {(byte)0xDB, 0x6D, (byte)0xB6},                  // 31
        };

        for (byte[] pattern : patterns) {
            if (!shreddingActive) return;
            overwriteCustomPattern(raf, buffer, length, pattern);
        }

        // Passes 32-35: random
        for (int i = 0; i < 4 && shreddingActive; i++) {
            overwriteRandom(raf, buffer, length);
        }
    }

    /**
     * NIST SP 800-88 inspired 4-pass purge.
     * Ends with a zero fill, enabling post-write verification.
     */
    private void overwriteNVMePurge(RandomAccessFile raf, byte[] buffer, long length)
            throws IOException {
        byte[] cryptoPattern = new byte[32];
        RANDOM.nextBytes(cryptoPattern);
        overwriteCustomPattern(raf, buffer, length, cryptoPattern);    // pass 1: random key pattern
        if (!shreddingActive) return;

        byte[] complement = new byte[32];
        for (int i = 0; i < 32; i++) complement[i] = (byte) ~cryptoPattern[i];
        overwriteCustomPattern(raf, buffer, length, complement);        // pass 2: bitwise complement
        if (!shreddingActive) return;

        overwriteRandom(raf, buffer, length);                          // pass 3: random
        if (!shreddingActive) return;

        overwritePattern(raf, buffer, length, (byte) 0x00);            // pass 4: zeros (verified after)
    }

    // -------------------------------------------------------------------------
    // Post-write verification
    // -------------------------------------------------------------------------

    /**
     * Verifies that every byte in the file is 0x00.
     * Only called for algorithms whose last pass writes zeros (ZERO, NVME_PURGE).
     * Was incorrectly called after RANDOM/DOD3/GUTMANN in the original code,
     * guaranteeing an IOException for every shred operation with those algorithms.
     */
    private void verifyZeroFill(File file) throws IOException {
        byte[] buffer = new byte[BUFFER_SIZE];
        try (RandomAccessFile raf = new RandomAccessFile(file, "r")) {
            long remaining = raf.length();
            while (remaining > 0 && shreddingActive) {
                int read = raf.read(buffer, 0, (int) Math.min(buffer.length, remaining));
                if (read == -1) break;
                for (int i = 0; i < read; i++) {
                    if (buffer[i] != 0) {
                        throw new IOException(
                                "Zero-fill verification failed at offset " + (raf.getFilePointer() - read + i));
                    }
                }
                remaining -= read;
            }
        }
    }

    // -------------------------------------------------------------------------
    // Deletion
    // -------------------------------------------------------------------------

    private boolean deleteFilePermanently(File file) {
        // 3 retries with 200 ms delay (was up to 102 seconds in original)
        for (int i = 0; i < 3; i++) {
            try {
                Files.deleteIfExists(file.toPath());
                return true;
            } catch (IOException ex) {
                try { Thread.sleep(200); } catch (InterruptedException ie) {
                    Thread.currentThread().interrupt();
                    return false;
                }
            }
        }

        // Last-resort: rename so the original name is freed, schedule JVM-exit delete
        File renamed = new File(file.getParent(), generateRandomName() + ".shred");
        try {
            Files.move(file.toPath(), renamed.toPath());
            renamed.deleteOnExit();
        } catch (IOException ignored) {}
        return false;
    }

    // -------------------------------------------------------------------------
    // Progress tracking
    // -------------------------------------------------------------------------

    private synchronized void recordProgress(int bytes) {
        processedBytes += bytes;

        long elapsed = System.currentTimeMillis() - startTimeMs;
        if (elapsed > 0) {
            averageSpeedKBs = (processedBytes / 1024.0) / (elapsed / 1000.0);
        }

        if (totalBytes <= 0) return;
        long pct = (processedBytes * 100L) / totalBytes;
        // Guard against divide-by-zero: only compute ETA once speed is established
        String eta = (averageSpeedKBs > 0)
                ? formatTime((totalBytes - processedBytes) / (averageSpeedKBs * 1024.0))
                : "--:--:--";
        String label = String.format("%d%% \u2014 %s remaining", pct, eta);

        SwingUtilities.invokeLater(() -> {
            progressBar.setValue((int) Math.min(pct, 100));
            progressBar.setString(label);
        });
    }

    private String formatTime(double seconds) {
        if (Double.isNaN(seconds) || Double.isInfinite(seconds) || seconds < 0) return "--:--:--";
        int h = (int) (seconds / 3600);
        int m = (int) ((seconds % 3600) / 60);
        int s = (int) (seconds % 60);
        return String.format("%02d:%02d:%02d", h, m, s);
    }

    // -------------------------------------------------------------------------
    // UI helpers
    // -------------------------------------------------------------------------

    private void updateFilePathLabel() {
        SwingUtilities.invokeLater(() -> {
            if (selectedFiles.isEmpty()) {
                filePathLabel.setText("No files selected.");
            } else if (selectedFiles.size() == 1) {
                filePathLabel.setText("<html>Selected: "
                        + selectedFiles.get(0).getAbsolutePath() + "</html>");
            } else {
                StringBuilder sb = new StringBuilder(
                        "<html>Selected " + selectedFiles.size() + " items:<br>");
                int preview = Math.min(3, selectedFiles.size());
                for (int i = 0; i < preview; i++) {
                    sb.append("&bull; ").append(selectedFiles.get(i).getName()).append("<br>");
                }
                if (selectedFiles.size() > 3) {
                    sb.append("&bull; ...and ").append(selectedFiles.size() - 3).append(" more");
                }
                filePathLabel.setText(sb + "</html>");
            }
        });
    }

    private void showFinalReport(List<String> errors, int successCount,
                                  int totalCount, boolean wasCanceled) {
        StringBuilder msg = new StringBuilder();
        if (wasCanceled) {
            msg.append("Shredding was canceled.\n\n");
        }
        msg.append("Shredded ").append(successCount).append(" / ")
           .append(totalCount).append(" file(s).");

        if (!errors.isEmpty()) {
            msg.append("\n\nIssues:\n");
            for (String err : errors) msg.append("  \u2022 ").append(err).append("\n");
        }

        int type = errors.isEmpty() && !wasCanceled
                ? JOptionPane.INFORMATION_MESSAGE
                : JOptionPane.WARNING_MESSAGE;
        JOptionPane.showMessageDialog(this, msg.toString(), "Results", type);
    }

    private void showError(String message) {
        SwingUtilities.invokeLater(() ->
                JOptionPane.showMessageDialog(this,
                        "<html><b>Error:</b><br>" + message + "</html>",
                        "Error", JOptionPane.ERROR_MESSAGE));
    }

    // -------------------------------------------------------------------------
    // Utilities
    // -------------------------------------------------------------------------

    private String generateRandomName() {
        // Uses the class-level RANDOM, not a new SecureRandom() per call
        final String chars =
                "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
        int length = 8 + RANDOM.nextInt(9);
        StringBuilder sb = new StringBuilder(length);
        for (int i = 0; i < length; i++) {
            sb.append(chars.charAt(RANDOM.nextInt(chars.length())));
        }
        return sb.toString();
    }

    // -------------------------------------------------------------------------
    // Entry point
    // -------------------------------------------------------------------------

    public static void main(String[] args) {
        SwingUtilities.invokeLater(() -> {
            try {
                UIManager.setLookAndFeel(UIManager.getSystemLookAndFeelClassName());
            } catch (Exception ignored) {}

            Thread.setDefaultUncaughtExceptionHandler((t, ex) ->
                    JOptionPane.showMessageDialog(null,
                            "Unhandled error: " + ex.getMessage(),
                            "Fatal Error", JOptionPane.ERROR_MESSAGE));

            new DataShredderV2().setVisible(true);
        });
    }
}