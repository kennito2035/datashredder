/**
 * DataShredder v3.0.0
 *
 * Full-featured file/directory shredder with crypto erase, filename scrubbing,
 * metadata scrubbing, dark-mode theming, and live ETA.
 *
 * Algorithms:
 *  - RANDOM      : Configurable passes of cryptographically random data
 *  - DOD3        : DoD 5220.22-M  (zeros -> ones -> random, correct order)
 *  - GUTMANN     : Gutmann 35-pass (deterministic order, not shuffled)
 *  - ZERO        : Single zero-fill pass with post-write verification
 *  - NVME_PURGE  : NIST SP 800-88 4-pass ending in zeros, with verification
 *  - CRYPTO_ERASE: ChaCha20 in-place encryption; key discarded after use.
 *                  File content becomes unrecoverable without the key.
 *                  (Uses ChaCha20 via standard JCA — no third-party library needed.)
 */

import javax.crypto.Cipher;
import javax.crypto.spec.ChaCha20ParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import javax.swing.*;
import javax.swing.text.NumberFormatter;
import java.awt.*;
import java.io.File;
import java.io.IOException;
import java.io.RandomAccessFile;
import java.nio.channels.FileChannel;
import java.nio.channels.FileLock;
import java.nio.file.*;
import java.nio.file.attribute.BasicFileAttributeView;
import java.nio.file.attribute.FileTime;
import java.security.GeneralSecurityException;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.stream.Collectors;
import java.util.stream.Stream;

public class DataShredderV3 extends JFrame {

    private static final long serialVersionUID = 3000L;
    private static final SecureRandom RANDOM = new SecureRandom();
    private static final int BUFFER_SIZE  = 1048576; // 1 MB
    private static final int DEFAULT_PASSES = 3;

    // -------------------------------------------------------------------------
    // Algorithm definitions
    // -------------------------------------------------------------------------

    private enum ShredAlgorithm {
        RANDOM      ("Random Data Overwrite (Custom Passes)",					false),
        DOD3        ("DoD 5220.22-M Standard (3 Passes)",						false),
        GUTMANN     ("Gutmann Method (35 Passes)",								false),
        ZERO        ("Zero Overwrite (1 Pass + Verify)",						true),
        NVME_PURGE  ("NIST SP 800-88 Purge (4 Passes + Verify)",				true),
        CRYPTO_ERASE("ChaCha20 Cryptographic Erase (1 Pass, key discarded)",	false);

        final String displayName;
        /** True when the algorithm's final pass writes zeros and should be verified. */
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

    private JLabel                    filePathLabel;
    private JButton                   browseButton;
    private JButton                   shredButton;
    private JButton                   cancelButton;
    private JProgressBar              progressBar;
    private JSpinner                  passesSpinner;
    private JComboBox<ShredAlgorithm> algorithmComboBox;

    // Timers used for transient progress messages
    private Timer messageTimer;
    private Timer resetTimer;

    // -------------------------------------------------------------------------
    // Runtime state
    // -------------------------------------------------------------------------

    private final List<File> selectedFiles    = new ArrayList<>();
    private volatile boolean shreddingActive  = false;
    private volatile long    totalBytes       = 0;
    private volatile long    processedBytes   = 0;
    private volatile long    startTimeMs      = 0;
    private volatile double  averageSpeedKBs  = 0;

    // -------------------------------------------------------------------------
    // Construction
    // -------------------------------------------------------------------------

    public DataShredderV3() {
        initializeUI();
        setupWindowListener();
        setupEventHandlers();
        updatePassesState();
    }

    // -------------------------------------------------------------------------
    // Dark mode
    // -------------------------------------------------------------------------

    /**
     * Returns whether the dark theme should be applied.
     *
     * Currently hardcoded to true. To enable automatic detection, replace this
     * body with: return OsThemeDetector.getDetector().isDark();
     * and add the com.jthemedetecor dependency.
     */
    private static boolean isDarkModeEnabled() {
        return true;
    }

    // -------------------------------------------------------------------------
    // UI setup
    // -------------------------------------------------------------------------

    private void initializeUI() {
        setTitle("Data Shredder v3.0.0");
        setSize(700, 300);
        setResizable(false);
        setDefaultCloseOperation(JFrame.DO_NOTHING_ON_CLOSE);
        setLayout(new GridBagLayout());

        GridBagConstraints gbc = new GridBagConstraints();
        gbc.insets = new Insets(5, 5, 5, 5);
        gbc.fill   = GridBagConstraints.HORIZONTAL;

        boolean dark = isDarkModeEnabled();
        Color labelFg = dark ? Color.WHITE : Color.BLACK;

        // Row 0: Algorithm
        JLabel algorithmLabel = new JLabel("Algorithm:");
        algorithmLabel.setForeground(labelFg);
        gbc.gridx = 0; gbc.gridy = 0; gbc.gridwidth = 1;
        add(algorithmLabel, gbc);
        gbc.gridx = 1;
        algorithmComboBox = new JComboBox<>(ShredAlgorithm.values());
        add(algorithmComboBox, gbc);

        // Row 1: Passes (with input validation — blocks non-numeric entry)
        JLabel passesLabel = new JLabel("Passes:");
        passesLabel.setForeground(labelFg);
        gbc.gridx = 0; gbc.gridy = 1;
        add(passesLabel, gbc);
        gbc.gridx = 1;
        passesSpinner = new JSpinner(new SpinnerNumberModel(DEFAULT_PASSES, 1, 100, 1));
        JSpinner.NumberEditor editor = new JSpinner.NumberEditor(passesSpinner, "#");
        passesSpinner.setEditor(editor);
        ((NumberFormatter) editor.getTextField().getFormatter()).setAllowsInvalid(false);
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
        filePathLabel.setForeground(labelFg);
        add(filePathLabel, gbc);

        // Row 4: Progress bar with forced black text for readability on both themes
        gbc.gridy = 4;
        progressBar = new JProgressBar(0, 100) {
            private static final long serialVersionUID = 3001L;
            @Override public void updateUI() {
                super.updateUI();
                setUI(new javax.swing.plaf.basic.BasicProgressBarUI() {
                    @Override protected Color getSelectionBackground() { return Color.DARK_GRAY; }
                    @Override protected Color getSelectionForeground() { return Color.BLACK; }
                });
            }
        };
        progressBar.setStringPainted(true);
        progressBar.setPreferredSize(new Dimension(650, 25));
        progressBar.setForeground(Color.GRAY);
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
                            DataShredderV3.this,
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
            int confirm = JOptionPane.showConfirmDialog(DataShredderV3.this,
                    "Cancel the shredding operation?", "Confirm Cancel",
                    JOptionPane.YES_NO_OPTION);
            if (confirm == JOptionPane.YES_OPTION) {
                shreddingActive = false;
                cancelButton.setEnabled(false);
                stopMessageTimer();
                progressBar.setString("Canceling...");
                progressBar.setForeground(Color.RED);
                // Reset bar appearance after 3 s
                resetTimer = new Timer(3000, ev -> {
                    progressBar.setString("Ready.");
                    progressBar.setValue(0);
                    progressBar.setForeground(Color.GRAY);
                });
                resetTimer.setRepeats(false);
                resetTimer.start();
            }
        });
    }

    private void updatePassesState() {
        ShredAlgorithm algo = (ShredAlgorithm) algorithmComboBox.getSelectedItem();
        switch (algo) {
            case RANDOM:       passesSpinner.setValue(DEFAULT_PASSES); passesSpinner.setEnabled(true);  break;
            case DOD3:         passesSpinner.setValue(3);              passesSpinner.setEnabled(false); break;
            case GUTMANN:      passesSpinner.setValue(35);             passesSpinner.setEnabled(false); break;
            case ZERO:         passesSpinner.setValue(1);              passesSpinner.setEnabled(false); break;
            case NVME_PURGE:   passesSpinner.setValue(4);              passesSpinner.setEnabled(false); break;
            case CRYPTO_ERASE: passesSpinner.setValue(1);              passesSpinner.setEnabled(false); break;
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
                if (f.exists() && !Files.isSymbolicLink(f.toPath())) selectedFiles.add(f);
            }
            updateFilePathLabel();
        }
    }

    /**
     * Recursively expands directories into regular files only.
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

    /**
     * Collects all sub-directories (deepest first) for post-shred deletion.
     */
    private List<File> collectDirectories(List<File> inputs) {
        List<File> dirs = new ArrayList<>();
        for (File f : inputs) {
            if (!f.isDirectory() || Files.isSymbolicLink(f.toPath())) continue;
            try (Stream<Path> walk = Files.walk(f.toPath())) {
                walk.filter(p -> !Files.isSymbolicLink(p))
                    .filter(p -> Files.isDirectory(p, LinkOption.NOFOLLOW_LINKS))
                    .map(Path::toFile)
                    .forEach(dirs::add);
            } catch (IOException ex) {
                showError("Error scanning directory: " + ex.getMessage());
            }
        }
        // Sort deepest first so child directories are removed before parents
        return dirs.stream()
                .distinct()
                .sorted((a, b) -> Integer.compare(
                        b.getAbsolutePath().length(),
                        a.getAbsolutePath().length()))
                .collect(Collectors.toList());
    }

    // -------------------------------------------------------------------------
    // Shredding orchestration
    // -------------------------------------------------------------------------

    private void startShreddingProcess() {
        stopMessageTimer();
        if (resetTimer != null && resetTimer.isRunning()) resetTimer.stop();

        List<File> filesToProcess = collectFiles(selectedFiles);
        List<File> dirsToDelete   = collectDirectories(selectedFiles);

        if (filesToProcess.isEmpty() && dirsToDelete.isEmpty()) {
            JOptionPane.showMessageDialog(this, "Please select files or directories first!");
            return;
        }

        ShredAlgorithm algo       = (ShredAlgorithm) algorithmComboBox.getSelectedItem();
        int            totalItems = filesToProcess.size() + dirsToDelete.size();

        int confirm = JOptionPane.showConfirmDialog(this,
                "This will permanently destroy " + totalItems + " item(s).\n\nProceed?",
                "Confirmation", JOptionPane.YES_NO_OPTION, JOptionPane.WARNING_MESSAGE);
        if (confirm != JOptionPane.YES_OPTION) return;

        shreddingActive = true;
        browseButton.setEnabled(false);
        shredButton .setEnabled(false);
        cancelButton.setEnabled(true);
        progressBar.setValue(0);
        progressBar.setForeground(Color.GREEN);
        progressBar.setString("Starting...");

        startTimeMs     = System.currentTimeMillis();
        averageSpeedKBs = 0;
        processedBytes  = 0;

        // CRYPTO_ERASE reads + writes each byte once; all others multiply by pass count
        int passMultiplier = (algo == ShredAlgorithm.CRYPTO_ERASE) ? 1 : getTotalPasses(algo);
        totalBytes = filesToProcess.stream().mapToLong(File::length).sum() * passMultiplier;

        new Thread(() -> runShredding(filesToProcess, dirsToDelete, algo), "shredder-thread").start();
    }

    private void runShredding(List<File> files, List<File> dirs, ShredAlgorithm algo) {
        List<String> errors           = new ArrayList<>();
        int          successCount     = 0;
        boolean      wasCanceled      = false;

        // --- Process files ---
        for (File file : files) {
            if (!shreddingActive) { wasCanceled = true; break; }

            try {
                if (!file.exists())   { errors.add("Not found: "        + file.getName()); continue; }
                if (!file.canWrite()) { errors.add("Skipped (read-only): " + file.getName()); continue; }

                shredFile(file, algo);

                if (algo.requiresZeroVerification) verifyZeroFill(file);

                // Scrub metadata and rename before deletion to frustrate name-based recovery
                File scrubbed = scrubFilename(file);
                scrubMetadata(scrubbed);

                if (algo != ShredAlgorithm.CRYPTO_ERASE) {
                    if (deleteFilePermanently(scrubbed)) {
                        successCount++;
                        final String name = file.getName();
                        SwingUtilities.invokeLater(() -> showTransientMessage("Obliterated: " + name));
                    } else {
                        errors.add("Shredded but could not delete: " + file.getName());
                    }
                } else {
                    // Crypto erase: content unrecoverable; file stays on disk (key is gone)
                    successCount++;
                    final String name = file.getName();
                    SwingUtilities.invokeLater(() -> showTransientMessage("Encrypted: " + name));
                }

            } catch (IOException ex) {
                errors.add(file.getName() + ": " + ex.getMessage());
            }
        }

        // --- Remove empty directories (deepest first) ---
        for (File dir : dirs) {
            if (!shreddingActive) { wasCanceled = true; break; }
            try {
                File scrubbed = scrubFilename(dir);
                scrubMetadata(scrubbed);
                if (deleteFilePermanently(scrubbed)) {
                    successCount++;
                } else {
                    errors.add("Could not remove directory: " + dir.getAbsolutePath());
                }
            } catch (IOException ex) {
                errors.add("Directory error " + dir.getName() + ": " + ex.getMessage());
            }
        }

        if (!wasCanceled && !shreddingActive) wasCanceled = true;

        final int          finalSuccess  = successCount;
        final int          finalTotal    = files.size() + dirs.size();
        final boolean      finalCanceled = wasCanceled;
        final List<String> finalErrors   = new ArrayList<>(errors);

        shreddingActive = false;
        SwingUtilities.invokeLater(() -> {
            selectedFiles.clear();
            filePathLabel.setText("No files selected.");
            browseButton.setEnabled(true);
            shredButton .setEnabled(true);
            cancelButton.setEnabled(false);
            showFinalReport(finalErrors, finalSuccess, finalTotal, finalCanceled);
        });
    }

    private int getTotalPasses(ShredAlgorithm algo) {
        switch (algo) {
            case GUTMANN:     return 35;
            case DOD3:        return 3;
            case NVME_PURGE:  return 4;
            case ZERO:        return 1;
            case CRYPTO_ERASE:return 1;
            default:          return (Integer) passesSpinner.getValue();
        }
    }

    // -------------------------------------------------------------------------
    // Shred dispatch
    // -------------------------------------------------------------------------

    private void shredFile(File file, ShredAlgorithm algo) throws IOException {
        if (!file.exists()) throw new IOException("File does not exist.");

        final long fileSize = file.length();
        if (fileSize == 0) return; // nothing to overwrite; caller handles deletion

        final byte[] buffer = new byte[BUFFER_SIZE];

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
                case CRYPTO_ERASE:
                    performCryptoErase(raf, fileSize);
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
            recordProgress(writeSize);
        }
        raf.getFD().sync();
    }

    private void overwriteCustomPattern(RandomAccessFile raf, byte[] buffer,
                                        long length, byte[] pattern) throws IOException {
        raf.seek(0);
        for (int i = 0; i < buffer.length; i++) buffer[i] = pattern[i % pattern.length];
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
     * Correct order per the standard: zeros -> ones -> random.
     */
    private void overwriteDoD3(RandomAccessFile raf, byte[] buffer, long length)
            throws IOException {
        overwritePattern(raf, buffer, length, (byte) 0x00);
        if (!shreddingActive) return;
        overwritePattern(raf, buffer, length, (byte) 0xFF);
        if (!shreddingActive) return;
        overwriteRandom (raf, buffer, length);
    }

    /**
     * Gutmann 35-pass wipe.
     * Pattern order is deterministic as specified by the paper.
     */
    private void overwriteGutmann(RandomAccessFile raf, byte[] buffer, long length)
            throws IOException {
        for (int i = 0; i < 4 && shreddingActive; i++) overwriteRandom(raf, buffer, length);

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

        for (byte[] p : patterns) {
            if (!shreddingActive) return;
            overwriteCustomPattern(raf, buffer, length, p);
        }

        for (int i = 0; i < 4 && shreddingActive; i++) overwriteRandom(raf, buffer, length);
    }

    /**
     * NIST SP 800-88 inspired 4-pass purge.
     * Last pass is zeros, enabling post-write verification.
     */
    private void overwriteNVMePurge(RandomAccessFile raf, byte[] buffer, long length)
            throws IOException {
        byte[] key = new byte[32];
        RANDOM.nextBytes(key);
        overwriteCustomPattern(raf, buffer, length, key);
        if (!shreddingActive) return;

        byte[] complement = new byte[32];
        for (int i = 0; i < 32; i++) complement[i] = (byte) ~key[i];
        overwriteCustomPattern(raf, buffer, length, complement);
        if (!shreddingActive) return;

        overwriteRandom(raf, buffer, length);
        if (!shreddingActive) return;

        overwritePattern(raf, buffer, length, (byte) 0x00);
    }

    /**
     * ChaCha20 in-place cryptographic erase.
     *
     * A random 256-bit key and 96-bit nonce are generated, used to encrypt the
     * file in-place, then securely wiped from memory. Without the key the
     * ciphertext is computationally indistinguishable from random noise.
     *
     * ChaCha20 is available in the standard JDK (Java 11+) with no extra dependencies.
     */
    private void performCryptoErase(RandomAccessFile raf, long fileSize) throws IOException {
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
            byte[] inBuf  = new byte[BUFFER_SIZE];
            long processed = 0;

            while (processed < fileSize && shreddingActive) {
                int read = raf.read(inBuf, 0, (int) Math.min(inBuf.length, fileSize - processed));
                if (read == -1) break;

                byte[] encrypted = cipher.update(inBuf, 0, read);
                if (encrypted != null) {
                    raf.seek(processed);
                    raf.write(encrypted);
                }
                processed += read;
                recordProgress(read);
            }

            byte[] finalBlock = cipher.doFinal();
            if (finalBlock != null && finalBlock.length > 0) {
                raf.seek(processed);
                raf.write(finalBlock);
                recordProgress(finalBlock.length);
            }

        } catch (GeneralSecurityException ex) {
            throw new IOException("ChaCha20 crypto erase failed: " + ex.getMessage(), ex);
        } finally {
            // Wipe key material from heap regardless of success or failure
            Arrays.fill(key,   (byte) 0);
            Arrays.fill(nonce, (byte) 0);
        }
    }

    // -------------------------------------------------------------------------
    // Post-write zero-fill verification
    // -------------------------------------------------------------------------

    /**
     * Verifies every byte in the file is 0x00.
     * Only called after ZERO and NVME_PURGE, both of which end with a zero-fill pass.
     */
    private void verifyZeroFill(File file) throws IOException {
        byte[] buffer = new byte[BUFFER_SIZE];
        try (RandomAccessFile raf = new RandomAccessFile(file, "r")) {
            long remaining = raf.length();
            long offset    = 0;
            while (remaining > 0 && shreddingActive) {
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
            }
        }
    }

    // -------------------------------------------------------------------------
    // Metadata and filename scrubbing
    // -------------------------------------------------------------------------

    /**
     * Scrubs the file's timestamps by setting them to Unix epoch (1970-01-01).
     */
    private void scrubMetadata(File file) {
        try {
            BasicFileAttributeView attrs = Files.getFileAttributeView(
                    file.toPath(), BasicFileAttributeView.class);
            FileTime epoch = FileTime.fromMillis(0);
            attrs.setTimes(epoch, epoch, epoch);
        } catch (IOException ignored) {
            // Non-fatal: some file systems don't support all timestamp attributes
        }
    }

    /**
     * Renames the file three times to random names to frustrate directory-entry recovery.
     */
    private File scrubFilename(File file) throws IOException {
        Path current = file.toPath();
        for (int i = 0; i < 3; i++) {
            Path next = current.resolveSibling(generateRandomName());
            try {
                Files.move(current, next, StandardCopyOption.ATOMIC_MOVE);
            } catch (AtomicMoveNotSupportedException ex) {
                Files.move(current, next); // fallback if filesystem doesn't support atomic move
            }
            current = next;
        }
        return current.toFile();
    }

    // -------------------------------------------------------------------------
    // Deletion
    // -------------------------------------------------------------------------

    private boolean deleteFilePermanently(File file) {
        // 3 retries with 200 ms delay (original had up to ~102 seconds)
        for (int i = 0; i < 3; i++) {
            try {
                file.setWritable(true);
                Files.deleteIfExists(file.toPath());
                return true;
            } catch (IOException ex) {
                System.err.println("Delete attempt " + (i + 1) + " failed: " + ex.getMessage());
                try { Thread.sleep(200); } catch (InterruptedException ie) {
                    Thread.currentThread().interrupt();
                    return false;
                }
            }
        }
        return false;
    }

    // -------------------------------------------------------------------------
    // Progress tracking
    // -------------------------------------------------------------------------

    /**
     * Records bytes written and updates the progress bar on the EDT.
     */
    private synchronized void recordProgress(int bytes) {
        processedBytes += bytes;

        long elapsed = System.currentTimeMillis() - startTimeMs;
        if (elapsed > 0) {
            averageSpeedKBs = (processedBytes / 1024.0) / (elapsed / 1000.0);
        }

        if (totalBytes <= 0) return;
        long   pct = (processedBytes * 100L) / totalBytes;
        String eta = (averageSpeedKBs > 0)
                ? formatTime((totalBytes - processedBytes) / (averageSpeedKBs * 1024.0))
                : "--:--:--";
        String label = String.format("%d%% \u2014 %s remaining...", pct, eta);

        SwingUtilities.invokeLater(() -> {
            if (shreddingActive) {
                progressBar.setValue((int) Math.min(pct, 100));
                progressBar.setString(label);
            }
        });
    }

    /**
     * Shows a transient file-specific message on the progress bar,
     * then reverts to the ETA display after 2.5 seconds.
     */
    private void showTransientMessage(String message) {
        stopMessageTimer();
        progressBar.setString(message);

        messageTimer = new Timer(2500, e -> {
            // Revert to progress display without calling recordProgress(0)
            if (shreddingActive) {
                synchronized (DataShredderV3.this) {
                    long pct = (totalBytes > 0) ? (processedBytes * 100L) / totalBytes : 0;
                    String eta = (averageSpeedKBs > 0)
                            ? formatTime((totalBytes - processedBytes) / (averageSpeedKBs * 1024.0))
                            : "--:--:--";
                    progressBar.setString(String.format("%d%% \u2014 %s remaining...", pct, eta));
                }
            }
        });
        messageTimer.setRepeats(false);
        messageTimer.start();
    }

    private void stopMessageTimer() {
        if (messageTimer != null && messageTimer.isRunning()) messageTimer.stop();
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
        stopMessageTimer();

        StringBuilder msg = new StringBuilder();
        if (wasCanceled)  msg.append("Shredding was canceled.\n\n");
        msg.append("Completed: ").append(successCount).append(" / ").append(totalCount).append(" item(s).");
        if (!errors.isEmpty()) {
            msg.append("\n\nIssues:\n");
            for (String err : errors) msg.append("  \u2022 ").append(err).append("\n");
        }

        boolean isClean = errors.isEmpty() && !wasCanceled;
        int     type    = isClean ? JOptionPane.INFORMATION_MESSAGE : JOptionPane.WARNING_MESSAGE;

        if (isClean) {
            // Non-modal so the reset timer can still fire
            JOptionPane pane   = new JOptionPane(msg.toString(), type);
            JDialog     dialog = pane.createDialog(this, "Result");
            dialog.setModal(false);
            dialog.setVisible(true);
        } else {
            JOptionPane.showMessageDialog(this, msg.toString(), "Result", type);
        }

        if (!wasCanceled) {
            resetTimer = new Timer(3000, e -> {
                progressBar.setString("Ready.");
                progressBar.setValue(0);
                progressBar.setForeground(Color.GRAY);
            });
            resetTimer.setRepeats(false);
            resetTimer.start();
        }
    }

    private void showError(String message) {
        SwingUtilities.invokeLater(() ->
                JOptionPane.showMessageDialog(this,
                        "<html><b>Error:</b><br>" + message.replace("\n", "<br>") + "</html>",
                        "Error", JOptionPane.ERROR_MESSAGE));
    }

    // -------------------------------------------------------------------------
    // Utilities
    // -------------------------------------------------------------------------

    /**
     * Generates a random filename using the class-level RANDOM instance.
     */
    private String generateRandomName() {
        final String chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
        int length = 8 + RANDOM.nextInt(9); // 8-16 characters
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
        try {
            UIManager.setLookAndFeel(UIManager.getSystemLookAndFeelClassName());

            if (isDarkModeEnabled()) {
                Color darkBg        = new Color(50, 50, 50);
                Color componentBg   = new Color(85, 85, 85);
                Color white         = Color.WHITE;
                Color black         = Color.BLACK;

                UIManager.put("Panel.background",              darkBg);
                UIManager.put("Label.foreground",              black);
                UIManager.put("Button.foreground",             black);
                UIManager.put("Button.background",             new Color(70, 70, 70));
                UIManager.put("Button.focus",                  new Color(0, 0, 0, 0));
                UIManager.put("Button.select",                 new Color(100, 100, 100));
                UIManager.put("ComboBox.foreground",           black);
                UIManager.put("ComboBox.background",           componentBg);
                UIManager.put("ComboBox.selectionForeground",  white);
                UIManager.put("Spinner.foreground",            white);
                UIManager.put("Spinner.background",            componentBg);
                UIManager.put("FormattedTextField.foreground", black);
                UIManager.put("OptionPane.background",         darkBg);
                UIManager.put("OptionPane.messageForeground",  white);
                UIManager.put("OptionPane.buttonAreaBackground", darkBg);
                UIManager.put("OptionPane.messageFont",
                        new Font("Segoe UI", Font.PLAIN, 13));
                UIManager.put("OptionPane.messageAlignment",   SwingConstants.CENTER);
            }
        } catch (Exception ex) {
            ex.printStackTrace();
        }

        Thread.setDefaultUncaughtExceptionHandler((t, ex) ->
                JOptionPane.showMessageDialog(null,
                        "Unhandled error: " + ex.getMessage(),
                        "Fatal Error", JOptionPane.ERROR_MESSAGE));

        SwingUtilities.invokeLater(() -> new DataShredderV3().setVisible(true));
    }
}