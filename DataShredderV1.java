/**
 * DataShredder v1.0.0
 *
 * Simple file shredder: random-data overwrite with a configurable number of passes.
 */

import javax.swing.*;
import java.awt.*;
import java.io.File;
import java.io.IOException;
import java.io.RandomAccessFile;
import java.nio.file.Files;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.List;

public class DataShredderV1 extends JFrame {

    private static final long serialVersionUID = 1000L;
    private static final SecureRandom RANDOM = new SecureRandom();
    private static final int BUFFER_SIZE = 65536; // 64 KB
    private static final int MIN_PASSES = 1;
    private static final int MAX_PASSES = 100;
    private static final int DEFAULT_PASSES = 3;

    // UI
    private JLabel       filePathLabel;
    private JButton      browseButton;
    private JButton      shredButton;
    private JProgressBar progressBar;
    private JSpinner     passesSpinner;

    // State
    private final List<File> selectedFiles = new ArrayList<>();
    private volatile boolean shreddingActive = false;

    // -------------------------------------------------------------------------
    // Construction
    // -------------------------------------------------------------------------

    public DataShredderV1() {
        initializeUI();
        setupWindowListener();
        setupEventHandlers();
    }

    // -------------------------------------------------------------------------
    // UI setup
    // -------------------------------------------------------------------------

    private void initializeUI() {
        setTitle("File Shredder v1.0.0");
        setSize(585, 240);
        setDefaultCloseOperation(JFrame.DO_NOTHING_ON_CLOSE);
        setLayout(new FlowLayout(FlowLayout.LEFT, 10, 10));

        JPanel configPanel = new JPanel();
        configPanel.add(new JLabel("Number of passes:"));
        passesSpinner = new JSpinner(
                new SpinnerNumberModel(DEFAULT_PASSES, MIN_PASSES, MAX_PASSES, 1));
        configPanel.add(passesSpinner);

        filePathLabel = new JLabel("No files selected");
        browseButton  = new JButton("Browse");
        shredButton   = new JButton("Shred");

        progressBar = new JProgressBar(0, 100);
        progressBar.setStringPainted(true);
        progressBar.setPreferredSize(new Dimension(550, 30));
        progressBar.setString("Ready.");

        add(configPanel);
        add(filePathLabel);
        add(browseButton);
        add(shredButton);
        add(progressBar);
    }

    private void setupWindowListener() {
        addWindowListener(new java.awt.event.WindowAdapter() {
            @Override
            public void windowClosing(java.awt.event.WindowEvent e) {
                if (shreddingActive) {
                    int choice = JOptionPane.showConfirmDialog(
                            DataShredderV1.this,
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
        browseButton.addActionListener(e -> handleFileSelection());
        shredButton .addActionListener(e -> startShreddingProcess());
    }

    // -------------------------------------------------------------------------
    // File selection
    // -------------------------------------------------------------------------

    private void handleFileSelection() {
        JFileChooser chooser = new JFileChooser();
        chooser.setMultiSelectionEnabled(true);
        chooser.setFileSelectionMode(JFileChooser.FILES_ONLY);

        if (chooser.showOpenDialog(this) == JFileChooser.APPROVE_OPTION) {
            selectedFiles.clear();
            for (File f : chooser.getSelectedFiles()) {
                if (f.exists() && f.isFile()) selectedFiles.add(f);
            }
            updateFilePathLabel();
        }
    }

    // -------------------------------------------------------------------------
    // Shredding orchestration
    // -------------------------------------------------------------------------

    private void startShreddingProcess() {
        if (selectedFiles.isEmpty()) {
            JOptionPane.showMessageDialog(this, "Please select files first!");
            return;
        }

        int confirm = JOptionPane.showConfirmDialog(this,
                "This will permanently destroy " + selectedFiles.size() + " file(s)!\nProceed?",
                "Confirmation", JOptionPane.YES_NO_OPTION, JOptionPane.WARNING_MESSAGE);
        if (confirm != JOptionPane.YES_OPTION) return;

        // Snapshot list so the worker owns it independently from EDT changes
        List<File> filesToProcess = new ArrayList<>(selectedFiles);
        int passes = (Integer) passesSpinner.getValue();

        shreddingActive = true;
        shredButton .setEnabled(false);
        browseButton.setEnabled(false);
        progressBar.setValue(0);
        progressBar.setString("Starting...");

        new Thread(() -> runShredding(filesToProcess, passes), "shredder-thread").start();
    }

    private void runShredding(List<File> files, int passes) {
        List<String> errors    = new ArrayList<>();
        int successCount       = 0;
        int totalFiles         = files.size();

        // Pre-calculate total byte work for smooth progress reporting
        long totalBytes = 0;
        for (File f : files) totalBytes += f.length();
        totalBytes *= passes;

        // Mutable counter wrapped to satisfy lambda capture rules
        final long[] processedBytes = {0};

        try {
            for (File file : files) {
                if (!shreddingActive) break;

                try {
                    if (!file.canWrite()) {
                        errors.add("Skipped (read-only): " + file.getName());
                        continue; // don't count toward successCount
                    }
                    if (Files.isSymbolicLink(file.toPath())) {
                        errors.add("Skipped (symbolic link): " + file.getName());
                        continue;
                    }

                    shredFile(file, passes, totalBytes, processedBytes);
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
            // Capture final state NOW before anything else touches these fields
            final int          finalSuccess = successCount;
            final int          finalTotal   = totalFiles;
            final List<String> finalErrors  = new ArrayList<>(errors);

            shreddingActive = false;
            SwingUtilities.invokeLater(() -> {
                selectedFiles.clear();
                filePathLabel.setText("No files selected");
                progressBar.setValue(0);
                progressBar.setString("Ready.");
                shredButton .setEnabled(true);
                browseButton.setEnabled(true);
                showFinalReport(finalErrors, finalSuccess, finalTotal);
            });
        }
    }

    // -------------------------------------------------------------------------
    // Core shred logic
    // -------------------------------------------------------------------------

    /**
     * Overwrites the file with random data for the given number of passes,
     * updating the shared progress counter after each write.
     */
    private void shredFile(File file, int passes, long totalBytes, long[] processedBytes)
            throws IOException {

        final long   fileSize = file.length();
        final byte[] buffer   = new byte[BUFFER_SIZE];

        try (RandomAccessFile raf = new RandomAccessFile(file, "rw")) {
            for (int pass = 0; pass < passes && shreddingActive; pass++) {
                raf.seek(0);
                long written = 0;

                while (written < fileSize && shreddingActive) {
                    RANDOM.nextBytes(buffer);
                    int writeSize = (int) Math.min(buffer.length, fileSize - written);
                    raf.write(buffer, 0, writeSize);
                    written           += writeSize;
                    processedBytes[0] += writeSize;
                    updateProgressBar(totalBytes, processedBytes[0]);
                }

                raf.getFD().sync(); // flush OS write cache after each complete pass
            }
        }
    }

    // -------------------------------------------------------------------------
    // Deletion
    // -------------------------------------------------------------------------

    private boolean deleteFilePermanently(File file) {
        if (file.delete()) return true;

        // Rename then retry deletion (helps release OS name-cache locks)
        File renamed = new File(file.getParent(),
                generateRandomString(12) + ".shred");
        if (file.renameTo(renamed) && renamed.delete()) return true;

        return false;
    }

    // -------------------------------------------------------------------------
    // Progress & UI helpers
    // -------------------------------------------------------------------------

    private void updateProgressBar(long totalBytes, long processedBytes) {
        if (totalBytes <= 0) return;
        int pct = (int) Math.min(100, (processedBytes * 100L) / totalBytes);
        SwingUtilities.invokeLater(() -> {
            progressBar.setValue(pct);
            progressBar.setString(pct + "%");
        });
    }

    private void updateFilePathLabel() {
        SwingUtilities.invokeLater(() -> {
            if (selectedFiles.isEmpty()) {
                filePathLabel.setText("No files selected");
            } else if (selectedFiles.size() == 1) {
                filePathLabel.setText("<html>Selected: "
                        + selectedFiles.get(0).getAbsolutePath() + "</html>");
            } else {
                StringBuilder sb = new StringBuilder(
                        "<html>Selected " + selectedFiles.size() + " files:<br>");
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

    private void showFinalReport(List<String> errors, int successCount, int totalCount) {
        StringBuilder msg = new StringBuilder();
        msg.append("Shredded ").append(successCount).append(" / ")
           .append(totalCount).append(" file(s).");

        if (!errors.isEmpty()) {
            msg.append("\n\nIssues:\n");
            for (String err : errors) msg.append("  \u2022 ").append(err).append("\n");
        }

        JOptionPane.showMessageDialog(this, msg.toString(),
                "Results", JOptionPane.INFORMATION_MESSAGE);
    }

    // -------------------------------------------------------------------------
    // Utilities
    // -------------------------------------------------------------------------

    private String generateRandomString(int length) {
        final String chars =
                "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
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

            DataShredderV1 shredder = new DataShredderV1();
            shredder.setLocationRelativeTo(null);
            shredder.setVisible(true);
        });
    }
}