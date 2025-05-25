import javax.swing.*;
import javax.swing.border.TitledBorder;
import java.awt.*;
import java.io.*;
import java.nio.file.*;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.util.*;
import java.util.List;
import java.util.Timer;
import java.util.TimerTask;
import java.util.stream.Collectors;

public class UserBehaviorMonitor {
    private static final String FAILED_LOGON_TODAY = "logs/failed_logons_today.csv";
    private static final String FAILED_LOGON_ARCHIVE = "logs/failed_logons_archive.csv";
    private static final String SUSPICIOUS_PROC_TODAY = "logs/suspicious_processes_today.csv";
    private static final String SUSPICIOUS_PROC_ARCHIVE = "logs/suspicious_processes_archive.csv";
    private static final String RDP_LOGON_TODAY = "logs/rdp_logons_today.csv";
    private static final String RDP_LOGON_ARCHIVE = "logs/rdp_logons_archive.csv";

    private static final String SUSPICIOUS_LIST_FILE = "logs/suspicious_programs.txt";
    private static final String POWERSHELL_SCRIPT = "scripts/export-suspicious-processes.ps1";
    private static final String THRESHOLD_FILE = "logs/threshold.txt";

    private int loginThreshold = 5;

    private JTextArea logArea, notificationArea;
    private JCheckBox showFailed, showSuspicious, showRDP;
    private List<String> suspiciousPrograms;
    private Set<String> seenProcesses = new HashSet<>();
    private Timer realtimeTimer;

    public static void main(String[] args) {
        SwingUtilities.invokeLater(() -> new UserBehaviorMonitor().createAndShowGUI());
    }

    private void createAndShowGUI() {
        loadThresholdFromFile();

        JFrame frame = new JFrame("User Behavior Monitor");
        frame.setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);
        frame.setSize(800, 700);

        logArea = new JTextArea();
        logArea.setEditable(false);
        notificationArea = new JTextArea(5, 50);
        notificationArea.setEditable(false);
        notificationArea.setBorder(new TitledBorder("Notifications"));

        JPanel topPanel = new JPanel(new FlowLayout());
        JButton showTodayButton = new JButton("Show Today's Logs");
        JButton showArchiveButton = new JButton("Show Archived Logs");
        JButton settingsButton = new JButton("Settings");
        showFailed = new JCheckBox("Failed Logons", true);
        showSuspicious = new JCheckBox("Suspicious Processes", true);
        showRDP = new JCheckBox("RDP Logons", true);

        showTodayButton.addActionListener(e -> showTodayLogs());
        showArchiveButton.addActionListener(e -> showArchivedLogs());
        settingsButton.addActionListener(e -> openSettingsDialog());

        topPanel.add(showFailed);
        topPanel.add(showSuspicious);
        topPanel.add(showRDP);
        topPanel.add(showTodayButton);
        topPanel.add(showArchiveButton);
        topPanel.add(settingsButton);

        frame.setLayout(new BorderLayout());
        frame.add(topPanel, BorderLayout.NORTH);
        frame.add(new JScrollPane(logArea), BorderLayout.CENTER);
        frame.add(new JScrollPane(notificationArea), BorderLayout.SOUTH);

        frame.setVisible(true);
        loadSuspiciousPrograms();
        startRealtimeMonitoring();
    }

    private void showTodayLogs() {
        logArea.setText("");
        if (showFailed.isSelected()) displayLog(FAILED_LOGON_TODAY, "FAILED LOGON");
        if (showSuspicious.isSelected()) displayLog(SUSPICIOUS_PROC_TODAY, "SUSPICIOUS PROCESS");
        if (showRDP.isSelected()) displayLog(RDP_LOGON_TODAY, "RDP LOGIN");
    }

    private void showArchivedLogs() {
        logArea.setText("");
        if (showFailed.isSelected()) displayLog(FAILED_LOGON_ARCHIVE, "ARCHIVED FAILED LOGON");
        if (showSuspicious.isSelected()) displayLog(SUSPICIOUS_PROC_ARCHIVE, "ARCHIVED SUSPICIOUS PROCESS");
        if (showRDP.isSelected()) displayLog(RDP_LOGON_ARCHIVE, "ARCHIVED RDP LOGIN");
    }

    private void displayLog(String path, String label) {
        File file = new File(path);
        if (!file.exists() || file.length() == 0) {
            logArea.append("[" + label + "] No entries found.\n");
            return;
        }

        try (BufferedReader reader = new BufferedReader(new FileReader(path))) {
            String line;
            boolean skip = true;
            while ((line = reader.readLine()) != null) {
                if (skip) { skip = false; continue; }
                logArea.append("[" + label + "] " + line + "\n");
            }
        } catch (IOException e) {
            logArea.append("[ERROR] Reading log: " + e.getMessage() + "\n");
        }
    }

    private void startRealtimeMonitoring() {
        realtimeTimer = new Timer(true);
        realtimeTimer.schedule(new TimerTask() {
            public void run() {
                monitorSuspiciousProcessesRealtime();
                monitorFailedLogonsRealtime();
            }
        }, 0, 10000); // 10 seconds
    }

    private DateTimeFormatter formatter = DateTimeFormatter.ISO_LOCAL_DATE_TIME;
    private LocalDateTime lastFailedLogonCheckTime = LocalDateTime.MIN;

    private void monitorFailedLogonsRealtime() {
        Map<String, Integer> userAttempts = new HashMap<>();
        try (BufferedReader reader = new BufferedReader(new FileReader(FAILED_LOGON_TODAY))) {
            String line;
            boolean skipHeader = true;
            while ((line = reader.readLine()) != null) {
                if (skipHeader) { skipHeader = false; continue; }
                String[] parts = line.split(",");
                if (parts.length > 1) {
                    LocalDateTime time = LocalDateTime.parse(parts[0].trim(), formatter);
                    if (time.isAfter(lastFailedLogonCheckTime)) {
                        String user = parts[1].trim();
                        userAttempts.put(user, userAttempts.getOrDefault(user, 0) + 1);
                    }
                }
            }

            for (Map.Entry<String, Integer> entry : userAttempts.entrySet()) {
                if (entry.getValue() >= loginThreshold) {
                    disableUser(entry.getKey());
                    notifyUser("[ACTION] Disabled user: " + entry.getKey() + " after " + loginThreshold + " failed logins.");
                }
            }

            lastFailedLogonCheckTime = LocalDateTime.now();
        } catch (IOException e) {
            notifyUser("[ERROR] Real-time failed logon: " + e.getMessage());
        }
    }

    private LocalDateTime lastSuspiciousPrecessCheckTime = LocalDateTime.MIN;

    private void monitorSuspiciousProcessesRealtime() {
        try (BufferedReader reader = new BufferedReader(new FileReader(SUSPICIOUS_PROC_TODAY))) {
            String line;
            boolean skip = true;
            while ((line = reader.readLine()) != null) {
                if (skip) { skip = false; continue; }
                    String[] parts = line.split(",");
                    if (parts.length > 2) {
                        LocalDateTime time = LocalDateTime.parse(parts[0].trim(), formatter);
                        if (time.isAfter(lastSuspiciousPrecessCheckTime)) {
                            String proc = parts[1].trim();
                            notifyUser("[ALERT] Suspicious process detected: " + proc);
                        }
                    }
            }
            lastSuspiciousPrecessCheckTime = LocalDateTime.now();
        } catch (IOException e) {
            notifyUser("[ERROR] Suspicious process check: " + e.getMessage());
        }
    }

    private void disableUser(String username) {
        try {
            String command = "powershell.exe -ExecutionPolicy Bypass -File scripts/disable-user.ps1 -UserName " + username;
            Process p = Runtime.getRuntime().exec(command);
            p.waitFor();
        } catch (Exception e) {
            notifyUser("[ERROR] Failed to disable user: " + e.getMessage());
        }
    }

    private void notifyUser(String message) {
        SwingUtilities.invokeLater(() -> {
            notificationArea.append(message + "\n");
            Toolkit.getDefaultToolkit().beep();
        });
    }

    private void loadSuspiciousPrograms() {
        try {
            suspiciousPrograms = Files.readAllLines(Paths.get(SUSPICIOUS_LIST_FILE)).stream()
                    .map(String::trim)
                    .filter(line -> !line.isEmpty())
                    .collect(Collectors.toList());
        } catch (IOException e) {
            notifyUser("[ERROR] Loading suspicious programs: " + e.getMessage());
            suspiciousPrograms = new ArrayList<>();
        }
    }

    private void openSettingsDialog() {
        JDialog dialog = new JDialog((Frame) null, "Settings", true);
        dialog.setSize(400, 350);
        dialog.setLayout(new BorderLayout());

        DefaultListModel<String> model = new DefaultListModel<>();
        suspiciousPrograms.forEach(model::addElement);
        JList<String> list = new JList<>(model);

        JPanel inputPanel = new JPanel();
        JTextField input = new JTextField(15);
        JButton addBtn = new JButton("Add");
        JButton removeBtn = new JButton("Remove");
        JButton applyBtn = new JButton("Apply");
        inputPanel.add(input);
        inputPanel.add(addBtn);
        inputPanel.add(removeBtn);
        inputPanel.add(applyBtn);

        JPanel thresholdPanel = new JPanel();
        JLabel thresholdLabel = new JLabel("Failed login threshold:");
        JSpinner thresholdSpinner = new JSpinner(new SpinnerNumberModel(loginThreshold, 1, 100, 1));
        thresholdPanel.add(thresholdLabel);
        thresholdPanel.add(thresholdSpinner);

        addBtn.addActionListener(e -> {
            String text = input.getText().trim();
            if (!text.isEmpty() && !model.contains(text)) model.addElement(text);
        });

        removeBtn.addActionListener(e -> {
            List<String> selected = list.getSelectedValuesList();
            selected.forEach(model::removeElement);
        });

        applyBtn.addActionListener(e -> {
            try {
                List<String> updatedList = Collections.list(model.elements());
                Files.write(Paths.get(SUSPICIOUS_LIST_FILE), updatedList);
                updatePowerShellScript(updatedList);
                suspiciousPrograms = updatedList;

                loginThreshold = (int) thresholdSpinner.getValue();
                Files.write(Paths.get(THRESHOLD_FILE), Collections.singletonList(String.valueOf(loginThreshold)));

                notifyUser("[SETTINGS] Threshold updated to " + loginThreshold);
                notifyUser("[SETTINGS] Suspicious list updated.");
                dialog.dispose();
            } catch (IOException ex) {
                notifyUser("[ERROR] Updating list: " + ex.getMessage());
            }
        });

        dialog.add(thresholdPanel, BorderLayout.NORTH);
        dialog.add(new JScrollPane(list), BorderLayout.CENTER);
        dialog.add(inputPanel, BorderLayout.SOUTH);
        dialog.setVisible(true);
    }

    private void loadThresholdFromFile() {
        try {
            if (Files.exists(Paths.get(THRESHOLD_FILE))) {
                String value = Files.readAllLines(Paths.get(THRESHOLD_FILE)).get(0).trim();
                loginThreshold = Integer.parseInt(value);
            }
        } catch (Exception e) {
            notifyUser("[WARNING] Using default threshold. Could not load saved value.");
        }
    }

    private void updatePowerShellScript(List<String> list) throws IOException {
        String header = "$blacklist = @(";
        String joined = list.stream().map(s -> "\"" + s + "\"").collect(Collectors.joining(", "));
        String script = header + joined + ")\n" +
                "$basePath = \"logs\"\n" +
                "$todayFile = \"$basePath\\suspicious_processes_today.csv\"\n" +
                "$archiveFile = \"$basePath\\suspicious_processes_archive.csv\"\n" +
                "$lastTimeFile = \"$basePath\\suspicious_last_time.txt\"\n" +
                "Set-Location -Path $PSScriptRoot\n" +
                "\n" +
                "if (-not (Test-Path $basePath)) {\n" +
                "    New-Item -Path $basePath -ItemType Directory | Out-Null\n" +
                "}\n" +
                "\n" +
                "if (Test-Path $lastTimeFile) {\n" +
                "    $lastRun = Get-Content $lastTimeFile | Get-Date\n" +
                "} else {\n" +
                "    $lastRun = (Get-Date).AddDays(-1)\n" +
                "}\n" +
                "\n" +
                "$events = Get-WinEvent -FilterHashtable @{LogName='Security'; Id=4688; StartTime=$lastRun}\n" +
                "$matches = foreach ($event in $events) {\n" +
                "    $cmd = $event.Properties[5].Value\n" +
                "    foreach ($bad in $blacklist) {\n" +
                "        if ($cmd -like \"*$bad*\") {\n" +
                "            [PSCustomObject]@{\n" +
                "                TimeCreated = $event.TimeCreated\n" +
                "                User        = $event.Properties[1].Value\n" +
                "                CommandLine = $cmd\n" +
                "            }\n" +
                "        }\n" +
                "    }\n" +
                "}\n" +
                "\n" +
                "if ($matches) {\n" +
                "    $matches | Export-Csv -Path $todayFile -NoTypeInformation\n" +
                "    $matches | Export-Csv -Path $archiveFile -NoTypeInformation -Append\n" +
                "}\n" +
                "\n" +
                "(Get-Date).ToString(\"o\") | Out-File $lastTimeFile -Force\n";
        Files.write(Paths.get(POWERSHELL_SCRIPT), script.getBytes());
    }
}