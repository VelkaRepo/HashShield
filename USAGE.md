# HashShield User Guide

Welcome to the detailed usage documentation for **HashShield**.
This guide covers advanced scanning modes, daemon management, reporting, and configuration.

## 📖 Table of Contents
- [Architecture Overview](#architecture-overview)
- [Starting the Engine (Daemon)](#starting-the-engine-daemon)
- [Scanning Modes](#scanning-modes)
  - [Basic Scanning](#basic-scanning)
  - [Archive Scanning](#archive-scanning)
  - [Cloud Upload](#cloud-upload)
- [Reporting & Exporting](#reporting--exporting)
- [Performance Tuning](#performance-tuning)
- [Configuration & Exclusions](#configuration--exclusions)
- [Testing & Validation](#testing--validation)

---

## Architecture Overview

HashShield uses a **Client-Server** model to achieve high performance.

1. **The Daemon (Server):** Loads the virus database (2.5M+ signatures) into RAM. It listens on a local port (Default: 65432).
2. **The Client (Scanner):** Sends file paths to the daemon for instant checking. If the daemon is offline, the client attempts to auto-start it.

---

## Starting the Engine (Daemon)

For the best performance, keep the daemon running in a background terminal.

```bash
# Start the daemon
hashshield --daemon
```

* **Startup Time:** ~10-20 seconds (Downloads/Loads database).
* **Scan Speed:** Instant (O(1) Lookup) once loaded.

> **Note:** If you forget to start the daemon, the scanner will attempt to **auto-start** it when you run a scan command.

---

## Scanning Modes

### Basic Scanning
Scan a specific file or recursively scan a directory.

```bash
# Scan current directory
hashshield .

# Scan a specific path
hashshield /home/user/Downloads
```

### Archive Scanning
HashShield can recursively extract and scan nested archives (`.zip`, `.tar`, `.tar.gz`).

* **Mechanism:** Extracts files to a secure `temp_scans/` directory, scans them, and auto-cleans up.

```bash
hashshield . --scan-archives
```

### Cloud Upload (Deep Scan)
By default, HashShield only checks hashes against VirusTotal. If a file is unknown (Zero-Day), you can force an upload for sandbox analysis.

```bash
# Upload unknown files to VirusTotal
hashshield . --upload
```

---

## Reporting & Exporting

Generate professional audit logs for your scans.

### Supported Formats
1. **TXT:** Human-readable audit log with ASCII branding and summary tables.
2. **CSV:** Spreadsheet-compatible format (Timestamp, File, Status, Engine, Threat Name).
3. **JSON:** Structured data for SIEM integration.
4. **HTML:** Interactive dashboard with charts and tables.

### Examples

```bash
# Generate a Text Report (Default)
hashshield . -o audit_log.txt

# Generate a CSV Report for Excel
hashshield . -o scan_results.csv --format csv

# Generate a JSON Report for Development
hashshield . -o data.json --format json

# Generate HTML Dashboard Report
hashshield . -o scan_report.html --format html
```

---

## Performance Tuning

You can control the concurrency of the scanner to balance speed vs. API limits.

* **Default:** `4 threads` (Safe for VirusTotal Free Tier).
* **High Speed:** `20+ threads` (Recommended if using Local Engine only or Premium API).

```bash
# Maximize speed for local scanning
hashshield . --threads 20
```

---

## Configuration & Exclusions

### Environment Variables (`.env`)

```env
VIRUSTOTAL_API_KEY="your_key"
SHIELD_DAEMON_PORT=65432
```

### Ignoring Files (`.shieldignore`)
Place a `.shieldignore` file in the target directory to exclude specific patterns.

```text
# Example .shieldignore
*.log
secret_backup.zip
test_data/
```

---

## Testing & Validation

HashShield includes a test generator to validate detection capabilities against "Safe" threats (EICAR) and simulated malware.

1. **Generate the Malware Zoo:**
   Run the helper script included in the repository.
   ```bash
   ./setup_test_zone.sh
   ```
   *Creates `live_malware_test/` with EICAR files, MSFVenom payloads, and copied system binaries.*

2. **Run the Test Scan:**
   ```bash
   hashshield live_malware_test --threads 4
   ```

3. **Expected Results:**
   * **EICAR Files:** Detected by `Shield Engine (Local DB)`.
   * **MSFVenom Payloads:** Detected by `YARA` (Custom Rules).
   * **Real Threats:** Detected by `Shield Engine` or `VirusTotal`.
#     * **Safe Files:** Marked as `CLEAN`.