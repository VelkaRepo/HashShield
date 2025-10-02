# ✨ Hash Shield

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

A simple, fast, signature-based malware scanner written in Python. Scans directories recursively and matches file hashes against a custom signature database.

## 🎯 Features

- **Recursive Directory Scanning**: Scans a target folder and all its subfolders.
- **MD5 Hash-Based Detection**: Matches file hashes against a provided signature database.
- **Flexible Signature DB**: Easily add or update malware signatures in a simple `.txt` file.
- **Simple & Fast**: Built with standard Python libraries for maximum compatibility and speed.

## 🚀 Getting Started

### Prerequisites
- Python 3.6+

### Installation
1.  Clone the repository:
    ```bash
    # Replace with your actual repository URL
    git clone [https://github.com/VelkaRepo/HashShield.git](https://github.com/VelkaRepo/HashShield.git)
    ```
2.  Navigate to the project directory:
    ```bash
    cd Hash-Shield
    ```

## 💻 Usage

Run the scanner from the project's root directory:
```bash
python src/scanner.py

The script will then prompt you to enter the path of the directory you want to scan. To scan the current directory, simply enter . and press Enter.

Example Ouput:
Signature database loaded successfully.
Enter the directory path to scan (e.g., C:\Downloads or .): .

Starting scan in directory: '.'
========================================
[!!!] MALWARE DETECTED: File '.\file_tes_eicar.txt' matches 'EICAR-Test-File-System-Specific'
[!!!] MALWARE DETECTED: File '.\file_tes_aman.txt' matches 'Test-File-Aman-System-Specific'
========================================
Scan Summary:
  Total files scanned: 48
  Threats found: 2

```bash