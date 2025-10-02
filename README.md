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