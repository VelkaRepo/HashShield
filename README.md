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
1. Clone the repository:
   ```bash
   # Replace with your actual repository URL
   git clone [https://github.com/YOUR_USERNAME/Hash-Shield.git](https://github.com/YOUR_USERNAME/Hash-Shield.git)
Navigate to the project directory:

Bash

cd Hash-Shield
💻 Usage
Run the scanner from the project's root directory:

Bash

python src/scanner.py
The script will then prompt you to enter the path of the directory you want to scan. To scan the current directory, simply enter . and press Enter.

Example Output:

Plaintext

Signature database loaded successfully.
Enter the directory path to scan (e.g., C:\Downloads or .): .

Starting scan in directory: '.'

[!!!] MALWARE DETECTED: File '.\file_tes_eicar.txt' matches 'EICAR-Test-File-System-Specific'
[!!!] MALWARE DETECTED: File '.\file_tes_aman.txt' matches 'Test-File-Aman-System-Specific'

Scan Summary:
  Total files scanned: 48
  Threats found: 2
📖 Signature Format
The signatures.txt file uses a simple hash,name format, with one entry per line:

44d88612fea8a8f36de82e1278abb02f,EICAR-Test-File-System-Specific
🗺️ Roadmap
Here are some planned features to make Hash Shield even better:

[ ] Directory Exclusions (e.g., ignore .git, __pycache__)

[ ] Professional CLI with argparse for flags and arguments

[ ] Scan Progress Indicator (Progress Bar)

[ ] Support for SHA-256 Hashes

[ ] Multi-threaded Scanning for Performance

📜 License
This project is licensed under the MIT License. See the LICENSE file for details.