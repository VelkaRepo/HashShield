# HashShield v1.2.0

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Python](https://img.shields.io/badge/Python-3.8+-blue.svg)](https://www.python.org/downloads/)
[![Latest Release](https://img.shields.io/github/v/release/VelkaRepo/HashShield)](https://github.com/VelkaRepo/HashShield/releases/latest)
![HashShield Banner](./img/HashShield-banner.png)

**HashShield** is a **hybrid command-line malware scanner** written in Python.  
It combines fast local signature-based detection with cloud-powered hash analysis using the **VirusTotal API**, providing efficient and comprehensive file scanning capabilities.

---

## Key Features


- **YARA-Powered Engine** 
  Utilizes a powerful YARA engine for local scanning, replacing the previous simple-string search. This allows for complex and professional-grade signature detection.

- **Hybrid Scanning Engine**
  Combines local YARA rule detection with cloud-based hash checking via the VirusTotal API for comprehensive analysis.

- **Custom Exclusions (`.shieldignore`)**
  Allows users to create a `.shieldignore` file to specify custom file and directory patterns (including wildcards) to exclude from scans.

- **Asynchronous & Fast**
  Built on `asyncio` for high-performance concurrent scanning of multiple files, complete with a `tqdm` progress bar.

- **Recursive Directory Scanning**
  Capable of scanning a single file or an entire directory and all its sub-folders.

- **Smart Caching System**
  Avoids redundant API calls by caching previous online scan results, dramatically speeding up subsequent scans.

- **Professional CLI**
  Features a clean, colored (`colorama`), and adaptive multi-line report layout, complete with flags (`--fresh`, `--verbose`) and a detailed help message (`-h`).

- **Installable as a Python Package**
  Packaged as a standard Python application, making the `hashshield` command available system-wide after a simple installation.

---

## Requirements

- Python **3.8+**
- A [VirusTotal API key](https://www.virustotal.com/gui/join-us) (free for personal use)

---

## Installation & Setup

### For Users (Recommended)

This method installs the latest stable release (`v1.2.0`) directly from GitHub.

1.  **Install from GitHub**
    ```bash
    pip install git+https://github.com/VelkaRepo/HashShield.git@v1.2.0
    ```
2.  **Configure API Key**
    Follow the configuration steps in the section below to set your VirusTotal API key.

### For Developers (Contributing)

This method is for those who want to modify or contribute to the source code.

1.  **Clone the Repository**
    ```bash
    git clone https://github.com/VelkaRepo/HashShield.git
    cd HashShield
    ```
2.  **(Optional) Create & Activate a Virtual Environment**
    ```bash
    python -m venv .venv
    .\.venv\Scripts\Activate.ps1
    ```
3.  **Install Dependencies & Project in Editable Mode**
    ```bash
    pip install -r requirements.txt
    pip install -e .
    ```

4. **Configure the API Key**
    You must provide your VirusTotal API key. Choose **one** of the following methods:

    - **Recommended:** Create a `.env` file inside the `src/` directory:
      ```env
      VIRUSTOTAL_API_KEY="YOUR_API_KEY_HERE"
      ```

    - Or set it as a **system environment variable**:
      ```bash
      setx VIRUSTOTAL_API_KEY "YOUR_API_KEY_HERE"
      ```

5. **Install HashShield as a Global Command**
    ```bash
    pip install -e .
    ```
    The `-e` (editable) flag allows you to modify the source code without reinstalling.

---

## Usage

Once installed, you can run `hashshield` from any directory.

### Basic Syntax
```bash
hashshield [PATH_TO_FILE_OR_DIRECTORY] [OPTIONS]
```

### Examples

- **View available options**
    ```bash
    hashshield -h
    ```

- **Scan a single file**
    ```bash
    hashshield "C:\Users\User\Downloads\suspicious.exe"
    ```

- **Scan the current directory**
    ```bash
    hashshield .
    ```

- **Scan another directory and force a fresh scan (ignore cache)**
    ```bash
    hashshield "D:\My Projects" --fresh
    ```

- **Scan with verbose output**
    ```bash
    hashshield "C:\Samples" --verbose
    ```