# HashShield v1.1

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Python](https://img.shields.io/badge/Python-3.8+-blue.svg)](https://www.python.org/downloads/)
[![Latest Release](https://img.shields.io/github/v/release/VelkaRepo/HashShield)](https://github.com/VelkaRepo/HashShield/releases/latest)

**HashShield** is a **hybrid command-line malware scanner** written in Python.  
It combines fast local signature-based detection with cloud-powered hash analysis using the **VirusTotal API**, providing efficient and comprehensive file scanning capabilities.

---

## Key Features

- **Hybrid Scanning**  
  Performs local signature-based detection for known threats, followed by SHA-256 hash verification via the VirusTotal API for deeper analysis.

- **Asynchronous and Fast**  
  Built with `asyncio` and `aiohttp` to handle multiple concurrent scans efficiently, enhanced with a progress bar using `tqdm`.

- **Recursive Directory Scanning**  
  Capable of scanning individual files or entire directories, including all subfolders.

- **Smart Caching System**  
  Saves online scan results to `scan_cache.txt` to avoid redundant API calls, significantly improving subsequent scan performance.

- **Flexible Exclusion Rules**  
  Automatically skips common development directories (`.git`, `__pycache__`, `venv`) and internal files (`signatures.txt`, `scan_cache.txt`).

- **Professional CLI Interface**  
  Provides clean, color-coded terminal output using `colorama`, along with detailed help messages (`-h`) for ease of use.

- **Installable as a Python Package**  
  Configured with `pyproject.toml` and can be installed globally, making the `hashshield` command accessible from anywhere in your system.

---

## Requirements

- Python **3.8+**
- A [VirusTotal API key](https://www.virustotal.com/gui/join-us) (free for personal use)

---

## Installation & Setup

### For Users (Recommended)

This method installs the latest stable release (`v1.1`) directly from GitHub.

1.  **Install from GitHub**
    ```bash
    pip install git+https://github.com/VelkaRepo/HashShield.git@v1.1
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