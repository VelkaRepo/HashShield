# HashShield

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Python](https://img.shields.io/badge/Python-3.8+-blue.svg)](https://www.python.org/downloads/)
[![Latest Release](https://img.shields.io/github/v/release/VelkaRepo/HashShield)](https://github.com/VelkaRepo/HashShield/releases/latest)
![HashShield Banner](./img/HashShield-banner.png)

**HashShield** is a **hybrid command-line malware scanner** written in Python.  
It combines fast local signature-based detection with cloud-powered hash analysis using the **VirusTotal API**, providing efficient and comprehensive file scanning capabilities.

---

## Key Features


- **Interactive Threat Response** 
  Prompts the user for action (Quarantine, Delete, or Ignore) upon detecting a threat, giving you full control over how to handle malicious files.

- **Dynamic YARA Rules**
  Supports scanning with remote YARA rules by providing a URL with the `--yara-url` flag, ensuring you can always use the latest threat intelligence.

- **YARA-Powered Engine**
  Utilizes a powerful YARA engine for local scanning, allowing for complex and professional-grade signature detection.

- **Hybrid Scanning Engine**
  Combines local YARA rule detection with cloud-based hash checking via the VirusTotal API.

- **Asynchronous & Fast**
  Built on `asyncio` for high-performance concurrent scanning.

- **Custom Exclusions (`.shieldignore`)**
  Allows users to create a `.shieldignore` file to specify custom exclusion patterns.

- **Professional CLI**
  A fully installable command (`hashshield`) with a polished, adaptive, and colored report layout.

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

- **Perform a fresh scan using a remote YARA rule set**
    ```bash
    hashshield "D:\Downloads" --fresh --yara-url https://raw.githubusercontent.com/Yara-Rules/rules/master/malware/MALW_Eicar.yar
    ```

- **Scan with verbose output**
    ```bash
    hashshield "C:\Samples" --verbose
    ```

---

## Testing

To test the scanner's detection capabilities, you first need to generate a set of standard and custom test files. A helper script is provided for this purpose.

In the project's root directory, run:
```bash
python create_test_files.py
```