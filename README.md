# HashShield

[![CI Status](https://img.shields.io/github/actions/workflow/status/VelkaRepo/HashShield/test.yml?style=flat-square&label=Build&logo=github&labelColor=black&color=orange)](https://github.com/VelkaRepo/HashShield/actions)
[![License: MIT](https://img.shields.io/badge/License-MIT-orange?style=flat-square&logo=github&labelColor=black)](https://opensource.org/licenses/MIT)
[![Python](https://img.shields.io/badge/Python-3.8+-orange?style=flat-square&logo=python&labelColor=black)](https://www.python.org/downloads/)
[![Linux](https://img.shields.io/badge/Linux-FCC624?style=flat-square&logo=linux&logoColor=black)](https://www.linux.org/)
[![Windows](https://img.shields.io/badge/Windows-0078D6?style=flat-square&logo=windows&logoColor=white)](https://www.microsoft.com/)
[![Latest Release](https://img.shields.io/github/v/release/VelkaRepo/HashShield?style=flat-square&color=orange&labelColor=black)](https://github.com/VelkaRepo/HashShield/releases/latest)

![HashShield Banner](./img/HashShield-banner.png)

**HashShield** is a professional-grade **hybrid antivirus engine** written in Python. It utilizes a **Client-Server Architecture** to combine instant local detection (Hash + Heuristics) with cloud-powered analysis (VirusTotal), providing enterprise-level scanning capabilities.

---

## 📖 Table of Contents

- [Key Features](#-key-features)
- [Architecture](#%EF%B8%8F-architecture)
- [Installation](#-installation)
- [Quick Start](#-quick-start)
- [Documentation](#-documentation)

---

## 🚀 Key Features

- **Hybrid Engine:** Combines Local Signatures (2.5M+), Heuristics (NDB/YARA), and Cloud Intelligence (VirusTotal).
- **Daemon Architecture:** Background service for **O(1) Instant Scanning**.
- **Archive Scanning:** Recursively scans inside `.zip`, `.tar`, and `.tar.gz` files.
- **Professional Reporting:** Exports audit logs to **HTML, TXT, CSV, and JSON**.
- **Resilience:** Auto-healing database updates and offline fallback modes.

---

## 🏗️ Architecture

HashShield separates the **Scanner (Client)** from the **Engine (Server)**:

```mermaid
graph LR
    subgraph Client
        A[CLI Scanner]
    end
    
    subgraph Server_Daemon ["🛡️ Shield Engine Daemon (Local)"]
        direction TB
        B(Incoming Request) --> C{Hash Database};
        C -- Match (Fast) --> D[🚨 INFECTED];
        C -- No Match --> E{NDB Heuristics};
        E -- Match (Smart) --> D;
    end

    A -->|File Path| B
    E -- No Match --> F{YARA Rules};
    F -- Match --> D;
    F -- No Match --> G[Cloud Check];
    G -->|API Query| H[VirusTotal];
    H --> I[Final Verdict];
    D --> I;

---

## 📦 Installation

1.  **Clone & Setup Environment**
     ```bash
     git clone [https://github.com/VelkaRepo/HashShield.git](https://github.com/VelkaRepo/HashShield.git)
     cd HashShield
     
     # Linux / Mac
     python3 -m venv .venv
     source .venv/bin/activate
     
     # Windows (PowerShell)
     python -m venv .venv
     .\.venv\Scripts\Activate.ps1
     
     # Install Dependencies
     pip install -r requirements.txt
     ```

2. **Install Global Command**
   ```bash
   pip install -e .
   ```

3. **Database Setup**
   The engine will attempt to download the database automatically upon first launch.
   
   *Manual Option:* Download `main.cvd` from [Releases](https://github.com/VelkaRepo/HashShield/releases) and place in `src/`.

4. **Configuration**
   Create `src/.env` with your API key:
   ```env
   VIRUSTOTAL_API_KEY="YOUR_KEY"
   SHIELD_DAEMON_PORT=65432
   ```

---

## ⚡ Quick Start

**1. Start the Engine (Daemon)**
```bash
hashshield --daemon
```

**2. Scan a Directory**
```bash
hashshield .
```

---

## 📚 Documentation

For advanced usage, including **Archive Scanning**, **Reporting**, and **Automation**, please consult the **User Guide**:

👉 **[Read the Full Usage Guide (USAGE.md)](./USAGE.md)**