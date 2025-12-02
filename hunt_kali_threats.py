import os
import hashlib
import shutil
import sys

# Import your upgraded engine
sys.path.append(os.path.join(os.path.dirname(__file__), 'src'))
from shield_engine import download_clamav_hashes

# EXPANDED HUNTING ZONES (The "Red Light" Districts of Kali)
HUNT_ZONES = [
    "/usr/share/windows-resources",
    "/usr/share/webshells",
    "/usr/share/exploitdb/exploits",
    "/usr/share/metasploit-framework/data/templates",
    "/usr/share/nishang",          # PowerShell Malware
    "/usr/share/powersploit",      # PowerShell Attack Tools
    "/usr/share/set",              # Social Engineer Toolkit
    "/usr/share/responder",        # Attack Tool
    "/usr/share/sqlmap",           # DB Attack Tool
    "/usr/share/mimikatz"          # Credential Dumpers
]

# Targeted Extensions (Don't scan README.md or .png)
TARGET_EXTS = {'.exe', '.dll', '.bin', '.php', '.pl', '.py', '.rb', '.sh', '.ps1', '.c', '.jsp', '.asp', '.aspx'}

TARGET_DIR = "live_malware_test"

def hunt():
    print("[-] Loading Shield Engine (God Mode)...")
    # Load BOTH engines
    db_hashes, db_heuristics = download_clamav_hashes()
    
    if not db_hashes:
        print("[!] Critical: Database load failed.")
        return

    print(f"[-] Engine Ready. Hunting in {len(HUNT_ZONES)} zones...")

    if not os.path.exists(TARGET_DIR):
        os.makedirs(TARGET_DIR)

    stats = {"HASH": 0, "NDB": 0}

    for zone in HUNT_ZONES:
        if not os.path.exists(zone):
            continue
            
        print(f"[*] Scanning: {zone} ...")
        
        for root, _, files in os.walk(zone):
            for file in files:
                # OPTIMIZATION: Only scan "dangerous" file types
                _, ext = os.path.splitext(file)
                if ext.lower() not in TARGET_EXTS:
                    continue

                filepath = os.path.join(root, file)
                
                try:
                    # Skip massive files (ISO, etc)
                    if os.path.getsize(filepath) > 10 * 1024 * 1024: 
                        continue
                        
                    # 1. HASH CHECK (Fast)
                    hasher = hashlib.md5()
                    with open(filepath, 'rb') as f:
                        content = f.read() # Read all for YARA later
                        hasher.update(content)
                    file_hash = hasher.hexdigest()
                    
                    found_threat = None
                    detection_type = ""

                    if file_hash in db_hashes:
                        found_threat = db_hashes[file_hash]
                        detection_type = "HASH"
                        stats["HASH"] += 1
                    
                    # 2. HEURISTIC CHECK (Smart)
                    # Only check if Hash failed AND we have the engine
                    elif db_heuristics:
                        try:
                            # Scan the file path directly with YARA
                            matches = db_heuristics.match(data=content)
                            if matches:
                                # We found a pattern!
                                # matches is a list of Rule objects.
                                # Since we used "chunks", we might see "ClamAV_NDB_12"
                                rule_name = matches[0].rule
                                found_threat = f"Heuristic.Match.{rule_name}"
                                detection_type = "NDB"
                                stats["NDB"] += 1
                        except Exception as e: 
                            pass

                    # REPORT & COPY
                    if found_threat:
                        print(f"   [!] {detection_type} HIT: {file} -> {found_threat}")
                        
                        # Sanitize filename for copy
                        safe_name = f"{detection_type}_{file}_FOUND.bin".replace("/", "_")
                        shutil.copy(filepath, os.path.join(TARGET_DIR, safe_name))
                        
                except Exception:
                    continue 

    print("\n" + "="*40)
    print(f"[+] HUNT COMPLETE")
    print(f"[+] Exact Hash Matches : {stats['HASH']}")
    print(f"[+] Heuristic Patterns : {stats['NDB']}")
    print(f"[+] Total Detected     : {stats['HASH'] + stats['NDB']}")
    print("="*40)

if __name__ == "__main__":
    hunt()