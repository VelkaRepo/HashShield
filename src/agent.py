import argparse
import base64
import json
import os
import platform
import shutil
import socket
import sys
import time
import hashlib
import subprocess
from datetime import datetime
from pathlib import Path
import threading
import requests

import colorama
from colorama import Fore, Style
from dotenv import load_dotenv

colorama.init(autoreset=True)

# --- CONFIG ---
if getattr(sys, 'frozen', False):
    _base_dir = Path(sys.executable).resolve().parent
else:
    _base_dir = Path(__file__).resolve().parent
load_dotenv(_base_dir / ".env")

# Ambil IP Lokal dan Tailscale dari .env
LOCAL_IP      = os.getenv("SHIELD_LOCAL_IP", "192.168.18.6")
TAILSCALE_IP  = os.getenv("SHIELD_TAILSCALE_IP", "")
DEFAULT_HOST  = LOCAL_IP or TAILSCALE_IP or "127.0.0.1"
DEFAULT_PORT  = int(os.getenv("SHIELD_DAEMON_PORT", 65432))
DEFAULT_TOKEN = os.getenv("SHIELD_AUTH_TOKEN", "")
TIMEOUT       = 10.0
MAX_FILE_SIZE = 32 * 1024 * 1024

C_RED    = Fore.RED
C_GREEN  = Fore.GREEN
C_YELLOW = Fore.YELLOW
C_GREY   = Fore.LIGHTBLACK_EX
C_RESET  = Style.RESET_ALL
C_BRIGHT = Style.BRIGHT


# --- CONNECTION ---

def check_daemon(host, port, timeout=1.5):
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True
    except OSError:
        return False


# --- SCAN LOGIC ---

def scan_file(filepath, host, port, token):
    try:
        file_size = os.path.getsize(filepath)
        if file_size > MAX_FILE_SIZE:
            return False, "Skipped (file exceeds 32MB limit)", None

        sha256 = hashlib.sha256()
        md5 = hashlib.md5()
        with open(filepath, 'rb') as f:
            while chunk := f.read(65536):
                sha256.update(chunk)
                md5.update(chunk)
        file_sha256 = sha256.hexdigest()
        file_md5 = md5.hexdigest()

        handshake_payload = json.dumps({
            "type": "check_hash",
            "token": token,
            "hostname": socket.gethostname(),
            "md5": file_md5,
            "sha256": file_sha256
        })

        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(TIMEOUT)
            s.connect((host, port))
            s.sendall(handshake_payload.encode())
            s.shutdown(socket.SHUT_WR)
            response = s.recv(1024).decode().strip()

        if response == "UNAUTHORIZED":
            return False, "Error: Invalid token", None
        
        if response != "UNKNOWN":
            if response.startswith("INFECTED"):
                parts = response.split(":", 2)
                engine_type = parts[1] if len(parts) > 2 else "YARA"
                threat = parts[2] if len(parts) > 2 else "Unknown Threat"
                return True, threat, engine_type
            elif response == "CLEAN":
                return False, "Clean", None

        with open(filepath, "rb") as f:
            encoded = base64.b64encode(f.read()).decode()

        payload = json.dumps({
            "token": token,
            "hostname": socket.gethostname(),
            "path": os.path.abspath(filepath),
            "content": encoded,
            "sha256": file_sha256
        })

        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(TIMEOUT)
            s.connect((host, port))
            s.sendall(payload.encode())
            s.shutdown(socket.SHUT_WR)
            response = s.recv(1024).decode().strip()

        if response.startswith("INFECTED"):
            parts = response.split(":", 2)
            engine_type = parts[1] if len(parts) > 2 else "YARA"
            threat = parts[2] if len(parts) > 2 else "Unknown Threat"
            return True, threat, engine_type
        
        return False, "Clean", None

    except Exception as e:
        return False, f"Error: {e}", None


EXCLUDED_DIRS = {
    'AppData', '$Recycle.Bin', 'System Volume Information',
    'Windows', 'Program Files', 'Program Files (x86)',
    '__pycache__', '.git'
}

def scan_directory(directory, host, port, token):
    results = []
    for item in Path(directory).rglob("*"):
        try:
            if os.path.islink(item):
                continue
            if not item.is_file():
                continue
            if any(part in EXCLUDED_DIRS for part in item.parts):
                continue
        except (PermissionError, OSError):
            continue
        is_infected, detail, engine_type = scan_file(str(item), host, port, token)
        results.append((str(item), is_infected, detail, engine_type, "INFECTED" if is_infected else "CLEAN"))
        _print_live(str(item), is_infected, detail)
    return results


# --- REMEDIATION ---

def quarantine_file(filepath):
    try:
        quarantine_dir = _base_dir / "hashshield-quarantine"
        quarantine_dir.mkdir(exist_ok=True)

        original    = Path(filepath)
        timestamp   = datetime.now().strftime("%Y%m%d_%H%M%S")
        locked_name = f"{original.name}.{timestamp}.locked"
        destination = quarantine_dir / locked_name

        shutil.move(str(original), str(destination))

        if platform.system() == "Windows":
            os.system(f'icacls "{destination}" /deny Everyone:(X) >nul 2>&1')
        else:
            os.chmod(destination, 0o444)

        return True, str(destination)
    except Exception as e:
        return False, str(e)


def delete_file(filepath):
    try:
        os.remove(filepath)
        return True, filepath
    except Exception as e:
        return False, str(e)


def _do_quarantine(fp, detail, results):
    success, result = quarantine_file(fp)
    if success:
        print(f"  {C_GREEN}[+] Quarantined → {result}{C_RESET}")
        _update_result_status(results, fp, f"[QUARANTINED] {detail}", "QUARANTINED")
    else:
        print(f"  {C_RED}[!] Failed: {result}{C_RESET}")


def _do_delete(fp, detail, results):
    success, result = delete_file(fp)
    if success:
        print(f"  {C_GREEN}[+] Deleted → {fp}{C_RESET}")
        _update_result_status(results, fp, f"[DELETED] {detail}", "DELETED")
    else:
        print(f"  {C_RED}[!] Failed: {result}{C_RESET}")


def _update_result_status(results, filepath, new_detail, new_status):
    for i, entry in enumerate(results):
        if entry[0] == filepath:
            results[i] = (entry[0], entry[1], new_detail, entry[3], new_status)
            break


def prompt_remediation(infected_results, results):
    if not infected_results:
        return

    print(f"\n{C_YELLOW}{'─' * 55}")
    print(f"  INFECTED FILES DETECTED ({len(infected_results)})")
    print(f"{'─' * 55}{C_RESET}")

    for i, (fp, detail, _) in enumerate(infected_results, 1):
        print(f"  {C_RED}[{i}]{C_RESET} {Path(fp).name}")
        print(f"       {C_YELLOW}→ {detail}{C_RESET}")

    print(f"\n  Action for ALL infected files?")
    print(f"  ({C_YELLOW}Q{C_RESET})uarantine  "
          f"({C_RED}D{C_RESET})elete  "
          f"({C_GREEN}S{C_RESET})kip  "
          f"({C_BRIGHT}R{C_RESET})eview one by one")

    try:
        action = input(f"\n  Choice: ").strip().lower()
    except (EOFError, KeyboardInterrupt):
        print(f"\n  {C_YELLOW}Non-interactive mode. Skipping remediation.{C_RESET}")
        return

    if action == 'q':
        print(f"\n  {C_YELLOW}[*] Quarantining all infected files...{C_RESET}")
        for fp, detail, _ in infected_results:
            _do_quarantine(fp, detail, results)

    elif action == 'd':
        print(f"\n  {C_RED}[*] Deleting all infected files...{C_RESET}")
        for fp, detail, _ in infected_results:
            _do_delete(fp, detail, results)

    elif action == 'r':
        print(f"\n  {C_BRIGHT}[*] Reviewing one by one...{C_RESET}\n")
        batch_action = None
        for idx, (fp, detail, _) in enumerate(infected_results):
            if batch_action:
                if batch_action == 'q':
                    _do_quarantine(fp, detail, results)
                elif batch_action == 'd':
                    _do_delete(fp, detail, results)
                continue

            remaining = len(infected_results) - idx
            print(f"  {C_RED}[INFECTED]{C_RESET} {fp}")
            print(f"  {C_YELLOW}→ {detail}{C_RESET}")
            print(f"  ({C_YELLOW}Q{C_RESET})uarantine  "
                  f"({C_RED}D{C_RESET})elete  "
                  f"({C_GREEN}S{C_RESET})kip  "
                  f"({C_BRIGHT}A{C_RESET})pply to all remaining ({remaining})")
            try:
                choice = input(f"  Choice: ").strip().lower()
            except (EOFError, KeyboardInterrupt):
                print(f"  {C_YELLOW}Skipping remaining.{C_RESET}")
                break

            if choice == 'q':
                _do_quarantine(fp, detail, results)
            elif choice == 'd':
                _do_delete(fp, detail, results)
            elif choice == 'a':
                print(f"\n  Apply to all remaining {remaining} files?")
                print(f"  ({C_YELLOW}Q{C_RESET})uarantine  ({C_RED}D{C_RESET})elete  ({C_GREEN}S{C_RESET})kip")
                try:
                    batch_choice = input(f"  Choice: ").strip().lower()
                except (EOFError, KeyboardInterrupt):
                    batch_choice = 's'
                if batch_choice in ('q', 'd'):
                    batch_action = batch_choice
                    if batch_action == 'q':
                        _do_quarantine(fp, detail, results)
                    elif batch_action == 'd':
                        _do_delete(fp, detail, results)
                else:
                    print(f"  {C_GREY}[*] Skipping remaining.{C_RESET}")
                    break
            else:
                print(f"  {C_GREY}[*] Skipped.{C_RESET}")
            print()

    else:
        print(f"\n  {C_GREY}[*] Skipped. No action taken.{C_RESET}")


# --- REPORTING ---

def request_report(results, fmt, host, port, token, scan_duration):
    try:
        hostname = socket.gethostname()
        try:
            client_ip = socket.gethostbyname(hostname)
        except Exception:
            client_ip = "Unknown"

        payload = json.dumps({
            "token":         token,
            "type":          "generate_report",
            "format":        fmt,
            "hostname":      hostname,
            "client_ip":     client_ip,
            "system_info":   f"{platform.system()} {platform.release()}",
            "scan_duration": round(scan_duration, 2),
            "results": [
                {
                    "file":        fp,
                    "infected":    is_infected,
                    "detail":      detail,
                    "engine_type": engine_type or "",
                    "status":      status
                }
                for fp, is_infected, detail, engine_type, status in results
            ]
        })

        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(30.0)
            s.connect((host, port))
            s.sendall(payload.encode())
            s.shutdown(socket.SHUT_WR)

            chunks = []
            while True:
                chunk = s.recv(65536)
                if not chunk:
                    break
                chunks.append(chunk)

        return b"".join(chunks).decode()

    except Exception as e:
        return None


# --- OUTPUT ---

def _print_live(filepath, is_infected, detail):
    if is_infected:
        print(f"  {C_RED}[INFECTED]{C_RESET} {filepath}")
        print(f"  {C_YELLOW}          → {detail}{C_RESET}")
    else:
        print(f"  {C_GREY}[CLEAN]   {filepath}{C_RESET}")


def print_summary(results, duration, log_path):
    infected = [r for r in results if r[1]]
    print(f"\n{'─' * 55}")
    print(f"  Scanned  : {C_BRIGHT}{len(results)}{C_RESET} files in {duration:.2f}s")
    print(f"  Infected : {C_RED}{C_BRIGHT}{len(infected)}{C_RESET}")
    print(f"  Clean    : {C_GREEN}{C_BRIGHT}{len(results) - len(infected)}{C_RESET}")
    print(f"{'─' * 55}")
    print(f"  {C_GREY}Log saved → {log_path}{C_RESET}\n")


def write_log(results, log_path, host, port):
    with open(log_path, "a", encoding="utf-8") as f:
        f.write(f"\n{'=' * 55}\n")
        f.write(f"Scan Time : {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
        f.write(f"Host      : {socket.gethostname()}\n")
        f.write(f"Daemon    : {host}:{port}\n")
        f.write(f"{'=' * 55}\n")
        for fp, is_infected, detail, _, status in results:
            f.write(f"[{status}] {fp} | {detail}\n")

# --- EDITED: HEARTBEAT WORKER ---
def heartbeat_worker(daemon_ip="100.72.155.33", http_port=8080):
    url = f"http://{daemon_ip}:{http_port}/api/heartbeat"
    hostname = socket.gethostname()
    os_info = f"{platform.system()} {platform.release()}"
    
    # 1. Deteksi IP Lokal
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        local_ip = s.getsockname()[0]
        s.close()
    except:
        local_ip = "127.0.0.1"

    # 2. Deteksi IP Tailscale
    tailscale_ip = "—"
    try:
        # Penanganan khusus jika berjalan di Windows Server
        if platform.system() == "Windows":
            cmd = [r"C:\Program Files\Tailscale\tailscale.exe", "ip", "-4"]
        else:
            cmd = ["tailscale", "ip", "-4"]
        
        res = subprocess.run(cmd, capture_output=True, text=True, timeout=2)
        if res.returncode == 0:
            tailscale_ip = res.stdout.strip()
    except Exception:
        pass

    # Mengirim sinyal kehidupan secara diam-diam
    while True:
        try:
            payload = {
                "hostname": hostname,
                "os": os_info,
                "localIp": local_ip,
                "tailscaleIp": tailscale_ip,
                "scans": 0, 
                "threats": 0
            }
            requests.post(url, json=payload, timeout=3)
        except Exception:
            pass # Abaikan jika gagal (misal daemon belum nyala)
        
        time.sleep(10) # Melapor setiap 10 detik


# --- ENTRY POINT ---

def main():
    parser = argparse.ArgumentParser(
        description="HashShield Agent — Remote Scanner Client",
        formatter_class=argparse.RawTextHelpFormatter
    )
    parser.add_argument("path",      metavar="PATH",   help="File or directory to scan")
    parser.add_argument("--server",  metavar="IP",     default=DEFAULT_HOST,  help=f"Daemon IP (default: {DEFAULT_HOST})")
    parser.add_argument("--port",    metavar="PORT",   type=int, default=DEFAULT_PORT, help=f"Daemon port (default: {DEFAULT_PORT})")
    parser.add_argument("--token",   metavar="TOKEN",  default=DEFAULT_TOKEN, help="Auth token (overrides .env)")
    parser.add_argument("-o",        metavar="FILE",   dest="output", default=None, help="Save report to file")
    parser.add_argument("--format",  metavar="FORMAT", dest="fmt",
                        choices=["html", "txt", "csv", "json"], default="html",
                        help="Report format (default: html)")
    args = parser.parse_args()

    port     = args.port
    token    = args.token
    log_path = Path.cwd() / "agent_log.txt"
    
    # --- EDITED: START HEARTBEAT BACKGROUND ---
    # Thread berjalan di background. Begitu user mematikan CMD, thread ikut mati.
    h_thread = threading.Thread(target=heartbeat_worker, daemon=True)
    h_thread.start()

    print(f"\n{C_YELLOW}{C_BRIGHT}  HashShield Agent{C_RESET}  "
          f"{C_GREY}→ Mencari rute jaringan terbaik...{C_RESET}\n")

    # --- SMART CONNECTION ROUTING ---
    target_ips = []
    
    # Jika user memaksa menggunakan flag --server spesifik di terminal
    if args.server != DEFAULT_HOST and args.server:
        target_ips.append(("Manual Flag", args.server))
    else:
        # Jika menggunakan default, kita susun hierarki pencarian (Lokal dulu, baru Tailscale)
        if LOCAL_IP: target_ips.append(("Lokal", LOCAL_IP))
        if TAILSCALE_IP: target_ips.append(("Tailscale", TAILSCALE_IP))

    host = None
    for route_name, ip in target_ips:
        print(f"  [*] Mencoba koneksi {route_name} ({ip}:{port}) ... ", end="")
        if check_daemon(ip, port, timeout=1.5): # Timeout 1.5 detik agar cepat failover
            print(f"{C_GREEN}SUKSES{C_RESET}")
            host = ip
            break
        else:
            print(f"{C_RED}GAGAL{C_RESET}")

    if not host:
        print(f"\n  {C_RED}[ERROR]{C_RESET} Cannot reach daemon at any known IP addresses.")
        print(f"  {C_GREY}Pastikan Daemon Kali Linux menyala dan terhubung ke Jaringan / Tailscale.{C_RESET}\n")
        return

    print(f"\n  {C_GREEN}[+] Daemon reachable via {host}. Starting scan...{C_RESET}\n")
    print(f"{'─' * 55}")

    target = Path(args.path)
    if not target.exists():
        print(f"  {C_RED}[ERROR]{C_RESET} Path not found: {target}\n")
        return

    start = time.time()

    if target.is_file():
        is_infected, detail, engine_type = scan_file(str(target), host, port, token)
        _print_live(str(target), is_infected, detail)
        status  = "INFECTED" if is_infected else "CLEAN"
        results = [(str(target), is_infected, detail, engine_type, status)]
    else:
        results = scan_directory(str(target), host, port, token)

    duration = time.time() - start

    print_summary(results, duration, log_path)

    infected_results = [(fp, detail, engine_type)
                        for fp, is_infected, detail, engine_type, _ in results
                        if is_infected]
    if infected_results:
        prompt_remediation(infected_results, results)

    write_log(results, log_path, host, port)

    if args.output:
        print(f"\n  {C_YELLOW}[*] Requesting report from daemon...{C_RESET}")
        content = request_report(results, args.fmt, host, port, token, duration)
        if content:
            output_path = Path.cwd() / args.output
            with open(output_path, "w", encoding="utf-8") as f:
                f.write(content)
            print(f"  {C_GREEN}[+] Report saved → {output_path}{C_RESET}\n")
        else:
            print(f"  {C_RED}[!] Report generation failed.{C_RESET}\n")


if __name__ == "__main__":
    main()