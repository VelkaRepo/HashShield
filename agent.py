import argparse
import base64
import json
import os
import socket
import time
from datetime import datetime
from pathlib import Path

import colorama
from colorama import Fore, Style

colorama.init(autoreset=True)

# --- CONFIG ---
DAEMON_HOST  = "192.168.18.6"
DAEMON_PORT  = 65432
TIMEOUT      = 10.0
MAX_FILE_SIZE = 32 * 1024 * 1024
LOG_FILE     = Path(__file__).resolve().parent / "agent_log.txt"

C_RED    = Fore.RED
C_GREEN  = Fore.GREEN
C_YELLOW = Fore.YELLOW
C_GREY   = Fore.LIGHTBLACK_EX
C_RESET  = Style.RESET_ALL
C_BRIGHT = Style.BRIGHT


# --- CONNECTION ---

def check_daemon():
    try:
        with socket.create_connection((DAEMON_HOST, DAEMON_PORT), timeout=TIMEOUT):
            return True
    except OSError:
        return False


# --- SCAN LOGIC ---

def scan_file(filepath):
    try:
        file_size = os.path.getsize(filepath)
        if file_size > MAX_FILE_SIZE:
            return False, "Skipped (file exceeds 32MB limit)"

        with open(filepath, "rb") as f:
            encoded = base64.b64encode(f.read()).decode()

        payload = json.dumps({
            "hostname": socket.gethostname(),
            "path": os.path.abspath(filepath),
            "content": encoded
        })

        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(TIMEOUT)
            s.connect((DAEMON_HOST, DAEMON_PORT))
            s.sendall(payload.encode())
            s.shutdown(socket.SHUT_WR)
            response = s.recv(1024).decode().strip()

        if response.startswith("INFECTED"):
            threat = response.split(":", 1)[1] if ":" in response else "Unknown Threat"
            return True, threat
        return False, "Clean"

    except Exception as e:
        return False, f"Error: {e}"


def scan_directory(directory):
    results = []
    for item in Path(directory).rglob("*"):
        if not item.is_file():
            continue
        is_infected, detail = scan_file(str(item))
        results.append((str(item), is_infected, detail))
        _print_live(str(item), is_infected, detail)
    return results


# --- OUTPUT ---

def _print_live(filepath, is_infected, detail):
    if is_infected:
        print(f"  {C_RED}[INFECTED]{C_RESET} {filepath}")
        print(f"  {C_YELLOW}          → {detail}{C_RESET}")
    else:
        print(f"  {C_GREY}[CLEAN]   {filepath}{C_RESET}")


def print_summary(results, duration):
    infected = [r for r in results if r[1]]
    print(f"\n{'─' * 55}")
    print(f"  Scanned  : {C_BRIGHT}{len(results)}{C_RESET} files in {duration:.2f}s")
    print(f"  Infected : {C_RED}{C_BRIGHT}{len(infected)}{C_RESET}")
    print(f"  Clean    : {C_GREEN}{C_BRIGHT}{len(results) - len(infected)}{C_RESET}")
    print(f"{'─' * 55}")
    print(f"  {C_GREY}Log saved → {LOG_FILE}{C_RESET}\n")


def write_log(results):
    with open(LOG_FILE, "a", encoding="utf-8") as f:
        f.write(f"\n{'=' * 55}\n")
        f.write(f"Scan Time : {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
        f.write(f"Host      : {socket.gethostname()}\n")
        f.write(f"Daemon    : {DAEMON_HOST}:{DAEMON_PORT}\n")
        f.write(f"{'=' * 55}\n")
        for filepath, is_infected, detail in results:
            status = "INFECTED" if is_infected else "CLEAN"
            f.write(f"[{status}] {filepath} | {detail}\n")


# --- ENTRY POINT ---

def main():
    parser = argparse.ArgumentParser(
        description="HashShield Agent — Remote Scanner Client",
        formatter_class=argparse.RawTextHelpFormatter
    )
    parser.add_argument("path", metavar="PATH", help="File or directory to scan")
    args = parser.parse_args()

    print(f"\n{C_YELLOW}{C_BRIGHT}  HashShield Agent{C_RESET}  "
          f"{C_GREY}→ {DAEMON_HOST}:{DAEMON_PORT}{C_RESET}\n")

    if not check_daemon():
        print(f"  {C_RED}[ERROR]{C_RESET} Cannot reach daemon at {DAEMON_HOST}:{DAEMON_PORT}")
        print(f"  {C_GREY}Make sure the daemon is running on the server.{C_RESET}\n")
        return

    print(f"  {C_GREEN}[+] Daemon reachable. Starting scan...{C_RESET}\n")
    print(f"{'─' * 55}")

    target = Path(args.path)
    if not target.exists():
        print(f"  {C_RED}[ERROR]{C_RESET} Path not found: {target}\n")
        return

    start = time.time()

    if target.is_file():
        is_infected, detail = scan_file(str(target))
        _print_live(str(target), is_infected, detail)
        results = [(str(target), is_infected, detail)]
    else:
        results = scan_directory(str(target))

    duration = time.time() - start

    print_summary(results, duration)
    write_log(results)


if __name__ == "__main__":
    main()