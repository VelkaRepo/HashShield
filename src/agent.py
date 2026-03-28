import argparse
import base64
import json
import os
import platform
import socket
import time
from datetime import datetime
from pathlib import Path

import colorama
from colorama import Fore, Style
from dotenv import load_dotenv

colorama.init(autoreset=True)

# --- CONFIG ---
_base_dir = Path(__file__).resolve().parent
load_dotenv(_base_dir / ".env")

DEFAULT_HOST  = os.getenv("SHIELD_SERVER", "192.168.18.6")
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

def check_daemon(host, port):
    try:
        with socket.create_connection((host, port), timeout=TIMEOUT):
            return True
    except OSError:
        return False


# --- SCAN LOGIC ---

def scan_file(filepath, host, port, token):
    try:
        file_size = os.path.getsize(filepath)
        if file_size > MAX_FILE_SIZE:
            return False, "Skipped (file exceeds 32MB limit)", None

        with open(filepath, "rb") as f:
            encoded = base64.b64encode(f.read()).decode()

        payload = json.dumps({
            "token":    token,
            "hostname": socket.gethostname(),
            "path":     os.path.abspath(filepath),
            "content":  encoded
        })

        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(TIMEOUT)
            s.connect((host, port))
            s.sendall(payload.encode())
            s.shutdown(socket.SHUT_WR)
            response = s.recv(1024).decode().strip()

        if response == "UNAUTHORIZED":
            return False, "Error: Invalid token — check .env SHIELD_AUTH_TOKEN", None
        if response.startswith("INFECTED"):
            parts       = response.split(":", 2)
            engine_type = parts[1] if len(parts) > 2 else "YARA"
            threat      = parts[2] if len(parts) > 2 else parts[1] if len(parts) > 1 else "Unknown Threat"
            return True, threat, engine_type
        return False, "Clean", None

    except Exception as e:
        return False, f"Error: {e}", None


def scan_directory(directory, host, port, token):
    results = []
    for item in Path(directory).rglob("*"):
        if not item.is_file():
            continue
        is_infected, detail, engine_type = scan_file(str(item), host, port, token)
        results.append((str(item), is_infected, detail, engine_type))
        _print_live(str(item), is_infected, detail)
    return results


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
                    "infected":    infected,
                    "detail":      detail,
                    "engine_type": engine_type or ""
                }
                for fp, infected, detail, engine_type in results
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
        for filepath, is_infected, detail, _ in results:
            status = "INFECTED" if is_infected else "CLEAN"
            f.write(f"[{status}] {filepath} | {detail}\n")


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

    host     = args.server
    port     = args.port
    token    = args.token
    log_path = Path.cwd() / "agent_log.txt"

    print(f"\n{C_YELLOW}{C_BRIGHT}  HashShield Agent{C_RESET}  "
          f"{C_GREY}→ {host}:{port}{C_RESET}\n")

    if not check_daemon(host, port):
        print(f"  {C_RED}[ERROR]{C_RESET} Cannot reach daemon at {host}:{port}")
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
        is_infected, detail, engine_type = scan_file(str(target), host, port, token)
        _print_live(str(target), is_infected, detail)
        results = [(str(target), is_infected, detail, engine_type)]
    else:
        results = scan_directory(str(target), host, port, token)

    duration = time.time() - start

    print_summary(results, duration, log_path)
    write_log(results, log_path, host, port)

    if args.output:
        print(f"  {C_YELLOW}[*] Requesting report from daemon...{C_RESET}")
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