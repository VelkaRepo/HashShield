import hashlib
import os
import argparse # -> 1. Import library argparse

# Daftar pengecualian default
DEFAULT_EXCLUDED_DIRS = {'.git', '__pycache__', 'node_modules', 'venv'}

def calculate_md5(file_path):
    hash_md5 = hashlib.md5()
    try:
        with open(file_path, "rb") as f:
            for chunk in iter(lambda: f.read(4096), b""):
                hash_md5.update(chunk)
        return hash_md5.hexdigest()
    except Exception:
        return None

def load_signatures(db_path):
    signatures = {}
    try:
        with open(db_path, 'r') as f:
            for line in f:
                parts = line.strip().split(',')
                if len(parts) == 2:
                    signatures[parts[0]] = parts[1]
    except FileNotFoundError:
        print(f"Error: File database signature tidak ditemukan di '{db_path}'")
    except Exception as e:
        print(f"Error saat memuat signature: {e}")
    return signatures

def scan_file(file_path, signatures):
    file_hash = calculate_md5(file_path)
    if file_hash and file_hash in signatures:
        print(f"[!!!] MALWARE DITEMUKAN: File '{file_path}' cocok dengan '{signatures[file_hash]}'")
        return True
    return False

def scan_directory(dir_path, signatures, excluded_dirs):
    files_scanned = 0
    threats_found = 0
    print(f"\nMemulai pemindaian di direktori: '{dir_path}'\n" + "="*40)
    
    for root, dirs, files in os.walk(dir_path):
        dirs[:] = [d for d in dirs if d not in excluded_dirs]
        
        for file in files:
            file_path = os.path.join(root, file)
            try:
                if scan_file(file_path, signatures):
                    threats_found += 1
            except Exception as e:
                print(f"[???] GAGAL memindai file '{file_path}': {e}")
            files_scanned += 1

    print("="*40 + f"\nRingkasan Pemindaian Selesai:")
    print(f"  Total file dipindai: {files_scanned}")
    print(f"  Total ancaman ditemukan: {threats_found}")


# --- BAGIAN EKSEKUSI UTAMA (Dirombak total dengan argparse) ---
if __name__ == "__main__":
    # 2. Buat parser argumen
    parser = argparse.ArgumentParser(
        description="Hash Shield: Memindai direktori untuk mencari file berbahaya berdasarkan signature hash."
    )
    
    # 3. Tambahkan argumen yang dibutuhkan: path direktori
    parser.add_argument(
        "directory", 
        help="Path ke direktori yang ingin dipindai."
    )
    
    # 4. Tambahkan argumen opsional: --exclude
    parser.add_argument(
        "-e", "--exclude", 
        nargs='+', 
        default=[], 
        help="Daftar tambahan direktori/file yang ingin diabaikan."
    )
    
    # 5. Proses argumen yang diberikan pengguna
    args = parser.parse_args()
    
    # 6. Jalankan logika utama
    db_file_path = os.path.join(os.path.dirname(__file__), '..', 'signatures.txt')
    malware_signatures = load_signatures(db_file_path)
    
    if malware_signatures:
        print("Database signature berhasil dimuat.")
        
        # Gabungkan daftar pengecualian default dengan yang diberikan pengguna
        excluded_items = DEFAULT_EXCLUDED_DIRS.union(set(args.exclude))
        
        if os.path.isdir(args.directory):
            scan_directory(args.directory, malware_signatures, excluded_items)
        else:
            print(f"Error: Path '{args.directory}' bukan direktori yang valid atau tidak ditemukan.")
    else:
        print("Tidak dapat melanjutkan pemindaian karena database signature gagal dimuat.")