import hashlib
import os

# --- BAGIAN BARU: Daftar direktori yang akan diabaikan ---
# Kita definisikan sebagai konstanta di bagian atas agar mudah diubah.
EXCLUDED_DIRS = {'.git', '__pycache__', 'node_modules', 'venv'}

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

# --- FUNGSI SCAN_DIRECTORY (Diperbarui) ---
def scan_directory(dir_path, signatures, excluded_dirs):
    files_scanned = 0
    threats_found = 0
    print(f"\nMemulai pemindaian di direktori: '{dir_path}'\n" + "="*40)
    
    for root, dirs, files in os.walk(dir_path):
        
        # --- LOGIKA BARU: Pengecualian Direktori ---
        # Kita modifikasi 'dirs' secara "in-place" menggunakan [:]
        # Ini akan memberitahu os.walk untuk tidak masuk ke dalam direktori yang kita ekskludekan.
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

# --- BAGIAN EKSEKUSI UTAMA (Diperbarui) ---
if __name__ == "__main__":
    db_file_path = os.path.join(os.path.dirname(__file__), '..', 'signatures.txt')
    malware_signatures = load_signatures(db_file_path)
    
    if malware_signatures:
        print("Database signature berhasil dimuat.")
        target_dir = input("Masukkan path direktori yang akan di-scan (contoh: D:\\Downloads atau .): ")
        if os.path.isdir(target_dir):
            # Panggil fungsi scan_directory dengan daftar pengecualian
            scan_directory(target_dir, malware_signatures, EXCLUDED_DIRS)
        else:
            print(f"Error: Path '{target_dir}' bukan direktori yang valid atau tidak ditemukan.")
    else:
        print("Tidak dapat melanjutkan pemindaian karena database signature gagal dimuat.")