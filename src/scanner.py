import hashlib
import os

# Fungsi untuk menghitung hash MD5 dari sebuah file
def calculate_md5(file_path):
    """
    Membaca file dalam mode binary dan mengembalikan hash MD5-nya.
    Menggunakan 'rb' (read binary) penting agar hash konsisten di semua OS.
    """
    hash_md5 = hashlib.md5()
    try:
        with open(file_path, "rb") as f:
            for chunk in iter(lambda: f.read(4096), b""):
                hash_md5.update(chunk)
        return hash_md5.hexdigest()
    except FileNotFoundError:
        print(f"Error: File tidak ditemukan di '{file_path}'")
        return None
    except Exception as e:
        print(f"Error saat membaca file '{file_path}': {e}")
        return None

# Fungsi untuk memuat signature malware dari file database
def load_signatures(db_path):
    """
    Membaca file database signature dan memuatnya ke dalam dictionary.
    Format: { 'hash_value': 'malware_name' }
    """
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

# Fungsi utama untuk memindai file
def scan_file(file_path, signatures):
    """
    Menghitung hash file dan memeriksanya di dalam dictionary signatures.
    """
    file_hash = calculate_md5(file_path)
    if file_hash:
        if file_hash in signatures:
            print(f"[!!!] MALWARE DITEMUKAN: File '{file_path}' cocok dengan signature '{signatures[file_hash]}'")
        else:
            print(f"[---] AMAN: File '{file_path}' bersih.")
    else:
        print(f"[???] GAGAL: Tidak dapat memindai file '{file_path}'.")

# --- Bagian Eksekusi Utama ---
if __name__ == "__main__":
    # Path ke file signature, relatif dari lokasi script
    db_file_path = os.path.join(os.path.dirname(__file__), '..', 'signatures.txt')

    malware_signatures = load_signatures(db_file_path)

    if malware_signatures:
        print("Database signature berhasil dimuat.")

        # File yang akan di-scan (file tes EICAR kita)
        file_to_scan = "file_tes_eicar.txt" 

        print(f"\nMemindai file: {file_to_scan}...")
        scan_file(file_to_scan, malware_signatures)
    else:
        print("Tidak dapat melanjutkan pemindaian karena database signature gagal dimuat.")