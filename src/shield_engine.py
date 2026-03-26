import tarfile
import io
import os
import requests
import glob
import time
import yara

# --- CONFIGURATION ---
CHUNK_SIZE = 8000 
DB_URL = "https://github.com/VelkaRepo/HashShield/releases/download/v2.0-beta/main.cvd"

def format_clamav_to_yara(hex_string):
    if any(c in hex_string for c in "*{}-()"): 
        return None
    try:
        chunks = [hex_string[i:i+2] for i in range(0, len(hex_string), 2)]
        return " ".join(chunks)
    except:
        return None

def download_clamav_hashes():
    current_dir = os.path.dirname(os.path.abspath(__file__))
    local_db_path = os.path.join(current_dir, 'main.cvd')
    
    hash_db = {}
    ndb_map = {} 
    
    # --- BARIS KRUSIAL YANG TADI TERLEWAT ---
    start_time = time.time() 
    # ----------------------------------------

    yara_rules_buffer = []
    ndb_total_count = 0
    current_chunk_count = 0
    current_rule_index = 0
    
    if not os.path.exists(local_db_path):
        print("[Shield Engine] Local DB missing. Initializing first download...")
        success = update_database(local_db_path)
        if not success:
            return {}, None, {}

    try:
        with open(local_db_path, 'rb') as f:
            data = f.read()
            tar_data = data[512:] 
            
            with tarfile.open(fileobj=io.BytesIO(tar_data), mode='r:gz') as tar:
                # Mulai Rule Pertama
                yara_rules_buffer.append(f"rule ClamAV_NDB_{current_rule_index} {{\nstrings:\n")
                
                for member in tar.getmembers():
                    if member.name.endswith(('.hdb', '.hsb')):
                        f_ext = tar.extractfile(member)
                        if f_ext:
                            for line in f_ext:
                                try:
                                    parts = line.decode('latin-1').strip().split(':')
                                    if len(parts) >= 3:
                                        hash_db[parts[0]] = parts[2]
                                except: continue

                    if member.name.endswith('.ndb'):
                        f_ext = tar.extractfile(member)
                        if f_ext:
                            for line in f_ext:
                                try:
                                    parts = line.decode('latin-1').strip().split(':')
                                    if len(parts) >= 4:
                                        malware_name = parts[0]
                                        yara_sig = format_clamav_to_yara(parts[3])
                                        if yara_sig:
                                            var_id = f"s_{ndb_total_count}"
                                            ndb_map[var_id] = malware_name
                                            yara_rules_buffer.append(f"    ${var_id} = {{ {yara_sig} }}\n")
                                            ndb_total_count += 1
                                            current_chunk_count += 1
                                            
                                            if current_chunk_count >= CHUNK_SIZE:
                                                yara_rules_buffer.append("\ncondition:\n    any of them\n}\n\n")
                                                current_rule_index += 1
                                                current_chunk_count = 0
                                                yara_rules_buffer.append(f"rule ClamAV_NDB_{current_rule_index} {{\nstrings:\n")
                                except: continue
    except Exception as e:
        print(f"[Shield Engine] Error: {e}")

    # Finalize Rules
    if current_chunk_count == 0 and yara_rules_buffer:
        yara_rules_buffer.pop() 
    else:
        yara_rules_buffer.append("\ncondition:\n    any of them\n}")

    yara_rules_source = "".join(yara_rules_buffer)
    
    # Hitung Durasi Startup
    end_time = time.time()
    startup_duration = end_time - start_time
    
    # Compile
    compiled_yara = None
    if ndb_total_count > 0:
        print(f"[Shield Engine] Parsed {ndb_total_count} patterns in {startup_duration:.2f}s")
        try:
            c_start = time.time()
            compiled_yara = yara.compile(source=yara_rules_source)
            print(f"[Shield Engine] Compilation finished in {time.time() - c_start:.2f}s")
        except yara.Error as e:
            print(f"[Shield Engine] YARA Error: {e}")
    
    print(f"[Shield Engine] Hash Engine Online. Loaded {len(hash_db)} signatures.")
    return hash_db, compiled_yara, ndb_map