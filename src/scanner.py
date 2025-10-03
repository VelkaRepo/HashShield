# A malware detection system with Caching, Asynchronous Scanning, and Progress Bar.

import hashlib
import aiohttp # For asynchronous HTTP requests
import asyncio # For concurrent task execution
import os
import json
from tqdm.asyncio import tqdm # For asynchronous progress bars

# --- Configuration ---
API_KEY = "YOUR_VIRUSTOTAL_API_KEY_HERE"
API_URL = "https://www.virustotal.com/api/v3/files/"
CACHE_FILE = "scan_cache.txt"

# --- Cache Functions (remain synchronous for simplicity) ---
def load_cache():
    """Loads the scan cache from a file."""
    cache = {}
    if os.path.exists(CACHE_FILE):
        with open(CACHE_FILE, 'r') as f:
            for line in f:
                if ':' in line:
                    file_hash, status = line.strip().split(':', 1)
                    cache[file_hash] = status
    return cache

def save_cache(cache):
    """Saves the scan cache to a file."""
    with open(CACHE_FILE, 'w') as f:
        for file_hash, status in cache.items():
            f.write(f"{file_hash}:{status}\n")

# --- Asynchronous Hashing Function ---
# Use asyncio.to_thread to run the potentially blocking hash calculation 
# in a separate thread so it doesn't block the main asyncio loop.
async def calculate_file_hash_async(filepath, block_size=65536):
    """Calculates the SHA256 hash of a file in a separate thread."""
    def sync_hash():
        sha256 = hashlib.sha256()
        try:
            with open(filepath, 'rb') as f:
                while True:
                    data = f.read(block_size)
                    if not data:
                        break
                    sha256.update(data)
            return sha256.hexdigest()
        except FileNotFoundError:
            return None
        except Exception:
            return None # Handle other file-related errors

    return await asyncio.to_thread(sync_hash)


# --- Asynchronous Scanner Function with Cache ---
async def scan_file_virustotal_async(filepath, cache, session):
    """
    Scans a file using the VirusTotal API asynchronously and a local cache.
    Returns: filepath, is_malicious, report_message
    """
    file_hash = await calculate_file_hash_async(filepath)
    
    if not file_hash:
        return filepath, False, "Error: Could not calculate file hash."

    # 1. Check the local cache first
    if file_hash in cache:
        status = cache[file_hash]
        is_malware = status == 'malicious'
        return filepath, is_malware, f"Result from cache: {status}"

    # 2. If not in cache, proceed with the API call
    headers = {
        "x-apikey": API_KEY,
        "Accept": "application/json"
    }
    url = f"{API_URL}{file_hash}"

    try:
        # Use the aiohttp session for the request
        async with session.get(url, headers=headers) as response:
            
            # Rate limit handling: VirusTotal API returns a 429 status code
            if response.status == 429:
                 return filepath, False, "API Error: Rate limit exceeded. Please wait and try again."
            
            response.raise_for_status() # Raises an exception for 4xx/5xx status codes
            
            data = await response.json()
            
            is_malicious = False
            report_msg = "Scan complete. File is clean."
            
            if response.status == 200:
                attributes = data.get("data", {}).get("attributes", {})
                last_analysis_stats = attributes.get("last_analysis_stats", {})
                malicious_count = last_analysis_stats.get("malicious", 0)

                if malicious_count > 0:
                    is_malicious = True
                    report_msg = f"DANGER! Detected by {malicious_count} vendors."
                else:
                    report_msg = "Scan complete. File is clean."
            
            elif response.status == 404:
                # File hash not in VT database, so we assume clean
                report_msg = "File hash not found in VirusTotal database. Assumed clean."
            
            # 3. Update and save the cache with the new result
            cache[file_hash] = 'malicious' if is_malicious else 'clean'
            # Note: In a true async application, saving the cache should also be non-blocking.
            # We keep it sync here for simplicity, but it's a known potential bottleneck.
            save_cache(cache) 

            return filepath, is_malicious, report_msg

    except aiohttp.ClientResponseError as e:
        return filepath, False, f"HTTP Error {e.status}: {e.message}"
    except Exception as e:
        return filepath, False, f"Network/Other Error: {e}"


# --- Main Asynchronous Runner ---
async def main_async_scanner(filepaths):
    """Runs all file scans concurrently and displays progress."""
    scan_cache = load_cache()
    results = []
    
    # Use aiohttp.ClientSession to manage connections efficiently
    async with aiohttp.ClientSession() as session:
        # Create a list of tasks for asyncio
        tasks = [
            scan_file_virustotal_async(filepath, scan_cache, session)
            for filepath in filepaths
        ]

        # Use tqdm.asyncio.tqdm to display a progress bar while tasks run
        # as_completed yields results as they finish, which is ideal for a progress bar
        print(f"Starting concurrent scan of {len(filepaths)} files...")
        
        for coro in tqdm(asyncio.as_completed(tasks), total=len(tasks), desc="Scanning Files"):
            result = await coro
            results.append(result)

    return results

# --- Main Execution ---
if __name__ == "__main__":
    
    # --- Setup Test Files ---
    eicar_test_string = r"X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"
    
    test_files = [
        ("eicar_1.txt", eicar_test_string), # Malware sim
        ("benign_a.txt", "This is a safe file A."), # Clean
        ("eicar_2.txt", eicar_test_string), # Malware sim (will be cached)
        ("benign_b.txt", "This is a safe file B."), # Clean
        ("new_file.txt", "A third unique clean file.") # Clean (new API call)
    ]
    
    filepaths_to_scan = []
    try:
        for filename, content in test_files:
            with open(filename, "w") as f:
                f.write(content)
            filepaths_to_scan.append(filename)
    except IOError as e:
        print(f"Could not create test files: {e}")
        exit()

    print("Test files created. Running asynchronous scan...\n")

    # Run the asynchronous main function
    results = asyncio.run(main_async_scanner(filepaths_to_scan))

    # --- Print Final Results ---
    print("\n\n--- SCAN RESULTS SUMMARY ---")
    for filepath, is_malicious, message in results:
        status_icon = "⚠️ MALICIOUS" if is_malicious else "✅ CLEAN"
        print(f"[{status_icon:<12}] {filepath:<15} | {message}")
    print("-" * 35)

    # --- Clean up ---
    for filepath in filepaths_to_scan:
        if os.path.exists(filepath):
            os.remove(filepath)
    
    if os.path.exists(CACHE_FILE):
        os.remove(CACHE_FILE)
    print("\nTest files and cache removed.")