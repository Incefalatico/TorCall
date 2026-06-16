import urllib.request
import tarfile
import os
import ssl
import sys

# Target directories
ROOT_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
TOR_TARGET_DIR = os.path.join(ROOT_DIR, "tor")
TEMP_TAR = os.path.join(ROOT_DIR, "tor_expert_bundle.tar.gz")

URL = "https://dist.torproject.org/torbrowser/15.0.15/tor-expert-bundle-windows-x86_64-15.0.15.tar.gz"

ctx = ssl.create_default_context()
ctx.check_hostname = False
ctx.verify_mode = ssl.CERT_NONE

print(f"Downloading Tor Expert Bundle from:\n{URL}")
try:
    # Use urlopen with context and write in chunks
    req = urllib.request.Request(
        URL, 
        headers={'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64)'}
    )
    with urllib.request.urlopen(req, context=ctx, timeout=30) as response:
        total_size = int(response.headers.get('content-length', 0))
        read_so_far = 0
        block_size = 1024 * 64 # 64 KB
        
        with open(TEMP_TAR, 'wb') as f:
            while True:
                chunk = response.read(block_size)
                if not chunk:
                    break
                f.write(chunk)
                read_so_far += len(chunk)
                if total_size > 0:
                    percent = min(100, read_so_far * 100 // total_size)
                    sys.stdout.write(f"\rDownloading Tor: {percent}% ({read_so_far}/{total_size} bytes)")
                else:
                    sys.stdout.write(f"\rDownloading Tor: {read_so_far} bytes")
                sys.stdout.flush()
                
    print("\nDownload complete.")
    
    print("Extracting archive...")
    os.makedirs(TOR_TARGET_DIR, exist_ok=True)
    
    with tarfile.open(TEMP_TAR, "r:gz") as tar:
        members = tar.getmembers()
        print(f"Archive has {len(members)} files/directories.")
        
        print("First 15 files in archive:")
        for m in members[:15]:
            print(f" - {m.name}")
            
        # Extract all files
        # Note: on Windows, tarfile.extractall might hit path issues or create folders.
        # Let's extract to ROOT_DIR
        tar.extractall(path=ROOT_DIR)
        
    print(f"Extraction complete. Verifying Tor binary...")
    # Let's list files in TOR_TARGET_DIR
    if os.path.exists(TOR_TARGET_DIR):
        print(f"Contents of {TOR_TARGET_DIR}:")
        for f in os.listdir(TOR_TARGET_DIR):
            print(f" - {f}")
            
    tor_exe = os.path.join(TOR_TARGET_DIR, "tor.exe")
    if os.path.isfile(tor_exe):
        print(f"Success! tor.exe is at: {tor_exe}")
    else:
        # Check if the folder extracted differently, e.g., nested
        print(f"Checking if tor.exe is nested...")
        found = False
        for root, dirs, files in os.walk(TOR_TARGET_DIR):
            if "tor.exe" in files:
                print(f"Found tor.exe nested at: {os.path.join(root, 'tor.exe')}")
                found = True
        if not found:
            print(f"Warning! tor.exe not found anywhere under {TOR_TARGET_DIR}")
        
    # Clean up temp file
    if os.path.isfile(TEMP_TAR):
        os.remove(TEMP_TAR)
        print("Cleaned up temp archive.")
        
except Exception as e:
    print(f"\nError: {e}")
