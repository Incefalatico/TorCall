import urllib.request
import re
import ssl

ctx = ssl.create_default_context()
ctx.check_hostname = False
ctx.verify_mode = ssl.CERT_NONE

url = "https://dist.torproject.org/torbrowser/15.0.15/"
print(f"Fetching {url}...")
try:
    with urllib.request.urlopen(url, context=ctx, timeout=10) as response:
        html = response.read().decode('utf-8')
    
    # Find all links that contain tor-expert-bundle-windows
    files = re.findall(r'href=["\'](tor-expert-bundle-windows-[^"\']+)["\']', html)
    print("Found expert bundle files:")
    for f in files:
        print(f" - {f}")
except Exception as e:
    print(f"Error: {e}")
