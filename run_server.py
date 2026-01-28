# Simple auto-restart wrapper for development (Windows)
import subprocess
import time
import sys

while True:
    print("Starting app.py ...")
    p = subprocess.Popen([sys.executable, "app.py"])
    p.wait()
    code = p.returncode
    print(f"app.py exited with code {code}. Restarting in 2s...")
    time.sleep(2)
