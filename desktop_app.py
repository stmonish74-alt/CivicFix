import subprocess
import sys
import time
from pathlib import Path
import webview

BASE_DIR = Path(__file__).resolve().parent
APP_FILE = BASE_DIR / "streamlit_app.py"
PORT = 8765
URL = f"http://127.0.0.1:{PORT}"

server = None

try:
    server = subprocess.Popen(
        [
            sys.executable,
            "-m", "streamlit",
            "run", str(APP_FILE),
            "--server.headless=true",
            f"--server.port={PORT}",
            "--server.address=127.0.0.1",
            "--server.fileWatcherType=none",
            "--browser.gatherUsageStats=false"
        ],
        cwd=str(BASE_DIR)
    )

    time.sleep(5)

    webview.create_window(
        "CivicFix",
        URL,
        width=1200,
        height=800,
        min_size=(900, 600)
    )

    webview.start()

finally:
    if server and server.poll() is None:
        server.terminate()
        server.wait()