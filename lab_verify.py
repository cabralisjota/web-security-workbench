import json
import urllib.request
import urllib.parse
import urllib.error
import http.cookiejar
from pathlib import Path
from datetime import datetime, timezone

BASE = "http://127.0.0.1:18766"
REPORTS = Path("reports")
REPORTS.mkdir(exist_ok=True)

cookies = http.cookiejar.CookieJar()
client = urllib.request.build_opener(
    urllib.request.HTTPCookieProcessor(cookies)
)

def request(path, data=None, headers=None):
    req = urllib.request.Request(
        BASE + path,
        data=data,
        headers=headers or {}
    )
    try:
        with client.open(req, timeout=8) as r:
            return r.status, r.read().decode(
                "utf-8", errors="replace"
            )
    except urllib.error.HTTPError as e:
        return e.code, e.read().decode(
            "utf-8", errors="replace"
        )

print("\n=== WEB APP PENTEST LAB VERIFICATION ===\n")

try:
    status, body = request("/health")
    health = json.loads(body)
    if status != 200 or "localhost" not in str(health):
        raise ValueError("Unexpected training application")
    print("Lab mode:", health.get("mode", "unknown"))
except Exception as e:
    raise SystemExit(
        f"Training lab unavailable: {e}\n"
        "Start web_pentest.py on port 18766 first."
    )

results = []

# 1. HTML injection / XSS indicator
payload = "<b>LAB-XSS</b>"
path = "/search?q=" + urllib.parse.quote(payload)
status, body = request(path)

exposed = payload in body
results.append({
    "test": "XSS indicator",
    "status": status,
    "result": "UNESCAPED HTML" if exposed else "NOT OBSERVED",
    "note": "HTML reflection alone does not prove JavaScript execution"
})
print("XSS indicator:", results[-1]["result"])

# 2. SQL injection
control = "/api/users?name=__missing_lab_user__"
injection = "/api/users?name=" + urllib.parse.quote(
    "' OR '1'='1"
)

_, baseline = request(control)
status, body = request(injection)

names_found = (
    "alice" in body.lower()
    and "bob" in body.lower()
    and not (
        "alice" in baseline.lower()
        and "bob" in baseline.lower()
    )
)

results.append({
    "test": "SQL injection",
    "status": status,
    "result": "POSITIVE INDICATOR" if names_found
              else "NOT OBSERVED",
    "note": "Compare injected query against nonexistent-user control"
})
print("SQL injection:", results[-1]["result"])

# 3. IDOR / broken access control
login_data = urllib.parse.urlencode({
    "username": "alice",
    "password": "labpass"
}).encode()

login_status, _ = request(
    "/login",
    data=login_data,
    headers={
        "Content-Type": "application/x-www-form-urlencoded"
    }
)

status, body = request("/api/invoices/2")

exposed = status == 200 and "bob" in body.lower()

results.append({
    "test": "IDOR",
    "login_http_status": login_status,
    "invoice_http_status": status,
    "result": "POSITIVE INDICATOR" if exposed
              else "NOT OBSERVED",
    "note": "Alice session attempting to access Bob's invoice"
})
print("IDOR:", results[-1]["result"])

report = {
    "project": "Web App Pentest Lab",
    "target": BASE,
    "mode": health.get("mode"),
    "timestamp": datetime.now(timezone.utc).isoformat(),
    "results": results
}

filename = REPORTS / (
    "lab-verification-" +
    datetime.now().strftime("%Y%m%d-%H%M%S") +
    ".json"
)

filename.write_text(
    json.dumps(report, indent=2),
    encoding="utf-8"
)

print("\nReport saved:", filename)
print("\nVerification complete.")
