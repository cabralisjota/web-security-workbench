#!/data/data/com.termux/files/usr/bin/bash
set -euo pipefail
APP="$HOME/web-app-pentest"
cd "$APP" || exit 1
if ! command -v tmux >/dev/null 2>&1; then pkg install -y tmux; fi
python -m py_compile monitor_portal.py v5_suite.py v5_features.py
# Only this tmux session is restarted; other cybersecurity projects are untouched.
tmux kill-session -t customer-monitor 2>/dev/null || true
tmux new-session -d -s customer-monitor "cd '$APP' && bash -c 'set -a; [ -f .copilot.env ] && . .copilot.env; [ -f .monitor.env ] && . .monitor.env; [ -f .v5.env ] && . .v5.env; set +a; export MONITOR_DEMO_MODE=1; exec python -u monitor_portal.py'"
sleep 2
python - <<'PY'
import json,urllib.request
url='http://127.0.0.1:18771/health'
try:
    with urllib.request.urlopen(url,timeout=5) as response:
        result=json.loads(response.read())
    if result.get('version')!='5.0':
        print('Another process (probably old v4) is still serving port 18771.')
        print('Stop the manually started old monitor_portal.py, then run: bash ~/web-app-pentest/start_v5.sh')
        raise SystemExit(1)
    print('SUCCESS: Workbench v5 is online at http://127.0.0.1:18771/')
    print('Open the dashboard, choose Explore demo, then Security Center → Run all training checks.')
except Exception as exc:
    print('The v5 portal did not start:',type(exc).__name__,str(exc))
    print('Check logs: tmux capture-pane -pt customer-monitor -S -60')
    raise SystemExit(1)
PY
