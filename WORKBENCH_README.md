# Web Security Workbench v1 (Android / Termux)

A local unified dashboard for the existing Web App Pentest Lab and Client Website Security Assessor. Uses Python's standard library and imports the existing `client_assessor.py`.

## Install

Prerequisites: `~/web-app-pentest/client_assessor.py` and `~/web-app-pentest/web_pentest.py` are already installed.

```sh
pkg install -y unzip tmux
unzip -o ~/storage/downloads/web-security-workbench-v1.zip -d ~/web-app-pentest
cd ~/web-app-pentest
python -m py_compile unified_dashboard.py
tmux new-session -d -s workbench 'cd ~/web-app-pentest && python -u unified_dashboard.py'
```

Open `http://127.0.0.1:18768/` in Chrome. Keep the existing lab server on port 18766 running. The old assessor on 18767 is optional because this dashboard imports its scanner directly.

## Features

- Run authorized baseline assessments with existing scope controls and report generation.
- Link to the existing vulnerable lab and original assessor.
- Verify local-lab XSS JavaScript execution via a harmless browser callback; only targets 127.0.0.1:18766.
- Show guidance for XSS, SQLi, IDOR and other future testing areas.

## Limits

The XSS proof is **lab only**. External scanning is baseline only and requires written authorization. The workbench does not provide a general-purpose exploitation engine. A callback confirms browser execution for that specific test; no callback is inconclusive.

To check the session: `tmux ls`. To see output: `tmux attach -t workbench` (detach with Ctrl+B then D). To stop: `tmux kill-session -t workbench`.
