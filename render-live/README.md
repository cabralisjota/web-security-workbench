# Web Security Workbench — Live Render training service

This is a separate **public interactive training demonstration**, not the original local customer portal. It reuses the current `render-showcase/index.html` design and the 17 predefined training fixtures from `v5_suite.py`. Individual and all-module buttons execute Python fixture comparisons on the Render server and provide downloadable synthetic JSON reports. There are **no arbitrary URL scans, user accounts, API secrets, or persistent customer data**.

## Install into the existing GitHub repository

Copy `render_live.py`, `requirements-render.txt`, and the `render-live/` directory into the root of `cabralisjota/web-security-workbench`, alongside `v5_suite.py` and `render-showcase/`.

Local check (from repository root):

```bash
python -m pip install -r requirements-render.txt
python -m unittest discover -s render-live -p 'test_*.py' -v
python render_live.py
```

Open `http://127.0.0.1:18772/` and try a module or Run All.

## Deploy as a new Render Web Service

Keep the current **Static Site** intact. In Render select **New → Web Service**, choose the same GitHub repository and `main` branch, and set:

- Runtime: **Python**
- Root directory: **blank** (repository root)
- Build command: `pip install -r requirements-render.txt`
- Start command: `gunicorn --workers 1 --threads 4 --bind 0.0.0.0:$PORT render_live:app`
- Environment variables: **none required** for this demo

Use the newly generated `*.onrender.com` URL. This cannot be deployed on the existing static-only service without creating a Web Service. You can later link the old showcase to the new live demo.

## Security boundaries

The training comparisons are in-memory functions; they do not send payloads to external sites, expose vulnerable HTTP fixtures, or execute untrusted input. The dashboard map and original showcase metrics remain fictional. This is not production customer monitoring, a vulnerability scanner for arbitrary targets, or a hardened multi-tenant SaaS. Do not expose the original local `monitor_portal.py` to the public internet without a separate security review and hardening effort.
