# Web Security Workbench v3.1 — Gemini SQLi Copilot

Adds **Google Gemini AI** to the local SQL injection training dashboard at `http://127.0.0.1:18770/`. This upgrade **does not replace** your existing training lab, Workbench, Academy, or baseline scanner. It works without an AI key for local tests and rule-based guidance.

## Install in Android Termux

1. Download `web-security-workbench-v3.1.zip` to Android Downloads.
2. Paste **this entire block** into Termux (the `-j` flag flattens the ZIP to prevent the nested-directory error in the previous release):

```bash
pkg install -y unzip tmux
mkdir -p "$HOME/web-security-workbench-v3.1-install"
unzip -o -j "$HOME/storage/downloads/web-security-workbench-v3.1.zip" -d "$HOME/web-security-workbench-v3.1-install"
bash "$HOME/web-security-workbench-v3.1-install/install.sh"
```

3. Open `http://127.0.0.1:18770/`. The SQLi training lab must also be running on port 18766 to use **Run SQLi lab tests**.

## Connect Gemini (free tier if eligible)

1. Visit **https://aistudio.google.com/apikey** and create a Gemini API key. A Google account is needed. Check free-tier model availability and quotas in AI Studio.
2. In Termux:

```bash
cd "$HOME/web-app-pentest"
bash configure_ai.sh
```

3. Paste the key when asked (the terminal hides it). **Do not paste your key into ChatGPT or the dashboard.**
4. Refresh `http://127.0.0.1:18770/` and press **Test Gemini connection**. A real AI response confirms connectivity.
5. Try **Ask AI** with a fictional SQLi lab question. To compare vulnerable and fixed behavior, switch the training lab's mode separately.

**Default model:** `gemini-3.5-flash-lite`. The free tier has rate limits and may not be available for every account/project. Google says free-tier prompts may be used to improve its products. **Do not send confidential client data, customer records, secrets, or private source code.** For a commercial release, migrate to an appropriate paid/enterprise service with suitable contractual data protections.

## What this actually does

- Four local-only, bounded SQLi requests to the intentionally vulnerable `127.0.0.1:18766` training endpoint.
- JSON/HTML lab evidence reports and deterministic explanations without AI.
- Gemini AI explanations of synthetic lab indicators, optional AI Q&A, and review of user-supplied redacted observations.
- No autonomous external attacks, SQL data extraction, or commands generated and executed by AI.
- The API key is stored only in `.copilot.env` with file mode 0600; `.gitignore` excludes it. The app binds to localhost only.
- A backup of the prior `sqli_copilot.py` is saved as `sqli_copilot.py.before_gemini_v31`.

## Troubleshooting

```bash
cd "$HOME/web-app-pentest"
python -m unittest -v test_copilot.py
tmux ls
tmux attach -t sqli-copilot
```

To detach from tmux, press Ctrl+B then D. If Google returns HTTP 403, your project may not have free-tier access; HTTP 429 indicates a quota limit. The dashboard's **Test Gemini connection** is a live API test, while the included unit tests use mocked responses and never contact Google.

## Commercial readiness

See `PRODUCT_READINESS.md`. This is a **local demonstration prototype**, not yet a validated client-facing penetration-testing service or a finished product ready to sell to an enterprise. Additional security, authorization controls, independent testing, deployment, documentation, and IP review are required.
