# Web Security Workbench v4 — Small Business Security Monitor

This is a **local prototype**, not a production SaaS product. It adds a customer-facing monitoring dashboard to your existing v1/v2/v3.1 projects without replacing them. Runs on Android Termux with Python's standard library.

## Install on your phone

1. Download `web-security-workbench-v4.zip` into Android Downloads.
2. Paste the following in Termux:

```bash
pkg install -y unzip tmux
mkdir -p "$HOME/workbench-v4-install"
unzip -o -j "$HOME/storage/downloads/web-security-workbench-v4.zip" -d "$HOME/workbench-v4-install"
bash "$HOME/workbench-v4-install/install.sh"
```

3. Open **http://127.0.0.1:18771/**. Create a local account (use a unique password). Select **Create demo website**, then **Run checkup now** to see a sample report. The demo never makes network requests.
4. Visit **Reports & settings** to choose **daily**, **weekly** or **monthly** updates, a time zone, local delivery hour, and whether to receive email checkups and urgent website-unavailable alerts.

## Reuse Gemini from v3.1

The installer loads your existing `~/web-app-pentest/.copilot.env` file when starting the new server. If Gemini was connected to v3.1, the new monitor should also use it automatically. **Only controlled finding titles and severities are sent to Gemini**; no customer domain, page content, secrets, credentials, cookies, or account details. When the API is unavailable, the monitor uses a clearly labeled rule-based summary. Google free-tier data-use terms may not be suitable for client data; this prototype intentionally avoids submitting client-identifying information.

## Optional: configure real email delivery

```bash
cd ~/web-app-pentest
bash configure_notifications.sh
```

You'll be asked for an SMTP server, TLS port (465 or 587), SMTP username, SMTP password/app password (hidden input), and sender address. You must provide an email delivery service/account. For personal Gmail, an eligible account generally needs 2-step verification and an app password. For a commercial product, use a transactional email provider and manage credentials on the server.

Once configured, open a website's **Reports & settings** and press **Send test email**. The account's email address is the recipient. Scheduled checks automatically email a digest when enabled; urgent emails are sent if a previously reachable/verified website becomes unavailable or loses verification. **An SMTP submission is not proof of inbox delivery.** If SMTP isn't configured, reports are still saved in the portal and notification history says `not-configured`.

## Verify ownership before checking a real site

1. Add a domain, such as `shop.yourbusiness.com` (hostname only, not a URL).
2. The dashboard shows a randomly generated verification string.
3. Publish it exactly at `https://your-domain/.well-known/security-workbench-verification.txt`.
4. Press **Verify ownership**. The app only sends requests to a public HTTPS host, pinned to a DNS-verified public IP; it blocks private IPs, uses TLS certificate validation, and never follows redirects.
5. Run a manual check or wait for the scheduled check. The app rechecks the proof file before each assessment.

**What is tested:** HTTP response status, selected response headers, cookie flags, TLS certificate expiration, and reachability. These are *low-impact baseline checks only*. **It does not scan for SQL injection or other exploitable vulnerabilities on external websites.** Your v3.1 SQLi lab remains separate on port 18770.

## Limitations and safety

- The dashboard binds to `127.0.0.1` only; **do not expose port 18771 or forward it to the public internet**. It uses local sign-up with no email verification, password recovery, MFA, subscription billing, tenancy hardening, or formal privacy/legal controls.
- Email delivery and scheduling work only **while the Termux process is running and Android permits background activity**. Android can suspend or kill the app. For reliable daily/weekly customer delivery, move the service to an always-on hosted environment with a durable job queue, retry logic, observability, and delivery tracking.
- The prototype uses SQLite with private filesystem permissions, password hashing, session expiration, CSRF tokens, same-site cookies, per-user record isolation, and safe URL/host restrictions. It has **not** undergone independent security review.
- Urgent alerts currently mean availability or verification loss, **not confirmed critical security vulnerabilities**. Baseline findings should not be presented as proof that the website is secure.
- AI summaries can be wrong; the evidence-based rule output remains the fallback.
- No SMS, Stripe billing, automatic website repairs, real client SQLi scanning, or public multi-tenant deployment is included.

## Useful commands

```bash
# Check running apps
tmux ls
# View server log (Ctrl+B, D to detach)
tmux attach -t customer-monitor
# Run offline tests
cd ~/web-app-pentest && python -m unittest -v test_monitor.py
# Start the app again if Termux was closed
tmux new-session -d -s customer-monitor "cd ~/web-app-pentest && bash -c 'set -a; [ -f .copilot.env ] && . .copilot.env; [ -f .monitor.env ] && . .monitor.env; set +a; exec python -u monitor_portal.py'"
```

## Next milestones before selling

1. Hosted authentication, verified email, MFA, account recovery, tenant isolation and abuse protection.
2. Real job queue, retry/backoff, audit logs, SMTP delivery tracking and operational monitoring.
3. Validated detection engine for authorized client staging sites, measured against independent benchmark applications.
4. Privacy terms, contracts, data retention/deletion, encryption, independent pentest, security incident process.
5. Customer onboarding, billing, cancellation, support, and product differentiation versus FortiDAST and competing SMB scanners.
