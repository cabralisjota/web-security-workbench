#!/data/data/com.termux/files/usr/bin/bash
set -euo pipefail
APP="$HOME/web-app-pentest"
mkdir -p "$APP"
cd "$APP"
umask 077
printf 'Configure SMTP email delivery (optional).\n'
printf 'SMTP host [smtp.gmail.com]: '
IFS= read -r SMTP_HOST
SMTP_HOST="${SMTP_HOST:-smtp.gmail.com}"
printf 'SMTP port [465] (465 SSL / 587 STARTTLS): '
IFS= read -r SMTP_PORT
SMTP_PORT="${SMTP_PORT:-465}"
case "$SMTP_PORT" in 465|587) ;; *) echo 'Port must be 465 or 587'; exit 1 ;; esac
printf 'SMTP username: '
IFS= read -r SMTP_USER
printf 'SMTP app password (hidden): '
IFS= read -rs SMTP_PASSWORD
printf '\nSender email: '
IFS= read -r SMTP_FROM
if [[ "$SMTP_HOST" != *.* || "$SMTP_HOST" == *[[:space:]/:]* || "$SMTP_FROM" != *@*.* || "$SMTP_FROM" == *[[:space:]]* ]]; then
  echo 'Invalid SMTP settings. No changes made.'; exit 1
fi
{
  printf 'export SMTP_HOST=%q\n' "$SMTP_HOST"
  printf 'export SMTP_PORT=%q\n' "$SMTP_PORT"
  printf 'export SMTP_USER=%q\n' "$SMTP_USER"
  printf 'export SMTP_PASSWORD=%q\n' "$SMTP_PASSWORD"
  printf 'export SMTP_FROM=%q\n' "$SMTP_FROM"
} > .monitor.env
chmod 600 .monitor.env
unset SMTP_PASSWORD
if ! grep -qxF '.monitor.env' .gitignore 2>/dev/null; then printf '\n.monitor.env\n' >> .gitignore; fi
bash "$APP/start_v5.sh"
echo 'SMTP configuration saved. Sign in to a real account and use Send test email.'
