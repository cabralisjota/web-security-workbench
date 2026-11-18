#!/data/data/com.termux/files/usr/bin/bash
set -euo pipefail
APP="$HOME/web-app-pentest"
mkdir -p "$APP"
cd "$APP"
umask 077
printf 'Gemini API key (input hidden; leave blank to cancel): '
IFS= read -rs KEY
printf '\n'
if [ -z "$KEY" ]; then echo 'No changes made.'; exit 0; fi
printf 'export GEMINI_API_KEY=%q\n' "$KEY" > .v5.env
printf 'export GEMINI_MODEL=%q\n' 'gemini-3.5-flash-lite' >> .v5.env
chmod 600 .v5.env
unset KEY
if ! grep -qxF '.v5.env' .gitignore 2>/dev/null; then printf '\n.v5.env\n' >> .gitignore; fi
bash "$APP/start_v5.sh"
echo 'Gemini configuration saved privately. Free-tier requests may be used by Google to improve services.'
echo 'Only synthetic lab labels and redacted configuration observations are sent to Gemini.'
