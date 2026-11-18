#!/data/data/com.termux/files/usr/bin/bash
set -euo pipefail
cd "$HOME/web-app-pentest" || exit 1
umask 077
printf 'Paste your Google Gemini API key (hidden input): '
IFS= read -rs KEY
printf '\n'
if [ -z "$KEY" ]; then
  echo 'No key entered. Nothing changed.'
  exit 1
fi
# Only shell-escaped values go into the environment file.
printf 'export GEMINI_API_KEY=%q\n' "$KEY" > .copilot.env
printf 'export GEMINI_MODEL=%q\n' 'gemini-3.5-flash-lite' >> .copilot.env
chmod 600 .copilot.env
unset KEY
if ! grep -qxF '.copilot.env' .gitignore 2>/dev/null; then
  printf '\n.copilot.env\n' >> .gitignore
fi
if command -v tmux >/dev/null 2>&1; then
  tmux kill-session -t sqli-copilot 2>/dev/null || true
  tmux new-session -d -s sqli-copilot "cd '$HOME/web-app-pentest' && bash -c 'source .copilot.env; exec python -u sqli_copilot.py'"
fi
echo 'Gemini key stored privately; SQLi Copilot restarted.'
echo 'Open http://127.0.0.1:18770/ and press Test Gemini connection.'
echo 'Free tier may use prompts to improve Google products. Never upload confidential client data.'
echo 'Do not share this key or commit .copilot.env to GitHub.'
