# Render deployment: public showcase

This folder deploys a **static, interactive showcase**, not the localhost-only customer portal. It uses fictional traffic and security results and does not perform real scanning, accept credentials, or connect to Gemini.

## Publish from Termux

After downloading and extracting the ZIP, run `bash install_render_showcase.sh`. This clones `cabralisjota/web-security-workbench` into a temporary directory, adds `render-showcase/index.html`, `render.yaml`, and this guide, and pushes the commit to `main`. It does not alter the working Termux application.

## Deploy on Render

1. Sign in at https://dashboard.render.com/ and connect your GitHub account.
2. Choose **New > Static Site**.
3. Select the `cabralisjota/web-security-workbench` repository and branch `main`.
4. Set **Build Command** to `echo "Static showcase ready"`.
5. Set **Publish Directory** to `render-showcase` (relative to the repository root).
6. Choose a name such as `web-security-workbench-showcase`, then create the site.
7. Open the generated `*.onrender.com` URL after the deploy succeeds.

Alternatively, use **New > Blueprint** to deploy from the repository's `render.yaml` file.

## Security and limitations

- Do not set `GEMINI_API_KEY`, SMTP passwords, or other credentials for this static showcase. It has no server-side AI calls.
- The 17 listed modules are **local training checks in the original Termux application**, not scans run by the public showcase.
- The world map, metrics, and training results displayed here are synthetic examples.
- The original `monitor_portal.py` binds to `127.0.0.1:18771`, uses local SQLite, and is not ready to deploy directly as a public customer portal.
- Production deployment requires secure account management, durable customer data, tenant isolation, review of authorization and CSRF behavior behind a reverse proxy, robust logging, background jobs, and independent security testing.
