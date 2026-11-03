# TerraGuard on Cloudflare Pages

The site and workspace are static files (the engine runs in the browser as
WebAssembly), so they can be served from Cloudflare Pages on your own domain,
with Cloudflare Access in front if only your team should reach it. Scans still
run in each visitor's browser; nothing is uploaded.

## Build

```bash
make web                 # builds web/terraguard.wasm and copies examples and docs
```

The `web/` folder is the whole site.

## Deploy once

```bash
npx wrangler pages deploy web --project-name terraguard
```

## Deploy from CI

Copy [`pages.yml`](pages.yml) to `.github/workflows/` in your fork, add the
repository secrets `CLOUDFLARE_API_TOKEN` (scoped to "Cloudflare Pages: Edit"
on one account, with an expiry) and `CLOUDFLARE_ACCOUNT_ID`, and push. It runs
only on pushes to `main`; there is no schedule.

## Private to your team

Create a Cloudflare Access application for the Pages domain and include your
email domain or identity provider group (not `everyone`; TerraGuard's own rule
TG-CF-004 flags that).

The workspace's optional AI assistant calls the model provider from the
browser; leave it unconfigured, or point it at your own gateway, if code must
not leave your network.
