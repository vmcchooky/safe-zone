# Gemini Handoff - Safe Zone on `quorix.io.vn`

Date: 2026-05-25

You are helping me finish the initial VPS deployment for the Safe Zone project.

## Current situation

- The project already has a VPS.
- The main website `quorix.io.vn` is a Hugo site currently hosted on Vercel.
- DNS is managed at PA Viet Nam.
- I have not created any Safe Zone subdomain yet.
- The deployment must not break the existing root site.

## Hard requirements

- Keep `quorix.io.vn` and `www.quorix.io.vn` on Vercel.
- Use a separate subdomain for Safe Zone, preferably `safe.quorix.io.vn`.
- Treat the VPS as a single-node deployment target.
- Assume Ubuntu 24.04 LTS unless another OS is explicitly provided.
- Use Docker and Docker Compose for the deployment.
- Public surface should be `80/tcp`, `443/tcp`, and `853/tcp`, plus SSH on `22/tcp`.
- Internal app ports should stay loopback-only.

## What I need from you

Give me a practical step-by-step deployment plan for the current state, starting from the VPS already being available.

The plan should cover:

1. First VPS setup and basic hardening.
2. Docker / Compose installation.
3. Which repo files I should use first.
4. What env vars and secrets I must prepare.
5. Exactly what DNS record to add in PA Viet Nam for the Safe Zone subdomain.
6. How to deploy the stack.
7. How to verify the deployment is working.
8. Any rollback or recovery notes I should keep.

## Important domain notes

- Do not change the root `quorix.io.vn` records unless I explicitly ask to move the website away from Vercel.
- The Safe Zone service should live on a subdomain only.
- The expected target hostname is `safe.quorix.io.vn`.

## Repo files that already exist

Use these as the source of truth:

- `README.md`
- `docs/deployment/quorix-io-vn-step-by-step.md`
- `docs/deployment/safe-zone-free-tier-deploy-guide-vi.md`
- `docs/runbooks/production-edge.md`
- `docker-compose.yml`
- `docker-compose.production.yml`
- `Caddyfile`
- `.env.example`
- `ops/secrets/README.md`
- `ops/cron/safe-zone.cron.example`
- `scripts/safe-zone.ps1`
- `scripts/safe-zone.sh`

## Current deployment assumptions

- I want the initial deployment to be as close to production as possible.
- I want the answer to be specific, not generic.
- If something is missing, tell me exactly what is missing and what value I need to provide.
- Prefer safe defaults and do not assume I want to move the whole domain away from Vercel.

## Output format I want from you

Please answer in this order:

1. Short summary of the recommended setup.
2. Exact DNS record(s) to add in PA Viet Nam.
3. Exact VPS setup commands.
4. Exact deployment commands.
5. Exact verification commands.
6. Common mistakes to avoid.

If there are multiple deployment paths, recommend the safest one for a first production-style test and explain why briefly.
