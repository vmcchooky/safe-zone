# Private ML bundle mount

This directory is the default host-side root for Phase 5 model provisioning.
The actual versioned bundles are intentionally ignored by Git. Provision one
with the repository helper, which validates every runtime file against
`SHA256SUMS` before activation:

```powershell
mise run ops:ml-provision
mise run ops:ml-validate
```

For production, set `SAFE_ZONE_ML_BUNDLE_SOURCE` to the approved private
artifact directory (or copy the verified artifact there) before provisioning.
The active `current` link is mounted read-only into both `core-api` and
`dns-resolver`. The runtime still defaults to `SAFE_ZONE_ML_MODE=disabled`.

To collect shadow evidence after approval:

```text
SAFE_ZONE_ML_MODE=shadow
SAFE_ZONE_ML_REQUIRED=true
SAFE_ZONE_ML_BUNDLE_HOST_DIR=./deploy/model-bundle/current
SAFE_ZONE_ML_BUNDLE_DIR=/app/models/safe-zone/current
SAFE_ZONE_ML_CANARY_PERCENT=10
SAFE_ZONE_ML_CANARY_SEED=<stable-observation-window-seed>
```

The selector only records cohort telemetry in `shadow`. `enforce` requires a
non-zero percentage and stable seed, and it promotes only selected normalized
domains. A production percentage/seed must come from the approved canary
packet; the values above are an observation example, not approval.

Do not place secrets, raw domains, training data, or unverified model files in
this directory.
