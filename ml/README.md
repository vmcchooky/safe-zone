# Safe Zone ML Package

The `ml/` package contains the reproducible training artifacts, feature contract, model bundle, and verification tools for Safe Zone Custom Domain ML. The Go runtime is documented in [the canonical AI Engine plan](../docs/specs/safe-zone-ai-plan.md); this file is the local ML operator/developer guide.

## Current status

Phase 0–4 implementation evidence is present in the repository. The v1 runtime bundle is loaded by Go through `leaves` and is safe to deploy in `disabled`, `shadow`, or `enforce` mode. Private artifact provisioning, read-only mounts, staging shadow observation, and rollback mechanics have been validated; production remains `disabled` by default until human-labelled evidence, canary approval, and product/security rollout gates are complete.

The v1 contract contains 534 ordered features:

- 22 handcrafted lexical, PSL, IDN, hosting, and brand features;
- 512 character TF-IDF features using the frozen vocabulary and learned `idf_by_index` values.

The bundle at `ml/models/v1/` contains the LightGBM text model, `feature_manifest.v1.json`, Platt calibration, policy, model report, and `SHA256SUMS`. Raw/processed datasets and derived matrices remain outside the Git commit policy; `ml/data/data_manifest.json` records non-sensitive provenance and checksums.

An R&D-only v2 candidate is configured by
`ml/configs/v2-suffix-debiased-hard-negatives.json`. It removes the complete
public suffix from TF-IDF input, uses bounded provenance-aware weights for
benign hard negatives, and excludes the owner-reviewed false-positive groups
from every model partition. Generated matrices and the candidate bundle remain
under the Git-ignored `ml/data/derived/v2-suffix-debiased-hard-negatives/`
directory. The candidate is not provisioned to staging and does not authorize
`enforce`; see
`docs/research/ml/suffix-debiased-hard-negative-candidate.md` for metrics,
reviewed stale-domain exclusions, and the representative recall regression
that currently blocks staging restart.

## Runtime configuration

```env
SAFE_ZONE_ML_MODE=disabled
SAFE_ZONE_ML_BUNDLE_HOST_DIR=./deploy/model-bundle/current
SAFE_ZONE_ML_BUNDLE_DIR=/app/models/safe-zone/current
SAFE_ZONE_ML_REQUIRED=false
SAFE_ZONE_ML_BLOCK_THRESHOLD=
```

| Mode | Behavior |
|---|---|
| `disabled` | Do not load or call the classifier; preserve the previous risk flow. |
| `shadow` | Classify lexical `SUSPICIOUS` candidates and expose aggregate prediction evidence, but never change the verdict. |
| `enforce` | Promote only calibrated high-risk `SUSPICIOUS` candidates to `MALICIOUS`; abstentions continue to the existing LLM path. |

`SAFE_ZONE_ML_REQUIRED=true` converts bundle loading errors into a startup failure. Otherwise, a missing or invalid bundle keeps the requested `shadow` mode visible as `degraded` and keeps the deterministic analyzer available. Threshold overrides must be in `(0,1)` and are included in the model-aware cache revision.

## Phase 5 provisioning and shadow

The host-side release root is `deploy/model-bundle/`; versioned bundles are
ignored by Git. The provisioner validates all five runtime files against
`SHA256SUMS` before activating `current` and makes the release files
read-only:

```powershell
$env:SAFE_ZONE_ML_BUNDLE_SOURCE = 'C:\secure-artifacts\safe-zone-domain-v1'
$env:SAFE_ZONE_ML_BUNDLE_VERSION = 'v1'
mise run ops:ml-provision
mise run ops:ml-validate
```

For a controlled shadow run, set `SAFE_ZONE_ML_MODE=shadow` and preferably
`SAFE_ZONE_ML_REQUIRED=true`. The `/v1/status` and `/metrics` responses from
`core-api`, plus `/` and `/metrics` from `dns-resolver`, expose the same model
version/revision, readiness state, would-pass/would-block counts, probability
histogram, abstains/errors, and latency histogram. No shadow metric changes a
verdict.

## Reproducibility and validation

The pipeline must fail rather than produce an unlinked split manifest when `ml/data/data_manifest.json` is missing. The artifact validator also checks that `split_manifest.json.input_data_manifest_hash` matches the manifest digest.

```powershell
python -B ml/src/validate_artifacts.py
go test ./...
go test -race ./internal/analysis ./internal/risk
go vet ./...
```

Candidate v2 reproduction uses an explicit derived root:

```powershell
python -B ml/src/build_features.py --config ml/configs/v2-suffix-debiased-hard-negatives.json --num-workers 8
python -B ml/src/validate_artifacts.py --derived-dir ml/data/derived/v2-suffix-debiased-hard-negatives
python -B ml/src/train_lightgbm.py --config ml/configs/v2-suffix-debiased-hard-negatives.json
python -B ml/src/calibrate_model.py --config ml/configs/v2-suffix-debiased-hard-negatives.json
python -B ml/src/evaluate_model.py --config ml/configs/v2-suffix-debiased-hard-negatives.json
python -B ml/src/export_artifacts.py --config ml/configs/v2-suffix-debiased-hard-negatives.json
```

The current local evidence is:

- artifact validation: 49/49 checks passed for v1 and 33/33 for the v2 candidate;
- data provenance: 15/15 raw/processed file hashes matched;
- Go unit/integration tests: passed;
- Go race tests for analysis and risk: passed;
- model bundle `SHA256SUMS`: all entries matched using canonical LF text hashing, so Windows CRLF and Linux LF checkouts produce the same bundle revision.

## Artifact layout

```text
ml/
├── configs/v1.json
├── contracts/                         # frozen feature and analysis snapshots
├── data/data_manifest.json            # tracked provenance metadata only
├── data/derived/                      # local, ignored datasets/matrices
├── evidence/                          # tracked, checksum-gated release evidence
├── models/v1/                         # immutable v1 bundle
├── src/                               # pipeline and validation scripts
└── tests/fixtures/golden_vectors.v1.json
```

For release gates, rollout stages, privacy constraints, and incident response, use `docs/specs/safe-zone-ai-plan.md` and `docs/production-completion-checklist.md` rather than creating a parallel ML deployment contract.
