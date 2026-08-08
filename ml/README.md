# Safe Zone ML Package

The `ml/` package contains the reproducible training artifacts, feature contract, model bundle, and verification tools for Safe Zone Custom Domain ML. The Go runtime is documented in [the canonical AI Engine plan](../docs/specs/safe-zone-ai-plan.md); this file is the local ML operator/developer guide.

## Current status

Phase 0–4 implementation evidence is present in the repository. The v1 runtime bundle is loaded by Go through `leaves` and is safe to deploy in `disabled`, `shadow`, or `enforce` mode. Production remains `disabled` by default until Phase 5 private artifact provisioning, read-only mounts, shadow evidence, canary approval, and rollback drills are complete.

The v1 contract contains 534 ordered features:

- 22 handcrafted lexical, PSL, IDN, hosting, and brand features;
- 512 character TF-IDF features using the frozen vocabulary and learned `idf_by_index` values.

The bundle at `ml/models/v1/` contains the LightGBM text model, `feature_manifest.v1.json`, Platt calibration, policy, model report, and `SHA256SUMS`. Raw/processed datasets and derived matrices remain outside the Git commit policy; `ml/data/data_manifest.json` records non-sensitive provenance and checksums.

## Runtime configuration

```env
SAFE_ZONE_ML_MODE=disabled
SAFE_ZONE_ML_BUNDLE_DIR=/app/models/safe-zone/current
SAFE_ZONE_ML_REQUIRED=false
SAFE_ZONE_ML_BLOCK_THRESHOLD=
```

| Mode | Behavior |
|---|---|
| `disabled` | Do not load or call the classifier; preserve the previous risk flow. |
| `shadow` | Classify lexical `SUSPICIOUS` candidates and expose telemetry, but never change the verdict. |
| `enforce` | Promote only calibrated high-risk `SUSPICIOUS` candidates to `MALICIOUS`; abstentions continue to the existing LLM path. |

`SAFE_ZONE_ML_REQUIRED=true` converts bundle loading errors into a startup failure. Otherwise, missing or invalid bundles disable ML and keep the deterministic analyzer available. Threshold overrides must be in `(0,1)` and are included in the model-aware cache revision.

## Reproducibility and validation

The pipeline must fail rather than produce an unlinked split manifest when `ml/data/data_manifest.json` is missing. The artifact validator also checks that `split_manifest.json.input_data_manifest_hash` matches the manifest digest.

```powershell
python -B ml/src/validate_artifacts.py
go test ./...
go test -race ./internal/analysis ./internal/risk
go vet ./...
```

The current local evidence is:

- artifact validation: 41/41 checks passed;
- data provenance: 15/15 raw/processed file hashes matched;
- Go unit/integration tests: passed;
- Go race tests for analysis and risk: passed;
- model bundle `SHA256SUMS`: all entries matched.

## Artifact layout

```text
ml/
├── configs/v1.json
├── contracts/                         # frozen feature and analysis snapshots
├── data/data_manifest.json            # tracked provenance metadata only
├── data/derived/                      # local, ignored datasets/matrices
├── models/v1/                         # immutable v1 bundle
├── src/                               # pipeline and validation scripts
└── tests/fixtures/golden_vectors.v1.json
```

For release gates, rollout stages, privacy constraints, and incident response, use `docs/specs/safe-zone-ai-plan.md` and `docs/production-completion-checklist.md` rather than creating a parallel ML deployment contract.
