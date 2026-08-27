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

The leakage-free comparison is configured by
`ml/configs/v2-leakage-free-control.json` and
`ml/configs/v3-leakage-free-context.json`. It excludes the 137-case reviewed
packet from every partition and groups shared-hosting cases by tenant instead
of excluding an entire provider. Candidate v3 keeps the 534-feature shape and
adds bounded snapshot entries for three risk keywords, Spotify, and three
shared-hosting providers. Both controls pass 35/35 artifact checks, but v3
reaches only 22/34 representative malicious true positives at threshold 0.92;
the documented gate is 26/34. The v3 bundle therefore remains private and must
not be provisioned or used to restart local staging. See
`docs/research/ml/representative-false-negative-analysis.md` for the A/B and
ablation results.

The pre-registered v4 research round is configured by
`ml/configs/v4-time-forward-protocol.json`,
`ml/configs/v3-time-forward-data.json`, and
`ml/configs/v4-time-forward-ternary-tld.json`. It freezes checksum-pinned
PhishTank adaptation/development cohorts and a source-disjoint OpenPhish final
holdout before training. Six family/weight combinations selected v4 ternary
TLD state with hard-positive weight `1.5`, but the one-time final evaluation
kept representative malicious recall at `22/34` and produced `1/1,400` SAFE VN
runtime-candidate false positive. The candidate is private `NO-GO`; its model
must not be exported, provisioned, or used to restart staging. Aggregate
selection/final evidence is tracked in
`ml/experiments/v4-weight-ablation-selection.json` and
`ml/experiments/v4-final-evaluation.json`.

The checksum-pinned production-free context evaluation joins the selected v4
predictions with fresh URLhaus Recent and OpenPhish Community snapshots using
the same parser and exact/parent-suffix matcher as the Go runtime. It recovered
`0/12` model false negatives and introduced one representative benign hostname
collision, so it is measurement evidence rather than a release path. The local
whitelist state was empty and the configured Tranco snapshot endpoint was
unavailable; the report records that limitation explicitly.

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

URL-aware analysis is a separate core-API-only specialist. `POST /v1/analyze`
may include `requested_url` and a caller-observed `redirect_chain`; the service
never fetches those URLs. It defaults to disabled and currently supports
shadow observation only:

```env
SAFE_ZONE_URL_ML_MODE=disabled
SAFE_ZONE_URL_ML_BUNDLE_DIR=/app/models/safe-zone/url-v1
SAFE_ZONE_URL_ML_REQUIRED=false
SAFE_ZONE_URL_ML_SHADOW_PERCENT=100
SAFE_ZONE_URL_ML_SHADOW_SEED=
```

Invalid, oversized, credential-bearing, or host-mismatched URL context fails
open to the unchanged domain-only result. Raw URL and query values are not
returned or stored in URL ML observation telemetry. Shadow metrics include
stable traffic sampling, probability/input/verdict histograms, error classes,
latency and diagnostic PSI against the bundled offline proxy. Partial shadow
percentages require a seed. The proxy is not an operational drift baseline.

Replay and rollback verification:

```powershell
python ml/src/replay_v10_url_shadow.py --base-url http://127.0.0.1:8080 --workers 12
python ml/src/check_v10_url_rollback.py --base-url http://127.0.0.1:8080
```

Both reports contain aggregate evidence only. See
`docs/runbooks/url-ml-shadow-rollout.md` for rollout gates and alerts.

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

Leakage-free control/v3 research uses the same sequence with the corresponding
config. Do not run `export_artifacts.py` for v3 while its model-quality gate is
`NO-GO`:

```powershell
python -B ml/src/build_features.py --config ml/configs/v2-leakage-free-control.json --num-workers 8
python -B ml/src/validate_artifacts.py --derived-dir ml/data/derived/v2-leakage-free-control
python -B ml/src/train_lightgbm.py --config ml/configs/v2-leakage-free-control.json
python -B ml/src/calibrate_model.py --config ml/configs/v2-leakage-free-control.json
python -B ml/src/evaluate_model.py --config ml/configs/v2-leakage-free-control.json

python -B ml/src/build_features.py --config ml/configs/v3-leakage-free-context.json --num-workers 8
python -B ml/src/validate_artifacts.py --derived-dir ml/data/derived/v3-leakage-free-context
python -B ml/src/train_lightgbm.py --config ml/configs/v3-leakage-free-context.json
python -B ml/src/calibrate_model.py --config ml/configs/v3-leakage-free-context.json
python -B ml/src/evaluate_model.py --config ml/configs/v3-leakage-free-context.json
```

The v4 negative-result reproduction keeps the raw feed snapshots and Parquet
cohorts under Git-ignored `ml/data/derived/` while tracking their checksums:

```powershell
python -B ml/src/build_time_forward_snapshot.py --config ml/configs/v4-time-forward-protocol.json
python -B ml/src/build_features.py --config ml/configs/v3-time-forward-data.json --num-workers 8
python -B ml/src/validate_artifacts.py --derived-dir ml/data/derived/v3-time-forward-data
python -B ml/src/build_tld_state_ablation.py --source-derived-dir ml/data/derived/v3-time-forward-data --config ml/configs/v4-time-forward-ternary-tld.json
python -B ml/src/validate_artifacts.py --derived-dir ml/data/derived/v4-time-forward-ternary-tld
python -B ml/src/select_time_forward_candidate.py --protocol ml/configs/v4-time-forward-protocol.json
python -B ml/src/evaluate_model.py --config ml/configs/v4-time-forward-ternary-tld.json
python -B ml/src/evaluate_time_forward_candidate.py --config ml/configs/v4-time-forward-ternary-tld.json --protocol ml/configs/v4-time-forward-protocol.json
```

After collecting the checksum-pinned raw feed snapshots, reproduce the bounded
context join without Redis or a running service:

```powershell
python -B ml/src/evaluate_time_forward_candidate.py --config ml/configs/v4-time-forward-ternary-tld.json --protocol ml/configs/v4-time-forward-protocol.json --prediction-output ml/data/derived/threat-context-20260824/v4-representative-predictions.jsonl
go run ./cmd/threat-context-eval --config ml/configs/threat-context-production-free-20260824.json --output ml/experiments/threat-context-production-free-20260824.json
```

The current local evidence is:

- artifact validation: 49/49 checks passed for v1 and 33/33 for the v2 candidate;
- leakage-free artifact validation: 35/35 for both v2 control and v3 candidate, with identical four partition hashes, feature order, and IDF values;
- data provenance: 15/15 raw/processed file hashes matched;
- Go unit/integration tests: passed;
- Go race tests for analysis and risk: passed;
- model bundle `SHA256SUMS`: all entries matched using canonical LF text hashing, so Windows CRLF and Linux LF checkouts produce the same bundle revision.

## URL-aware canary tooling (Vòng 4)

Round-4 adds the operational tooling for the V10 URL shadow canary
(`ml/src/`):

- `canary_scope.py` — seeded scope stepper (1% → 5% → 10%). Writes a literal
  Compose override (`docker-compose.canary.yml`, via `canary_override.py`)
  so shell env vars cannot defeat the intended scope; appends every change
  with selector/policy revisions to `ml/experiments/v10-url-canary-scope-changes.json`.
- `canary_snapshot_delta.py` — observation-window collector. All metrics are
  start/end deltas of `/v1/status` (never cumulative); records workers,
  concurrency, duration, request counts, exact + round-half-up rates,
  histogram deltas and container CPU/RSS. Aggregate-only.
- `freeze_url_canary_baseline.py` — freezes the live canary probability
  histogram into an operational drift baseline artifact
  (`ml/models/url-baseline/operational-baseline.json`); loaded by core-api
  via `SAFE_ZONE_URL_ML_BASELINE_PATH`, strictly fail-open.
- `canary_failure_injection.py` — missing/corrupt baseline fail-open,
  malformed-context rejection (cohort-aware probe domains), restart with
  valid baseline.
- `run_external_pilot.py` (Round 5) — gated external pilot windows: verifies
  shadow-only runtime, records snapshot-delta evidence, evaluates the
  observable promotion gates and only then advances the seeded scope;
  refuses `--drive-count` with `--traffic-kind external` so generated
  requests can never be counted as external evidence.

Durable label feedback (Round 5): when
`SAFE_ZONE_URL_ML_FEEDBACK_SECRET` (env or `_FILE`) is injected,
fingerprints become stable HMACs keyed by version and labels persist in the
bounded `url_ml_feedback` SQLite table (TTL + row cap + dedupe + one-label
anti-replay). Persistence failures fail closed for feedback alone (HTTP 503)
and never touch analysis.

Error-path correlation (fix in `c3314a8`): sampled events with caller-supplied
`event_id` are recorded synchronously before the analyze response returns even
when URL classification fails (`invalid_url_context` or `prediction_error`),
using a probability sentinel `-1` so that caller feedback is never rejected with
a spurious `unknown_event`.

Operational drift baseline note: `ml/models/url-baseline/operational-baseline.json`
is a **staging operational baseline** frozen from 34 synthetic-driven canary samples.
It is explicitly non-production; an external operational baseline can only be
frozen from live external traffic windows.

Privacy invariants: no raw URL/query/redirect target is ever persisted;
label feedback (`POST /v1/url-ml/feedback`) correlates only HMAC
fingerprints of opaque caller event IDs; calibration/FPR numbers exist only
over labelled events.

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

For canonical release status and two-gate evaluation, see `docs/deployment/release-manifest-r5.md`. For release gates, rollout stages, privacy constraints, and incident response, use `docs/specs/safe-zone-ai-plan.md` and `docs/production-completion-checklist.md` rather than creating a parallel ML deployment contract.
