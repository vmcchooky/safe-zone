# Representative replay owner-approved addendum — 2026-08-23

## Tóm tắt

Archive này lưu phần thay đổi đã được Product và Security ghi owner decision
ngày 2026-08-23. Nó là delta của `run-20260808`, không sao chép toàn bộ replay
requests/results/predictions. Base archive được khóa bằng commit và SHA-256 của
ba artifact review chính; mọi file thay đổi hoặc bổ sung nằm trong thư mục này
và được liệt kê tại `checksums.sha256`.

Trạng thái là `owner_approved_preflight_pending`. Review gate đã pass với
exact-set reviewed-unclassifiable waiver, nhưng archive không cấp quyền deploy,
restart hoặc bật `SAFE_ZONE_ML_MODE=enforce`.

## Phạm vi thay đổi

- `replay-0072` chuyển từ `unknown` sang `malicious`, outcome `true_positive`,
  dựa trên cảnh báo `Dangerous site` do reviewer cung cấp.
- Reviewed-unclassifiable waiver còn 78 case: 33 model would-block và 45
  would-pass. SHA-256 của danh sách case ID đã sort là
  `efdaa81a8fc9cb6350aff67a1e1513f4b696a71f7d11b3e8c728fcf86e6acb27`.
- FPR giữ `0/25`; malicious subset tăng lên 34 case, với 26 true positives và
  recall `0.7647`.
- Product và Security owner decisions được ghi trong `approval-packet.md` và
  `GOVERNANCE-ADDENDUM.md`.

## Provenance

Base archive:

- path: `ml/evidence/representative-replay/run-20260808/`;
- archive commit: `56f25dd970cee368be306fe3beb75959a393d285`;
- `labels.csv` SHA-256:
  `bdef87e4e775740a32713d0b471d1f37d2ff7ec62eed591f424e41498cb75d15`;
- `review-summary.json` SHA-256:
  `79131ec8ffbf97a224525914d77dd3692e8a361667b18f07fb54cefd51b3d8c9`;
- `approval-packet.md` SHA-256:
  `f2f5282dd0d2700bf7dbf0038121fd62774850cf25aa1270b4c9f4bb05ee4639`.

Reporter implementation được khóa tại ML logic commit
`847c6d582f305c99439e1293d2e28ba65606205d`; candidate head sau CI/runbook
hygiene là `2f0a9e79cf468e2b8603f709479850b629453b4a`. `manifest.json` khóa source
và test bằng SHA-256. Local CI-equivalent đã pass; GitHub Actions chưa có vì
branch chưa được push.

## Verification

Các kiểm tra đã pass trước khi tạo archive:

- label validator: 137/137, 0 error, 0 warning;
- reporter: exit `0`, chạy lặp lại byte-identical;
- Python ML suite: 34/34 tests;
- Go 1.26.7 test and build: pass;
- Go vet/race: pass; `golangci-lint` 2.12.2 config hợp lệ, 0 issue;
- `govulncheck`: 0 reachable vulnerability; `gosec`: 0 issue trong 87 file;
- UI typecheck/build pass; Playwright E2E 4/4 pass;
- ML artifact validation: 41/41 checks;
- Docker Desktop 29.4.0 đang hoạt động; `core-api` healthy/ready và
  `dns-resolver` healthy, các endpoint status/metrics trả HTTP 200;
- runtime hai service khớp mode `shadow`, state `ready`, revision, threshold và
  zero-state error counters; counters prediction đều bằng 0 nên chưa có fresh
  predictive parity/latency/probability sample sau lần start này;
- signed base artifacts: hash không đổi;
- working checksum manifest: mọi file khớp.

## Giới hạn và gate còn lại

- Owner decision là typed governance attestation, không phải detached
  cryptographic signature.
- Runtime snapshot mới đã chụp, nhưng hai image đang báo `version=dev`,
  `git_commit=unknown` và `image_tag=unreleased`; đây không phải release
  identity có thể promote.
- Telemetry sau start chưa có representative requests (`prediction_attempts=0`)
  nên latency/probability histograms chưa đủ làm fresh canary evidence.
- Local candidate commit đã có; GitHub Actions và immutable application image
  digests cho candidate chưa có.
- Chưa có canary routing object/scope đã triển khai và chưa có last-known-good
  image/config snapshot.

Không promote archive này thành deployment authorization. Deploy, restart và
`enforce` chỉ được thực hiện sau khi các gate trên pass và có xác nhận riêng.
