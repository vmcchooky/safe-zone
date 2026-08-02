# Kế hoạch trích xuất đặc trưng Domain ML — bản rà soát

> Trạng thái: **đã triển khai** — toàn bộ quyết định kỹ thuật trong tài liệu này đã được implement trong Phases 0–3.
> Ngày rà soát: 2026-07-31.
> Phạm vi: chuẩn bị contract, trích xuất handcrafted features + character TF-IDF, tạo dữ liệu trainable không leakage, và chứng minh Python–Go/`leaves` compatibility trước khi chạy full dataset.
> Kết quả thực hiện: xem [method.md](method.md).

## 1. Kết luận rà soát hai bản Gemini

Bản Gemini thứ hai đi đúng hướng hơn bản đầu vì đã bổ sung phase gate, frozen snapshots, dependency pinning, ablation, `leaves` spike và capacity strategy. Tuy nhiên, **chưa nên triển khai nguyên trạng** vì vẫn khóa schema quá sớm, chưa xử lý các blocker dữ liệu hiện tại và còn một số semantics không thể parity với runtime Go.

### 1.1 Các điểm đúng nên giữ

- Không train/chạy full dataset trước khi canonicalization, feature contract, Python–Go parity, `leaves` và Docker pass.
- PSL, brand, keyword và các lookup table ảnh hưởng feature phải là snapshot bất biến, có version và SHA-256.
- Không lưu ma trận dense bằng CSV.
- TF-IDF chỉ được `fit()` trên train partition.
- Phải có group-aware split, source/temporal holdout, candidate cohort và hard-case set.
- Phải benchmark handcrafted-only, TF-IDF-only và combined trước khi chọn schema/model.
- Feature order phải explicit trong contract; không dựa vào thứ tự `dict`/DataFrame/reflection.

### 1.2 Các điểm cần sửa hoặc cải tiến

| Vấn đề | Vì sao chưa ổn | Điều chỉnh trong kế hoạch này |
|---|---|---|
| Cam kết Python và Go “giống 100%” | Integer/binary có thể exact, nhưng floating point TF-IDF và prediction cần tolerance có chứng cứ. | Canonical string/index/integer phải exact; float/vector/prediction dùng tolerance khóa bằng golden test. |
| Khóa ngay `24 + 128 = 152` feature | Spec yêu cầu ablation trước khi khóa schema; một số feature có thể constant/redundant. | Dùng **candidate schema**, profile + ablation trên lite, sau đó mới freeze contract v1 và feature count. |
| `special_char_count` được giữ trong 24 feature | Với A-label FQDN hợp lệ, ký tự ngoài `[a-z0-9.-]` phải bằng 0. | Loại mặc định; chỉ giữ nếu dữ liệu chứng minh không constant và contract định nghĩa rõ pre/post-IDNA view. |
| `has_mixed_script` tính trực tiếp trên A-label | Contract đầu vào là lower-case ASCII A-label nên feature này sẽ luôn false. | Tính trên Unicode U-label view được decode bằng IDNA profile đã pin; decode lỗi thì invalid/abstain theo contract. |
| TLD risk 3 cấp `safe/neutral/suspicious` tự gán | Gọi `.vn`/`.com` “safe” là giả định chủ quan và có thể tạo bias. | Baseline v1 dùng map binary hiện có (`listed=1`, default `0`); multi-level chỉ là experiment nếu có nguồn/evidence. |
| Tách 5 cơ chế brand thành 5 feature là mặc định | Có ích nhưng vẫn phải tránh semantics khác Go, short-brand bias và official-domain false positive. | Giữ làm candidate features riêng, định nghĩa chính xác label set, skeleton, distance, short-brand rule và trusted-suffix bypass. |
| `tfidf.joblib` là artifact chính | Go không đọc `joblib`; file này không đủ cho runtime parity. | `joblib` chỉ là cache Python tùy chọn; runtime artifact phải có vocabulary/idf theo index trong manifest JSON. |
| “Xuất Parquet feature matrix” | Parquet phù hợp metadata/dense columns, không tối ưu để lưu toàn bộ sparse TF-IDF matrix. | Metadata/split dùng Parquet; sparse matrix dùng CSR `.npz` hoặc binary tương đương; đo I/O trước khi chốt. |
| Chạy feature extraction rồi mới split | Nếu vectorizer được fit trước split sẽ leakage. | Tạo cohort + split trước; chỉ fit vocabulary/IDF trên train; transform từng partition theo batch. |
| Snapshot tách ra nhưng không nêu source of truth | Copy tay từ Go sang JSON sẽ drift ngay lần sửa tiếp theo. | Mỗi semantics chỉ có một source of truth machine-readable; Python và Go cùng load/validate snapshot hoặc dùng generator có parity test. |
| Chỉ nhắc `ml/data/psl/` | Thư mục data có thể bị ignore/mất khỏi artifact; Go `x/net/publicsuffix` cũng không mặc nhiên dùng cùng file. | PSL phải là versioned contract/runtime snapshot, kèm source URL, retrieval time, license và checksum; Go phải chứng minh dùng đúng snapshot đó. |
| Chưa có performance gate cho brand distances | Full dataset × labels × 40 brands có thể là bottleneck chính. | Benchmark 10k/100k rows, profile allocations/RSS, tối ưu/caching rồi mới duyệt full run. |

## 2. Các fact đã xác minh trong repo

1. `ml/data/data_manifest.json` ghi nhận:
   - `domain_dataset.csv`: `2,772,091` file rows;
   - `domain_dataset_lite.csv`: `300,001` file rows;
   - con số này bao gồm header, tương ứng `2,772,090` và `300,000` data rows trong spec.
2. `ml/data/processed/` và `ml/data/derived/` hiện trống trong workspace, dù manifest tham chiếu các artifact processed. Phải restore/rebuild và verify checksum trước mọi run.
3. Mọi raw source trong manifest đang có `terms_review_id: "pending-review"`; release/training gate chưa thể coi là pass.
4. `.gitignore` đang ignore toàn bộ `*.py`, chỉ exception một đường dẫn cũ. Trong khi Python scripts thực tế nằm dưới `scripts/data_processing/`.
5. Repo chưa có `pyproject.toml`, lockfile hoặc requirements lock; `mise.toml` cũng chưa pin Python.
6. Canonicalization hiện đang drift:
   - dataset builder strip wildcard và `www.`, chỉ chấp nhận regex ASCII;
   - `analysis.NormalizeDomain` không strip `www.`, cho phép Unicode và chưa thực thi đầy đủ label/FQDN bounds;
   - `brand.go:getRootDomain` dùng heuristic ccTLD, không dùng pinned PSL.
7. Runtime Go hiện có 40 default brands, 15 default phishing keywords, 17 suspicious TLDs và 36 shared/CDN roots. Các con số này là snapshot hiện tại, không phải hằng số vĩnh viễn.
8. Go brand detector có short-circuit và bypass official/alt domains; nếu Python chỉ tính “minimum distance tới brand” đơn giản thì sẽ không tái tạo semantics hiện tại.
9. `create_data_manifest.py` hiện có thể bỏ qua file thiếu thay vì fail; validator chưa thực hiện đầy đủ source-policy/terms/count-drift checks mà spec yêu cầu.
10. Đường dẫn lệnh trong spec còn dùng `scripts/*.py`, trong khi file thật ở `scripts/data_processing/*.py`; implementation cần thống nhất CLI/path thay vì tạo bản sao ở hai nơi.

## 3. Nguyên tắc thiết kế

- **Một contract, hai implementation:** Python training và Go runtime cùng tuân thủ một contract versioned.
- **Không dùng network lúc build feature/train/inference:** tài nguyên ngoài chỉ được tải một lần có kiểm soát, lưu snapshot + checksum + provenance.
- **Không thay semantics theo config runtime:** model dùng frozen brand/keyword/TLD/shared-hosting snapshots trong bundle; admin config vẫn chỉ ảnh hưởng deterministic analyzer.
- **Leakage-safe by construction:** split trước mọi learned transform; final test không dùng để chọn feature, vocabulary, hyperparameter, calibration hoặc threshold.
- **Candidate-cohort first:** metric chính phải phản ánh population mà Local ML thật sự thấy: lexical verdict `SUSPICIOUS` sau các deterministic short-circuit.
- **Fail closed cho build, fail open cho runtime ML:** build/validation gặp mismatch phải non-zero; runtime model lỗi giữ deterministic `SUSPICIOUS` khi ML không required.
- **Không khóa feature vì “giống rule hiện tại”:** deterministic rule là nguồn tham khảo semantics, không phải bằng chứng feature có giá trị. Feature phải qua variance/correlation/ablation.

## 4. Các quyết định kỹ thuật đề xuất

### 4.1 Canonicalization v1

Tạo riêng ML canonicalization contract; không âm thầm tái sử dụng parser khác khi lỗi.

1. Input adapter xử lý URL/host/port/path/query/fragment/trailing dot theo bảng golden cases.
2. Wildcard chỉ được xử lý ở data-ingestion adapter; runtime ML host contract không nhận wildcard.
3. **Đề xuất giữ `www.`** trong canonical FQDN vì đây là một label thật; PSL-derived main/registrable features tự loại phần subdomain. Nếu chọn strip `www.`, phải ghi rõ và rebuild dataset theo cùng semantics.
4. Chuẩn hóa Unicode bằng một IDNA/UTS #46 profile được pin và test tương đương Python–Go; output chính là lower-case ASCII A-label.
5. Giữ thêm U-label view chỉ cho mixed-script/homoglyph features; không dùng U-label làm khóa split hoặc TF-IDF nếu contract không quy định.
6. Kiểm tra label length, FQDN length, empty labels, bare IP, invalid port và unsupported IDNA. Invalid/unsupported phải bị loại lúc build hoặc ML abstain lúc runtime.
7. Registrable domain/eTLD+1 dùng cùng frozen PSL, gồm ICANN + private section theo quyết định contract. Không dùng heuristic `getRootDomain` cho ML features.
8. Canonical output, registrable domain, main label, suffix và subdomain labels đều phải có golden corpus Python–Go.

### 4.2 PSL strategy

- Lưu snapshot versioned, ví dụ `ml/contracts/snapshots/public_suffix_list.v1.dat`, kèm `NOTICE`/license và metadata nguồn.
- Contract ghi `retrieved_at`, upstream revision nếu có, sections được dùng và SHA-256.
- Cấm auto-fetch của `tldextract` bằng cấu hình offline và test network-independent.
- Không giả định `golang.org/x/net/publicsuffix` hiện tại tự parity với file snapshot. Phase 0 phải chọn một trong hai cách và chứng minh bằng test:
  1. Go load/compile chính snapshot bundle; hoặc
  2. sinh deterministic Go table từ snapshot và xác minh hash/version.
- Bundle runtime phải mang đủ dữ liệu để feature semantics không phụ thuộc vào binary/library snapshot ngoài contract.

### 4.3 Frozen analysis semantics

Source of truth machine-readable dự kiến:

- `brands.v1.json`: name, official domain, alt domains; baseline lấy đúng 40 brand hiện tại, chưa thêm brand mới không review.
- `keywords.v1.json`: đúng 15 default keywords hiện tại.
- `tld_risk.v1.json`: baseline binary 17 TLDs, default `0`.
- `shared_hosting.v1.json`: 36 roots hiện tại; match exact hoặc suffix boundary `.`.
- `homoglyphs.v1.json`: đầy đủ rune map Go hiện tại.
- `keyboard_adjacency.v1.json`: QWERTY adjacency hiện tại; weighted substitution phải kiểm tra hai chiều và digits như Go.
- `analysis_config.v1.json`: config dùng để tạo ML-candidate cohort, có checksum riêng.

Không copy tay hai chiều. Nên chuyển Go sang load snapshot trong model bundle hoặc sinh code từ snapshot và có test chống drift.

## 5. Candidate feature schema

Danh sách dưới đây là **candidate set**, chưa phải contract v1 cuối cùng.

| Nhóm | Candidate feature | Semantics cần khóa | Trạng thái đề xuất |
|---|---|---|---|
| Lexical | `fqdn_length` | Byte/rune semantics trên canonical A-label; đề xuất byte length vì ASCII | Giữ candidate |
| Lexical | `num_dots`, `num_hyphens`, `num_digits`, `digit_ratio` | Cùng A-label và denominator explicit | Giữ candidate |
| Lexical | `entropy` | Shannon entropy trên main A-label, log2, float64 | Giữ candidate |
| Lexical | `max_consecutive_consonants` | Alphabet `a-z`; cách xử lý digits/hyphen explicit | Giữ candidate |
| PSL | `main_label_length`, `registrable_domain_length`, `subdomain_depth` | Cùng frozen PSL; depth là số label trước registrable domain | Giữ candidate |
| Token | `token_count` | Split trên `.` và `-`; bỏ hay giữ empty token phải explicit | Giữ candidate |
| IDN/pattern | `is_punycode` | Có label prefix `xn--` | Giữ candidate |
| IDN/pattern | `has_mixed_script` | Tính trên U-label view bằng script table/profile versioned | Giữ candidate, không tính trên A-label |
| Pattern | `is_ip_like` | Bare IP là invalid; feature chỉ có nghĩa nếu pattern “IP-like hostname” được định nghĩa và có variance | Giữ có điều kiện |
| Lookup | `tld_risk_score` | Binary listed/default baseline; không gọi unlisted là safe | Giữ candidate |
| Lookup | `phishing_keyword_count` | Count distinct frozen keywords matched; matching/case/boundary explicit | Giữ candidate |
| Lookup | `is_shared_hosting` | Exact/suffix-boundary against frozen roots | Giữ candidate |
| Brand | `min_brand_levenshtein` | Min raw edit distance trên eligible non-suffix labels; short-brand rules explicit | Giữ candidate |
| Brand | `min_brand_keyboard_distance` | Port đúng weighted Go algorithm, float64 | Giữ candidate |
| Brand | `has_brand_homoglyph` | Skeleton match nhưng label khác brand; official suffix bypass | Giữ candidate |
| Brand | `has_brand_in_main_label` | Port đúng `isSuspiciousLabel`, gồm short-brand behavior | Giữ candidate |
| Brand | `has_brand_in_subdomain` | Chỉ labels trước registrable domain; boundary-aware | Giữ candidate |
| Optional | `vowel_ratio` | Chưa có runtime semantics; có thể tương quan mạnh với entropy/consonants | Chỉ ablation |
| Optional | `is_trusted_brand_suffix` | Frozen official/alt suffix match | Chỉ ablation/safety feature |
| Redundant | `num_labels` | Gần như `num_dots + 1` với valid FQDN | Không giữ nếu correlation/ablation không chứng minh |
| Constant | `special_char_count` | Luôn 0 sau valid A-label canonicalization | Loại khỏi v1 mặc định |

Feature cuối cùng phải có trong contract: `name`, `index`, `dtype`, input view, algorithm/version, default/error behavior và rounding. Không mặc định tất cả là `float64`; lưu compact dtype cho dữ liệu nếu parity/probability test cho phép, nhưng Go runtime phải tính theo precision đã khóa.

## 6. Character n-gram TF-IDF

Baseline ban đầu để experiment, chưa khóa:

- Input: full canonical A-label FQDN, không URL/path, không trailing dot.
- Analyzer: character n-gram; không gọi là embedding.
- So sánh range `(2,3)` và `(3,5)`.
- So sánh vocabulary `128/512/1024/2048` nếu capacity cho phép.
- Fit vocabulary + IDF **chỉ trên train**.
- Contract khóa lowercase behavior, raw TF, smoothed IDF, sublinear TF, L2 norm, token/index ordering, tie behavior và OOV handling.
- Pin chính xác scikit-learn vì vocabulary selection/tie behavior có thể đổi theo version.
- Export `vocabulary_by_index` và `idf_by_index` vào manifest; `joblib` chỉ là cache/debug nội bộ.
- Python–Go golden vectors phải kiểm tra zero vector, unknown n-grams, repeated chars, dots/hyphens, punycode và normalization tolerance.

## 7. Trình tự thực hiện và gates

### Gate G0 — Data readiness và governance

**Công việc**

1. Restore hoặc rebuild các file được `ml/data/data_manifest.json` tham chiếu; fail nếu thiếu.
2. Sửa manifest để phân biệt `file_rows` và `data_rows`; không đếm header như sample.
3. Nâng validator để kiểm raw + processed checksums, schema, duplicates, bare IP, conflicts, cleaning report, source counts và missing files.
4. Hoàn tất machine-readable source/label policy; xử lý `terms_review_id: pending-review` trước approved training/release.
5. Tách `unwanted-ad-tracker` và weak/mixed sources khỏi positive ground truth mặc định hoặc ghi experiment/weight policy rõ ràng.
6. Bổ sung trust tier/timestamp/all-source metadata cần cho split, source holdout và candidate report.
7. Thống nhất CLI thực tế dưới `scripts/data_processing/`; cập nhật spec/task runner thay vì tạo script trùng ở root.

**Gate pass khi**

- Tất cả artifact tồn tại và hash khớp.
- Data rows/counts khớp report; conflicts trong trainable set bằng 0.
- Source policy/terms metadata không còn trạng thái thiếu chưa được phê duyệt.
- Preflight trả non-zero cho mọi negative fixture bắt buộc.

### Phase 0A — Toolchain, snapshots và draft contract

**Công việc**

1. Cho phép commit có chủ đích `ml/**/*.py`, tiếp tục ignore raw/processed/derived/private bundle.
2. Pin Python trong `mise.toml`; tạo `ml/pyproject.toml` và lockfile với version chính xác.
3. Pin NumPy, pandas/Polars nếu dùng, SciPy, scikit-learn, LightGBM, IDNA/PSL parser, PyArrow và pytest.
4. Tạo frozen PSL + analysis snapshots, metadata provenance, SHA-256 và validator chống drift.
5. Viết draft canonicalization/feature contract và synthetic golden corpus đã security review.
6. Quy định artifact format, deterministic seeds, command-line interface, logging và resource report.

**Gate pass khi**

- Cài môi trường từ lockfile trên máy sạch thành công.
- Build/test không cần network.
- Snapshot hashes được contract xác nhận; sửa snapshot mà không bump version làm test fail.

### Phase 0B — Python/Go canonicalization và handcrafted parity

**Công việc**

1. Implement Python ML canonicalizer + feature extractor.
2. Implement Go counterpart trong `internal/analysis` mà không thay đổi public API hoặc deterministic verdict thresholds.
3. Port brand/keyboard/homoglyph semantics từ snapshot, không dùng config runtime động.
4. Test exact parity cho canonical output/index/integer/binary và tolerance cho float.
5. Benchmark 10k rồi 100k rows; đặc biệt profile brand distances, PSL lookup và allocations.

**Gate pass khi**

- Golden canonicalization và handcrafted vectors pass trên valid/invalid/IDN/PSL/private-suffix cases.
- Không có fallback parser âm thầm.
- Resource profile cho phép dự toán full run; nếu brand feature quá chậm phải tối ưu hoặc loại qua ablation.

### Phase 0C — Schema-selection ablation và freeze contract v1

**Công việc**

1. Tạo group-disjoint development split trên `domain_dataset_lite` hoặc subset đã restore.
2. Loại constant/near-constant features; ghi correlation và duplicate semantics.
3. Benchmark tối thiểu:
   - deterministic baseline hiện tại;
   - handcrafted-only;
   - TF-IDF logistic regression;
   - LightGBM handcrafted-only;
   - LightGBM TF-IDF-only;
   - LightGBM combined;
   - TF-IDF ranges/vocabulary sizes đã nêu.
4. Đo candidate-cohort metrics, critical benign FPR, model size và Go transform latency; không chọn theo accuracy tổng.
5. Freeze `domain_feature_contract.v1.json`, feature count/order và TF-IDF settings sau khi có evidence.

**Gate pass khi**

- Có ablation report và lý do giữ/loại từng feature.
- Contract v1 được review; không còn “24/152” chỉ vì kế hoạch ban đầu ghi như vậy.

### Phase 0D — `leaves` và Docker compatibility spike

**Công việc**

1. Pin một version/commit `leaves` thử nghiệm.
2. Train mini LightGBM bằng **contract v1 đã freeze**, export text model bằng `save_model()`.
3. Kiểm `NFeatures()` trước prediction.
4. So raw margin, transformed probability và batch/single prediction Python–Go trên ít nhất 1,000 frozen vectors.
5. Test malformed/truncated model, wrong feature count, unsupported objective/transformation.
6. Build/test `CGO_ENABLED=0` và đúng Docker Alpine/production image path.

**Gate pass khi**

- Probability parity tolerance pass.
- Wrong model/schema fail startup khi required và fail-open đúng policy khi optional.
- Chỉ lúc này mới duyệt dependency `leaves` cho implementation chính và cho phép full extraction.

### Phase 1 — Candidate cohort và leakage-safe splits

**Công việc**

1. Canonicalize theo contract v1 và join provenance/trust/timestamp metadata.
2. Mô phỏng deterministic short-circuit; chạy analyzer với frozen `analysis_config.v1.json`.
3. Ghi `lexical_verdict`, score/reasons và `is_ml_candidate` mà không dump domain hàng loạt vào log.
4. Tạo train/validation/calibration/test theo registrable-domain group; thêm source/temporal holdout khi dữ liệu cho phép.
5. Tạo immutable `split_manifest.json` với hashes, seed, counts, time ranges, `group_overlap=0`, `conflicts_in_trainable=0`.
6. Đóng băng final test; hard cases đã dùng chọn threshold không được tái sử dụng như final test.

**Gate pass khi**

- Group overlap bằng 0.
- Candidate cohort phản ánh production path.
- Source/temporal holdout và critical benign sets có coverage được báo cáo.

### Phase 2 — Full feature extraction

**Công việc**

1. Fit TF-IDF trên train partition duy nhất.
2. Transform train/validation/calibration/test/holdouts theo batch; handcrafted extractor dùng cùng contract.
3. Kết hợp dense handcrafted block với sparse TF-IDF thành CSR mà không densify toàn matrix.
4. Lưu partition metadata bằng Parquet và matrix bằng `.npz`/binary đã benchmark.
5. Ghi SHA-256, row/column counts, feature order, sparsity, dtype, peak RSS, wall time, CPU và disk/temp usage.
6. Chạy schema/hash/vector spot-check sau serialize/deserialize.

**Gate pass khi**

- Không fit transform trên non-train data.
- Không có dense `features_X.csv`.
- Matrix dimensions/order/hash khớp contract và split manifest.
- Capacity report xác nhận pipeline chạy được trên training environment đã phê duyệt.

## 8. Artifact layout đề xuất

```text
ml/
├── pyproject.toml
├── uv.lock                         # hoặc lockfile tương đương đã chọn
├── configs/
│   └── v1.json
├── contracts/
│   ├── domain_feature_contract.v1.json
│   └── snapshots/
│       ├── public_suffix_list.v1.dat
│       ├── psl_metadata.v1.json
│       ├── brands.v1.json
│       ├── keywords.v1.json
│       ├── tld_risk.v1.json
│       ├── shared_hosting.v1.json
│       ├── homoglyphs.v1.json
│       ├── keyboard_adjacency.v1.json
│       └── analysis_config.v1.json
├── src/
│   ├── canonicalize.py
│   ├── build_candidate_cohort.py
│   ├── make_splits.py
│   ├── build_features.py
│   ├── run_ablation.py
│   └── validate_artifacts.py
├── tests/
│   ├── test_contract.py
│   ├── test_canonicalize.py
│   ├── test_features.py
│   ├── test_tfidf.py
│   ├── test_splits.py
│   └── fixtures/                  # synthetic/reviewed only
└── data/
    └── derived/                   # gitignored
        ├── partitions/*.parquet
        ├── matrices/*.npz
        ├── split_manifest.json
        ├── feature_manifest.json
        ├── capacity_report.json
        └── ablation_report.json
```

Bundle runtime cuối cùng phải chứa model, feature manifest, calibration/policy/report, checksums **và các frozen snapshots cần để Go tái tạo feature**. Không đặt raw dataset, provenance domain-level hoặc Python-only `joblib` vào bundle.

## 9. Verification matrix tối thiểu

| Lớp | Kiểm tra bắt buộc |
|---|---|
| Data | Missing file, checksum mismatch, header/schema, row semantics, duplicate, invalid/bare IP, conflict, source/terms policy |
| Canonicalization | URL/host/port/trailing dot/wildcard, `www`, label limits, IDNA, invalid Unicode, `com.vn`, `gov.vn`, private suffix |
| Handcrafted | Empty/edge labels, digits/hyphens, entropy, tokens, subdomain depth, shared-host boundary, short brands |
| Brand/IDN | Official suffix bypass, alt domains, homoglyph, mixed script, keyboard adjacency both directions, punycode decode failure |
| TF-IDF | Vocabulary index, IDF, repeated n-gram TF, L2 normalization, OOV, zero vector, Python–Go tolerance |
| Split | Group overlap 0, conflicts 0, fit-on-train assertion, source/temporal isolation |
| Model loader | Feature count, objective/transformation, raw/probability parity, malformed/truncated model |
| Runtime | `CGO_ENABLED=0`, Docker Alpine, optional fail-open, required fail-start, read-only bundle |
| Capacity | Peak RSS, wall time, CPU, disk/temp, matrix sparsity, Go p50/p95 transform latency |

Tolerance không được ghi tùy ý trong plan rồi coi là pass. Bắt đầu thử `1e-12` cho TF-IDF float64 và xác lập ngưỡng cuối bằng cross-platform evidence; prediction có tolerance riêng theo LightGBM/`leaves` output.

## 10. Rủi ro và biện pháp

| Rủi ro | Biện pháp |
|---|---|
| Dataset snapshot không còn local | Restore từ private storage hoặc rebuild; hash phải khớp manifest mới trước khi dùng. |
| Source terms/label policy chưa duyệt | Chặn approved training/release; cho phép technical spike chỉ trên synthetic/lite data được phê duyệt. |
| Canonicalization builder/runtime khác nhau | Rebuild dataset theo contract v1; không vá riêng feature extractor trên snapshot cũ. |
| PSL Python/Go khác version/private section | Một frozen snapshot, hash trong contract/bundle, golden eTLD+1 corpus. |
| Brand extraction quá chậm | Profile sớm, pre-index labels/brands, cache deterministic transforms; loại feature nếu cost/benefit không đạt. |
| TF-IDF/source leakage | Split trước fit; pipeline API không cho fit trên combined data; test assertion bắt buộc. |
| Bias từ TLD/shared hosting | Binary semantics trung tính, benign hard cases, source-aware FPR và ablation. |
| Artifact mismatch | Immutable bundle + checksums + schema version + feature count + startup validation. |
| Sparse matrix bị densify ngoài ý muốn | CSR end-to-end, memory regression test, peak RSS gate. |
| Dynamic admin brand/config làm model drift | Model chỉ dùng frozen snapshots; đổi semantics phải train/release bundle mới. |

## 11. Các quyết định cần chủ sở hữu phê duyệt

1. **PSL:** cho phép tải một snapshot PSL chính thức một lần, lưu kèm license/provenance/hash trong repo hoặc private artifact source. Đề xuất: **đồng ý**, nhưng tuyệt đối không auto-download lúc train/runtime.
2. **Canonical `www`:** đề xuất **không strip** trong ML contract và rebuild dữ liệu; nếu muốn strip để tương thích snapshot cũ thì phải ghi rõ trade-off và test runtime tương ứng.
3. **TLD risk:** đề xuất **binary v1** theo map hiện tại; multi-level chỉ experiment sau khi có nguồn/evidence.
4. **Brand list:** đề xuất baseline đúng **40 brands hiện tại**; brand mới (Zalo/Viettel/VNPT/FPT...) đi qua review và experiment riêng, không trộn âm thầm vào v1.
5. **Ablation:** đề xuất dùng `domain_dataset_lite` cho schema search, nhưng vẫn xác nhận model được chọn trên full group-disjoint train/validation và chỉ đánh giá một lần trên frozen final test.
6. **Training environment:** cần chốt CPU/RAM/disk/temp budget để capacity gate có con số pass/fail thay vì mô tả chung.
7. **Source/legal:** cần owner xử lý toàn bộ `pending-review`; đây là blocker governance, không thể giải quyết bằng code feature extraction.

## 12. Definition of Done cho phạm vi feature extraction

- [ ] Data preflight và source policy gate pass.
- [ ] Canonicalization v1 được review; dataset được rebuild/validated theo đúng contract.
- [ ] PSL và mọi analysis snapshot được pin, có provenance/hash và không cần network.
- [ ] Candidate features đã qua variance/correlation/performance/ablation; contract v1 mới được freeze sau đó.
- [ ] Python–Go canonicalization, handcrafted và TF-IDF parity pass.
- [ ] `leaves` mini-model probability parity và Docker `CGO_ENABLED=0` pass.
- [ ] Candidate cohort và group/source/temporal splits pass leakage assertions.
- [ ] TF-IDF chỉ fit trên train; full partitions transform theo batch, không densify.
- [ ] Parquet/NPZ artifacts có manifest/checksum/dimensions và capacity report.
- [ ] Không có raw/private domains trong Git fixtures, logs hoặc runtime bundle.
- [ ] Mọi thay đổi semantics sau v1 đều bump contract/snapshot/model bundle version.
