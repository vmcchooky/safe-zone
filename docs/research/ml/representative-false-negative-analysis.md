# Phân tích 13 false-negative của representative replay

> **Tài liệu Living Document** — Cập nhật đồng bộ mỗi khi có thay đổi.
> Tuân thủ quy tắc tại `.agents/AGENTS.md` Section 5.

## Tóm tắt (Abstract)

Candidate v2 suffix-debiased giữ representative benign FPR ở `0/25` nhưng chỉ phát hiện `21/34` malicious case tại threshold `0,92`, tạo 13 false-negative. Phân tích `pred_contrib` và bounded Firecrawl cho thấy model domain-only thiếu tín hiệu về redirect, cloaking, security interstitial và exact threat-feed membership; Firecrawl chỉ được dùng làm evidence transport, không làm adjudicator. Vòng A/B ngày 2026-08-24 sửa phép loại leakage theo tenant trên shared hosting và candidate v3 tăng representative recall lên `22/34`, nhưng vẫn thấp hơn gate `26/34`. Vòng v4 pre-register PhishTank development và OpenPhish holdout source-disjoint; candidate được chọn tăng OpenPhish tổng thể từ `89/130` lên `91/130`, nhưng ordinary-looking giảm từ `6/40` xuống `5/40`, representative giữ nguyên `22/34` và SAFE VN runtime-candidate phát sinh `1/1.400` false positive. Vòng v5 đổi representation sang suffix-stripped character TF-IDF linear model, đóng băng `349` development rows và `81.528` PhishDestroy holdout rows trước selection. Cả ba log-odds blend đều giảm validation false positive nhưng mất `206–809` true positive và giảm time-forward development TP từ `196` xuống `172–185`; vì không candidate nào đạt selection guardrail, final test, PhishDestroy holdout và frozen representative packet không được mở. V4 và v5 đều giữ trạng thái private `NO-GO`; không export, provision, restart service, thay đổi traffic scope hoặc bật `enforce`.

## Sơ đồ Tổng quan

```mermaid
flowchart LR
    A[/Signed labels/] -->|Replay| B[Candidate v3]
    B -->|22/34| C[Freeze v4 cohorts]
    C -->|Dev và holdout| D[6 ablation v4]
    D -->|Final fail| E[NO-GO v4]
    E -->|Đổi representation| F[Freeze v5 cohorts]
    F -->|349 dev rows| G[Char-linear ensemble]
    G -->|3 log-odds blends| H{Selection gates đạt?}
    H -->|Không| I[NO ELIGIBLE v5]

    classDef input fill:#E9ECEF,stroke:#6C757D,color:#343A40
    classDef ai fill:#E8DAEF,stroke:#8E44AD,color:#4A235A
    classDef decision fill:#FFF3CD,stroke:#FFC107,color:#856404
    classDef blocked fill:#F8D7DA,stroke:#DC3545,color:#721C24
    class A,C,F input
    class B,D,G ai
    class H decision
    class E,I blocked
```

## Phân tích nguyên nhân và phương án remediation

### Mục tiêu (Objectives)

- Xác định nguyên nhân khiến 13 malicious case nằm dưới threshold `0,92` mà không thay đổi evidence hoặc nhãn đã được owner duyệt.
- Phân biệt lỗi quan sát hiện tại của website với lỗi phân loại lexical của model.
- Xây dựng hướng hard-positive độc lập, group-disjoint và không rò rỉ frozen representative set.
- Xác định guardrail bắt buộc trước khi retrain, replay hoặc xem xét restart local staging ở `shadow`.

### Phương pháp & Lý do (Methodology & Rationale)

| Quyết định | Phương pháp chọn | Các phương pháp thay thế | Lý do |
|---|---|---|---|
| Giải thích model | LightGBM `pred_contrib=True`, tách handcrafted và TF-IDF contribution | Chỉ so probability; dùng global feature importance | Contribution theo từng case cho biết feature nào đẩy margin lên hoặc xuống; global importance không giải thích 13 lỗi cụ thể |
| Xác minh trạng thái web | Firecrawl `/v2/scrape`, exact URL, schema-constrained JSON, cache tắt, không crawl/agent | Browser thủ công; Firecrawl Agent/Crawl | Scrape có giới hạn giảm external requests và tạo record checksum-pinned; kết quả extractor không được dùng làm nhãn |
| Ground truth | Giữ quyết định malicious trong owner-approved addendum | Relabel theo website hiện tại; yêu cầu owner review lại toàn bộ | Domain có thể chết, đổi nội dung hoặc chặn crawler sau thời điểm review; trạng thái hiện tại không phủ định bằng chứng lịch sử |
| Remediation dữ liệu | Hard-positive time-forward từ source độc lập, loại toàn bộ representative registrable groups | Đưa chính 13 case vào train; oversample ngẫu nhiên mọi malicious row | Giữ 13 case làm regression độc lập và tránh leakage |
| Remediation kiến trúc | Kết hợp feature v3 có kiểm soát với exact threat-feed/runtime context | Chỉ hạ threshold; đổi ngay model family | Threshold `0,85` vẫn chỉ đạt `25/34` và tạo `1/25` FP; nhiều hành vi không thể suy ra từ hostname |

### Cách thức Thực hiện (Implementation Details)

Phân tích sử dụng model revision `97b2ef1f3f6e77e043b3c26502a919f69fd2ca225140a3b13f4dfbafea3aa691`, feature contract `2.0.0` và threshold `0,92`. Offline probabilities của v1/v2 được nối với 13 label malicious trong owner-approved addendum; LightGBM raw margin được phân rã thành bias, 22 handcrafted feature và 512 TF-IDF feature. Việc tái kiểm tra web chỉ gọi Firecrawl scrape trên exact domain, tắt cache, không dùng crawl hoặc agent, không ghi API key vào request artifact và lưu output trong thư mục Git-ignored.

AI agent sử dụng Codex (GPT-5) với chiến lược đối chiếu ba lớp: signed evidence, model contribution và current scrape. Số subagent là `0`; không dùng voting. Kiểm soát chất lượng gồm SHA-256 verification, schema/result count, feature extraction chạy lại từ snapshot contract và so sánh threshold sweep đã có. Con người giữ vai trò phê duyệt ground truth trong addendum trước đó; vòng phân tích này không tạo yêu cầu review lại 13 domain.

Firecrawl không phải adjudicator. `1xbet-xoso.com` trả nội dung cờ bạc đang hoạt động nhưng extractor ghi `observed_category=benign_content`; `yvan.acces11506256.pro` và `gbeq.netlify.app` cũng nhận category benign khi trang hiện tại bị chặn hoặc trả trạng thái không hoạt động. Các record này chứng minh extractor category có thể sai trong chính cohort đang kiểm tra.

### Số liệu (Metrics & Results)

#### Contribution audit

| Chỉ số | Kết quả |
|---|---:|
| False-negative tại threshold `0,92` | 13/34 malicious case |
| Xác suất giảm từ v1 sang v2 | 8/13 |
| Mean probability v1 | 0,753660 |
| Mean probability v2 | 0,742047 |
| Mean delta v2 − v1 | −0,011613 |
| `tld_risk_score=0` | 13/13 |
| `phishing_keyword_count=0` | 13/13 |
| Shared hosting được nhận diện | 1/13 |
| Brand main/subdomain/homoglyph flag bật | 0/13 |
| TF-IDF contribution âm | 4/13 |
| Handcrafted contribution âm | 2/13 |
| Mean `tld_risk_score` contribution | −0,350826 raw-margin unit |

`tld_risk_score=0` là feature có mean contribution âm lớn nhất trong cohort. Giá trị `0` hiện mang nghĩa “TLD không có trong snapshot rủi ro”, nhưng cây đã học nhánh này như tín hiệu benign mạnh; đây là correlation do phân phối train, không phải bằng chứng rằng TLD phổ biến làm domain an toàn. Feature v3 cần tách `unknown/neutral` khỏi risk flag hoặc điều chỉnh source balancing để nhánh zero không lấn át các tín hiệu khác.

#### Case audit

| Case | Domain | v1 | v2 | Delta | Nhóm nguyên nhân chính | Firecrawl 2026-08-24 |
|---|---|---:|---:|---:|---|---|
| replay-0054 | `litetotolubu.com` | 0,853041 | 0,783453 | −0,069588 | redirect/gambling không được keyword feature nhận diện | live gambling |
| replay-0056 | `mod22.com` | 0,832536 | 0,727916 | −0,104620 | short domain + TDS rotating redirect | fetch lỗi HTTP 500 |
| replay-0071 | `absicherung-kontakt.com` | 0,723373 | 0,836679 | +0,113306 | security-feed evidence, TF-IDF contribution âm | Firecrawl `success=false` |
| replay-0083 | `mcaavoli.com` | 0,816538 | 0,805115 | −0,011423 | ordinary-looking hostname, threat visible qua interstitial | phishing interstitial |
| replay-0097 | `yvan.acces11506256.pro` | 0,871053 | 0,892814 | +0,021760 | numeric/subdomain signal chưa đủ threshold | access blocked; category không tin cậy |
| replay-0099 | `500326.com` | 0,924396 | 0,889313 | −0,035083 | numeric threat từng vượt threshold, phụ thuộc feed/interstitial | Firecrawl `success=false` |
| replay-0108 | `gbeq.netlify.app` | 0,922205 | 0,776493 | −0,145712 | shared-hosting subdomain; suffix debias làm mất signal | access blocked/404 |
| replay-0113 | `pl.spotify-original.com` | 0,427092 | 0,651373 | +0,224281 | brand trong compound registrable label không bật brand flag | phishing interstitial |
| replay-0119 | `1xbet-xoso.com` | 0,800885 | 0,909618 | +0,108734 | gambling token không nằm trong keyword snapshot | live gambling; extractor gọi benign |
| replay-0123 | `axygames.com` | 0,379730 | 0,434954 | +0,055223 | redirect gateway không quan sát được từ hostname | redirect landing |
| replay-0132 | `li88.net` | 0,626056 | 0,611222 | −0,014834 | short numeric gambling domain; handcrafted sum âm | HTTP 403/access blocked |
| replay-0133 | `merrychampionstream.pro` | 0,928835 | 0,874820 | −0,054014 | cloaking; TF-IDF contribution âm | live content, category unknown |
| replay-0135 | `speedingk.com` | 0,692135 | 0,452841 | −0,239293 | threat-feed evidence, lexical n-gram mang tín hiệu benign | Firecrawl `success=false` sau retry |

Giá trị v1 của `500326.com`, `gbeq.netlify.app` và `merrychampionstream.pro` đều từng vượt `0,92` nhưng v2 kéo xuống dưới threshold. Đây là regression do thay đổi phân phối feature, không phải 13 domain mới chưa từng được model nhận diện.

#### Firecrawl refresh

| Chỉ số | Kết quả |
|---|---:|
| Exact domain planned | 13 |
| Schema-valid sau initial + bounded retry | 9/13 |
| Current live content | 3/13 (`litetotolubu.com`, `1xbet-xoso.com`, `merrychampionstream.pro`) |
| Security interstitial | 2/13 |
| Redirect landing | 1/13 |
| Access blocked/404/403 | 3/13 |
| Không lấy được record | 4/13 |
| Crawl/Agent request | 0 |
| API key xuất hiện trong artifact | 0 |

Bốn domain không có current record là `mod22.com`, `absicherung-kontakt.com`, `500326.com` và `speedingk.com`. Các lỗi này được ghi nhận là thiếu current scrape, không phải thiếu ground truth. Hai `results.jsonl` khớp SHA-256 trong manifest tương ứng.

## Thử nghiệm leakage-free feature contract v3

### Mục tiêu (Objectives)

- Loại mọi domain hoặc tenant group trong owner-approved representative packet khỏi train, validation, calibration và test trước khi đo candidate mới.
- So sánh control v2 và candidate v3 trên cùng partition, vocabulary, IDF, seed và threshold `0,92`.
- Kiểm tra liệu feature snapshot có mục tiêu cải thiện 13 false-negative mà không vượt benign guardrail đã khóa.
- Chỉ cho phép restart local staging ở `shadow` khi representative malicious recall đạt tối thiểu `26/34`.

### Phương pháp & Lý do (Methodology & Rationale)

| Quyết định | Phương pháp chọn | Các phương pháp thay thế | Lý do |
|---|---|---|---|
| Đơn vị loại leakage | eTLD+1 cho ordinary domains; tenant label + provider root cho shared hosting | Loại toàn bộ provider root; chỉ loại exact FQDN | Loại provider root làm mất 18.173 train rows; exact FQDN cho phép sibling subdomain cùng tenant rò rỉ. Tenant-aware grouping loại đúng case review nhưng giữ tenant độc lập |
| A/B control | Dựng `v2-leakage-free-control` và v3 từ cùng source partition | So v3 với report v2 cũ | Report cũ đã giao với 137 representative rows theo 135 registrable groups, nên không còn là holdout hợp lệ |
| Feature update | Giữ 534 chiều; snapshot-pin `xbet/casino/slot`, Spotify và ba shared-hosting root | Thêm nhiều keyword; crawl feature; đổi model family | Thay đổi bounded giữ latency/bundle contract; crawl feature không deterministic và không phù hợp DNS-path inference |
| TLD policy | Monotone increasing chỉ cho `tld_risk_score` theo tên feature | Không constraint; raw index vector | Named constraint tránh lệch feature order. Ablation không constraint giảm full-test FP nhưng tạo `1/1.400` SAFE VN candidate FP |
| Positive remediation | Không dùng generic positive reweighting/OHEM sau ablation | Weight toàn bộ malicious candidate; đưa 13 case vào train | Reweighting chỉ đạt `18–19/34`; đưa frozen case vào train làm mất giá trị regression |
| Threshold | Giữ policy `0,92`; validation-only matching được audit riêng | Hạ threshold theo representative/test | Tuning theo frozen packet hoặc final test tạo leakage. Validation-only threshold `0,920459` vẫn không vượt final gate |
| Runtime action | `NO-GO`, không export/restart | Restart local staging ở `shadow` vì benign guardrail xanh | Gate yêu cầu `26/34`; candidate chỉ đạt `22/34`, nên parity/runtime replay không thể thay thế model-quality gate |

Monotone constraint sử dụng cơ chế chính thức của [LightGBM](https://lightgbm.readthedocs.io/en/stable/Parameters.html#monotone_constraints). Việc tách train/validation/calibration/test và không tiếp tục chọn hyperparameter sau final test tuân theo nguyên tắc holdout của [Google Machine Learning](https://developers.google.com/machine-learning/crash-course/overfitting/dividing-datasets). Spotify được thêm bằng snapshot contract với official domain lấy từ [Spotify Support](https://support.spotify.com/us/article/spotify-email-legit/), không suy ra từ Firecrawl output.

### Cách thức Thực hiện (Implementation Details)

`ml/src/training_data.py` đọc checksum của owner-approved labels, canonicalize toàn bộ 137 domain và xây evaluation group. Với shared-hosting provider, group dùng tenant gần provider nhất: `login.victim.weebly.com` ánh xạ thành `victim.weebly.com`; tenant khác trên `weebly.com` vẫn được giữ. Shared-hosting root được sắp xếp theo độ dài giảm dần để kết quả deterministic khi snapshot có suffix lồng nhau. Manifest ghi label SHA-256, shared-hosting snapshot SHA-256, số tenant group và số hàng bị loại theo từng partition.

Feature contract `3.0.0` giữ nguyên 22 handcrafted + 512 TF-IDF features. `snapshot_policy` khai báo chính xác base files, ba keyword extensions (`xbet`, `casino`, `slot`), Spotify brand record và ba roots (`weebly.com`, `weeblysite.com`, `godaddysites.com`). Python builder và Go runtime cùng reject v3 manifest không khớp exact snapshot policy. Training config dùng seed `42`, LightGBM tối đa 1.000 trees, broad benign proxy weight `1,5`, evidence hard-negative weight `3,0` cho 252 rows và monotone increasing constraint theo tên `tld_risk_score`.

Control và candidate được build, validate, train, Platt calibrate và evaluate độc lập. Cả hai có partition SHA-256 giống nhau, feature-name order giống nhau và `idf_by_index` giống nhau. Representative binary subset chỉ được feature-transform sau training. Không có signed evidence nào bị sửa; toàn bộ matrices, models và ablation reports nằm trong `ml/data/derived/` bị Git ignore.

AI agent sử dụng Codex (GPT-5) với chiến lược constraint-first: xác minh leakage và provenance trước, chạy một biến thay đổi cho từng ablation, sau đó áp gate đã ghi trong tài liệu. Số subagent là `0`; không dùng voting. Kiểm soát chất lượng gồm unit tests Python/Go, artifact validator, checksum comparison, full-test/candidate-cohort audit và frozen representative replay. Con người giữ quyền duyệt ground truth; agent chỉ quyết định `NO-GO` theo gate có sẵn và không thay đổi traffic scope.

### Số liệu (Metrics & Results)

#### Integrity và partition

| Chỉ số | Kết quả |
|---|---:|
| Owner-approved evaluation cases | 137 |
| Shared-hosting tenant groups | 17 |
| Evaluation rows loại khỏi train/val/cal/test | 321 / 9 / 13 / 543 |
| Combined challenge + evaluation rows loại | 323 / 9 / 14 / 543 |
| Rows sau loại train/val/cal/test | 1.929.386 / 273.799 / 281.212 / 286.804 |
| Group overlap sau loại | 0 |
| Validator control v2 | 35/35 pass |
| Validator candidate v3 | 35/35 pass |
| A/B partition SHA giống nhau | 4/4 |
| Feature order và IDF giống nhau | pass |

Phép loại cũ theo provider eTLD+1 đã loại 18.173 train rows của representative set. Tenant-aware policy giảm con số này còn 321, nhưng vẫn giữ overlap bằng 0. Đây là thay đổi phương pháp đo có ảnh hưởng lớn hơn mọi hyperparameter ablation trong vòng thử nghiệm.

#### Control v2 và candidate v3 tại threshold `0,92`

| Chỉ số | Control v2 sạch | Candidate v3 | Delta v3 − v2 |
|---|---:|---:|---:|
| Full-test ROC-AUC | 0,9565 | 0,9565 | 0,0000 |
| Full-test PR-AUC | 0,9507 | 0,9503 | −0,0004 |
| Full-test Brier | 0,082046 | 0,081909 | −0,000137 |
| Full-test ECE | 0,008124 | 0,008245 | +0,000121 |
| Full-test FP | 1.501 | 1.545 | +44 |
| Full-test TP | 70.506 | 70.573 | +67 |
| Runtime-candidate FP / 9.504 benign | 168 | 164 | −4 |
| Runtime-candidate TP / 14.572 malicious | 11.278 | 11.256 | −22 |
| Runtime-candidate FPR | 1,7677% | 1,7256% | −0,0421 điểm % |
| Runtime-candidate recall | 77,3950% | 77,2440% | −0,1510 điểm % |
| SAFE VN benign FP / 44.833 | 4 | 2 | −2 |
| SAFE VN candidate FP / 1.400 | 0 | 0 | 0 |
| Representative benign FP / 25 | 0 | 0 | 0 |
| Representative malicious TP / 34 | 21 | 22 | +1 |
| Targeted benign challenge FP / 3 | 0 | 0 | 0 |

V3 đưa `1xbet-xoso.com` từ `0,900078` lên `0,966539` và Spotify compound-domain case từ `0,619158` lên `0,720186`. Mười hai malicious case vẫn dưới threshold. Candidate cải thiện FPR trong runtime-candidate cohort nhưng giảm 22 true positive trên cohort test; mức đổi này không bù được việc thiếu bốn true positive so với gate representative `26/34`.

#### Ablation bị loại

| Ablation | Kết quả chính | Quyết định |
|---|---|---|
| Generic malicious-candidate weight `1,25–2,0` | Representative `18–19/34`; SAFE VN candidate FP `9–16` trong proxy audit | Loại |
| Mined hard-positive/OHEM | Representative `18/34`; SAFE VN candidate FP `5–8` | Loại |
| V3 không monotone | Representative `22/34`; full-test FP `1.456`; SAFE VN candidate FP `1/1.400` | Loại vì phá guardrail targeted benign |
| Candidate-only train/calibration | Tại `0,92`: test candidate TP `11.804`, FP `183`, SAFE VN candidate FP `2`; validation-constrained threshold `0,976108` giảm representative còn `20/34` | Loại |
| Validation-only threshold match | Threshold `0,920459`; representative `22/34`; final full-test FP `1.531` | Không promote; final test không được dùng để tune tiếp |

Kết quả không hỗ trợ restart local staging. Signed packet vẫn là frozen regression; lần phát triển kế tiếp cần một time-forward holdout mới trước khi thử thêm model/data policy.

## Thử nghiệm v4 time-forward và TLD state

### Mục tiêu (Objectives)

- Đóng băng một holdout mới trước model selection, tách biệt theo thời gian, source và evaluation group với toàn bộ partition/frozen packet hiện có.
- Kiểm tra liệu hard-positive ordinary-looking cùng TLD state ba mức có giảm correlation `tld_risk_score=0 ⇒ benign` mà không tuning theo representative packet.
- Chọn family/weight chỉ bằng PhishTank development và validation candidate FP; chỉ mở final test, OpenPhish holdout và representative packet sau selection.
- Giữ candidate private nếu bất kỳ release gate nào không đạt.

### Phương pháp & Lý do (Methodology & Rationale)

| Quyết định | Phương pháp chọn | Các phương pháp thay thế | Lý do |
|---|---|---|---|
| Time-forward adaptation | PhishTank `verified=yes`, `online=yes`, sau mốc snapshot gốc; một row mỗi group | Reuse row train cũ; thêm representative false-negative | Dữ liệu mới có verification time, provenance và checksum; frozen packet không đi vào train |
| Final holdout | OpenPhish Community snapshot, loại mọi group đã có trong partitions, frozen packet hoặc PhishTank hiện tại | Chia ngẫu nhiên PhishTank; dùng final test để chọn | Source-disjoint giảm khả năng học artifact riêng của PhishTank và giữ final test ngoài selection |
| Hard-positive filter | Chỉ giữ neutral TLD, không keyword/brand/shared-hosting/IDN/IP flag | Weight mọi malicious; OHEM từ train | Nhắm vào ordinary-looking subgroup theo feature policy định trước, không theo token của 12 representative false-negative |
| TLD representation | Giữ 534 chiều; `unknown=0`, `known-neutral=0,5`, `risky=1` với monotone constraint | Thêm one-hot dimensions; giữ binary | Tách trạng thái unknown khỏi neutral mà không đổi bundle width hoặc TF-IDF offset |
| Model selection | Sáu tổ hợp: hai family × weight `1,0/1,5/2,0`; maximize development recall, validation candidate FP không vượt v3 | Chọn theo OpenPhish/representative/test | Quy tắc selection được ghi trong protocol trước train và không tiêu thụ final holdout |
| Release decision | Áp đồng thời representative, targeted benign, SAFE VN candidate và OpenPhish non-regression | Promote vì OpenPhish tổng tăng 2 TP | Tổng recall tăng nhỏ không bù được ordinary-looking regression và targeted proxy FP mới |

PhishTank cung cấp downloadable database chỉ gồm record đã verified và online; snapshot dùng đúng các cột `verified`, `online`, `verification_time` theo [developer documentation](https://phishtank.org/developer_info.php). OpenPhish Community Feed có định dạng text và chu kỳ cập nhật 12 giờ theo [official feed matrix](https://openphish.com/phishing_feeds.html). Hai source chỉ cung cấp transport/provenance cho label policy đã định nghĩa; không source nào được dùng làm adjudicator cho signed representative packet.

### Cách thức Thực hiện (Implementation Details)

Protocol `ml/configs/v4-time-forward-protocol.json` được commit ở `4b11f75` trước khi train hoặc đọc prediction. Snapshot PhishTank hiện tại có SHA-256 `f5bed724...61893e7`; OpenPhish có SHA-256 `1465805a...36f4e2a`. Builder canonicalize URL theo UTS #46/PSL, group shared hosting theo tenant, loại `1.935.620` baseline partition groups và `140` frozen groups, rồi xuất ba Parquet Git-ignored kèm public manifest checksum.

Adaptation thêm `1.232` malicious rows vào train với provenance `verified_online_time_forward`. Hai feature family dùng cùng `1.930.618 / 273.799 / 281.212 / 286.804` rows và cùng TF-IDF vocabulary/IDF. V4 thay riêng feature index `14`; builder kiểm tra `100/100` Python parity samples và Go runtime chỉ chấp nhận exact contract `4.0.0`. Selector train/Platt-calibrate sáu tổ hợp, đọc duy nhất validation và `467` development rows, rồi chọn v4 weight `1,5`. Final evaluator sau đó mở OpenPhish `130` rows, representative binary `59` rows, final test và targeted benign challenge đúng một lần.

AI agent sử dụng Codex (GPT-5) với chiến lược pre-registration, checksum-first và constraint-gated selection. Số subagent là `0`; không dùng voting. Kiểm soát chất lượng gồm unit test Python/Go, `36/36` artifact validation cho mỗi family, partition/feature ablation parity, selection input audit và one-time final evaluation. Con người giữ quyền duyệt signed labels và mọi thay đổi rollout; agent không export model, provision bundle, restart service, thay đổi traffic scope hoặc bật `enforce`.

### Số liệu (Metrics & Results)

#### Integrity và cohort

| Chỉ số | Kết quả |
|---|---:|
| PhishTank raw / canonical rows | 73.191 / 73.043 |
| Adaptation / development rows | 1.232 / 467 |
| OpenPhish raw / source-disjoint holdout groups | 300 / 130 |
| OpenPhish ordinary-looking subgroup | 40 |
| Cross-cohort group overlap | 0 |
| V3 data-only artifact checks | 36/36 pass |
| V4 ternary-TLD artifact checks | 36/36 pass |
| V4 single-feature Python parity | 100/100 pass |

#### Model selection không dùng final inputs

| Family | Weight | Development TP / 467 | Validation candidate FP / 11.032 | Eligible |
|---|---:|---:|---:|---|
| V3 + time-forward | 1,0 | 201 | 197 | có |
| V3 + time-forward | 1,5 | 205 | 241 | không |
| V3 + time-forward | 2,0 | 202 | 179 | có |
| V4 TLD state + time-forward | 1,0 | 204 | 233 | có |
| **V4 TLD state + time-forward** | **1,5** | **206** | **229** | **chọn** |
| V4 TLD state + time-forward | 2,0 | 203 | 214 | có |
| V3 control | n/a | không dùng để selection recall | 238 | guardrail |

#### Final evaluation tại threshold `0,92`

| Chỉ số | V3 control | V4 selected | Delta v4 − v3 |
|---|---:|---:|---:|
| Full-test ROC-AUC | 0,9565 | 0,9565 | xấp xỉ 0 |
| Full-test PR-AUC | 0,9503 | 0,9504 | +0,0001 |
| Full-test Brier | 0,081909 | 0,081934 | +0,000025 |
| Full-test ECE | 0,008245 | 0,007829 | −0,000416 |
| Full-test FP | 1.545 | 1.526 | −19 |
| Full-test TP | 70.573 | 70.390 | −183 |
| Runtime-candidate FP / 9.504 | 164 | 162 | −2 |
| Runtime-candidate TP / 14.572 | 11.256 | 11.175 | −81 |
| OpenPhish tổng TP / 130 | 89 | 91 | +2 |
| OpenPhish ordinary TP / 40 | 6 | 5 | −1 |
| Representative malicious TP / 34 | 22 | 22 | 0 |
| Representative benign FP / 25 | 0 | 0 | 0 |
| Targeted benign FP / 3 | 0 | 0 | 0 |
| SAFE VN candidate FP / 1.400 | 0 | 1 | +1 |

Candidate tăng OpenPhish tổng recall `1,54` điểm phần trăm nhưng giảm ordinary-looking `2,50` điểm phần trăm. Representative probability trung bình cũng giảm từ `0,896627` xuống `0,894769`; không có case bổ sung vượt threshold. Final-test runtime-candidate recall giảm từ `77,2440%` xuống `76,6882%`, trong khi FPR giảm `0,0210` điểm phần trăm. Đây là precision/recall trade-off bất lợi cho mục tiêu remediation.

Hai gate thất bại: representative malicious chỉ `22/34` thay vì tối thiểu `26/34`, và SAFE VN candidate có `1/1.400` false positive thay vì `0/1.400`. OpenPhish tổng non-regression, representative benign và targeted benign đều đạt. Quyết định cuối là `NO-GO`; artifacts v4 không được export hoặc provision.

### Liên kết Artifacts

- Pre-registered protocol: `ml/configs/v4-time-forward-protocol.json`
- Public snapshot manifest: `ml/experiments/v4-time-forward-snapshot.json`
- V3 data-only config: `ml/configs/v3-time-forward-data.json`
- V4 selected config: `ml/configs/v4-time-forward-ternary-tld.json`
- V4 feature contract: `ml/contracts/domain_feature_contract.v4.json`
- Selection report: `ml/experiments/v4-weight-ablation-selection.json`
- Final report: `ml/experiments/v4-final-evaluation.json`
- Private selected model: `ml/data/derived/v4-time-forward-ternary-tld/models/domain_threat_lgbm_raw.txt` (Git-ignored; SHA-256 `66f07894728d7c64292f4fad9f8c75d2a35d863921c82bb82b06cfee74c4c2ce`)

## Thử nghiệm v5 char-linear log-odds ensemble

### Mục tiêu (Objectives)

- Kiểm tra một representation khác đáng kể so với LightGBM handcrafted + fixed-width TF-IDF của v3/v4, không thêm token hoặc domain lấy từ frozen representative packet.
- Đo khả năng tổng quát hóa trên development cohort time-forward mới và chỉ mở final inputs khi candidate không làm giảm validation runtime-candidate true positive hoặc tăng false positive.
- Giữ chi phí triển khai thấp bằng một linear expert nhỏ, đã calibration, chỉ được blend vào v3 control nếu chứng minh được giá trị bổ sung.
- Dừng family này ngay tại selection khi trade-off precision/recall bất lợi, thay vì dò thêm weight hoặc threshold theo kết quả đã quan sát.

### Phương pháp & Lý do (Methodology & Rationale)

| Quyết định | Phương pháp chọn | Các phương pháp thay thế | Lý do |
|---|---|---|---|
| Representation | Character TF-IDF `2–5` gram trên domain đã bỏ public suffix, tối đa `4.096` feature, fit trên train | Thêm feature thủ công; tăng LightGBM weight; deep sequence model | Char n-gram kiểm tra trực tiếp lexical shape và composition; thay đổi đủ lớn so với v4 nhưng vẫn rẻ, giải thích được và không cần online dependency |
| Linear expert | `SGDClassifier(loss=log_loss, L2, average=true)`, Platt calibration trên calibration partition | Logistic regression batch; neural encoder | SGD xử lý được `1.930.618` train rows với memory hữu hạn; calibration giữ phép blend trong probability/log-odds space có nghĩa |
| Ensemble | Weighted log-odds với v3 control tại weight `0,1/0,2/0,3` | Trung bình probability; thay thế hoàn toàn v3 | Log-odds blend bảo toàn vai trò control và giới hạn ảnh hưởng expert mới; ba weight được pre-register trước train |
| Development cohort | `349` PhishTank rows sau 2026-08-18, ordinary-looking và không trùng partitions/frozen/prior development | Reuse OpenPhish v4; chọn theo representative | Cohort mới có thời gian và provenance rõ; frozen packet không tham gia selection |
| Final holdout | PhishDestroy Primary Active tải sau protocol, loại toàn bộ group có trong PhishTank hiện tại | Mở final test; chia ngẫu nhiên train | Source-disjoint holdout tạo phép kiểm tra final mới; checksum và exclusions được đóng băng trước model selection |
| Stop rule | Validation candidate FP không tăng và TP không giảm so với v3; không đạt thì không mở final inputs | Chấp nhận TP giảm để lấy FP; thử thêm weight nhỏ | Mục tiêu là cải thiện generalization chứ không đổi recall lấy precision; stop rule ngăn tuning nối tiếp theo kết quả vừa thấy |

### Cách thức Thực hiện (Implementation Details)

Protocol `ml/configs/v5-char-linear-ensemble-protocol.json` được commit ở `3b82e22` trước khi tải PhishDestroy hoặc train. Field `ordinary_looking_contract` ban đầu trỏ nhầm v4, trong khi helper định nghĩa neutral TLD bằng giá trị `0` của contract v3; lỗi cấu hình được sửa ở `ea9ec1f` trước train và trước mọi final prediction. Tại thời điểm sửa chỉ có aggregate count bằng `0` từ lần build không hợp lệ; không có domain, score hoặc label final nào được dùng để đổi protocol.

Builder xác minh checksum của bốn partition, PhishTank, prior development và frozen labels; canonicalize theo cùng evaluation-group policy; loại `1.936.767` baseline groups, `140` frozen groups và `467` prior-development groups. PhishDestroy Primary Active được tải sau protocol với SHA-256 `1de52204...79f40`; holdout loại thêm toàn bộ `32.963` current-PhishTank groups. Kết quả là `349` development rows và `81.528` source-disjoint holdout rows, cross-cohort overlap bằng `0`.

Selector fit vocabulary/IDF chỉ trên train, train linear expert với weighting policy đã có của v4, rồi Platt-calibrate trên calibration partition. Selection chỉ đọc train, calibration, validation và v5 development; report ghi `forbidden_inputs_read=[]`. Do không weight nào đạt guardrail, selector không đọc final test, PhishDestroy holdout, OpenPhish v4 holdout hoặc frozen representative packet; final evaluator không được chạy.

AI agent sử dụng Codex (GPT-5) với chiến lược pre-registration, checksum-first và early-stop theo guardrail. Số subagent là `0`; không dùng voting. Kiểm soát chất lượng gồm hash pinning, group-disjoint manifest, train-only vocabulary, explicit input audit, unit tests cho log-odds blend/metric filter và full ML test suite. Con người giữ quyền duyệt signed labels và rollout; agent chỉ train/evaluate offline, không export model, provision bundle, restart service, đổi traffic scope hoặc bật `enforce`.

### Số liệu (Metrics & Results)

#### Integrity và cohort

| Chỉ số | Kết quả |
|---|---:|
| PhishTank raw / canonical rows | 73.191 / 73.043 |
| Development window trước ordinary filter | 813 |
| Development ordinary-looking rows | 349 |
| PhishDestroy raw / source-disjoint holdout rows | 120.606 / 81.528 |
| PhishDestroy ordinary-looking holdout rows | 44.419 |
| Cross-cohort group overlap | 0 |
| Character vocabulary | 4.096 |
| Selection wall time | 627,25 giây |
| Forbidden inputs được đọc | 0 |

#### Selection tại threshold `0,92`

| Candidate | Validation FP / 11.032 | Validation TP / 15.324 | Development TP / 349 | Delta TP validation | Eligible |
|---|---:|---:|---:|---:|---|
| V3 control | 238 | 11.529 | 196 | — | guardrail |
| Linear expert | 284 | 7.337 | 141 | −4.192 | không |
| Blend weight `0,1` | 229 | 11.323 | 185 | −206 | không |
| Blend weight `0,2` | 220 | 11.040 | 180 | −489 | không |
| Blend weight `0,3` | 214 | 10.720 | 172 | −809 | không |

Weight `0,1` giảm validation FP từ `238` xuống `229` và logloss từ `0,286526` xuống `0,286230`, nhưng mất `206` validation TP cùng `11` development TP. Khi tăng weight, FP tiếp tục giảm nhưng TP giảm nhanh hơn; linear expert độc lập cũng kém control trên cả precision lẫn recall. Mẫu hình nhất quán trên validation và time-forward development cho thấy expert mới không bổ sung lexical signal cần thiết cho mục tiêu malicious generalization.

Quyết định selection là `NO_ELIGIBLE_CANDIDATE`. Vì stop rule kích hoạt trước final evaluation, v5 không tạo kết quả representative mới và không thay đổi mốc `22/34` của control; PhishDestroy holdout vẫn chưa bị tiêu thụ bởi model prediction. Chi phí chính là khoảng 10,5 phút train/selection và gần 2,83 GB peak RAM trong local run; đổi lại, thử nghiệm loại được một hướng representation/ensemble có vẻ hấp dẫn nhưng thực tế tạo precision/recall trade-off sai mục tiêu.

### Liên kết Artifacts

- Pre-registered protocol: `ml/configs/v5-char-linear-ensemble-protocol.json`
- Public snapshot manifest: `ml/experiments/v5-char-linear-snapshot.json`
- Selection report: `ml/experiments/v5-char-linear-selection.json`
- Cohort builder: `ml/src/build_v5_char_linear_snapshot.py`
- Selector và unit tests: `ml/src/select_v5_char_linear.py`, `ml/tests/test_v5_char_linear.py`
- Private vectorizer/classifier/calibrator: `ml/data/derived/v5-char-linear-20260824/models/` (Git-ignored; SHA-256 lần lượt `456326d8...fc388`, `0e221e75...f23b9`, `9d917312...d3905`)

### Phương án candidate kế tiếp

Candidate kế tiếp cần thực hiện ba lớp, theo thứ tự sau:

1. Dừng ablation weight/threshold/alpha trên char-linear v5. Cả ba weight đã cho cùng một hướng trade-off; thêm điểm weight nhỏ hơn sau khi xem selection report sẽ có giá trị thấp và tăng nguy cơ overfit quy trình.
2. Tách lexical-model generalization trên hostname khỏi end-to-end runtime recall với exact threat-feed membership/freshness. Redirect, cloaking và security interstitial thuộc runtime/evidence context; threat-context preset hiện tại đã cho `0/12` recovery và `1/25` benign collision nên chưa đủ điều kiện mở rộng.
3. Nếu tiếp tục model research, ưu tiên source-adversarial/contrastive data design với source-held-out validation mới, hoặc bổ sung tín hiệu URL/path/redirect có provenance ở một engine riêng. Chỉ khởi động vòng này khi có protocol và development cohort mới; không thêm exact 12 domain còn lại hoặc token chỉ xuất hiện trong frozen packet.

PhishDestroy holdout v5 vẫn chưa được prediction và có thể được bảo toàn cho một candidate khác biệt thực chất đã pre-register, nhưng không dùng để chọn representation. Không chọn phương án chỉ hạ threshold: sweep hiện tại cho thấy threshold `0,90` đạt `22/34` với `0/25` FP; threshold `0,85` đạt `25/34` nhưng tạo `1/25` FP. Candidate mới chỉ được xem xét cho local staging `shadow` khi đạt tối thiểu representative recall `26/34`, giữ representative benign FP `0/25`, targeted benign challenge `0/3`, cross-service probability/response parity trong tolerance `10^-6`, ML errors bằng `0` và enforce promotions bằng `0`.

### Liên kết Artifacts

- Owner-approved labels: `ml/evidence/representative-replay/run-20260823-owner-approved-addendum/`
- Candidate v2 report: `docs/research/ml/suffix-debiased-hard-negative-candidate.md`
- Private contribution report: `ml/data/derived/v2-suffix-debiased-hard-negatives/representative-fn-contributions-00b6bab.json` (Git-ignored; SHA-256 `a3fbd8638121ad638473081dd8e8afaf39d8b4cde7b8fba54f2b18b91806e088`)
- Private initial Firecrawl results: `ml/data/derived/v2-suffix-debiased-hard-negatives/firecrawl-fn-refresh-20260824/results.jsonl` (Git-ignored; SHA-256 `c40b7111c0b20b5218df6cd9e4865a4ae798182494fffc0a55c4195887627866`)
- Private retry Firecrawl results: `ml/data/derived/v2-suffix-debiased-hard-negatives/firecrawl-fn-refresh-20260824-retry1/results.jsonl` (Git-ignored; SHA-256 `d68a1039b330e8a3ca0c30275e297b4fae080b13c9699cddb10c73e76376247a`)
- Feature implementation: `ml/src/build_features.py`
- Leakage policy: `ml/src/training_data.py`
- Control config: `ml/configs/v2-leakage-free-control.json`
- Candidate config: `ml/configs/v3-leakage-free-context.json`
- Feature contracts: `ml/contracts/domain_feature_contract.v2.json`, `ml/contracts/domain_feature_contract.v3.json`
- Private control report: `ml/data/derived/v2-leakage-free-control/models/model_report.json` (Git-ignored; SHA-256 `90f87d51c579e80fccc0c91f0b9a37dcc2ca3da2c307b5867e7ba1aa8663f718`)
- Private candidate report: `ml/data/derived/v3-leakage-free-context/models/model_report.json` (Git-ignored; SHA-256 `062f36178aa6792812a8ff9eab0eb4170d206472ef5b902fe4e27d79ebd45794`)
- Private candidate model: `ml/data/derived/v3-leakage-free-context/models/domain_threat_lgbm_raw.txt` (Git-ignored; SHA-256 `e375ec1720af854362084d509e262dd0c7e1e6e91c48a4cb50060630ab2d463a`)
- Private generic-weight ablation: `ml/data/derived/v2-suffix-debiased-hard-negatives/candidate-positive-ablation-20260824.json` (Git-ignored; SHA-256 `70afbaa09eb98b0b1bd89045a76c1c2afff08cc3f5695e5e485c244aa01a48ac`)
- Private hard-positive ablation: `ml/data/derived/v2-suffix-debiased-hard-negatives/hard-positive-mining-ablation-20260824.json` (Git-ignored; SHA-256 `e6924c03d149455d5228b6b98040fb89314054ba7057c1ef84da7c75b9838b93`)
- Time-forward public manifest: `ml/experiments/v4-time-forward-snapshot.json`
- V4 selection/final reports: `ml/experiments/v4-weight-ablation-selection.json`, `ml/experiments/v4-final-evaluation.json`
- V5 protocol/snapshot/selection reports: `ml/configs/v5-char-linear-ensemble-protocol.json`, `ml/experiments/v5-char-linear-snapshot.json`, `ml/experiments/v5-char-linear-selection.json`
- Threat-context protocol/report: `ml/configs/threat-context-production-free-20260824.json`, `ml/experiments/threat-context-production-free-20260824.json`
- Threat-context R&D report: `docs/research/security/threat-context-evaluation.md`

---

## Lịch sử Thay đổi (Version History)

| Ngày | Thay đổi | Tác giả |
|---|---|---|
| 2026-08-24 | Pre-register v5 char-linear ensemble, freeze `349` development và `81.528` PhishDestroy holdout rows; dừng ở `NO_ELIGIBLE_CANDIDATE` trước final inputs vì cả ba blend đều giảm validation/development TP | Codex (GPT-5) |
| 2026-08-24 | Đo production-free threat context và giữ `NO-GO` vì phục hồi `0/12` model false-negative nhưng tạo `1/25` benign collision | Codex (GPT-5) |
| 2026-08-24 | Freeze time-forward cohorts, thử sáu ablation v3/v4, mở final holdout một lần và giữ v4 `NO-GO` do representative `22/34` cùng SAFE VN candidate `1/1.400` FP | Codex (GPT-5) |
| 2026-08-24 | Sửa leakage theo shared-hosting tenant, dựng control v2 sạch, triển khai/evaluate feature contract v3 và ghi nhận quyết định `NO-GO` sau năm ablation | Codex (GPT-5) |
| 2026-08-24 | Phân tích contribution của 13 false-negative, chạy bounded Firecrawl refresh và xác định hướng hard-positive/feature v3 không leakage | Codex (GPT-5) |
