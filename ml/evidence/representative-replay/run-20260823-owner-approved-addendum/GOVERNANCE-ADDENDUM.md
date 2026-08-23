# Reviewed-unclassifiable waiver addendum

Trạng thái: **OWNER-APPROVED GOVERNANCE ATTESTATION / NOT CRYPTOGRAPHICALLY SIGNED**
Ngày lập: 2026-08-23 (Asia/Saigon)

Tài liệu này tham chiếu archive bất biến
`ml/evidence/representative-replay/run-20260808/`. Nó không sửa hoặc thay thế
signed evidence. Người dùng đã xác nhận trong phiên review rằng các case đã
được review nhưng không thể phân loại có thể dùng waiver. Product và Security
đã ghi quyết định, ngày và owner bên dưới; đây là governance attestation,
không phải detached cryptographic signature.

## Evidence update

- Case: `replay-0072`
- Domain: `ahshyallegrolokalnie.pl-835347547.click`
- Kết luận mới trong working copy: `malicious`, confidence `high`
- Outcome: `true_positive`; model would-block tại probability `0.9994931`
- Evidence: Chrome hiển thị interstitial đỏ `Dangerous site`; reviewer xác
  nhận domain lừa đảo/không an toàn ngày 2026-08-23.
- Screenshot SHA-256:
  `3c7f33dd56077994ad9d660a359dfe459d6b5a0420eace5829199946d8142831`

Không truy cập lại domain trong quá trình tạo addendum. Ảnh do reviewer cung
cấp được sao chép nguyên byte vào working evidence directory.

## Reviewed-unclassifiable waiver

Sau evidence update, waiver áp dụng chính xác cho:

| Thuộc tính | Giá trị |
|---|---:|
| Reviewed-unclassifiable cases | 78 |
| Model would-block | 33 |
| Model would-pass | 45 |
| Case-ID SHA-256 | `efdaa81a8fc9cb6350aff67a1e1513f4b696a71f7d11b3e8c728fcf86e6acb27` |

Các case này đã có review entry của người được ủy quyền, nhưng nội dung hiện
không đủ để gán nhãn nhị phân. Waiver chỉ loại chúng khỏi FPR/recall; không
biến chúng thành benign hoặc malicious và không cho phép tuyên bố FPR trên
78 case đó.

Reporter chỉ chấp nhận waiver khi `case_count`, `would_block_count` và SHA-256
của tập case ID khớp output thực tế. Bất kỳ thay đổi tập case nào cũng làm
waiver mất hiệu lực và khôi phục approval blocker.

## Metrics của working copy

| Metric | Kết quả |
|---|---:|
| Review coverage | 137/137 |
| Benign | 25 |
| Malicious | 34 |
| Unknown/unresolved | 78 |
| False positives | 0/25 |
| True positives | 26/34 |
| Recall | 0.7647 |
| Reporter exit | 0 |
| Review gate | `ready_for_review_with_reviewed_unclassifiable_waiver` |

## Canary boundary đề xuất

- Scope: instance tách biệt hoặc internal allowlist; không thay đổi stack
  production dùng chung.
- Traffic cap: tối đa 1% eligible requests.
- Observation window: tối thiểu 60 phút và 1.000 prediction attempts.
- Rollback theo runbook khi service lệch revision/threshold, `ml_state` không
  `ready`, errors/parity mismatch tăng, confirmed critical-benign FP xuất
  hiện hoặc promotion vượt scope.
- Không bật `enforce` cho tới khi exact release commit/CI/image digests,
  last-known-good snapshot và runtime snapshot của hai service đã khép kín.

## Owner decisions

### Product owner

- [X] Chấp nhận exclusion của đúng 78 reviewed-unclassifiable cases nêu trên.
- [X] Chấp nhận metrics chỉ dựa trên 25 benign và 34 malicious cases.
- [X] Chấp nhận canary scope, traffic cap và observation window.
- Decision/date/owner: August 23, 2026 Vo Manh Cuong - Chooky

### Security owner

- [X] Chấp nhận evidence handling và giới hạn của Chrome warning screenshot.
- [X] Chấp nhận 33 reviewed-unclassifiable would-block cases là uncertainty
  được theo dõi trong canary, không phải confirmed true positives.
- [X] Chấp nhận rollback boundary và source retention.
- Decision/date/owner: August 23, 2026 Vo Manh Cuong - Chooky

## Provenance

Signed source hashes trước và sau working-copy generation không đổi:

| File | SHA-256 |
|---|---|
| `labels.csv` | `bdef87e4e775740a32713d0b471d1f37d2ff7ec62eed591f424e41498cb75d15` |
| `review-summary.json` | `79131ec8ffbf97a224525914d77dd3692e8a361667b18f07fb54cefd51b3d8c9` |
| `approval-packet.md` | `f2f5282dd0d2700bf7dbf0038121fd62774850cf25aa1270b4c9f4bb05ee4639` |

Working files phải được checksum lại sau khi owner decisions được ghi; các
hash trung gian không phải chữ ký hoặc release identity.
