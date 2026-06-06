# Implementation Plan: Redis Pub/Sub Analysis Config Reload

Tài liệu này chuyển thiết kế ở `analysis-config-pubsub-reload` thành các bước triển khai nhỏ, có thể verify độc lập và hạn chế blast radius trong từng commit.

## Mục tiêu triển khai

Hoàn thiện cơ chế hot-reload `analysis_config` đa node cho cả `core-api` và `dns-resolver`, với:

- SQLite là nguồn chân lý duy nhất
- Redis Pub/Sub là đường truyền tín hiệu thời gian thực
- vòng reconciliation là lớp tự phục hồi khi miss event
- fail-open khi Redis gặp sự cố

## Nguyên tắc thực hiện

- Giữ toàn bộ orchestration trong `internal/risk`
- Chỉ publish revision event, không publish full config
- Tái sử dụng `analyzerMu` và `configRevision`
- Ưu tiên các bước có thể test cục bộ bằng unit test hoặc integration test ngắn

## Giai đoạn 1: Mở rộng Redis wrapper

### Mục tiêu

Thêm đủ API Pub/Sub vào `internal/cache.Redis` mà không làm rò raw client ra ngoài.

### Công việc

- Thêm `PublishJSON(ctx, channel string, value any) error`
- Thêm `Subscribe(ctx, channel string) (<-chan string, func() error, error)`
- Chuẩn hóa hành vi `ErrDisabled` khi Redis không được cấu hình

### File dự kiến

- [internal/cache/redis.go](D:/Quorix/services/safe-zone/internal/cache/redis.go)

### Verification

- test publish/subscribe round-trip với Redis thật hoặc `miniredis` nếu tương thích
- test disabled behavior trả về `ErrDisabled`

## Giai đoạn 2: Gom logic apply config vào một đường duy nhất

### Mục tiêu

Loại bỏ việc swap analyzer rải rác để local write, remote reload, startup load, và reconciliation dùng cùng một helper.

### Công việc

- Thêm helper kiểu `applyAnalysisConfigLocked(cfg config.AnalysisConfig)`
- Thêm helper ngoài lock kiểu `applyAnalysisConfig(cfg config.AnalysisConfig, source string)`
- Bổ sung tracking nhẹ cho `last reload source` và `last reload time`

### File dự kiến

- [internal/risk/service.go](D:/Quorix/services/safe-zone/internal/risk/service.go)

### Verification

- test `UpdateAnalysisConfig` vẫn invalidates cache revision như hiện tại
- test `GetAnalysisConfig` vẫn trả clone an toàn

## Giai đoạn 3: Publish event sau khi ghi SQLite thành công

### Mục tiêu

Writer node phát tín hiệu reload ngay sau khi source of truth đã bền vững.

### Công việc

- Định nghĩa payload event nội bộ
- Publish sau `store.SetAnalysisConfig(cfg)` và sau local apply
- Giữ request thành công ngay cả khi publish lỗi, chỉ log warning

### File dự kiến

- [internal/risk/service.go](D:/Quorix/services/safe-zone/internal/risk/service.go)

### Verification

- test publish failure không làm `UpdateAnalysisConfig` fail
- test `ResetAnalysisConfig` cũng publish cùng cơ chế

## Giai đoạn 4: Thêm subscriber lifecycle vào `risk.Service`

### Mục tiêu

Mọi process dùng `risk.Service` tự subscribe và hot-reload mà không cần code riêng ở `core-api` hay `dns-resolver`.

### Công việc

- Mở rộng `risk.Options` với:
  - `ConfigReloadChannel`
  - `ConfigReloadPollInterval`
  - `ConfigReloadEnabled`
  - `NodeRole`
- Khởi động subscriber trong `NewService` khi Redis + SQLite cùng available
- Dùng reconnect loop với bounded exponential backoff
- Bảo đảm backoff bị ngắt ngay khi shutdown

### File dự kiến

- [internal/risk/service.go](D:/Quorix/services/safe-zone/internal/risk/service.go)
- [internal/risk/env.go](D:/Quorix/services/safe-zone/internal/risk/env.go)

### Verification

- test ignore self-loop khi `event.revision == currentConfigRevision()`
- test remote event gây reload khi revision khác
- test disconnect path retry lại subscribe

## Giai đoạn 5: Thêm reconciliation loop

### Mục tiêu

Tự chữa drift khi node bỏ lỡ Pub/Sub event trong lúc reconnect hoặc Redis tạm outage.

### Công việc

- Thêm ticker đọc `analysis_config` từ SQLite theo chu kỳ
- So revision với local `configRevision`
- Nếu khác thì reload và log nguồn `reconcile`

### File dự kiến

- [internal/risk/service.go](D:/Quorix/services/safe-zone/internal/risk/service.go)

### Verification

- test node hội tụ lại config mới dù không nhận event
- test reconciliation không reload lặp vô ích khi revision giữ nguyên

## Giai đoạn 6: Wiring env và observability

### Mục tiêu

Khi deploy, operator có thể bật/tắt và debug hành vi reload bằng env rõ ràng.

### Công việc

- Thêm env:
  - `SAFE_ZONE_CONFIG_RELOAD_ENABLED`
  - `SAFE_ZONE_CONFIG_RELOAD_CHANNEL`
  - `SAFE_ZONE_CONFIG_RELOAD_POLL_SECONDS`
- Gắn `NodeRole` mặc định theo process (`core-api`, `dns-resolver`) nếu tiện
- Log các sự kiện:
  - publish success/failure
  - subscribe disconnect/retry
  - duplicate/self-loop ignore
  - pubsub reload apply
  - reconcile self-heal

### File dự kiến

- [internal/risk/env.go](D:/Quorix/services/safe-zone/internal/risk/env.go)
- [cmd/core-api/main.go](D:/Quorix/services/safe-zone/cmd/core-api/main.go)
- [cmd/dns-resolver/main.go](D:/Quorix/services/safe-zone/cmd/dns-resolver/main.go)

### Verification

- kiểm tra log và revision hiện hành trong runtime
- kiểm tra single-node không Redis vẫn hoạt động như cũ

## Giai đoạn 7: Test tích hợp trọng điểm

### Mục tiêu

Chứng minh đầy đủ các acceptance criteria quan trọng nhất trước khi merge.

### Test cases ưu tiên

1. Node A update config, Node B nhận event và reload.
2. Node B nhận lại cùng revision và bỏ qua ngay, không đọc SQLite.
3. Publish lỗi nhưng writer vẫn thành công cục bộ.
4. Node B miss event trong lúc subscriber down, sau đó reconciliation kéo về revision mới.
5. Shutdown trong lúc subscriber đang backoff không bị treo.

### Gói test tối thiểu

```bash
go test ./internal/cache ./internal/risk ./cmd/core-api ./cmd/dns-resolver
```

Nếu thay đổi lan rộng hơn:

```bash
go test ./...
```

## Thứ tự commit khuyến nghị

1. `internal/cache`: Pub/Sub wrapper + tests
2. `internal/risk`: shared apply helper
3. `internal/risk`: publish event on config update
4. `internal/risk`: subscriber + backoff
5. `internal/risk`: reconciliation loop
6. env wiring + docs + final tests

## Điểm cần cảnh giác khi code

- Không để subscriber tin payload hơn SQLite
- Không để publish failure làm request config update trả lỗi giả
- Không để reconnect/backoff chặn shutdown
- Không để duplicate event gây I/O SQLite lặp vô ích
- Không để reconciliation tranh lock quá lâu với luồng analyze nóng
