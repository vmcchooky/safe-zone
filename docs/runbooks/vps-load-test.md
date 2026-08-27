# VPS Capacity Verification Runbook

> **Canonical benchmark reference:** [docs/benchmarks/local-capacity-loadtest-20260827.md](../benchmarks/local-capacity-loadtest-20260827.md)  
> **Release Gate criterion:** Gate A, Criterion A6 ([docs/runbooks/release-gate.md](release-gate.md))

Tài liệu này hướng dẫn quy trình kiểm tra công suất rút gọn trên máy chủ VPS đích trước khi phát hành sản phẩm. **Không tái chạy máy móc toàn bộ bài test dài của môi trường local.** Bài kiểm tra này đo lường các mốc vận hành thực tế trên phần cứng VPS độc lập.

---

## 1. Nguyên tắc An toàn & Giới hạn Môi trường

1. **Chỉ chạy nội bộ qua loopback / Docker network:**
   - Dùng project Compose cô lập `safe-zone-loadtest` qua `docker-compose.loadtest.yml`.
   - Lưu lượng phát sinh từ service `loadgen` (`cmd/load-ramp`) trong cùng mạng Docker.
   - **Tuyệt đối không bắn tải vào public hostname, public IP hoặc hạ tầng ngoài phạm vi được phê duyệt.**
2. **Ghi lại cấu hình phần cứng (Hardware / VPS Class):**
   - Nhà cung cấp & gói VPS (ví dụ: Hetzner CPX21 — 2 vCPU / 4 GB RAM / AMD EPYC).
   - CPU model, số core/threads, dung lượng RAM, swap, kernel version (`uname -r`), Docker Engine version (`docker version`).
3. **Phân loại giới hạn (Bottleneck Classification):**
   - `APP_LIMITED`: CPU core của `core-api` đạt saturation, latency tăng tuyến tính, `loadgen` chưa hết năng lực.
   - `GENERATOR_LIMITED`: `loadgen` đạt ngưỡng scheduling drops hoặc CPU generator bão hòa trước khi server đạt tải.
   - `DOCKER_LIMITED`: Bridge network, iptables/conntrack, hoặc Docker socket proxy đạt giới hạn throughput.
   - `OS_LIMITED`: File descriptor ceiling (`ulimit -n`), socket port exhaustion (`ephemeral ports`), memory paging.

---

## 2. Stop Guards (Quy tắc Dừng Khẩn cấp)

Ngắt ngay lập tức toàn bộ quá trình phát tải nếu xuất hiện một trong các điều kiện sau:
- **Free RAM:** Bộ nhớ RAM khả dụng trên VPS tụt xuống dưới **600 MB** (tránh OOM-killer hệ thống).
- **Lỗi ứng dụng:** Tỉ lệ HTTP 5xx hoặc transport error vượt quá **0.1%** trong bất kỳ cửa sổ 10 giây nào.
- **Container restart:** `core-api` hoặc `redis` bị restart bất ngờ (`ExitCode != 0`).
- **Disk growth:** Phân vùng root (`/`) có dung lượng trống còn lại dưới **1 GB**.

---

## 3. Các Bước Kiểm Tra Rút Gọn

### Bước 0: Chuẩn bị Môi trường Cô lập

```bash
# Khởi động stack load-test cô lập (không ảnh hưởng staging/production)
docker compose -p safe-zone-loadtest \
  -f docker-compose.yml \
  -f docker-compose.loadtest.yml \
  up -d --build core-api

# Kiểm tra trạng thái sẵn sàng
curl -fsS http://127.0.0.1:18080/healthz
```

---

### Workload 1: Health Ceiling (`GET /healthz`)

Mục tiêu: Xác định trần chuyển tiếp HTTP tối đa của runtime và network layer trên VPS.

```bash
docker compose -p safe-zone-loadtest \
  -f docker-compose.yml \
  -f docker-compose.loadtest.yml \
  run --rm loadgen \
  -url http://core-api:8080 \
  -workload health \
  -rate 10000 \
  -duration 30s \
  -warmup 10s \
  -conns 64
```

*Kỳ vọng:* Không có lỗi (0 errors, 0 drops), keep-alive $\ge 99.9\%$, p99 $< 15$ ms. Nếu đạt, có thể tăng thử nghiệm lên 15k–20k RPS để đo trần thực tế của VPS.

---

### Workload 2: Analyze Path (`GET /v1/analyze`)

Mục tiêu: Đo lường thông lượng xử lý phân tích tên miền xoay vòng (8.192 tên miền).

```bash
docker compose -p safe-zone-loadtest \
  -f docker-compose.yml \
  -f docker-compose.loadtest.yml \
  run --rm loadgen \
  -url http://core-api:8080 \
  -workload analyze-mixed \
  -rate 2500 \
  -duration 45s \
  -warmup 15s \
  -conns 64
```

*Kỳ vọng:* Tỉ lệ đạt $\ge 99\%$, zero HTTP errors, live heap ổn định. Ghi nhận mốc bão hòa clean của VPS (thường dao động 2.500–5.000 RPS tùy theo số vCPU).

---

### Workload 3: URL ML Shadow A/B Overhead

Mục tiêu: Xác thực phụ tải thực tế của chuyên gia URL ML ở chế độ shadow so với khi disabled.

**A. URL ML disabled (baseline):**
```bash
LOADTEST_URL_ML_MODE=disabled \
docker compose -p safe-zone-loadtest \
  -f docker-compose.yml \
  -f docker-compose.loadtest.yml \
  run --rm loadgen \
  -url http://core-api:8080 \
  -workload url-shadow \
  -rate 2000 \
  -duration 45s \
  -conns 64
```

**B. URL ML shadow 100%:**
```bash
LOADTEST_URL_ML_MODE=shadow \
docker compose -p safe-zone-loadtest \
  -f docker-compose.yml \
  -f docker-compose.loadtest.yml \
  run --rm loadgen \
  -url http://core-api:8080 \
  -workload url-shadow \
  -rate 2000 \
  -duration 45s \
  -conns 64
```

*Kỳ vọng:* Parity kết quả chính giữ nguyên $100\%$; CPU phụ trội của shadow trong ngưỡng cho phép (khoảng $+20\%$ đến $+35\%$ CPU); latency p95 của URL ML $< 2.000\ \mu\text{s}$; zero prediction errors.

---

### Workload 4: Short Soak Test (15–30 phút, Telemetry 5%)

Mục tiêu: Đảm bảo bộ nhớ không bị rò rỉ (memory leak), goroutine ổn định, và tốc độ phình SQLite được khống chế bởi telemetry write sampling.

```bash
# Đặt cấu hình sampling thực tế của production (5%)
# Chạy với tải vận hành bền vững (ví dụ: 1.000–1.500 RPS)
docker compose -p safe-zone-loadtest \
  -f docker-compose.yml \
  -f docker-compose.loadtest.yml \
  run --rm loadgen \
  -url http://core-api:8080 \
  -workload analyze-mixed \
  -rate 1200 \
  -duration 15m \
  -warmup 30s \
  -conns 64
```

*Trong lúc chạy soak, quan sát:*
- `curl -fsS http://127.0.0.1:18080/metrics | jq .runtime`: `heap_alloc_mb` phải đạt bình nguyên (plateau $< 15$ MB), `goroutines` không tăng lũy tiến.
- `ls -lh /var/lib/docker/volumes/...`: Kích thước file database SQLite và WAL không tăng đột biến.

---

## 4. Báo Cáo & Thu Thập Bằng Chứng

Sau khi hoàn thành, xuất bản ghi kết quả vào thư mục `tmp/bench/vps-<timestamp>/` gồm:
1. `summary.json` cho từng workload từ output của `loadgen`.
2. File ghi thông tin phần cứng VPS: `uname -a`, `lscpu`, `free -m`.
3. Snapshot `/metrics` trước và sau khi cooldown 10 phút.
4. Ghi nhận verdict của Gate A6:
   - `VPS_CAPACITY_PASS`: Đạt thông lượng mục tiêu vận hành không phát sinh lỗi.
   - `VPS_CAPACITY_INSUFFICIENT`: Bị nghẽn phần cứng hoặc không đạt ngưỡng tối thiểu.

Dọn dẹp môi trường kiểm tra:
```bash
docker compose -p safe-zone-loadtest \
  -f docker-compose.yml \
  -f docker-compose.loadtest.yml \
  down -v
```
