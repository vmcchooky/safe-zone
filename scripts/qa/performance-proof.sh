#!/usr/bin/env sh
set -eu

api_url="${SAFE_ZONE_BENCH_API_URL:-http://localhost:8080/v1/analyze}"
out_dir="${SAFE_ZONE_BENCH_OUT_DIR:-tmp/performance-proof/$(date -u +%Y%m%dT%H%M%SZ)}"
duration="${SAFE_ZONE_BENCH_DURATION:-60s}"
hit_rate="${SAFE_ZONE_BENCH_HIT_RATE:-500}"
miss_rate="${SAFE_ZONE_BENCH_MISS_RATE:-50}"
hit_concurrency="${SAFE_ZONE_BENCH_HIT_CONCURRENCY:-64}"
miss_concurrency="${SAFE_ZONE_BENCH_MISS_CONCURRENCY:-16}"
warmup="${SAFE_ZONE_BENCH_WARMUP:-200}"
hit_domains="${SAFE_ZONE_BENCH_HIT_DOMAINS:-google.com,facebook.com,wikipedia.org,example.com}"
max_error_rate="${SAFE_ZONE_BENCH_MAX_ERROR_RATE:-1.0}"
hit_min_cache="${SAFE_ZONE_BENCH_HIT_MIN_CACHE_RATE:-95.0}"
hit_max_p95="${SAFE_ZONE_BENCH_HIT_MAX_P95:-150ms}"
hit_max_p99="${SAFE_ZONE_BENCH_HIT_MAX_P99:-300ms}"
miss_max_p95="${SAFE_ZONE_BENCH_MISS_MAX_P95:-750ms}"
miss_max_p99="${SAFE_ZONE_BENCH_MISS_MAX_P99:-1500ms}"
sample_interval="${SAFE_ZONE_BENCH_STATS_INTERVAL:-2}"
docker_containers="${SAFE_ZONE_BENCH_DOCKER_CONTAINERS:-}"

mkdir -p "$out_dir"
load_test_bin="$out_dir/load-test"

log() {
  printf '%s\n' "$*"
}

discover_containers() {
  if [ -n "$docker_containers" ]; then
    printf '%s\n' "$docker_containers"
    return
  fi
  if command -v docker >/dev/null 2>&1; then
    docker ps --format '{{.Names}}' | grep -E 'safe-zone|core-api|dns-resolver|redis' || true
  fi
}

sample_docker_stats() {
  containers="$1"
  output="$2"
  if [ -z "$containers" ] || ! command -v docker >/dev/null 2>&1; then
    return 0
  fi
  printf 'timestamp_utc,container,cpu_percent,mem_usage,mem_percent\n' > "$output"
  while :; do
    timestamp="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
    # shellcheck disable=SC2086
    docker stats --no-stream --format "${timestamp},{{.Name}},{{.CPUPerc}},{{.MemUsage}},{{.MemPerc}}" $containers >> "$output" 2>/dev/null || true
    sleep "$sample_interval"
  done
}

summarize_docker_stats() {
  input="$1"
  output="$2"
  if [ ! -s "$input" ]; then
    printf 'Docker stats unavailable. Set SAFE_ZONE_BENCH_DOCKER_CONTAINERS to sample explicit containers.\n' > "$output"
    return
  fi
  awk -F, '
    NR == 1 { next }
    {
      cpu=$3; gsub(/%/, "", cpu)
      mem=$5; gsub(/%/, "", mem)
      count[$2]++
      cpu_sum[$2]+=cpu
      mem_sum[$2]+=mem
      if (cpu > cpu_max[$2]) cpu_max[$2]=cpu
      if (mem > mem_max[$2]) mem_max[$2]=mem
    }
    END {
      printf "container,avg_cpu_percent,max_cpu_percent,avg_mem_percent,max_mem_percent,samples\n"
      for (name in count) {
        printf "%s,%.2f,%.2f,%.2f,%.2f,%d\n", name, cpu_sum[name]/count[name], cpu_max[name], mem_sum[name]/count[name], mem_max[name], count[name]
      }
    }
  ' "$input" > "$output"
}

run_scenario() {
  name="$1"
  rate="$2"
  concurrency="$3"
  extra_args="$4"
  json_file="$out_dir/${name}.json"
  text_file="$out_dir/${name}.txt"

  log "Running $name benchmark..."
  # shellcheck disable=SC2086
  set +e
  "$load_test_bin" \
    -type api \
    -url "$api_url" \
    -scenario "$name" \
    -duration "$duration" \
    -rate "$rate" \
    -concurrency "$concurrency" \
    -warmup "$warmup" \
    -max-error-rate "$max_error_rate" \
    $extra_args \
    > "$text_file" 2>&1
  text_status="$?"
  set -e
  cat "$text_file"
  if [ "$text_status" -ne 0 ]; then
    return "$text_status"
  fi

  # shellcheck disable=SC2086
  "$load_test_bin" \
    -type api \
    -url "$api_url" \
    -scenario "$name" \
    -duration "$duration" \
    -rate "$rate" \
    -concurrency "$concurrency" \
    -warmup "$warmup" \
    -max-error-rate "$max_error_rate" \
    -json \
    $extra_args \
    > "$json_file"
}

containers="$(discover_containers | tr '\n' ' ')"
stats_csv="$out_dir/docker-stats.csv"
stats_summary="$out_dir/docker-stats-summary.csv"

log "Performance proof output: $out_dir"
log "API URL: $api_url"
go build -o "$load_test_bin" ./cmd/load-test
if [ -n "$containers" ]; then
  log "Sampling Docker stats for: $containers"
  sample_docker_stats "$containers" "$stats_csv" &
  stats_pid="$!"
else
  log "Docker stats sampling disabled or no matching containers found."
  stats_pid=""
fi

cleanup() {
  if [ -n "${stats_pid:-}" ]; then
    kill "$stats_pid" 2>/dev/null || true
    wait "$stats_pid" 2>/dev/null || true
  fi
}
trap cleanup EXIT INT TERM

run_scenario "cache-hit" "$hit_rate" "$hit_concurrency" "-domains $hit_domains -require-cache-metric -min-cache-hit-rate $hit_min_cache -max-p95 $hit_max_p95 -max-p99 $hit_max_p99"
run_scenario "cache-miss" "$miss_rate" "$miss_concurrency" "-max-p95 $miss_max_p95 -max-p99 $miss_max_p99"

cleanup
stats_pid=""
summarize_docker_stats "$stats_csv" "$stats_summary"

cat > "$out_dir/README.md" <<EOF
# Safe Zone Performance Proof

- API URL: \`$api_url\`
- Duration per scenario: \`$duration\`
- Cache-hit target: \`$hit_rate req/s\`
- Cache-miss target: \`$miss_rate req/s\`
- Generated at: \`$(date -u +%Y-%m-%dT%H:%M:%SZ)\`

Files:

- \`cache-hit.txt\` and \`cache-hit.json\`
- \`cache-miss.txt\` and \`cache-miss.json\`
- \`docker-stats.csv\` raw CPU/memory samples, when Docker is available
- \`docker-stats-summary.csv\` aggregate CPU/memory summary
EOF

log "Performance proof complete."
log "Evidence directory: $out_dir"
