#!/usr/bin/env sh
set -eu

target=""
evidence_dir=""
while [ $# -gt 0 ]; do
  case "$1" in
    --evidence-dir)
      evidence_dir="${2:-}"
      shift 2
      ;;
    -h|--help)
      cat <<'USAGE'
Usage: check-production-ports.sh [target] [--evidence-dir <path>]

  No arguments: audit listeners, health, firewall, container bindings
  and the DoT certificate on this host.
  target: also probe public/internal ports on a remote host.
  --evidence-dir: retain the full run output under <path>/run.log.
USAGE
      exit 0
      ;;
    --)
      shift
      break
      ;;
    -*)
      printf 'ERROR: unknown option: %s\n' "$1" >&2
      exit 2
      ;;
    *)
      target="$1"
      shift
      ;;
  esac
done
health_core="http://127.0.0.1:8080/healthz"
health_dns="http://127.0.0.1:8081/healthz"
internal_ports="8080 8081 6379 11434"
public_ports="80 443 853"

if [ -t 1 ] && [ "${NO_COLOR:-}" = "" ]; then
  green="$(printf '\033[32m')"
  red="$(printf '\033[31m')"
  yellow="$(printf '\033[33m')"
  blue="$(printf '\033[36m')"
  reset="$(printf '\033[0m')"
else
  green=""
  red=""
  yellow=""
  blue=""
  reset=""
fi

failures=0
warnings=0

mark() {
  color="$1"
  label="$2"
  shift 2
  printf '%s[%s]%s %s\n' "$color" "$label" "$reset" "$*"
}

pass() {
  mark "$green" "PASS" "$@"
}

ok() {
  mark "$green" "OK" "$@"
}

blocked() {
  mark "$green" "BLOCKED" "$@"
}

warn() {
  warnings=$((warnings + 1))
  mark "$yellow" "WARN" "$@"
}

fail() {
  failures=$((failures + 1))
  mark "$red" "FAIL" "$@"
}

critical() {
  failures=$((failures + 1))
  mark "$red" "CRITICAL" "$@"
}

section() {
  printf '\n%s%s%s\n' "$blue" "$1" "$reset"
  printf '%s\n' "----------------------------------------"
}

port_name() {
  case "$1" in
    80) printf '%s' "HTTP" ;;
    443) printf '%s' "HTTPS" ;;
    853) printf '%s' "DNS-over-TLS" ;;
    8080) printf '%s' "Core API" ;;
    8081) printf '%s' "DoH Resolver" ;;
    6379) printf '%s' "Redis" ;;
    11434) printf '%s' "Ollama" ;;
    *) printf '%s' "port $1" ;;
  esac
}

check_health() {
  name="$1"
  url="$2"

  if command -v curl >/dev/null 2>&1; then
    if curl -fsS --max-time 3 "$url" >/dev/null 2>&1; then
      pass "$name health endpoint is reachable at $url"
    else
      fail "$name health endpoint is not reachable at $url"
    fi
    return
  fi

  if command -v wget >/dev/null 2>&1; then
    if wget -q -T 3 -O /dev/null "$url" >/dev/null 2>&1; then
      pass "$name health endpoint is reachable at $url"
    else
      fail "$name health endpoint is not reachable at $url"
    fi
    return
  fi

  fail "Neither curl nor wget is installed; cannot verify $name health endpoint"
}

listener_tool() {
  if command -v ss >/dev/null 2>&1; then
    printf '%s' "ss"
    return
  fi
  if command -v netstat >/dev/null 2>&1; then
    printf '%s' "netstat"
    return
  fi
  if command -v lsof >/dev/null 2>&1; then
    printf '%s' "lsof"
    return
  fi
  printf '%s' ""
}

listener_lines_for_port() {
  tool="$1"
  port="$2"

  case "$tool" in
    ss)
      ss -ltnH 2>/dev/null |
        awk -v port="$port" '$4 ~ ("[:.]" port "$") || $4 ~ ("\\]:" port "$") {print $4}'
      ;;
    netstat)
      netstat -an 2>/dev/null |
        awk -v port="$port" '
          /LISTEN/ && ($0 ~ (":" port "([[:space:]]|$)") || $0 ~ ("\\." port "([[:space:]]|$)")) {print}
        '
      ;;
    lsof)
      lsof -nP -iTCP:"$port" -sTCP:LISTEN 2>/dev/null |
        awk 'NR > 1 {print}'
      ;;
  esac
}

is_allowed_internal_listener() {
  line="$1"
  port="$2"

  printf '%s\n' "$line" | grep -Eq "(^|[^0-9])127\.0\.0\.1[:.]$port([^0-9]|$)|\[::1\]:$port([^0-9]|$)|(^|[[:space:]])::1[:.]$port([^0-9]|$)|localhost[:.]$port([^0-9]|$)" && return 0
  printf '%s\n' "$line" | grep -Eq "(^|[^0-9])192\.168\.[0-9]+\.[0-9]+[:.]$port([^0-9]|$)" && return 0
  printf '%s\n' "$line" | grep -Eq "(^|[^0-9])172\.(1[6-9]|2[0-9]|3[0-1])\.[0-9]+\.[0-9]+[:.]$port([^0-9]|$)" && return 0

  return 1
}

audit_local_port() {
  tool="$1"
  port="$2"
  name="$(port_name "$port")"
  lines="$(listener_lines_for_port "$tool" "$port" || true)"

  if [ -z "$lines" ]; then
    pass "$name port $port has no host listener"
    return
  fi

  bad=""
  old_ifs="$IFS"
  IFS='
'
  for line in $lines; do
    if is_allowed_internal_listener "$line" "$port"; then
      :
    else
      bad="${bad}${line}
"
    fi
  done
  IFS="$old_ifs"

  if [ -n "$bad" ]; then
    critical "$name port $port is bound to a public or unexpected interface"
    printf '%s' "$bad" | sed 's/^/    /'
  else
    pass "$name port $port is restricted to loopback or private Docker interfaces"
  fi
}

run_local_audit() {
  section "Local Host Audit"
  check_health "core-api" "$health_core"
  check_health "dns-resolver" "$health_dns"

  section "Internal Listener Exposure"
  tool="$(listener_tool)"
  if [ -z "$tool" ]; then
    fail "No listener inspection tool found. Install ss, netstat, or lsof."
    return
  fi

  ok "Using $tool for local listener audit"
  for port in $internal_ports; do
    audit_local_port "$tool" "$port"
  done

  section "Host Firewall (UFW)"
  audit_ufw

  section "Container Bindings"
  audit_docker_bindings

  section "DoT Certificate (informational)"
  audit_dot_cert
}

# ufw needs root; prefer passwordless sudo, non-interactive only (sudo -n
# never prompts, so this cannot hang waiting for input).
ufw_status() {
  if command -v sudo >/dev/null 2>&1 && sudo -n true 2>/dev/null; then
    sudo -n ufw status numbered
  else
    ufw status numbered
  fi
}

audit_ufw() {
  if ! command -v ufw >/dev/null 2>&1; then
    warn "ufw not installed; firewall state unverifiable on this host"
    return
  fi
  rules="$(ufw_status 2>&1)" || {
    warn "ufw status unreadable (needs root without passwordless sudo)"
    return
  }
  case "$rules" in
    *'Status: active'*) pass "ufw active" ;;
    *) fail "ufw not active"; return ;;
  esac
  for port in 22 80 443 853; do
    if printf '%s\n' "$rules" | grep -Eq "ALLOW.*${port}/tcp|${port}/tcp.*ALLOW"; then
      pass "ufw allows ${port}/tcp"
    else
      fail "ufw missing allow for ${port}/tcp"
    fi
  done
  # Any ALLOW outside the intended set is a violation, not a warning:
  # unexpected holes are exactly what RB-1 guards against.
  if printf '%s\n' "$rules" | grep 'ALLOW' | grep -vE '22/tcp|80/tcp|443/tcp|853/tcp' | grep -q .; then
    fail "ufw has ALLOW rules outside 22/80/443/853"
  else
    pass "no ufw ALLOW outside 22/80/443/853"
  fi
}

compose_container() {
  # Match "<project>-<service>-1" regardless of compose project name.
  docker ps --format '{{.Names}}' 2>/dev/null | grep -E "(^|[-_])$1-1\$" | head -n 1
}

audit_docker_bindings() {
  if ! command -v docker >/dev/null 2>&1; then
    warn "docker not available; container bindings unverifiable"
    return
  fi
  api="$(compose_container 'core-api')"
  dns="$(compose_container 'dns-resolver')"
  caddy="$(compose_container 'caddy')"
  redis="$(compose_container 'redis')"
  if [ -z "$api$dns$caddy$redis" ]; then
    warn "Safe Zone containers not found; bindings unchecked"
    return
  fi
  case "$(docker port "$api" 2>/dev/null)" in
    *127.0.0.1:8080*) pass "core-api published on 127.0.0.1:8080" ;;
    *) fail "core-api not on 127.0.0.1:8080" ;;
  esac
  dns_ports="$(docker port "$dns" 2>/dev/null)"
  case "$dns_ports" in
    *127.0.0.1:8081*) pass "dns-resolver published on 127.0.0.1:8081" ;;
    *) fail "dns-resolver not on 127.0.0.1:8081" ;;
  esac
  case "$dns_ports" in
    *0.0.0.0:853*|*'[::]:853'*) pass "dns-resolver publishes DoT 853" ;;
    *) fail "dns-resolver does not publish DoT 853" ;;
  esac
  if [ -z "$(docker port "$redis" 2>/dev/null | tr -d '[:space:]')" ]; then
    pass "redis publishes no ports"
  else
    fail "redis publishes ports"
  fi
  caddy_ports="$(docker port "$caddy" 2>/dev/null)"
  case "$caddy_ports" in
    *'0.0.0.0:80'*|*'[::]:80'*) pass "caddy publishes 80" ;;
    *) fail "caddy does not publish 80" ;;
  esac
  case "$caddy_ports" in
    *'0.0.0.0:443'*|*'[::]:443'*) pass "caddy publishes 443" ;;
    *) fail "caddy does not publish 443" ;;
  esac
  case "$caddy_ports" in
    *'0.0.0.0:2019'*|*'[::]:2019'*) fail "caddy admin 2019 published (must stay internal)" ;;
    *) pass "caddy admin 2019 not published" ;;
  esac
}

audit_dot_cert() {
  if ! command -v openssl >/dev/null 2>&1; then
    warn "openssl missing; DoT cert unchecked"
    return
  fi
  out="$(printf '' | openssl s_client -connect 127.0.0.1:853 -servername localhost 2>&1)" || {
    warn "DoT handshake on 127.0.0.1:853 failed"
    return
  }
  subject="$(printf '%s\n' "$out" | grep -m1 'subject=' || true)"
  issuer="$(printf '%s\n' "$out" | grep -m1 'issuer=' || true)"
  ok "DoT cert ${subject} ${issuer}"
}

probe_with_nc() {
  host="$1"
  port="$2"

  if nc -z -w 2 "$host" "$port" >/dev/null 2>&1; then
    return 0
  fi
  return 1
}

probe_with_nmap() {
  host="$1"
  port="$2"

  output="$(nmap -Pn -p "$port" "$host" 2>/dev/null || true)"
  printf '%s\n' "$output" | grep -Eq "^${port}/tcp[[:space:]]+open" && return 0
  return 1
}

probe_with_bash_tcp() {
  host="$1"
  port="$2"

  bash -c 'host=$1; port=$2; timeout 2 bash -c ":</dev/tcp/$host/$port" >/dev/null 2>&1' sh "$host" "$port" >/dev/null 2>&1
}

probe_with_telnet() {
  host="$1"
  port="$2"

  if command -v timeout >/dev/null 2>&1; then
    printf '\n' | timeout 2 telnet "$host" "$port" 2>/dev/null | grep -Eiq 'connected|escape character' && return 0
  else
    printf '\n' | telnet "$host" "$port" 2>/dev/null | grep -Eiq 'connected|escape character' && return 0
  fi
  return 1
}

probe_with_perl() {
  host="$1"
  port="$2"

  perl -MIO::Socket::INET -e '$s=IO::Socket::INET->new(PeerAddr=>$ARGV[0],PeerPort=>$ARGV[1],Proto=>"tcp",Timeout=>2); exit($s ? 0 : 1)' "$host" "$port" >/dev/null 2>&1
}

probe_port() {
  host="$1"
  port="$2"

  if command -v nc >/dev/null 2>&1; then
    probe_with_nc "$host" "$port"
    return $?
  fi

  if command -v nmap >/dev/null 2>&1; then
    probe_with_nmap "$host" "$port"
    return $?
  fi

  if command -v bash >/dev/null 2>&1 && command -v timeout >/dev/null 2>&1; then
    probe_with_bash_tcp "$host" "$port"
    return $?
  fi

  if command -v telnet >/dev/null 2>&1; then
    probe_with_telnet "$host" "$port"
    return $?
  fi

  if command -v perl >/dev/null 2>&1; then
    probe_with_perl "$host" "$port"
    return $?
  fi

  return 2
}

audit_remote_public_port() {
  host="$1"
  port="$2"
  name="$(port_name "$port")"

  if probe_port "$host" "$port"; then
    ok "$name public port $port is OPEN as expected"
  else
    status=$?
    if [ "$status" -eq 2 ]; then
      fail "No remote probing tool available. Install nc, nmap, bash+timeout, or telnet."
    else
      fail "$name public port $port is CLOSED/FILTERED but should be open"
    fi
  fi
}

audit_remote_internal_port() {
  host="$1"
  port="$2"
  name="$(port_name "$port")"

  if probe_port "$host" "$port"; then
    critical "$name internal port $port is OPEN on $host"
  else
    status=$?
    if [ "$status" -eq 2 ]; then
      fail "No remote probing tool available. Install nc, nmap, bash+timeout, or telnet."
    else
      blocked "$name internal port $port is closed or filtered as expected"
    fi
  fi
}

run_remote_scan() {
  host="$1"
  section "Remote Port Scan: $host"

  if command -v nc >/dev/null 2>&1; then
    ok "Using nc for remote probing"
  elif command -v nmap >/dev/null 2>&1; then
    ok "Using nmap for remote probing"
  elif command -v bash >/dev/null 2>&1 && command -v timeout >/dev/null 2>&1; then
    ok "Using bash /dev/tcp for remote probing"
  elif command -v telnet >/dev/null 2>&1; then
    ok "Using telnet for remote probing"
  elif command -v perl >/dev/null 2>&1; then
    ok "Using Perl raw sockets for remote probing"
  else
    fail "No remote probing tool available. Install nc, nmap, bash+timeout, telnet, or perl."
    return
  fi

  section "Allowed Public Ports"
  for port in $public_ports; do
    audit_remote_public_port "$host" "$port"
  done

  section "Strictly Internal Ports"
  for port in $internal_ports; do
    audit_remote_internal_port "$host" "$port"
  done
}

print_summary_and_exit() {
  section "Audit Summary"
  if [ "$failures" -eq 0 ]; then
    pass "No production port exposure problems detected"
    if [ "$warnings" -gt 0 ]; then
      mark "$yellow" "WARN" "$warnings warning(s) were reported"
    fi
    exit 0
  fi

  mark "$red" "FAIL" "$failures critical/failing check(s) detected"
  if [ "$warnings" -gt 0 ]; then
    mark "$yellow" "WARN" "$warnings warning(s) were reported"
  fi
  exit 1
}

main() {
  if [ -n "$target" ]; then
    run_remote_scan "$target"
  else
    run_local_audit
  fi
  print_summary_and_exit
}

if [ -n "$evidence_dir" ]; then
  mkdir -p "$evidence_dir" || {
    printf 'ERROR: cannot create evidence dir %s\n' "$evidence_dir" >&2
    exit 2
  }
  # Subshell so print_summary_and_exit's exit code is captured, not acted on.
  ( main ) >"$evidence_dir/run.log" 2>&1
  status=$?
  cat "$evidence_dir/run.log"
  exit $status
fi

main
