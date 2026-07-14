export interface AuthSession {
  username: string;
  role: string;
  read_only: boolean;
  can_mutate: boolean;
  can_view_settings: boolean;
  guest_message?: string;
}

export interface TelemetryStats {
  total: number;
  safe: number;
  suspicious: number;
  malicious: number;
  cache_hits: number;
  period: string;
  score_bands?: Array<{
    label: string;
    value: number;
  }>;
  trend?: Array<{
    timestamp: string;
    safe: number;
    suspicious: number;
    malicious: number;
    threats: number;
  }>;
}

export interface TelemetryEntry {
  id: number;
  domain: string;
  verdict: string;
  score: number;
  confidence: number;
  reasons: string[];
  cache_hit: boolean;
  source: string;
  analyzed_at: string;
  created_at?: string;
  client_ip?: string;
  client_id?: string;
}

export interface PolicyGroup {
  id: number;
  name: string;
  description: string;
  block_categories: string[];
  strict_phishing: boolean;
  strict_malware: boolean;
}

export interface ClientMapping {
  id: number;
  mapping_type: 'ip' | 'cidr' | 'client_id';
  value: string;
  group_id: number;
  group_name?: string;
  created_at: string;
}

export interface AgentTask {
  name: string;
  state: 'idle' | 'running' | 'failed';
  interval: string;
  last_run: string;
  next_run: string;
  run_count: number;
  error_count: number;
  last_error: string;
}

export interface AgentStatus {
  enabled: boolean;
  tasks: AgentTask[];
  whitelist_stats?: {
    loaded_domains: number;
    bloom_size_ram_kb: number;
    bloom_hashes: number;
    bloom_bits: number;
    fpr: number;
  };
  database_stats?: {
    file_size_mb: number;
    disk_free_gb: number;
  };
  telemetry_retention_days?: number;
}

export interface CoreStatus {
  service: string;
  status: string;
  mode?: string;
  deployment_tier?: string;
  redis?: {
    configured: boolean;
    status: string;
    error?: string;
  };
  feed_sync?: {
    status: string;
    total_domains: number;
    last_sync: string;
    error?: string;
  };
  adblock?: {
    enabled: boolean;
    loaded_rules: number;
    status: string;
  };
  analysis_config_reload?: {
    enabled: boolean;
    last_reload_at: string;
  };
}

export interface RequestSummary {
  count: number;
  bytes: number;
  total_duration_ms: number;
  max_duration_ms: number;
  last_status: number;
}

export interface MetricsSnapshot {
  started_at: string;
  uptime_seconds: number;
  request_summary: Record<string, RequestSummary>;
  counters?: Record<string, number>;
}

export interface MetricsResponse {
  service: string;
  status: string;
  metrics: MetricsSnapshot;
}
