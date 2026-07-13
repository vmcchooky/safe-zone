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
  trend?: any[];
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
