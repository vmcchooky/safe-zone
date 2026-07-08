import {
  startTransition,
  useDeferredValue,
  useEffect,
  useEffectEvent,
  useMemo,
  useState,
} from 'react';
import {
  AlertTriangle,
  ArrowRight,
  Database,
  LoaderCircle,
  RefreshCcw,
  Search,
  ShieldAlert,
  ShieldCheck,
  TriangleAlert,
  Zap,
} from 'lucide-react';
import {
  Bar,
  BarChart,
  CartesianGrid,
  Cell,
  Legend,
  Pie,
  PieChart,
  ResponsiveContainer,
  Tooltip,
  XAxis,
  YAxis,
} from 'recharts';
import { motion } from 'framer-motion';
import { useNavigate } from 'react-router-dom';

import { apiFetch, messageFromError } from '../../lib/api';
import type { TelemetryEntry, TelemetryStats } from '../../lib/types';
import './TelemetryPage.css';

const PAGE_SIZE = 20;
const PERIOD_OPTIONS = [
  { label: '24 hours', value: '24h' },
  { label: '7 days', value: '7d' },
  { label: '30 days', value: '30d' },
] as const;

const VERDICT_OPTIONS = [
  { label: 'All verdicts', value: '' },
  { label: 'Safe', value: 'SAFE' },
  { label: 'Suspicious', value: 'SUSPICIOUS' },
  { label: 'Malicious', value: 'MALICIOUS' },
] as const;

const SOURCE_OPTIONS = [
  { label: 'All sources', value: '' },
  { label: 'Cache', value: 'cache' },
  { label: 'Lexical', value: 'lexical' },
  { label: 'AI', value: 'ai' },
  { label: 'OSINT', value: 'osint' },
] as const;

function verdictTone(verdict: string) {
  switch (verdict) {
    case 'SAFE':
      return 'safe';
    case 'SUSPICIOUS':
      return 'warn';
    case 'MALICIOUS':
      return 'bad';
    default:
      return 'muted';
  }
}

function formatCompact(value: number) {
  return new Intl.NumberFormat('en', {
    notation: 'compact',
    maximumFractionDigits: 1,
  }).format(value);
}

export function TelemetryPage() {
  const navigate = useNavigate();
  const [stats, setStats] = useState<TelemetryStats | null>(null);
  const [entries, setEntries] = useState<TelemetryEntry[]>([]);
  const [loading, setLoading] = useState(true);
  const [refreshing, setRefreshing] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const [period, setPeriod] = useState('24h');
  const [domain, setDomain] = useState('');
  const [verdict, setVerdict] = useState('');
  const [source, setSource] = useState('');
  const [page, setPage] = useState(1);

  const deferredDomain = useDeferredValue(domain.trim());

  const loadTelemetry = useEffectEvent(async (showSpinner: boolean) => {
    if (showSpinner) {
      startTransition(() => {
        setRefreshing(true);
      });
    }

    try {
      const statsResponse = await apiFetch<TelemetryStats>(`/v1/telemetry/stats?period=${period}`);

      const params = new URLSearchParams({
        period,
        limit: String(PAGE_SIZE),
        offset: String((page - 1) * PAGE_SIZE),
      });
      if (deferredDomain) {
        params.set('domain', deferredDomain);
      }
      if (verdict) {
        params.set('verdict', verdict);
      }
      if (source) {
        params.set('source', source);
      }

      const recentResponse = await apiFetch<{ items: TelemetryEntry[] }>(
        `/v1/telemetry/recent?${params.toString()}`,
      );

      startTransition(() => {
        setStats(statsResponse);
        setEntries(recentResponse.items || []);
        setError(null);
      });
    } catch (err) {
      startTransition(() => {
        setError(messageFromError(err));
      });
    } finally {
      startTransition(() => {
        setLoading(false);
        setRefreshing(false);
      });
    }
  });

  useEffect(() => {
    void loadTelemetry(true);
  }, [deferredDomain, loadTelemetry, page, period, source, verdict]);

  useEffect(() => {
    const timer = window.setInterval(() => {
      void loadTelemetry(false);
    }, 15000);

    return () => window.clearInterval(timer);
  }, [loadTelemetry]);

  const distribution = useMemo(() => {
    if (!stats) {
      return [];
    }
    return [
      { name: 'Safe', value: stats.safe, fill: 'var(--safe)' },
      { name: 'Suspicious', value: stats.suspicious, fill: 'var(--warn)' },
      { name: 'Malicious', value: stats.malicious, fill: 'var(--bad)' },
    ];
  }, [stats]);

  const scoreBands = useMemo(() => {
    if (!stats) {
      return [];
    }

    const safe = stats.safe;
    const suspicious = stats.suspicious;
    const malicious = stats.malicious;

    return [
      { label: 'Safe', value: safe, fill: 'rgba(20, 184, 166, 0.88)' },
      { label: 'Suspicious', value: suspicious, fill: 'rgba(251, 191, 36, 0.88)' },
      { label: 'Malicious', value: malicious, fill: 'rgba(248, 113, 113, 0.88)' },
    ];
  }, [stats]);

  const riskRatio = stats?.total
    ? Math.round(((stats.suspicious + stats.malicious) / stats.total) * 100)
    : 0;
  const cacheRatio = stats?.total ? Math.round((stats.cache_hits / stats.total) * 100) : 0;

  return (
    <section className="telemetry-page">
      <div className="telemetry-hero">
        <div>
          <div className="eyebrow">Live telemetry workspace</div>
          <h1 className="page-title">Network telemetry, grounded in the real API</h1>
          <p className="page-copy">
            This React route pulls directly from `/v1/telemetry/stats` and `/v1/telemetry/recent`
            while preserving the same auth session as the production dashboard.
          </p>
        </div>

        <div className="telemetry-actions">
          <button className="button-secondary" type="button" onClick={() => void loadTelemetry(true)}>
            {refreshing ? <LoaderCircle size={16} className="spin" /> : <RefreshCcw size={16} />}
            Refresh now
          </button>
        </div>
      </div>

      <div className="telemetry-filters surface-card">
        <div className="telemetry-filter">
          <label htmlFor="telemetry-period">Period</label>
          <select
            id="telemetry-period"
            value={period}
            onChange={(event) => {
              setPage(1);
              setPeriod(event.target.value);
            }}
          >
            {PERIOD_OPTIONS.map((option) => (
              <option key={option.value} value={option.value}>
                {option.label}
              </option>
            ))}
          </select>
        </div>

        <div className="telemetry-filter telemetry-filter-wide">
          <label htmlFor="telemetry-domain">Domain search</label>
          <div className="telemetry-search">
            <Search size={16} />
            <input
              id="telemetry-domain"
              value={domain}
              onChange={(event) => {
                setPage(1);
                setDomain(event.target.value);
              }}
              placeholder="Filter by domain fragment"
            />
          </div>
        </div>

        <div className="telemetry-filter">
          <label htmlFor="telemetry-verdict">Verdict</label>
          <select
            id="telemetry-verdict"
            value={verdict}
            onChange={(event) => {
              setPage(1);
              setVerdict(event.target.value);
            }}
          >
            {VERDICT_OPTIONS.map((option) => (
              <option key={option.label} value={option.value}>
                {option.label}
              </option>
            ))}
          </select>
        </div>

        <div className="telemetry-filter">
          <label htmlFor="telemetry-source">Source</label>
          <select
            id="telemetry-source"
            value={source}
            onChange={(event) => {
              setPage(1);
              setSource(event.target.value);
            }}
          >
            {SOURCE_OPTIONS.map((option) => (
              <option key={option.label} value={option.value}>
                {option.label}
              </option>
            ))}
          </select>
        </div>
      </div>

      {error ? <div className="telemetry-error">{error}</div> : null}

      <div className="telemetry-stats-grid">
        {[
          {
            label: 'Total analyzed',
            value: stats?.total || 0,
            tone: 'safe',
            icon: <Database size={18} />,
          },
          {
            label: 'Safe',
            value: stats?.safe || 0,
            tone: 'safe',
            icon: <ShieldCheck size={18} />,
          },
          {
            label: 'Suspicious',
            value: stats?.suspicious || 0,
            tone: 'warn',
            icon: <TriangleAlert size={18} />,
          },
          {
            label: 'Malicious',
            value: stats?.malicious || 0,
            tone: 'bad',
            icon: <ShieldAlert size={18} />,
          },
          {
            label: 'Cache efficiency',
            value: cacheRatio,
            suffix: '%',
            tone: 'accent',
            icon: <Zap size={18} />,
          },
        ].map((card, index) => (
          <motion.article
            key={card.label}
            className={`telemetry-stat surface-card tone-${card.tone}`}
            initial={{ opacity: 0, y: 14 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ delay: index * 0.04, duration: 0.2 }}
          >
            <div className="telemetry-stat-top">
              <span>{card.label}</span>
              {card.icon}
            </div>
            <strong>
              {card.suffix ? `${card.value}${card.suffix}` : formatCompact(card.value)}
            </strong>
          </motion.article>
        ))}
      </div>

      <div className="telemetry-mix surface-card">
        <div className="telemetry-mix-head">
          <div>
            <h2>Threat pressure</h2>
            <p>Share of suspicious and malicious verdicts in the selected period.</p>
          </div>
          <strong>{riskRatio}% risk</strong>
        </div>
        <div className="telemetry-mix-bar" aria-hidden="true">
          <span className="mix-safe" style={{ width: `${Math.max(0, 100 - riskRatio)}%` }} />
          <span className="mix-risk" style={{ width: `${riskRatio}%` }} />
        </div>
      </div>

      <div className="telemetry-chart-grid">
        <article className="surface-card telemetry-chart-card">
          <div className="telemetry-chart-head">
            <div>
              <h2>Verdict distribution</h2>
              <p>Actual category mix from the backend telemetry store.</p>
            </div>
          </div>
          <div className="telemetry-chart-wrap">
            <ResponsiveContainer width="100%" height="100%">
              <PieChart>
                <Pie
                  data={distribution}
                  dataKey="value"
                  nameKey="name"
                  cx="50%"
                  cy="50%"
                  innerRadius="56%"
                  outerRadius="82%"
                  paddingAngle={2}
                >
                  {distribution.map((slice) => (
                    <Cell key={slice.name} fill={slice.fill} />
                  ))}
                </Pie>
                <Tooltip formatter={(value: number) => formatCompact(Number(value))} />
                <Legend />
              </PieChart>
            </ResponsiveContainer>
          </div>
        </article>

        <article className="surface-card telemetry-chart-card">
          <div className="telemetry-chart-head">
            <div>
              <h2>Category volume</h2>
              <p>Quick comparison of safe, suspicious, and malicious decisions.</p>
            </div>
          </div>
          <div className="telemetry-chart-wrap">
            <ResponsiveContainer width="100%" height="100%">
              <BarChart data={scoreBands} margin={{ top: 8, right: 12, left: 0, bottom: 0 }}>
                <CartesianGrid strokeDasharray="4 4" stroke="rgba(255,255,255,0.08)" vertical={false} />
                <XAxis dataKey="label" tick={{ fill: 'rgba(255,255,255,0.68)' }} axisLine={false} tickLine={false} />
                <YAxis
                  tick={{ fill: 'rgba(255,255,255,0.48)' }}
                  axisLine={false}
                  tickLine={false}
                  tickFormatter={(value) => formatCompact(Number(value))}
                />
                <Tooltip formatter={(value: number) => formatCompact(Number(value))} />
                <Bar dataKey="value" radius={[10, 10, 0, 0]}>
                  {scoreBands.map((bar) => (
                    <Cell key={bar.label} fill={bar.fill} />
                  ))}
                </Bar>
              </BarChart>
            </ResponsiveContainer>
          </div>
        </article>
      </div>

      <article className="surface-card telemetry-table-card">
        <div className="telemetry-table-head">
          <div>
            <h2>Recent activity</h2>
            <p>Filtered data from `/v1/telemetry/recent` with server-side paging.</p>
          </div>
          {refreshing ? <LoaderCircle size={16} className="spin" /> : null}
        </div>

        <div className="telemetry-table-wrap">
          <table className="telemetry-table">
            <thead>
              <tr>
                <th>Domain</th>
                <th>Verdict</th>
                <th>Source</th>
                <th>Score</th>
                <th>Analyzed at</th>
                <th>Action</th>
              </tr>
            </thead>
            <tbody>
              {loading ? (
                <tr>
                  <td colSpan={6}>
                    <div className="telemetry-empty">
                      <LoaderCircle size={18} className="spin" />
                      Loading telemetry feed…
                    </div>
                  </td>
                </tr>
              ) : entries.length === 0 ? (
                <tr>
                  <td colSpan={6}>
                    <div className="telemetry-empty">
                      <AlertTriangle size={18} />
                      No telemetry records match the current filters.
                    </div>
                  </td>
                </tr>
              ) : (
                entries.map((entry) => (
                  <tr key={`${entry.id}-${entry.domain}`}>
                    <td>
                      <div className="telemetry-domain">
                        <strong>{entry.domain}</strong>
                        <span>{entry.confidence ? `${Math.round(entry.confidence * 100)}% confidence` : 'No confidence score'}</span>
                      </div>
                    </td>
                    <td>
                      <span className={`telemetry-pill tone-${verdictTone(entry.verdict)}`}>
                        {entry.verdict === 'SAFE' ? <ShieldCheck size={13} /> : null}
                        {entry.verdict === 'SUSPICIOUS' ? <TriangleAlert size={13} /> : null}
                        {entry.verdict === 'MALICIOUS' ? <ShieldAlert size={13} /> : null}
                        {entry.verdict}
                      </span>
                    </td>
                    <td>{entry.source || (entry.cache_hit ? 'cache' : '--')}</td>
                    <td>{entry.score}/100</td>
                    <td>{new Date(entry.analyzed_at).toLocaleString()}</td>
                    <td>
                      <button
                        className="button-secondary telemetry-review-button"
                        type="button"
                        onClick={() =>
                          navigate(`/analysis?domain=${encodeURIComponent(entry.domain)}`)
                        }
                      >
                        Review
                        <ArrowRight size={14} />
                      </button>
                    </td>
                  </tr>
                ))
              )}
            </tbody>
          </table>
        </div>

        <div className="telemetry-pagination">
          <button
            className="button-secondary"
            type="button"
            disabled={page === 1 || refreshing}
            onClick={() => setPage((value) => Math.max(1, value - 1))}
          >
            Previous
          </button>
          <span>
            Page <strong>{page}</strong>
          </span>
          <button
            className="button-secondary"
            type="button"
            disabled={entries.length < PAGE_SIZE || refreshing}
            onClick={() => setPage((value) => value + 1)}
          >
            Next
          </button>
        </div>
      </article>
    </section>
  );
}
