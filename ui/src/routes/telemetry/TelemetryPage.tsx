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
    <section className="relative min-h-[calc(100vh-4rem)] p-4 sm:p-8">
      {/* Background Orbs */}
      <div className="absolute inset-0 bg-slate-50/50 -z-10" />
      <div className="absolute top-0 right-0 w-[800px] h-[800px] bg-sky-400/20 rounded-full blur-[120px] -translate-y-1/2 translate-x-1/3 pointer-events-none -z-10" />
      <div className="absolute bottom-0 left-0 w-[600px] h-[600px] bg-pink-400/20 rounded-full blur-[100px] translate-y-1/3 -translate-x-1/4 pointer-events-none -z-10" />

      <div className="max-w-7xl mx-auto space-y-8">
        {/* Header */}
        <div className="flex flex-col md:flex-row md:items-end justify-between gap-6">
          <div>
            <div className="text-sky-600 font-bold uppercase tracking-wider text-xs mb-2">Live telemetry workspace</div>
            <h1 className="text-4xl font-extrabold text-slate-800 tracking-tight mb-3">Network Telemetry</h1>
            <p className="text-slate-500 max-w-2xl text-lg">
              Live feed of API decisions and threat metrics.
            </p>
          </div>
          <button 
            className="flex items-center gap-2 bg-white/60 hover:bg-white/90 hover:-translate-y-0.5 hover:scale-[1.02] border border-slate-200 text-slate-700 px-6 py-3 rounded-2xl font-semibold transition-all duration-300 ease-out shadow-sm whitespace-nowrap"
            type="button" 
            onClick={() => void loadTelemetry(true)}
          >
            {refreshing ? <LoaderCircle size={18} className="animate-spin text-sky-500" /> : <RefreshCcw size={18} className="text-sky-500" />}
            Refresh now
          </button>
        </div>

        {/* Filters */}
        <div className="bg-white/40 backdrop-blur-xl border border-white/60 rounded-3xl p-6 shadow-sm flex flex-wrap gap-6 items-end">
          <div className="flex flex-col gap-2 w-48">
            <label htmlFor="telemetry-period" className="text-xs font-bold text-slate-500 uppercase tracking-wider ml-1">Period</label>
            <select
              id="telemetry-period"
              value={period}
              onChange={(event) => {
                setPage(1);
                setPeriod(event.target.value);
              }}
              className="w-full bg-white/50 border border-white/80 rounded-xl px-4 py-3 text-slate-700 font-medium shadow-sm focus:bg-white focus:ring-2 focus:ring-sky-500/20 focus:border-sky-500 outline-none transition-all appearance-none cursor-pointer"
            >
              {PERIOD_OPTIONS.map((option) => (
                <option key={option.value} value={option.value}>{option.label}</option>
              ))}
            </select>
          </div>

          <div className="flex flex-col gap-2 flex-1 min-w-[240px]">
            <label htmlFor="telemetry-domain" className="text-xs font-bold text-slate-500 uppercase tracking-wider ml-1">Domain search</label>
            <div className="relative">
              <Search size={18} className="absolute left-4 top-1/2 -translate-y-1/2 text-slate-400" />
              <input
                id="telemetry-domain"
                value={domain}
                onChange={(event) => {
                  setPage(1);
                  setDomain(event.target.value);
                }}
                placeholder="Filter by domain fragment"
                className="w-full bg-white/50 border border-white/80 rounded-xl pl-11 pr-4 py-3 text-slate-700 font-medium shadow-sm focus:bg-white focus:ring-2 focus:ring-sky-500/20 focus:border-sky-500 outline-none transition-all placeholder:text-slate-400"
              />
            </div>
          </div>

          <div className="flex flex-col gap-2 w-48">
            <label htmlFor="telemetry-verdict" className="text-xs font-bold text-slate-500 uppercase tracking-wider ml-1">Verdict</label>
            <select
              id="telemetry-verdict"
              value={verdict}
              onChange={(event) => {
                setPage(1);
                setVerdict(event.target.value);
              }}
              className="w-full bg-white/50 border border-white/80 rounded-xl px-4 py-3 text-slate-700 font-medium shadow-sm focus:bg-white focus:ring-2 focus:ring-sky-500/20 focus:border-sky-500 outline-none transition-all appearance-none cursor-pointer"
            >
              {VERDICT_OPTIONS.map((option) => (
                <option key={option.label} value={option.value}>{option.label}</option>
              ))}
            </select>
          </div>

          <div className="flex flex-col gap-2 w-48">
            <label htmlFor="telemetry-source" className="text-xs font-bold text-slate-500 uppercase tracking-wider ml-1">Source</label>
            <select
              id="telemetry-source"
              value={source}
              onChange={(event) => {
                setPage(1);
                setSource(event.target.value);
              }}
              className="w-full bg-white/50 border border-white/80 rounded-xl px-4 py-3 text-slate-700 font-medium shadow-sm focus:bg-white focus:ring-2 focus:ring-sky-500/20 focus:border-sky-500 outline-none transition-all appearance-none cursor-pointer"
            >
              {SOURCE_OPTIONS.map((option) => (
                <option key={option.label} value={option.value}>{option.label}</option>
              ))}
            </select>
          </div>
        </div>

        {error ? (
          <motion.div 
            initial={{ opacity: 0, y: -10 }} 
            animate={{ opacity: 1, y: 0 }} 
            className="bg-rose-50 border border-rose-200 text-rose-600 px-6 py-4 rounded-2xl flex gap-3 items-center"
          >
            <AlertTriangle size={20} />
            <span className="font-medium">{error}</span>
          </motion.div>
        ) : null}

        {/* Stats Grid */}
        <div className="grid grid-cols-1 md:grid-cols-3 lg:grid-cols-5 gap-6">
          {[
            { label: 'Total analyzed', value: stats?.total || 0, tone: 'sky', icon: <Database size={20} /> },
            { label: 'Safe', value: stats?.safe || 0, tone: 'teal', icon: <ShieldCheck size={20} /> },
            { label: 'Suspicious', value: stats?.suspicious || 0, tone: 'amber', icon: <TriangleAlert size={20} /> },
            { label: 'Malicious', value: stats?.malicious || 0, tone: 'rose', icon: <ShieldAlert size={20} /> },
            { label: 'Cache efficiency', value: cacheRatio, suffix: '%', tone: 'indigo', icon: <Zap size={20} /> },
          ].map((card, index) => {
            const colors: Record<string, string> = {
              sky: 'text-sky-600 bg-sky-100',
              teal: 'text-teal-600 bg-teal-100',
              amber: 'text-amber-600 bg-amber-100',
              rose: 'text-rose-600 bg-rose-100',
              indigo: 'text-indigo-600 bg-indigo-100',
            };
            return (
            <motion.div
              key={card.label}
              initial={{ opacity: 0, y: 14 }}
              animate={{ opacity: 1, y: 0 }}
              transition={{ delay: index * 0.05, type: 'spring', stiffness: 300, damping: 24 }}
              className="bg-white/60 backdrop-blur-xl border border-white/80 rounded-3xl p-6 shadow-[0_8px_32px_rgba(0,0,0,0.02)] hover:shadow-[0_8px_32px_rgba(0,0,0,0.04)] transition-shadow"
            >
              <div className="flex items-center gap-3 mb-4">
                <div className={`p-2.5 rounded-xl ${colors[card.tone]}`}>
                  {card.icon}
                </div>
                <span className="text-slate-500 font-semibold">{card.label}</span>
              </div>
              <div className="text-3xl font-extrabold text-slate-800">
                {card.suffix ? `${card.value}${card.suffix}` : formatCompact(card.value)}
              </div>
            </motion.div>
            );
          })}
        </div>

        {/* Threat Pressure Bar */}
        <div className="bg-white/60 backdrop-blur-xl border border-white/80 rounded-3xl p-8 shadow-[0_8px_32px_rgba(0,0,0,0.02)] relative overflow-hidden">
          <div className="absolute top-0 right-0 w-64 h-64 bg-gradient-to-br from-rose-400/20 to-amber-400/20 rounded-full blur-3xl -translate-y-1/2 translate-x-1/2 pointer-events-none" />
          <div className="flex justify-between items-end mb-6 relative z-10">
            <div>
              <h2 className="text-xl font-bold text-slate-800 mb-1">Threat pressure</h2>
              <p className="text-slate-500 font-medium">Share of suspicious and malicious verdicts in the selected period.</p>
            </div>
            <strong className="text-3xl font-extrabold bg-clip-text text-transparent bg-gradient-to-r from-amber-500 to-rose-500">{riskRatio}% risk</strong>
          </div>
          <div className="w-full h-4 rounded-full bg-teal-100 relative z-10 overflow-hidden shadow-inner">
            <motion.div 
              initial={{ width: 0 }}
              animate={{ width: `${riskRatio}%` }}
              transition={{ duration: 1, ease: "easeOut" }}
              className="absolute right-0 top-0 bottom-0 bg-gradient-to-l from-amber-400 to-rose-500 rounded-l-full"
            />
          </div>
        </div>

        {/* Charts Grid */}
        <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
          <article className="bg-white/60 backdrop-blur-xl border border-white/80 rounded-3xl p-8 shadow-[0_8px_32px_rgba(0,0,0,0.02)] flex flex-col h-[400px]">
            <div className="mb-6">
              <h2 className="text-xl font-bold text-slate-800 mb-1">Verdict distribution</h2>
              <p className="text-slate-500 font-medium">Actual category mix from the backend telemetry store.</p>
            </div>
            <div className="flex-1 min-h-0">
              <ResponsiveContainer width="100%" height="100%">
                <PieChart>
                  <Pie
                    data={distribution}
                    dataKey="value"
                    nameKey="name"
                    cx="50%"
                    cy="50%"
                    innerRadius="60%"
                    outerRadius="85%"
                    paddingAngle={4}
                    cornerRadius={6}
                    stroke="none"
                  >
                    {distribution.map((slice) => (
                      <Cell key={slice.name} fill={slice.fill} />
                    ))}
                  </Pie>
                  <Tooltip 
                    formatter={(value: number) => formatCompact(Number(value))}
                    contentStyle={{ borderRadius: '16px', border: '1px solid rgba(255,255,255,0.8)', background: 'rgba(255,255,255,0.9)', boxShadow: '0 4px 20px rgba(0,0,0,0.08)' }}
                    itemStyle={{ color: '#1e293b' }}
                  />
                  <Legend iconType="circle" wrapperStyle={{ paddingTop: '20px' }} />
                </PieChart>
              </ResponsiveContainer>
            </div>
          </article>

          <article className="bg-white/60 backdrop-blur-xl border border-white/80 rounded-3xl p-8 shadow-[0_8px_32px_rgba(0,0,0,0.02)] flex flex-col h-[400px]">
            <div className="mb-6">
              <h2 className="text-xl font-bold text-slate-800 mb-1">Category volume</h2>
              <p className="text-slate-500 font-medium">Quick comparison of safe, suspicious, and malicious decisions.</p>
            </div>
            <div className="flex-1 min-h-0">
              <ResponsiveContainer width="100%" height="100%">
                <BarChart data={scoreBands} margin={{ top: 8, right: 12, left: -20, bottom: 0 }}>
                  <CartesianGrid strokeDasharray="4 4" stroke="rgba(0,0,0,0.05)" vertical={false} />
                  <XAxis dataKey="label" tick={{ fill: '#64748b', fontSize: 13, fontWeight: 600 }} axisLine={false} tickLine={false} dy={10} />
                  <YAxis
                    tick={{ fill: '#94a3b8', fontSize: 13 }}
                    axisLine={false}
                    tickLine={false}
                    tickFormatter={(value) => formatCompact(Number(value))}
                    dx={-10}
                  />
                  <Tooltip 
                    formatter={(value: number) => formatCompact(Number(value))}
                    contentStyle={{ borderRadius: '16px', border: '1px solid rgba(255,255,255,0.8)', background: 'rgba(255,255,255,0.9)', boxShadow: '0 4px 20px rgba(0,0,0,0.08)' }}
                    cursor={{ fill: 'rgba(0,0,0,0.02)' }}
                    itemStyle={{ color: '#1e293b' }}
                  />
                  <Bar dataKey="value" radius={[6, 6, 0, 0]} maxBarSize={60}>
                    {scoreBands.map((bar) => (
                      <Cell key={bar.label} fill={bar.fill} />
                    ))}
                  </Bar>
                </BarChart>
              </ResponsiveContainer>
            </div>
          </article>
        </div>

        {/* Table */}
        <article className="bg-white/60 backdrop-blur-xl border border-white/80 rounded-3xl p-8 shadow-[0_8px_32px_rgba(0,0,0,0.02)]">
          <div className="flex justify-between items-center mb-8">
            <div>
              <h2 className="text-xl font-bold text-slate-800 mb-1">Recent activity</h2>
              <p className="text-slate-500 font-medium">Filtered data from `/v1/telemetry/recent` with server-side paging.</p>
            </div>
            {refreshing ? <LoaderCircle size={20} className="animate-spin text-sky-500" /> : null}
          </div>

          <div className="overflow-x-auto">
            <table className="w-full text-left border-collapse min-w-[800px]">
              <thead>
                <tr className="border-b border-black/5 text-slate-500 text-sm">
                  <th className="pb-4 font-bold uppercase tracking-wider pl-4">Domain</th>
                  <th className="pb-4 font-bold uppercase tracking-wider">Verdict</th>
                  <th className="pb-4 font-bold uppercase tracking-wider">Source</th>
                  <th className="pb-4 font-bold uppercase tracking-wider">Score</th>
                  <th className="pb-4 font-bold uppercase tracking-wider">Analyzed at</th>
                  <th className="pb-4 font-bold uppercase tracking-wider text-right pr-4">Action</th>
                </tr>
              </thead>
              <motion.tbody
                initial="hidden"
                animate="show"
                variants={{
                  hidden: {},
                  show: {
                    transition: {
                      staggerChildren: 0.04
                    }
                  }
                }}
                className="divide-y divide-black/5 text-slate-800"
              >
                {loading ? (
                  <tr>
                    <td colSpan={6} className="py-16 text-center">
                      <div className="flex flex-col items-center justify-center text-slate-500 gap-4">
                        <LoaderCircle size={28} className="animate-spin text-sky-500" />
                        <span className="font-medium">Loading telemetry feed…</span>
                      </div>
                    </td>
                  </tr>
                ) : entries.length === 0 ? (
                  <tr>
                    <td colSpan={6} className="py-16 text-center">
                      <div className="flex flex-col items-center justify-center text-slate-500 gap-4">
                        <AlertTriangle size={28} className="text-amber-500" />
                        <span className="font-medium">No telemetry records match the current filters.</span>
                      </div>
                    </td>
                  </tr>
                ) : (
                  entries.map((entry) => (
                    <motion.tr 
                      key={`${entry.id}-${entry.domain}`}
                      variants={{
                        hidden: { opacity: 0, x: -10 },
                        show: { opacity: 1, x: 0, transition: { type: "spring", stiffness: 300, damping: 24 } }
                      }}
                      className="hover:bg-white/50 transition-colors group"
                    >
                      <td className="py-4 pl-4">
                        <div className="flex flex-col">
                          <strong className="font-mono text-[15px] group-hover:text-sky-600 transition-colors">{entry.domain}</strong>
                          <span className="text-xs text-slate-500 font-medium">{entry.confidence ? `${Math.round(entry.confidence * 100)}% confidence` : 'No confidence score'}</span>
                        </div>
                      </td>
                      <td className="py-4 pr-4">
                        <span className={`inline-flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-xs font-bold uppercase tracking-wider shadow-sm ${
                          entry.verdict === 'MALICIOUS' ? 'bg-rose-500/20 text-rose-700 border border-rose-500/30' :
                          entry.verdict === 'SUSPICIOUS' ? 'bg-amber-500/20 text-amber-700 border border-amber-500/30' :
                          'bg-teal-500/20 text-teal-800 border border-teal-500/30'
                        }`}>
                          {entry.verdict === 'SAFE' ? <ShieldCheck size={14} /> : null}
                          {entry.verdict === 'SUSPICIOUS' ? <TriangleAlert size={14} /> : null}
                          {entry.verdict === 'MALICIOUS' ? <ShieldAlert size={14} /> : null}
                          {entry.verdict}
                        </span>
                      </td>
                      <td className="py-4 pr-4 font-medium text-slate-600">
                        <span className="px-2 py-1 bg-slate-100 text-slate-700 rounded-md text-xs font-bold uppercase">
                          {entry.source || (entry.cache_hit ? 'cache' : '--')}
                        </span>
                      </td>
                      <td className="py-4 pr-4">
                        <div className="flex items-center gap-3">
                          <div className="w-16 h-2.5 rounded-full bg-slate-200 overflow-hidden shadow-inner">
                            <div 
                              className={`h-full rounded-full ${entry.score > 70 ? 'bg-rose-500' : entry.score > 30 ? 'bg-amber-500' : 'bg-teal-500'}`} 
                              style={{ width: `${entry.score}%` }} 
                            />
                          </div>
                          <span className="text-sm font-bold text-slate-600 w-6">{entry.score}</span>
                        </div>
                      </td>
                      <td className="py-4 pr-4 text-sm text-slate-500 font-medium">{new Date(entry.analyzed_at).toLocaleString()}</td>
                      <td className="py-4 pr-4 text-right">
                        <button
                          className="inline-flex items-center gap-2 px-4 py-2 bg-white/60 hover:bg-sky-50 text-sky-600 border border-sky-100 hover:border-sky-200 rounded-xl font-bold text-sm transition-all shadow-sm group/btn"
                          type="button"
                          onClick={() => navigate(`/analysis?domain=${encodeURIComponent(entry.domain)}`)}
                        >
                          Review
                          <ArrowRight size={14} className="group-hover/btn:translate-x-0.5 transition-transform" />
                        </button>
                      </td>
                    </motion.tr>
                  ))
                )}
              </motion.tbody>
            </table>
          </div>

          <div className="mt-8 flex items-center justify-between border-t border-black/5 pt-6">
            <span className="text-slate-500 font-medium ml-4">
              Page <strong className="text-slate-800">{page}</strong>
            </span>
            <div className="flex gap-3 mr-4">
              <button
                className="px-5 py-2.5 bg-white/60 hover:bg-white/90 border border-slate-200 text-slate-700 rounded-xl font-bold transition-all disabled:opacity-50 disabled:pointer-events-none shadow-sm active:scale-95"
                type="button"
                disabled={page === 1 || refreshing}
                onClick={() => setPage((value) => Math.max(1, value - 1))}
              >
                Previous
              </button>
              <button
                className="px-5 py-2.5 bg-white/60 hover:bg-white/90 border border-slate-200 text-slate-700 rounded-xl font-bold transition-all disabled:opacity-50 disabled:pointer-events-none shadow-sm active:scale-95"
                type="button"
                disabled={entries.length < PAGE_SIZE || refreshing}
                onClick={() => setPage((value) => value + 1)}
              >
                Next
              </button>
            </div>
          </div>
        </article>
      </div>
    </section>
  );
}
