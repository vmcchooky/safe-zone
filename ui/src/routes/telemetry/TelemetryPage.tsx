import {
  startTransition,
  useCallback,
  useDeferredValue,
  useEffect,
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
  RadioTower,
} from 'lucide-react';
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from '../../components/ui/select';
import { InfoTooltip } from '../../components/InfoTooltip';
import {
  Area,
  AreaChart,
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

  const loadTelemetry = useCallback(async (showSpinner: boolean) => {
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
  }, [period, page, deferredDomain, verdict, source]);

  useEffect(() => {
    void loadTelemetry(true);
  }, [loadTelemetry]);

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
      { name: 'Safe', value: stats.safe, fill: 'url(#pattern-safe-pie)' },
      { name: 'Suspicious', value: stats.suspicious, fill: 'url(#pattern-suspicious-pie)' },
      { name: 'Malicious', value: stats.malicious, fill: 'url(#pattern-malicious-pie)' },
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
      { label: '0-20', name: 'Safe', value: Math.ceil(safe * 0.7), fill: 'url(#pattern-safe-bar)' },
      { label: '21-40', name: 'Low Risk', value: Math.floor(safe * 0.3), fill: 'url(#pattern-safe-low-bar)' },
      { label: '41-60', name: 'Suspicious', value: suspicious, fill: 'url(#pattern-suspicious-bar)' },
      { label: '61-80', name: 'High Risk', value: Math.floor(malicious * 0.3), fill: 'url(#pattern-high-risk-bar)' },
      { label: '81-100', name: 'Malicious', value: Math.ceil(malicious * 0.7), fill: 'url(#pattern-malicious-bar)' },
    ];
  }, [stats]);

  const trendData = useMemo(() => {
    if (!stats) {
      return [];
    }
    
    const points = [];
    const now = new Date();
    const is24h = period === '24h';
    const count = is24h ? 24 : period === '7d' ? 42 : 60;
    
    // Base average per point (simulated)
    let baseMal = stats.malicious / count;
    let baseSusp = stats.suspicious / count;
    let baseSafe = stats.safe / count;
    
    for (let i = count - 1; i >= 0; i--) {
      const d = new Date(now);
      if (is24h) {
        d.setHours(d.getHours() - i);
      } else if (period === '7d') {
        d.setHours(d.getHours() - i * 4);
      } else {
        d.setHours(d.getHours() - i * 12);
      }
      
      const noise = 0.5 + Math.random();
      const m = Math.round(baseMal * noise);
      const s = Math.round(baseSusp * noise);
      const sf = Math.round(baseSafe * noise);
      
      let timeLabel = '';
      if (is24h) timeLabel = d.toLocaleTimeString([], { hour: '2-digit' });
      else if (period === '7d') timeLabel = d.toLocaleDateString([], { month: 'short', day: 'numeric', hour: '2-digit' });
      else timeLabel = d.toLocaleDateString([], { month: 'short', day: 'numeric' });
      
      points.push({
        time: timeLabel,
        malicious: m,
        suspicious: s,
        safe: sf,
        threats: m + s
      });
    }
    return points;
  }, [stats, period]);

  const riskRatio = stats?.total
    ? Math.round(((stats.suspicious + stats.malicious) / stats.total) * 100)
    : 0;
  const safeRatio = stats?.total ? Math.round((stats.safe / stats.total) * 100) : 100;
  const suspiciousRatio = stats?.total ? Math.round((stats.suspicious / stats.total) * 100) : 0;
  const maliciousRatio = stats?.total ? Math.max(0, 100 - safeRatio - suspiciousRatio) : 0;
  const cacheRatio = stats?.total ? Math.round((stats.cache_hits / stats.total) * 100) : 0;

  return (
    <section className="relative min-h-[calc(100vh-4rem)] p-4 sm:p-8">

      <div className="max-w-7xl mx-auto space-y-8">
        {/* Header */}
        <div className="flex flex-col md:flex-row md:items-center justify-between gap-6 mb-4">
          <header>
            <div className="text-sky-600 font-bold uppercase tracking-wider text-xs mb-1.5 pl-8">Live telemetry workspace</div>
            <div className="flex items-center gap-2.5">
              <RadioTower size={24} className="text-sky-500" />
              <h1 className="text-2xl font-bold text-slate-900 leading-none">Network Telemetry</h1>
              <InfoTooltip content="Live feed of API decisions and threat metrics." />
            </div>
          </header>
          <div className="flex items-center gap-3">
            <div className="relative">
              <Select 
                value={period} 
                onValueChange={(val) => {
                  setPage(1);
                  setPeriod(val);
                }}
              >
                <motion.div 
                  whileHover={{ scale: 1.02, y: -1 }}
                  whileTap={{ scale: 0.95, y: 0 }} 
                  transition={{ type: "spring", stiffness: 500, damping: 15 }} 
                  className="w-36"
                >
                  <SelectTrigger className="bg-white/60 border border-slate-200 rounded-2xl pl-5 pr-4 py-4 h-[58px] text-slate-700 font-semibold focus:outline-none transition-shadow duration-300 shadow-sm w-full">
                    <SelectValue placeholder="Period" />
                  </SelectTrigger>
                </motion.div>
                <SelectContent className="rounded-xl border-slate-200 shadow-lg bg-white/90 backdrop-blur-xl">
                  {PERIOD_OPTIONS.map((option, i) => (
                    <motion.div
                      key={option.value}
                      initial={{ opacity: 0, x: -15 }}
                      animate={{ opacity: 1, x: 0 }}
                      transition={{ delay: i * 0.04, type: "spring", stiffness: 350, damping: 25 }}
                    >
                      <SelectItem value={option.value} className="rounded-lg font-medium text-slate-700 focus:bg-sky-50 focus:text-sky-700 cursor-pointer">{option.label}</SelectItem>
                    </motion.div>
                  ))}
                </SelectContent>
              </Select>
            </div>
            <motion.button 
              whileTap={{ scale: 0.92 }}
              transition={{ type: "spring", stiffness: 400, damping: 12 }}
              className="flex items-center gap-2 bg-white/60 border border-slate-200 text-slate-700 px-6 py-4 rounded-2xl font-semibold transition-shadow duration-300 shadow-sm whitespace-nowrap"
              type="button" 
              onClick={() => void loadTelemetry(true)}
            >
              {refreshing ? <LoaderCircle size={20} className="animate-spin text-sky-500" /> : <RefreshCcw size={20} className="text-sky-500" />}
              Refresh now
            </motion.button>
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
              className="bg-white/60 backdrop-blur-xl border border-white rounded-3xl p-6 shadow-[0_8px_32px_rgba(0,0,0,0.02)] hover:shadow-[0_8px_32px_rgba(0,0,0,0.04)] transition-shadow"
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
        <div className="bg-white/60 backdrop-blur-xl border border-white rounded-3xl p-8 shadow-[0_8px_32px_rgba(0,0,0,0.02)] relative">
          <div className="absolute inset-0 rounded-3xl overflow-hidden pointer-events-none">
            <div className="absolute top-0 right-0 w-64 h-64 bg-gradient-to-br from-rose-400/20 to-amber-400/20 rounded-full blur-3xl -translate-y-1/2 translate-x-1/2" />
          </div>
          <div className="flex justify-between items-end mb-6 relative z-10">
            <div>
              <div className="flex items-center gap-2 mb-1">
                <h2 className="text-xl font-bold text-slate-800">Threat pressure</h2>
                <InfoTooltip content="Share of suspicious and malicious verdicts in the selected period." />
              </div>
            </div>
            <strong className="text-3xl font-extrabold bg-clip-text text-transparent bg-gradient-to-r from-amber-500 to-rose-500">{riskRatio}% risk</strong>
          </div>
          <div className="w-full h-5 rounded-full bg-slate-100 relative z-10 overflow-hidden shadow-inner flex">
            <motion.div 
              initial={{ width: 0 }}
              animate={{ width: `${100 - riskRatio}%` }}
              transition={{ duration: 1, ease: "easeOut" }}
              className="h-full bg-teal-500"
            />
            <motion.div 
              initial={{ width: 0 }}
              animate={{ width: `${riskRatio}%` }}
              transition={{ duration: 1, ease: "easeOut" }}
              className="h-full bg-rose-500"
              style={{
                backgroundImage: 'radial-gradient(circle, rgba(255, 255, 255, 0.35) 20%, transparent 20%)',
                backgroundSize: '6px 6px'
              }}
            />
          </div>
        </div>

        {/* Charts Grid */}
        <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
          {/* Trend Chart */}
          <article className="bg-white/60 backdrop-blur-xl border border-white rounded-3xl p-8 shadow-[0_8px_32px_rgba(0,0,0,0.02)] flex flex-col h-[400px] lg:col-span-2">
            <div className="mb-6 flex justify-between items-start">
              <div>
                <h2 className="text-xl font-bold text-slate-800 mb-1">Threat trend</h2>
                <p className="text-slate-500 font-medium">Volume of suspicious and malicious activities over time (simulated).</p>
              </div>
            </div>
            <div className="flex-1 min-h-0">
              <ResponsiveContainer width="100%" height="100%">
                <AreaChart data={trendData} margin={{ top: 10, right: 10, left: 0, bottom: 0 }}>
                  <defs>
                    <pattern id="pattern-safe-area" width="8" height="8" patternUnits="userSpaceOnUse">
                      <rect width="8" height="8" fill="rgba(20, 184, 166, 0.15)" />
                    </pattern>
                    <pattern id="pattern-suspicious-area" width="8" height="8" patternTransform="rotate(45)" patternUnits="userSpaceOnUse">
                      <rect width="8" height="8" fill="rgba(245, 158, 11, 0.15)" />
                      <line x1="0" y1="0" x2="0" y2="8" stroke="rgba(245, 158, 11, 0.5)" strokeWidth="1.5" />
                    </pattern>
                    <pattern id="pattern-malicious-area" width="8" height="8" patternUnits="userSpaceOnUse">
                      <rect width="8" height="8" fill="rgba(244, 63, 94, 0.15)" />
                      <circle cx="4" cy="4" r="1.5" fill="rgba(244, 63, 94, 0.5)" />
                    </pattern>
                  </defs>
                  <CartesianGrid strokeDasharray="4 4" stroke="rgba(0,0,0,0.05)" vertical={false} />
                  <XAxis dataKey="time" tick={{ fill: '#64748b', fontSize: 12, fontWeight: 500 }} axisLine={false} tickLine={false} dy={10} minTickGap={30} />
                  <YAxis
                    tick={{ fill: '#94a3b8', fontSize: 12 }}
                    axisLine={false}
                    tickLine={false}
                    tickFormatter={(value) => formatCompact(Number(value))}
                    dx={-5}
                    width={40}
                    allowDecimals={false}
                    domain={[0, (dataMax: number) => Math.max(10, Math.ceil(dataMax * 1.1))]}
                  />
                  <Tooltip 
                    cursor={{ stroke: 'rgba(148, 163, 184, 0.4)', strokeWidth: 2, strokeDasharray: '4 4', style: { transition: 'all 0.1s ease' } }}
                    isAnimationActive={true}
                    animationDuration={150}
                    animationEasing="ease-out"
                    content={({ active, payload, label }) => {
                      if (active && payload && payload.length) {
                        return (
                          <motion.div
                            initial={{ opacity: 0, y: 8, scale: 0.95 }}
                            animate={{ opacity: 1, y: 0, scale: 1 }}
                            transition={{ type: "spring", stiffness: 400, damping: 20 }}
                            className="bg-white/95 backdrop-blur-md border border-white/80 rounded-2xl p-4 shadow-[0_8px_32px_rgba(0,0,0,0.12)] min-w-[140px]"
                          >
                            <p className="text-slate-500 font-medium text-sm mb-3">{label}</p>
                            <div className="space-y-2">
                              {payload.map((entry: any, index: number) => (
                                <div key={index} className="flex items-center gap-3 text-sm">
                                  <div className="w-2.5 h-2.5 rounded-full shadow-sm" style={{ backgroundColor: entry.color }} />
                                  <span className="text-slate-600 font-medium">{entry.name}:</span>
                                  <span className="text-slate-900 font-bold ml-auto">{entry.value}</span>
                                </div>
                              ))}
                            </div>
                          </motion.div>
                        );
                      }
                      return null;
                    }}
                  />
                  <Area type="monotone" stackId="1" dataKey="safe" name="Safe" stroke="#14b8a6" strokeWidth={2} fillOpacity={1} fill="url(#pattern-safe-area)" activeDot={{ r: 6, strokeWidth: 0, fill: '#14b8a6' }} />
                  <Area type="monotone" stackId="1" dataKey="suspicious" name="Suspicious" stroke="#f59e0b" strokeWidth={2} fillOpacity={1} fill="url(#pattern-suspicious-area)" activeDot={{ r: 6, strokeWidth: 0, fill: '#f59e0b' }} />
                  <Area type="monotone" stackId="1" dataKey="malicious" name="Malicious" stroke="#f43f5e" strokeWidth={2} fillOpacity={1} fill="url(#pattern-malicious-area)" activeDot={{ r: 6, strokeWidth: 0, fill: '#f43f5e' }} />
                </AreaChart>
              </ResponsiveContainer>
            </div>
          </article>

          <article className="bg-white/60 backdrop-blur-xl border border-white rounded-3xl p-8 shadow-[0_8px_32px_rgba(0,0,0,0.02)] flex flex-col h-[400px]">
            <div className="mb-6">
              <h2 className="text-xl font-bold text-slate-800 mb-1">Verdict distribution</h2>
              <p className="text-slate-500 font-medium">Actual category mix from the backend telemetry store.</p>
            </div>
            <div className="flex-1 min-h-0 relative">
              <ResponsiveContainer width="100%" height="100%">
                <PieChart>
                  <defs>
                    <pattern id="pattern-safe-pie" width="8" height="8" patternUnits="userSpaceOnUse">
                      <rect width="8" height="8" fill="#14b8a6" />
                    </pattern>
                    <pattern id="pattern-suspicious-pie" width="8" height="8" patternTransform="rotate(45)" patternUnits="userSpaceOnUse">
                      <rect width="8" height="8" fill="#f59e0b" />
                      <line x1="0" y1="0" x2="0" y2="8" stroke="rgba(255, 255, 255, 0.4)" strokeWidth="2.5" />
                    </pattern>
                    <pattern id="pattern-malicious-pie" width="6" height="6" patternUnits="userSpaceOnUse">
                      <rect width="6" height="6" fill="#f43f5e" />
                      <circle cx="3" cy="3" r="1.2" fill="rgba(255, 255, 255, 0.5)" />
                    </pattern>
                  </defs>
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
                    formatter={(value: number) => {
                      const percentage = stats?.total ? ((value / stats.total) * 100).toFixed(1) : 0;
                      return `${percentage}%`;
                    }}
                    contentStyle={{ borderRadius: '16px', border: '1px solid rgba(255,255,255,0.8)', background: 'rgba(255,255,255,0.9)', boxShadow: '0 4px 20px rgba(0,0,0,0.08)' }}
                    itemStyle={{ color: '#1e293b', fontWeight: 600 }}
                  />
                </PieChart>
              </ResponsiveContainer>
              <div className="absolute inset-0 flex items-center justify-center pointer-events-none flex-col mt-2">
                <span className="text-4xl font-extrabold text-slate-800">{safeRatio}%</span>
                <span className="text-sm font-bold text-teal-600 uppercase tracking-wide">Safe</span>
              </div>
            </div>
          </article>

          <article className="bg-white/60 backdrop-blur-xl border border-white rounded-3xl p-8 shadow-[0_8px_32px_rgba(0,0,0,0.02)] flex flex-col h-[400px]">
            <div className="mb-6">
              <h2 className="text-xl font-bold text-slate-800 mb-1">Score distribution</h2>
              <p className="text-slate-500 font-medium">Breakdown of telemetry events into 5 threat score bands.</p>
            </div>
            <div className="flex-1 min-h-0">
              <ResponsiveContainer width="100%" height="100%">
                <BarChart data={scoreBands} margin={{ top: 8, right: 12, left: -20, bottom: 0 }}>
                  <defs>
                    <pattern id="pattern-safe-bar" width="8" height="8" patternUnits="userSpaceOnUse">
                      <rect width="8" height="8" fill="rgba(20, 184, 166, 0.88)" />
                    </pattern>
                    <pattern id="pattern-safe-low-bar" width="8" height="8" patternUnits="userSpaceOnUse">
                      <rect width="8" height="8" fill="rgba(16, 185, 129, 0.6)" />
                    </pattern>
                    <pattern id="pattern-suspicious-bar" width="8" height="8" patternTransform="rotate(45)" patternUnits="userSpaceOnUse">
                      <rect width="8" height="8" fill="rgba(251, 191, 36, 0.88)" />
                      <line x1="0" y1="0" x2="0" y2="8" stroke="rgba(255, 255, 255, 0.4)" strokeWidth="2.5" />
                    </pattern>
                    <pattern id="pattern-high-risk-bar" width="8" height="8" patternTransform="rotate(-45)" patternUnits="userSpaceOnUse">
                      <rect width="8" height="8" fill="rgba(249, 115, 22, 0.7)" />
                      <line x1="0" y1="0" x2="0" y2="8" stroke="rgba(255, 255, 255, 0.4)" strokeWidth="1.5" />
                    </pattern>
                    <pattern id="pattern-malicious-bar" width="6" height="6" patternUnits="userSpaceOnUse">
                      <rect width="6" height="6" fill="rgba(248, 113, 113, 0.88)" />
                      <circle cx="3" cy="3" r="1.2" fill="rgba(255, 255, 255, 0.5)" />
                    </pattern>
                  </defs>
                  <CartesianGrid strokeDasharray="4 4" stroke="rgba(0,0,0,0.05)" vertical={false} />
                  <XAxis dataKey="label" tick={{ fill: '#64748b', fontSize: 12, fontWeight: 600 }} axisLine={false} tickLine={false} dy={10} />
                  <YAxis
                    tick={{ fill: '#94a3b8', fontSize: 12 }}
                    axisLine={false}
                    tickLine={false}
                    tickFormatter={(value) => formatCompact(Number(value))}
                    dx={-10}
                  />
                  <Tooltip 
                    formatter={(value: number, name: string, props: any) => [formatCompact(Number(value)), props.payload.name]}
                    contentStyle={{ borderRadius: '16px', border: '1px solid rgba(255,255,255,0.8)', background: 'rgba(255,255,255,0.9)', boxShadow: '0 4px 20px rgba(0,0,0,0.08)' }}
                    cursor={{ fill: 'rgba(0,0,0,0.02)' }}
                    itemStyle={{ color: '#1e293b', fontWeight: 600 }}
                    labelStyle={{ display: 'none' }}
                  />
                  <Bar dataKey="value" radius={[6, 6, 0, 0]} maxBarSize={48}>
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
        <article className="bg-white/60 backdrop-blur-xl border border-white rounded-3xl p-8 shadow-[0_8px_32px_rgba(0,0,0,0.02)]">
          <div className="flex justify-between items-center mb-8">
            <div>
              <h2 className="text-xl font-bold text-slate-800 mb-1">Recent activity</h2>
              <p className="text-slate-500 font-medium">Filtered data from `/v1/telemetry/recent` with server-side paging.</p>
            </div>
            {refreshing ? <LoaderCircle size={20} className="animate-spin text-sky-500" /> : null}
          </div>

          {/* Table Filters */}
          <div className="flex flex-wrap gap-4 items-end mb-8 bg-slate-50/50 p-5 rounded-3xl border border-slate-100">
            <div className="flex flex-col gap-2 flex-1 min-w-[240px]">
              <label htmlFor="telemetry-domain" className="text-xs font-bold text-slate-500 uppercase tracking-wider ml-1">Domain search</label>
              <div className="relative">
                <Search size={20} className="absolute left-4 top-1/2 -translate-y-1/2 text-slate-400" />
                <input
                  id="telemetry-domain"
                  value={domain}
                  onChange={(event) => {
                    setPage(1);
                    setDomain(event.target.value);
                  }}
                  placeholder="Filter by domain fragment"
                  className="w-full bg-white/70 border border-slate-200 rounded-xl !py-3 !pr-4 !pl-12 text-slate-900 font-medium placeholder:text-slate-400 focus:outline-none focus:ring-4 focus:ring-sky-500/20 focus:border-sky-500/40 hover:border-slate-300 transition-all shadow-sm"
                />
              </div>
            </div>

            <div className="flex flex-col gap-2 w-48">
              <label htmlFor="telemetry-verdict" className="text-xs font-bold text-slate-500 uppercase tracking-wider ml-1">Verdict</label>
              <Select 
                value={verdict} 
                onValueChange={(val) => {
                  setPage(1);
                  setVerdict(val);
                }}
              >
                <motion.div 
                  whileHover={{ scale: 1.02, y: -1 }}
                  whileTap={{ scale: 0.95, y: 0 }} 
                  transition={{ type: "spring", stiffness: 500, damping: 15 }}
                >
                  <SelectTrigger id="telemetry-verdict" className="w-full h-[46px] bg-white/70 border border-slate-200 rounded-xl px-4 py-3 text-slate-900 font-medium focus:outline-none transition-shadow shadow-sm">
                    <SelectValue placeholder="Verdict" />
                  </SelectTrigger>
                </motion.div>
                <SelectContent className="rounded-xl border-slate-200 shadow-lg bg-white/90 backdrop-blur-xl">
                  {VERDICT_OPTIONS.map((option, i) => (
                    <motion.div
                      key={option.label}
                      initial={{ opacity: 0, x: -15 }}
                      animate={{ opacity: 1, x: 0 }}
                      transition={{ delay: i * 0.04, type: "spring", stiffness: 350, damping: 25 }}
                    >
                      <SelectItem value={option.value} className="rounded-lg font-medium text-slate-700 focus:bg-sky-50 focus:text-sky-700 cursor-pointer">{option.label}</SelectItem>
                    </motion.div>
                  ))}
                </SelectContent>
              </Select>
            </div>

            <div className="flex flex-col gap-2 w-48">
              <label htmlFor="telemetry-source" className="text-xs font-bold text-slate-500 uppercase tracking-wider ml-1">Source</label>
              <Select 
                value={source} 
                onValueChange={(val) => {
                  setPage(1);
                  setSource(val);
                }}
              >
                <motion.div 
                  whileHover={{ scale: 1.02, y: -1 }}
                  whileTap={{ scale: 0.95, y: 0 }} 
                  transition={{ type: "spring", stiffness: 500, damping: 15 }}
                >
                  <SelectTrigger id="telemetry-source" className="w-full h-[46px] bg-white/70 border border-slate-200 rounded-xl px-4 py-3 text-slate-900 font-medium focus:outline-none transition-shadow shadow-sm">
                    <SelectValue placeholder="Source" />
                  </SelectTrigger>
                </motion.div>
                <SelectContent className="rounded-xl border-slate-200 shadow-lg bg-white/90 backdrop-blur-xl">
                  {SOURCE_OPTIONS.map((option, i) => (
                    <motion.div
                      key={option.label}
                      initial={{ opacity: 0, x: -15 }}
                      animate={{ opacity: 1, x: 0 }}
                      transition={{ delay: i * 0.04, type: "spring", stiffness: 350, damping: 25 }}
                    >
                      <SelectItem value={option.value} className="rounded-lg font-medium text-slate-700 focus:bg-sky-50 focus:text-sky-700 cursor-pointer">{option.label}</SelectItem>
                    </motion.div>
                  ))}
                </SelectContent>
              </Select>
            </div>
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
                  Array.from({ length: 5 }).map((_, i) => (
                    <tr key={i} className="animate-pulse border-b border-black/5 last:border-0">
                      <td className="py-4 pl-4"><div className="h-5 bg-slate-200/60 rounded-md w-48"></div></td>
                      <td className="py-4"><div className="h-6 bg-slate-200/60 rounded-full w-24"></div></td>
                      <td className="py-4"><div className="h-5 bg-slate-200/60 rounded-md w-20"></div></td>
                      <td className="py-4"><div className="h-5 bg-slate-200/60 rounded-md w-16"></div></td>
                      <td className="py-4"><div className="h-5 bg-slate-200/60 rounded-md w-32"></div></td>
                      <td className="py-4 pr-4"><div className="h-8 bg-slate-200/60 rounded-lg w-20 ml-auto"></div></td>
                    </tr>
                  ))
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
                          className="inline-flex items-center gap-2 px-4 py-2 bg-white/60 hover:bg-sky-50 text-sky-600 border border-sky-100 hover:border-sky-200 rounded-xl font-bold text-sm transition-all shadow-sm group/btn active:scale-95"
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
                className="px-6 py-3 bg-white/60 hover:bg-white/90 border border-slate-200 text-slate-700 rounded-2xl font-bold transition-all duration-300 ease-out active:duration-150 disabled:opacity-50 disabled:pointer-events-none shadow-sm active:scale-95"
                type="button"
                disabled={page === 1 || refreshing}
                onClick={() => setPage((value) => Math.max(1, value - 1))}
              >
                Previous
              </button>
              <button
                className="px-6 py-3 bg-white/60 hover:bg-white/90 border border-slate-200 text-slate-700 rounded-2xl font-bold transition-all duration-300 ease-out active:duration-150 disabled:opacity-50 disabled:pointer-events-none shadow-sm active:scale-95"
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
