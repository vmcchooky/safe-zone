import { useState, useEffect } from 'react';
import { 
  Activity, ShieldCheck, ShieldBan, 
  Search, Globe, ChevronRight, Zap, Target, AlertTriangle, Fingerprint, Loader2, X, CheckCircle2, Info
} from 'lucide-react';
import { motion, AnimatePresence } from 'framer-motion';
import { InfoTooltip } from '../../components/InfoTooltip';

export interface Evidence {
  domain: string;
  source_url: string;
  source_title?: string;
  source_type: string;
  confidence: number;
  matched_terms?: string[];
  retrieved_at: string;
}

export interface AnalysisResult {
  domain: string;
  verdict: 'SAFE' | 'SUSPICIOUS' | 'MALICIOUS' | 'INVALID';
  confidence: number;
  score: number;
  reasons: string[];
  category?: string;
  cache_hit: boolean;
  analyzed_at: string;
  evidence?: Evidence[];
}

export interface RawDNS {
  resolved: boolean;
  nameservers?: string[];
  error?: string;
}

export interface RawTLS {
  has_tls: boolean;
  valid: boolean;
  self_signed: boolean;
  expired: boolean;
  issuer: string;
  subject: string;
  san_match: boolean;
  cert_age_days: number;
  is_wildcard: boolean;
  not_before: string;
  not_after: string;
  score: number;
  reasons: string[];
}

export interface RawWHOIS {
  found: boolean;
  registered_date?: string;
  domain_age_days: number;
  registrar?: string;
  privacy_guard: boolean;
  score: number;
  reasons: string[];
}

export interface RawInspection {
  domain: string;
  dns: RawDNS;
  tls: RawTLS;
  whois: RawWHOIS;
  inspect_at: string;
}

interface ToastMessage {
  id: string;
  message: string;
  type: 'success' | 'error' | 'info' | 'allow' | 'block';
}

export function AnalysisPage() {
  const [domain, setDomain] = useState('');
  const [isScanning, setIsScanning] = useState(false);
  const [result, setResult] = useState<AnalysisResult | null>(null);
  const [showRawData, setShowRawData] = useState(false);
  const [rawData, setRawData] = useState<RawInspection | null>(null);
  const [rawLoading, setRawLoading] = useState(false);
  const [recentAnalyses, setRecentAnalyses] = useState<AnalysisResult[]>([]);
  const [error, setError] = useState('');
  const [toasts, setToasts] = useState<ToastMessage[]>([]);

  const addToast = (message: string, type: 'success' | 'error' | 'info' | 'allow' | 'block' = 'info') => {
    const id = Math.random().toString(36).substr(2, 9);
    setToasts(prev => [...prev, { id, message, type }]);
    setTimeout(() => {
      setToasts(prev => prev.filter(t => t.id !== id));
    }, 5000);
  };

  const fetchRecentAnalyses = async () => {
    try {
      const res = await fetch('/v1/analysis/recent');
      if (!res.ok) throw new Error('Failed to fetch history');
      const data = await res.json();
      setRecentAnalyses((data.items || []).slice(0, 10));
    } catch (err) {
      console.error(err);
    }
  };

  useEffect(() => {
    fetchRecentAnalyses();
  }, []);

  const handleAnalyze = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!domain.trim()) return;

    setIsScanning(true);
    setResult(null);
    setError('');

    try {
      const res = await fetch(`/v1/analyze?domain=${encodeURIComponent(domain)}&include_evidence=1`);
      if (!res.ok) {
         throw new Error(`Analysis failed: ${res.statusText}`);
      }
      const data = await res.json();
      setResult(data);
      fetchRecentAnalyses();
    } catch (err: any) {
      setError(err.message || 'An error occurred');
    } finally {
      setIsScanning(false);
    }
  };

  const setQuickDomain = (d: string) => {
    setDomain(d);
  };

  return (
    <>
      <div className="flex flex-col gap-6 max-w-7xl mx-auto p-4 lg:p-8 animate-in fade-in duration-500 pb-32">
        {/* Page Header */}
      <header className="mb-4">
        <div className="text-xs font-bold tracking-wider uppercase text-sky-600 mb-1.5 pl-8">
          Analysis Deck
        </div>
        <div className="flex items-center gap-2.5">
          <Activity size={24} className="text-sky-500" />
          <h1 className="text-2xl font-bold text-slate-900 leading-none">Domain Inspection</h1>
          <InfoTooltip content="Fast lexical and evidence-backed triage for suspicious destinations." />
        </div>
      </header>

      {/* Inspection Dock */}
      <section className="bg-transparent border border-black/5 rounded-3xl p-6 shadow-sm relative overflow-hidden">
        {/* Subtle decorative glow */}
        <motion.div 
          className="absolute top-0 right-0 w-64 h-64 bg-sky-400/10 rounded-full blur-3xl pointer-events-none"
          animate={{
            x: [0, 30, -15, 0],
            y: [0, -25, 20, 0],
            scale: [1, 1.15, 0.9, 1]
          }}
          transition={{
            duration: 15,
            repeat: Infinity,
            ease: "easeInOut"
          }}
          style={{ originX: 0.5, originY: 0.5, willChange: "transform, opacity" }}
        />
        


        <form onSubmit={handleAnalyze} className="flex flex-col md:flex-row gap-4 relative">
          <div className="flex-1 relative">
            <Search className="absolute left-5 top-1/2 -translate-y-1/2 text-slate-400" size={22} />
            <input 
              type="text" 
              value={domain}
              onChange={(e) => setDomain(e.target.value)}
              placeholder="secure-login-wallet-example.com"
              className="w-full bg-slate-50/70 border border-slate-200 rounded-2xl !py-4 !pr-4 !pl-16 text-slate-900 font-medium placeholder:text-slate-400 focus:outline-none focus:ring-4 focus:ring-sky-500/20 focus:border-sky-500/40 hover:border-slate-300 hover:shadow-md focus:shadow-md transition-all duration-300 shadow-sm"
              spellCheck="false"
              autoComplete="off"
            />
          </div>
          <button 
            type="submit"
            disabled={isScanning || !domain.trim()}
            className="bg-slate-900 hover:bg-slate-800 disabled:bg-slate-400 text-slate-50 px-8 py-4 rounded-2xl font-semibold flex items-center justify-center gap-2 transition-all duration-300 ease-out active:duration-150 shadow-md active:scale-90 active:translate-y-1"
          >
            {isScanning ? <Loader2 className="animate-spin" size={20} /> : <Zap size={20} />}
            Analyze
          </button>
          <button 
            type="button"
            onClick={async () => {
              if (!domain.trim() || isScanning) return;
              setIsScanning(true);
              setError('');
              setResult(null);
              try {
                const res = await fetch(`/v1/analyze?domain=${encodeURIComponent(domain)}&include_evidence=1&force_osint=1`);
                if (!res.ok) throw new Error('Analysis failed');
                const data = await res.json();
                setResult(data);
                if (data.domain) {
                  setRecentAnalyses(prev => {
                    const filtered = prev.filter(p => p.domain !== data.domain);
                    return [data, ...filtered].slice(0, 10);
                  });
                }
              } catch (err: any) {
                setError(err.message || 'An error occurred during analysis');
              } finally {
                setIsScanning(false);
              }
            }}
            disabled={isScanning || !domain.trim()}
            className="bg-slate-50/60 hover:bg-slate-50/90 hover:-translate-y-0.5 hover:scale-[1.02] border border-slate-200 text-slate-700 px-6 py-4 rounded-2xl font-semibold transition-all duration-300 ease-out active:duration-150 shadow-sm active:scale-90 active:translate-y-1 disabled:opacity-50 disabled:pointer-events-none"
          >
            OSINT
          </button>
        </form>

        <div className="mt-6 flex flex-wrap gap-2 items-center text-sm relative">
          <span className="text-slate-500 font-medium mr-2">Quick actions:</span>
          {['example.com', 'login-update.test', 'secure-wallet.test'].map((d, i) => (
            <button 
              key={d}
              type="button"
              onClick={() => setQuickDomain(d)}
              className={`bg-slate-50/50 hover:bg-slate-50 border border-slate-200 text-slate-700 px-3 py-1.5 rounded-lg transition-all duration-300 ease-out shadow-sm hover:border-sky-200 ${
                i % 2 === 0 ? 'event-card-tilt-left hover:shadow-md' : 'event-card-tilt-right hover:shadow-md'
              }`}
            >
              {d}
            </button>
          ))}
        </div>

        <AnimatePresence>
          {error && (
            <motion.div 
              initial={{ opacity: 0, y: -10 }} 
              animate={{ opacity: 1, y: 0 }} 
              exit={{ opacity: 0, y: -10 }}
              className="mt-6 relative z-10 text-rose-700 text-sm font-medium bg-rose-50 p-4 rounded-xl border border-rose-200 flex items-center gap-3 shadow-sm"
            >
              <AlertTriangle size={18} className="text-rose-600 shrink-0" />
              {error}
            </motion.div>
          )}
        </AnimatePresence>
      </section>

      {/* Grid: Risk Dossier + Event Stream */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        
        {/* Risk Dossier */}
        <section className="lg:col-span-2 bg-transparent border border-black/5 rounded-3xl p-6 shadow-sm relative h-[430px] flex flex-col">
          
          <div className="flex justify-between items-start mb-6 z-10">
            <div className="flex items-center gap-2">
              <div className="text-xs font-semibold tracking-wider uppercase text-slate-500">Risk dossier</div>
              <InfoTooltip content="Detailed analysis and evidence-backed triage for the destination." />
            </div>
          </div>

          <div className="flex-1 flex flex-col relative z-10">
            {/* Empty State */}
            <AnimatePresence mode="wait">
              {!isScanning && !result && (
                <motion.div 
                  key="empty"
                  initial={{ opacity: 0 }}
                  animate={{ opacity: 1 }}
                  exit={{ opacity: 0 }}
                  className="flex-1 flex flex-col items-center justify-center text-center p-8 text-slate-500"
                >
                  <Target size={48} strokeWidth={1} className="mb-4 text-slate-400 opacity-50" />
                  <h3 className="text-lg font-semibold text-slate-700 mb-2">Awaiting inspection target</h3>
                  <p className="max-w-sm">Enter a domain above to generate verdict, score, confidence, signals, and evidence.</p>
                </motion.div>
              )}

              {/* Scanning State */}
              {isScanning && (
                <motion.div 
                  key="scanning"
                  initial={{ opacity: 0 }}
                  animate={{ opacity: 1 }}
                  exit={{ opacity: 0 }}
                  className="flex-1 flex flex-col items-center justify-center relative"
                >
                  {/* Laser effect */}
                  <motion.div 
                    className="absolute w-full h-[2px] bg-sky-400 shadow-[0_0_20px_4px_rgba(56,189,248,0.5)] z-20"
                    animate={{ top: ['0%', '100%', '0%'] }}
                    transition={{ duration: 1.5, repeat: Infinity, ease: "linear" }}
                  />
                  <div className="w-full max-w-md space-y-4 opacity-50">
                    <div className="h-8 bg-slate-200 rounded-lg w-3/4 animate-pulse" />
                    <div className="h-24 bg-slate-200 rounded-xl w-full animate-pulse" />
                    <div className="h-12 bg-slate-200 rounded-lg w-1/2 animate-pulse" />
                  </div>
                </motion.div>
              )}

              {/* Result State */}
              {!isScanning && result && (
                <motion.div 
                  key="result"
                  initial={{ opacity: 0, y: 20 }}
                  animate={{ opacity: 1, y: 0 }}
                  className="flex flex-col gap-6"
                >
                  <div className="flex items-start justify-between">
                    <div>
                      <h3 className="text-2xl font-bold text-slate-900 mb-2 flex items-center gap-2">
                        <Globe className="text-slate-400" /> {result.domain}
                      </h3>
                      <div className="flex gap-3">
                        <span className={`px-3 py-1 rounded-full text-sm font-bold flex items-center gap-1.5 ${
                          result.verdict === 'MALICIOUS' ? 'bg-rose-100 text-rose-700 border border-rose-200' : 'bg-teal-100 text-teal-700 border border-teal-200'
                        }`}>
                          {result.verdict === 'MALICIOUS' ? <ShieldBan size={16} /> : <ShieldCheck size={16} />}
                          {result.verdict}
                        </span>
                        <span className="px-3 py-1 rounded-full text-sm font-medium bg-slate-100 text-slate-600 border border-slate-200">
                          Score: {result.score}/100
                        </span>
                      </div>
                    </div>
                  </div>

                  <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                    <div className="bg-slate-50 border border-slate-200 rounded-2xl p-4">
                      <div className="text-sm font-semibold text-slate-500 mb-3 flex items-center gap-2">
                        <Fingerprint size={16} /> Signals Detected
                      </div>
                      <ul className="space-y-2">
                        {result.reasons && result.reasons.length > 0 ? (
                          result.reasons.map((sig, i) => (
                            <li key={i} className="flex items-start gap-2 text-slate-700 font-medium text-sm">
                              <ChevronRight size={14} className="text-sky-500 shrink-0 mt-0.5" />
                              <span>{sig}</span>
                            </li>
                          ))
                        ) : (
                          <li className="text-slate-500 text-sm">No specific signals detected.</li>
                        )}
                      </ul>
                    </div>
                    
                    <div className="bg-slate-50 border border-slate-200 rounded-2xl p-4 flex flex-col">
                      <div className="text-sm font-semibold text-slate-500 mb-2 flex items-center gap-2">
                        <AlertTriangle size={16} /> OSINT Evidence
                      </div>
                      {result.evidence && result.evidence.length > 0 ? (
                        <div className="space-y-3 flex-1 overflow-y-auto max-h-48 pr-2">
                          {result.evidence.map((ev, i) => (
                            <div key={i} className="text-xs text-slate-600 bg-slate-50 p-2.5 rounded-xl border border-slate-100">
                              <div className="font-semibold text-slate-800 break-words flex items-center gap-1.5">
                                <Globe size={12} className="text-slate-400" />
                                {ev.source_title || ev.source_type}
                              </div>
                              <a href={ev.source_url} target="_blank" rel="noreferrer" className="text-sky-600 hover:underline break-all mt-1 inline-block">{ev.source_url}</a>
                              {ev.matched_terms && ev.matched_terms.length > 0 && (
                                <div className="mt-2 flex flex-wrap gap-1.5">
                                  {ev.matched_terms.map(t => <span key={t} className="px-1.5 py-0.5 bg-rose-100 text-rose-700 rounded-md text-[10px] uppercase font-bold">{t}</span>)}
                                </div>
                              )}
                            </div>
                          ))}
                        </div>
                      ) : (
                        <div className="flex-1 text-slate-500 text-sm flex items-center">
                          No external OSINT evidence found.
                        </div>
                      )}
                      
                      <div className="mt-4 pt-3 border-t border-slate-100 flex items-center justify-between">
                        <div className="text-sm font-semibold text-slate-500">System Confidence</div>
                        <div className="text-slate-900 font-bold bg-slate-100 px-2 py-0.5 rounded-md text-sm">
                          {Math.round(result.confidence * 100)}%
                        </div>
                      </div>
                    </div>
                  </div>

                  <div className="mt-auto pt-4 border-t border-slate-100 flex justify-end gap-3">
                       <motion.button 
                         initial={{ opacity: 0, scale: 0.3 }}
                         animate={{ opacity: 1, scale: 1 }}
                         transition={{ type: "spring", stiffness: 300, damping: 15, delay: 0.1 }}
                         style={{ backgroundColor: '#F4C2C2', color: '#f8fafc' }}
                         onClick={async () => {
                           if (!result) return;
                           try {
                             const res = await fetch('/v1/overrides', {
                               method: 'POST',
                               headers: { 'Content-Type': 'application/json' },
                               body: JSON.stringify({ domain: result.domain, action: 'allow', reason: 'Manual override from dashboard' })
                             });
                             if (res.ok) {
                               addToast(`Successfully allowed ${result.domain}`, 'allow');
                             } else {
                               const err = await res.json().catch(() => ({}));
                               addToast(`Failed: ${err.error || res.statusText}`, 'error');
                             }
                           } catch (err: any) { addToast(`Error: ${err.message}`, 'error'); }
                         }}
                         className="px-6 py-2 rounded-xl font-bold shadow-sm active:!scale-90 active:!translate-y-1 transition-all duration-300 ease-out active:duration-150">
                         Allow
                       </motion.button>
                       <motion.button 
                         initial={{ opacity: 0, scale: 0.3 }}
                         animate={{ opacity: 1, scale: 1 }}
                         transition={{ type: "spring", stiffness: 300, damping: 15, delay: 0.2 }}
                         style={{ backgroundColor: '#64748b', color: '#f8fafc' }}
                         onClick={async () => {
                           if (!result) return;
                           try {
                             const res = await fetch('/v1/overrides', {
                               method: 'POST',
                               headers: { 'Content-Type': 'application/json' },
                               body: JSON.stringify({ domain: result.domain, action: 'block', reason: 'Manual override from dashboard' })
                             });
                             if (res.ok) {
                               addToast(`Successfully blocked ${result.domain}`, 'block');
                             } else {
                               const err = await res.json().catch(() => ({}));
                               addToast(`Failed: ${err.error || res.statusText}`, 'error');
                             }
                           } catch (err: any) { addToast(`Error: ${err.message}`, 'error'); }
                         }}
                         className="px-6 py-2 rounded-xl font-bold shadow-sm active:!scale-90 active:!translate-y-1 transition-all duration-300 ease-out active:duration-150">
                         Block
                       </motion.button>
                       <motion.button 
                         initial={{ opacity: 0, scale: 0.3 }}
                         animate={{ opacity: 1, scale: 1 }}
                         transition={{ type: "spring", stiffness: 300, damping: 15, delay: 0.3 }}
                         onClick={async () => {
                           if (!result) return;
                           setShowRawData(true);
                           setRawData(null);
                           setRawLoading(true);
                           try {
                             const res = await fetch(`/v1/analyze/raw?domain=${encodeURIComponent(result.domain)}`);
                             if (res.ok) {
                               setRawData(await res.json());
                             }
                           } catch (err) {
                             console.error('Raw data fetch failed:', err);
                           } finally {
                             setRawLoading(false);
                           }
                         }}
                         className="bg-slate-50 hover:bg-slate-50 border border-slate-200 text-slate-700 px-4 py-2 rounded-xl font-medium shadow-sm active:!scale-90 active:!translate-y-1 transition-all duration-300 ease-out active:duration-150">
                         View Raw Data
                       </motion.button>
                  </div>
                </motion.div>
              )}
            </AnimatePresence>
          </div>
        </section>

        {/* Event Stream */}
        <aside className="bg-transparent border border-black/5 rounded-3xl p-6 shadow-sm flex flex-col h-[430px]">
          <div className="flex justify-between items-start mb-6">
            <div>
              <div className="text-xs font-semibold tracking-wider uppercase text-slate-500 mb-1">Event Stream</div>
              <h2 className="text-xl font-bold text-slate-900">Recent activity</h2>
            </div>
            <span className="text-xs font-medium px-2 py-1 bg-slate-100 text-slate-600 rounded-md border border-slate-200">
              {recentAnalyses.length}
            </span>
          </div>

          <div className="flex-1 min-h-0 overflow-y-auto px-2 py-1 space-y-3 [&::-webkit-scrollbar]:hidden [-ms-overflow-style:none] [scrollbar-width:none]">
            {recentAnalyses.map((item, i) => (
              <div 
                key={i} 
                className={`bg-slate-50/70 border border-slate-100 rounded-2xl p-3 flex flex-col gap-2 cursor-pointer shadow-sm group hover:border-sky-200 transition-all duration-300 ${
                  i % 2 === 0 ? 'event-card-tilt-left hover:shadow-md' : 'event-card-tilt-right hover:shadow-md'
                }`}
                onClick={() => setQuickDomain(item.domain)}
              >
                <div className="flex justify-between items-start">
                  <span className="font-semibold text-slate-900 truncate pr-2 text-sm group-hover:text-sky-600 transition-colors">{item.domain}</span>
                  <span className="text-xs text-slate-400 whitespace-nowrap">
                    {new Date(item.analyzed_at).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })}
                  </span>
                </div>
                <div className="flex items-center justify-between">
                  <span className={`text-[10px] font-bold uppercase px-2 py-0.5 rounded-full ${
                    item.verdict === 'MALICIOUS' ? 'bg-rose-100 text-rose-700' : 
                    item.verdict === 'SUSPICIOUS' ? 'bg-amber-100 text-amber-700' : 
                    item.verdict === 'INVALID' ? 'bg-slate-100 text-slate-600' :
                    'bg-teal-100 text-teal-700'
                  }`}>
                    {item.verdict}
                  </span>
                  <span className="text-xs font-medium text-slate-500">Score: {item.score}</span>
                </div>
              </div>
            ))}
          </div>
        </aside>

      </div>
    </div>

      {/* Raw Data Modal */}
      <AnimatePresence>
        {showRawData && result && (
          <div className="fixed inset-0 z-[100] flex items-center justify-center p-4 sm:p-6 transform-gpu">
            <motion.div 
              initial={{ opacity: 0 }}
              animate={{ opacity: 1 }}
              exit={{ opacity: 0 }}
              transition={{ duration: 0.2 }}
              onClick={() => setShowRawData(false)}
              className="absolute inset-0 bg-slate-900/25 backdrop-blur-[12px]"
              style={{ willChange: "opacity" }}
            />
            <motion.div
              layout
              initial={{ opacity: 0, scale: 0.95, y: 20 }}
              animate={{ opacity: 1, scale: 1, y: 0 }}
              exit={{ opacity: 0, scale: 0.95, y: 20 }}
              transition={{ type: "spring", stiffness: 350, damping: 25 }}
              className="relative w-full max-w-4xl max-h-[85vh] rounded-2xl shadow-[0_50px_100px_rgba(0,0,0,0.12)] border border-slate-50/60 overflow-hidden flex flex-col transform-gpu"
              style={{ willChange: "opacity, transform" }}
            >
              {/* Glass background */}
              <div className="absolute inset-0 bg-slate-50/80 backdrop-blur-3xl saturate-[1.6] -z-10" />

              {/* Header */}
              <div className="px-8 py-6 border-b border-black/5 flex justify-between items-center bg-slate-50/30">
                <h3 className="text-xl font-bold text-slate-800 flex items-center gap-3">
                  <div className="p-2 bg-slate-50/50 rounded-xl border border-slate-50/80 shadow-sm">
                     <Activity size={20} className="text-sky-600" />
                  </div>
                  Raw Telemetry Data
                </h3>
                <button 
                  onClick={() => setShowRawData(false)}
                  className="p-2.5 rounded-full bg-slate-50/40 hover:bg-slate-50/60 border border-slate-50/80 text-slate-600 transition-all active:scale-95 shadow-sm"
                >
                  <X size={18} strokeWidth={2.5} />
                </button>
              </div>
              
              {/* Table Body */}
              <div className="flex-1 overflow-y-auto p-8">
                {rawLoading ? (
                  <div className="flex flex-col items-center justify-center py-16 text-slate-500">
                    <Loader2 className="animate-spin mb-4" size={32} />
                    <p className="text-sm font-medium">Inspecting DNS, TLS & WHOIS...</p>
                  </div>
                ) : rawData ? (
                <div className="bg-slate-50/30 rounded-xl border border-slate-50/60 shadow-[0_8px_32px_rgba(0,0,0,0.02),inset_0_0_20px_rgba(255,255,255,0.2)] overflow-hidden">
                  <table className="w-full text-sm text-left border-collapse">
                    <thead className="bg-slate-50/45 text-slate-800 font-bold border-b border-black/5">
                      <tr>
                        <th className="px-6 py-5 w-1/3">PROPERTY</th>
                        <th className="px-6 py-5 w-2/3">VALUE</th>
                      </tr>
                    </thead>
                    <motion.tbody 
                      initial="hidden"
                      animate="show"
                      variants={{
                        hidden: {},
                        show: {
                          transition: {
                            staggerChildren: 0.06
                          }
                        }
                      }}
                      className="divide-y divide-black/5 text-slate-800"
                    >
                      <motion.tr 
                        variants={{
                          hidden: { opacity: 0, x: -10 },
                          show: { opacity: 1, x: 0, transition: { type: "spring", stiffness: 300, damping: 20 } }
                        }}
                        className="hover:bg-slate-50/50 transition-colors group"
                      >
                        <td className="px-6 py-4 font-semibold text-slate-600 group-hover:text-slate-900 transition-colors">Target Domain</td>
                        <td className="px-6 py-4 font-mono text-sm">{rawData.domain}</td>
                      </motion.tr>
                      <motion.tr 
                        variants={{
                          hidden: { opacity: 0, x: -10 },
                          show: { opacity: 1, x: 0, transition: { type: "spring", stiffness: 300, damping: 20 } }
                        }}
                        className="hover:bg-slate-50/50 transition-colors group"
                      >
                        <td className="px-6 py-4 font-semibold text-slate-600 group-hover:text-slate-900 transition-colors">DNS Status</td>
                        <td className="px-6 py-4">
                          <span className={`px-2.5 py-1 rounded-lg text-xs font-bold uppercase tracking-wider ${
                            rawData.dns.resolved ? 'bg-teal-100 text-teal-700' : 'bg-rose-100 text-rose-700'
                          }`}>
                            {rawData.dns.resolved ? 'Resolved' : 'Failed'}
                          </span>
                          {rawData.dns.error && <span className="ml-2 text-xs text-rose-500">{rawData.dns.error}</span>}
                        </td>
                      </motion.tr>
                      <motion.tr 
                        variants={{
                          hidden: { opacity: 0, x: -10 },
                          show: { opacity: 1, x: 0, transition: { type: "spring", stiffness: 300, damping: 20 } }
                        }}
                        className="hover:bg-slate-50/50 transition-colors group"
                      >
                        <td className="px-6 py-4 font-semibold text-slate-600 group-hover:text-slate-900 transition-colors">Nameservers</td>
                        <td className="px-6 py-4 font-mono text-sm">
                          {rawData.dns.nameservers?.length ? rawData.dns.nameservers.join(', ') : <span className="text-slate-400">N/A</span>}
                        </td>
                      </motion.tr>
                      <motion.tr 
                        variants={{
                          hidden: { opacity: 0, x: -10 },
                          show: { opacity: 1, x: 0, transition: { type: "spring", stiffness: 300, damping: 20 } }
                        }}
                        className="hover:bg-slate-50/50 transition-colors group"
                      >
                        <td className="px-6 py-4 font-semibold text-slate-600 group-hover:text-slate-900 transition-colors">TLS Certificate</td>
                        <td className="px-6 py-4">
                          {rawData.tls.has_tls ? (
                            <div className="space-y-1">
                              <span className={`px-2.5 py-1 rounded-lg text-xs font-bold uppercase tracking-wider ${
                                rawData.tls.valid ? 'bg-teal-100 text-teal-700' :
                                rawData.tls.expired ? 'bg-rose-100 text-rose-700' :
                                rawData.tls.self_signed ? 'bg-amber-100 text-amber-700' :
                                'bg-rose-100 text-rose-700'
                              }`}>
                                {rawData.tls.valid ? 'Valid' : rawData.tls.expired ? 'Expired' : rawData.tls.self_signed ? 'Self-Signed' : 'Invalid'}
                              </span>
                              <span className="ml-2 text-sm text-slate-600">{rawData.tls.issuer}</span>
                            </div>
                          ) : (
                            <span className="text-slate-400 text-sm">No TLS detected</span>
                          )}
                        </td>
                      </motion.tr>
                      {rawData.tls.has_tls && (
                        <>
                          <motion.tr 
                            variants={{
                              hidden: { opacity: 0, x: -10 },
                              show: { opacity: 1, x: 0, transition: { type: "spring", stiffness: 300, damping: 20 } }
                            }}
                            className="hover:bg-slate-50/50 transition-colors group"
                          >
                            <td className="px-6 py-4 font-semibold text-slate-600 group-hover:text-slate-900 transition-colors">TLS Subject</td>
                            <td className="px-6 py-4 font-mono text-sm">
                              {rawData.tls.subject}
                              {rawData.tls.is_wildcard && <span className="ml-2 px-1.5 py-0.5 bg-sky-100 text-sky-700 rounded text-[10px] font-bold">WILDCARD</span>}
                              {!rawData.tls.san_match && <span className="ml-2 px-1.5 py-0.5 bg-rose-100 text-rose-700 rounded text-[10px] font-bold">SAN MISMATCH</span>}
                            </td>
                          </motion.tr>
                          <motion.tr 
                            variants={{
                              hidden: { opacity: 0, x: -10 },
                              show: { opacity: 1, x: 0, transition: { type: "spring", stiffness: 300, damping: 20 } }
                            }}
                            className="hover:bg-slate-50/50 transition-colors group"
                          >
                            <td className="px-6 py-4 font-semibold text-slate-600 group-hover:text-slate-900 transition-colors">Certificate Validity</td>
                            <td className="px-6 py-4 text-sm">
                              {new Date(rawData.tls.not_before).toLocaleDateString()} — {new Date(rawData.tls.not_after).toLocaleDateString()}
                              <span className="ml-2 text-slate-500">({rawData.tls.cert_age_days} days old)</span>
                            </td>
                          </motion.tr>
                        </>
                      )}
                      <motion.tr 
                        variants={{
                          hidden: { opacity: 0, x: -10 },
                          show: { opacity: 1, x: 0, transition: { type: "spring", stiffness: 300, damping: 20 } }
                        }}
                        className="hover:bg-slate-50/50 transition-colors group"
                      >
                        <td className="px-6 py-4 font-semibold text-slate-600 group-hover:text-slate-900 transition-colors">WHOIS Registrar</td>
                        <td className="px-6 py-4 font-medium">
                          {rawData.whois.found ? (
                            <>{rawData.whois.registrar || 'Unknown'}{rawData.whois.privacy_guard && <span className="ml-2 px-1.5 py-0.5 bg-amber-100 text-amber-700 rounded text-[10px] font-bold">PRIVACY GUARD</span>}</>
                          ) : (
                            <span className="text-slate-400">WHOIS data not available</span>
                          )}
                        </td>
                      </motion.tr>
                      {rawData.whois.found && rawData.whois.registered_date && (
                        <motion.tr 
                          variants={{
                            hidden: { opacity: 0, x: -10 },
                            show: { opacity: 1, x: 0, transition: { type: "spring", stiffness: 300, damping: 20 } }
                          }}
                          className="hover:bg-slate-50/50 transition-colors group"
                        >
                          <td className="px-6 py-4 font-semibold text-slate-600 group-hover:text-slate-900 transition-colors">Registration Date</td>
                          <td className="px-6 py-4 font-medium">
                            {new Date(rawData.whois.registered_date).toLocaleDateString()}
                            <span className="text-slate-500 font-normal ml-2">({rawData.whois.domain_age_days} days ago)</span>
                          </td>
                        </motion.tr>
                      )}
                      <motion.tr 
                        variants={{
                          hidden: { opacity: 0, x: -10 },
                          show: { opacity: 1, x: 0, transition: { type: "spring", stiffness: 300, damping: 20 } }
                        }}
                        className="hover:bg-slate-50/50 transition-colors group"
                      >
                        <td className="px-6 py-4 font-semibold text-slate-600 group-hover:text-slate-900 transition-colors">Verdict</td>
                        <td className="px-6 py-4">
                          <span className={`px-3 py-1 rounded-lg text-xs font-bold uppercase tracking-wider shadow-sm ${
                            result.verdict === 'MALICIOUS' ? 'bg-rose-500/20 text-rose-700 border border-rose-500/30' :
                            result.verdict === 'SUSPICIOUS' ? 'bg-amber-500/20 text-amber-700 border border-amber-500/30' :
                            'bg-teal-500/20 text-teal-800 border border-teal-500/30'
                          }`}>
                            {result.verdict}
                          </span>
                        </td>
                      </motion.tr>
                    </motion.tbody>
                  </table>
                </div>
                ) : (
                  <div className="flex flex-col items-center justify-center py-16 text-slate-500">
                    <AlertTriangle size={32} className="mb-4 text-slate-400" />
                    <p className="text-sm font-medium">Failed to load raw inspection data.</p>
                  </div>
                )}
              </div>
            </motion.div>
          </div>
        )}
      </AnimatePresence>

      {/* Toast Notifications */}
      <div className="fixed bottom-6 left-6 z-[200] flex flex-col-reverse gap-3 pointer-events-none">
        <AnimatePresence>
          {toasts.map(t => (
            <motion.div
              key={t.id}
              initial={{ opacity: 0, x: -50, scale: 0.8 }}
              animate={{ opacity: 1, x: 0, scale: 1 }}
              exit={{ opacity: 0, scale: 0.8, transition: { duration: 0.2 } }}
              layout
              className={`pointer-events-auto px-5 py-3 rounded-xl shadow-lg border backdrop-blur-md flex items-center gap-3 w-max max-w-sm ${
                t.type === 'allow' ? 'bg-[#F4C2C2]/90 border-[#F4C2C2] text-slate-50' :
                t.type === 'block' ? 'bg-[#64748b]/90 border-[#64748b] text-slate-50' :
                t.type === 'success' ? 'bg-teal-500/10 border-teal-500/20 text-teal-800' :
                t.type === 'error' ? 'bg-rose-500/10 border-rose-500/20 text-rose-800' :
                'bg-slate-800/10 border-slate-800/20 text-slate-800'
              }`}
            >
              {t.type === 'allow' || t.type === 'success' ? <CheckCircle2 size={18} className={t.type === 'allow' ? "text-slate-50 shrink-0" : "text-teal-600 shrink-0"} /> :
               t.type === 'block' ? <ShieldBan size={18} className="text-slate-50 shrink-0" /> :
               t.type === 'error' ? <AlertTriangle size={18} className="text-rose-600 shrink-0" /> :
               <Info size={18} className="text-slate-600 shrink-0" />}
              <span className="font-semibold text-sm">{t.message}</span>
              <button 
                onClick={() => setToasts(prev => prev.filter(toast => toast.id !== t.id))}
                className={`ml-2 transition-colors ${t.type === 'allow' || t.type === 'block' ? 'text-slate-50/70 hover:text-slate-50' : 'text-slate-400 hover:text-slate-700'}`}
              >
                <X size={14} strokeWidth={3} />
              </button>
            </motion.div>
          ))}
        </AnimatePresence>
      </div>
    </>
  );
}
