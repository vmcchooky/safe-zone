import React, { useState } from 'react';
import { HardDrive, Activity, RefreshCw, Download, Database, Server, AlertCircle, Loader2, Cpu, Archive, FileText, Globe, ShieldAlert, CheckCircle2, XCircle, BarChart2 } from 'lucide-react';
import { motion } from 'framer-motion';
import useSWR from 'swr';
import { apiFetch } from '../lib/api';
import type { AgentStatus, CoreStatus, MetricsResponse } from '../lib/types';
import { InfoTooltip } from '../components/InfoTooltip';
import { globalLoader } from '../App';

class ErrorBoundary extends React.Component<{ children: React.ReactNode }, { hasError: boolean, error: any }> {
  constructor(props: any) {
    super(props);
    this.state = { hasError: false, error: null };
  }
  static getDerivedStateFromError(error: any) {
    return { hasError: true, error };
  }
  render() {
    if (this.state.hasError) {
      return <div className="p-10 bg-red-100 text-red-900 m-10 rounded-xl z-50 relative"><h1 className="font-bold text-2xl mb-4">Error Rendering System Page</h1><pre className="whitespace-pre-wrap break-words">{this.state.error?.toString()}</pre><pre className="mt-4 text-xs opacity-70 whitespace-pre-wrap">{this.state.error?.stack}</pre></div>;
    }
    return this.props.children;
  }
}

export function SystemPage() {
  return (
    <ErrorBoundary>
      <SystemPageContent />
    </ErrorBoundary>
  );
}

function SystemPageContent() {
  const { data: statusData, error: statusErr } = useSWR<AgentStatus | { status: AgentStatus }>('/v1/agent/status', apiFetch, { refreshInterval: 5000, keepPreviousData: true });
  const { data: coreStatus, error: coreErr } = useSWR<CoreStatus>('/v1/status', apiFetch, { refreshInterval: 5000, keepPreviousData: true });
  const { data: metricsData, error: metricsErr } = useSWR<MetricsResponse>('/metrics', apiFetch, { refreshInterval: 5000, keepPreviousData: true });
  
  const [isClearing, setIsClearing] = useState(false);

  const status = statusData ? ('status' in statusData ? statusData.status : statusData) : null;
  const loading = !status && !coreStatus && !metricsData && !statusErr && !coreErr && !metricsErr;
  const errorObj = statusErr || coreErr || metricsErr;
  const error = errorObj ? (errorObj.message || 'Failed to load system status') : null;

  const handleClearCache = async () => {
    if (!window.confirm("Are you sure you want to flush the system cache?")) return;
    setIsClearing(true);
    globalLoader.show();
    try {
      await apiFetch('/v1/cache/flush', { method: 'POST' });
      alert("Cache flushed successfully.");
    } catch (err: any) {
      alert(`Error flushing cache: ${err.message}`);
    } finally {
      setIsClearing(false);
      globalLoader.hide();
    }
  };

  const handleDownloadLogs = () => {
    window.open('/v1/logs/export', '_blank');
  };

  if (loading) {
    return (
      <div className="flex justify-center items-center h-64 text-slate-500">
        <Loader2 className="animate-spin text-slate-400" size={32} />
      </div>
    );
  }

  return (
    <motion.div 
      initial={{ opacity: 0 }} 
      animate={{ opacity: 1 }} 
      className="space-y-8 max-w-7xl mx-auto p-4 lg:p-8 pb-32"
    >
      {/* Header */}
      <motion.div 
        initial={{ opacity: 0, y: -20 }} 
        animate={{ opacity: 1, y: 0 }} 
        transition={{ duration: 0.5, ease: "easeOut" }}
        className="flex flex-col md:flex-row md:items-center justify-between gap-6"
      >
        <div>
          <div className="text-sky-600 font-bold uppercase tracking-wider text-xs mb-1.5 pl-1">Infrastructure & Core</div>
          <div className="flex items-center gap-2.5">
            <HardDrive size={24} className="text-sky-500" />
            <h1 className="text-3xl font-bold text-slate-900 tracking-tight leading-none">System</h1>
            <InfoTooltip content="System status, logs, and cache management." />
          </div>
        </div>
      </motion.div>

      {error && (
        <motion.div 
          initial={{ opacity: 0, y: -10 }} 
          animate={{ opacity: 1, y: 0 }} 
          className="p-4 bg-red-50 text-red-600 rounded-2xl border border-red-100 flex items-center gap-3"
        >
          <AlertCircle size={20} />
          <span className="font-medium">{error}</span>
        </motion.div>
      )}

      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6 items-stretch">
          {/* Status Card */}
          <motion.section 
            initial={{ opacity: 0, y: 20 }} 
            animate={{ opacity: 1, y: 0 }} 
            transition={{ duration: 0.5, delay: 0.1, ease: "easeOut" }}
            className="bg-white/60 backdrop-blur-xl border border-white/80 rounded-3xl p-6 shadow-sm relative overflow-hidden flex flex-col h-full"
          >
          <div className="absolute top-0 right-0 w-64 h-64 bg-blue-100/30 rounded-full blur-3xl -z-10 -translate-y-1/2 translate-x-1/2"></div>
          
          <div className="flex items-center gap-3 mb-6 relative z-10">
            <div className="p-2.5 bg-blue-100/80 text-blue-600 rounded-xl">
              <Activity size={20} />
            </div>
            <div>
              <h2 className="text-lg font-bold text-slate-900">System Health</h2>
              <p className="text-sm text-slate-500">Real-time resource utilization</p>
            </div>
          </div>

          <div className="space-y-4 relative z-10">
            <div className="p-4 rounded-2xl bg-white border border-slate-100 shadow-sm">
              <div className="flex items-center gap-2 text-slate-500 text-sm font-semibold mb-3">
                <Cpu size={16} className="text-sky-500" /> Processing Engine
              </div>
              <div className="flex justify-between items-center text-sm mb-2">
                <span className="text-slate-500">Engine Status</span>
                {status?.enabled ? (
                  <span className="inline-flex items-center gap-1.5 px-2 py-0.5 rounded-lg bg-emerald-50 text-emerald-700 font-medium border border-emerald-100">
                    <span className="w-1.5 h-1.5 rounded-full bg-emerald-500 animate-pulse" />Active
                  </span>
                ) : (
                  <span className="inline-flex items-center gap-1.5 px-2 py-0.5 rounded-lg bg-slate-100 text-slate-700 font-medium border border-slate-200">Disabled</span>
                )}
              </div>
              <div className="flex justify-between items-center text-sm">
                <span className="text-slate-500">Active Tasks</span>
                <span className="font-medium text-slate-900">{(status?.tasks || []).filter(t => t.state === 'running').length} Running</span>
              </div>
            </div>

            <div className="p-4 rounded-2xl bg-white border border-slate-100 shadow-sm">
              <div className="flex items-center gap-2 text-slate-500 text-sm font-semibold mb-3">
                <Database size={16} className="text-indigo-500" /> Database & Storage
              </div>
              <div className="space-y-2 text-sm">
                <div className="flex justify-between">
                  <span className="text-slate-500">Database Size</span>
                  <span className="font-medium text-slate-900">{(status?.database_stats?.file_size_mb || 0).toFixed(2)} MB</span>
                </div>
                <div className="flex justify-between">
                  <span className="text-slate-500">Disk Free Space</span>
                  <span className="font-medium text-slate-900">{(status?.database_stats?.disk_free_gb || 0).toFixed(2)} GB</span>
                </div>
                <div className="flex justify-between">
                  <span className="text-slate-500">Telemetry Retention</span>
                  <span className="font-medium text-slate-900">{status?.telemetry_retention_days || 30} Days</span>
                </div>
              </div>
              </div>
            </div>
          </motion.section>

          {/* Core Infrastructure Card - Moved under System Health */}
          <motion.section 
            initial={{ opacity: 0, y: 20 }} 
            animate={{ opacity: 1, y: 0 }} 
            transition={{ duration: 0.5, delay: 0.2, ease: "easeOut" }}
            className="bg-white/60 backdrop-blur-xl border border-white/80 rounded-3xl p-6 shadow-sm relative overflow-hidden flex flex-col h-full"
          >
            <div className="absolute top-0 left-0 w-64 h-64 bg-indigo-100/30 rounded-full blur-3xl -z-10 -translate-y-1/2 -translate-x-1/2"></div>
            
            <div className="flex items-center gap-3 mb-6 relative z-10">
              <div className="p-2.5 bg-indigo-100/80 text-indigo-600 rounded-xl">
                <Server size={20} />
              </div>
              <div>
                <h2 className="text-lg font-bold text-slate-900">Core Services</h2>
                <p className="text-sm text-slate-500">Backend API & integrations</p>
              </div>
            </div>

            <div className="space-y-4 relative z-10">
              <div className="p-4 rounded-2xl bg-white border border-slate-100 shadow-sm space-y-4 h-max">
                <div className="flex justify-between items-center text-sm">
                  <span className="text-slate-500">Mode</span>
                  <span className="font-medium text-slate-900 uppercase text-xs tracking-wider bg-slate-100 px-2 py-0.5 rounded-md">{coreStatus?.mode || 'API'}</span>
                </div>
                <div className="flex justify-between items-center text-sm">
                  <span className="text-slate-500">Environment</span>
                  <span className="font-medium text-slate-900">{coreStatus?.deployment_tier || 'Production'}</span>
                </div>
              </div>

              <div className="p-4 rounded-2xl bg-white border border-slate-100 shadow-sm space-y-4">
                <div className="flex justify-between items-center text-sm">
                  <div className="flex items-center gap-2 text-slate-500">
                    <Database size={15} /> Redis Cache
                  </div>
                  {coreStatus?.redis?.status === 'ok' ? (
                    <span className="flex items-center gap-1 text-emerald-600 font-medium text-xs"><CheckCircle2 size={14} /> OK</span>
                  ) : (
                    <span className="flex items-center gap-1 text-red-500 font-medium text-xs"><XCircle size={14} /> ERR</span>
                  )}
                </div>
                <div className="flex justify-between items-center text-sm">
                  <div className="flex items-center gap-2 text-slate-500">
                    <Globe size={15} /> Threat Feeds
                  </div>
                  {coreStatus?.feed_sync?.status === 'ok' ? (
                    <span className="flex items-center gap-1 text-emerald-600 font-medium text-xs"><CheckCircle2 size={14} /> Synced</span>
                  ) : (
                    <span className="flex items-center gap-1 text-amber-500 font-medium text-xs"><AlertCircle size={14} /> Syncing</span>
                  )}
                </div>
                <div className="flex justify-between items-center text-sm">
                  <div className="flex items-center gap-2 text-slate-500">
                    <ShieldAlert size={15} /> Adblock Engine
                  </div>
                  {coreStatus?.adblock?.enabled ? (
                    <span className="flex items-center gap-1 text-emerald-600 font-medium text-xs"><CheckCircle2 size={14} /> Active</span>
                  ) : (
                    <span className="flex items-center gap-1 text-slate-400 font-medium text-xs"><XCircle size={14} /> Off</span>
                  )}
                </div>
              </div>
            </div>
          </motion.section>

          {/* Management Card */}
          <motion.section 
            initial={{ opacity: 0, y: 20 }} 
            animate={{ opacity: 1, y: 0 }} 
            transition={{ duration: 0.5, delay: 0.2, ease: "easeOut" }}
            className="bg-transparent border border-black/5 rounded-3xl p-6 shadow-sm relative overflow-hidden flex flex-col h-full"
          >
            <div className="flex items-center gap-3 mb-6">
              <div className="p-2.5 bg-purple-100/80 text-purple-600 rounded-xl">
                <Archive size={20} />
              </div>
              <div>
                <h2 className="text-lg font-bold text-slate-900">Cache Management</h2>
                <p className="text-sm text-slate-500">In-memory bloom filters & threat data</p>
              </div>
            </div>
            
            <div className="p-4 rounded-2xl bg-white border border-slate-100 shadow-sm mb-4">
              <div className="space-y-2 text-sm">
                <div className="flex justify-between">
                  <span className="text-slate-500">Loaded Domains</span>
                  <span className="font-medium text-slate-900">{(status?.whitelist_stats?.loaded_domains || 0).toLocaleString()}</span>
                </div>
                <div className="flex justify-between">
                  <span className="text-slate-500">Hash Functions</span>
                  <span className="font-medium text-slate-900">{status?.whitelist_stats?.bloom_hashes || 0}</span>
                </div>
                <div className="flex justify-between">
                  <span className="text-slate-500">Bloom Filter Bits</span>
                  <span className="font-medium text-slate-900">{(status?.whitelist_stats?.bloom_bits || 0).toLocaleString()}</span>
                </div>
                <div className="flex justify-between">
                  <span className="text-slate-500">Memory Usage (RAM)</span>
                  <span className="font-medium text-slate-900">{(status?.whitelist_stats?.bloom_size_ram_kb || 0).toFixed(2)} KB</span>
                </div>
                <div className="flex justify-between">
                  <span className="text-slate-500">False Positive Rate</span>
                  <span className="font-medium text-slate-900">{((status?.whitelist_stats?.fpr || 0) * 100).toFixed(4)}%</span>
                </div>
              </div>
            </div>

            <motion.button
              whileHover={{ scale: 1.02 }}
              whileTap={{ scale: 0.98 }}
              onClick={handleClearCache}
              disabled={isClearing}
              className="w-full mt-auto flex items-center justify-center gap-2 py-2.5 px-4 bg-slate-900 hover:bg-slate-800 text-white rounded-xl font-medium transition-colors shadow-sm disabled:opacity-50"
            >
              <RefreshCw size={18} className={isClearing ? 'animate-spin' : ''} />
              {isClearing ? 'Flushing Cache...' : 'Flush Cache'}
            </motion.button>
          </motion.section>

          <motion.section 
            initial={{ opacity: 0, y: 20 }} 
            animate={{ opacity: 1, y: 0 }} 
            transition={{ duration: 0.5, delay: 0.3, ease: "easeOut" }}
            className="bg-transparent border border-black/5 rounded-3xl p-6 shadow-sm relative overflow-hidden lg:col-start-3"
          >
            <div className="flex items-center gap-3 mb-6">
              <div className="p-2.5 bg-orange-100/80 text-orange-600 rounded-xl">
                <FileText size={20} />
              </div>
              <div>
                <h2 className="text-lg font-bold text-slate-900">System Logs</h2>
                <p className="text-sm text-slate-500">Export and view diagnostic logs</p>
              </div>
            </div>

            <div className="text-sm text-slate-600 mb-6 bg-orange-50/50 p-4 rounded-2xl border border-orange-100/50">
              Download diagnostic logs to troubleshoot agent engine issues, network errors, and system faults. Logs contain the last 7 days of activity.
            </div>
            
            <motion.button
              whileHover={{ scale: 1.02 }}
              whileTap={{ scale: 0.98 }}
              onClick={handleDownloadLogs}
              className="w-full flex items-center justify-center gap-2 py-2.5 px-4 bg-white border border-slate-200 hover:border-slate-300 text-slate-700 hover:text-slate-900 rounded-xl font-medium transition-all shadow-sm"
            >
              <Download size={18} />
              Download Diagnostic Logs
            </motion.button>
          </motion.section>
      </div>

      {/* Request Metrics Panel */}
      <motion.section 
        initial={{ opacity: 0, y: 20 }} 
        animate={{ opacity: 1, y: 0 }} 
        transition={{ duration: 0.5, delay: 0.5, ease: "easeOut" }}
        className="bg-white/60 backdrop-blur-xl border border-white/80 rounded-3xl p-6 shadow-sm relative overflow-hidden flex flex-col mt-6"
      >
        <div className="flex items-center gap-3 mb-6 relative z-10">
          <div className="p-2.5 bg-rose-100/80 text-rose-600 rounded-xl">
            <BarChart2 size={20} />
          </div>
          <div>
            <h2 className="text-lg font-bold text-slate-900">Request Metrics</h2>
            <p className="text-sm text-slate-500">API endpoint performance and latency</p>
          </div>
        </div>

        <div className="overflow-x-auto relative z-10">
          <table className="w-full text-left border-collapse text-sm">
            <thead>
              <tr className="border-b border-slate-200">
                <th className="pb-3 font-semibold text-slate-500">ENDPOINT</th>
                <th className="pb-3 font-semibold text-slate-500">REQUESTS</th>
                <th className="pb-3 font-semibold text-slate-500">AVG LATENCY</th>
                <th className="pb-3 font-semibold text-slate-500">MAX LATENCY</th>
                <th className="pb-3 font-semibold text-slate-500 text-right">LAST STATUS</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-100">
              {(!metricsData?.metrics?.request_summary || Object.entries(metricsData.metrics.request_summary).length === 0) ? (
                <tr>
                  <td colSpan={5} className="py-4 text-slate-500 italic text-center">Metrics unavailable.</td>
                </tr>
              ) : (
                Object.entries(metricsData.metrics.request_summary).map(([endpoint, metric]) => {
                  const avgLatency = metric.count > 0 ? (metric.total_duration_ms / metric.count).toFixed(2) : '0.00';
                  return (
                    <tr key={endpoint} className="group hover:bg-slate-50/50 transition-colors">
                      <td className="py-3 pr-4 font-medium text-slate-700">{endpoint}</td>
                      <td className="py-3 px-4 text-slate-600">{metric.count.toLocaleString()}</td>
                      <td className="py-3 px-4 text-slate-600">{avgLatency} ms</td>
                      <td className="py-3 px-4 text-slate-600">{metric.max_duration_ms} ms</td>
                      <td className="py-3 pl-4 text-right">
                        <span className={`inline-flex px-2 py-0.5 rounded text-xs font-medium ${
                          metric.last_status >= 200 && metric.last_status < 300 ? 'bg-emerald-100 text-emerald-700' : 
                          metric.last_status >= 400 && metric.last_status < 500 ? 'bg-amber-100 text-amber-700' : 
                          metric.last_status >= 500 ? 'bg-red-100 text-red-700' : 'bg-slate-100 text-slate-700'
                        }`}>
                          {metric.last_status}
                        </span>
                      </td>
                    </tr>
                  );
                })
              )}
            </tbody>
          </table>
        </div>
      </motion.section>
    </motion.div>
  );
}

