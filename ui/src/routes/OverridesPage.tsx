import { useState } from 'react';
import useSWR from 'swr';
import { apiFetch, apiJSON, messageFromError } from '../lib/api';
import { motion, AnimatePresence } from 'framer-motion';
import { ShieldAlert, Plus, Trash2, CheckCircle2, XCircle, Loader2 } from 'lucide-react';

interface Override {
  domain: string;
  action: 'allow' | 'block';
  reason: string;
  source?: string;
  created_at: string;
}

export function OverridesPage() {
  const { data, error, mutate } = useSWR<{ items: Override[] }>('/v1/overrides', apiFetch, { keepPreviousData: true });

  const [newDomain, setNewDomain] = useState('');
  const [newAction, setNewAction] = useState<'allow' | 'block'>('block');
  const [newReason, setNewReason] = useState('');
  const [isSubmitting, setIsSubmitting] = useState(false);
  const [submitError, setSubmitError] = useState('');

  const handleAddOverride = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!newDomain.trim() || !newReason.trim()) return;

    setIsSubmitting(true);
    setSubmitError('');

    try {
      await apiJSON('/v1/overrides', {
        domain: newDomain.trim(),
        action: newAction,
        reason: newReason.trim(),
      }, { method: 'POST' });
      
      setNewDomain('');
      setNewReason('');
      mutate();
    } catch (err) {
      setSubmitError(messageFromError(err));
    } finally {
      setIsSubmitting(false);
    }
  };

  const handleDelete = async (domain: string) => {
    try {
      await apiFetch(`/v1/overrides?domain=${encodeURIComponent(domain)}`, { method: 'DELETE' });
      mutate();
    } catch (err) {
      alert(`Failed to delete override for ${domain}: ${messageFromError(err)}`);
    }
  };

  const isLoading = !data && !error;

  return (
    <motion.div 
      initial={{ opacity: 0, y: 15 }}
      animate={{ opacity: 1, y: 0 }}
      exit={{ opacity: 0, y: 15 }}
      transition={{ duration: 0.3 }}
      className="max-w-6xl mx-auto space-y-6"
    >
      <header className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold tracking-tight text-slate-900 flex items-center gap-3">
            <ShieldAlert className="w-8 h-8 text-blue-600" />
            Domain Overrides
          </h1>
          <p className="text-sm text-slate-500 mt-1">
            Manage custom allow and block lists to bypass automated threat intelligence.
          </p>
        </div>
      </header>

      {/* Add Override Form */}
      <section className="bg-white/60 backdrop-blur-md rounded-2xl border border-slate-200/50 p-6 shadow-sm">
        <h2 className="text-base font-semibold text-slate-800 mb-4 flex items-center gap-2">
          <Plus className="w-5 h-5 text-slate-400" />
          Add New Override
        </h2>
        
        <form onSubmit={handleAddOverride} className="flex items-start gap-4">
          <div className="flex-1 space-y-2">
            <input
              type="text"
              placeholder="e.g., trusted-domain.com"
              value={newDomain}
              onChange={(e) => setNewDomain(e.target.value)}
              className="w-full h-11 px-4 bg-white/80 border border-slate-200 rounded-xl text-sm focus:outline-none focus:ring-2 focus:ring-blue-500/20 focus:border-blue-500 transition-all shadow-sm"
              disabled={isSubmitting}
            />
          </div>

          <div className="flex-none">
            <button
              type="button"
              onClick={() => setNewAction(prev => prev === 'allow' ? 'block' : 'allow')}
              className={`h-11 px-6 rounded-xl text-sm font-medium transition-all shadow-sm flex items-center justify-center gap-2 min-w-[110px] ${
                newAction === 'allow' 
                  ? 'bg-emerald-50 text-emerald-700 border border-emerald-200 hover:bg-emerald-100' 
                  : 'bg-rose-50 text-rose-700 border border-rose-200 hover:bg-rose-100'
              }`}
            >
              {newAction === 'allow' ? <CheckCircle2 className="w-4 h-4" /> : <XCircle className="w-4 h-4" />}
              {newAction === 'allow' ? 'Allow' : 'Block'}
            </button>
          </div>

          <div className="flex-[2] space-y-2">
            <input
              type="text"
              placeholder="Reason for override..."
              value={newReason}
              onChange={(e) => setNewReason(e.target.value)}
              className="w-full h-11 px-4 bg-white/80 border border-slate-200 rounded-xl text-sm focus:outline-none focus:ring-2 focus:ring-blue-500/20 focus:border-blue-500 transition-all shadow-sm"
              disabled={isSubmitting}
            />
          </div>

          <button
            type="submit"
            disabled={!newDomain.trim() || !newReason.trim() || isSubmitting}
            className="flex-none h-11 px-6 bg-slate-900 text-white text-sm font-medium rounded-xl hover:bg-slate-800 focus:outline-none focus:ring-2 focus:ring-slate-900/20 disabled:opacity-50 transition-all shadow-sm flex items-center justify-center min-w-[100px]"
          >
            {isSubmitting ? <Loader2 className="w-4 h-4 animate-spin" /> : 'Add'}
          </button>
        </form>
        {submitError && (
          <p className="mt-3 text-sm text-rose-600 bg-rose-50 p-3 rounded-lg border border-rose-100">{submitError}</p>
        )}
      </section>

      {/* Overrides Table */}
      <section className="bg-white/60 backdrop-blur-md rounded-2xl border border-slate-200/50 shadow-sm overflow-hidden flex flex-col min-h-[400px]">
        {error ? (
          <div className="flex-1 flex flex-col items-center justify-center p-8 text-center">
            <ShieldAlert className="w-12 h-12 text-rose-500 mb-4 opacity-50" />
            <h3 className="text-base font-semibold text-slate-800">Failed to load overrides</h3>
            <p className="text-sm text-slate-500 mt-1">{messageFromError(error)}</p>
          </div>
        ) : isLoading ? (
          <div className="flex-1 flex items-center justify-center p-8">
            <Loader2 className="w-8 h-8 text-blue-500 animate-spin" />
          </div>
        ) : !data?.items?.length ? (
          <div className="flex-1 flex flex-col items-center justify-center p-8 text-center">
            <ShieldAlert className="w-12 h-12 text-slate-300 mb-4" />
            <h3 className="text-base font-semibold text-slate-800">No Overrides Found</h3>
            <p className="text-sm text-slate-500 mt-1">Custom allow and block rules will appear here.</p>
          </div>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full text-left text-sm whitespace-nowrap">
              <thead className="bg-slate-50/50 text-slate-500 border-b border-slate-200/50">
                <tr>
                  <th className="px-6 py-4 font-medium">Domain</th>
                  <th className="px-6 py-4 font-medium">Action</th>
                  <th className="px-6 py-4 font-medium">Reason</th>
                  <th className="px-6 py-4 font-medium">Source</th>
                  <th className="px-6 py-4 font-medium text-right">Manage</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-100/80">
                <AnimatePresence mode="popLayout">
                  {data.items.map((override) => (
                    <motion.tr
                      key={override.domain}
                      layout
                      initial={{ opacity: 0, y: 10 }}
                      animate={{ opacity: 1, y: 0 }}
                      exit={{ opacity: 0, scale: 0.95, transition: { duration: 0.2 } }}
                      className="hover:bg-slate-50/50 transition-colors group"
                    >
                      <td className="px-6 py-4">
                        <span className="font-medium text-slate-700 font-mono">{override.domain}</span>
                      </td>
                      <td className="px-6 py-4">
                        <span className={`inline-flex items-center gap-1.5 px-2.5 py-1 rounded-full text-xs font-medium border ${
                          override.action === 'allow'
                            ? 'bg-emerald-50 text-emerald-700 border-emerald-200/60'
                            : 'bg-rose-50 text-rose-700 border-rose-200/60'
                        }`}>
                          {override.action === 'allow' ? <CheckCircle2 className="w-3.5 h-3.5" /> : <XCircle className="w-3.5 h-3.5" />}
                          {override.action.charAt(0).toUpperCase() + override.action.slice(1)}
                        </span>
                      </td>
                      <td className="px-6 py-4">
                        <span className="text-slate-600 truncate max-w-xs inline-block" title={override.reason}>
                          {override.reason}
                        </span>
                      </td>
                      <td className="px-6 py-4">
                        <span className="text-slate-500 text-xs px-2 py-1 bg-slate-100 rounded-md">
                          {override.source || 'manual'}
                        </span>
                      </td>
                      <td className="px-6 py-4 text-right">
                        <button
                          onClick={() => handleDelete(override.domain)}
                          className="p-2 text-slate-400 hover:text-rose-600 hover:bg-rose-50 rounded-lg transition-colors opacity-0 group-hover:opacity-100 focus:opacity-100"
                          title="Delete Override"
                        >
                          <Trash2 className="w-4 h-4" />
                        </button>
                      </td>
                    </motion.tr>
                  ))}
                </AnimatePresence>
              </tbody>
            </table>
          </div>
        )}
      </section>
    </motion.div>
  );
}
