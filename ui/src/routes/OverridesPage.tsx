import { useState } from 'react';
import useSWR from 'swr';
import { apiFetch, apiJSON, messageFromError } from '../lib/api';
import { motion, AnimatePresence } from 'framer-motion';
import { ShieldAlert, Plus, Trash2, CheckCircle2, XCircle, Loader2, ChevronLeft, ChevronRight } from 'lucide-react';
import { InfoTooltip } from '../components/InfoTooltip';
import { useDialog } from '../components/DialogContext';

interface Override {
  domain: string;
  action: 'allow' | 'block';
  reason: string;
  source?: string;
  created_at: string;
}

export function OverridesPage() {
  const { data, error, mutate } = useSWR<{ items: Override[] }>('/v1/overrides', apiFetch, { keepPreviousData: true });
  const { alert, confirm } = useDialog();

  const [newDomain, setNewDomain] = useState('');
  const [newAction, setNewAction] = useState<'allow' | 'block'>('block');
  const [newReason, setNewReason] = useState('');
  const [isSubmitting, setIsSubmitting] = useState(false);
  const [submitError, setSubmitError] = useState('');
  
  const [currentPage, setCurrentPage] = useState(1);
  const itemsPerPage = 12;

  const handleAddOverride = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!newDomain.trim()) return;

    setIsSubmitting(true);
    setSubmitError('');

    try {
      await apiJSON('/v1/overrides', {
        domain: newDomain.trim(),
        action: newAction,
        reason: newReason.trim() || 'Manual override',
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
    if (!(await confirm(`Delete override for ${domain}?`))) return;
    try {
      await apiFetch(`/v1/overrides?domain=${encodeURIComponent(domain)}`, { method: 'DELETE' });
      mutate();
    } catch (err) {
      await alert({ message: `Failed to delete override for ${domain}: ${messageFromError(err)}`, type: 'error' });
    }
  };

  const isLoading = !data && !error;

  const totalItems = data?.items?.length || 0;
  const totalPages = Math.max(1, Math.ceil(totalItems / itemsPerPage));
  const safeCurrentPage = Math.min(currentPage, totalPages);
  const startIndex = (safeCurrentPage - 1) * itemsPerPage;
  const currentItems = data?.items?.slice(startIndex, startIndex + itemsPerPage) || [];

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
          <div className="text-sky-600 font-bold uppercase tracking-wider text-xs mb-1.5 pl-1">Policy Controls</div>
          <div className="flex items-center gap-2.5">
            <ShieldAlert size={24} className="text-sky-500" />
            <h1 className="text-3xl font-bold text-slate-900 tracking-tight leading-none">Domain Overrides</h1>
            <InfoTooltip content="Manage custom allow and block lists to bypass automated threat intelligence." />
          </div>
        </div>
      </motion.div>

      {/* Add Override Form */}
      <section className="bg-transparent border border-black/5 rounded-3xl p-6 shadow-sm relative overflow-hidden">
        <h2 className="text-base font-semibold text-slate-800 mb-4 flex items-center gap-2">
          <Plus className="w-5 h-5 text-pink-500" />
          Add New Override
        </h2>
        
        <form onSubmit={handleAddOverride} className="flex items-start gap-4">
          <div className="w-72 shrink-0 space-y-2">
            <input
              type="text"
              placeholder="e.g., trusted-domain.com"
              value={newDomain}
              onChange={(e) => setNewDomain(e.target.value)}
              className="w-full h-11 px-4 bg-white/80 border border-slate-200 rounded-xl text-sm focus:outline-none focus:ring-2 focus:ring-blue-500/20 focus:border-blue-500 transition-all shadow-sm"
              disabled={isSubmitting}
            />
          </div>

          <motion.button
            whileHover={{ scale: 1.02, y: -1 }}
            whileTap={{ scale: 0.95, y: 0 }}
            transition={{ type: "spring", stiffness: 500, damping: 15 }}
            type="button"
            onClick={() => setNewAction(prev => prev === 'allow' ? 'block' : 'allow')}
            className={`w-32 h-11 rounded-xl text-sm font-medium transition-colors duration-200 shadow-sm flex items-center justify-center gap-2 shrink-0 ${
              newAction === 'allow' 
                ? 'bg-emerald-50 text-emerald-700 border border-emerald-200 hover:bg-emerald-100' 
                : 'bg-rose-50 text-rose-700 border border-rose-200 hover:bg-rose-100'
            }`}
          >
            {newAction === 'allow' ? <CheckCircle2 className="w-4 h-4" /> : <XCircle className="w-4 h-4" />}
            {newAction === 'allow' ? 'Allow' : 'Block'}
          </motion.button>

          <div className="flex-1 space-y-2">
            <input
              type="text"
              placeholder="Reason for override..."
              value={newReason}
              onChange={(e) => setNewReason(e.target.value)}
              className="w-full h-11 px-4 bg-white/80 border border-slate-200 rounded-xl text-sm focus:outline-none focus:ring-2 focus:ring-blue-500/20 focus:border-blue-500 transition-all shadow-sm"
              disabled={isSubmitting}
            />
          </div>

          <motion.button
            whileHover={{ scale: 1.02, y: -1 }}
            whileTap={{ scale: 0.95, y: 0 }}
            transition={{ type: "spring", stiffness: 500, damping: 15 }}
            type="submit"
            disabled={!newDomain.trim() || isSubmitting}
            className="w-24 h-11 bg-slate-900 text-white text-sm font-medium rounded-xl hover:bg-slate-800 focus:outline-none focus:ring-2 focus:ring-slate-900/20 disabled:opacity-50 disabled:pointer-events-none transition-colors duration-200 shadow-sm flex items-center justify-center shrink-0"
          >
            {isSubmitting ? <Loader2 className="w-4 h-4 animate-spin" /> : 'Add'}
          </motion.button>
        </form>
        {submitError && (
          <p className="mt-3 text-sm text-rose-600 bg-rose-50 p-3 rounded-lg border border-rose-100">{submitError}</p>
        )}
      </section>

      {/* Overrides Table */}
      <section className="bg-white border border-black/5 rounded-3xl shadow-sm overflow-hidden flex flex-col min-h-[400px] relative">
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
          <>
            <div className="overflow-x-auto flex-1">
              <table className="w-full text-left text-base whitespace-nowrap table-fixed">
              <thead className="bg-slate-50/50 text-slate-500 border-b border-slate-200/50">
                <tr>
                  <th className="px-6 py-4 font-medium w-[328px]">Domain</th>
                  <th className="px-6 py-4 font-medium w-32 text-center">Action</th>
                  <th className="px-6 py-4 font-medium">Reason</th>
                  <th className="px-6 py-4 font-medium w-28">Source</th>
                  <th className="px-6 py-4 font-medium text-right w-24">Manage</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-100/80">
                <AnimatePresence mode="popLayout">
                  {currentItems.map((override) => (
                    <motion.tr
                      key={override.domain}
                      layout
                      initial={{ opacity: 0, y: 10 }}
                      animate={{ opacity: 1, y: 0 }}
                      exit={{ opacity: 0, scale: 0.95, transition: { duration: 0.2 } }}
                      className="hover:bg-slate-50/50 transition-colors group"
                    >
                      <td className="px-6 py-4 w-[328px]">
                        <span className="font-medium text-slate-700 font-mono block truncate w-64" title={override.domain}>
                          {override.domain}
                        </span>
                      </td>
                      <td className="px-6 py-4 w-32 text-center">
                        <span className={`inline-flex items-center gap-1.5 px-2.5 py-1 rounded-md text-sm font-medium border ${
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
                        <span className="text-slate-500 text-sm px-2 py-1 bg-slate-100 rounded-md">
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
          
          {totalItems > 0 && (
            <div className="flex flex-col sm:flex-row items-center justify-between gap-4 px-6 py-4 border-t border-slate-200/50 bg-slate-50/30">
              <span className="text-sm text-slate-500">
                Total: <span className="font-medium text-slate-700">{totalItems}</span>
              </span>
              <div className="flex items-center gap-1.5">
                <button
                  onClick={() => setCurrentPage(prev => Math.max(1, prev - 1))}
                  disabled={safeCurrentPage === 1}
                  className="p-1.5 rounded-lg text-slate-500 hover:text-slate-700 hover:bg-slate-100 active:bg-slate-200 active:scale-95 disabled:opacity-50 disabled:pointer-events-none transition-all duration-200"
                >
                  <ChevronLeft className="w-5 h-5" />
                </button>
                <div className="flex items-center gap-1">
                  {Array.from({ length: totalPages }, (_, i) => i + 1).map((page) => (
                    <button
                      key={page}
                      onClick={() => setCurrentPage(page)}
                      className={`min-w-[32px] h-8 flex items-center justify-center rounded-lg text-sm font-medium active:scale-95 transition-all duration-200 ${
                        safeCurrentPage === page
                          ? 'bg-blue-50 text-blue-600 font-semibold'
                          : 'text-slate-600 hover:bg-slate-100 active:bg-slate-200'
                      }`}
                    >
                      {page}
                    </button>
                  ))}
                </div>
                <button
                  onClick={() => setCurrentPage(prev => Math.min(totalPages, prev + 1))}
                  disabled={safeCurrentPage === totalPages}
                  className="p-1.5 rounded-lg text-slate-500 hover:text-slate-700 hover:bg-slate-100 active:bg-slate-200 active:scale-95 disabled:opacity-50 disabled:pointer-events-none transition-all duration-200"
                >
                  <ChevronRight className="w-5 h-5" />
                </button>
              </div>
            </div>
          )}
          </>
        )}
      </section>
    </motion.div>
  );
}
