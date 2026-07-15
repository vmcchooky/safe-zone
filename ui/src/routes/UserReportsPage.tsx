import { useEffect, useState } from 'react';
import useSWR from 'swr';
import { apiFetch, apiJSON, messageFromError } from '../lib/api';
import { motion, AnimatePresence } from 'framer-motion';
import { MessageSquareWarning, ShieldAlert, CheckCircle2, XCircle, Loader2, ChevronLeft, ChevronRight, ShieldCheck, Search, Filter } from 'lucide-react';
import { InfoTooltip } from '../components/InfoTooltip';
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from '../components/ui/select';

interface BlockReport {
  id: number;
  domain: string;
  contact: string;
  note: string;
  status: string;
  created_at: string;
}

interface ToastMessage {
  id: string;
  message: string;
  type: 'success' | 'error';
}

interface ReportsResponse {
  reports: BlockReport[];
  total: number;
}

export function UserReportsPage() {
  const [statusFilter, setStatusFilter] = useState<string>('pending');
  const [searchQuery, setSearchQuery] = useState('');
  const [debouncedSearchQuery, setDebouncedSearchQuery] = useState('');
  const [currentPage, setCurrentPage] = useState(1);
  const [toasts, setToasts] = useState<ToastMessage[]>([]);
  const itemsPerPage = 12;

  useEffect(() => {
    const timeout = window.setTimeout(() => setDebouncedSearchQuery(searchQuery), 400);
    return () => window.clearTimeout(timeout);
  }, [searchQuery]);

  const showToast = (message: string, type: ToastMessage['type']) => {
    const id = crypto.randomUUID();
    setToasts((previous) => [...previous, { id, message, type }]);
    window.setTimeout(() => {
      setToasts((previous) => previous.filter((toast) => toast.id !== id));
    }, 5000);
  };

  const offset = (currentPage - 1) * itemsPerPage;
  const url = `/v1/reports?limit=${itemsPerPage}&offset=${offset}${statusFilter !== 'all' ? `&status=${statusFilter}` : ''}${debouncedSearchQuery ? `&q=${encodeURIComponent(debouncedSearchQuery)}` : ''}`;
  const { data, error, mutate } = useSWR<ReportsResponse>(url, apiFetch, { keepPreviousData: true });

  const totalItems = data?.total || 0;
  const totalPages = Math.max(1, Math.ceil(totalItems / itemsPerPage));
  const safeCurrentPage = Math.min(currentPage, totalPages);

  useEffect(() => {
    setCurrentPage((page) => Math.min(page, totalPages));
  }, [totalPages]);

  const handleUpdateStatus = async (id: number, status: string) => {
    try {
      await apiJSON('/v1/reports/status', { id, status }, { method: 'POST' });
      await mutate();
      showToast(status === 'resolved' ? 'Report marked as resolved.' : 'Report rejected.', 'success');
    } catch (err) {
      showToast(`Failed to update report status: ${messageFromError(err)}`, 'error');
    }
  };

  const handleAllowDomain = async (report: BlockReport) => {
    try {
      // This endpoint always creates an `allow` override and resolves pending reports
      // for the approved domain as one review operation.
      await apiJSON('/v1/overrides/review-false-positive', {
        domain: report.domain,
        reason: 'Approved from User Reports',
        source: 'user_reports',
      }, { method: 'POST' });
      await mutate();
      showToast(`Allowed ${report.domain} and resolved its pending reports.`, 'success');
    } catch (err) {
      showToast(`Failed to allow domain: ${messageFromError(err)}`, 'error');
    }
  };

  const isLoading = !data && !error;
  const startIndex = offset;
  const currentItems = data?.reports || [];

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
        transition={{ duration: 0.3, ease: "easeOut" }}
        className="flex flex-col md:flex-row md:items-center justify-between gap-6"
      >
        <div>
          <div className="text-amber-600 font-bold uppercase tracking-wider text-xs mb-1.5 pl-1">Feedback</div>
          <div className="flex items-center gap-2.5">
            <MessageSquareWarning size={24} className="text-amber-500" />
            <h1 className="text-3xl font-bold text-slate-900 tracking-tight leading-none">User Reports</h1>
            <InfoTooltip content="Review and resolve suspicious domains or false-positives reported by users." />
          </div>
        </div>
      </motion.div>

      {/* Controls Section */}
      <section className="bg-transparent border border-black/5 rounded-3xl p-6 shadow-sm relative overflow-hidden">
        <div className="flex flex-col sm:flex-row gap-4">
          <div className="relative flex-1">
            <Search className="absolute left-4 top-1/2 -translate-y-1/2 w-5 h-5 text-slate-400" />
            <input
              type="text"
              placeholder="Search domains or notes..."
              value={searchQuery}
              onChange={(e) => {
                setSearchQuery(e.target.value);
                setCurrentPage(1);
              }}
              className="w-full h-12 !pl-12 !pr-4 bg-white/80 border border-slate-200 rounded-xl text-sm focus:outline-none focus:ring-2 focus:ring-slate-100 focus:border-slate-300 transition-all shadow-sm"
            />
          </div>
          
          <div className="w-full sm:w-48 shrink-0">
            <Select value={statusFilter} onValueChange={(val: any) => { setStatusFilter(val); setCurrentPage(1); }}>
              <motion.div
                whileHover={{ scale: 1.02, y: -1 }}
                whileTap={{ scale: 0.95, y: 0 }} 
                transition={{ type: "spring", stiffness: 500, damping: 15 }}
              >
                <SelectTrigger className="w-full bg-white/80 border-slate-200 rounded-xl px-4 py-3 text-sm outline-none focus:ring-2 focus:ring-slate-100 focus:border-slate-300 text-slate-700 font-medium h-12 shadow-sm">
                  <div className="flex items-center gap-2">
                    <Filter className="w-4 h-4 text-slate-400" />
                    <SelectValue placeholder="Filter Status" />
                  </div>
                </SelectTrigger>
              </motion.div>
              <SelectContent className="rounded-xl border-slate-200 shadow-lg bg-white">
                <SelectItem value="all" className="rounded-lg font-medium text-slate-700 focus:bg-amber-50 cursor-pointer">All Statuses</SelectItem>
                <SelectItem value="pending" className="rounded-lg font-medium text-slate-700 focus:bg-amber-50 cursor-pointer">Pending</SelectItem>
                <SelectItem value="resolved" className="rounded-lg font-medium text-slate-700 focus:bg-amber-50 cursor-pointer">Resolved</SelectItem>
                <SelectItem value="rejected" className="rounded-lg font-medium text-slate-700 focus:bg-amber-50 cursor-pointer">Rejected</SelectItem>
              </SelectContent>
            </Select>
          </div>
        </div>
      </section>

      {/* Reports Table */}
      <section className="bg-white border border-black/5 rounded-3xl shadow-sm overflow-hidden flex flex-col min-h-[400px] relative">
        {error ? (
          <div className="flex-1 flex flex-col items-center justify-center p-8 text-center">
            <ShieldAlert className="w-12 h-12 text-rose-500 mb-4 opacity-50" />
            <h3 className="text-base font-semibold text-slate-800">Failed to load reports</h3>
            <p className="text-sm text-slate-500 mt-1">{messageFromError(error)}</p>
          </div>
        ) : isLoading ? (
          <div className="flex-1 flex items-center justify-center p-8">
            <Loader2 className="w-8 h-8 text-amber-500 animate-spin" />
          </div>
        ) : !data?.reports?.length ? (
          <div className="flex-1 flex flex-col items-center justify-center p-8 text-center">
            <MessageSquareWarning className="w-12 h-12 text-slate-300 mb-4" />
            <h3 className="text-base font-semibold text-slate-800">No Reports Found</h3>
            <p className="text-sm text-slate-500 mt-1">There are no user reports matching your criteria.</p>
          </div>
        ) : (
          <>
            <div className="overflow-x-auto flex-1">
              <table className="w-full text-left text-base whitespace-nowrap table-fixed">
              <thead className="bg-slate-50/50 text-slate-500 border-b border-slate-200/50">
                <tr>
                  <th className="px-6 py-4 font-medium w-64">Domain</th>
                  <th className="px-6 py-4 font-medium w-48">Contact</th>
                  <th className="px-6 py-4 font-medium w-64">Note</th>
                  <th className="px-6 py-4 font-medium w-28 text-center">Status</th>
                  <th className="px-6 py-4 font-medium w-48 text-center">Actions</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-100/80">
                <AnimatePresence mode="popLayout">
                  {currentItems.map((report) => (
                    <motion.tr
                      key={report.id}
                      layout
                      initial={{ opacity: 0, y: 10 }}
                      animate={{ opacity: 1, y: 0 }}
                      exit={{ opacity: 0, scale: 0.95, transition: { duration: 0.2 } }}
                      className="hover:bg-slate-50/50 transition-colors group"
                    >
                      <td className="px-6 py-4 w-64">
                        <span className="font-medium text-slate-700 font-mono block truncate w-60" title={report.domain}>
                          {report.domain}
                        </span>
                        <span className="text-xs text-slate-400 block mt-1">
                          {new Date(report.created_at).toLocaleString()}
                        </span>
                      </td>
                      <td className="px-6 py-4 w-48">
                        <span className="text-slate-600 truncate w-40 inline-block" title={report.contact || 'Anonymous'}>
                          {report.contact || <span className="text-slate-400 italic">Anonymous</span>}
                        </span>
                      </td>
                      <td className="px-6 py-4 w-64">
                        <span className="text-slate-600 truncate w-60 inline-block" title={report.note}>
                          {report.note || '-'}
                        </span>
                      </td>
                      <td className="px-6 py-4 w-28 text-center">
                        <span className={`inline-flex items-center gap-1.5 px-2.5 py-1 rounded-md text-sm font-medium border ${
                          report.status === 'resolved'
                            ? 'bg-blue-50 text-blue-700 border-blue-200/60'
                            : report.status === 'rejected'
                            ? 'bg-rose-50 text-rose-700 border-rose-200/60'
                            : 'bg-amber-50 text-amber-700 border-amber-200/60'
                        }`}>
                          {report.status.charAt(0).toUpperCase() + report.status.slice(1)}
                        </span>
                      </td>
                      <td className="px-6 py-4 text-center w-48">
                        <div className="flex items-center justify-center gap-2">
                          {report.status !== 'resolved' && (
                            <>
                              <button
                                onClick={() => handleAllowDomain(report)}
                                className="px-3 py-1.5 text-xs font-medium text-emerald-700 bg-emerald-50 hover:bg-emerald-100 border border-emerald-200 rounded-lg transition-colors flex items-center gap-1.5"
                                title="Allow this domain (Override)"
                              >
                                <ShieldCheck className="w-3.5 h-3.5" />
                                Allow
                              </button>
                              <button
                                onClick={() => handleUpdateStatus(report.id, 'resolved')}
                                className="p-2 text-slate-400 hover:text-blue-600 hover:bg-blue-50 rounded-lg transition-colors"
                                title="Mark Resolved"
                              >
                                <CheckCircle2 className="w-5 h-5" />
                              </button>
                              <button
                                onClick={() => handleUpdateStatus(report.id, 'rejected')}
                                className="p-2 text-slate-400 hover:text-rose-600 hover:bg-rose-50 rounded-lg transition-colors"
                                title="Reject Report"
                              >
                                <XCircle className="w-5 h-5" />
                              </button>
                            </>
                          )}
                        </div>
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
                          ? 'bg-amber-50 text-amber-600 font-semibold'
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

      <div className="fixed bottom-6 right-6 z-[200] flex flex-col-reverse gap-3 pointer-events-none" aria-live="polite">
        <AnimatePresence>
          {toasts.map((toast) => (
            <motion.div
              key={toast.id}
              initial={{ opacity: 0, x: 32, scale: 0.96 }}
              animate={{ opacity: 1, x: 0, scale: 1 }}
              exit={{ opacity: 0, x: 32, scale: 0.96 }}
              className={`pointer-events-auto flex items-center gap-3 rounded-xl border px-4 py-3 shadow-lg backdrop-blur-md ${
                toast.type === 'success'
                  ? 'border-emerald-200 bg-emerald-50/95 text-emerald-800'
                  : 'border-rose-200 bg-rose-50/95 text-rose-800'
              }`}
              role={toast.type === 'error' ? 'alert' : 'status'}
            >
              {toast.type === 'success' ? <CheckCircle2 className="h-5 w-5 shrink-0" /> : <XCircle className="h-5 w-5 shrink-0" />}
              <span className="text-sm font-medium">{toast.message}</span>
              <button
                type="button"
                onClick={() => setToasts((previous) => previous.filter((item) => item.id !== toast.id))}
                className="rounded p-1 opacity-60 transition-opacity hover:opacity-100"
                aria-label="Dismiss notification"
              >
                <XCircle className="h-4 w-4" />
              </button>
            </motion.div>
          ))}
        </AnimatePresence>
      </div>
    </motion.div>
  );
}
