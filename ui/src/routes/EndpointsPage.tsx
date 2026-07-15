import { useState } from 'react';
import { Shield, Activity, Server, Database, Plus, Trash2, Play, Users, Link as LinkIcon, AlertCircle, Loader2 } from 'lucide-react';
import { motion } from 'framer-motion';
import { useForm, Controller } from 'react-hook-form';
import { zodResolver } from '@hookform/resolvers/zod';
import * as z from 'zod';

const mappingSchema = z.object({
  mapType: z.enum(['ip', 'cidr', 'client_id']),
  mapValue: z.string().min(1, 'Mapping value is required'),
  mapGroupId: z.string().min(1, 'Group is required')
}).superRefine((data, ctx) => {
  if (data.mapType === 'ip') {
    if (!/^((25[0-5]|(2[0-4]|1\d|[1-9]|)\d)\.?\b){4}$/.test(data.mapValue) && !/^[a-fA-F0-9:]+$/.test(data.mapValue)) {
      ctx.addIssue({ code: z.ZodIssueCode.custom, message: 'Invalid IP address', path: ['mapValue'] });
    }
  } else if (data.mapType === 'cidr') {
    if (!/^([0-9]{1,3}\.){3}[0-9]{1,3}(\/([0-9]|[1-2][0-9]|3[0-2]))$/.test(data.mapValue)) {
      ctx.addIssue({ code: z.ZodIssueCode.custom, message: 'Invalid CIDR', path: ['mapValue'] });
    }
  }
});

type MappingFormValues = z.infer<typeof mappingSchema>;
import useSWR from 'swr';
import { apiFetch, apiJSON } from '../lib/api';
import type { AgentStatus, PolicyGroup, ClientMapping } from '../lib/types';
import { globalLoader } from '../App';
import { GroupModal } from '../components/GroupModal';
import { InfoTooltip } from '../components/InfoTooltip';
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from '../components/ui/select';
import { useDialog } from '../components/DialogContext';

export function EndpointsPage() {
  const { data: statusData, error: statusErr, mutate: mutateStatus } = useSWR<AgentStatus | { status: AgentStatus }>('/v1/agent/status', apiFetch, { refreshInterval: 5000, keepPreviousData: true });
  const { data: groupsData, error: groupsErr, mutate: mutateGroups } = useSWR<{ items: PolicyGroup[] }>('/v1/groups', apiFetch, { keepPreviousData: true });
  const { data: mappingsData, error: mappingsErr, mutate: mutateMappings } = useSWR<{ items: ClientMapping[] }>('/v1/mappings', apiFetch, { keepPreviousData: true });

  const status = statusData ? ('status' in statusData ? statusData.status : statusData) : null;
  const groups = groupsData?.items || [];
  const mappings = mappingsData?.items || [];
  
  const loading = !status && !groupsData && !mappingsData && !statusErr && !groupsErr && !mappingsErr;
  const errorObj = statusErr || groupsErr || mappingsErr;
  const error = errorObj ? (errorObj.message || 'Failed to load endpoints data') : null;

  // Modal state
  const [isGroupModalOpen, setIsGroupModalOpen] = useState(false);
  const [editingGroup, setEditingGroup] = useState<PolicyGroup | null>(null);

  // Mapping Form State
  const { register, handleSubmit, control, reset, formState: { errors }, watch } = useForm<MappingFormValues>({
    resolver: zodResolver(mappingSchema),
    defaultValues: { mapType: 'ip', mapValue: '', mapGroupId: '' }
  });
  const mapType = watch('mapType');

  const { alert, confirm } = useDialog();

  const triggerTask = async (taskName: string) => {
    if (!(await confirm(`Manually trigger agent task "${taskName}"?`))) return;
    
    globalLoader.show();
    try {
      await apiJSON(`/v1/agent/trigger?task=${encodeURIComponent(taskName)}`, {}, { method: 'POST' });
      // Wait a bit to let the task run before reloading status
      await new Promise(r => setTimeout(r, 1000));
      await mutateStatus();
    } catch (err: any) {
      await alert({ message: `Error triggering task: ${err.message}`, type: 'error' });
    } finally {
      globalLoader.hide();
    }
  };

  const deleteGroup = async (group: PolicyGroup) => {
    if (group.id === 1 || group.name.toLowerCase() === 'default') {
      await alert({ message: 'Cannot delete default group', type: 'error' });
      return;
    }
    if (!(await confirm(`Delete group "${group.name}"? This will remove all associated client mappings and overrides.`))) return;
    
    try {
      await apiFetch(`/v1/groups?id=${group.id}`, { method: 'DELETE' });
      await mutateGroups();
    } catch (err: any) {
      await alert({ message: `Error deleting group: ${err.message}`, type: 'error' });
    }
  };

  const createMapping = async (data: MappingFormValues) => {
    try {
      await apiJSON('/v1/mappings', {
        mapping_type: data.mapType,
        value: data.mapValue.trim(),
        group_id: parseInt(data.mapGroupId, 10),
      }, { method: 'POST' });
      
      reset({ ...data, mapValue: '' });
      await mutateMappings();
    } catch (err: any) {
      await alert({ message: `Error adding mapping: ${err.message}`, type: 'error' });
    }
  };

  const deleteMapping = async (id: number) => {
    if (!(await confirm('Delete this client mapping?'))) return;
    try {
      await apiFetch(`/v1/mappings?id=${id}`, { method: 'DELETE' });
      await mutateMappings();
    } catch (err: any) {
      await alert({ message: `Error deleting mapping: ${err.message}`, type: 'error' });
    }
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
        transition={{ duration: 0.3, ease: "easeOut" }}
        className="flex flex-col md:flex-row md:items-center justify-between gap-6"
      >
        <div>
          <div className="text-sky-600 font-bold uppercase tracking-wider text-xs mb-1.5 pl-1">Device & Agent Management</div>
          <div className="flex items-center gap-2.5">
            <Server size={24} className="text-sky-500" />
            <h1 className="text-3xl font-bold text-slate-900 tracking-tight leading-none">Endpoints</h1>
            <InfoTooltip content="Manage agent engines, policy groups, and endpoint mappings." />
          </div>
        </div>

        {!status?.enabled && (
          <div className="flex items-center gap-3 px-4 py-2.5 bg-slate-50/60 backdrop-blur-md border border-slate-200 rounded-2xl shadow-sm">
            <span className="text-sm font-medium text-slate-600">Agent Engine:</span>
            <span className="inline-flex items-center gap-1.5 px-3 py-1 rounded-full bg-slate-100/80 text-slate-700 text-sm font-semibold border border-slate-200/80">
              <span className="w-2 h-2 rounded-full bg-slate-400" />
              Disabled
            </span>
          </div>
        )}
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

      {/* Agent Engine Status */}
      {status?.enabled && (
        <motion.section 
          initial={{ opacity: 0, y: 20 }} 
          animate={{ opacity: 1, y: 0 }} 
          transition={{ duration: 0.3, delay: 0.05, ease: "easeOut" }}
          className="bg-white/60 backdrop-blur-xl border border-white/80 rounded-3xl p-6 shadow-sm relative overflow-hidden"
        >
          {/* Decorative background glow */}
          <div className="absolute top-0 right-0 w-64 h-64 bg-blue-100/30 rounded-full blur-3xl -z-10 -translate-y-1/2 translate-x-1/2"></div>
          
          <div className="flex items-center gap-3 mb-6 relative z-10">
            <div className="p-2.5 bg-blue-100/80 text-blue-600 rounded-xl">
              <Activity size={20} />
            </div>
            <div>
              <h2 className="text-lg font-bold text-slate-900">Agent Engine Status</h2>
              <p className="text-sm text-slate-500">Local node health and background tasks</p>
            </div>
            <div className="ml-auto">
              <span className="inline-flex items-center gap-1.5 px-3 py-1 rounded-full bg-emerald-100/80 text-emerald-700 text-sm font-semibold border border-emerald-200">
                <span className="w-2 h-2 rounded-full bg-emerald-500 animate-pulse" />
                Active
              </span>
            </div>
          </div>


          <div className="grid grid-cols-1 lg:grid-cols-3 gap-6 relative z-10">
            {/* Stats Summary */}
            <div className="col-span-1 space-y-4">
              <motion.div 
                className="p-4 rounded-2xl bg-white border border-slate-100 shadow-sm transition-transform"
              >
                <div className="flex items-center gap-2 text-slate-500 text-sm font-semibold mb-3">
                  <Shield size={16} className="text-sky-500" /> Whitelist Cache
                </div>
                <div className="space-y-2 text-sm">
                  <div className="flex justify-between">
                    <span className="text-slate-500">Loaded Domains</span>
                    <span className="font-medium text-slate-900">{(status.whitelist_stats?.loaded_domains || 0).toLocaleString()}</span>
                  </div>
                  <div className="flex justify-between">
                    <span className="text-slate-500">Bloom Size</span>
                    <span className="font-medium text-slate-900">{(status.whitelist_stats?.bloom_size_ram_kb || 0).toFixed(2)} KB</span>
                  </div>
                  <div className="flex justify-between">
                    <span className="text-slate-500">False Pos Rate</span>
                    <span className="font-medium text-slate-900">{((status.whitelist_stats?.fpr || 0) * 100).toFixed(4)}%</span>
                  </div>
                </div>
              </motion.div>

              <motion.div 
                className="p-4 rounded-2xl bg-white border border-slate-100 shadow-sm transition-transform"
              >
                <div className="flex items-center gap-2 text-slate-500 text-sm font-semibold mb-3">
                  <Database size={16} className="text-indigo-500" /> Storage
                </div>
                <div className="space-y-2 text-sm">
                  <div className="flex justify-between">
                    <span className="text-slate-500">Database Size</span>
                    <span className="font-medium text-slate-900">{(status.database_stats?.file_size_mb || 0).toFixed(2)} MB</span>
                  </div>
                  <div className="flex justify-between">
                    <span className="text-slate-500">Disk Free</span>
                    <span className="font-medium text-slate-900">{(status.database_stats?.disk_free_gb || 0).toFixed(2)} GB</span>
                  </div>
                </div>
              </motion.div>
            </div>

            {/* Background Tasks Table */}
            <div className="col-span-2">
              <div className="border border-slate-100 rounded-2xl overflow-hidden bg-white shadow-sm">
                <table className="w-full text-left text-sm">
                  <thead className="bg-slate-50 text-slate-500 border-b border-slate-100">
                    <tr>
                      <th className="px-4 py-3 font-semibold">Task Name</th>
                      <th className="px-4 py-3 font-semibold">Status</th>
                      <th className="px-4 py-3 font-semibold">Last Run</th>
                      <th className="px-4 py-3 font-semibold text-right">Action</th>
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-slate-50">
                    {status.tasks.map((t, index) => (
                      <motion.tr 
                        key={t.name} 
                        initial={{ opacity: 0, x: -10 }}
                        animate={{ opacity: 1, x: 0 }}
                        transition={{ delay: index * 0.02 }}
                        className="hover:bg-slate-50/80 transition-colors"
                      >
                        <td className="px-4 py-3 font-medium text-slate-900">{t.name}</td>
                        <td className="px-4 py-3">
                          {t.state === 'running' && <span className="inline-flex items-center gap-1.5 px-2 py-0.5 rounded-lg bg-blue-50 text-blue-600 font-medium"><span className="w-1.5 h-1.5 rounded-full bg-blue-500 animate-pulse" />Running</span>}
                          {t.state === 'failed' && <span className="inline-flex items-center gap-1.5 px-2 py-0.5 rounded-lg bg-red-50 text-red-600 font-medium">Failed</span>}
                          {t.state === 'idle' && <span className="inline-flex items-center gap-1.5 px-2 py-0.5 rounded-lg bg-slate-100 text-slate-500 font-medium">Idle</span>}
                        </td>
                        <td className="px-4 py-3 text-slate-500">
                          {t.last_run ? new Date(t.last_run).toLocaleTimeString() : 'Never'}
                          {t.last_error && <div className="text-xs text-red-500 mt-1 truncate max-w-[200px]" title={t.last_error}>{t.last_error}</div>}
                        </td>
                        <td className="px-4 py-3 text-right">
                          <motion.button
                            whileHover={{ scale: 1.1 }}
                            whileTap={{ scale: 0.95 }}
                            onClick={() => triggerTask(t.name)}
                            disabled={t.state === 'running'}
                            className="inline-flex items-center justify-center p-1.5 text-slate-400 hover:text-blue-600 hover:bg-blue-50 rounded-lg transition-colors disabled:opacity-50"
                            title="Trigger Now"
                          >
                            <Play size={16} className={t.state === 'running' ? 'opacity-50' : ''} fill={t.state !== 'running' ? 'currentColor' : 'none'} />
                          </motion.button>
                        </td>
                      </motion.tr>
                    ))}
                    {status.tasks.length === 0 && (
                      <tr>
                        <td colSpan={4} className="px-4 py-8 text-center text-slate-500">No background tasks registered.</td>
                      </tr>
                    )}
                  </tbody>
                </table>
              </div>
            </div>
          </div>
        </motion.section>
      )}

      {/* Policy Groups */}
      <motion.section
        initial={{ opacity: 0, y: 20 }} 
        animate={{ opacity: 1, y: 0 }} 
        transition={{ duration: 0.3, delay: 0.1, ease: "easeOut" }}
        className="bg-transparent border border-black/5 rounded-3xl p-6 shadow-sm relative overflow-hidden"
      >
        <div className="flex items-center justify-between mb-4">
          <div className="flex items-center gap-3">
            <div className="p-2 bg-indigo-100/80 text-indigo-600 rounded-xl">
              <Users size={20} />
            </div>
            <h2 className="text-xl font-bold text-slate-900">Policy Groups</h2>
          </div>
          <motion.button 
            whileHover={{ scale: 1.02 }}
            whileTap={{ scale: 0.98 }}
            onClick={() => { setEditingGroup(null); setIsGroupModalOpen(true); }}
            className="flex items-center gap-2 px-4 py-2 bg-slate-900 text-white text-sm font-semibold rounded-xl hover:bg-slate-800 transition-colors shadow-md shadow-slate-900/10"
          >
            <Plus size={16} /> Add Group
          </motion.button>
        </div>

        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-6">
          {groups.map((g, index) => (
            <motion.div 
              key={g.id} 
              initial={{ opacity: 0, scale: 0.95 }}
              animate={{ opacity: 1, scale: 1 }}
              transition={{ delay: index * 0.02 + 0.3, type: "spring", stiffness: 300, damping: 25 }}
              className="bg-white border border-slate-100 rounded-3xl p-5 shadow-sm transition-all group flex flex-col"
            >
              <div className="flex justify-between items-start mb-2">
                <h3 className="font-bold text-slate-900 text-lg group-hover:text-indigo-600 transition-colors">{g.name}</h3>
                <span className="text-xs font-semibold text-slate-400 bg-slate-100/80 px-2 py-1 rounded-lg">ID: {g.id}</span>
              </div>
              <p className="text-sm text-slate-500 mb-4 flex-1 line-clamp-2">
                {g.description || 'No description provided.'}
              </p>
              
              <div className="flex flex-wrap gap-1.5 mb-4">
                {(g.block_categories || []).map(cat => (
                  <span key={cat} className="px-2 py-0.5 rounded-md bg-slate-100 text-slate-600 text-xs font-medium border border-slate-200/60">
                    {cat}
                  </span>
                ))}
                {(!g.block_categories || g.block_categories.length === 0) && (
                  <span className="text-xs text-slate-400 italic">No categories blocked</span>
                )}
              </div>

              <div className="flex items-center gap-3 text-xs font-semibold text-slate-500 mb-5">
                <span className={g.strict_phishing ? 'text-emerald-600 bg-emerald-50 px-2 py-0.5 rounded-md' : 'px-2 py-0.5'}>Phishing: {g.strict_phishing ? 'Strict' : 'Off'}</span>
                <span>&middot;</span>
                <span className={g.strict_malware ? 'text-rose-600 bg-rose-50 px-2 py-0.5 rounded-md' : 'px-2 py-0.5'}>Malware: {g.strict_malware ? 'Strict' : 'Off'}</span>
              </div>

              <div className="flex items-center gap-2 pt-4 border-t border-slate-100/80 mt-auto">
                <motion.button 
                  whileHover={{ scale: 1.05 }}
                  whileTap={{ scale: 0.95 }}
                  onClick={() => { setEditingGroup(g); setIsGroupModalOpen(true); }}
                  className="px-3 py-1.5 text-sm font-semibold text-slate-700 bg-slate-100 hover:bg-slate-200 rounded-lg transition-colors"
                >
                  Edit
                </motion.button>
                {g.id !== 1 && g.name.toLowerCase() !== 'default' && (
                  <motion.button 
                    whileHover={{ scale: 1.1 }}
                    whileTap={{ scale: 0.9 }}
                    onClick={() => deleteGroup(g)}
                    className="p-1.5 text-slate-400 hover:text-red-600 hover:bg-red-50 rounded-lg transition-colors ml-auto"
                    title="Delete Group"
                  >
                    <Trash2 size={16} />
                  </motion.button>
                )}
              </div>
            </motion.div>
          ))}
          {groups.length === 0 && (
            <div className="col-span-full py-12 text-center text-slate-500 bg-slate-50/50 rounded-3xl border border-dashed border-slate-200">
              No policy groups configured.
            </div>
          )}
        </div>
      </motion.section>

      {/* Client Mappings */}
      <motion.section 
        initial={{ opacity: 0, y: 20 }} 
        animate={{ opacity: 1, y: 0 }} 
        transition={{ duration: 0.3, delay: 0.15, ease: "easeOut" }}
        className="bg-transparent border border-black/5 rounded-3xl p-6 shadow-sm relative overflow-hidden"
      >
        <div className="flex items-center gap-3 mb-6">
          <div className="p-2 bg-rose-100/80 text-rose-600 rounded-xl">
            <LinkIcon size={20} />
          </div>
          <div className="flex items-center gap-2">
            <h2 className="text-xl font-bold text-slate-900">Client Mappings</h2>
            <InfoTooltip content="Map specific devices or networks to a policy group." />
          </div>
        </div>

        <div className="flex flex-col md:flex-row gap-4 mb-6">
          <form onSubmit={handleSubmit(createMapping)} className="flex flex-1 flex-col md:flex-row gap-3 bg-white/40 backdrop-blur-md p-2 rounded-2xl relative">
            <Controller
              name="mapType"
              control={control}
              render={({ field }) => (
                <Select value={field.value} onValueChange={field.onChange}>
                  <motion.div
                    whileHover={{ scale: 1.02, y: -1 }}
                    whileTap={{ scale: 0.95, y: 0 }} 
                    transition={{ type: "spring", stiffness: 500, damping: 15 }}
                  >
                    <SelectTrigger className="w-40 bg-white border-none rounded-xl px-4 py-3 text-sm outline-none focus:ring-0 focus:ring-offset-0 text-slate-700 font-medium cursor-pointer h-auto min-h-[44px]">
                      <SelectValue placeholder="Map type" />
                    </SelectTrigger>
                  </motion.div>
                  <SelectContent className="rounded-xl border-slate-200 shadow-lg bg-slate-50/90 backdrop-blur-xl">
                    {[
                      { value: 'ip', label: 'IP Address' },
                      { value: 'cidr', label: 'CIDR Range' },
                      { value: 'client_id', label: 'DoH Client ID' }
                    ].map((option, i) => (
                      <motion.div
                        key={option.value}
                        initial={{ opacity: 0, x: -15 }}
                        animate={{ opacity: 1, x: 0 }}
                        transition={{ delay: i * 0.02, type: "spring", stiffness: 350, damping: 25 }}
                      >
                        <SelectItem value={option.value} className="rounded-lg font-medium text-slate-700 focus:bg-sky-50 focus:text-sky-700 cursor-pointer">{option.label}</SelectItem>
                      </motion.div>
                    ))}
                  </SelectContent>
                </Select>
              )}
            />
            
            <div className="flex-1 relative">
              <input 
                type="text" 
                placeholder={mapType === 'ip' ? "e.g. 192.168.1.50" : mapType === 'cidr' ? "e.g. 192.168.1.0/24" : "e.g. device-01"} 
                {...register('mapValue')}
                className={`w-full bg-white rounded-xl border ${errors.mapValue ? 'border-rose-400' : 'border-transparent'} px-4 py-3 text-sm outline-none placeholder:text-slate-400 font-medium`}
              />
              {errors.mapValue && <p className="absolute -bottom-5 left-2 text-[10px] text-rose-500 font-medium">{errors.mapValue.message}</p>}
            </div>

            <div className="relative">
              <Controller
                name="mapGroupId"
                control={control}
                render={({ field }) => (
                  <Select value={field.value} onValueChange={field.onChange}>
                    <motion.div
                      whileHover={{ scale: 1.02, y: -1 }}
                      whileTap={{ scale: 0.95, y: 0 }} 
                      transition={{ type: "spring", stiffness: 500, damping: 15 }}
                    >
                      <SelectTrigger className={`w-48 bg-white border ${errors.mapGroupId ? 'border-rose-400' : 'border-transparent'} rounded-xl px-4 py-3 text-sm outline-none focus:ring-0 focus:ring-offset-0 text-slate-700 font-medium cursor-pointer h-auto min-h-[44px]`}>
                        <SelectValue placeholder="Select Group..." />
                      </SelectTrigger>
                    </motion.div>
                    <SelectContent className="rounded-xl border-slate-200 shadow-lg bg-slate-50/90 backdrop-blur-xl">
                      {groups.map((g, i) => (
                        <motion.div
                          key={g.id}
                          initial={{ opacity: 0, x: -15 }}
                          animate={{ opacity: 1, x: 0 }}
                          transition={{ delay: i * 0.02, type: "spring", stiffness: 350, damping: 25 }}
                        >
                          <SelectItem value={g.id.toString()} className="rounded-lg font-medium text-slate-700 focus:bg-sky-50 focus:text-sky-700 cursor-pointer">{g.name}</SelectItem>
                        </motion.div>
                      ))}
                    </SelectContent>
                  </Select>
                )}
              />
              {errors.mapGroupId && <p className="absolute -bottom-5 left-2 text-[10px] text-rose-500 font-medium">{errors.mapGroupId.message}</p>}
            </div>

            <motion.button 
              whileHover={{ scale: 1.02, y: -1 }}
              whileTap={{ scale: 0.95, y: 0 }}
              transition={{ type: "spring", stiffness: 500, damping: 15 }}
              type="submit" 
              className="bg-slate-900 text-white px-5 py-3 rounded-xl font-medium text-sm flex items-center justify-center gap-2 hover:bg-slate-800 transition-colors shadow-sm"
            >
              <Plus size={16} />
              Add Map
            </motion.button>
          </form>
        </div>

        <div className="border border-slate-100 rounded-2xl overflow-hidden bg-white shadow-sm">
          <table className="w-full text-left text-sm">
            <thead className="bg-slate-50 text-slate-500 border-b border-slate-100">
              <tr>
                <th className="px-6 py-4 font-semibold">Type</th>
                <th className="px-6 py-4 font-semibold">Value</th>
                <th className="px-6 py-4 font-semibold">Target Group</th>
                <th className="px-6 py-4 font-semibold text-right">Action</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-50">
              {mappings.map((m, index) => {
                const typeLabels: Record<string, string> = { 'ip': 'IP Address', 'cidr': 'CIDR Range', 'client_id': 'Client ID' };
                return (
                  <motion.tr 
                    key={m.id} 
                    initial={{ opacity: 0, x: -10 }}
                    animate={{ opacity: 1, x: 0 }}
                    transition={{ delay: index * 0.02 + 0.4 }}
                    className="hover:bg-slate-50/80 transition-colors"
                  >
                    <td className="px-6 py-4 text-slate-500 font-medium">{typeLabels[m.mapping_type] || m.mapping_type}</td>
                    <td className="px-6 py-4 font-bold text-slate-900">{m.value}</td>
                    <td className="px-6 py-4">
                      <span className="px-3 py-1.5 bg-indigo-50 text-indigo-700 font-semibold rounded-lg text-xs border border-indigo-100">
                        {m.group_name || `Group ID ${m.group_id}`}
                      </span>
                    </td>
                    <td className="px-6 py-4 text-right">
                      <motion.button
                        whileHover={{ scale: 1.1 }}
                        whileTap={{ scale: 0.9 }}
                        onClick={() => deleteMapping(m.id)}
                        className="inline-flex items-center justify-center p-2 text-slate-400 hover:text-red-600 hover:bg-red-50 rounded-lg transition-colors"
                        title="Delete Mapping"
                      >
                        <Trash2 size={18} />
                      </motion.button>
                    </td>
                  </motion.tr>
                );
              })}
              {mappings.length === 0 && (
                <tr>
                  <td colSpan={4} className="px-6 py-10 text-center text-slate-500">No client mappings configured.</td>
                </tr>
              )}
            </tbody>
          </table>
        </div>
      </motion.section>

      <GroupModal 
        isOpen={isGroupModalOpen} 
        onClose={() => setIsGroupModalOpen(false)} 
        onSave={mutateGroups}
        group={editingGroup}
      />
    </motion.div>
  );
}
