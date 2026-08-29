import { useState, useEffect, useRef } from 'react';
import type { FormEvent } from 'react';
import { motion, AnimatePresence } from 'framer-motion';
import { useForm, Controller } from 'react-hook-form';
import { zodResolver } from '@hookform/resolvers/zod';
import * as z from 'zod';

import { 
  Key, 
  Bell, 
  Sliders, 
  Users, 
  Eye, 
  EyeOff, 
  Play, 
  RotateCcw, 
  Save, 
  Plus, 
  X, 
  Check, 
  AlertCircle,
  Loader2,
  Info,
  Server,
  Database,
  Lock,
  Globe,
  Activity,
  Shield,
  Settings
} from 'lucide-react';
import { useDialog } from '../../components/DialogContext';
import { InfoTooltip } from '../../components/InfoTooltip';

interface AnalysisConfig {
  punycode_score: number;
  long_domain_length: number;
  long_domain_score: number;
  hyphen_count_threshold: number;
  hyphen_score: number;
  digit_ratio_threshold: number;
  digit_ratio_score: number;
  mixed_script_score: number;
  keywords: string[];
  keyword_base_score: number;
  keyword_match_score: number;
  keyword_multiple_bonus: number;
  brand_spoofing_score: number;
  entropy_threshold: number;
  entropy_score: number;
}

interface GuestAccess {
  username: string;
  exists: boolean;
  enabled: boolean;
}

interface Toast {
  id: string;
  message: string;
  type: 'ok' | 'err';
}


const coreSchema = z.object({
  geminiKey: z.string(),
  webhookUrl: z.string().url('Must be a valid URL').or(z.literal('')),
  retentionDays: z.number().min(1, 'Min 1 day').max(90, 'Max 90 days')
});

const guestSchema = z.object({
  guestPassword: z.string().optional().refine(val => !val || val.length >= 6, 'Password must be at least 6 characters')
});

const scoringSchema = z.object({
  punycode_score: z.number().min(0).max(100),
  long_domain_length: z.number().min(1).max(255),
  long_domain_score: z.number().min(0).max(100),
  hyphen_count_threshold: z.number().min(1).max(50),
  hyphen_score: z.number().min(0).max(100),
  digit_ratio_threshold: z.number().min(0).max(1),
  digit_ratio_score: z.number().min(0).max(100),
  mixed_script_score: z.number().min(0).max(100),
  keyword_base_score: z.number().min(0).max(100),
  keyword_match_score: z.number().min(0).max(100),
  brand_spoofing_score: z.number().min(0).max(100),
  entropy_threshold: z.number().min(0).max(10),
  entropy_score: z.number().min(0).max(100)
});

const DEFAULT_ANALYSIS_CONFIG: AnalysisConfig = {
  punycode_score: 35,
  long_domain_length: 24,
  long_domain_score: 15,
  hyphen_count_threshold: 3,
  hyphen_score: 10,
  digit_ratio_threshold: 0.25,
  digit_ratio_score: 10,
  mixed_script_score: 25,
  keywords: [],
  keyword_base_score: 15,
  keyword_match_score: 10,
  keyword_multiple_bonus: 10,
  brand_spoofing_score: 50,
  entropy_threshold: 3.0,
  entropy_score: 35
};

/**
 * Server payloads for the analysis config come from a persisted store that
 * older versions may write partially or with null fields; every missing or
 * malformed numeric falls back to the built-in default and `keywords` MUST
 * end up a string[] or the keyword-chips render path crashes the whole app
 * (no error boundary wraps routes).
 */
function normalizeAnalysisConfig(raw: unknown): AnalysisConfig {
  const cfg = raw && typeof raw === 'object' ? (raw as Record<string, unknown>) : {};
  const normalized: AnalysisConfig = { ...DEFAULT_ANALYSIS_CONFIG };
  for (const key of Object.keys(DEFAULT_ANALYSIS_CONFIG) as Array<keyof AnalysisConfig>) {
    if (key === 'keywords') continue;
    const value = cfg[key];
    if (typeof value === 'number' && Number.isFinite(value)) {
      normalized[key] = value;
    }
  }
  normalized.keywords = Array.isArray(cfg.keywords)
    ? cfg.keywords.filter((kw): kw is string => typeof kw === 'string')
    : [];
  return normalized;
}

export function SettingsPage() {
  const [loading, setLoading] = useState(true);
  const [loadError, setLoadError] = useState<string | null>(null);
  const [savingCore, setSavingCore] = useState(false);
  const [savingGuest, setSavingGuest] = useState(false);
  const [savingScoring, setSavingScoring] = useState(false);
  const [toasts, setToasts] = useState<Toast[]>([]);
  const { confirm } = useDialog();
  const { register: registerCore, handleSubmit: handleSubmitCore, formState: { errors: coreErrors, dirtyFields: coreDirtyFields }, reset: resetCore, watch: watchCore } = useForm<z.infer<typeof coreSchema>>({ resolver: zodResolver(coreSchema) });
  const { register: registerGuest, handleSubmit: handleSubmitGuest, formState: { errors: guestErrors }, reset: resetGuest } = useForm<z.infer<typeof guestSchema>>({ resolver: zodResolver(guestSchema) });
  const { register: registerScoring, handleSubmit: handleSubmitScoring, formState: { errors: scoringErrors }, reset: resetScoring } = useForm<z.infer<typeof scoringSchema>>({ resolver: zodResolver(scoringSchema) });
  const geminiKeyValue = watchCore('geminiKey', '');
  const webhookUrlValue = watchCore('webhookUrl', '');


  // Core settings states
  const [geminiKey, setGeminiKey] = useState('');
  const [webhookUrl, setWebhookUrl] = useState('');
  const [retentionDays, setRetentionDays] = useState(30);

  // Visibility states
  const [showApiKey, setShowApiKey] = useState(false);
  const [showWebhook, setShowWebhook] = useState(false);

  // Testing states
  const [testingAi, setTestingAi] = useState(false);
  const [testingAlert, setTestingAlert] = useState(false);

  // Scoring engine states
  const [scoring, setScoring] = useState<AnalysisConfig>(DEFAULT_ANALYSIS_CONFIG);
  const [newKeyword, setNewKeyword] = useState('');

  // Guest access states
  const [guest, setGuest] = useState<GuestAccess>({
    username: 'guest',
    exists: false,
    enabled: false
  });
  const [guestPassword, setGuestPassword] = useState('');
  const [showGuestPassword, setShowGuestPassword] = useState(false);

  // While the settings bundle has not loaded successfully, every mutating
  // control is disabled AND its handler early-returns: saving defaults from
  // an unloaded form would overwrite the operator's real configuration.
  const mutationLocked = loadError !== null;
  // Monotonic sequence for loadSettings — see the guard inside it.
  const loadSeqRef = useRef(0);

  const showToast = (message: string, type: 'ok' | 'err') => {
    const id = Math.random().toString(36).substring(2, 9);
    setToasts(prev => [...prev, { id, message, type }]);
    setTimeout(() => {
      setToasts(prev => prev.filter(t => t.id !== id));
    }, 4000);
  };

  const loadSettings = async () => {
    // Sequence guard: React StrictMode (dev) fires the mount effect twice
    // and Retry can race an in-flight load; a stale response must never
    // overwrite a newer one's result (e.g. a late 500 clobbering a success).
    const seq = ++loadSeqRef.current;
    setLoadError(null);
    try {
      const res = await fetch('/v1/settings/bundle');
      if (!res.ok) throw new Error(`Failed to load settings (HTTP ${res.status})`);
      const data = await res.json();
      if (seq !== loadSeqRef.current) return;

      // The bundle is assembled from several server-side stores; a partial or
      // legacy payload must degrade to field defaults instead of white-
      // screening the route (no error boundary wraps it).
      const settings = data && typeof data.settings === 'object' && data.settings !== null ? data.settings : {};
      const rawRetention = settings.telemetry_retention_days;
      const retention = typeof rawRetention === 'number' && Number.isFinite(rawRetention) ? rawRetention : 30;
      resetCore({
        geminiKey: typeof settings.gemini_api_key === 'string' ? settings.gemini_api_key : '',
        webhookUrl: typeof settings.agent_webhook_url === 'string' ? settings.agent_webhook_url : '',
        retentionDays: Number.isFinite(retention) ? retention : 30,
      });

      setScoring(normalizeAnalysisConfig(data?.analysis_config));
      resetScoring(normalizeAnalysisConfig(data?.analysis_config));
      if (data && typeof data.guest_access === 'object' && data.guest_access !== null) {
        const g = data.guest_access;
        setGuest({
          username: typeof g.username === 'string' ? g.username : 'guest',
          exists: Boolean(g.exists),
          enabled: Boolean(g.enabled),
        });
      }

      setLoading(false);
    } catch (err) {
      if (seq !== loadSeqRef.current) return;
      console.error(err);
      // The loading gate MUST clear on failure too, or /app/settings spins
      // forever whenever /v1/settings/bundle errors (500, offline, ...).
      setLoading(false);
      setLoadError(err instanceof Error ? err.message : 'Error loading settings from server');
    }
  };

  useEffect(() => {
    loadSettings();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  const handleSaveCore = async (data: z.infer<typeof coreSchema>) => {
    if (mutationLocked) return;
    setSavingCore(true);
    try {
      const payload: Record<string, string | number> = {
        telemetry_retention_days: data.retentionDays
      };
      if (coreDirtyFields.geminiKey) payload.gemini_api_key = data.geminiKey.trim();
      if (coreDirtyFields.webhookUrl) payload.agent_webhook_url = data.webhookUrl.trim();
      const res = await fetch('/v1/settings', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(payload)
      });
      if (!res.ok) {
        const error = await res.json();
        throw new Error(error.error || 'Failed to save settings');
      }
      showToast('Core integrations updated successfully', 'ok');
      loadSettings(); 
    } catch (err: any) {
      showToast(err.message, 'err');
    } finally {
      setSavingCore(false);
    }
  };

  const handleSaveScoring = async (data: z.infer<typeof scoringSchema>) => { const fullScoring = { ...scoring, ...data };
    if (mutationLocked) return;
    setSavingScoring(true);
    try {
      const res = await fetch('/v1/config/analysis', {
        method: 'PUT',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(fullScoring)
      });
      if (!res.ok) {
        const error = await res.json();
        throw new Error(error.error || 'Failed to update scoring thresholds');
      }
      showToast('Scoring engine thresholds updated', 'ok');
    } catch (err: any) {
      showToast(err.message, 'err');
    } finally {
      setSavingScoring(false);
    }
  };

  const handleResetScoring = async () => {
    if (mutationLocked) return;
    if (!(await confirm('Are you sure you want to reset all scoring thresholds to default?'))) return;
    setSavingScoring(true);
    try {
      const res = await fetch('/v1/config/analysis/reset', { method: 'POST' });
      if (!res.ok) {
        const error = await res.json();
        throw new Error(error.error || 'Failed to reset settings');
      }
      const defaultData = await res.json();
      // Same contract as loadSettings: one normalization pass, and BOTH the
      // keyword chips (component state) and the numeric inputs (RHF) must
      // reflect the server response.
      const normalized = normalizeAnalysisConfig(defaultData);
      setScoring(normalized);
      resetScoring(normalized);
      showToast('Scoring thresholds reset to defaults', 'ok');
    } catch (err: any) {
      showToast(err.message, 'err');
    } finally {
      setSavingScoring(false);
    }
  };

  const handleSaveGuest = async (data: z.infer<typeof guestSchema>) => { if (mutationLocked) return; if (!data.guestPassword && !guest.exists) {
      showToast('Password is required to initialize guest access', 'err');
      return;
    }
    setSavingGuest(true);
    try {
      const payload: Record<string, any> = { enabled: guest.enabled };
      if (data.guestPassword) payload.password = data.guestPassword;

      const res = await fetch('/v1/settings/guest-access', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(payload)
      });
      if (!res.ok) {
        const error = await res.json();
        throw new Error(error.error || 'Failed to update guest access');
      }
      showToast('Guest access configurations saved', 'ok');
      resetGuest({ guestPassword: '' });
      loadSettings();
    } catch (err: any) {
      showToast(err.message, 'err');
    } finally {
      setSavingGuest(false);
    }
  };

  const handleTestAi = async () => {
    if (mutationLocked) return;
    setTestingAi(true);
    try {
      const res = await fetch('/v1/settings/test-ai', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ gemini_api_key: geminiKeyValue.trim() })
      });
      const data = await res.json();
      if (!res.ok) throw new Error(data.error || 'Connection failed');
      if (data.status === 'ok') {
        showToast('AI Client connected successfully', 'ok');
      } else {
        throw new Error(data.error || data.message || 'Verification failed');
      }
    } catch (err: any) {
      showToast(err.message, 'err');
    } finally {
      setTestingAi(false);
    }
  };

  const handleTestAlert = async () => {
    if (mutationLocked) return;
    setTestingAlert(true);
    try {
      const res = await fetch('/v1/settings/test-alert', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ agent_webhook_url: webhookUrlValue.trim() })
      });
      const data = await res.json();
      if (!res.ok || data.status !== 'ok') {
        throw new Error(data.error || data.message || 'Delivery failed');
      }
      showToast('Test alert delivered successfully', 'ok');
    } catch (err: any) {
      showToast(err.message, 'err');
    } finally {
      setTestingAlert(false);
    }
  };

  const handleAddKeyword = (e: React.KeyboardEvent) => {
    if (e.key === 'Enter') {
      e.preventDefault();
      if (mutationLocked) return;
      const kw = newKeyword.trim().toLowerCase();
      if (kw && !scoring.keywords.includes(kw)) {
        setScoring(prev => ({ ...prev, keywords: [...prev.keywords, kw] }));
        setNewKeyword('');
      }
    }
  };

  const handleRemoveKeyword = (kw: string) => {
    if (mutationLocked) return;
    setScoring(prev => ({ ...prev, keywords: prev.keywords.filter(k => k !== kw) }));
  };

  const updateScoringField = (field: keyof AnalysisConfig, val: any) => {
    setScoring(prev => ({ ...prev, [field]: val }));
  };

  if (loading) {
    return (
      <div className="flex-1 flex items-center justify-center p-8 h-64">
        <Loader2 size={32} className="animate-spin text-slate-400" />
      </div>
    );
  }

  return (
    <motion.div 
      initial={{ opacity: 0 }} 
      animate={{ opacity: 1 }} 
      className="space-y-8 max-w-7xl mx-auto p-4 lg:p-8 pb-32"
    >
      
      {/* Toasts */}
      <div className="fixed bottom-6 right-6 z-50 flex flex-col gap-3">
        <AnimatePresence>
          {toasts.map(t => (
            <motion.div 
              key={t.id}
              initial={{ opacity: 0, y: 20, scale: 0.95 }}
              animate={{ opacity: 1, y: 0, scale: 1 }}
              exit={{ opacity: 0, scale: 0.95, transition: { duration: 0.2 } }}
              className={`flex items-center gap-3 px-4 py-3 rounded-2xl shadow-xl border ${
                t.type === 'ok' 
                  ? 'bg-emerald-50 text-emerald-800 border-emerald-200/50 shadow-emerald-900/5' 
                  : 'bg-red-50 text-red-800 border-red-200/50 shadow-red-900/5'
              }`}
            >
              {t.type === 'ok' ? <Check size={18} className="text-emerald-500" /> : <AlertCircle size={18} className="text-red-500" />}
              <span className="font-medium text-sm pr-2">{t.message}</span>
            </motion.div>
          ))}
        </AnimatePresence>
      </div>

      {/* Load failure: the page shell still renders with field defaults so
          the operator keeps navigation, plus an actionable retry. */}
      {loadError && (
        <div
          role="alert"
          data-testid="settings-load-error"
          className="p-4 bg-red-50 text-red-800 rounded-2xl border border-red-200/50 flex flex-col sm:flex-row sm:items-center gap-3 shadow-sm"
        >
          <AlertCircle size={20} className="text-red-500 shrink-0" />
          <span className="font-medium text-sm flex-1">
            {loadError} — values shown below are defaults, not your saved configuration.
          </span>
          <button
            type="button"
            onClick={() => {
              setLoading(true);
              loadSettings();
            }}
            className="px-4 py-2 bg-red-600 hover:bg-red-700 text-white rounded-xl text-sm font-semibold transition-colors shrink-0"
          >
            Retry
          </button>
        </div>
      )}

      {/* Header */}
      <motion.div 
        initial={{ opacity: 0, y: -20 }} 
        animate={{ opacity: 1, y: 0 }} 
        transition={{ duration: 0.3, ease: "easeOut" }}
        className="flex flex-col md:flex-row md:items-center justify-between gap-6"
      >
        <div>
          <div className="text-sky-600 font-bold uppercase tracking-wider text-xs mb-1.5 pl-1">Configuration</div>
          <div className="flex items-center gap-2.5">
            <Settings size={24} className="text-sky-500" />
            <h1 className="text-3xl font-bold text-slate-900 tracking-tight leading-none">Settings</h1>
            <InfoTooltip content="Configure core integrations, scoring thresholds, and access controls." />
          </div>
        </div>
      </motion.div>

      {/* Main Grid Layout */}
      <div className="grid grid-cols-1 xl:grid-cols-3 gap-6 items-start">
        
        {/* Left Column: Core & Access */}
        <div className="xl:col-span-1 space-y-6">
          
          {/* Core Integrations */}
          <motion.form 
            onSubmit={handleSubmitCore(handleSaveCore)}
            initial={{ opacity: 0, y: 20 }} 
            animate={{ opacity: 1, y: 0 }} 
            transition={{ duration: 0.3, delay: 0.05, ease: "easeOut" }}
            className="bg-white/60 backdrop-blur-xl border border-white/80 rounded-3xl p-6 shadow-sm relative overflow-hidden flex flex-col"
          >
            <div className="absolute top-0 right-0 w-64 h-64 bg-indigo-100/30 rounded-full blur-3xl -z-10 -translate-y-1/2 translate-x-1/2"></div>
            
            <div className="flex items-center gap-3 mb-6 relative z-10">
              <div className="p-2.5 bg-indigo-100/80 text-indigo-600 rounded-xl">
                <Key size={20} />
              </div>
              <div>
                <h2 className="text-lg font-bold text-slate-900">Core Integrations</h2>
                <p className="text-sm text-slate-500">API keys and webhooks</p>
              </div>
            </div>

            <div className="space-y-4 relative z-10">
              {/* API Key Box */}
              <div className="p-4 rounded-2xl bg-white border border-slate-100 shadow-sm space-y-4">
                <div>
                  <label htmlFor="gemini-key-input" className="block font-semibold text-slate-900 text-sm">Gemini API Key</label>
                  <p className="text-xs text-slate-500 mt-0.5">Used by AI classifier node. You can test a new key before saving.</p>
                </div>
                <div className="relative">
                  <input
                    id="gemini-key-input"
                    type={showApiKey && !geminiKeyValue.includes('*') ? "text" : "password"}
                    disabled={mutationLocked}
                    {...registerCore("geminiKey")}
                    placeholder="Enter API Key"
                    className="w-full pl-3 pr-10 py-2.5 bg-slate-50 border border-slate-200 rounded-xl focus:ring-2 focus:ring-indigo-500/20 focus:border-indigo-500 outline-none transition-all text-sm font-mono text-slate-700 disabled:opacity-60 disabled:cursor-not-allowed"
                    autoComplete="off"
                  />
{coreErrors.geminiKey && <p className="text-red-500 text-xs mt-1">{coreErrors.geminiKey.message}</p>}
                  <button
                    type="button"
                    aria-label={showApiKey && !geminiKeyValue.includes('*') ? 'Hide Gemini API key' : 'Show Gemini API key'}
                    className="absolute right-2 top-1/2 -translate-y-1/2 text-slate-400 hover:text-slate-600 p-1.5 rounded-lg hover:bg-slate-100 transition-colors"
                    onClick={() => setShowApiKey(!showApiKey)}
                  >
                    {showApiKey && !geminiKeyValue.includes('*') ? <EyeOff size={16} /> : <Eye size={16} />}
                  </button>
                </div>
                
                <div className="flex items-center justify-between pt-2 border-t border-slate-50">
                  <div className="flex items-center gap-2 text-xs font-medium text-slate-500">
                    <Check size={14} className="text-emerald-500" />
                    <span>Status</span>
                  </div>
                  <button
                    type="button"
                    onClick={handleTestAi}
                    disabled={testingAi || mutationLocked}
                    className="flex items-center gap-1.5 px-3 py-1.5 bg-indigo-50 text-indigo-700 hover:bg-indigo-100 rounded-lg text-xs font-medium transition-colors disabled:opacity-50"
                  >
                    {testingAi ? <Loader2 size={14} className="animate-spin" /> : <Play size={14} />}
                    Test API
                  </button>
                </div>
              </div>

              {/* Webhook Box */}
              <div className="p-4 rounded-2xl bg-white border border-slate-100 shadow-sm space-y-4">
                <div>
                  <label htmlFor="webhook-url-input" className="block font-semibold text-slate-900 text-sm">Agent Webhook URL</label>
                  <p className="text-xs text-slate-500 mt-0.5">Endpoint for instant alerts. You can test a new URL before saving.</p>
                </div>
                <div className="relative">
                  <input
                    id="webhook-url-input"
                    type={showWebhook && !webhookUrlValue.includes('*') ? "text" : "password"}
                    disabled={mutationLocked}
                    {...registerCore("webhookUrl")}
                    placeholder="https://..."
                    aria-invalid={coreErrors.webhookUrl ? true : undefined}
                    aria-describedby={coreErrors.webhookUrl ? 'webhook-url-error' : undefined}
                    className="w-full pl-3 pr-10 py-2.5 bg-slate-50 border border-slate-200 rounded-xl focus:ring-2 focus:ring-blue-500/20 focus:border-blue-500 outline-none transition-all text-sm font-mono text-slate-700 disabled:opacity-60 disabled:cursor-not-allowed"
                    autoComplete="off"
                  />
{coreErrors.webhookUrl && <p id="webhook-url-error" className="text-red-500 text-xs mt-1">{coreErrors.webhookUrl.message}</p>}
                  <button
                    type="button"
                    aria-label={showWebhook && !webhookUrlValue.includes('*') ? 'Hide webhook URL' : 'Show webhook URL'}
                    className="absolute right-2 top-1/2 -translate-y-1/2 text-slate-400 hover:text-slate-600 p-1.5 rounded-lg hover:bg-slate-100 transition-colors"
                    onClick={() => setShowWebhook(!showWebhook)}
                  >
                    {showWebhook && !webhookUrlValue.includes('*') ? <EyeOff size={16} /> : <Eye size={16} />}
                  </button>
                </div>
                
                <div className="flex items-center justify-between pt-2 border-t border-slate-50">
                  <div className="flex items-center gap-2 text-xs font-medium text-slate-500">
                    <Bell size={14} className="text-blue-500" />
                    <span>Pipeline</span>
                  </div>
                  <button
                    type="button"
                    onClick={handleTestAlert}
                    disabled={testingAlert || mutationLocked}
                    className="flex items-center gap-1.5 px-3 py-1.5 bg-blue-50 text-blue-700 hover:bg-blue-100 rounded-lg text-xs font-medium transition-colors disabled:opacity-50"
                  >
                    {testingAlert ? <Loader2 size={14} className="animate-spin" /> : <Play size={14} />}
                    Test Webhook
                  </button>
                </div>
              </div>

              {/* Telemetry Box */}
              <div className="p-4 rounded-2xl bg-white border border-slate-100 shadow-sm flex items-center justify-between">
                <div>
                  <label htmlFor="retention-days-input" className="block font-semibold text-slate-900 text-sm">Log Retention</label>
                  <p className="text-xs text-slate-500 mt-0.5">Days to keep diagnostic logs.</p>
                </div>
                <div className="flex items-center gap-2">
                  <input
                    id="retention-days-input"
                    type="number"
                    min={1}
                    max={90}
                    disabled={mutationLocked}
                    aria-invalid={coreErrors.retentionDays ? true : undefined}
                    aria-describedby={coreErrors.retentionDays ? 'retention-days-error' : undefined}
                    {...registerCore("retentionDays", { valueAsNumber: true })}
                    className="w-16 text-center px-2 py-1.5 bg-slate-50 border border-slate-200 rounded-xl focus:ring-2 focus:ring-indigo-500/20 focus:border-indigo-500 outline-none font-medium text-slate-700 text-sm disabled:opacity-60 disabled:cursor-not-allowed"
                  />
                  <span className="text-xs font-medium text-slate-500">Days</span>
{coreErrors.retentionDays && <p id="retention-days-error" className="text-red-500 text-xs ml-2">{coreErrors.retentionDays.message}</p>}
                </div>
              </div>
            </div>

            <div className="mt-6 pt-4 border-t border-slate-200/50">
              <button
                type="submit"
                disabled={savingCore || mutationLocked}
                className="w-full flex items-center justify-center gap-2 px-6 py-2.5 bg-slate-900 hover:bg-slate-800 text-white rounded-xl font-medium transition-colors disabled:opacity-50 shadow-sm text-sm"
              >
                {savingCore ? <Loader2 size={16} className="animate-spin" /> : <Save size={16} />}
                Save Integrations
              </button>
            </div>
          </motion.form>

          {/* Access Control */}
          <motion.form 
            onSubmit={handleSubmitGuest(handleSaveGuest)}
            initial={{ opacity: 0, y: 20 }} 
            animate={{ opacity: 1, y: 0 }} 
            transition={{ duration: 0.3, delay: 0.1, ease: "easeOut" }}
            className="bg-white/60 backdrop-blur-xl border border-white/80 rounded-3xl p-6 shadow-sm relative overflow-hidden flex flex-col"
          >
            <div className="absolute top-0 left-0 w-64 h-64 bg-emerald-100/30 rounded-full blur-3xl -z-10 -translate-y-1/2 -translate-x-1/2"></div>
            
            <div className="flex items-center gap-3 mb-6 relative z-10">
              <div className="p-2.5 bg-emerald-100/80 text-emerald-600 rounded-xl">
                <Users size={20} />
              </div>
              <div>
                <h2 className="text-lg font-bold text-slate-900">Guest Access</h2>
                <p className="text-sm text-slate-500">Read-only dashboard viewers</p>
              </div>
            </div>

            <div className="space-y-4 relative z-10">
              <div className="p-4 rounded-2xl bg-white border border-slate-100 shadow-sm space-y-4">
                <div className="flex items-center justify-between bg-slate-50 rounded-xl p-3 border border-slate-100">
                  <div>
                    <h4 id="guest-mode-heading" className="font-semibold text-slate-900 text-sm">Enable Guest Mode</h4>
                    <p className="text-xs text-slate-500 mt-0.5">Allows login as <code className="px-1 bg-slate-200 rounded text-slate-700 font-mono">guest</code></p>
                  </div>

                  <button
                    type="button"
                    role="switch"
                    aria-checked={guest.enabled}
                    aria-labelledby="guest-mode-heading"
                    data-testid="guest-mode-toggle"
                    disabled={mutationLocked}
                    className={`relative inline-flex h-6 w-11 items-center rounded-full transition-colors focus:outline-none focus-visible:ring-2 focus-visible:ring-emerald-600 focus-visible:ring-offset-2 focus-visible:ring-offset-white disabled:cursor-not-allowed ${guest.enabled ? 'bg-emerald-500' : 'bg-slate-300'} ${mutationLocked ? 'opacity-60' : ''}`}
                    onClick={() => {
                      if (mutationLocked) return;
                      setGuest(prev => ({ ...prev, enabled: !prev.enabled }));
                    }}
                  >
                    <span className={`inline-block h-4 w-4 transform rounded-full bg-white shadow-sm transition-transform ${guest.enabled ? 'translate-x-6' : 'translate-x-1'}`} />
                  </button>
                </div>

                <div className="space-y-2">
                  <label htmlFor="guest-password-input" className="block text-xs font-semibold text-slate-700">
                    {guest.exists ? 'Reset Guest Password (Optional)' : 'Set Initial Guest Password'}
                  </label>
                  <div className="relative">
                    <input
                      id="guest-password-input"
                      type={showGuestPassword ? "text" : "password"}
                      disabled={mutationLocked}
                      {...registerGuest("guestPassword")}
                      placeholder="Enter password..."
                      aria-invalid={guestErrors.guestPassword ? true : undefined}
                      aria-describedby={guestErrors.guestPassword ? 'guest-password-error' : undefined}
                      className="w-full pl-3 pr-10 py-2.5 bg-slate-50 border border-slate-200 rounded-xl focus:ring-2 focus:ring-emerald-500/20 focus:border-emerald-500 outline-none transition-all text-sm font-mono text-slate-700 disabled:opacity-60 disabled:cursor-not-allowed"
                      autoComplete="new-password"
                    />
{guestErrors.guestPassword && <p id="guest-password-error" className="text-red-500 text-xs mt-1">{guestErrors.guestPassword.message}</p>}
                    <button
                      type="button"
                      aria-label={showGuestPassword ? 'Hide guest password' : 'Show guest password'}
                      className="absolute right-2 top-1/2 -translate-y-1/2 text-slate-400 hover:text-slate-600 p-1.5 rounded-lg hover:bg-slate-100 transition-colors"
                      onClick={() => setShowGuestPassword(!showGuestPassword)}
                    >
                      {showGuestPassword ? <EyeOff size={16} /> : <Eye size={16} />}
                    </button>
                  </div>
                </div>
              </div>
            </div>

            <div className="mt-6 pt-4 border-t border-slate-200/50">
              <button
                type="submit"
                disabled={savingGuest || mutationLocked}
                className="w-full flex items-center justify-center gap-2 px-6 py-2.5 bg-emerald-600 hover:bg-emerald-700 text-white rounded-xl font-medium transition-colors disabled:opacity-50 shadow-sm text-sm"
              >
                {savingGuest ? <Loader2 size={16} className="animate-spin" /> : <Save size={16} />}
                Save Access Control
              </button>
            </div>
          </motion.form>

        </div>

        {/* Right Column: Scoring Engine */}
        <div className="xl:col-span-2">
          <motion.section 
            initial={{ opacity: 0, y: 20 }} 
            animate={{ opacity: 1, y: 0 }} 
            transition={{ duration: 0.3, delay: 0.15, ease: "easeOut" }}
            className="bg-white/60 backdrop-blur-xl border border-white/80 rounded-3xl p-6 shadow-sm relative overflow-hidden flex flex-col h-full"
          >
            <div className="absolute top-0 right-0 w-[500px] h-[500px] bg-amber-50/40 rounded-full blur-[80px] -z-10 -translate-y-1/2 translate-x-1/3"></div>
            
            <div className="flex flex-col md:flex-row md:items-center justify-between gap-4 mb-6 relative z-10">
              <div className="flex items-center gap-3">
                <div className="p-2.5 bg-amber-100/80 text-amber-600 rounded-xl">
                  <Sliders size={20} />
                </div>
                <div>
                  <h2 className="text-lg font-bold text-slate-900">Engine Thresholds</h2>
                  <p className="text-sm text-slate-500">Fine-grained scoring weights and heuristics</p>
                </div>
              </div>
              <div className="flex items-center gap-3">
                <button
                  onClick={handleResetScoring}
                  disabled={savingScoring || mutationLocked}
                  className="flex items-center gap-1.5 px-3 py-2 bg-white border border-slate-200 hover:border-slate-300 hover:bg-slate-50 text-slate-700 rounded-xl text-xs font-semibold transition-all shadow-sm disabled:opacity-50 disabled:cursor-not-allowed"
                >
                  <RotateCcw size={14} />
                  Reset Defaults
                </button>
                <button
                  onClick={handleSubmitScoring(handleSaveScoring)}
                  disabled={savingScoring || mutationLocked}
                  className="flex items-center gap-1.5 px-4 py-2 bg-slate-900 hover:bg-slate-800 text-white rounded-xl text-xs font-semibold transition-colors shadow-sm disabled:opacity-50 disabled:cursor-not-allowed"
                >
                  {savingScoring ? <Loader2 size={14} className="animate-spin" /> : <Save size={14} />}
                  Apply Config
                </button>
              </div>
            </div>

            <div className="grid grid-cols-1 md:grid-cols-2 gap-6 relative z-10">
              
              {/* Domain Structure Analysis */}
              <div className="p-5 rounded-2xl bg-white border border-slate-100 shadow-sm space-y-4">
                <h3 className="font-semibold text-slate-800 flex items-center gap-2 text-sm">
                  <Globe size={16} className="text-sky-500" />
                  Domain Structure Analysis
                </h3>
                
                <div className="grid grid-cols-2 gap-x-4 gap-y-3 items-center">
                  <label htmlFor="scoring-punycode-score" className="text-xs font-medium text-slate-600">Punycode Penalty</label>
                  <input id="scoring-punycode-score" type="number" disabled={mutationLocked} aria-invalid={scoringErrors.punycode_score ? true : undefined} className="settings-num-input text-sm" {...registerScoring("punycode_score", { valueAsNumber: true })} />
{scoringErrors.punycode_score && <span className="text-red-500 text-[10px]">punycode_score</span>}

                  <label htmlFor="scoring-mixed-script-score" className="text-xs font-medium text-slate-600">Mixed Script Penalty</label>
                  <input id="scoring-mixed-script-score" type="number" disabled={mutationLocked} aria-invalid={scoringErrors.mixed_script_score ? true : undefined} className="settings-num-input text-sm" {...registerScoring("mixed_script_score", { valueAsNumber: true })} />
{scoringErrors.mixed_script_score && <span className="text-red-500 text-[10px]">mixed_script_score</span>}

                  <label htmlFor="scoring-long-domain-length" className="text-xs font-medium text-slate-600">Long Domain (Chars)</label>
                  <input id="scoring-long-domain-length" type="number" disabled={mutationLocked} aria-invalid={scoringErrors.long_domain_length ? true : undefined} className="settings-num-input text-sm" {...registerScoring("long_domain_length", { valueAsNumber: true })} />
{scoringErrors.long_domain_length && <span className="text-red-500 text-[10px]">long_domain_length</span>}

                  <label htmlFor="scoring-long-domain-score" className="text-xs font-medium text-slate-600">Long Domain Penalty</label>
                  <input id="scoring-long-domain-score" type="number" disabled={mutationLocked} aria-invalid={scoringErrors.long_domain_score ? true : undefined} className="settings-num-input text-sm" {...registerScoring("long_domain_score", { valueAsNumber: true })} />
{scoringErrors.long_domain_score && <span className="text-red-500 text-[10px]">long_domain_score</span>}

                  <label htmlFor="scoring-hyphen-count-threshold" className="text-xs font-medium text-slate-600">Hyphen Threshold</label>
                  <input id="scoring-hyphen-count-threshold" type="number" disabled={mutationLocked} aria-invalid={scoringErrors.hyphen_count_threshold ? true : undefined} className="settings-num-input text-sm" {...registerScoring("hyphen_count_threshold", { valueAsNumber: true })} />
{scoringErrors.hyphen_count_threshold && <span className="text-red-500 text-[10px]">hyphen_count_threshold</span>}

                  <label htmlFor="scoring-hyphen-score" className="text-xs font-medium text-slate-600">Hyphen Penalty</label>
                  <input id="scoring-hyphen-score" type="number" disabled={mutationLocked} aria-invalid={scoringErrors.hyphen_score ? true : undefined} className="settings-num-input text-sm" {...registerScoring("hyphen_score", { valueAsNumber: true })} />
{scoringErrors.hyphen_score && <span className="text-red-500 text-[10px]">hyphen_score</span>}
                </div>
              </div>

              {/* Entropy & Density */}
              <div className="p-5 rounded-2xl bg-white border border-slate-100 shadow-sm space-y-4">
                <h3 className="font-semibold text-slate-800 flex items-center gap-2 text-sm">
                  <Activity size={16} className="text-rose-500" />
                  Entropy & Density
                </h3>
                
                <div className="grid grid-cols-2 gap-x-4 gap-y-3 items-center">
                  <label htmlFor="scoring-digit-ratio-threshold" className="text-xs font-medium text-slate-600">Digit Ratio Threshold</label>
                  <input id="scoring-digit-ratio-threshold" type="number" disabled={mutationLocked} step="0.05" aria-invalid={scoringErrors.digit_ratio_threshold ? true : undefined} className="settings-num-input text-sm" {...registerScoring("digit_ratio_threshold", { valueAsNumber: true })} />
{scoringErrors.digit_ratio_threshold && <span className="text-red-500 text-[10px]">digit_ratio_threshold</span>}

                  <label htmlFor="scoring-digit-ratio-score" className="text-xs font-medium text-slate-600">Digit Ratio Penalty</label>
                  <input id="scoring-digit-ratio-score" type="number" disabled={mutationLocked} aria-invalid={scoringErrors.digit_ratio_score ? true : undefined} className="settings-num-input text-sm" {...registerScoring("digit_ratio_score", { valueAsNumber: true })} />
{scoringErrors.digit_ratio_score && <span className="text-red-500 text-[10px]">digit_ratio_score</span>}

                  <label htmlFor="scoring-entropy-threshold" className="text-xs font-medium text-slate-600">Entropy Threshold</label>
                  <input id="scoring-entropy-threshold" type="number" disabled={mutationLocked} step="0.1" aria-invalid={scoringErrors.entropy_threshold ? true : undefined} className="settings-num-input text-sm" {...registerScoring("entropy_threshold", { valueAsNumber: true })} />
{scoringErrors.entropy_threshold && <span className="text-red-500 text-[10px]">entropy_threshold</span>}

                  <label htmlFor="scoring-entropy-score" className="text-xs font-medium text-slate-600">Entropy Penalty</label>
                  <input id="scoring-entropy-score" type="number" disabled={mutationLocked} aria-invalid={scoringErrors.entropy_score ? true : undefined} className="settings-num-input text-sm" {...registerScoring("entropy_score", { valueAsNumber: true })} />
{scoringErrors.entropy_score && <span className="text-red-500 text-[10px]">entropy_score</span>}
                </div>
              </div>

              {/* Keyword Heuristics */}
              <div className="md:col-span-2 p-5 rounded-2xl bg-white border border-slate-100 shadow-sm space-y-4 mt-2">
                <h3 className="font-semibold text-slate-800 flex items-center gap-2 text-sm">
                  <Shield size={16} className="text-emerald-500" />
                  Keyword Heuristics
                </h3>
                
                <div className="grid grid-cols-1 md:grid-cols-3 gap-4 mb-4">
                  <div>
                    <label htmlFor="scoring-keyword-base-score" className="block text-xs font-medium text-slate-600 mb-1">Keyword Base Score</label>
                    <input id="scoring-keyword-base-score" type="number" disabled={mutationLocked} aria-invalid={scoringErrors.keyword_base_score ? true : undefined} className="settings-num-input text-sm" {...registerScoring("keyword_base_score", { valueAsNumber: true })} />
{scoringErrors.keyword_base_score && <span className="text-red-500 text-[10px]">keyword_base_score</span>}
                  </div>
                  <div>
                    <label htmlFor="scoring-keyword-match-score" className="block text-xs font-medium text-slate-600 mb-1">Match Multiplier</label>
                    <input id="scoring-keyword-match-score" type="number" disabled={mutationLocked} aria-invalid={scoringErrors.keyword_match_score ? true : undefined} className="settings-num-input text-sm" {...registerScoring("keyword_match_score", { valueAsNumber: true })} />
{scoringErrors.keyword_match_score && <span className="text-red-500 text-[10px]">keyword_match_score</span>}
                  </div>
                  <div>
                    <label htmlFor="scoring-brand-spoofing-score" className="block text-xs font-medium text-slate-600 mb-1">Brand Spoof Penalty</label>
                    <input id="scoring-brand-spoofing-score" type="number" disabled={mutationLocked} aria-invalid={scoringErrors.brand_spoofing_score ? true : undefined} className="settings-num-input text-sm" {...registerScoring("brand_spoofing_score", { valueAsNumber: true })} />
{scoringErrors.brand_spoofing_score && <span className="text-red-500 text-[10px]">brand_spoofing_score</span>}
                  </div>
                </div>

                <div className="mt-4 pt-4 border-t border-slate-50">
                  <label htmlFor="new-keyword-input" className="block text-sm font-semibold text-slate-800 mb-2">Suspicious Keywords Dictionary</label>
                  <p className="text-xs text-slate-500 mb-3">Add exact match substrings that indicate phishing or scams.</p>
                  <div className="p-3 bg-slate-50 rounded-xl border border-slate-200 min-h-[120px]">
                    <div className="flex flex-wrap gap-2 mb-3">
                      <AnimatePresence>
                        {scoring.keywords.map(kw => (
                          <motion.span
                            key={kw}
                            initial={{ opacity: 0, scale: 0.8 }}
                            animate={{ opacity: 1, scale: 1 }}
                            exit={{ opacity: 0, scale: 0.8 }}
                            className="inline-flex items-center gap-1.5 px-2.5 py-1 bg-white border border-slate-200 text-slate-700 rounded-lg text-xs font-medium shadow-sm"
                          >
                            {kw}
                            <button
                              type="button"
                              aria-label={`Remove keyword ${kw}`}
                              disabled={mutationLocked}
                              onClick={() => handleRemoveKeyword(kw)}
                              className="text-slate-400 hover:text-red-500 focus:outline-none focus-visible:ring-2 focus-visible:ring-rose-600 focus-visible:ring-offset-1 focus-visible:ring-offset-white rounded transition-colors ml-1 disabled:cursor-not-allowed disabled:opacity-50"
                            >
                              <X size={14} />
                            </button>
                          </motion.span>
                        ))}
                      </AnimatePresence>
                    </div>
                    <div className="flex items-center gap-2 mt-2">
                      <Plus size={16} className="text-slate-400 ml-1" />
                      <input
                        id="new-keyword-input"
                        type="text"
                        disabled={mutationLocked}
                        className="flex-1 bg-transparent border-none focus:ring-0 text-sm outline-none placeholder:text-slate-400 font-medium text-slate-700 disabled:cursor-not-allowed"
                        placeholder="Add keyword and press Enter..."
                        value={newKeyword}
                        onChange={(e) => setNewKeyword(e.target.value)}
                        onKeyDown={handleAddKeyword}
                      />
                    </div>
                  </div>
                </div>
              </div>

            </div>
          </motion.section>
        </div>

      </div>

      <style>{`
        .settings-num-input {
          width: 100%;
          padding: 0.4rem 0.75rem;
          background-color: #f8fafc;
          border: 1px solid #e2e8f0;
          border-radius: 0.75rem;
          outline: none;
          font-weight: 500;
          color: #334155;
          transition: all 0.2s;
        }
        .settings-num-input:focus {
          border-color: #6366f1;
          box-shadow: 0 0 0 3px rgba(99, 102, 241, 0.1);
          background-color: #ffffff;
        }
      `}</style>
    </motion.div>
  );
}
