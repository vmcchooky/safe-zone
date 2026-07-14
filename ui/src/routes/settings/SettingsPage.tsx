import { useState, useEffect } from 'react';
import type { FormEvent } from 'react';
import { motion, AnimatePresence } from 'framer-motion';
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
  Shield
} from 'lucide-react';
import { useDialog } from '../../components/DialogContext';

type Tab = 'CORE' | 'SCORING' | 'ACCESS';

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

export function SettingsPage() {
  const [activeTab, setActiveTab] = useState<Tab>('CORE');
  const [loading, setLoading] = useState(true);
  const [saving, setSaving] = useState(false);
  const [toasts, setToasts] = useState<Toast[]>([]);
  const { confirm } = useDialog();

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
  const [scoring, setScoring] = useState<AnalysisConfig>({
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
  });
  const [newKeyword, setNewKeyword] = useState('');

  // Guest access states
  const [guest, setGuest] = useState<GuestAccess>({
    username: 'guest',
    exists: false,
    enabled: false
  });
  const [guestPassword, setGuestPassword] = useState('');
  const [showGuestPassword, setShowGuestPassword] = useState(false);

  const showToast = (message: string, type: 'ok' | 'err') => {
    const id = Math.random().toString(36).substring(2, 9);
    setToasts(prev => [...prev, { id, message, type }]);
    setTimeout(() => {
      setToasts(prev => prev.filter(t => t.id !== id));
    }, 4000);
  };

  const loadSettings = async () => {
    try {
      const res = await fetch('/v1/settings/bundle');
      if (!res.ok) throw new Error('Failed to load settings');
      const data = await res.json();

      setGeminiKey(data.settings.gemini_api_key || '');
      setWebhookUrl(data.settings.agent_webhook_url || '');
      setRetentionDays(data.settings.telemetry_retention_days || 30);

      if (data.analysis_config) setScoring(data.analysis_config);
      if (data.guest_access) setGuest(data.guest_access);

      setLoading(false);
    } catch (err) {
      console.error(err);
      showToast('Error loading settings from server', 'err');
    }
  };

  useEffect(() => {
    loadSettings();
  }, []);

  const handleSaveCore = async (e: FormEvent) => {
    e.preventDefault();
    setSaving(true);
    try {
      const payload = {
        telemetry_retention_days: retentionDays,
        gemini_api_key: geminiKey.trim(),
        agent_webhook_url: webhookUrl.trim()
      };
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
      setSaving(false);
    }
  };

  const handleSaveScoring = async () => {
    setSaving(true);
    try {
      const res = await fetch('/v1/config/analysis', {
        method: 'PUT',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(scoring)
      });
      if (!res.ok) {
        const error = await res.json();
        throw new Error(error.error || 'Failed to update scoring thresholds');
      }
      showToast('Scoring engine thresholds updated', 'ok');
    } catch (err: any) {
      showToast(err.message, 'err');
    } finally {
      setSaving(false);
    }
  };

  const handleResetScoring = async () => {
    if (!(await confirm('Are you sure you want to reset all scoring thresholds to default?'))) return;
    setSaving(true);
    try {
      const res = await fetch('/v1/config/analysis/reset', { method: 'POST' });
      if (!res.ok) {
        const error = await res.json();
        throw new Error(error.error || 'Failed to reset settings');
      }
      const defaultData = await res.json();
      setScoring(defaultData);
      showToast('Scoring thresholds reset to defaults', 'ok');
    } catch (err: any) {
      showToast(err.message, 'err');
    } finally {
      setSaving(false);
    }
  };

  const handleSaveGuest = async (e: FormEvent) => {
    e.preventDefault();
    if (!guestPassword && !guest.exists) {
      showToast('Password is required to initialize guest access', 'err');
      return;
    }
    setSaving(true);
    try {
      const payload: Record<string, any> = { enabled: guest.enabled };
      if (guestPassword) payload.password = guestPassword;

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
      setGuestPassword('');
      loadSettings();
    } catch (err: any) {
      showToast(err.message, 'err');
    } finally {
      setSaving(false);
    }
  };

  const handleTestAi = async () => {
    setTestingAi(true);
    try {
      const res = await fetch('/v1/settings/test-ai', { method: 'POST' });
      const data = await res.json();
      if (!res.ok) throw new Error(data.error || 'Connection failed');
      if (data.status === 'ok') {
        showToast('AI Client connected successfully', 'ok');
      } else {
        throw new Error(data.message || 'Verification failed');
      }
    } catch (err: any) {
      showToast(err.message, 'err');
    } finally {
      setTestingAi(false);
    }
  };

  const handleTestAlert = async () => {
    setTestingAlert(true);
    try {
      const res = await fetch('/v1/settings/test-webhook', { method: 'POST' });
      const data = await res.json();
      if (!res.ok) throw new Error(data.error || 'Delivery failed');
      if (data.status === 'ok') {
        showToast('Test alert delivered successfully', 'ok');
      } else {
        throw new Error(data.message || 'Delivery failed');
      }
    } catch (err: any) {
      showToast(err.message, 'err');
    } finally {
      setTestingAlert(false);
    }
  };

  const handleAddKeyword = (e: React.KeyboardEvent) => {
    if (e.key === 'Enter') {
      e.preventDefault();
      const kw = newKeyword.trim().toLowerCase();
      if (kw && !scoring.keywords.includes(kw)) {
        setScoring(prev => ({ ...prev, keywords: [...prev.keywords, kw] }));
        setNewKeyword('');
      }
    }
  };

  const handleRemoveKeyword = (kw: string) => {
    setScoring(prev => ({ ...prev, keywords: prev.keywords.filter(k => k !== kw) }));
  };

  const updateScoringField = (field: keyof AnalysisConfig, val: any) => {
    setScoring(prev => ({ ...prev, [field]: val }));
  };

  if (loading) {
    return (
      <div className="flex-1 flex items-center justify-center p-8">
        <Loader2 size={32} className="animate-spin text-slate-400" />
      </div>
    );
  }

  return (
    <div className="flex-1 p-6 lg:p-8 max-w-[1200px] mx-auto w-full flex flex-col gap-8">
      
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

      <div>
        <h1 className="text-2xl font-bold text-slate-900 mb-2">Platform Settings</h1>
        <p className="text-slate-500">Configure core integrations, scoring thresholds, and access controls.</p>
      </div>

      {/* Modern Pill Tabs */}
      <div className="flex flex-wrap items-center gap-2 p-1.5 bg-slate-100/80 backdrop-blur-md rounded-2xl w-max border border-slate-200/50">
        {[
          { id: 'CORE', label: 'Core Integrations', icon: Key },
          { id: 'SCORING', label: 'Scoring Engine', icon: Sliders },
          { id: 'ACCESS', label: 'Access Control', icon: Users }
        ].map(tab => (
          <button 
            key={tab.id}
            className={`relative flex items-center gap-2 px-5 py-2.5 rounded-xl font-medium text-sm transition-colors ${
              activeTab === tab.id ? 'text-slate-900' : 'text-slate-500 hover:text-slate-700'
            }`}
            onClick={() => setActiveTab(tab.id as Tab)}
          >
            {activeTab === tab.id && (
              <motion.div 
                layoutId="activeSettingsTab"
                className="absolute inset-0 bg-white rounded-xl shadow-[0_2px_8px_-2px_rgba(0,0,0,0.05)] border border-slate-200/50"
                transition={{ type: 'spring', stiffness: 400, damping: 30 }}
              />
            )}
            <tab.icon size={16} className={`relative z-10 ${activeTab === tab.id ? 'text-indigo-500' : ''}`} />
            <span className="relative z-10">{tab.label}</span>
          </button>
        ))}
      </div>

      {/* Main Content Area */}
      <div className="bg-white/60 backdrop-blur-xl border border-white/80 rounded-[2rem] p-6 lg:p-8 shadow-sm relative overflow-hidden min-h-[600px]">
        {/* Background blobs for premium feel */}
        <div className="absolute top-0 right-0 w-[600px] h-[600px] bg-blue-50/40 rounded-full blur-[80px] -z-10 -translate-y-1/2 translate-x-1/3"></div>
        <div className="absolute bottom-0 left-0 w-[500px] h-[500px] bg-indigo-50/40 rounded-full blur-[80px] -z-10 translate-y-1/3 -translate-x-1/3"></div>

        <AnimatePresence mode="wait">
          
          {/* =========================================
              CORE TAB 
          ========================================= */}
          {activeTab === 'CORE' && (
            <motion.form 
              key="core"
              onSubmit={handleSaveCore}
              initial={{ opacity: 0, y: 10 }}
              animate={{ opacity: 1, y: 0 }}
              exit={{ opacity: 0, y: -10 }}
              transition={{ duration: 0.2 }}
              className="flex flex-col h-full"
            >
              <div className="mb-8">
                <h2 className="text-xl font-bold text-slate-900 flex items-center gap-3">
                  <span className="p-2 bg-indigo-100 text-indigo-600 rounded-xl"><Server size={20} /></span>
                  Core Integrations
                </h2>
                <p className="text-slate-500 text-sm mt-2 ml-12">Configure external threat intelligence APIs and alert webhooks.</p>
              </div>

              <div className="space-y-6 max-w-3xl">
                {/* API Key Box */}
                <div className="p-5 rounded-2xl bg-white border border-slate-100 shadow-sm space-y-4">
                  <div className="flex items-center justify-between">
                    <div>
                      <label className="block font-semibold text-slate-900 text-sm">Gemini AI Client API Key</label>
                      <p className="text-xs text-slate-500 mt-1">Used by AI classifier node to enrich and confirm domain risk dossiers.</p>
                    </div>
                  </div>
                  <div className="relative">
                    <input 
                      type={showApiKey && !geminiKey.includes('*') ? "text" : "password"}
                      value={geminiKey}
                      onChange={(e) => setGeminiKey(e.target.value)}
                      placeholder="Enter Google Gemini API Key"
                      className="w-full pl-4 pr-12 py-3 bg-slate-50 border border-slate-200 rounded-xl focus:ring-2 focus:ring-indigo-500/20 focus:border-indigo-500 outline-none transition-all text-sm font-mono text-slate-700"
                      autoComplete="off"
                    />
                    <button 
                      type="button"
                      className="absolute right-3 top-1/2 -translate-y-1/2 text-slate-400 hover:text-slate-600 p-1.5 rounded-lg hover:bg-slate-100 transition-colors"
                      onClick={() => setShowApiKey(!showApiKey)}
                    >
                      {showApiKey && !geminiKey.includes('*') ? <EyeOff size={18} /> : <Eye size={18} />}
                    </button>
                  </div>
                  
                  <div className="flex items-center justify-between pt-2 border-t border-slate-50">
                    <div className="flex items-center gap-2 text-sm text-slate-500">
                      <Check size={16} className="text-emerald-500" />
                      <span>Integration Status</span>
                    </div>
                    <button 
                      type="button" 
                      onClick={handleTestAi}
                      disabled={testingAi}
                      className="flex items-center gap-2 px-4 py-2 bg-indigo-50 text-indigo-700 hover:bg-indigo-100 rounded-lg text-sm font-medium transition-colors disabled:opacity-50"
                    >
                      {testingAi ? <Loader2 size={16} className="animate-spin" /> : <Play size={16} />}
                      Test Connection
                    </button>
                  </div>
                </div>

                {/* Webhook Box */}
                <div className="p-5 rounded-2xl bg-white border border-slate-100 shadow-sm space-y-4">
                  <div className="flex items-center justify-between">
                    <div>
                      <label className="block font-semibold text-slate-900 text-sm">Incident Agent Webhook URL</label>
                      <p className="text-xs text-slate-500 mt-1">Endpoint to send instant alert payloads when suspicious activity is blocked.</p>
                    </div>
                  </div>
                  <div className="relative">
                    <input 
                      type={showWebhook && !webhookUrl.includes('*') ? "text" : "password"}
                      value={webhookUrl}
                      onChange={(e) => setWebhookUrl(e.target.value)}
                      placeholder="https://hooks.slack.com/services/..."
                      className="w-full pl-4 pr-12 py-3 bg-slate-50 border border-slate-200 rounded-xl focus:ring-2 focus:ring-blue-500/20 focus:border-blue-500 outline-none transition-all text-sm font-mono text-slate-700"
                      autoComplete="off"
                    />
                    <button 
                      type="button"
                      className="absolute right-3 top-1/2 -translate-y-1/2 text-slate-400 hover:text-slate-600 p-1.5 rounded-lg hover:bg-slate-100 transition-colors"
                      onClick={() => setShowWebhook(!showWebhook)}
                    >
                      {showWebhook && !webhookUrl.includes('*') ? <EyeOff size={18} /> : <Eye size={18} />}
                    </button>
                  </div>
                  
                  <div className="flex items-center justify-between pt-2 border-t border-slate-50">
                    <div className="flex items-center gap-2 text-sm text-slate-500">
                      <Bell size={16} className="text-blue-500" />
                      <span>Delivery Pipeline</span>
                    </div>
                    <button 
                      type="button" 
                      onClick={handleTestAlert}
                      disabled={testingAlert}
                      className="flex items-center gap-2 px-4 py-2 bg-blue-50 text-blue-700 hover:bg-blue-100 rounded-lg text-sm font-medium transition-colors disabled:opacity-50"
                    >
                      {testingAlert ? <Loader2 size={16} className="animate-spin" /> : <Play size={16} />}
                      Test Payload
                    </button>
                  </div>
                </div>

                {/* Telemetry Box */}
                <div className="p-5 rounded-2xl bg-white border border-slate-100 shadow-sm flex items-center justify-between">
                  <div>
                    <label className="block font-semibold text-slate-900 text-sm">Telemetry Log Retention</label>
                    <p className="text-xs text-slate-500 mt-1">Days to keep diagnostic logs before auto-pruning.</p>
                  </div>
                  <div className="flex items-center gap-3">
                    <input 
                      type="number"
                      min={1}
                      max={90}
                      value={retentionDays}
                      onChange={(e) => setRetentionDays(parseInt(e.target.value) || 30)}
                      className="w-24 text-center px-3 py-2 bg-slate-50 border border-slate-200 rounded-xl focus:ring-2 focus:ring-indigo-500/20 focus:border-indigo-500 outline-none font-medium text-slate-700"
                    />
                    <span className="text-sm font-medium text-slate-500">Days</span>
                  </div>
                </div>
              </div>

              <div className="mt-10 pt-6 border-t border-slate-200/50">
                <button 
                  type="submit" 
                  disabled={saving}
                  className="flex items-center gap-2 px-6 py-3 bg-slate-900 hover:bg-slate-800 text-white rounded-xl font-medium transition-colors disabled:opacity-50 shadow-sm"
                >
                  {saving ? <Loader2 size={18} className="animate-spin" /> : <Save size={18} />}
                  Save Integrations
                </button>
              </div>
            </motion.form>
          )}

          {/* =========================================
              SCORING TAB 
          ========================================= */}
          {activeTab === 'SCORING' && (
            <motion.div 
              key="scoring"
              initial={{ opacity: 0, y: 10 }}
              animate={{ opacity: 1, y: 0 }}
              exit={{ opacity: 0, y: -10 }}
              transition={{ duration: 0.2 }}
              className="flex flex-col h-full"
            >
              <div className="flex flex-col md:flex-row md:items-center justify-between gap-4 mb-8">
                <div>
                  <h2 className="text-xl font-bold text-slate-900 flex items-center gap-3">
                    <span className="p-2 bg-amber-100 text-amber-600 rounded-xl"><Sliders size={20} /></span>
                    Engine Thresholds
                  </h2>
                  <p className="text-slate-500 text-sm mt-2 ml-12">Configure fine-grained scoring weights and heuristic triggers.</p>
                </div>
                <div className="flex items-center gap-3 ml-12 md:ml-0">
                  <button 
                    onClick={handleResetScoring}
                    className="flex items-center gap-2 px-4 py-2.5 bg-white border border-slate-200 hover:border-slate-300 hover:bg-slate-50 text-slate-700 rounded-xl text-sm font-medium transition-all shadow-sm"
                  >
                    <RotateCcw size={16} />
                    Reset to Defaults
                  </button>
                  <button 
                    onClick={handleSaveScoring}
                    disabled={saving}
                    className="flex items-center gap-2 px-5 py-2.5 bg-slate-900 hover:bg-slate-800 text-white rounded-xl text-sm font-medium transition-colors shadow-sm disabled:opacity-50"
                  >
                    {saving ? <Loader2 size={16} className="animate-spin" /> : <Save size={16} />}
                    Apply Config
                  </button>
                </div>
              </div>

              <div className="grid grid-cols-1 md:grid-cols-2 gap-6 pb-8">
                {/* Section 1: Domain Structure */}
                <div className="p-6 rounded-2xl bg-white border border-slate-100 shadow-sm space-y-5">
                  <h3 className="font-bold text-slate-800 flex items-center gap-2 border-b border-slate-50 pb-3">
                    <Globe size={18} className="text-slate-400" />
                    Domain Structure Analysis
                  </h3>
                  
                  <div className="grid grid-cols-2 gap-4 items-center">
                    <label className="text-sm font-medium text-slate-600">Punycode Penalty</label>
                    <input type="number" className="settings-num-input" value={scoring.punycode_score} onChange={(e) => updateScoringField('punycode_score', parseInt(e.target.value) || 0)} />
                    
                    <label className="text-sm font-medium text-slate-600">Mixed Script Penalty</label>
                    <input type="number" className="settings-num-input" value={scoring.mixed_script_score} onChange={(e) => updateScoringField('mixed_script_score', parseInt(e.target.value) || 0)} />
                    
                    <label className="text-sm font-medium text-slate-600">Long Domain (Chars)</label>
                    <input type="number" className="settings-num-input" value={scoring.long_domain_length} onChange={(e) => updateScoringField('long_domain_length', parseInt(e.target.value) || 0)} />
                    
                    <label className="text-sm font-medium text-slate-600">Long Domain Penalty</label>
                    <input type="number" className="settings-num-input" value={scoring.long_domain_score} onChange={(e) => updateScoringField('long_domain_score', parseInt(e.target.value) || 0)} />
                    
                    <label className="text-sm font-medium text-slate-600">Hyphen Threshold</label>
                    <input type="number" className="settings-num-input" value={scoring.hyphen_count_threshold} onChange={(e) => updateScoringField('hyphen_count_threshold', parseInt(e.target.value) || 0)} />
                    
                    <label className="text-sm font-medium text-slate-600">Hyphen Penalty</label>
                    <input type="number" className="settings-num-input" value={scoring.hyphen_score} onChange={(e) => updateScoringField('hyphen_score', parseInt(e.target.value) || 0)} />
                  </div>
                </div>

                {/* Section 2: Complexity & Keywords */}
                <div className="space-y-6">
                  <div className="p-6 rounded-2xl bg-white border border-slate-100 shadow-sm space-y-5">
                    <h3 className="font-bold text-slate-800 flex items-center gap-2 border-b border-slate-50 pb-3">
                      <Activity size={18} className="text-slate-400" />
                      Entropy & Density
                    </h3>
                    
                    <div className="grid grid-cols-2 gap-4 items-center">
                      <label className="text-sm font-medium text-slate-600">Digit Ratio Threshold</label>
                      <input type="number" step="0.05" className="settings-num-input" value={scoring.digit_ratio_threshold} onChange={(e) => updateScoringField('digit_ratio_threshold', parseFloat(e.target.value) || 0)} />
                      
                      <label className="text-sm font-medium text-slate-600">Digit Ratio Penalty</label>
                      <input type="number" className="settings-num-input" value={scoring.digit_ratio_score} onChange={(e) => updateScoringField('digit_ratio_score', parseInt(e.target.value) || 0)} />
                      
                      <label className="text-sm font-medium text-slate-600">Entropy Threshold</label>
                      <input type="number" step="0.1" className="settings-num-input" value={scoring.entropy_threshold} onChange={(e) => updateScoringField('entropy_threshold', parseFloat(e.target.value) || 0)} />
                      
                      <label className="text-sm font-medium text-slate-600">Entropy Penalty</label>
                      <input type="number" className="settings-num-input" value={scoring.entropy_score} onChange={(e) => updateScoringField('entropy_score', parseInt(e.target.value) || 0)} />
                    </div>
                  </div>

                  <div className="p-6 rounded-2xl bg-white border border-slate-100 shadow-sm space-y-5">
                    <h3 className="font-bold text-slate-800 flex items-center gap-2 border-b border-slate-50 pb-3">
                      <Shield size={18} className="text-slate-400" />
                      Keyword Heuristics
                    </h3>
                    
                    <div className="grid grid-cols-2 gap-4 items-center mb-4">
                      <label className="text-sm font-medium text-slate-600">Keyword Base Score</label>
                      <input type="number" className="settings-num-input" value={scoring.keyword_base_score} onChange={(e) => updateScoringField('keyword_base_score', parseInt(e.target.value) || 0)} />
                      
                      <label className="text-sm font-medium text-slate-600">Match Multiplier</label>
                      <input type="number" className="settings-num-input" value={scoring.keyword_match_score} onChange={(e) => updateScoringField('keyword_match_score', parseInt(e.target.value) || 0)} />
                      
                      <label className="text-sm font-medium text-slate-600">Brand Spoof Penalty</label>
                      <input type="number" className="settings-num-input" value={scoring.brand_spoofing_score} onChange={(e) => updateScoringField('brand_spoofing_score', parseInt(e.target.value) || 0)} />
                    </div>

                    <div>
                      <label className="block text-sm font-medium text-slate-600 mb-2">Suspicious Keywords Dictionary</label>
                      <div className="p-3 bg-slate-50 rounded-xl border border-slate-200 min-h-[100px]">
                        <div className="flex flex-wrap gap-2 mb-3">
                          <AnimatePresence>
                            {scoring.keywords.map(kw => (
                              <motion.span 
                                key={kw} 
                                initial={{ opacity: 0, scale: 0.8 }}
                                animate={{ opacity: 1, scale: 1 }}
                                exit={{ opacity: 0, scale: 0.8 }}
                                className="inline-flex items-center gap-1.5 px-3 py-1 bg-white border border-slate-200 text-slate-700 rounded-lg text-xs font-medium shadow-sm"
                              >
                                {kw}
                                <button onClick={() => handleRemoveKeyword(kw)} className="text-slate-400 hover:text-red-500 focus:outline-none transition-colors">
                                  <X size={14} />
                                </button>
                              </motion.span>
                            ))}
                          </AnimatePresence>
                        </div>
                        <div className="flex items-center gap-2">
                          <Plus size={16} className="text-slate-400 ml-1" />
                          <input 
                            type="text" 
                            className="flex-1 bg-transparent border-none focus:ring-0 text-sm outline-none placeholder:text-slate-400 font-medium text-slate-700" 
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
              </div>
            </motion.div>
          )}

          {/* =========================================
              ACCESS TAB 
          ========================================= */}
          {activeTab === 'ACCESS' && (
            <motion.form 
              key="access"
              onSubmit={handleSaveGuest}
              initial={{ opacity: 0, y: 10 }}
              animate={{ opacity: 1, y: 0 }}
              exit={{ opacity: 0, y: -10 }}
              transition={{ duration: 0.2 }}
              className="flex flex-col h-full"
            >
              <div className="mb-8">
                <h2 className="text-xl font-bold text-slate-900 flex items-center gap-3">
                  <span className="p-2 bg-emerald-100 text-emerald-600 rounded-xl"><Lock size={20} /></span>
                  Guest Access Control
                </h2>
                <p className="text-slate-500 text-sm mt-2 ml-12">Manage read-only access to the dashboard for external viewers.</p>
              </div>

              <div className="max-w-2xl">
                <div className="p-6 rounded-3xl bg-white border border-slate-100 shadow-sm space-y-6">
                  
                  <div className="flex items-center justify-between p-4 bg-slate-50 rounded-2xl border border-slate-100">
                    <div>
                      <h4 className="font-bold text-slate-900">Enable Guest Mode</h4>
                      <p className="text-xs text-slate-500 mt-1">Allows login with username <code className="px-1 py-0.5 bg-slate-200 rounded text-slate-700 font-mono">guest</code></p>
                    </div>
                    
                    <button 
                      type="button"
                      className={`relative inline-flex h-7 w-12 items-center rounded-full transition-colors focus:outline-none ${guest.enabled ? 'bg-emerald-500' : 'bg-slate-300'}`}
                      onClick={() => setGuest(prev => ({ ...prev, enabled: !prev.enabled }))}
                    >
                      <span className={`inline-block h-5 w-5 transform rounded-full bg-white shadow-sm transition-transform ${guest.enabled ? 'translate-x-6' : 'translate-x-1'}`} />
                    </button>
                  </div>

                  <div className="space-y-3">
                    <label className="block text-sm font-semibold text-slate-900">
                      {guest.exists ? 'Reset Guest Password (Optional)' : 'Set Initial Guest Password'}
                    </label>
                    <div className="relative">
                      <input 
                        type={showGuestPassword ? "text" : "password"}
                        value={guestPassword}
                        onChange={(e) => setGuestPassword(e.target.value)}
                        placeholder="Enter password..."
                        className="w-full pl-4 pr-12 py-3 bg-white border border-slate-200 rounded-xl focus:ring-2 focus:ring-emerald-500/20 focus:border-emerald-500 outline-none transition-all text-sm font-mono text-slate-700"
                        autoComplete="new-password"
                      />
                      <button 
                        type="button"
                        className="absolute right-3 top-1/2 -translate-y-1/2 text-slate-400 hover:text-slate-600 p-1.5 rounded-lg hover:bg-slate-100 transition-colors"
                        onClick={() => setShowGuestPassword(!showGuestPassword)}
                      >
                        {showGuestPassword ? <EyeOff size={18} /> : <Eye size={18} />}
                      </button>
                    </div>
                  </div>

                </div>
              </div>

              <div className="mt-10 pt-6 border-t border-slate-200/50">
                <button 
                  type="submit" 
                  disabled={saving}
                  className="flex items-center gap-2 px-6 py-3 bg-emerald-600 hover:bg-emerald-700 text-white rounded-xl font-medium transition-colors disabled:opacity-50 shadow-sm"
                >
                  {saving ? <Loader2 size={18} className="animate-spin" /> : <Save size={18} />}
                  Save Access Controls
                </button>
              </div>
            </motion.form>
          )}

        </AnimatePresence>
      </div>

      {/* Global utility class for scoring number inputs to keep code clean */}
      <style>{`
        .settings-num-input {
          width: 100%;
          padding: 0.5rem 0.75rem;
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
        }
      `}</style>
    </div>
  );
}
