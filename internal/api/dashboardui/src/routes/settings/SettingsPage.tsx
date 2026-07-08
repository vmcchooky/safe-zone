import { useState, useEffect, FormEvent } from 'react';
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
  Info
} from 'lucide-react';
import './SettingsPage.css';

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

      // Set Core Settings
      setGeminiKey(data.settings.gemini_api_key || '');
      setWebhookUrl(data.settings.agent_webhook_url || '');
      setRetentionDays(data.settings.telemetry_retention_days || 30);

      // Set Scoring Engine Config
      if (data.analysis_config) {
        setScoring(data.analysis_config);
      }

      // Set Guest Access status
      if (data.guest_access) {
        setGuest(data.guest_access);
      }

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
      loadSettings(); // Reload to refresh masked values
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
    if (!window.confirm('Are you sure you want to reset all scoring thresholds to default?')) return;
    setSaving(true);
    try {
      const res = await fetch('/v1/config/analysis/reset', {
        method: 'POST'
      });

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
      const payload: Record<string, any> = {
        enabled: guest.enabled
      };
      if (guestPassword) {
        payload.password = guestPassword;
      }

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
      if (data.status === 'ok') {
        showToast('Gemini API test connection success!', 'ok');
      } else {
        showToast(`AI Test failed: ${data.message || 'Check API Key'}`, 'err');
      }
    } catch (err) {
      showToast('Error sending API request to AI test endpoint', 'err');
    } finally {
      setTestingAi(false);
    }
  };

  const handleTestAlert = async () => {
    setTestingAlert(true);
    try {
      const res = await fetch('/v1/settings/test-alert', { method: 'POST' });
      if (res.ok) {
        showToast('Test alert triggered successfully!', 'ok');
      } else {
        const err = await res.json();
        showToast(`Alert Test failed: ${err.error || 'Check configurations'}`, 'err');
      }
    } catch (err) {
      showToast('Error triggering test alert', 'err');
    } finally {
      setTestingAlert(false);
    }
  };

  const handleAddKeyword = () => {
    const kw = newKeyword.trim().toLowerCase();
    if (!kw) return;
    if (scoring.keywords.includes(kw)) {
      showToast('Keyword already exists in config', 'err');
      return;
    }
    setScoring(prev => ({
      ...prev,
      keywords: [...prev.keywords, kw]
    }));
    setNewKeyword('');
  };

  const handleRemoveKeyword = (kw: string) => {
    setScoring(prev => ({
      ...prev,
      keywords: prev.keywords.filter(k => k !== kw)
    }));
  };

  const updateScoringField = (field: keyof AnalysisConfig, val: any) => {
    setScoring(prev => ({
      ...prev,
      [field]: val
    }));
  };

  if (loading) {
    return (
      <div style={{ height: '70vh', display: 'flex', alignItems: 'center', justifyContent: 'center' }}>
        <Loader2 size={32} className="animate-spin" color="rgba(255, 255, 255, 0.2)" />
      </div>
    );
  }

  return (
    <div className="settings-container">
      {/* Toast container */}
      <div className="toast-container">
        {toasts.map(t => (
          <div key={t.id} className={`toast-item ${t.type}`}>
            {t.type === 'ok' ? <Check size={18} /> : <AlertCircle size={18} />}
            <span>{t.message}</span>
          </div>
        ))}
      </div>

      {/* Tabs */}
      <div className="settings-tab-bar">
        <button 
          className={`settings-tab-btn ${activeTab === 'CORE' ? 'active' : ''}`}
          onClick={() => setActiveTab('CORE')}
        >
          <Key size={16} />
          Core Integrations
        </button>
        <button 
          className={`settings-tab-btn ${activeTab === 'SCORING' ? 'active' : ''}`}
          onClick={() => setActiveTab('SCORING')}
        >
          <Sliders size={16} />
          Scoring Engine
        </button>
        <button 
          className={`settings-tab-btn ${activeTab === 'ACCESS' ? 'active' : ''}`}
          onClick={() => setActiveTab('ACCESS')}
        >
          <Users size={16} />
          Access Control
        </button>
      </div>

      {/* Panels */}
      <AnimatePresence mode="wait">
        {activeTab === 'CORE' && (
          <motion.form 
            key="core"
            className="settings-panel"
            onSubmit={handleSaveCore}
            initial={{ opacity: 0, y: 15 }}
            animate={{ opacity: 1, y: 0 }}
            exit={{ opacity: 0, y: -15 }}
            transition={{ duration: 0.15 }}
          >
            <div className="settings-panel-header">
              <h3>Core Integrations</h3>
              <p>Configure threat intelligence API keys and incident response integrations.</p>
            </div>

            <div className="settings-form-grid">
              <div className="settings-form-group full-width">
                <div className="settings-label-row">
                  <label className="settings-label" htmlFor="gemini-key">Gemini AI Client API Key</label>
                  <div className="settings-tooltip-wrapper">
                    <Info size={14} className="settings-tooltip-trigger" />
                    <div className="settings-tooltip-content">
                      Used by AI classifier node to enrich and confirm domain risk dossiers.
                    </div>
                  </div>
                </div>
                <div className="settings-input-wrapper">
                  <input 
                    id="gemini-key"
                    className="settings-input"
                    type={showApiKey && !geminiKey.includes('*') ? "text" : "password"}
                    value={geminiKey}
                    onChange={(e) => setGeminiKey(e.target.value)}
                    placeholder="Enter Google Gemini API Key"
                    autoComplete="off"
                    onCopy={(e) => e.preventDefault()}
                    onCut={(e) => e.preventDefault()}
                    onDragStart={(e) => e.preventDefault()}
                  />
                  <div className="settings-input-icon" onClick={() => setShowApiKey(!showApiKey)}>
                    {showApiKey && !geminiKey.includes('*') ? <EyeOff size={16} /> : <Eye size={16} />}
                  </div>
                </div>
              </div>

              <div className="settings-form-group full-width">
                <div className="integration-status-box">
                  <div className="integration-status-left">
                    <Check size={16} className="text-green" />
                    <span className="integration-status-text">Integrations Health Check</span>
                  </div>
                  <button 
                    type="button" 
                    className="settings-btn secondary"
                    onClick={handleTestAi}
                    disabled={testingAi}
                  >
                    {testingAi ? <Loader2 size={14} className="animate-spin" /> : <Play size={14} />}
                    Test AI Client Connection
                  </button>
                </div>
              </div>

              <div className="settings-form-group full-width">
                <div className="settings-label-row">
                  <label className="settings-label" htmlFor="webhook-url">Incident Agent Webhook URL</label>
                  <div className="settings-tooltip-wrapper">
                    <Info size={14} className="settings-tooltip-trigger" />
                    <div className="settings-tooltip-content">
                      Endpoint to send instant alert payloads when suspicious activity or critical threats are blocked.
                    </div>
                  </div>
                </div>
                <div className="settings-input-wrapper">
                  <input 
                    id="webhook-url"
                    className="settings-input"
                    type={showWebhook && !webhookUrl.includes('*') ? "text" : "password"}
                    value={webhookUrl}
                    onChange={(e) => setWebhookUrl(e.target.value)}
                    placeholder="https://hooks.slack.com/services/..."
                    autoComplete="off"
                    onCopy={(e) => e.preventDefault()}
                    onCut={(e) => e.preventDefault()}
                    onDragStart={(e) => e.preventDefault()}
                  />
                  <div className="settings-input-icon" onClick={() => setShowWebhook(!showWebhook)}>
                    {showWebhook && !webhookUrl.includes('*') ? <EyeOff size={16} /> : <Eye size={16} />}
                  </div>
                </div>
              </div>

              <div className="settings-form-group full-width">
                <div className="integration-status-box">
                  <div className="integration-status-left">
                    <Bell size={16} className="text-blue" />
                    <span className="integration-status-text">Webhooks Channel Trigger</span>
                  </div>
                  <button 
                    type="button" 
                    className="settings-btn secondary"
                    onClick={handleTestAlert}
                    disabled={testingAlert}
                  >
                    {testingAlert ? <Loader2 size={14} className="animate-spin" /> : <Play size={14} />}
                    Send Test Alert payload
                  </button>
                </div>
              </div>

              <div className="settings-form-group">
                <div className="settings-label-row">
                  <label className="settings-label" htmlFor="retention">Telemetry Log Retention (Days)</label>
                  <div className="settings-tooltip-wrapper">
                    <Info size={14} className="settings-tooltip-trigger" />
                    <div className="settings-tooltip-content">
                      System telemetry logs older than this threshold will be pruned automatically.
                    </div>
                  </div>
                </div>
                <input 
                  id="retention"
                  className="settings-input"
                  type="number"
                  min={1}
                  max={90}
                  value={retentionDays}
                  onChange={(e) => setRetentionDays(parseInt(e.target.value) || 30)}
                />
              </div>
            </div>

            <div className="settings-action-row">
              <button type="submit" className="settings-btn primary" disabled={saving}>
                {saving ? <Loader2 size={16} className="animate-spin" /> : <Save size={16} />}
                Save Integrations Configuration
              </button>
            </div>
          </motion.form>
        )}

        {activeTab === 'SCORING' && (
          <motion.div 
            key="scoring"
            className="settings-panel"
            initial={{ opacity: 0, y: 15 }}
            animate={{ opacity: 1, y: 0 }}
            exit={{ opacity: 0, y: -15 }}
            transition={{ duration: 0.15 }}
          >
            <div className="settings-panel-header">
              <h3>Scoring Engine Thresholds</h3>
              <p>Configure fine-grained scoring weights and triggers for the threat inspection engine.</p>
            </div>

            <div className="settings-form-grid">
              <div className="settings-form-group">
                <label className="settings-label">Punycode Penalty Score</label>
                <input 
                  className="settings-input"
                  type="number"
                  value={scoring.punycode_score}
                  onChange={(e) => updateScoringField('punycode_score', parseInt(e.target.value) || 0)}
                />
              </div>

              <div className="settings-form-group">
                <label className="settings-label">Mixed Script Score</label>
                <input 
                  className="settings-input"
                  type="number"
                  value={scoring.mixed_script_score}
                  onChange={(e) => updateScoringField('mixed_script_score', parseInt(e.target.value) || 0)}
                />
              </div>

              <div className="settings-form-group">
                <label className="settings-label">Long Domain Threshold (Length)</label>
                <input 
                  className="settings-input"
                  type="number"
                  value={scoring.long_domain_length}
                  onChange={(e) => updateScoringField('long_domain_length', parseInt(e.target.value) || 0)}
                />
              </div>

              <div className="settings-form-group">
                <label className="settings-label">Long Domain Penalty Score</label>
                <input 
                  className="settings-input"
                  type="number"
                  value={scoring.long_domain_score}
                  onChange={(e) => updateScoringField('long_domain_score', parseInt(e.target.value) || 0)}
                />
              </div>

              <div className="settings-form-group">
                <label className="settings-label">Hyphen Count Threshold</label>
                <input 
                  className="settings-input"
                  type="number"
                  value={scoring.hyphen_count_threshold}
                  onChange={(e) => updateScoringField('hyphen_count_threshold', parseInt(e.target.value) || 0)}
                />
              </div>

              <div className="settings-form-group">
                <label className="settings-label">Hyphen Penalty Score</label>
                <input 
                  className="settings-input"
                  type="number"
                  value={scoring.hyphen_score}
                  onChange={(e) => updateScoringField('hyphen_score', parseInt(e.target.value) || 0)}
                />
              </div>

              <div className="settings-form-group">
                <label className="settings-label">Digit Ratio Threshold (0.0 - 1.0)</label>
                <input 
                  className="settings-input"
                  type="number"
                  step="0.05"
                  value={scoring.digit_ratio_threshold}
                  onChange={(e) => updateScoringField('digit_ratio_threshold', parseFloat(e.target.value) || 0)}
                />
              </div>

              <div className="settings-form-group">
                <label className="settings-label">Digit Ratio Penalty Score</label>
                <input 
                  className="settings-input"
                  type="number"
                  value={scoring.digit_ratio_score}
                  onChange={(e) => updateScoringField('digit_ratio_score', parseInt(e.target.value) || 0)}
                />
              </div>

              <div className="settings-form-group">
                <label className="settings-label">Entropy Threshold (0.0 - 8.0)</label>
                <input 
                  className="settings-input"
                  type="number"
                  step="0.1"
                  value={scoring.entropy_threshold}
                  onChange={(e) => updateScoringField('entropy_threshold', parseFloat(e.target.value) || 0)}
                />
              </div>

              <div className="settings-form-group">
                <label className="settings-label">Entropy Penalty Score</label>
                <input 
                  className="settings-input"
                  type="number"
                  value={scoring.entropy_score}
                  onChange={(e) => updateScoringField('entropy_score', parseInt(e.target.value) || 0)}
                />
              </div>

              <div className="settings-form-group">
                <label className="settings-label">Brand Spoofing Base Score</label>
                <input 
                  className="settings-input"
                  type="number"
                  value={scoring.brand_spoofing_score}
                  onChange={(e) => updateScoringField('brand_spoofing_score', parseInt(e.target.value) || 0)}
                />
              </div>

              <div className="settings-form-group">
                <label className="settings-label">Keyword Match Base Score</label>
                <input 
                  className="settings-input"
                  type="number"
                  value={scoring.keyword_base_score}
                  onChange={(e) => updateScoringField('keyword_base_score', parseInt(e.target.value) || 0)}
                />
              </div>

              <div className="settings-form-group">
                <label className="settings-label">Keyword Multiple Match Bonus</label>
                <input 
                  className="settings-input"
                  type="number"
                  value={scoring.keyword_multiple_bonus}
                  onChange={(e) => updateScoringField('keyword_multiple_bonus', parseInt(e.target.value) || 0)}
                />
              </div>

              <div className="settings-form-group">
                <label className="settings-label">Keyword Penalty Score</label>
                <input 
                  className="settings-input"
                  type="number"
                  value={scoring.keyword_match_score}
                  onChange={(e) => updateScoringField('keyword_match_score', parseInt(e.target.value) || 0)}
                />
              </div>

              <div className="settings-form-group full-width">
                <label className="settings-label">Keyword Lexicons Manager</label>
                <div className="keyword-tag-container">
                  <AnimatePresence>
                    {scoring.keywords.map(kw => (
                      <motion.span 
                        key={kw} 
                        className="keyword-tag"
                        initial={{ opacity: 0, scale: 0.8, filter: "blur(4px)" }}
                        animate={{ opacity: 1, scale: 1, filter: "blur(0px)" }}
                        exit={{ opacity: 0, scale: 0.8, filter: "blur(4px)" }}
                        transition={{ duration: 0.15 }}
                      >
                        {kw}
                        <X size={12} className="keyword-tag-remove" onClick={() => handleRemoveKeyword(kw)} />
                      </motion.span>
                    ))}
                  </AnimatePresence>
                  {scoring.keywords.length === 0 && (
                    <span style={{ fontSize: '13px', color: '#94a3b8', alignSelf: 'center' }}>No keywords configured.</span>
                  )}
                </div>
                <div className="keyword-input-row" style={{ marginTop: '8px' }}>
                  <input 
                    className="settings-input"
                    style={{ flex: 1 }}
                    placeholder="Add new keyword..."
                    value={newKeyword}
                    onChange={(e) => setNewKeyword(e.target.value)}
                    onKeyDown={(e) => { if (e.key === 'Enter') { handleAddKeyword(); e.preventDefault(); } }}
                  />
                  <button type="button" className="settings-btn secondary" onClick={handleAddKeyword}>
                    <Plus size={16} /> Add
                  </button>
                </div>
              </div>
            </div>

            <div className="settings-action-row">
              <button type="button" className="settings-btn danger" style={{ marginRight: 'auto' }} onClick={handleResetScoring} disabled={saving}>
                <RotateCcw size={16} />
                Reset Defaults
              </button>
              <button type="button" className="settings-btn primary" onClick={handleSaveScoring} disabled={saving}>
                {saving ? <Loader2 size={16} className="animate-spin" /> : <Save size={16} />}
                Save Engine Configuration
              </button>
            </div>
          </motion.div>
        )}

        {activeTab === 'ACCESS' && (
          <motion.form 
            key="access"
            className="settings-panel"
            onSubmit={handleSaveGuest}
            initial={{ opacity: 0, y: 15 }}
            animate={{ opacity: 1, y: 0 }}
            exit={{ opacity: 0, y: -15 }}
            transition={{ duration: 0.15 }}
          >
            <div className="settings-panel-header">
              <h3>Access Control Configuration</h3>
              <p>Configure credentials and status settings for the guest dashboard user account.</p>
            </div>

            <div className="settings-form-grid">
              <div className="settings-form-group full-width">
                <div className="settings-label-row">
                  <label className="switch-label">
                    <input 
                      type="checkbox" 
                      className="switch-input"
                      checked={guest.enabled}
                      onChange={(e) => setGuest(prev => ({ ...prev, enabled: e.target.checked }))}
                    />
                    <div className="switch-slider" />
                    <span className="settings-label" style={{ fontSize: '14px' }}>Enable Guest Account Access</span>
                  </label>
                  <div className="settings-tooltip-wrapper">
                    <Info size={14} className="settings-tooltip-trigger" />
                    <div className="settings-tooltip-content">
                      Allows secondary operators to view telemetry charts, verdicts and audit summaries in read-only mode without full administrator privileges.
                    </div>
                  </div>
                </div>
              </div>

              <div className="settings-form-group">
                <div className="settings-label-row">
                  <label className="settings-label">Guest Username</label>
                  <div className="settings-tooltip-wrapper">
                    <Info size={14} className="settings-tooltip-trigger" />
                    <div className="settings-tooltip-content">
                      Standard system username designated for guest logins.
                    </div>
                  </div>
                </div>
                <input 
                  className="settings-input"
                  type="text"
                  value={guest.username || 'guest'}
                  disabled
                />
              </div>

              <div className="settings-form-group">
                <div className="settings-label-row">
                  <label className="settings-label" htmlFor="guest-pwd">Update Guest Password</label>
                  <div className="settings-tooltip-wrapper">
                    <Info size={14} className="settings-tooltip-trigger" />
                    <div className="settings-tooltip-content">
                      {guest.exists 
                        ? 'Leave empty to retain the current password. Enter a new password to change it.'
                        : 'Configure a strong password to initialize the guest login account.'
                      }
                    </div>
                  </div>
                </div>
                <div className="settings-input-wrapper">
                  <input 
                    id="guest-pwd"
                    className="settings-input"
                    type={showGuestPassword ? "text" : "password"}
                    value={guestPassword}
                    onChange={(e) => setGuestPassword(e.target.value)}
                    placeholder={guest.exists ? "•••••••• (Password configured)" : "Set new guest password"}
                    autoComplete="off"
                    onCopy={(e) => e.preventDefault()}
                    onCut={(e) => e.preventDefault()}
                    onDragStart={(e) => e.preventDefault()}
                  />
                  <div className="settings-input-icon" onClick={() => setShowGuestPassword(!showGuestPassword)}>
                    {showGuestPassword ? <EyeOff size={16} /> : <Eye size={16} />}
                  </div>
                </div>
              </div>
            </div>

            <div className="settings-action-row">
              <button type="submit" className="settings-btn primary" disabled={saving}>
                {saving ? <Loader2 size={16} className="animate-spin" /> : <Save size={16} />}
                Update Guest Credentials
              </button>
            </div>
          </motion.form>
        )}
      </AnimatePresence>
    </div>
  );
}
