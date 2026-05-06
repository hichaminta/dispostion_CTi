import React, { useState, useEffect } from 'react';
import axios from 'axios';
import {
  Bot, X, Key, Cpu, Globe, CheckCircle2, Loader2,
  Eye, EyeOff, ChevronRight, Zap, AlertTriangle, RefreshCw,
  Activity, DollarSign, Sparkles
} from 'lucide-react';

const API_BASE = `http://${window.location.hostname}:8000`;

const PROVIDERS = [
  { id: 'gemini',     name: 'Google Gemini', description: 'Gemini 1.5 Flash — Gratuit', color: 'from-blue-500/20 to-indigo-500/10 border-blue-500/30', activeColor: 'from-blue-500/30 to-indigo-500/20 border-blue-400/60 shadow-[0_0_20px_rgba(59,130,246,0.15)]', dot: 'bg-blue-400',   icon: '✦' },
  { id: 'openai',     name: 'OpenAI',         description: 'GPT-4o-mini — Précis',       color: 'from-emerald-500/20 to-teal-500/10 border-emerald-500/30', activeColor: 'from-emerald-500/30 to-teal-500/20 border-emerald-400/60 shadow-[0_0_20px_rgba(16,185,129,0.15)]', dot: 'bg-emerald-400', icon: '⬡' },
  { id: 'openrouter', name: 'OpenRouter',     description: 'Multi-modèle + Free tier',  color: 'from-violet-500/20 to-purple-500/10 border-violet-500/30', activeColor: 'from-violet-500/30 to-purple-500/20 border-violet-400/60 shadow-[0_0_20px_rgba(139,92,246,0.15)]', dot: 'bg-violet-400', icon: '◈' },
  { id: 'ollama',     name: 'Ollama',         description: 'Local — Privé & Offline',   color: 'from-orange-500/20 to-amber-500/10 border-orange-500/30', activeColor: 'from-orange-500/30 to-amber-500/20 border-orange-400/60 shadow-[0_0_20px_rgba(249,115,22,0.15)]', dot: 'bg-orange-400', icon: '⬢' },
];

// Grouped OpenRouter models — FREE models marked with ★
const OPENROUTER_MODEL_GROUPS = [
  {
    group: '★ Gratuits (Free)',
    color: 'text-emerald-400',
    models: [
      { id: 'google/gemini-2.0-flash-exp:free',           label: 'Gemini 2.0 Flash Exp — Google' },
      { id: 'google/gemini-flash-1.5-8b:free',            label: 'Gemini 1.5 Flash 8B — Google' },
      { id: 'meta-llama/llama-3.3-70b-instruct:free',     label: 'Llama 3.3 70B — Meta' },
      { id: 'meta-llama/llama-3.1-8b-instruct:free',      label: 'Llama 3.1 8B — Meta' },
      { id: 'meta-llama/llama-3.2-3b-instruct:free',      label: 'Llama 3.2 3B — Meta' },
      { id: 'meta-llama/llama-3.2-1b-instruct:free',      label: 'Llama 3.2 1B — Meta' },
      { id: 'mistralai/mistral-7b-instruct:free',          label: 'Mistral 7B — Mistral AI' },
      { id: 'mistralai/mistral-nemo:free',                 label: 'Mistral Nemo — Mistral AI' },
      { id: 'qwen/qwen-2.5-72b-instruct:free',             label: 'Qwen 2.5 72B — Alibaba' },
      { id: 'qwen/qwen-2.5-7b-instruct:free',              label: 'Qwen 2.5 7B — Alibaba' },
      { id: 'qwen/qwen2.5-vl-7b-instruct:free',            label: 'Qwen 2.5 VL 7B — Alibaba' },
      { id: 'deepseek/deepseek-r1:free',                   label: 'DeepSeek R1 — DeepSeek' },
      { id: 'deepseek/deepseek-chat-v3-0324:free',         label: 'DeepSeek Chat V3 — DeepSeek' },
      { id: 'deepseek/deepseek-prover-v2:free',            label: 'DeepSeek Prover V2 — DeepSeek' },
      { id: 'microsoft/phi-4:free',                        label: 'Phi-4 — Microsoft' },
      { id: 'microsoft/phi-4-reasoning:free',              label: 'Phi-4 Reasoning — Microsoft' },
      { id: 'nvidia/llama-3.1-nemotron-ultra-253b-v1:free',label: 'Nemotron Ultra 253B — NVIDIA' },
      { id: 'openchat/openchat-7b:free',                   label: 'OpenChat 7B — OpenChat' },
      { id: 'huggingfaceh4/zephyr-7b-beta:free',           label: 'Zephyr 7B — HuggingFace' },
    ]
  },
  {
    group: '⬡ OpenAI (Payant)',
    color: 'text-emerald-300',
    models: [
      { id: 'openai/gpt-4o-mini',       label: 'GPT-4o Mini' },
      { id: 'openai/gpt-4o',            label: 'GPT-4o' },
      { id: 'openai/o3-mini',           label: 'o3 Mini' },
    ]
  },
  {
    group: '◆ Anthropic (Payant)',
    color: 'text-orange-300',
    models: [
      { id: 'anthropic/claude-3-haiku',          label: 'Claude 3 Haiku' },
      { id: 'anthropic/claude-3.5-sonnet',       label: 'Claude 3.5 Sonnet' },
      { id: 'anthropic/claude-3.7-sonnet',       label: 'Claude 3.7 Sonnet' },
    ]
  },
  {
    group: '✦ Google (Payant)',
    color: 'text-blue-300',
    models: [
      { id: 'google/gemini-2.0-flash-001',       label: 'Gemini 2.0 Flash' },
      { id: 'google/gemini-2.5-pro-exp-03-25',   label: 'Gemini 2.5 Pro Exp' },
    ]
  },
];

const SecretInput = ({ label, value, onChange, placeholder }) => {
  const [show, setShow] = useState(false);
  return (
    <div>
      <label className="block text-[10px] font-black text-slate-500 uppercase tracking-widest mb-1.5">{label}</label>
      <div className="relative group">
        <Key className="absolute left-3 top-1/2 -translate-y-1/2 w-3.5 h-3.5 text-slate-600 group-focus-within:text-brand-400 transition-colors" />
        <input
          type={show ? 'text' : 'password'}
          value={value}
          onChange={e => onChange(e.target.value)}
          placeholder={placeholder || 'sk-••••••••••••••••••••'}
          className="w-full bg-slate-900/80 border border-slate-700/60 text-white rounded-xl pl-9 pr-10 py-3 text-xs font-mono focus:outline-none focus:border-brand-500/60 focus:ring-2 focus:ring-brand-500/10 transition-all placeholder-slate-700"
        />
        <button type="button" onClick={() => setShow(v => !v)} className="absolute right-3 top-1/2 -translate-y-1/2 text-slate-600 hover:text-slate-300 transition-colors">
          {show ? <EyeOff className="w-3.5 h-3.5" /> : <Eye className="w-3.5 h-3.5" />}
        </button>
      </div>
    </div>
  );
};

const SettingsModal = ({ onClose }) => {
  const [config, setConfig] = useState(null);
  const [loading, setLoading] = useState(true);
  const [saving, setSaving] = useState(false);
  const [saved, setSaved] = useState(false);
  const [error, setError] = useState(null);

  useEffect(() => { fetchSettings(); }, []);

  const fetchSettings = async () => {
    setLoading(true); setError(null);
    try {
      const res = await axios.get(`${API_BASE}/api/settings/ai`);
      setConfig(res.data);
    } catch {
      setError('Impossible de charger les paramètres. Vérifiez que le backend est démarré.');
    } finally { setLoading(false); }
  };

  const handleSave = async () => {
    setSaving(true); setError(null);
    try {
      await axios.post(`${API_BASE}/api/settings/ai`, config);
      setSaved(true);
      setTimeout(() => setSaved(false), 3000);
    } catch (e) {
      setError('Échec de la sauvegarde: ' + (e.response?.data?.detail || e.message));
    } finally { setSaving(false); }
  };

  const activeProvider = PROVIDERS.find(p => p.id === config?.provider) || PROVIDERS[0];

  return (
    <div className="fixed inset-0 z-[200] flex items-center justify-center p-4" onClick={onClose}>
      <div className="absolute inset-0 bg-black/70 backdrop-blur-md" />
      <div
        className="relative z-10 w-full max-w-2xl bg-[#0a0c14] border border-white/10 rounded-3xl shadow-2xl shadow-black/50 overflow-hidden animate-in zoom-in-95 fade-in duration-300"
        onClick={e => e.stopPropagation()}
      >
        {/* Header */}
        <div className="flex items-center justify-between px-8 py-5 border-b border-white/5 bg-slate-900/40">
          <div className="flex items-center gap-3">
            <div className="w-9 h-9 rounded-xl bg-brand-500/20 border border-brand-500/30 flex items-center justify-center shadow-[0_0_15px_rgba(14,165,233,0.2)]">
              <Bot className="w-5 h-5 text-brand-400" />
            </div>
            <div>
              <h2 className="text-base font-black text-white uppercase tracking-wider">Configuration AI</h2>
              <p className="text-[10px] font-mono text-slate-500 uppercase tracking-widest">Leak Intelligence Provider</p>
            </div>
          </div>
          <div className="flex items-center gap-2">
            <button onClick={fetchSettings} className="p-2 text-slate-500 hover:text-slate-300 transition-colors rounded-lg hover:bg-white/5" title="Rafraîchir">
              <RefreshCw className="w-4 h-4" />
            </button>
            <button onClick={onClose} className="p-2 text-slate-500 hover:text-white transition-colors rounded-lg hover:bg-white/5">
              <X className="w-4 h-4" />
            </button>
          </div>
        </div>

        {/* Content */}
        <div className="p-8 overflow-y-auto max-h-[72vh] custom-scrollbar space-y-7">
          {loading ? (
            <div className="flex flex-col items-center justify-center py-16 gap-4">
              <Loader2 className="w-10 h-10 text-brand-400 animate-spin" />
              <p className="text-slate-500 text-xs font-mono uppercase tracking-widest">Chargement...</p>
            </div>
          ) : error ? (
            <div className="flex flex-col items-center justify-center py-12 gap-4">
              <AlertTriangle className="w-10 h-10 text-red-400" />
              <p className="text-red-400 text-sm text-center">{error}</p>
              <button onClick={fetchSettings} className="px-4 py-2 bg-slate-800 hover:bg-slate-700 text-white text-xs rounded-xl font-bold transition-all">Réessayer</button>
            </div>
          ) : config && (<>

            {/* Provider Selection */}
            <div>
              <p className="text-[10px] font-black text-slate-400 uppercase tracking-[0.2em] mb-4 flex items-center gap-2">
                <Cpu className="w-3.5 h-3.5 text-brand-400" /> Choisir le Provider AI
              </p>
              <div className="grid grid-cols-2 gap-3">
                {PROVIDERS.map(prov => (
                  <button
                    key={prov.id}
                    onClick={() => setConfig(c => ({ ...c, provider: prov.id }))}
                    className={`relative flex items-center gap-4 p-4 rounded-2xl border bg-gradient-to-br transition-all duration-300 text-left group ${config.provider === prov.id ? prov.activeColor : prov.color + ' hover:border-white/20'}`}
                  >
                    <div className={`w-9 h-9 rounded-xl flex items-center justify-center font-black text-lg ${config.provider === prov.id ? 'bg-white/15 text-white' : 'bg-white/5 text-slate-500'}`}>
                      {prov.icon}
                    </div>
                    <div className="flex-1 min-w-0">
                      <p className={`text-sm font-black uppercase tracking-tight ${config.provider === prov.id ? 'text-white' : 'text-slate-400'}`}>{prov.name}</p>
                      <p className={`text-[9px] font-medium mt-0.5 truncate ${config.provider === prov.id ? 'text-slate-300' : 'text-slate-600'}`}>{prov.description}</p>
                    </div>
                    {config.provider === prov.id && (
                      <div className="absolute top-2 right-2">
                        <div className={`w-2 h-2 rounded-full ${prov.dot} animate-pulse`} />
                      </div>
                    )}
                  </button>
                ))}
              </div>
            </div>

            <div className="h-px bg-white/5" />

            {/* Provider Fields */}
            <div className="space-y-5">
              <p className="text-[10px] font-black text-slate-400 uppercase tracking-[0.2em] flex items-center gap-2">
                <Key className="w-3.5 h-3.5 text-brand-400" /> Configuration {activeProvider.name}
              </p>

              {config.provider === 'gemini' && (
                <SecretInput label="Gemini API Key" value={config.gemini_api_key} onChange={v => setConfig(c => ({ ...c, gemini_api_key: v }))} placeholder="AIza••••••••••••••••••••••••••••••••••" />
              )}

              {config.provider === 'openai' && (
                <SecretInput label="OpenAI API Key" value={config.openai_api_key} onChange={v => setConfig(c => ({ ...c, openai_api_key: v }))} placeholder="sk-••••••••••••••••••••••••••••••••••••" />
              )}

              {config.provider === 'openrouter' && (
                <div className="space-y-4">
                  <SecretInput label="OpenRouter API Key" value={config.openrouter_api_key} onChange={v => setConfig(c => ({ ...c, openrouter_api_key: v }))} placeholder="sk-or-v1-••••••••••••••••••••••••••••••" />

                  {/* Model selector grouped */}
                  <div>
                    <label className="block text-[10px] font-black text-slate-500 uppercase tracking-widest mb-1.5 flex items-center gap-2">
                      <Sparkles className="w-3 h-3 text-violet-400" /> Modèle OpenRouter
                    </label>
                    <div className="relative">
                      <Globe className="absolute left-3 top-1/2 -translate-y-1/2 w-3.5 h-3.5 text-slate-600 pointer-events-none" />
                      <select
                        value={config.openrouter_model}
                        onChange={e => setConfig(c => ({ ...c, openrouter_model: e.target.value }))}
                        className="w-full bg-slate-900/80 border border-slate-700/60 text-white rounded-xl pl-9 pr-4 py-3 text-xs font-mono focus:outline-none focus:border-brand-500/60 transition-all appearance-none cursor-pointer"
                      >
                        {OPENROUTER_MODEL_GROUPS.map(grp => (
                          <optgroup key={grp.group} label={grp.group}>
                            {grp.models.map(m => (
                              <option key={m.id} value={m.id}>{m.label}</option>
                            ))}
                          </optgroup>
                        ))}
                      </select>
                      <ChevronRight className="absolute right-3 top-1/2 -translate-y-1/2 w-3.5 h-3.5 text-slate-600 rotate-90 pointer-events-none" />
                    </div>
                    {/* Show current selected */}
                    <p className="text-[9px] text-violet-400/70 font-mono mt-1.5 ml-1">
                      ▸ {config.openrouter_model}
                    </p>
                    {/* Custom model input */}
                    <input
                      type="text"
                      value={config.openrouter_model}
                      onChange={e => setConfig(c => ({ ...c, openrouter_model: e.target.value }))}
                      placeholder="ou entrez un modèle personnalisé: provider/model-name"
                      className="w-full mt-2 bg-slate-900/60 border border-slate-800 text-slate-300 rounded-xl px-3 py-2 text-xs font-mono focus:outline-none focus:border-brand-500/40 transition-all"
                    />
                  </div>

                </div>
              )}

              {config.provider === 'ollama' && (
                <div className="space-y-4">
                  <div>
                    <label className="block text-[10px] font-black text-slate-500 uppercase tracking-widest mb-1.5">URL Ollama</label>
                    <input type="text" value={config.ollama_url} onChange={e => setConfig(c => ({ ...c, ollama_url: e.target.value }))}
                      placeholder="http://localhost:11434/api/generate"
                      className="w-full bg-slate-900/80 border border-slate-700/60 text-white rounded-xl px-4 py-3 text-xs font-mono focus:outline-none focus:border-brand-500/60 transition-all" />
                  </div>
                  <div>
                    <label className="block text-[10px] font-black text-slate-500 uppercase tracking-widest mb-1.5">Modèle Ollama</label>
                    <input type="text" value={config.ollama_model} onChange={e => setConfig(c => ({ ...c, ollama_model: e.target.value }))}
                      placeholder="qwen2.5-coder:1.5b"
                      className="w-full bg-slate-900/80 border border-slate-700/60 text-white rounded-xl px-4 py-3 text-xs font-mono focus:outline-none focus:border-brand-500/60 transition-all" />
                  </div>
                  <div className="bg-orange-500/10 border border-orange-500/20 rounded-xl p-3">
                    <p className="text-[10px] text-orange-400">⚠ Assurez-vous qu'Ollama est en cours d'exécution avant de lancer une analyse.</p>
                  </div>
                </div>
              )}
            </div>

            {error && (
              <div className="bg-red-500/10 border border-red-500/30 rounded-xl p-4">
                <p className="text-red-400 text-xs">{error}</p>
              </div>
            )}
          </>)}
        </div>

        {/* Footer */}
        {!loading && !error && config && (
          <div className="flex items-center justify-between px-8 py-5 border-t border-white/5 bg-slate-900/20">
            <div className="flex items-center gap-2">
              <div className={`w-2 h-2 rounded-full ${activeProvider.dot} animate-pulse`} />
              <span className="text-[10px] font-mono text-slate-500 uppercase tracking-widest">
                Active: <span className="text-white font-black">{activeProvider.name}</span>
              </span>
            </div>
            <div className="flex items-center gap-3">
              <button onClick={onClose} className="px-5 py-2.5 rounded-xl text-slate-400 hover:text-white text-xs font-black uppercase tracking-widest transition-all hover:bg-white/5">
                Annuler
              </button>
              <button
                onClick={handleSave}
                disabled={saving}
                className={`flex items-center gap-2 px-6 py-2.5 rounded-xl text-xs font-black uppercase tracking-widest transition-all active:scale-95 shadow-lg ${saved ? 'bg-emerald-500 text-white' : 'bg-gradient-to-r from-brand-600 to-indigo-600 hover:from-brand-500 hover:to-indigo-500 text-white disabled:opacity-50'}`}
              >
                {saving ? <Loader2 className="w-3.5 h-3.5 animate-spin" /> : saved ? <CheckCircle2 className="w-3.5 h-3.5" /> : <Zap className="w-3.5 h-3.5" />}
                {saving ? 'Sauvegarde...' : saved ? 'Sauvegardé !' : 'Sauvegarder'}
              </button>
            </div>
          </div>
        )}

        <style>{`
          .custom-scrollbar::-webkit-scrollbar { width: 4px; }
          .custom-scrollbar::-webkit-scrollbar-track { background: rgba(255,255,255,0.02); border-radius: 10px; }
          .custom-scrollbar::-webkit-scrollbar-thumb { background: rgba(14,165,233,0.15); border-radius: 10px; }
          .custom-scrollbar::-webkit-scrollbar-thumb:hover { background: rgba(14,165,233,0.3); }
        `}</style>
      </div>
    </div>
  );
};

export default SettingsModal;
