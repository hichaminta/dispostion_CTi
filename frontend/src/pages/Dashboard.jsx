import React, { useState, useEffect } from 'react';
import axios from 'axios';
import logo from '../assets/logo.png';
import {
  Play, Shield, Activity, Clock, FileText,
  Database, AlertTriangle, CheckCircle2, Loader2, Zap, Sparkles, Square
} from 'lucide-react';
import { format } from 'date-fns';

const API_BASE = "http://localhost:8000";
const WS_BASE  = "ws://localhost:8000/ws";

const SOURCES = [
  { id: 'abuseipdb',    name: 'AbuseIPDB',       type: 'IP Reputation',    color: 'blue'   },
//   { id: 'alienvault',   name: 'AlienVault OTX',  type: 'Threat Feeds',     color: 'purple' },
  { id: 'cins_army',    name: 'CINS Army',        type: 'IP Blocking',      color: 'red'    },
  { id: 'feodotracker', name: 'FeodoTracker',     type: 'Botnet C2',        color: 'orange' },
  { id: 'malwarebazaar',name: 'MalwareBazaar',    type: 'Malware Samples',  color: 'pink'   },
  { id: 'nvd',          name: 'NVD',              type: 'CVE Only',         color: 'yellow' },
  { id: 'openphish',    name: 'OpenPhish',        type: 'Phishing URLs',    color: 'cyan'   },
  { id: 'phishtank',    name: 'PhishTank',        type: 'Phishing URLs',    color: 'teal'   },
  { id: 'pulsedive',    name: 'PulseDive',        type: 'Community CTI',    color: 'indigo' },
  { id: 'spamhaus',     name: 'Spamhaus',         type: 'Drop List',        color: 'green'  },
  { id: 'threatfox',    name: 'ThreatFox',        type: 'IOC Sharing',      color: 'rose'   },
  { id: 'urlhaus',      name: 'URLhaus',          type: 'Malicious URLs',   color: 'amber'  },
  { id: 'virustotal',   name: 'VirusTotal',       type: 'Multi-engine Scan',color: 'violet' },
];

const COLOR_CLASSES = {
  blue:   'bg-blue-500/10 border-blue-500/30 text-blue-400 hover:bg-blue-500/20',
  purple: 'bg-purple-500/10 border-purple-500/30 text-purple-400 hover:bg-purple-500/20',
  red:    'bg-red-500/10 border-red-500/30 text-red-400 hover:bg-red-500/20',
  orange: 'bg-orange-500/10 border-orange-500/30 text-orange-400 hover:bg-orange-500/20',
  pink:   'bg-pink-500/10 border-pink-500/30 text-pink-400 hover:bg-pink-500/20',
  yellow: 'bg-yellow-500/10 border-yellow-500/30 text-yellow-400 hover:bg-yellow-500/20',
  cyan:   'bg-cyan-500/10 border-cyan-500/30 text-cyan-400 hover:bg-cyan-500/20',
  teal:   'bg-teal-500/10 border-teal-500/30 text-teal-400 hover:bg-teal-500/20',
  indigo: 'bg-indigo-500/10 border-indigo-500/30 text-indigo-400 hover:bg-indigo-500/20',
  green:  'bg-emerald-500/10 border-emerald-500/30 text-emerald-400 hover:bg-emerald-500/20',
  rose:   'bg-rose-500/10 border-rose-500/30 text-rose-400 hover:bg-rose-500/20',
  amber:  'bg-amber-500/10 border-amber-500/30 text-amber-400 hover:bg-amber-500/20',
  violet: 'bg-violet-500/10 border-violet-500/30 text-violet-400 hover:bg-violet-500/20',
};

const Dashboard = ({ onSelectRun }) => {
  const [runs,           setRuns]           = useState([]);
  const [stats,          setStats]          = useState(null);
  const [loading,        setLoading]        = useState(true);
  const [stopping,       setStopping]       = useState(false);
  const [runningSources, setRunningSources] = useState(new Set());

  useEffect(() => {
    fetchAll();
    const interval = setInterval(fetchAll, 5000);

    // WebSocket pour mises à jour temps réel des sources
    const ws = new WebSocket(WS_BASE);
    ws.onmessage = (evt) => {
      try {
        const data = JSON.parse(evt.data);
        if (data.type === "source_activity") {
          setRunningSources(prev => {
            const next = new Set(prev);
            if (data.active) next.add(data.source_id);
            else next.delete(data.source_id);
            return next;
          });
        }
      } catch (e) {
        console.error("WS parse error:", e);
      }
    };

    return () => {
      clearInterval(interval);
      ws.close();
    };
  }, []);

  const fetchAll = async () => {
    // Appel des runs (bloquant pour le dashboard principal)
    try {
      const runsRes = await axios.get(`${API_BASE}/runs`);
      setRuns(runsRes.data);
    } catch (e) {
      console.error("Fetch runs error:", e);
    }

    // Appel des stats (optionnel, ne doit pas bloquer)
    try {
      const statsRes = await axios.get(`${API_BASE}/stats`);
      setStats(statsRes.data);
    } catch (e) {
      console.error("Fetch stats error:", e);
      setStats({ total_ioc: 0, total_cve: 0, total_runs: 0, success_runs: 0, avg_duration_sec: 0 });
    } finally {
      setLoading(false);
    }
  };

  const startRun = async (source = null) => {
    const sourceName = source ? source.name : "Unified Extraction";
    const sourceType = source ? source.type : "All Sources";

    if (source) setRunningSources(prev => new Set([...prev, source.id]));

    try {
      const res = await axios.post(`${API_BASE}/runs`, { source_name: sourceName, source_type: sourceType });
      
      // Navigation immédiate vers le terminal pour montrer l'activité
      if (res.data && res.data.id) {
        onSelectRun(res.data.id);
      }
      
      fetchAll();
    } catch (e) {
      console.error("Error starting run:", e);
    }
  };

  const startEnrichment = async (source) => {
    if (source.id === 'nvd' || source.id === 'alienvault') return;
    
    setRunningSources(prev => new Set([...prev, source.id]));
    try {
      const res = await axios.post(`${API_BASE}/runs/enrich`, { 
        source_name: source.name, 
        source_type: source.type 
      });
      if (res.data && res.data.id) {
        onSelectRun(res.data.id);
      }
      fetchAll();
    } catch (e) {
      console.error("Error starting enrichment:", e);
    }
  };

  const startTargetedRun = async (source, stepName) => {
    setRunningSources(prev => new Set([...prev, source.id]));
    try {
      const res = await axios.post(`${API_BASE}/runs/targeted`, { 
        source_name: source.name, 
        source_type: source.type 
      }, { params: { step_name: stepName } });
      
      if (res.data && res.data.id) {
        onSelectRun(res.data.id);
      }
      fetchAll();
    } catch (e) {
      console.error("Error starting targeted run:", e);
    }
  };

  const stopRun = async () => {
    const activeRun = runs.find(r => r.status_global === "running");
    if (!activeRun) return;
    setStopping(true);
    try {
      await axios.post(`${API_BASE}/runs/${activeRun.id}/stop`);
      setTimeout(fetchAll, 1000);
    } catch (e) {
      console.error("Error stopping run:", e);
    } finally {
      setStopping(false);
    }
  };

  const clearHistory = async () => {
    if (!window.confirm("\u00cates-vous s\u00fbr de vouloir vider tout l'historique ? Cette action est irr\u00e9versible.")) return;
    try {
      await axios.delete(`${API_BASE}/runs`);
      await fetchAll();
    } catch (e) {
      console.error("Error clearing history:", e);
    }
  };

  const fmtNum = (n) => {
    if (n === undefined || n === null) return '—';
    if (n >= 1_000_000) return (n / 1_000_000).toFixed(1) + 'M';
    if (n >= 1_000)     return (n / 1_000).toFixed(1) + 'k';
    return String(n);
  };

  const fmtDuration = (sec) => {
    if (!sec) return '—';
    if (sec < 60) return `${sec}s`;
    return `${Math.round(sec / 60)}m`;
  };

  const latestRun = runs.length > 0 ? runs[0] : null;

  return (
    <div className="min-h-screen bg-[#0a0d1a] p-6 md:p-8">
      <div className="max-w-[1600px] mx-auto">

        {/* ── Header ─────────────────────────────────────────────────── */}
        <div className="flex flex-col md:flex-row md:items-center justify-between gap-4 mb-10">
          <div className="flex flex-col items-start gap-2">
            <img src={logo} alt="BlueSec Logo" className="h-6 w-auto object-contain" />
            <div className="flex items-center gap-2 mt-1">
              <span className="w-2 h-2 bg-emerald-500 rounded-full animate-pulse" />
              <p className="text-slate-400 text-sm font-medium tracking-wide uppercase text-[10px]">Threat intelligence — monitoring temps réel</p>
            </div>
          </div>
          <div className="flex items-center gap-3">
            {stats?.running_runs > 0 && (
              <button
                onClick={stopRun}
                disabled={stopping}
                className="flex items-center gap-2 bg-red-500/10 hover:bg-red-500/20 text-red-400 border border-red-500/30 px-6 py-3 rounded-xl font-semibold transition-all shadow-lg active:scale-95 disabled:opacity-50"
              >
                {stopping ? <Loader2 className="w-5 h-5 animate-spin" /> : <Square className="w-5 h-5 fill-current" />}
                <span>{stopping ? "Arrêt..." : "Arrêter le Pipeline"}</span>
              </button>
            )}
            <button
              onClick={() => startRun()}
              disabled={stats?.running_runs > 0}
              className={`flex items-center gap-2 px-6 py-3 rounded-xl font-semibold transition-all shadow-lg active:scale-95 ${
                stats?.running_runs > 0 
                  ? 'bg-slate-800 text-slate-500 cursor-not-allowed shadow-none' 
                  : 'bg-brand-600 hover:bg-brand-500 text-white shadow-brand-600/20'
              }`}
            >
              {stats?.running_runs > 0 ? <Loader2 className="w-5 h-5 animate-spin" /> : <Zap className="w-5 h-5" />}
              <span>{stats?.running_runs > 0 ? "Pipeline en cours..." : "Lancer Tout le Pipeline"}</span>
            </button>
          </div>
        </div>

        {/* ── Dashboard Menu / System ────────────────────────────────── */}
        <div className="flex items-center gap-4 mb-8">
           <div className="flex p-1 bg-slate-900/60 rounded-xl border border-slate-800">
              <button className="px-4 py-2 bg-slate-800 text-white text-xs font-bold rounded-lg shadow-sm">Dashboard</button>
              <button 
                onClick={clearHistory}
                className="px-4 py-2 text-slate-500 hover:text-red-400 text-xs font-bold transition-colors flex items-center gap-2"
              >
                <AlertTriangle className="w-3.5 h-3.5" />
                R\u00e9initialiser la Plateforme
              </button>
           </div>
        </div>

        {/* ── Métriques globales ──────────────────────────────────────── */}
        <div className="grid grid-cols-2 md:grid-cols-4 gap-4 mb-10">
          <StatCard
            icon={<Database className="w-5 h-5 text-blue-400" />}
            label="Total IOCs"
            value={fmtNum(stats?.total_ioc)}
            sub="dans la base"
            color="blue"
            loading={!stats}
          />
          <StatCard
            icon={<AlertTriangle className="w-5 h-5 text-purple-400" />}
            label="Total CVEs"
            value={fmtNum(stats?.total_cve)}
            sub="NVD inclus"
            color="purple"
            loading={!stats}
          />
          <StatCard
            icon={<Activity className="w-5 h-5 text-emerald-400" />}
            label="Runs Réussis"
            value={stats ? `${stats.success_runs} / ${stats.total_runs}` : '—'}
            sub="success rate"
            color="emerald"
            loading={!stats}
          />
          <StatCard
            icon={<Clock className="w-5 h-5 text-orange-400" />}
            label="Durée Moy."
            value={fmtDuration(stats?.avg_duration_sec)}
            sub="par run"
            color="orange"
            loading={!stats}
          />
        </div>

        {/* ── Pipeline Steps (dernier run) ────────────────────────────── */}
        {latestRun && (
          <div className="mb-10">
            <div className="flex items-center justify-between mb-4">
              <h2 className="text-base font-bold text-white">Dernier Run</h2>
              <button
                onClick={() => onSelectRun(latestRun.id)}
                className="text-xs text-brand-400 hover:text-brand-300 transition-colors"
              >
                Voir les détails →
              </button>
            </div>
            <PipelineStepper run={latestRun} />
          </div>
        )}

        {/* ── Sources ─────────────────────────────────────────────────── */}
        <div className="mb-10">
          <h2 className="text-base font-bold text-white mb-4 flex items-center gap-2">
            <Activity className="w-4 h-4 text-brand-400" />
            Sources d'Extraction
          </h2>
          <div className="grid grid-cols-2 md:grid-cols-4 lg:grid-cols-5 xl:grid-cols-7 gap-3">
            {SOURCES.map(source => (
              <SourceCard
                key={source.id}
                source={source}
                onRun={() => startRun(source)}
                onEnrich={() => startEnrichment(source)}
                onRunStep={(step) => startTargetedRun(source, step)}
                isRunning={runningSources.has(source.id)}
              />
            ))}
          </div>
        </div>

        {/* ── Table des runs ──────────────────────────────────────────── */}
        <div className="bg-slate-900/40 rounded-2xl border border-slate-800 overflow-hidden">
          <div className="px-6 py-4 border-b border-slate-800 flex items-center justify-between">
            <h3 className="text-sm font-bold text-white flex items-center gap-2">
              <FileText className="w-4 h-4 text-slate-400" />
              Historique des Runs
            </h3>
            <div className="flex items-center gap-2">
              {stats?.running_runs > 0 && (
                <span className="flex items-center gap-1.5 text-xs text-brand-400 font-mono">
                  <Loader2 className="w-3 h-3 animate-spin" />
                  {stats.running_runs} run(s) actif(s)
                </span>
              )}
              <span className="text-[10px] text-slate-600 font-mono">auto-refresh 5s</span>
            </div>
          </div>

          <div className="overflow-x-auto">
            <table className="w-full text-left">
              <thead className="bg-slate-800/30 border-b border-slate-800">
                <tr>
                  {['ID', 'Source', 'Démarré', 'IOCs', 'CVEs', 'Statut', ''].map(col => (
                    <th key={col} className="px-5 py-3 text-[11px] font-semibold text-slate-500 uppercase tracking-wider">
                      {col}
                    </th>
                  ))}
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-800/50">
                {loading && runs.length === 0 ? (
                  <tr><td colSpan="7" className="px-6 py-12 text-center">
                    <Loader2 className="w-6 h-6 text-brand-500 animate-spin mx-auto mb-2" />
                    <p className="text-slate-500 text-sm">Chargement...</p>
                  </td></tr>
                ) : runs.length === 0 ? (
                  <tr><td colSpan="7" className="px-6 py-12 text-center text-slate-500 text-sm">
                    Aucun run. Lancez une source pour commencer.
                  </td></tr>
                ) : runs.map(run => {
                  const ioc = (run.steps || []).reduce((a, s) => a + (s.ioc_count || 0), 0);
                  const cve = (run.steps || []).reduce((a, s) => a + (s.cve_count || 0), 0);
                  return (
                    <tr key={run.id} className="hover:bg-slate-800/20 transition-colors group">
                      <td className="px-5 py-3 font-mono text-[11px] text-slate-500">
                        {run.run_id.split('-')[0].toUpperCase()}
                      </td>
                      <td className="px-5 py-3">
                        <span className="text-white font-medium text-sm block">{run.source_name}</span>
                        <span className="text-slate-500 text-[11px]">{run.source_type}</span>
                      </td>
                      <td className="px-5 py-3 text-slate-400 text-xs">
                        {format(new Date(run.created_at), 'dd/MM HH:mm')}
                      </td>
                      <td className="px-5 py-3">
                        {ioc > 0
                          ? <span className="text-blue-400 font-mono text-xs">{fmtNum(ioc)}</span>
                          : <span className="text-slate-600 text-xs">—</span>}
                      </td>
                      <td className="px-5 py-3">
                        {cve > 0
                          ? <span className="text-purple-400 font-mono text-xs">{fmtNum(cve)}</span>
                          : <span className="text-slate-600 text-xs">—</span>}
                      </td>
                      <td className="px-5 py-3">
                        <StatusBadge status={run.status_global} />
                      </td>
                      <td className="px-5 py-3 text-right">
                        <button
                          onClick={() => onSelectRun(run.id)}
                          className="opacity-0 group-hover:opacity-100 text-slate-400 hover:text-white text-xs px-3 py-1 bg-slate-800 hover:bg-slate-700 rounded-lg transition-all"
                        >
                          Voir \u2192
                        </button>
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>
        </div>
      </div>
    </div>
  );
};

// ── Pipeline Stepper ──────────────────────────────────────────────────────────
const PIPELINE_STEPS = [
  { name: "Collecte",             icon: Database  },
  { name: "Extraction CVE / IOC", icon: Activity  },
  { name: "Enrichissement",       icon: Zap       },
  { name: "Normalisation",        icon: Shield    },
  { name: "Intégration MISP",     icon: Zap       },
];

const PipelineStepper = ({ run }) => {
  const stepMap = {};
  (run?.steps || []).forEach(s => { stepMap[s.step_name] = s; });

  const activeSteps = PIPELINE_STEPS.filter(s => stepMap[s.name]);

  return (
    <div className="bg-slate-900/40 border border-slate-800 p-6 rounded-2xl">
      <div className="flex items-center gap-0">
        {activeSteps.map((step, idx) => {
          const stepData = stepMap[step.name];
          const isLast   = idx === activeSteps.length - 1;
          const Icon     = step.icon;

          const iconClass =
            stepData.status === 'running'  ? 'bg-brand-600 text-white shadow-lg shadow-brand-600/30 scale-110' :
            stepData.status === 'success'  ? 'bg-emerald-500/20 text-emerald-400 border-emerald-500/40' :
            stepData.status === 'failed'   ? 'bg-red-500/20 text-red-400 border-red-500/40' :
            stepData.status === 'planned'  ? 'bg-slate-800/40 text-slate-500 border-dashed border-slate-700' :
            'bg-slate-800 text-slate-600 border-slate-700';

          return (
            <React.Fragment key={step.name}>
              <div className="flex flex-col items-center flex-shrink-0">
                <div className={`w-12 h-12 rounded-2xl border flex items-center justify-center transition-all duration-500 ${iconClass}`}>
                  {stepData.status === 'running'
                    ? <Loader2 className="w-5 h-5 animate-spin" />
                    : <Icon className="w-5 h-5" />}
                </div>
                <div className="mt-2 text-center w-28">
                  <p className={`text-[11px] font-semibold truncate ${
                    stepData.status === 'running' ? 'text-brand-400' :
                    stepData.status === 'success' ? 'text-emerald-400' :
                    stepData.status === 'failed'  ? 'text-red-400'    : 'text-slate-500'
                  }`}>{step.name}</p>
                  <p className="text-[9px] font-mono text-slate-600 uppercase mt-0.5">
                    {stepData.status === 'planned' ? 'À Venir' : stepData.status}
                  </p>
                </div>
              </div>
              {!isLast && (
                <div className="flex-1 h-[1px] mx-2 mb-8 bg-slate-800 relative overflow-hidden">
                  {(stepData.status === 'success') && (
                    <div className="absolute inset-0 bg-emerald-500/40" />
                  )}
                  {(stepData.status === 'running') && (
                    <div className="absolute inset-0 bg-brand-500/60 animate-pulse" />
                  )}
                </div>
              )}
            </React.Fragment>
          );
        })}
      </div>
    </div>
  );
};

// ── Source Card ───────────────────────────────────────────────────────────────
const SourceCard = ({ source, onRun, onEnrich, onRunStep, isRunning }) => {
  const [isExpanded, setIsExpanded] = useState(false);
  const colorClass = COLOR_CLASSES[source.color] || COLOR_CLASSES.blue;
  const isNVD = source.id === 'nvd' || source.id === 'alienvault';

  // Liste des étapes pour le lancement ciblé
  const STEPS = [
    "Collecte",
    "Extraction CVE / IOC",
    "Enrichissement",
    "Normalisation",
    "Intégration MISP"
  ];

  return (
    <div 
      className={`rounded-xl border transition-all duration-300 overflow-hidden ${
        isRunning 
          ? `${colorClass} ring-1 ring-current ring-offset-1 ring-offset-[#0a0d1a]` 
          : `bg-slate-900/40 border-slate-800 hover:border-slate-700 ${isExpanded ? 'ring-1 ring-slate-700' : ''}`
      }`}
    >
      {/* Header (cliquable pour expand) */}
      <div 
        onClick={() => setIsExpanded(!isExpanded)}
        className="p-3 cursor-pointer select-none"
      >
        <div className="flex items-center justify-between mb-2">
          <span className={`text-[9px] uppercase tracking-wider font-bold ${isRunning ? '' : 'text-slate-600'}`}>
            {source.type}
          </span>
          <div className="flex items-center gap-1.5">
            {isRunning && <span className="w-1.5 h-1.5 rounded-full bg-current animate-ping" />}
            <Play className={`w-2.5 h-2.5 transition-transform duration-300 ${isExpanded ? 'rotate-90' : 'text-slate-700'}`} />
          </div>
        </div>
        <p className="text-white font-semibold text-xs leading-tight">{source.name}</p>
      </div>
      
      {/* Expanded Content: Step Selection */}
      <div className={`transition-all duration-300 ease-in-out ${isExpanded ? 'max-h-[400px] opacity-100 border-t border-slate-800/50' : 'max-h-0 opacity-0'}`}>
        <div className="p-3 space-y-2">
          <p className="text-[10px] text-slate-500 font-bold uppercase mb-1">Étapes du Pipeline</p>
          
          <div className="space-y-1.5">
            {STEPS.map((step, idx) => {
              const isDisabled = isRunning || (step === 'Enrichissement' && isNVD);
              return (
                <div key={step} className="flex items-center justify-between group/step">
                  <span className={`text-[11px] ${isDisabled ? 'text-slate-700' : 'text-slate-400 group-hover/step:text-white transition-colors'}`}>
                    {idx + 1}. {step}
                  </span>
                  <button
                    onClick={(e) => { e.stopPropagation(); onRunStep(step); }}
                    disabled={isDisabled}
                    className={`p-1 rounded bg-slate-800 border border-slate-700 transition-all ${
                      isDisabled ? 'opacity-30 cursor-not-allowed' : 'hover:bg-brand-600 hover:border-brand-500 text-slate-500 hover:text-white'
                    }`}
                  >
                    <Play className="w-2.5 h-2.5 fill-current" />
                  </button>
                </div>
              );
            })}
          </div>

          <div className="pt-2 border-t border-slate-800/50 mt-2 space-y-2">
            <button
              onClick={(e) => { e.stopPropagation(); onRun(); }}
              disabled={isRunning}
              className={`w-full py-2 rounded-lg text-[10px] font-bold transition-all flex items-center justify-center gap-1.5 ${
                isRunning ? 'bg-slate-800 text-slate-500 cursor-not-allowed' :
                'bg-brand-600/20 hover:bg-brand-600 border border-brand-500/30 hover:border-brand-500 text-brand-400 hover:text-white'
              }`}
            >
              <Zap className="w-3 h-3" />
              <span>Lancer Tout</span>
            </button>

            <button
              onClick={(e) => { e.stopPropagation(); window.open(`http://localhost:8000/results/`, '_blank'); }}
              className="w-full py-1.5 rounded-lg text-[10px] font-bold bg-slate-800/50 hover:bg-slate-700 text-slate-500 hover:text-white border border-slate-700 transition-all flex items-center justify-center gap-1.5"
            >
              <FileText className="w-3 h-3" />
              <span>Explorer</span>
            </button>
          </div>
        </div>
      </div>
    </div>
  );
};

// ── Stats Card ────────────────────────────────────────────────────────────────
const StatCard = ({ icon, label, value, sub, color, loading }) => {
  const colorBg = {
    blue:    'from-blue-500/10 to-transparent border-blue-500/20',
    purple:  'from-purple-500/10 to-transparent border-purple-500/20',
    emerald: 'from-emerald-500/10 to-transparent border-emerald-500/20',
    orange:  'from-orange-500/10 to-transparent border-orange-500/20',
  };
  return (
    <div className={`bg-gradient-to-br ${colorBg[color]} border rounded-2xl p-5`}>
      <div className="flex items-center gap-2 mb-3">
        <div className="p-1.5 bg-slate-800/80 rounded-lg">{icon}</div>
        <span className="text-slate-400 text-xs font-medium">{label}</span>
      </div>
      {loading
        ? <div className="h-8 w-16 bg-slate-800 rounded animate-pulse" />
        : <div className="text-2xl font-extrabold text-white">{value}</div>
      }
      <p className="text-[10px] text-slate-600 mt-1">{sub}</p>
    </div>
  );
};

// ── Status Badge ──────────────────────────────────────────────────────────────
const StatusBadge = ({ status }) => {
  const map = {
    running: { cls: "bg-brand-500/10 text-brand-400 border-brand-500/30", pulse: true  },
    success: { cls: "bg-emerald-500/10 text-emerald-400 border-emerald-500/30"         },
    failed:  { cls: "bg-red-500/10 text-red-400 border-red-500/30"                     },
    planned: { cls: "bg-slate-800/50 text-slate-500 border-dashed border-slate-700"  },
    pending: { cls: "bg-slate-500/10 text-slate-500 border-slate-500/30"               },
  };
  const { cls, pulse } = map[status] || map.pending;
  return (
    <span className={`inline-flex items-center gap-1 px-2 py-0.5 rounded-md border text-[10px] font-bold uppercase tracking-wider ${cls} ${pulse ? 'animate-pulse' : ''}`}>
      {status}
    </span>
  );
};

export default Dashboard;
