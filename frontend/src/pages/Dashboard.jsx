import React, { useState, useEffect, useRef } from 'react';
import axios from 'axios';
import {
  Play, Shield, Activity, Clock, FileText,
  Database, AlertTriangle, CheckCircle2, Loader2, Zap, Sparkles, Square,
  Download, Search, Cpu, Globe, Languages, ScanEye, Layers, Share2, ChevronRight,
  ChevronDown, ChevronUp, Terminal, Trash2
} from 'lucide-react';
import { format } from 'date-fns';

const API_BASE = `http://${window.location.hostname}:8000`;
const WS_BASE  = `ws://${window.location.hostname}:8000/ws`;

const SOURCES = [
  { id: 'alienvault',   name: 'AlienVault OTX',  type: 'Threat Feeds',     color: 'purple' },
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
  { id: 'dfir_report',  name: 'DFIR Report',      type: 'Threat Reports',   color: 'blue'   },
];

const PIPELINE_PHASES = [
  { id: 'collecte',      label: 'COL',  full: 'Collecte',             icon: Database },
  { id: 'extraction',    label: 'EXT',  full: 'Extraction CVE / IOC', icon: Search },
  { id: 'abuse_enr',     label: 'ABUSE', full: 'AbuseIPDB Enrichment',   icon: Shield },
  { id: 'vt_enr',        label: 'VT',    full: 'VirusTotal Enrichment',   icon: ScanEye },
  { id: 'geo',           label: 'GEO',   full: 'Geolocalisation',         icon: Globe },
  { id: 'urlscan',       label: 'URL',  full: 'URLScan',              icon: ScanEye },
  { id: 'fallback',      label: 'FALL', full: 'Fallback',             icon: Layers },
  { id: 'cve_enr',       label: 'CVE',  full: 'Enrichissement CVE',   icon: AlertTriangle },

  { id: 'classif',      label: 'CLASSIF', full: 'Classification',       icon: Sparkles },
  { id: 'mitre',        label: 'MITRE',full: 'MITRE Mapping',        icon: Shield },
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

};

const ArrowConnector = () => (
  <div className="flex items-center pb-4 px-1.5 opacity-60">
    <div className="w-3 h-[2px] bg-gradient-to-r from-slate-700 to-brand-500/50 rounded-full" />
    <div className="w-1.5 h-1.5 rounded-full bg-brand-500/50 shadow-[0_0_8px_rgba(14,165,233,0.5)] ml-[-2px]" />
  </div>
);

const Dashboard = ({ onSelectRun, onExploreSource }) => {
  const [runs,           setRuns]           = useState([]);
  const [stats,          setStats]          = useState(null);
  const [loading,        setLoading]        = useState(true);
  const [stopping,       setStopping]       = useState(false);
  const [runningSources, setRunningSources] = useState(new Set());
  const [showEnrichDetails, setShowEnrichDetails] = useState(false);
  const [showScoringDetails, setShowScoringDetails] = useState(false);

  const [showGlobalUrlDetails, setShowGlobalUrlDetails] = useState(false);
  const [isStarting, setIsStarting] = useState(false);
  const [countryStats, setCountryStats] = useState([]);
  const [bulletinLoading, setBulletinLoading] = useState(false);
  const [enrichmentStats, setEnrichmentStats] = useState({
    coverage: 0,
    topCountries: []
  });
  
  // New state for live console
  const [showConsole, setShowConsole] = useState(false);
  const [consoleLogs, setConsoleLogs] = useState([]);
  const [activeConsoleRunId, setActiveConsoleRunId] = useState(null);
  const [consoleFilter, setConsoleFilter] = useState(null);
  const logEndRef = useRef(null);

  // Scheduler state
  const [scheduleStatus, setScheduleStatus] = useState({ active: false, interval_minutes: 60, next_run: null });
  const [showScheduleModal, setShowScheduleModal] = useState(false);
  const [scheduleIntervalInput, setScheduleIntervalInput] = useState(60);

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
        } else if (data.type === "log") {
          // Si on est en train de suivre ce run (ou si on suit le dernier run par défaut)
          setConsoleLogs(prev => [...prev.slice(-100), { step: data.step_name, line: data.line, timestamp: new Date() }]);
        } else if (data.type === "run_complete") {
          fetchAll();
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

  // Auto-scroll for console
  useEffect(() => {
    if (showConsole && logEndRef.current) {
      logEndRef.current.scrollIntoView({ behavior: 'smooth' });
    }
  }, [consoleLogs, showConsole]);

  const fetchAll = async () => {
    // Appel des runs (bloquant pour le dashboard principal)
    try {
      const runsRes = await axios.get(`${API_BASE}/runs`);
      setRuns(runsRes.data);
    } catch (e) {
      console.error("Fetch runs error:", e);
    }

    // Appel du statut de planification
    try {
      const scheduleRes = await axios.get(`${API_BASE}/api/schedule/status`);
      setScheduleStatus(scheduleRes.data);
    } catch (e) {
      console.error("Fetch schedule status error:", e);
    }

    // Appel des stats (optionnel, ne doit pas bloquer)
    try {
      const statsRes = await axios.get(`${API_BASE}/stats`);
      setStats(statsRes.data);
      
      // Calculate coverage (approximate)
      const coverage = statsRes.data.total_ioc > 0 
        ? Math.min(100, Math.round((statsRes.data.total_ioc / (statsRes.data.total_ioc + 100)) * 100)) 
        : 0;
      setEnrichmentStats(prev => ({ ...prev, coverage }));
    } catch (e) {
      console.error("Fetch stats error:", e);
      setStats({ total_ioc: 0, total_cve: 0, total_runs: 0, success_runs: 0, avg_duration_sec: 0 });
    }

    try {
      const geoRes = await axios.get(`${API_BASE}/api/stats/countries`);
      setCountryStats(geoRes.data);
    } catch (e) {
      console.error("Fetch geo stats error:", e);
    } finally {
      setLoading(false);
    }
  };

  const toggleSchedule = async (start) => {
    try {
      const action = start ? "start" : "stop";
      await axios.post(`${API_BASE}/api/schedule`, { action, interval_minutes: scheduleIntervalInput });
      setShowScheduleModal(false);
      fetchAll();
    } catch(e) {
      alert("Erreur lors de la planification: " + (e.response?.data?.detail || e.message));
    }
  };

  const startRun = async (source = null) => {
    const sourceName = source ? source.name : "Unified Extraction";
    const sourceType = source ? source.type : "All Sources";

    console.log(`[FRONTEND] Starting full run for ${sourceName}...`);
    if (source) setRunningSources(prev => new Set([...prev, source.id]));
    setIsStarting(true);

    try {
      const res = await axios.post(`${API_BASE}/runs`, { source_name: sourceName, source_type: sourceType });
      console.log("[FRONTEND] Run started response:", res.data);
      
      // Navigation immédiate vers le terminal pour montrer l'activité
      if (res.data && res.data.id) {
        onSelectRun(res.data.id);
      } else {
        alert("Run démarré mais ID manquant dans la réponse");
      }
      
      fetchAll();
    } catch (e) {
      console.error("Error starting run:", e);
      alert("Erreur lors du démarrage du run: " + (e.response?.data?.detail || e.message));
    } finally {
      setIsStarting(false);
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

  const startGlobalStep = async (stepName) => {
    console.log(`[FRONTEND] Triggering global step: ${stepName}`);
    setIsStarting(true);
    try {
      const res = await axios.post(
        `${API_BASE}/runs/targeted`,
        { source_name: 'Unified Extraction', source_type: 'All Sources' },
        { params: { step_name: stepName } }
      );
      console.log(`[FRONTEND] Targeted run response for ${stepName}:`, res.data);
      if (res.data && res.data.id) {
        onSelectRun(res.data.id);
      } else {
        alert("Run ciblé démarré mais ID manquant dans la réponse");
      }
      fetchAll();
    } catch (e) {
      console.error('Error starting global step:', e);
      alert("Erreur lors du démarrage : " + (e.response?.data?.detail || e.message));
    } finally {
      setIsStarting(false);
    }
  };

  const startTargetedRun = async (source, stepName) => {
    setIsStarting(true);
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
      console.error('Error starting targeted run:', e);
      alert("Erreur : " + (e.response?.data?.detail || e.message));
      setRunningSources(prev => {
        const next = new Set(prev);
        next.delete(source.id);
        return next;
      });
    } finally {
      setIsStarting(false);
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

  const generateBulletin = async () => {
    setBulletinLoading(true);
    try {
      const res = await axios.post(`${API_BASE}/api/generate-stix-bulletin`);
      if (res.data.status === "success") {
        window.open(`${API_BASE}${res.data.url}`, '_blank');
      } else {
        alert("Erreur: " + res.data.message);
      }
    } catch (e) {
      console.error("Bulletin error:", e);
      alert("Erreur lors de la g\u00e9n\u00e9ration du bulletin");
    } finally {
      setBulletinLoading(false);
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

  const deleteRun = async (runId) => {
    if (!window.confirm("Supprimer ce run de l'historique ?")) return;
    try {
      await axios.delete(`${API_BASE}/runs/${runId}`);
      await fetchAll();
    } catch (e) {
      alert("Erreur : " + (e.response?.data?.detail || e.message));
    }
  };

  const getRunType = (run) => {
    const steps = (run.steps || []).map(s => s.step_name);
    if (steps.includes('Int\u00e9gration MISP'))
      return { label: 'Pipeline', color: 'text-yellow-400 bg-yellow-500/10 border-yellow-500/20' };
    if (steps.some(s => ['Classification', 'MITRE Mapping', 'Normalisation', 'Enrichissement CVE'].includes(s)))
      return { label: 'Enrichissement', color: 'text-amber-400 bg-amber-500/10 border-amber-500/20' };
    if (steps.some(s => ['AbuseIPDB Enrichment', 'VirusTotal Enrichment', 'Geolocalisation', 'URLScan', 'Fallback'].includes(s)))
      return { label: 'Enrichissement', color: 'text-amber-400 bg-amber-500/10 border-amber-500/20' };
    if (steps.includes('Extraction CVE / IOC'))
      return { label: 'Extraction', color: 'text-violet-400 bg-violet-500/10 border-violet-500/20' };
    if (steps.includes('Collecte'))
      return { label: 'Collecte', color: 'text-cyan-400 bg-cyan-500/10 border-cyan-500/20' };
    if (steps.length === 1)
      return { label: steps[0], color: 'text-slate-400 bg-slate-500/10 border-slate-500/20' };
    return { label: 'Run', color: 'text-slate-400 bg-slate-500/10 border-slate-500/20' };
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

  // Helper to get source health (DEPRECATED)
  const getSourceHealth = (sourceId) => {
    return 'neutral';
  };

  return (
    <div className="min-h-screen bg-transparent relative overflow-hidden p-6 md:p-8 text-slate-200">
      <div className="fixed inset-0 hud-grid pointer-events-none opacity-20" />
      
      {/* ── Background Glow Effects ── */}
      <div className="absolute top-0 left-1/4 w-[600px] h-[600px] bg-brand-500/10 blur-[150px] rounded-full pointer-events-none" />
      <div className="absolute bottom-0 right-1/4 w-[600px] h-[600px] bg-purple-500/10 blur-[150px] rounded-full pointer-events-none" />

      {/* ── Top Global Cyber Loading Bar ── */}
      {loading && (
        <div className="fixed top-14 left-0 w-full h-0.5 z-40 bg-slate-900/80">
          <div className="absolute top-0 h-full cyber-loading-bar shadow-[0_0_10px_#0ea5e9]" />
        </div>
      )}

      <div className="max-w-[1600px] mx-auto">

        {/* ── Header ─────────────────────────────────────────────────── */}
        <div className="flex flex-wrap items-start justify-between gap-4 mb-8">
          <div className="flex items-center gap-3">
            <div className="flex items-center gap-2 bg-slate-900/60 border border-slate-800 rounded-lg px-3 py-1.5">
              <span className="w-2 h-2 bg-emerald-500 rounded-full animate-pulse shadow-[0_0_8px_rgba(16,185,129,0.8)]" />
              <span className="text-slate-300 font-semibold text-xs">Plateforme Active</span>
            </div>
            <span className="text-xs text-slate-600 font-mono hidden sm:block">auto-refresh 5s</span>
            {scheduleStatus.active && (
              <div className="flex items-center gap-2 bg-brand-500/10 border border-brand-500/30 rounded-lg px-3 py-1.5 ml-2 cursor-pointer hover:bg-brand-500/20 transition-colors" onClick={() => setShowScheduleModal(true)}>
                <Clock className="w-3.5 h-3.5 text-brand-400 animate-pulse" />
                <span className="text-brand-300 font-semibold text-xs">
                  Prochaine exécution : {scheduleStatus.next_run ? format(new Date(scheduleStatus.next_run), 'HH:mm:ss') : '...'}
                </span>
              </div>
            )}
          </div>
          <div className="flex flex-col items-end gap-2">
            {/* HUD Pipeline Control Panel */}
            <div className="flex items-center gap-0 bg-slate-900/40 border border-brand-500/20 rounded-2xl p-2 shadow-[0_8px_32px_rgba(0,0,0,0.8),inset_0_0_30px_rgba(14,165,233,0.1)] backdrop-blur-xl relative overflow-hidden">
              <div className="absolute inset-0 bg-gradient-to-r from-transparent via-brand-500/[0.03] to-transparent pointer-events-none" />
              {/* Stop button when running */}
              {stats?.running_runs > 0 && (
                <>
                  <button
                    onClick={stopRun}
                    disabled={stopping}
                    className="flex items-center gap-2 bg-red-500/10 hover:bg-red-500/20 text-red-400 border border-red-500/40 px-4 py-2 rounded-xl font-semibold transition-all active:scale-95 disabled:opacity-50 text-xs mr-2"
                  >
                    {stopping ? <Loader2 className="w-3.5 h-3.5 animate-spin" /> : <Square className="w-3.5 h-3.5 fill-current" />}
                    <span>{stopping ? 'Arrêt...' : 'Arrêter'}</span>
                  </button>
                  <div className="w-px h-8 bg-slate-700 mx-1" />
                </>
              )}

              {/* Step 1: Collecte */}
              <button
                onClick={() => startGlobalStep('Collecte')}
                disabled={stats?.running_runs > 0}
                title="Collecte — Toutes sources"
                className={`group relative flex flex-col items-center gap-1 px-3 py-2 rounded-xl transition-all duration-200 active:scale-95 ${
                  stats?.running_runs > 0
                    ? 'opacity-40 cursor-not-allowed'
                    : 'hover:bg-cyan-500/10 cursor-pointer'
                }`}
              >
                <div className={`w-8 h-8 rounded-lg flex items-center justify-center border transition-all duration-200 ${
                  stats?.running_runs > 0 || isStarting
                    ? 'bg-slate-800 border-slate-700 text-slate-600'
                    : 'bg-cyan-500/10 border-cyan-500/30 text-cyan-400 group-hover:bg-cyan-500/20 group-hover:border-cyan-400 group-hover:shadow-[0_0_12px_rgba(6,182,212,0.3)]'
                }`}>
                  {isStarting ? <Loader2 className="w-3.5 h-3.5 animate-spin" /> : <Download className="w-3.5 h-3.5" />}
                </div>
                <span className={`text-xs font-medium uppercase tracking-wide transition-colors ${
                  stats?.running_runs > 0 ? 'text-slate-600' : 'text-slate-500 group-hover:text-cyan-400'
                }`}>Collecte</span>
              </button>

              <ArrowConnector />

              {/* Step 2: Extraction */}
              <button
                onClick={() => startGlobalStep('Extraction CVE / IOC')}
                disabled={stats?.running_runs > 0}
                title="Extraction IOC/CVE — Toutes sources"
                className={`group relative flex flex-col items-center gap-1 px-3 py-2 rounded-xl transition-all duration-200 active:scale-95 ${
                  stats?.running_runs > 0
                    ? 'opacity-40 cursor-not-allowed'
                    : 'hover:bg-violet-500/10 cursor-pointer'
                }`}
              >
                <div className={`w-8 h-8 rounded-lg flex items-center justify-center border transition-all duration-200 ${
                  stats?.running_runs > 0
                    ? 'bg-slate-800 border-slate-700 text-slate-600'
                    : 'bg-violet-500/10 border-violet-500/30 text-violet-400 group-hover:bg-violet-500/20 group-hover:border-violet-400 group-hover:shadow-[0_0_12px_rgba(139,92,246,0.3)]'
                }`}>
                  <Search className="w-3.5 h-3.5" />
                </div>
                <span className={`text-xs font-medium uppercase tracking-wide transition-colors ${
                  stats?.running_runs > 0 ? 'text-slate-600' : 'text-slate-500 group-hover:text-violet-400'
                }`}>Extraction</span>
              </button>

              <ArrowConnector />

              {/* Master Enrichment Control */}
              <div className="flex items-center gap-0.5 bg-amber-500/5 rounded-2xl p-0.5 border border-amber-500/10">
                <button
                  onClick={() => startGlobalStep('Enrichissement')}
                  disabled={stats?.running_runs > 0}
                  title="Lancer l'Enrichissement Complet (Géo + Scan) - Toutes sources"
                  className={`flex items-center gap-2 pr-4 pl-3 py-2 rounded-xl font-bold transition-all duration-200 active:scale-95 ${
                    stats?.running_runs > 0
                      ? 'opacity-40 cursor-not-allowed'
                      : 'hover:bg-amber-500/20 text-amber-500 group'
                  }`}
                >
                  <div className={`w-8 h-8 rounded-lg flex items-center justify-center border transition-all duration-200 ${
                    stats?.running_runs > 0
                      ? 'bg-slate-800 border-slate-700 text-slate-600'
                      : 'bg-amber-500/10 border-amber-500/30 text-amber-500 group-hover:bg-amber-500/30 group-hover:border-amber-400'
                  }`}>
                    <Sparkles className="w-3.5 h-3.5" />
                  </div>
                  <div className="flex flex-col items-start leading-none">
                    <span className="text-xs font-bold uppercase tracking-widest">Enrichir</span>
                    <span className="text-[10px] text-amber-500/60 uppercase font-mono mt-1">Unified Stage</span>
                  </div>
                </button>
                
                <button
                  onClick={() => setShowEnrichDetails(!showEnrichDetails)}
                  className={`p-2 rounded-lg transition-colors ${showEnrichDetails ? 'bg-amber-500/20 text-white' : 'text-amber-500/40 hover:text-amber-400'}`}
                  title={showEnrichDetails ? "Masquer les sous-étapes" : "Afficher les sous-étapes (Géo, Scan)"}
                >
                  {showEnrichDetails ? <ChevronUp size={14} /> : <ChevronDown size={14} />}
                </button>
              </div>

              {/* Expandable Sub-steps Area */}
              {showEnrichDetails && (
                <div className="flex items-center animate-in slide-in-from-left duration-300">
                  <ArrowConnector />
                  

                  {/* AbuseIPDB */}
                  <button
                    onClick={() => startGlobalStep('AbuseIPDB Enrichment')}
                    disabled={stats?.running_runs > 0 || isStarting}
                    title="Stage 1: AbuseIPDB Reputation"
                    className={`flex flex-col items-center gap-1 px-3 py-1 group/step ${isStarting ? 'opacity-40' : ''}`}
                  >
                    <div className="w-7 h-7 rounded bg-blue-500/10 border border-blue-500/20 flex items-center justify-center text-blue-400 group-hover/step:bg-blue-500 group-hover/step:text-white transition-all">
                      {isStarting ? <Loader2 size={12} className="animate-spin" /> : <Shield size={12} />}
                    </div>
                    <span className="text-[11px] font-medium text-slate-500 group-hover/step:text-blue-400 uppercase">Abuse</span>
                  </button>

                  <ArrowConnector />

                  {/* VirusTotal */}
                  <button
                    onClick={() => startGlobalStep('VirusTotal Enrichment')}
                    disabled={stats?.running_runs > 0 || isStarting}
                    title="Stage 1b: VirusTotal (URL / Domain / Hash)"
                    className={`flex flex-col items-center gap-1 px-3 py-1 group/step ${isStarting ? 'opacity-40' : ''}`}
                  >
                    <div className="w-7 h-7 rounded bg-indigo-500/10 border border-indigo-500/20 flex items-center justify-center text-indigo-400 group-hover/step:bg-indigo-500 group-hover/step:text-white transition-all">
                      {isStarting ? <Loader2 size={12} className="animate-spin" /> : <ScanEye size={12} />}
                    </div>
                    <span className="text-[11px] font-medium text-slate-500 group-hover/step:text-indigo-400 uppercase">VT</span>
                  </button>

                  <ArrowConnector />

                  {/* GEO */}
                  <button
                    onClick={() => startGlobalStep('Geolocalisation')}
                    disabled={stats?.running_runs > 0 || isStarting}
                    title="Stage 2: Geolocation"
                    className={`flex flex-col items-center gap-1 px-3 py-1 group/step ${isStarting ? 'opacity-40' : ''}`}
                  >
                    <div className="w-7 h-7 rounded bg-emerald-500/10 border border-emerald-500/20 flex items-center justify-center text-emerald-400 group-hover/step:bg-emerald-500 group-hover/step:text-white transition-all">
                      {isStarting ? <Loader2 size={12} className="animate-spin" /> : <Globe size={12} />}
                    </div>
                    <span className="text-[11px] font-medium text-slate-500 group-hover/step:text-emerald-400 uppercase">Geo</span>
                  </button>

                  <ArrowConnector />

                  {/* CVE Enrichment */}
                  <button
                    onClick={() => startGlobalStep('Enrichissement CVE')}
                    disabled={stats?.running_runs > 0 || isStarting}
                    title="CVE Enrichment (NVD + NLP)"
                    className={`flex flex-col items-center gap-1 px-3 py-1 group/step ${isStarting ? 'opacity-40' : ''}`}
                  >
                    <div className="w-7 h-7 rounded bg-amber-500/10 border border-amber-500/20 flex items-center justify-center text-amber-400 group-hover/step:bg-amber-500 group-hover/step:text-white transition-all">
                      {isStarting ? <Loader2 size={12} className="animate-spin" /> : <AlertTriangle size={12} />}
                    </div>
                    <span className="text-[11px] font-medium text-slate-500 group-hover/step:text-amber-400 uppercase">CVE Enrichment</span>
                  </button>

                  <ArrowConnector />
                  
                  {/* URL Analysis Group */}
                  <div className="flex items-center gap-0.5 bg-brand-500/5 rounded-2xl p-0.5 border border-brand-500/10 h-10">
                    <button
                      onClick={() => startGlobalStep('URLScan')}
                      disabled={stats?.running_runs > 0 || isStarting}
                      title="Complete Global URL Analysis (URLScan + Fallback)"
                      className={`flex items-center gap-2 pr-4 pl-3 py-1.5 rounded-xl font-bold transition-all duration-200 active:scale-95 ${
                        (stats?.running_runs > 0 || isStarting)
                          ? 'opacity-40 cursor-not-allowed'
                          : 'hover:bg-brand-500/20 text-brand-400 group/gs'
                      }`}
                    >
                      <div className={`w-7 h-7 rounded bg-brand-500/10 border border-brand-500/20 flex items-center justify-center text-brand-400 group-hover/gs:bg-brand-500 group-hover/gs:text-white transition-all`}>
                        {isStarting ? <Loader2 size={14} className="animate-spin" /> : <Sparkles size={14} />}
                      </div>
                      <span className="text-xs uppercase font-bold tracking-widest">URL Enrichment</span>
                    </button>
                    
                    <button
                      onClick={() => setShowGlobalUrlDetails(!showGlobalUrlDetails)}
                      className={`p-2 rounded-lg transition-colors ${showGlobalUrlDetails ? 'bg-brand-500/20 text-white' : 'text-brand-500/40 hover:text-brand-400'}`}
                      title={showGlobalUrlDetails ? "Masquer les sous-options" : "Afficher les sous-options (Only Scan, Only Fallback)"}
                    >
                      {showGlobalUrlDetails ? <ChevronUp size={12} /> : <ChevronDown size={12} />}
                    </button>
                  </div>

                  {/* SUB-STEPS (URL Only) */}
                  {showGlobalUrlDetails && (
                    <div className="flex items-center animate-in slide-in-from-left duration-300">
                      <ArrowConnector />
                      
                      {/* URLScan Only */}
                      <button
                        onClick={() => startGlobalStep('URLScan_Only')}
                        disabled={stats?.running_runs > 0 || isStarting}
                        title="URLScan.io API Analysis Only"
                        className={`flex flex-col items-center gap-1 px-3 py-1 group/step ${isStarting ? 'opacity-40' : ''}`}
                      >
                        <div className="w-8 h-8 rounded-lg bg-pink-500/10 border border-pink-500/20 flex items-center justify-center text-pink-400 group-hover/step:bg-pink-500/30 transition-all">
                          {isStarting ? <Loader2 size={14} className="animate-spin" /> : <ScanEye size={14} />}
                        </div>
                        <span className="text-[11px] font-medium text-slate-500 group-hover/step:text-pink-400 uppercase">URLScan</span>
                      </button>

                      <ArrowConnector />

                      {/* Fallback Only */}
                      <button
                        onClick={() => startGlobalStep('Fallback')}
                        disabled={stats?.running_runs > 0 || isStarting}
                        title="Stage 4: Fallback Enrichment"
                        className={`flex flex-col items-center gap-1 px-3 py-1 group/step ${isStarting ? 'opacity-40' : ''}`}
                      >
                        <div className="w-8 h-8 rounded-lg bg-orange-500/10 border border-orange-500/20 flex items-center justify-center text-orange-400 group-hover/step:bg-orange-500/30 transition-all">
                          {isStarting ? <Loader2 size={14} className="animate-spin" /> : <Layers size={14} />}
                        </div>
                        <span className="text-[11px] font-medium text-slate-500 group-hover/step:text-orange-400 uppercase">Fallback</span>
                      </button>
                    </div>
                  )}

                  <ArrowConnector />

                  {/* Classification */}
                  <button
                    onClick={() => startGlobalStep('Classification')}
                    disabled={stats?.running_runs > 0 || isStarting}
                    title="Intelligence Classification & Scoring"
                    className={`flex flex-col items-center gap-1 px-3 py-1 group/step ${isStarting ? 'opacity-40' : ''}`}
                  >
                    <div className="w-7 h-7 rounded bg-brand-500/10 border border-brand-500/20 flex items-center justify-center text-brand-400 group-hover/step:bg-brand-500 group-hover/step:text-white transition-all">
                      {isStarting ? <Loader2 size={12} className="animate-spin" /> : <Sparkles size={12} />}
                    </div>
                    <span className="text-[11px] font-medium text-slate-500 group-hover/step:text-brand-400 uppercase">Classification</span>
                  </button>

                  <ArrowConnector />

                  {/* MITRE Mapping */}
                  <button
                    onClick={() => startGlobalStep('MITRE Mapping')}
                    disabled={stats?.running_runs > 0 || isStarting}
                    title="MITRE ATT&CK Technique Mapping"
                    className={`flex flex-col items-center gap-1 px-3 py-1 group/step ${isStarting ? 'opacity-40' : ''}`}
                  >
                    <div className="w-7 h-7 rounded bg-slate-800 border border-slate-700 flex items-center justify-center text-slate-400 group-hover/step:bg-white group-hover/step:text-black transition-all">
                      {isStarting ? <Loader2 size={12} className="animate-spin" /> : <Shield size={12} />}
                    </div>
                    <span className="text-[11px] font-medium text-slate-500 group-hover/step:text-white uppercase">MITRE</span>
                  </button>
                </div>
              )}

              <ArrowConnector />

              {/* Step 4: Correlation SOC */}
              <button
                onClick={() => startGlobalStep('Corrélation SOC')}
                disabled={stats?.running_runs > 0}
                title="Corrélation SOC — Groupement des menaces"
                className={`group relative flex flex-col items-center gap-1 px-3 py-2 rounded-xl transition-all duration-200 active:scale-95 ${
                  stats?.running_runs > 0
                    ? 'opacity-40 cursor-not-allowed'
                    : 'hover:bg-emerald-500/10 cursor-pointer'
                }`}
              >
                <div className={`w-8 h-8 rounded-lg flex items-center justify-center border transition-all duration-200 ${
                  stats?.running_runs > 0
                    ? 'bg-slate-800 border-slate-700 text-slate-600'
                    : 'bg-emerald-500/10 border-emerald-500/30 text-emerald-400 group-hover:bg-emerald-500/20 group-hover:border-emerald-400 group-hover:shadow-[0_0_12px_rgba(16,185,129,0.3)]'
                }`}>
                  <Layers className="w-3.5 h-3.5" />
                </div>
                <span className={`text-xs font-medium uppercase tracking-wide transition-colors ${
                  stats?.running_runs > 0 ? 'text-slate-600' : 'text-slate-500 group-hover:text-emerald-400'
                }`}>Corrélation</span>
              </button>

              <ArrowConnector />

              {/* Step 5: Export STIX */}
              <button
                onClick={() => startGlobalStep('Export STIX')}
                disabled={stats?.running_runs > 0}
                title="Générer Export STIX 2.1"
                className={`group relative flex flex-col items-center gap-1 px-3 py-2 rounded-xl transition-all duration-200 active:scale-95 ${
                  stats?.running_runs > 0
                    ? 'opacity-40 cursor-not-allowed'
                    : 'hover:bg-blue-500/10 cursor-pointer'
                }`}
              >
                <div className={`w-8 h-8 rounded-lg flex items-center justify-center border transition-all duration-200 ${
                  stats?.running_runs > 0
                    ? 'bg-slate-800 border-slate-700 text-slate-600'
                    : 'bg-blue-500/10 border-blue-500/30 text-blue-400 group-hover:bg-blue-500/20 group-hover:border-blue-400 group-hover:shadow-[0_0_12px_rgba(14,165,233,0.3)]'
                }`}>
                  <Share2 className="w-3.5 h-3.5" />
                </div>
                <span className={`text-xs font-medium uppercase tracking-wide transition-colors ${
                  stats?.running_runs > 0 ? 'text-slate-600' : 'text-slate-500 group-hover:text-blue-400'
                }`}>STIX 2.1</span>
              </button>

              {/* Nouveau Bouton Bulletin PDF */}
              <button
                onClick={generateBulletin}
                disabled={bulletinLoading}
                title="G\u00e9n\u00e9rer Bulletin PDF (STIX)"
                className={`group relative flex flex-col items-center gap-1 px-3 py-2 rounded-xl transition-all duration-200 active:scale-95 ${
                  bulletinLoading
                    ? 'opacity-40 cursor-not-allowed'
                    : 'hover:bg-red-500/10 cursor-pointer'
                }`}
              >
                <div className={`w-8 h-8 rounded-lg flex items-center justify-center border transition-all duration-200 ${
                  bulletinLoading
                    ? 'bg-slate-800 border-slate-700 text-slate-600'
                    : 'bg-red-500/10 border-red-500/30 text-red-400 group-hover:bg-red-500/20 group-hover:border-red-400 group-hover:shadow-[0_0_12px_rgba(239,68,68,0.3)]'
                }`}>
                  {bulletinLoading ? <Loader2 className="w-3.5 h-3.5 animate-spin" /> : <FileText className="w-3.5 h-3.5" />}
                </div>
                <span className={`text-xs font-medium uppercase tracking-wide transition-colors ${
                  bulletinLoading ? 'text-slate-600' : 'text-slate-500 group-hover:text-red-400'
                }`}>Bulletin</span>
              </button>

              <ArrowConnector />

              {/* Step 5: Intégration MISP (Direct API Push) */}
              <button
                onClick={() => startGlobalStep('Intégration MISP')}
                disabled={stats?.running_runs > 0}
                title="Intégration MISP (Push API uniquement)"
                className={`group relative flex flex-col items-center gap-1 px-4 py-2 rounded-xl transition-all duration-200 active:scale-95 ${
                  stats?.running_runs > 0
                    ? 'opacity-40 cursor-not-allowed'
                    : 'hover:bg-orange-500/10 cursor-pointer'
                }`}
              >
                <div className={`w-10 h-10 rounded-xl flex items-center justify-center border transition-all duration-200 ${
                  stats?.running_runs > 0
                    ? 'bg-slate-800 border-slate-700 text-slate-600'
                    : 'bg-orange-600/20 border-orange-500/40 text-orange-400 group-hover:bg-orange-600 group-hover:border-orange-400 group-hover:text-white group-hover:shadow-[0_0_15px_rgba(249,115,22,0.4)]'
                }`}>
                  {stats?.running_runs > 0 ? <Loader2 className="w-5 h-5 animate-spin" /> : <Zap className="w-5 h-5" />}
                </div>
                <span className={`text-xs font-bold uppercase tracking-widest transition-colors ${
                  stats?.running_runs > 0 ? 'text-slate-600' : 'text-slate-500 group-hover:text-orange-400'
                }`}>Intégrer MISP</span>
              </button>

              {/* Separator */}
              <div className="w-px h-10 bg-slate-700 mx-2" />

              {/* Planifier Button */}
              <button
                onClick={() => setShowScheduleModal(true)}
                className={`flex items-center gap-2 px-4 py-3 rounded-xl font-black transition-all duration-300 shadow-xl active:scale-95 text-sm ml-2 overflow-hidden relative group/master ${
                  scheduleStatus.active
                    ? 'bg-emerald-500/20 text-emerald-400 border border-emerald-500/50 hover:bg-emerald-500/30'
                    : 'bg-slate-800 text-slate-300 border border-slate-700 hover:bg-slate-700'
                }`}
                title="Planifier le pipeline"
              >
                <Clock className={`w-4 h-4 ${scheduleStatus.active ? 'animate-pulse text-emerald-400' : ''}`} />
                <span className="tracking-wide uppercase hidden xl:block">
                  {scheduleStatus.active ? 'Planifié' : 'Planifier'}
                </span>
              </button>

              {/* Full pipeline button */}
              <button
                onClick={() => startRun()}
                disabled={stats?.running_runs > 0}
                className={`flex items-center gap-2 px-6 py-3 rounded-xl font-black transition-all duration-300 shadow-xl active:scale-95 text-sm ml-2 overflow-hidden relative group/master ${
                  stats?.running_runs > 0
                    ? 'bg-slate-800 text-slate-500 cursor-not-allowed shadow-none'
                    : 'bg-gradient-to-r from-brand-600 to-indigo-600 hover:from-brand-500 hover:to-indigo-500 text-white shadow-brand-600/30 hover:shadow-brand-500/50 hover:-translate-y-0.5'
                }`}
              >
                {!(stats?.running_runs > 0) && <div className="absolute inset-0 bg-white/20 translate-y-full group-hover/master:translate-y-0 transition-transform duration-300 ease-out" />}
                <div className="relative z-10 flex items-center gap-2">
                  {stats?.running_runs > 0
                    ? <Loader2 className="w-4 h-4 animate-spin" />
                    : <Zap className="w-4 h-4 group-hover/master:animate-bounce" />
                  }
                  <span className="tracking-wide uppercase">{stats?.running_runs > 0 ? 'En cours...' : 'Pipeline Complet'}</span>
                </div>
              </button>
          </div>
        </div>
      </div>





        {/* Modal de Planification */}
        {showScheduleModal && (
          <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/60 backdrop-blur-sm">
            <div className="bg-slate-900 border border-slate-700 rounded-2xl p-6 w-full max-w-md shadow-2xl relative">
              <button onClick={() => setShowScheduleModal(false)} className="absolute top-4 right-4 text-slate-500 hover:text-white font-bold">
                X
              </button>
              
              <h2 className="text-xl font-black text-white mb-2 flex items-center gap-2">
                <Clock className="w-5 h-5 text-brand-400" />
                Planification du Pipeline
              </h2>
              <p className="text-sm text-slate-400 mb-6">
                Configurez l'exécution automatique du pipeline complet ("Unified Extraction").
              </p>
              
              <div className="space-y-4 mb-8">
                <div>
                  <label className="block text-xs font-bold text-slate-500 uppercase tracking-widest mb-2">Fréquence d'exécution</label>
                  <select 
                    value={scheduleIntervalInput} 
                    onChange={(e) => setScheduleIntervalInput(Number(e.target.value))}
                    className="w-full bg-slate-800 border border-slate-700 text-white rounded-xl px-4 py-3 text-sm focus:outline-none focus:border-brand-500 transition-colors"
                  >
                    <option value={10}>Toutes les 10 minutes</option>
                    <option value={60}>Toutes les heures (1h)</option>
                    <option value={360}>Toutes les 6 heures (6h)</option>
                    <option value={720}>Toutes les 12 heures (12h)</option>
                    <option value={1440}>Tous les jours (24h)</option>
                  </select>
                </div>
                
                {scheduleStatus.active && (
                  <div className="p-3 bg-brand-500/10 border border-brand-500/20 rounded-xl">
                    <div className="flex items-center gap-2 text-brand-400 text-xs font-bold uppercase tracking-wide">
                      <span className="w-2 h-2 rounded-full bg-brand-500 animate-pulse" />
                      Planification Actuellement Active
                    </div>
                    {scheduleStatus.next_run && (
                      <div className="mt-1 text-slate-400 text-xs font-mono">
                        Prochaine exécution : {format(new Date(scheduleStatus.next_run), 'dd/MM/yyyy HH:mm:ss')}
                      </div>
                    )}
                  </div>
                )}
              </div>
              
              <div className="flex gap-3">
                {scheduleStatus.active ? (
                  <button 
                    onClick={() => toggleSchedule(false)}
                    className="flex-1 py-3 bg-red-500/20 hover:bg-red-500/30 text-red-400 font-bold rounded-xl border border-red-500/30 transition-colors"
                  >
                    Arrêter
                  </button>
                ) : (
                  <button 
                    onClick={() => toggleSchedule(true)}
                    className="flex-1 py-3 bg-brand-600 hover:bg-brand-500 text-white font-bold rounded-xl shadow-lg shadow-brand-600/20 transition-colors"
                  >
                    Démarrer
                  </button>
                )}
                <button 
                  onClick={() => setShowScheduleModal(false)}
                  className="px-6 py-3 bg-slate-800 hover:bg-slate-700 text-white font-bold rounded-xl transition-colors"
                >
                  Fermer
                </button>
              </div>
            </div>
          </div>
        )}

        {/* ── Dashboard Menu / System ────────────────────────────────── */}
        <div className="flex items-center gap-4 mb-8">
           <div className="flex p-1 bg-slate-900/40 rounded-xl border border-white/5 backdrop-blur-md">
              <div className="px-4 py-2 bg-brand-500/20 text-brand-400 text-xs font-bold rounded-lg border border-brand-500/30">System Monitor</div>
              <button 
                onClick={clearHistory}
                className="px-4 py-2 text-slate-500 hover:text-red-400 text-xs font-bold transition-colors flex items-center gap-2"
              >
                <AlertTriangle className="w-3.5 h-3.5" />
                Reset Infrastructure
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
            <PipelineStepper 
              run={latestRun} 
              onStepClick={(stepName) => {
                setConsoleFilter(prev => prev === stepName ? null : stepName);
                setShowConsole(true);
              }}
              activeFilter={consoleFilter}
            />
            
            {/* ── Console Terminal (Quick View) ── */}
            <div className="mt-4 flex flex-wrap gap-3 items-center">
              <button 
                onClick={() => {
                  setShowConsole(!showConsole);
                  if (!showConsole) setConsoleFilter(null);
                }}
                className={`flex items-center gap-2 px-4 py-2 rounded-xl text-[10px] font-black uppercase tracking-widest transition-all ${
                  showConsole ? 'bg-slate-800 text-brand-400 border border-brand-500/30' : 'bg-slate-900/40 text-slate-500 border border-white/5 hover:text-slate-300'
                }`}
              >
                <Terminal className="w-3.5 h-3.5" />
                {showConsole ? 'Masquer la console' : 'Afficher la console live'}
                {latestRun?.status_global === 'running' && <span className="w-1.5 h-1.5 bg-brand-500 rounded-full animate-ping ml-1" />}
              </button>

              {showConsole && consoleFilter && (
                <button 
                  onClick={() => setConsoleFilter(null)}
                  className="px-3 py-2 rounded-xl text-[9px] font-black uppercase tracking-widest bg-brand-500/20 text-brand-400 border border-brand-500/40 animate-in zoom-in-95"
                >
                  Filtre: {consoleFilter} ×
                </button>
              )}
            </div>

            {showConsole && (
              <div className="mt-3 animate-in fade-in slide-in-from-top-2 duration-300">
                <div className="bg-[#0d1117] rounded-2xl border border-slate-800/80 overflow-hidden shadow-2xl">
                  <div className="flex items-center justify-between px-4 py-2 border-b border-slate-800/50 bg-slate-900/60">
                    <div className="flex items-center gap-2">
                      <div className="flex gap-1">
                        <div className="w-2 h-2 rounded-full bg-red-500/50" />
                        <div className="w-2 h-2 rounded-full bg-yellow-500/50" />
                        <div className="w-2 h-2 rounded-full bg-emerald-500/50" />
                      </div>
                      <span className="text-xs font-mono text-slate-400 ml-2">
                        Terminal Output {consoleFilter ? `[ ${consoleFilter} ]` : '— Real-time'}
                      </span>
                    </div>
                    <div className="flex gap-3">
                      <button 
                        onClick={() => setConsoleLogs([])}
                        className="text-[9px] font-mono text-slate-600 hover:text-slate-400 uppercase"
                      >
                        Clear
                      </button>
                    </div>
                  </div>
                  <div 
                    className="p-4 font-mono text-[11px] leading-5 overflow-y-auto max-h-[300px] scrollbar-thin scrollbar-thumb-slate-800"
                  >
                    {(consoleFilter ? consoleLogs.filter(l => l.step === consoleFilter) : consoleLogs).length === 0 ? (
                      <div className="py-10 text-center text-slate-700 italic">
                        {consoleFilter ? `Aucun log pour l'étape "${consoleFilter}" pour le moment.` : "En attente d'activité sur le pipeline..."}
                      </div>
                    ) : (
                      <div className="space-y-0.5">
                        {(consoleFilter ? consoleLogs.filter(l => l.step === consoleFilter) : consoleLogs).map((log, i) => (
                          <div key={i} className="flex gap-3">
                            <span className="text-slate-700 shrink-0">{format(log.timestamp, 'HH:mm:ss')}</span>
                            {!consoleFilter && <span className="text-brand-500/50 shrink-0 w-20 truncate">[{log.step}]</span>}
                            <span className={`break-all ${
                              /✓|OK|success/i.test(log.line) ? 'text-emerald-400' :
                              /✗|ERROR|failed/i.test(log.line) ? 'text-red-400' :
                              /⚠|WARN/i.test(log.line) ? 'text-yellow-400' : 'text-slate-300'
                            }`}>
                              {log.line}
                            </span>
                          </div>
                        ))}
                        <div ref={logEndRef} />
                      </div>
                    )}
                  </div>
                </div>
              </div>
            )}
          </div>
        )}



        {/* ── Global Sources Operations Grid ─────────────────────────── */}
        <div className="mb-10">
          <div className="flex items-center justify-between mb-6">
            <h2 className="text-base font-black text-white flex items-center gap-2 uppercase tracking-widest">
              <Activity className="w-5 h-5 text-brand-400" />
              Source Operations Center
            </h2>
            <div className="flex items-center gap-4 text-xs font-semibold text-slate-500">
               <span className="flex items-center gap-1.5"><span className="w-1.5 h-1.5 rounded-full bg-emerald-500 shadow-[0_0_5px_#10b981]" /> Success</span>
               <span className="flex items-center gap-1.5"><span className="w-1.5 h-1.5 rounded-full bg-red-500 shadow-[0_0_5px_#ef4444]" /> Failed</span>
               <span className="flex items-center gap-1.5"><span className="w-1.5 h-1.5 rounded-full bg-brand-500 animate-pulse" /> Running</span>
               <span className="flex items-center gap-1.5"><span className="w-1.5 h-1.5 rounded-full bg-slate-700" /> Pending</span>
            </div>
          </div>
          
          <div className="bg-slate-900/40 rounded-3xl border border-white/5 overflow-hidden backdrop-blur-xl shadow-2xl">
            <div className="overflow-x-auto">
              <table className="w-full text-left border-collapse">
                <thead>
                  <tr className="bg-slate-800/30 border-b border-white/5">
                    <th className="px-6 py-4 text-xs font-semibold text-slate-500 uppercase tracking-wider min-w-[200px]">Source</th>
                    {PIPELINE_PHASES.map(phase => (
                      <th key={phase.id} className="px-2 py-4 text-xs font-semibold text-slate-500 uppercase tracking-wider text-center" title={phase.full}>
                        <div className="flex flex-col items-center gap-1">
                          <phase.icon className="w-3 h-3 opacity-40" />
                          {phase.label}
                        </div>
                      </th>
                    ))}
                    <th className="px-6 py-4 text-xs font-semibold text-slate-500 uppercase tracking-wider text-right">Actions</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-white/5">
                  {SOURCES.map(source => (
                    <SourceStatusRow 
                      key={source.id} 
                      source={source} 
                      runs={runs}
                      onRun={() => startRun(source)}
                      onRunPhase={(phaseName) => startTargetedRun(source, phaseName)}
                      isStarting={isStarting}
                      onExplore={() => onExploreSource(source.id)}
                    />
                  ))}
                </tbody>
              </table>
            </div>
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
                  {['ID', 'Source', 'Type', 'Démarré', 'IOCs', 'CVEs', 'Statut', ''].map(col => (
                    <th key={col} className="px-5 py-3 text-[11px] font-semibold text-slate-500 uppercase tracking-wider">
                      {col}
                    </th>
                  ))}
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-800/50">
                {loading && runs.length === 0 ? (
                  <tr><td colSpan="8" className="px-6 py-12 text-center">
                    <Loader2 className="w-6 h-6 text-brand-500 animate-spin mx-auto mb-2" />
                    <p className="text-slate-500 text-sm">Chargement...</p>
                  </td></tr>
                ) : runs.length === 0 ? (
                  <tr><td colSpan="8" className="px-6 py-12 text-center text-slate-500 text-sm">
                    Aucun run. Lancez une source pour commencer.
                  </td></tr>
                ) : runs.map(run => {
                  const ioc = Math.max(0, ...(run.steps || []).map(s => s.ioc_count || 0));
                  const cve = Math.max(0, ...(run.steps || []).map(s => s.cve_count || 0));
                  const runType = getRunType(run);
                  const isRunning = run.status_global === 'running';
                  return (
                    <tr key={run.id} className="hover:bg-slate-800/20 transition-colors group">
                      <td className="px-5 py-3 font-mono text-xs text-slate-500">
                        {run.run_id.split('-')[0].toUpperCase()}
                      </td>
                      <td className="px-5 py-3">
                        <span className="text-white font-medium text-sm block">{run.source_name}</span>
                        <span className="text-slate-500 text-[11px]">{run.source_type}</span>
                      </td>
                      <td className="px-5 py-3">
                        <span className={`px-2 py-0.5 rounded text-[10px] font-black uppercase border ${runType.color}`}>
                          {runType.label}
                        </span>
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
                        <div className="flex items-center justify-end gap-2">
                          <button
                            onClick={() => onSelectRun(run.id)}
                            className="text-slate-400 hover:text-brand-400 text-xs px-3 py-1 bg-slate-800/50 hover:bg-slate-800 border border-slate-700/50 hover:border-brand-500/50 rounded-lg transition-all flex items-center gap-1.5 active:scale-95"
                          >
                            <span>Voir</span>
                            <ChevronRight className="w-3 h-3" />
                          </button>
                          <button
                            onClick={() => deleteRun(run.id)}
                            disabled={isRunning}
                            title={isRunning ? 'Run en cours — impossible à supprimer' : 'Supprimer ce run'}
                            className="opacity-0 group-hover:opacity-100 p-1.5 rounded-lg text-slate-600 hover:text-red-400 hover:bg-red-500/10 border border-transparent hover:border-red-500/20 transition-all disabled:cursor-not-allowed disabled:opacity-20"
                          >
                            <Trash2 className="w-3.5 h-3.5" />
                          </button>
                        </div>
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
  { name: "AbuseIPDB Enrichment",   icon: Shield    },
  { name: "VirusTotal Enrichment",   icon: ScanEye   },
  { name: "Geolocalisation",         icon: Globe     },
  { name: "URLScan",              icon: ScanEye   },
  { name: "Enrichissement CVE",    icon: AlertTriangle },
  { name: "Classification",       icon: Sparkles      },
  { name: "MITRE Mapping",        icon: Shield        },
  { name: "Normalisation",        icon: Activity      },
  { name: "Intégration MISP",     icon: Zap           },
];

const PipelineStepper = ({ run, onStepClick, activeFilter }) => {
  const stepMap = {};
  (run?.steps || []).forEach(s => { stepMap[s.step_name] = s; });

  const activeSteps = PIPELINE_STEPS.filter(s => stepMap[s.name]);

  return (
    <div className="bg-slate-900/40 border border-white/5 p-8 rounded-3xl shadow-2xl backdrop-blur-xl relative overflow-hidden group/stepper transition-all duration-500 hover:shadow-brand-500/5 hover:border-white/10 glass-panel">
      <div className="absolute inset-0 hud-grid opacity-5 pointer-events-none" />
      <div className="flex items-center gap-0 relative z-10 overflow-x-auto pb-4 scrollbar-hide">
        {activeSteps.map((step, idx) => {
          const stepData = stepMap[step.name];
          const isLast   = idx === activeSteps.length - 1;
          const Icon     = step.icon;
          const Logo     = step.logo;

          const iconClass =
            stepData.status === 'running'  ? 'bg-brand-500 text-white shadow-[0_0_20px_rgba(14,165,233,0.4)] scale-110 border-brand-400' :
            stepData.status === 'success'  ? 'bg-emerald-500/10 text-emerald-400 border-emerald-500/30 shadow-[0_0_15px_rgba(16,185,129,0.1)]' :
            stepData.status === 'failed'   ? 'bg-red-500/10 text-red-400 border-red-500/30 shadow-[0_0_15px_rgba(239,68,68,0.1)]' :
            stepData.status === 'planned'  ? 'bg-slate-800/20 text-slate-500 border-dashed border-slate-700/50' :
            'bg-slate-800/40 text-slate-500 border-slate-700/50';

          return (
            <React.Fragment key={step.name}>
              <button 
                onClick={() => onStepClick?.(step.name)}
                className={`flex flex-col items-center flex-shrink-0 group/step transition-transform active:scale-95 ${activeFilter && activeFilter !== step.name ? 'opacity-30' : 'opacity-100'}`}
              >
                <div 
                  className={`w-12 h-12 rounded-2xl border flex items-center justify-center transition-all duration-500 ${iconClass} ${activeFilter === step.name ? 'ring-2 ring-brand-500 ring-offset-2 ring-offset-[#05060b]' : ''}`}
                >
                  {stepData.status === 'running' ? (
                    <Loader2 className="w-5 h-5 animate-spin" />
                  ) : Logo ? (
                    <img src={Logo} alt={step.name} className="w-7 h-7 object-contain" />
                  ) : (
                    <Icon className="w-5 h-5" />
                  )}
                </div>
                <div className="mt-3 text-center w-28 px-2">
                  <p className={`text-xs font-semibold uppercase tracking-wide truncate ${
                    stepData.status === 'running' ? 'text-brand-400' :
                    stepData.status === 'success' ? 'text-emerald-400' :
                    stepData.status === 'failed'  ? 'text-red-400'    : 'text-slate-500'
                  }`}>{step.name}</p>
                  <p className="text-[11px] font-mono text-slate-600 uppercase mt-1">
                    {stepData.status === 'planned' ? 'planned' : stepData.status}
                  </p>
                </div>
              </button>
              {!isLast && (
                <div className="flex-1 min-w-[20px] h-[2px] mx-2 mb-10 bg-slate-800/40 rounded-full relative overflow-hidden">
                  {(stepData.status === 'success') && (
                    <div className="absolute inset-0 bg-emerald-500/40" />
                  )}
                  {(stepData.status === 'running') && (
                    <div className="absolute inset-0 bg-brand-500 animate-pulse" />
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


const SourceStatusRow = ({ source, runs, onRun, onRunPhase, isStarting, onExplore }) => {
  // Trouver le run le plus récent spécifique à cette source (pour le statut global)
  const latestSourceRun = runs.find(r =>
    r.source_name.toLowerCase().includes(source.name.toLowerCase()) ||
    (source.id === 'nvd' && r.source_name === 'NVD')
  );

  // Construire un map des statuts de phase en parcourant TOUS les runs pertinents
  // (spécifiques à la source ET runs globaux "Unified Extraction")
  const phaseStatusMap = {};
  const relevantRuns = runs.filter(r =>
    r.source_name.toLowerCase().includes(source.name.toLowerCase()) ||
    (source.id === 'nvd' && r.source_name === 'NVD') ||
    r.source_name === 'Unified Extraction'
  );

  // Parcourir du plus ancien au plus récent pour que le plus récent écrase
  [...relevantRuns].reverse().forEach(run => {
    (run.steps || []).forEach(step => {
      if (step.status && step.status !== 'pending') {
        phaseStatusMap[step.step_name] = step.status;
      }
    });
  });

  // Fallback is always bundled inside the URLScan step — mirror its status
  if (!phaseStatusMap["Fallback"] && phaseStatusMap["URLScan"]) {
    phaseStatusMap["Fallback"] = phaseStatusMap["URLScan"];
  }

  const getPhaseStatus = (phaseFull) => {
    return phaseStatusMap[phaseFull] || 'pending';
  };

  // Le run actif : préférer le run spécifique, sinon le run global en cours
  const activeGlobalRun = runs.find(r =>
    r.status_global === 'running' && r.source_name === 'Unified Extraction'
  );
  const latestRun = latestSourceRun || activeGlobalRun || null;
  const isGlobalRunning = latestRun?.status_global === 'running' || !!activeGlobalRun;

  return (
    <tr className={`group transition-all duration-300 ${isGlobalRunning ? 'bg-brand-500/5 shadow-[inset_0_0_20px_rgba(14,165,233,0.05)]' : 'hover:bg-white/[0.02]'}`}>
      <td className="px-6 py-5">
        <div className="flex items-center gap-4">
          <div className={`w-2 h-2 rounded-full transition-all duration-500 ${
            isGlobalRunning ? 'bg-brand-500 animate-pulse shadow-[0_0_12px_#0ea5e9]' : 
            latestRun?.status_global === 'success' ? 'bg-emerald-500 shadow-[0_0_8px_#10b981]' :
            latestRun?.status_global === 'failed' ? 'bg-red-500 shadow-[0_0_8px_#ef4444]' : 'bg-slate-700'
          }`} />
          <div className="flex flex-col">
            <div className="text-sm font-black text-white uppercase tracking-tighter group-hover:text-brand-400 transition-colors">
              {source.name}
            </div>
            <div className="text-xs text-slate-500 mt-0.5">
              {source.id.toUpperCase()} • {source.type}
            </div>
          </div>
        </div>
      </td>
      
      {PIPELINE_PHASES.map(phase => {
        const status = getPhaseStatus(phase.full);
        // Only NVD is CVE-only — AlienVault has IPs/domains and needs all enrichment phases
        const isCveOnly = source.id === 'nvd';
        const isDisabled = isCveOnly && (phase.id === 'urlscan' || phase.id === 'fallback' || phase.id === 'vt');

        return (
          <td key={phase.id} className="px-1 py-5">
            <div className="flex justify-center group/phase relative">
              <button
                onClick={(e) => { e.stopPropagation(); onRunPhase(phase.full); }}
                disabled={isGlobalRunning || isStarting || isDisabled}
                className={`p-1.5 rounded-full transition-all duration-300 ${
                  isDisabled ? 'opacity-0 cursor-default' : 
                  (isGlobalRunning || isStarting) ? 'cursor-not-allowed' : 
                  'hover:bg-brand-500/20 hover:scale-125'
                }`}
              >
                <PhaseIndicator status={status} />
                
                {/* Play icon overlay on hover */}
                {!isGlobalRunning && !isStarting && !isDisabled && (
                  <div className="absolute inset-0 flex items-center justify-center opacity-0 group-hover/phase:opacity-100 transition-opacity">
                    <Play size={6} className="text-white fill-current ml-0.5" />
                  </div>
                )}
              </button>
              
              {/* Tooltip on hover */}
              {!isDisabled && (
                <div className="absolute bottom-full left-1/2 -translate-x-1/2 mb-2 px-2 py-1 bg-slate-900 border border-white/10 rounded text-[8px] font-black uppercase text-white opacity-0 group-hover/phase:opacity-100 transition-opacity pointer-events-none whitespace-nowrap z-50 shadow-2xl">
                  {phase.full}: <span className={
                    status === 'success' ? 'text-emerald-400' :
                    status === 'failed' ? 'text-red-400' :
                    status === 'running' ? 'text-brand-400' : 'text-slate-500'
                  }>{status}</span>
                  {!isGlobalRunning && !isStarting && <span className="ml-1 text-slate-500">Click to run</span>}
                </div>
              )}
            </div>
          </td>
        );
      })}

      <td className="px-6 py-5 text-right">
        <div className="flex items-center justify-end gap-3">
          {latestRun && (
            <span className="text-[10px] font-mono text-slate-600 opacity-0 group-hover:opacity-100 transition-opacity">
              Last: {latestRun.run_id.split('-')[0]}
            </span>
          )}
          <button
            onClick={onExplore}
            className="h-9 px-4 rounded-xl text-[10px] font-black uppercase tracking-widest transition-all active:scale-95 flex items-center gap-2 bg-white/5 hover:bg-white/10 text-slate-300 hover:text-white border border-white/5 hover:border-white/10 shadow-lg"
          >
            <ScanEye size={12} className="text-brand-400" />
            <span>Explore</span>
          </button>
          <button
            onClick={onRun}
            disabled={isGlobalRunning || isStarting}
            className={`h-9 px-5 rounded-xl text-[10px] font-black uppercase tracking-widest transition-all active:scale-95 flex items-center gap-2 ${
              isGlobalRunning 
                ? 'bg-slate-800 text-slate-600 border border-slate-700' 
                : 'bg-brand-500/10 hover:bg-brand-500 text-brand-400 hover:text-white border border-brand-500/30 hover:border-brand-400 shadow-lg shadow-brand-500/5'
            }`}
          >
            {isGlobalRunning ? <Loader2 size={12} className="animate-spin" /> : <Play size={10} className="fill-current" />}
            <span>{isGlobalRunning ? 'Syncing' : 'Run'}</span>
          </button>
        </div>
      </td>
    </tr>
  );
};

const PhaseIndicator = ({ status }) => {
  const map = {
    running: "bg-brand-500 shadow-[0_0_15px_#0ea5e9] animate-pulse scale-125",
    success: "bg-emerald-500 shadow-[0_0_10px_#10b981]",
    failed:  "bg-red-500 shadow-[0_0_10px_#ef4444]",
    pending: "bg-slate-800 border border-white/5 opacity-30",
  };
  
  return (
    <div className={`w-2.5 h-2.5 rounded-full transition-all duration-700 ${map[status] || map.pending}`} />
  );
};

// ── Source Card (REMOVED) ─────────
const SourceCard = null;

/**
 * Reusable row for pipeline steps
 */
const StepRow = ({ idx, step, isRunning, onRunStep }) => (
  <div className="flex items-center justify-between group/step">
    <div className="flex items-center gap-3">
      <span className="text-[10px] text-slate-700 font-black font-mono w-3">{idx + 1}.</span>
      <span className={`text-[11px] font-bold ${isRunning ? 'text-slate-700' : 'text-slate-400 group-hover/step:text-slate-200 transition-colors'}`}>
        {step}
      </span>
    </div>
    <button
      onClick={(e) => { e.stopPropagation(); onRunStep(); }}
      disabled={isRunning}
      className={`p-1.5 rounded-lg bg-slate-800/50 border border-slate-700/50 transition-all ${
        isRunning ? 'opacity-20 cursor-not-allowed' : 'hover:bg-brand-600 hover:border-brand-500 hover:text-white text-slate-600 hover:shadow-[0_0_10px_rgba(14,165,233,0.3)] hover:scale-110'
      }`}
    >
      <Play size={10} className="fill-current" />
    </button>
  </div>
);

// ── Stats Card ────────────────────────────────────────────────────────────────
const StatCard = ({ icon, label, value, sub, color, loading }) => {
  const colorBg = {
    blue:    'from-blue-500/20 to-slate-900/40 border-blue-500/30 hover:shadow-[0_0_30px_rgba(59,130,246,0.1)]',
    purple:  'from-purple-500/20 to-slate-900/40 border-purple-500/30 hover:shadow-[0_0_30px_rgba(168,85,247,0.1)]',
    emerald: 'from-emerald-500/20 to-slate-900/40 border-emerald-500/30 hover:shadow-[0_0_30px_rgba(16,185,129,0.1)]',
    orange:  'from-orange-500/20 to-slate-900/40 border-orange-500/30 hover:shadow-[0_0_30px_rgba(249,115,22,0.1)]',
  };
  return (
    <div className={`bg-gradient-to-br backdrop-blur-md ${colorBg[color]} border rounded-2xl p-6 relative overflow-hidden group transition-all duration-500 hover:-translate-y-0.5`}>
      {loading && <div className="scan-beam" />}

      <div className="relative z-10">
        <div className="flex items-center gap-2 mb-3">
          <div className="p-1.5 bg-slate-800/80 rounded-lg group-hover:scale-110 transition-transform">{icon}</div>
          <span className="text-slate-400 text-xs font-semibold uppercase tracking-wider">{label}</span>
        </div>
        {loading
          ? (
            <div className="space-y-2 py-1">
              <div className="h-6 w-24 bg-brand-500/10 border border-brand-500/20 rounded-md" />
              <div className="h-3 w-12 bg-slate-800/50 rounded" />
            </div>
          )
          : <div className="text-3xl font-bold text-white tracking-tight">{value}</div>
        }
        {!loading && <p className="text-xs text-slate-500 mt-1">{sub}</p>}
      </div>
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
    <span className={`inline-flex items-center gap-1 px-2 py-1 rounded-md border text-xs font-semibold uppercase tracking-wide ${cls} ${pulse ? 'animate-pulse' : ''}`}>
      {status}
    </span>
  );
};

// ── Phase Card (Operational Center) ──────────────────────────────────────────
const PhaseCard = ({ title, subtitle, icon, color, sources, onAction, isRunning }) => {
  const [selectedSourceId, setSelectedSourceId] = useState(sources[0]?.id || '');
  
  const colors = {
    emerald: "from-emerald-500/20 via-emerald-500/5 to-transparent border-emerald-500/30 text-emerald-400 btn-emerald",
    orange: "from-orange-500/20 via-orange-500/5 to-transparent border-orange-500/30 text-orange-400 btn-orange",
  };

  const btnColors = {
    emerald: "bg-emerald-500 hover:bg-emerald-400 shadow-emerald-500/20",
    orange: "bg-orange-500 hover:bg-orange-400 shadow-orange-500/20",
  };

  const selectedSource = sources.find(s => s.id === selectedSourceId);

  return (
    <div className={`relative overflow-hidden rounded-3xl border bg-gradient-to-br ${colors[color]} p-6 transition-all duration-300 hover:shadow-2xl`}>
      <div className="absolute inset-0 hud-grid opacity-10" />
      
      <div className="relative z-10 flex flex-col gap-6">
        <div className="flex items-center justify-between">
          <div className="flex items-center gap-4">
            <div className={`p-3 bg-slate-900/80 rounded-2xl border border-white/10 shadow-inner`}>
              {icon}
            </div>
            <div>
              <h3 className="text-xl font-black tracking-tighter text-white uppercase">{title}</h3>
              <p className="text-[10px] font-bold text-slate-500 uppercase tracking-widest">{subtitle}</p>
            </div>
          </div>
          <div className="h-10 w-10 rounded-full bg-slate-900/50 border border-white/5 flex items-center justify-center">
            <ChevronRight className="w-5 h-5 text-slate-700" />
          </div>
        </div>

        <div className="flex flex-col gap-3">
          <label className="text-xs font-semibold text-slate-500 uppercase tracking-wider ml-1">Sélectionner la Source</label>
          <div className="flex gap-2">
            <select 
              value={selectedSourceId}
              onChange={(e) => setSelectedSourceId(e.target.value)}
              disabled={isRunning}
              className="flex-1 bg-slate-900/80 border border-slate-700 text-white rounded-xl px-4 py-3 text-xs font-bold focus:outline-none focus:border-brand-500 transition-colors appearance-none cursor-pointer"
            >
              {sources.map(s => (
                <option key={s.id} value={s.id}>{s.name.toUpperCase()}</option>
              ))}
            </select>
            
            <button 
              onClick={() => onAction(selectedSource)}
              disabled={isRunning || !selectedSourceId}
              className={`px-6 py-3 rounded-xl text-white font-black text-xs uppercase tracking-widest transition-all active:scale-95 flex items-center gap-2 shadow-lg disabled:opacity-30 disabled:cursor-not-allowed ${btnColors[color]}`}
            >
              {isRunning ? <Loader2 className="w-4 h-4 animate-spin" /> : <Play className="w-4 h-4 fill-current" />}
              <span>Lancer</span>
            </button>
          </div>
        </div>
      </div>

      {/* Decorative Brackets */}
      <div className="hud-corner hud-corner-tl !border-slate-700" />
      <div className="hud-corner hud-corner-br !border-slate-700" />
    </div>
  );
};

export default Dashboard;

