import React, { useState, useEffect } from 'react';
import axios from 'axios';
import logo from '../assets/logo.png';
import {
  Play, Shield, Activity, Clock, FileText,
  Database, AlertTriangle, CheckCircle2, Loader2, Zap, Sparkles, Square,
  Download, Search, Cpu, Globe, Languages, ScanEye, Layers, ChevronRight,
  ChevronDown, ChevronUp
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

const ArrowConnector = () => (
  <div className="flex items-center pb-4 px-1">
    <div className="w-3 h-px bg-slate-700" />
    <div className="w-0 h-0 border-t-[3px] border-t-transparent border-b-[3px] border-b-transparent border-l-[4px] border-l-slate-600" />
  </div>
);

const Dashboard = ({ onSelectRun }) => {
  const [runs,           setRuns]           = useState([]);
  const [stats,          setStats]          = useState(null);
  const [loading,        setLoading]        = useState(true);
  const [stopping,       setStopping]       = useState(false);
  const [runningSources, setRunningSources] = useState(new Set());
  const [showEnrichDetails, setShowEnrichDetails] = useState(false);

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

  const startGlobalStep = async (stepName) => {
    try {
      const res = await axios.post(
        `${API_BASE}/runs/targeted`,
        { source_name: 'Unified Extraction', source_type: 'All Sources' },
        { params: { step_name: stepName } }
      );
      if (res.data && res.data.id) {
        onSelectRun(res.data.id);
      }
      fetchAll();
    } catch (e) {
      console.error('Error starting global step:', e);
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
      {/* ── Top Global Cyber Loading Bar ── */}
      {loading && (
        <div className="fixed top-0 left-0 w-full h-1.5 z-[100] bg-[#0a0d1a] border-b border-brand-500/20">
          <div className="absolute top-0 h-full cyber-loading-bar animate-indeterminate shadow-[0_0_15px_#0ea5e9]" />
        </div>
      )}

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
          <div className="flex flex-col items-end gap-3">
            {/* HUD Pipeline Control Panel */}
            <div className="flex items-center gap-0 bg-slate-900/80 border border-slate-700/60 rounded-2xl p-1.5 shadow-xl backdrop-blur-sm">
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
                  stats?.running_runs > 0
                    ? 'bg-slate-800 border-slate-700 text-slate-600'
                    : 'bg-cyan-500/10 border-cyan-500/30 text-cyan-400 group-hover:bg-cyan-500/20 group-hover:border-cyan-400 group-hover:shadow-[0_0_12px_rgba(6,182,212,0.3)]'
                }`}>
                  <Download className="w-3.5 h-3.5" />
                </div>
                <span className={`text-[9px] font-bold uppercase tracking-wider transition-colors ${
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
                <span className={`text-[9px] font-bold uppercase tracking-wider transition-colors ${
                  stats?.running_runs > 0 ? 'text-slate-600' : 'text-slate-500 group-hover:text-violet-400'
                }`}>Extraction</span>
              </button>

              <ArrowConnector />

              {/* Master Enrichment Control */}
              <div className="flex items-center gap-0.5 bg-amber-500/5 rounded-2xl p-0.5 border border-amber-500/10">
                <button
                  onClick={() => startGlobalStep('Enrichissement')}
                  disabled={stats?.running_runs > 0}
                  title="Lancer l'Enrichissement Complet (NLP + G\u00e9o + Scan) - Toutes sources"
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
                    <span className="text-[10px] font-black uppercase tracking-widest">Enrichir</span>
                    <span className="text-[8px] text-amber-500/50 uppercase font-mono mt-1">Unified Stage</span>
                  </div>
                </button>
                
                <button
                  onClick={() => setShowEnrichDetails(!showEnrichDetails)}
                  className={`p-2 rounded-lg transition-colors ${showEnrichDetails ? 'bg-amber-500/20 text-white' : 'text-amber-500/40 hover:text-amber-400'}`}
                  title={showEnrichDetails ? "Masquer les sous-\u00e9tapes" : "Afficher les sous-\u00e9tapes (NLP, G\u00e9o, Scan)"}
                >
                  {showEnrichDetails ? <ChevronUp size={14} /> : <ChevronDown size={14} />}
                </button>
              </div>

              {/* Expandable Sub-steps Area */}
              {showEnrichDetails && (
                <div className="flex items-center animate-in slide-in-from-left duration-300">
                  <ArrowConnector />
                  
                  {/* NLP */}
                  <button
                    onClick={() => startGlobalStep('NLP Enrichment')}
                    disabled={stats?.running_runs > 0}
                    title="Stage 1: NLP Enrichment"
                    className="flex flex-col items-center gap-1 px-3 py-1 group/step"
                  >
                    <div className="w-7 h-7 rounded bg-indigo-500/10 border border-indigo-500/20 flex items-center justify-center text-indigo-400 group-hover/step:bg-indigo-500 group-hover/step:text-white transition-all">
                      <Languages size={12} />
                    </div>
                    <span className="text-[8px] font-bold text-slate-600 group-hover/step:text-indigo-400 uppercase">NLP</span>
                  </button>

                  {/* GEO */}
                  <button
                    onClick={() => startGlobalStep('Geolocalisation')}
                    disabled={stats?.running_runs > 0}
                    title="Stage 2: Geolocation"
                    className="flex flex-col items-center gap-1 px-3 py-1 group/step"
                  >
                    <div className="w-7 h-7 rounded bg-emerald-500/10 border border-emerald-500/20 flex items-center justify-center text-emerald-400 group-hover/step:bg-emerald-500 group-hover/step:text-white transition-all">
                      <Globe size={12} />
                    </div>
                    <span className="text-[8px] font-bold text-slate-600 group-hover/step:text-emerald-400 uppercase">Geo</span>
                  </button>

                  {/* SCAN */}
                  <button
                    onClick={() => startGlobalStep('URLScan')}
                    disabled={stats?.running_runs > 0}
                    title="Stage 3: URLScan Analysis"
                    className="flex flex-col items-center gap-1 px-3 py-1 group/step"
                  >
                    <div className="w-7 h-7 rounded bg-pink-500/10 border border-pink-500/20 flex items-center justify-center text-pink-400 group-hover/step:bg-pink-500 group-hover/step:text-white transition-all">
                      <ScanEye size={12} />
                    </div>
                    <span className="text-[8px] font-bold text-slate-600 group-hover/step:text-pink-400 uppercase">Scan</span>
                  </button>
                </div>
              )}

              {/* Separator */}
              <div className="w-px h-10 bg-slate-700 mx-2" />



              {/* Full pipeline button */}
              <button
                onClick={() => startRun()}
                disabled={stats?.running_runs > 0}
                className={`flex items-center gap-2 px-5 py-2.5 rounded-xl font-bold transition-all duration-200 shadow-lg active:scale-95 text-sm mr-0.5 ${
                  stats?.running_runs > 0
                    ? 'bg-slate-800 text-slate-500 cursor-not-allowed shadow-none'
                    : 'bg-brand-600 hover:bg-brand-500 text-white shadow-brand-600/30 hover:shadow-brand-600/50 hover:shadow-lg'
                }`}
              >
                {stats?.running_runs > 0
                  ? <Loader2 className="w-4 h-4 animate-spin" />
                  : <Zap className="w-4 h-4" />
                }
                <span>{stats?.running_runs > 0 ? 'En cours...' : 'Pipeline Complet'}</span>
              </button>
            </div>

            {/* Subtle label below */}
            <p className="text-[9px] text-slate-600 font-mono tracking-wider pr-2">
              PIPELINE GLOBAL — TOUTES SOURCES
            </p>
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
                          className="text-slate-400 hover:text-brand-400 text-xs px-3 py-1 bg-slate-800/50 hover:bg-slate-800 border border-slate-700/50 hover:border-brand-500/50 rounded-lg transition-all flex items-center gap-1.5 ml-auto active:scale-95"
                        >
                          <span>Voir</span>
                          <ChevronRight className="w-3 h-3" />
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
  { name: "Enrichissement",        icon: Sparkles  },
  { name: "NLP Enrichment",       icon: Languages },
  { name: "Geolocalisation",      icon: Globe     },
  { name: "URLScan",              icon: ScanEye   },
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
  // Liste des étapes pour le lancement ciblé
  const STEPS = [
    "Collecte",
    "Extraction CVE / IOC",
    "NLP Enrichment",
    "Geolocalisation",
    "URLScan",
    "Intégration MISP"
  ];
  const isNVD = source.id === 'nvd' || source.id === 'alienvault';

  return (
    <div 
      className={`rounded-2xl border transition-all duration-500 relative overflow-hidden group/card shadow-2xl ${
        isRunning 
          ? `bg-slate-900 border-brand-500/50 ring-1 ring-brand-500/30` 
          : `bg-[#111827]/80 border-slate-800/60 hover:border-slate-700`
      }`}
    >
      {/* HUD Elements for active source */}
      {isRunning && (
        <>
          <div className="absolute inset-0 hud-grid opacity-20" />
          <div className="scan-beam" />
          <div className="hud-corner-tl hud-corner" />
          <div className="hud-corner-tr hud-corner" />
          <div className="hud-corner-bl hud-corner" />
          <div className="hud-corner-br hud-corner" />
          <div className="absolute bottom-0 left-0 w-full h-[2px] cyber-loading-bar animate-indeterminate" />
        </>
      )}

      {/* Header Info */}
      <div className="p-4 relative z-10">
        <div className="flex items-center justify-between mb-3 text-slate-500 uppercase tracking-widest font-black text-[9px] opacity-60">
          <span>{source.type}</span>
          <div className="flex items-center gap-1.5">
            <div className={`p-0.5 rounded-full ${isRunning ? 'bg-brand-500 animate-pulse' : 'bg-slate-800 opacity-0'}`} />
            <div className={`w-3 h-3 rounded bg-slate-800 border border-slate-700 flex items-center justify-center`}>
              <ChevronRight className={`w-2 h-2 text-slate-500 transition-transform ${isRunning ? 'rotate-90 text-brand-400' : ''}`} />
            </div>
          </div>
        </div>
        <h3 className="text-white font-black text-sm tracking-tight mb-5 group-hover/card:text-brand-400 transition-colors uppercase">{source.name}</h3>
        
        {/* Extraction Section */}
        <div className="space-y-3 mb-5">
          <p className="text-[9px] text-slate-600 font-extrabold uppercase tracking-widest border-b border-slate-800/60 pb-1.5 mb-2">1. Extraction / Collecte</p>
          <div className="space-y-2.5">
            {STEPS.slice(0, 2).map((step, idx) => (
              <StepRow key={step} idx={idx} step={step} isRunning={isRunning} onRunStep={() => onRunStep(step)} />
            ))}
          </div>
        </div>
        
        {/* Enrichment Section (Skip for NVD/AlienVault) */}
        {!isNVD && (
          <div className="bg-brand-500/5 rounded-xl p-3 border border-brand-500/10 mb-5">
            <div className="flex items-center justify-between mb-3">
              <p className="text-[9px] text-brand-400 font-black uppercase tracking-widest">2. Enrichissement</p>
              <button
                onClick={(e) => { e.stopPropagation(); onRunStep('Enrichissement'); }}
                disabled={isRunning}
                title="Lancer tout l'enrichissement"
                className={`flex items-center gap-1.5 px-2 py-1 rounded bg-brand-500/10 border border-brand-500/30 text-brand-400 text-[8px] font-black uppercase tracking-wider hover:bg-brand-500 hover:text-white transition-all ${isRunning ? 'opacity-20 cursor-not-allowed' : 'active:scale-90 shadow-md shadow-brand-500/10'}`}
              >
                <Sparkles size={8} />
                <span>Tout lancer</span>
              </button>
            </div>
            <div className="space-y-2.5">
              {STEPS.slice(2, 5).map((step, idx) => (
                <StepRow key={step} idx={idx + 2} step={step} isRunning={isRunning} onRunStep={() => onRunStep(step)} />
              ))}
            </div>
          </div>
        )}

        {/* Finalisation Section */}
        <div className="space-y-3 mb-6">
          <p className="text-[9px] text-slate-600 font-extrabold uppercase tracking-widest border-b border-slate-800/60 pb-1.5 mb-2">3. Finalisation</p>
          <div className="space-y-2.5">
            <StepRow idx={5} step={STEPS[5]} isRunning={isRunning} onRunStep={() => onRunStep(STEPS[5])} />
          </div>
        </div>

        {/* Action Buttons */}
        <div className="space-y-3 pt-4 border-t border-slate-800/60">
          <button
            onClick={() => onRun()}
            disabled={isRunning}
            className={`w-full py-3 rounded-xl text-[11px] font-black transition-all flex items-center justify-center gap-2 group/btn ${
              isRunning ? 'bg-slate-900 border border-slate-800 text-slate-700 cursor-not-allowed' :
              'bg-brand-600/10 hover:bg-brand-600 border border-brand-500/20 hover:border-brand-500 text-brand-400 hover:text-white shadow-lg hover:shadow-brand-500/20 active:scale-95'
            }`}
          >
            {isRunning ? <Loader2 size={12} className="animate-spin" /> : <Play size={12} className="group-hover/btn:animate-pulse" />}
            <span className="uppercase tracking-widest">Lancer le Pipeline</span>
          </button>

          <button
            onClick={() => window.open(`${API_BASE}/results/`, '_blank')}
            className="w-full py-2.5 rounded-xl text-[11px] font-black bg-slate-800/40 hover:bg-slate-800 text-slate-500 hover:text-slate-300 border border-slate-700/50 hover:border-slate-600 transition-all flex items-center justify-center gap-2 active:scale-95 group/explore"
          >
            <FileText size={12} className="group-hover/explore:scale-110 transition-transform" />
            <span className="uppercase tracking-widest">Explorer les Sources</span>
          </button>
        </div>
      </div>
    </div>
  );
};

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
    blue:    'from-blue-500/10 to-transparent border-blue-500/20',
    purple:  'from-purple-500/10 to-transparent border-purple-500/20',
    emerald: 'from-emerald-500/10 to-transparent border-emerald-500/20',
    orange:  'from-orange-500/10 to-transparent border-orange-500/20',
  };
  return (
    <div className={`bg-gradient-to-br ${colorBg[color]} border rounded-2xl p-5 relative overflow-hidden group transition-all duration-300 hover:shadow-lg hover:border-brand-500/40`}>
      {loading && <div className="absolute inset-0 hud-grid" />}
      {loading && <div className="scan-beam" />}
      
      {/* Corner Brackets */}
      {loading && (
        <>
          <div className="hud-corner hud-corner-tl" />
          <div className="hud-corner hud-corner-tr" />
          <div className="hud-corner hud-corner-bl" />
          <div className="hud-corner hud-corner-br" />
        </>
      )}

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
          : <div className="text-2xl font-extrabold text-white tracking-tight">{value}</div>
        }
        {!loading && <p className="text-[10px] text-slate-600 mt-1 font-mono">{sub}</p>}
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
    <span className={`inline-flex items-center gap-1 px-2 py-0.5 rounded-md border text-[10px] font-bold uppercase tracking-wider ${cls} ${pulse ? 'animate-pulse' : ''}`}>
      {status}
    </span>
  );
};

export default Dashboard;
