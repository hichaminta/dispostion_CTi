import React, { useState, useEffect, useRef, useCallback } from 'react';
import axios from 'axios';
import logo from '../assets/logo.png';
import {
  ChevronLeft, Terminal, BarChart3, CheckCircle2,
  XCircle, Loader2, Circle, Shield, Cpu, Database, Zap, Square,
  Globe, Languages, ScanEye
} from 'lucide-react';

const API_BASE = "http://localhost:8000";
const WS_BASE  = "ws://localhost:8000/ws";

// ─── Config étapes ────────────────────────────────────────────────────────────
const PIPELINE_STEPS = [
  { name: "Collecte",             icon: Database,  color: "blue"   },
  { name: "Extraction CVE / IOC", icon: Cpu,       color: "violet" },
  { name: "NLP Enrichment",       icon: Languages, color: "indigo" },
  { name: "Geolocalisation",      icon: Globe,     color: "emerald"},
  { name: "URLScan",              icon: ScanEye,   color: "pink"   },
  { name: "Normalisation",        icon: Shield,    color: "cyan"   },
  { name: "Intégration MISP",     icon: Zap,       color: "orange" },
];

const COLOR_MAP = {
  blue:    { bg: "bg-blue-500/10",    border: "border-blue-500/30",    text: "text-blue-400",    ring: "ring-blue-500",    dot: "bg-blue-500"    },
  violet:  { bg: "bg-violet-500/10",  border: "border-violet-500/30",  text: "text-violet-400",  ring: "ring-violet-500",  dot: "bg-violet-500"  },
  indigo:  { bg: "bg-indigo-500/10",  border: "border-indigo-500/30",  text: "text-indigo-400",  ring: "ring-indigo-500",  dot: "bg-indigo-500"  },
  emerald: { bg: "bg-emerald-500/10", border: "border-emerald-500/30", text: "text-emerald-400", ring: "ring-emerald-500", dot: "bg-emerald-500" },
  pink:    { bg: "bg-pink-500/10",    border: "border-pink-500/30",    text: "text-pink-400",    ring: "ring-pink-500",    dot: "bg-pink-500"    },
  cyan:    { bg: "bg-cyan-500/10",    border: "border-cyan-500/30",    text: "text-cyan-400",    ring: "ring-cyan-500",    dot: "bg-cyan-500"    },
  orange:  { bg: "bg-orange-500/10",  border: "border-orange-500/30",  text: "text-orange-400",  ring: "ring-orange-500",  dot: "bg-orange-500"  },
  amber:   { bg: "bg-amber-500/10",   border: "border-amber-500/30",   text: "text-amber-400",   ring: "ring-amber-500",   dot: "bg-amber-500"   },
};

// ─── Icônes de statut ─────────────────────────────────────────────────────────
const StatusIcon = ({ status, size = "w-5 h-5" }) => {
  if (status === "success") return <CheckCircle2 className={`${size} text-emerald-400`} />;
  if (status === "failed")  return <XCircle className={`${size} text-red-400`} />;
  if (status === "running") return <Loader2 className={`${size} text-blue-400 animate-spin`} />;
  if (status === "planned") return <Circle className={`${size} text-slate-500 opacity-50 border-dashed`} />;
  return <Circle className={`${size} text-slate-600`} />;
};

// ─── Coloration des lignes de log ─────────────────────────────────────────────
const colorLine = (line) => {
  if (/✓|OK|succès|terminé|completed|success/i.test(line))  return "text-emerald-400";
  if (/✗|ERROR|ERREUR|échoué|failed|exception/i.test(line)) return "text-red-400";
  if (/⚠|WARN|warning|partiel/i.test(line))                 return "text-yellow-400";
  if (/═══|──|DÉMARRAGE|ÉTAPE/i.test(line))                 return "text-brand-300 font-semibold";
  if (/\$/i.test(line))                                      return "text-slate-400";
  if (/IOC|CVE|IOCs|CVEs/i.test(line))                      return "text-purple-400";
  return "text-slate-300";
};

// ─── Composant RunDetail ──────────────────────────────────────────────────────
const RunDetail = ({ runId, onBack }) => {
  const [run,        setRun]        = useState(null);
  const [loading,    setLoading]    = useState(true);
  const [stopping,   setStopping]   = useState(false);
  const [activeStep, setActiveStep] = useState(null);
  const [allLogs,    setAllLogs]    = useState([]); // [{step, line}]
  const logEndRef      = useRef(null);
  const externalRunRef = useRef(null); // UUID externe, utilisé pour filtrer les WS

  // Auto-scroll
  const scrollToBottom = useCallback(() => {
    logEndRef.current?.scrollIntoView({ behavior: "smooth" });
  }, []);

  useEffect(() => { scrollToBottom(); }, [allLogs, scrollToBottom]);

  const handleStop = async () => {
    if (!run) return;
    setStopping(true);
    try {
      await axios.post(`${API_BASE}/runs/${runId}/stop`);
      // Update local state immediately for better UX
      setRun(prev => prev ? { ...prev, status_global: "failed" } : prev);
    } catch (e) {
      console.error("Error stopping run:", e);
    } finally {
      setStopping(false);
    }
  };

  // ... (fetchRun and WebSocket effect remain unchanged)

  // 1. Charger run initial
  const fetchRun = useCallback(async () => {
    try {
      const { data } = await axios.get(`${API_BASE}/runs/${runId}`);
      setRun(data);
      // Stocker l'UUID externe pour filtrer les WS
      externalRunRef.current = data.run_id;
      // Reconstruire les logs depuis les étapes
      const logs = [];
      (data.steps || []).forEach(step => {
        (step.logs || []).forEach(line => {
          logs.push({ step: step.step_name, line });
        });
      });
      setAllLogs(logs);
    } catch (e) {
      console.error(e);
    } finally {
      setLoading(false);
    }
  }, [runId]);

  useEffect(() => {
    fetchRun();

    // WebSocket pour mises à jour temps réel
    const ws = new WebSocket(WS_BASE);

    ws.onmessage = (evt) => {
      const data = JSON.parse(evt.data);
      // Filtrer : ignorer les messages d'autres runs
      if (externalRunRef.current && data.run_id && data.run_id !== externalRunRef.current) return;

      if (data.type === "log") {
        setAllLogs(prev => [...prev, { step: data.step_name, line: data.line }]);
      } else if (data.type === "step_update") {
        setRun(prev => {
          if (!prev) return prev;
          const updatedSteps = prev.steps.map(s =>
            s.step_name === data.step_name
              ? { ...s, status: data.status, ioc_count: data.ioc_count, cve_count: data.cve_count }
              : s
          );
          return { ...prev, steps: updatedSteps };
        });
      } else if (data.type === "run_complete") {
        setRun(prev => prev ? { ...prev, status_global: data.status } : prev);
        fetchRun(); // Refresh final pour récupérer tous les logs
      }
    };

    ws.onerror = () => {};
    return () => ws.close();
  }, [runId, fetchRun]);

  if (loading) return (
    <div className="min-h-screen flex items-center justify-center">
      <div className="text-center">
        <Loader2 className="w-10 h-10 text-brand-500 animate-spin mx-auto mb-4" />
        <p className="text-slate-400">Chargement du run...</p>
      </div>
    </div>
  );

  if (!run) return (
    <div className="p-20 text-center text-red-400">Run introuvable.</div>
  );

  const stepMap = {};
  (run.steps || []).forEach(s => { stepMap[s.step_name] = s; });

  const totalIOC = (run.steps || []).reduce((a, s) => a + (s.ioc_count || 0), 0);
  const totalCVE = (run.steps || []).reduce((a, s) => a + (s.cve_count || 0), 0);

  // Logs filtrés selon l'étape active
  const displayedLogs = activeStep
    ? allLogs.filter(l => l.step === activeStep)
    : allLogs;

  return (
    <div className="min-h-screen bg-[#0a0d1a] p-6">
      {/* Header */}
      <div className="max-w-[1600px] mx-auto">
        <button
          onClick={onBack}
          className="flex items-center space-x-2 text-slate-400 hover:text-white mb-6 transition-colors group"
        >
          <ChevronLeft className="w-5 h-5 group-hover:-translate-x-1 transition-transform" />
          <span className="text-sm font-medium">Retour au Dashboard</span>
        </button>

        {/* Run title */}
        <div className="flex items-center justify-between mb-8">
          <div className="flex flex-col items-start gap-2">
            <img src={logo} alt="BlueSec Logo" className="h-6 w-auto object-contain" />
            <div className="flex items-center gap-3">
              <span className="text-sm font-mono text-slate-500">#{run.run_id.split('-')[0].toUpperCase()}</span>
              <span className="w-1 h-1 bg-slate-700 rounded-full" />
              <p className="text-slate-500 text-[10px] uppercase font-bold tracking-wider">{run.source_name} • {run.source_type}</p>
            </div>
          </div>
          <div className="flex items-center gap-3">
            {run.status_global === "running" && (
              <button
                onClick={handleStop}
                disabled={stopping}
                className="flex items-center gap-2 bg-red-500/10 hover:bg-red-500/20 text-red-400 border border-red-500/30 px-4 py-1.5 rounded-lg text-xs font-bold transition-all active:scale-95 disabled:opacity-50"
              >
                {stopping ? <Loader2 className="w-4 h-4 animate-spin" /> : <Square className="w-4 h-4 fill-current" />}
                <span>{stopping ? "Arrêt..." : "Arrêter"}</span>
              </button>
            )}
            <StatusBadge status={run.status_global} />
          </div>
        </div>

        <div className="grid grid-cols-1 xl:grid-cols-[1fr_420px] gap-6">
          {/* ── Colonne gauche : Steps + Terminal ───────────────────────── */}
          <div className="space-y-4">
            <div className={`grid gap-3 ${
              PIPELINE_STEPS.filter(s => stepMap[s.name]).length > 2 
                ? 'grid-cols-2 md:grid-cols-4' 
                : 'grid-cols-1 md:grid-cols-2'
            }`}>
              {PIPELINE_STEPS.filter(s => stepMap[s.name]).map((step, idx) => {
                const stepData = stepMap[step.name];
                const c = COLOR_MAP[step.color];
                const isActive = stepData.status === 'running';
                const isActiveFilter = activeStep === step.name;

                return (
                  <button
                    key={step.name}
                    onClick={() => setActiveStep(isActiveFilter ? null : step.name)}
                    className={`p-4 rounded-xl border text-left transition-all duration-200 ${
                      isActiveFilter
                        ? `${c.bg} ${c.border} ring-1 ${c.ring} ring-offset-1 ring-offset-[#0a0d1a]`
                        : 'bg-slate-900/50 border-slate-800 hover:border-slate-700'
                    }`}
                  >
                    <div className="flex items-center justify-between mb-3">
                      <step.icon className={`w-4 h-4 ${isActiveFilter ? c.text : 'text-slate-500'}`} />
                      <StatusIcon status={stepData.status} size="w-4 h-4" />
                    </div>
                    <p className={`text-xs font-semibold mb-1 ${isActiveFilter ? c.text : 'text-white'}`}>
                      {step.name}
                    </p>
                    <div className="flex items-center gap-1">
                      {isActive && (
                        <span className={`w-1.5 h-1.5 rounded-full ${c.dot} animate-ping`} />
                      )}
                      <span className="text-[10px] text-slate-500 font-mono uppercase">
                        {stepData.status}
                      </span>
                    </div>
                    {(stepData.ioc_count > 0 || stepData.cve_count > 0) && (
                      <div className="flex gap-1 mt-2 flex-wrap">
                        {stepData.ioc_count > 0 && (
                          <span className="px-1.5 py-0.5 bg-blue-500/10 text-blue-400 text-[9px] rounded border border-blue-500/20 font-mono">
                            {stepData.ioc_count} IOC
                          </span>
                        )}
                        {stepData.cve_count > 0 && (
                          <span className="px-1.5 py-0.5 bg-purple-500/10 text-purple-400 text-[9px] rounded border border-purple-500/20 font-mono">
                            {stepData.cve_count} CVE
                          </span>
                        )}
                      </div>
                    )}
                  </button>
                );
              })}
            </div>

            {/* ── Terminal ───────────────────────────────────────────────── */}
            <div className="bg-[#0d1117] rounded-2xl border border-slate-800 overflow-hidden flex flex-col"
                 style={{ minHeight: '520px' }}>
              {/* Barre terminale */}
              <div className="flex items-center justify-between px-4 py-3 border-b border-slate-800/80 bg-slate-900/60">
                <div className="flex items-center gap-3">
                  <div className="flex gap-1.5">
                    <div className="w-3 h-3 rounded-full bg-red-500/70" />
                    <div className="w-3 h-3 rounded-full bg-yellow-500/70" />
                    <div className="w-3 h-3 rounded-full bg-emerald-500/70" />
                  </div>
                  <div className="flex items-center gap-2 text-slate-400">
                    <Terminal className="w-3.5 h-3.5" />
                    <span className="text-xs font-mono">
                      CTI Pipeline — Live Logs
                      {activeStep && <span className="text-brand-400 ml-2">[ {activeStep} ]</span>}
                    </span>
                  </div>
                </div>
                <div className="flex items-center gap-2">
                  {/* Filtre par étape */}
                  <div className="flex gap-1">
                    {PIPELINE_STEPS.map(step => {
                      const c = COLOR_MAP[step.color];
                      const isF = activeStep === step.name;
                      return (
                        <button
                          key={step.name}
                          onClick={() => setActiveStep(isF ? null : step.name)}
                          title={step.name}
                          className={`px-2 py-0.5 rounded text-[10px] font-mono transition-all ${
                            isF ? `${c.bg} ${c.text} ${c.border} border` : 'text-slate-600 hover:text-slate-400'
                          }`}
                        >
                          {step.name.split(' ')[0]}
                        </button>
                      );
                    })}
                  </div>
                  <span className="text-[10px] text-slate-600 font-mono ml-2">
                    {displayedLogs.length} lignes
                  </span>
                </div>
              </div>

              {/* Logs scrollables */}
              <div className="flex-1 overflow-y-auto p-4 font-mono text-xs leading-6"
                   style={{ maxHeight: '540px' }}>
                {displayedLogs.length === 0 ? (
                  <div className="flex flex-col items-center justify-center h-48 text-slate-600">
                    <Terminal className="w-8 h-8 mb-3 opacity-30" />
                    <p>En attente de logs...</p>
                  </div>
                ) : (
                  <div className="space-y-0.5">
                    {displayedLogs.map((entry, i) => (
                      <div key={i} className={`whitespace-pre-wrap break-all ${colorLine(entry.line)}`}>
                        {entry.line}
                      </div>
                    ))}
                    <div ref={logEndRef} />
                  </div>
                )}
              </div>

              {/* Pied du terminal */}
              <div className="px-4 py-2 border-t border-slate-800/60 bg-slate-900/40 flex items-center gap-2">
                {run.status_global === 'running' ? (
                  <>
                    <span className="w-2 h-2 bg-brand-500 rounded-full animate-pulse" />
                    <span className="text-[10px] text-brand-400 font-mono">Pipeline en cours d'exécution...</span>
                  </>
                ) : run.status_global === 'success' ? (
                  <>
                    <span className="w-2 h-2 bg-emerald-500 rounded-full" />
                    <span className="text-[10px] text-emerald-400 font-mono">Pipeline terminé avec succès</span>
                  </>
                ) : run.status_global === 'failed' ? (
                  <>
                    <span className="w-2 h-2 bg-red-500 rounded-full" />
                    <span className="text-[10px] text-red-400 font-mono">Pipeline terminé avec des erreurs</span>
                  </>
                ) : (
                  <span className="text-[10px] text-slate-600 font-mono">En attente...</span>
                )}
              </div>
            </div>
          </div>

          {/* ── Colonne droite : Résumé ──────────────────────────────────── */}
          <div className="space-y-4">
            {/* Métriques globales */}
            <div className="bg-slate-900/50 rounded-2xl border border-slate-800 p-5">
              <h3 className="text-sm font-bold text-white mb-4 flex items-center gap-2">
                <BarChart3 className="w-4 h-4 text-brand-400" />
                Résumé du Run
              </h3>
              <div className="space-y-3">
                <MetaRow label="Source"  value={run.source_name} />
                <MetaRow label="Type"    value={run.source_type} />
                <MetaRow label="Démarré" value={new Date(run.created_at).toLocaleString('fr-FR')} />
                <div className="border-t border-slate-800 pt-3 mt-3 grid grid-cols-2 gap-3">
                  <div className="bg-blue-500/5 border border-blue-500/20 rounded-xl p-3 text-center">
                    <div className="text-2xl font-bold text-blue-400">{totalIOC.toLocaleString()}</div>
                    <div className="text-[10px] text-slate-500 font-mono uppercase mt-1">IOCs</div>
                  </div>
                  <div className="bg-purple-500/5 border border-purple-500/20 rounded-xl p-3 text-center">
                    <div className="text-2xl font-bold text-purple-400">{totalCVE.toLocaleString()}</div>
                    <div className="text-[10px] text-slate-500 font-mono uppercase mt-1">CVEs</div>
                  </div>
                </div>
              </div>
            </div>

            {/* Détail étape par étape */}
            <div className="bg-slate-900/50 rounded-2xl border border-slate-800 p-5">
              <h3 className="text-sm font-bold text-white mb-4">Détail des étapes</h3>
              <div className="space-y-2">
                {PIPELINE_STEPS.filter(s => stepMap[s.name]).map((step, idx) => {
                  const stepData = stepMap[step.name];
                  const c = COLOR_MAP[step.color];
                  const duration = stepData.started_at && stepData.finished_at
                    ? Math.round((new Date(stepData.finished_at) - new Date(stepData.started_at)) / 1000)
                    : null;

                  return (
                    <div key={step.name} className={`flex flex-col p-3 rounded-xl border transition-all relative overflow-hidden ${
                      stepData.status === 'running'  ? `${c.bg} ${c.border} shadow-[0_0_15px_rgba(14,165,233,0.1)]` :
                      stepData.status === 'success'  ? 'bg-emerald-500/5 border-emerald-500/20' :
                      stepData.status === 'failed'   ? 'bg-red-500/5 border-red-500/20' :
                      'bg-slate-800/30 border-slate-800'
                    }`}>
                      <div className="flex items-center gap-3">
                        <StatusIcon status={stepData.status} size="w-4 h-4" />
                        <div className="flex-1 min-w-0">
                          <p className="text-xs font-medium text-white truncate">{step.name}</p>
                          {duration !== null && (
                            <p className="text-[10px] text-slate-500">{duration}s</p>
                          )}
                        </div>
                        {(stepData.ioc_count > 0 || stepData.cve_count > 0) && (
                          <div className="text-right">
                            {stepData.ioc_count > 0 && (
                              <div className="text-[10px] text-blue-400 font-mono">{stepData.ioc_count} IOC</div>
                            )}
                            {stepData.cve_count > 0 && (
                              <div className="text-[10px] text-purple-400 font-mono">{stepData.cve_count} CVE</div>
                            )}
                          </div>
                        )}
                      </div>
                      
                      {/* Premium HUD Elements for Active Step */}
                      {stepData.status === 'running' && (
                        <>
                          <div className="absolute inset-0 hud-grid pointer-events-none" />
                          <div className="scan-beam" />
                          <div className="hud-corner-tl hud-corner" />
                          <div className="hud-corner-tr hud-corner" />
                          <div className="hud-corner-bl hud-corner" />
                          <div className="hud-corner-br hud-corner" />
                          <div className="absolute bottom-0 left-0 w-full h-[3px] bg-slate-900 border-t border-brand-500/20 overflow-hidden">
                            <div className="absolute top-0 h-full cyber-loading-bar animate-indeterminate shadow-[0_0_10px_#0ea5e9]" />
                          </div>
                        </>
                      )}
                    </div>
                  );
                })}
              </div>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
};

// ── Badges & helpers ────────────────────────────────────────────────────────────
const StatusBadge = ({ status }) => {
  const map = {
    running: "bg-brand-500/10 text-brand-400 border-brand-500/30",
    success: "bg-emerald-500/10 text-emerald-400 border-emerald-500/30",
    failed:  "bg-red-500/10 text-red-400 border-red-500/30",
    planned: "bg-slate-800/50 text-slate-500 border-dashed border-slate-700",
    pending: "bg-slate-500/10 text-slate-400 border-slate-500/30",
  };
  return (
    <span className={`px-3 py-1 rounded-lg border text-xs font-bold uppercase tracking-wider ${map[status] || map.pending} ${status === 'running' ? 'animate-pulse' : ''}`}>
      {status}
    </span>
  );
};

const MetaRow = ({ label, value }) => (
  <div className="flex justify-between items-center text-xs">
    <span className="text-slate-500">{label}</span>
    <span className="text-white font-medium text-right max-w-[60%] truncate" title={value}>{value}</span>
  </div>
);

export default RunDetail;
