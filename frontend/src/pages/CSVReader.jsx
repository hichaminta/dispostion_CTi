import React, { useState, useEffect, useMemo } from 'react';
import axios from 'axios';
import {
  ArrowLeft,
  FileSpreadsheet,
  FileText,
  Loader2,
  AlertCircle,
  Search,
  Download,
  Settings2,
  Hash,
  Calendar,
  Mail,
  Link2,
  Type,
  RefreshCw,
  ChevronDown,
  Info,
  Cpu,
} from 'lucide-react';

const API_BASE = `http://${window.location.hostname}:8000`;

// ── Separator display helpers ────────────────────────────────────────────────
const SEP_OPTIONS = [
  { value: 'auto',  label: 'Auto-detect', icon: '🔍' },
  { value: ',',     label: 'Virgule  ,',  icon: ',' },
  { value: ';',     label: 'Point-virgule ;', icon: ';' },
  { value: '\\t',  label: 'Tabulation ⇥', icon: '⇥' },
  { value: '|',    label: 'Pipe  |',      icon: '|' },
  { value: ':',    label: 'Deux-points :', icon: ':' },
  { value: ' ',    label: 'Espace',        icon: '␣' },
];

const SEP_LABEL = {
  ',':   'Virgule (,)',
  ';':   'Point-virgule (;)',
  '\\t': 'Tabulation (⇥)',
  '|':   'Pipe (|)',
  ':':   'Deux-points (:)',
  ' ':   'Espace (␣)',
};

// ── Column type badge ────────────────────────────────────────────────────────
const TYPE_CONFIG = {
  number: { icon: Hash,      color: 'text-blue-400',   bg: 'bg-blue-500/10 border-blue-500/20',   label: 'Nombre' },
  date:   { icon: Calendar,  color: 'text-purple-400', bg: 'bg-purple-500/10 border-purple-500/20', label: 'Date' },
  email:  { icon: Mail,      color: 'text-emerald-400',bg: 'bg-emerald-500/10 border-emerald-500/20', label: 'Email' },
  url:    { icon: Link2,     color: 'text-cyan-400',   bg: 'bg-cyan-500/10 border-cyan-500/20',   label: 'URL' },
  text:   { icon: Type,      color: 'text-slate-400',  bg: 'bg-slate-800 border-slate-700',       label: 'Texte' },
  empty:  { icon: Type,      color: 'text-slate-600',  bg: 'bg-slate-900 border-slate-800',       label: 'Vide' },
};

const TypeBadge = ({ type }) => {
  const cfg = TYPE_CONFIG[type] || TYPE_CONFIG.text;
  const Icon = cfg.icon;
  return (
    <span className={`inline-flex items-center gap-1 px-1.5 py-0.5 rounded border text-[8px] font-black uppercase tracking-wider ${cfg.bg} ${cfg.color}`}>
      <Icon className="w-2.5 h-2.5" />
      {cfg.label}
    </span>
  );
};

// ── Cell renderer with type awareness ────────────────────────────────────────
const Cell = ({ value, type }) => {
  if (value === null || value === undefined) {
    return <span className="text-slate-700 italic text-[10px]">null</span>;
  }
  const str = String(value);
  if (type === 'email') {
    return <a href={`mailto:${str}`} className="text-emerald-400 hover:underline text-[11px] font-mono">{str}</a>;
  }
  if (type === 'url') {
    return <a href={str} target="_blank" rel="noreferrer" className="text-cyan-400 hover:underline text-[11px] font-mono truncate max-w-[180px] block">{str}</a>;
  }
  if (type === 'number') {
    return <span className="text-blue-300 font-mono text-[11px] tabular-nums">{str}</span>;
  }
  if (type === 'date') {
    return <span className="text-purple-300 font-mono text-[10px]">{str}</span>;
  }
  return <span className="text-slate-300 text-[11px]">{str}</span>;
};

// ── Main component ───────────────────────────────────────────────────────────
const CSVReader = ({ filePath, onBack }) => {
  const [result,      setResult]      = useState(null);
  const [loading,     setLoading]     = useState(true);
  const [error,       setError]       = useState(null);
  const [search,      setSearch]      = useState('');
  const [manualSep,   setManualSep]   = useState('auto');
  const [showSepMenu, setShowSepMenu] = useState(false);
  const [page,        setPage]        = useState(0);

  const PAGE_SIZE = 50;

  const fileName = filePath?.split(/[\\/]/).pop() || filePath;
  const isText   = fileName?.toLowerCase().endsWith('.txt');
  const isExcel  = fileName?.toLowerCase().endsWith('.xlsx') || fileName?.toLowerCase().endsWith('.xls');

  const fetchFile = async (sep = manualSep) => {
    setLoading(true);
    setError(null);
    setPage(0);
    try {
      let url = `${API_BASE}/api/leaks/csv/view?path=${encodeURIComponent(filePath)}`;
      if (sep !== 'auto') url += `&separator=${encodeURIComponent(sep)}`;
      const res = await axios.get(url);
      setResult(res.data);
    } catch (e) {
      setError(e.response?.data?.detail || e.message);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => { fetchFile(); }, [filePath]);

  // ── Filtered rows ─────────────────────────────────────────────────────────
  const filteredRows = useMemo(() => {
    if (!result?.data) return [];
    if (!search.trim()) return result.data;
    const q = search.toLowerCase();
    return result.data.filter(row =>
      Object.values(row).some(v => v !== null && String(v).toLowerCase().includes(q))
    );
  }, [result, search]);

  const pageRows    = filteredRows.slice(page * PAGE_SIZE, (page + 1) * PAGE_SIZE);
  const totalPages  = Math.ceil(filteredRows.length / PAGE_SIZE);
  const columns     = result?.columns || [];
  const colTypes    = result?.col_types || {};

  const handleSepChange = (sep) => {
    setManualSep(sep);
    setShowSepMenu(false);
    fetchFile(sep);
  };

  // ── Render ────────────────────────────────────────────────────────────────
  return (
    <div className="min-h-screen bg-[#05060b] text-slate-200 p-6 md:p-8 relative overflow-hidden">
      {/* Background glows */}
      <div className="absolute top-0 left-1/4 w-[500px] h-[500px] bg-brand-500/5 blur-[150px] rounded-full pointer-events-none" />
      <div className="absolute bottom-0 right-1/4 w-[500px] h-[500px] bg-purple-500/5 blur-[150px] rounded-full pointer-events-none" />

      <div className="max-w-[1600px] mx-auto relative z-10">

        {/* ── Header ────────────────────────────────────────────────────────── */}
        <div className="flex flex-col md:flex-row items-start md:items-center justify-between gap-4 mb-8">
          <div className="flex items-center gap-4">
            <button
              onClick={onBack}
              className="p-2 hover:bg-white/5 rounded-xl text-slate-400 hover:text-white transition-all border border-white/5"
            >
              <ArrowLeft className="w-5 h-5" />
            </button>
            <div>
              <div className="flex items-center gap-2 mb-1">
                {isText
                  ? <FileText  className="w-5 h-5 text-brand-400" />
                  : <FileSpreadsheet className="w-5 h-5 text-emerald-400" />
                }
                <h1 className="text-xl font-black text-white">{fileName}</h1>
              </div>
              <p className="text-slate-600 text-[10px] font-mono truncate max-w-[500px]">{filePath}</p>
            </div>
          </div>

          {/* Controls */}
          <div className="flex items-center gap-3 flex-wrap">

            {/* Separator chooser (CSV only) */}
            {!isText && !isExcel && (
              <div className="relative">
                <button
                  onClick={() => setShowSepMenu(v => !v)}
                  className={`flex items-center gap-2 px-4 py-2 rounded-xl border text-[11px] font-black uppercase tracking-wider transition-all ${
                    showSepMenu
                      ? 'bg-brand-500/20 border-brand-500/40 text-brand-300'
                      : 'bg-slate-900/60 border-white/10 text-slate-400 hover:border-white/20 hover:text-white'
                  }`}
                >
                  <Settings2 className="w-3.5 h-3.5" />
                  Séparateur
                  {manualSep !== 'auto' && (
                    <span className="px-1.5 py-0.5 bg-brand-500/30 text-brand-300 rounded font-mono text-[10px] border border-brand-500/30">
                      {manualSep === '\\t' ? '⇥' : manualSep === ' ' ? '␣' : manualSep}
                    </span>
                  )}
                  <ChevronDown className={`w-3 h-3 transition-transform ${showSepMenu ? 'rotate-180' : ''}`} />
                </button>

                {showSepMenu && (
                  <div className="absolute right-0 top-full mt-2 z-50 bg-[#0d1117] border border-white/10 rounded-2xl shadow-2xl overflow-hidden min-w-[200px] animate-in fade-in zoom-in-95 duration-150">
                    {SEP_OPTIONS.map(opt => (
                      <button
                        key={opt.value}
                        onClick={() => handleSepChange(opt.value)}
                        className={`w-full flex items-center gap-3 px-4 py-3 text-[11px] font-bold transition-colors text-left ${
                          manualSep === opt.value
                            ? 'bg-brand-500/20 text-brand-300'
                            : 'text-slate-400 hover:bg-white/5 hover:text-white'
                        }`}
                      >
                        <span className="font-mono text-base w-5 text-center">{opt.icon}</span>
                        {opt.label}
                        {manualSep === opt.value && <span className="ml-auto text-brand-400">✓</span>}
                      </button>
                    ))}
                  </div>
                )}
              </div>
            )}

            {/* Search */}
            <div className="relative">
              <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-slate-600" />
              <input
                type="text"
                placeholder="Rechercher dans les données..."
                value={search}
                onChange={e => { setSearch(e.target.value); setPage(0); }}
                className="bg-slate-900/60 border border-white/10 rounded-xl py-2 pl-9 pr-4 text-sm focus:outline-none focus:border-brand-500/40 transition-all w-52"
              />
            </div>

            {/* Reload */}
            <button
              onClick={() => fetchFile(manualSep)}
              className="p-2 bg-slate-900/60 border border-white/10 rounded-xl text-slate-400 hover:text-white hover:border-white/20 transition-all"
              title="Recharger"
            >
              <RefreshCw className="w-4 h-4" />
            </button>

            {/* Download */}
            <a
              href={`${API_BASE}/data/leaks/${filePath}`}
              download
              className="flex items-center gap-2 px-4 py-2 bg-emerald-600 hover:bg-emerald-500 text-white rounded-xl text-[11px] font-black uppercase tracking-wider transition-all shadow-lg shadow-emerald-600/20"
            >
              <Download className="w-4 h-4" />
              Télécharger
            </a>
          </div>
        </div>

        {/* ── Metadata bar ──────────────────────────────────────────────────── */}
        {result && result.type === 'csv' && (
          <div className="flex flex-wrap items-center gap-3 mb-6 px-4 py-3 bg-slate-900/30 border border-white/5 rounded-2xl backdrop-blur-md">
            {!isExcel && (
              <div className="flex items-center gap-2 text-[10px] font-black uppercase tracking-widest">
                <Cpu className="w-3.5 h-3.5 text-brand-400" />
                <span className="text-slate-500">Séparateur détecté :</span>
                <span className="px-2 py-0.5 bg-brand-500/20 border border-brand-500/30 text-brand-300 rounded font-mono">
                  {result.detected_sep === '\\t' ? 'TAB' : result.detected_sep === ' ' ? 'SPACE' : result.detected_sep}
                  {' — '}{SEP_LABEL[result.detected_sep] || result.detected_sep}
                </span>
              </div>
            )}
            {!isExcel && <div className="w-px h-4 bg-white/10" />}
            <div className="text-[10px] font-mono text-slate-500">
              Encodage : <span className="text-slate-300">{result.encoding}</span>
            </div>
            <div className="w-px h-4 bg-white/10" />
            <div className="text-[10px] font-mono text-slate-500">
              Colonnes : <span className="text-slate-300">{columns.length}</span>
            </div>
            <div className="w-px h-4 bg-white/10" />
            <div className="text-[10px] font-mono text-slate-500">
              Lignes affichées : <span className="text-brand-400 font-black">{filteredRows.length}</span>
              {' '}/{' '}{result.total_rows}
            </div>
            {manualSep !== 'auto' && (
              <>
                <div className="w-px h-4 bg-white/10" />
                <div className="flex items-center gap-1.5 text-[10px] text-amber-400">
                  <Info className="w-3 h-3" />
                  Séparateur manuel actif
                </div>
              </>
            )}
          </div>
        )}

        {/* ── Content ───────────────────────────────────────────────────────── */}
        <div className="bg-slate-900/40 border border-white/5 rounded-3xl overflow-hidden backdrop-blur-xl shadow-2xl">

          {loading ? (
            <div className="flex flex-col items-center justify-center py-40">
              <Loader2 className="w-10 h-10 text-brand-500 animate-spin mb-4" />
              <p className="text-slate-500 text-xs uppercase tracking-widest font-mono">Analyse du fichier en cours...</p>
            </div>

          ) : error ? (
            <div className="flex flex-col items-center justify-center py-40 text-center px-10">
              <AlertCircle className="w-12 h-12 text-red-500 mb-4" />
              <h3 className="text-lg font-bold text-white mb-2">Impossible de lire le fichier</h3>
              <p className="text-slate-500 text-sm max-w-md font-mono">{error}</p>
              <button
                onClick={() => fetchFile(manualSep)}
                className="mt-6 px-6 py-3 bg-slate-800 hover:bg-slate-700 text-white rounded-xl text-xs font-bold uppercase tracking-wider transition-all"
              >
                Réessayer
              </button>
            </div>

          ) : result?.type === 'text' ? (
            /* ── Plain text viewer ────────────────────────────────────────── */
            <div>
              <div className="flex items-center justify-between px-6 py-4 border-b border-white/5 bg-slate-900/60">
                <div className="flex items-center gap-2">
                  <div className="flex gap-1">
                    <div className="w-2.5 h-2.5 rounded-full bg-red-500/50" />
                    <div className="w-2.5 h-2.5 rounded-full bg-yellow-500/50" />
                    <div className="w-2.5 h-2.5 rounded-full bg-emerald-500/50" />
                  </div>
                  <span className="text-[10px] font-mono text-slate-500 uppercase tracking-widest ml-2">
                    TEXT VIEWER — {result.lines} lignes
                  </span>
                </div>
              </div>
              <pre className="p-6 font-mono text-[11px] leading-6 text-slate-300 overflow-x-auto overflow-y-auto max-h-[70vh] whitespace-pre-wrap break-all custom-scrollbar">
                {result.content}
              </pre>
            </div>

          ) : (
            /* ── CSV Table ────────────────────────────────────────────────── */
            <>
              <div className="overflow-x-auto custom-scrollbar">
                <table className="w-full text-left border-collapse">
                  <thead>
                    <tr className="bg-white/[0.03] border-b border-white/5">
                      <th className="px-4 py-4 text-[9px] font-black text-slate-600 uppercase tracking-widest w-10 sticky left-0 bg-[#0d1117]">#</th>
                      {columns.map(col => (
                        <th key={col} className="px-5 py-3 whitespace-nowrap">
                          <div className="flex flex-col gap-1.5">
                            <span className="text-[10px] font-black uppercase tracking-widest text-slate-300">{col}</span>
                            <TypeBadge type={colTypes[col] || 'text'} />
                          </div>
                        </th>
                      ))}
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-white/[0.03]">
                    {pageRows.length === 0 ? (
                      <tr>
                        <td colSpan={columns.length + 1} className="py-20 text-center text-slate-600 italic text-sm">
                          Aucune donnée correspondant à la recherche
                        </td>
                      </tr>
                    ) : pageRows.map((row, idx) => (
                      <tr
                        key={idx}
                        className="hover:bg-white/[0.02] transition-colors group"
                      >
                        <td className="px-4 py-3 text-[9px] font-mono text-slate-700 sticky left-0 bg-[#05060b] group-hover:bg-[#0a0d14] transition-colors">
                          {page * PAGE_SIZE + idx + 1}
                        </td>
                        {columns.map(col => (
                          <td key={col} className="px-5 py-3 max-w-[220px] truncate">
                            <Cell value={row[col]} type={colTypes[col]} />
                          </td>
                        ))}
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>

              {/* Pagination */}
              {totalPages > 1 && (
                <div className="flex items-center justify-between px-6 py-4 border-t border-white/5 bg-slate-900/30">
                  <p className="text-[10px] font-mono text-slate-500">
                    Page <span className="text-white font-black">{page + 1}</span> / {totalPages}
                    {' — '}
                    <span className="text-brand-400">{filteredRows.length}</span> lignes
                  </p>
                  <div className="flex items-center gap-2">
                    <button
                      disabled={page === 0}
                      onClick={() => setPage(p => p - 1)}
                      className="px-4 py-2 bg-slate-800 hover:bg-slate-700 text-white rounded-xl text-[10px] font-black uppercase tracking-wider transition-all disabled:opacity-30 disabled:cursor-not-allowed"
                    >
                      ← Précédent
                    </button>
                    <div className="flex gap-1">
                      {Array.from({ length: Math.min(totalPages, 7) }, (_, i) => {
                        const p = totalPages <= 7 ? i : Math.max(0, Math.min(page - 3, totalPages - 7)) + i;
                        return (
                          <button
                            key={p}
                            onClick={() => setPage(p)}
                            className={`w-8 h-8 rounded-lg text-[10px] font-black transition-all ${
                              p === page
                                ? 'bg-brand-500 text-white shadow-[0_0_12px_rgba(14,165,233,0.4)]'
                                : 'bg-slate-800 hover:bg-slate-700 text-slate-400'
                            }`}
                          >
                            {p + 1}
                          </button>
                        );
                      })}
                    </div>
                    <button
                      disabled={page >= totalPages - 1}
                      onClick={() => setPage(p => p + 1)}
                      className="px-4 py-2 bg-slate-800 hover:bg-slate-700 text-white rounded-xl text-[10px] font-black uppercase tracking-wider transition-all disabled:opacity-30 disabled:cursor-not-allowed"
                    >
                      Suivant →
                    </button>
                  </div>
                </div>
              )}
            </>
          )}
        </div>

        {/* Footer note */}
        <p className="mt-4 text-center text-[9px] text-slate-700 uppercase tracking-widest font-mono">
          Affichage limité à 200 lignes par chargement — téléchargez le fichier complet pour l'analyse intégrale
        </p>
      </div>

      <style dangerouslySetInnerHTML={{ __html: `
        .custom-scrollbar::-webkit-scrollbar { width: 4px; height: 4px; }
        .custom-scrollbar::-webkit-scrollbar-track { background: rgba(255,255,255,0.02); }
        .custom-scrollbar::-webkit-scrollbar-thumb { background: rgba(14,165,233,0.15); border-radius: 10px; }
        .custom-scrollbar::-webkit-scrollbar-thumb:hover { background: rgba(14,165,233,0.3); }
      `}} />
    </div>
  );
};

export default CSVReader;
