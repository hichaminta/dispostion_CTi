import React, { useState, useEffect, useCallback } from 'react';
import axios from 'axios';
import {
  Database, Zap, Search, Filter, RefreshCw, ChevronLeft, ChevronRight,
  Shield, AlertTriangle, Clock, FileText, Globe, ScanEye, Layers,
  CheckCircle2, AlertCircle, Info, X, Share2, Layout, Code, Monitor,
  ChevronUp, ChevronDown, MapPin, Building, Target, Bug, Link as LinkIcon,
  PlayCircle, Loader2, Sparkles
} from 'lucide-react';

const API_BASE = `http://${window.location.hostname}:8000`;

const gf = (domain) => `https://www.google.com/s2/favicons?domain=${domain}&sz=32`;

const SOURCE_LOGOS = {
  'AbuseIPDB':    gf('abuseipdb.com'),
  'Spamhaus':     gf('spamhaus.org'),
  'URLhaus':      gf('urlhaus.abuse.ch'),
  'URLHaus':      gf('urlhaus.abuse.ch'),
  'ThreatFox':    gf('threatfox.abuse.ch'),
  'MalwareBazaar': gf('bazaar.abuse.ch'),
  'PhishTank':    gf('phishtank.com'),
  'OpenPhish':    gf('openphish.com'),
  'NVD':          gf('nvd.nist.gov'),
  'PulseDive':    gf('pulsedive.com'),
  'FeodoTracker': gf('feodotracker.abuse.ch'),
  'DFIR Report':  gf('thedfirreport.com'),
  'CINS Army':    gf('cinsscore.com'),
};

const COUNTRY_CODE_TO_NAME = {
  'af': 'Afghanistan', 'al': 'Albania', 'dz': 'Algeria', 'ad': 'Andorra', 'ao': 'Angola', 'ar': 'Argentina', 'am': 'Armenia', 'au': 'Australia', 'at': 'Austria', 'az': 'Azerbaijan',
  'bs': 'Bahamas', 'bh': 'Bahrain', 'bd': 'Bangladesh', 'bb': 'Barbados', 'by': 'Belarus', 'be': 'Belgium', 'bz': 'Belize', 'bj': 'Benin', 'bt': 'Bhutan', 'bo': 'Bolivia',
  'br': 'Brazil', 'bg': 'Bulgaria', 'bf': 'Burkina Faso', 'bi': 'Burundi', 'kh': 'Cambodia', 'cm': 'Cameroon', 'ca': 'Canada', 'td': 'Chad', 'cl': 'Chile', 'cn': 'China',
  'co': 'Colombia', 'cg': 'Congo', 'cr': 'Costa Rica', 'hr': 'Croatia', 'cu': 'Cuba', 'cy': 'Cyprus', 'cz': 'Czechia', 'dk': 'Denmark', 'dj': 'Djibouti', 'dm': 'Dominica',
  'ec': 'Ecuador', 'eg': 'Egypt', 'ee': 'Estonia', 'et': 'Ethiopia', 'fj': 'Fiji', 'fi': 'Finland', 'fr': 'France', 'ga': 'Gabon', 'gm': 'Gambia', 'ge': 'Georgia', 'de': 'Germany',
  'gh': 'Ghana', 'gr': 'Greece', 'gt': 'Guatemala', 'gn': 'Guinea', 'gy': 'Guyana', 'ht': 'Haiti', 'hn': 'Honduras', 'hu': 'Hungary', 'is': 'Iceland', 'in': 'India', 'id': 'Indonesia',
  'ir': 'Iran', 'iq': 'Iraq', 'ie': 'Ireland', 'il': 'Israel', 'it': 'Italy', 'jm': 'Jamaica', 'jp': 'Japan', 'jo': 'Jordan', 'kz': 'Kazakhstan', 'ke': 'Kenya', 'kw': 'Kuwait',
  'kg': 'Kyrgyzstan', 'la': 'Laos', 'lv': 'Latvia', 'lb': 'Lebanon', 'ls': 'Lesotho', 'lr': 'Liberia', 'ly': 'Libya', 'lt': 'Lithuania', 'lu': 'Luxembourg', 'mg': 'Madagascar',
  'my': 'Malaysia', 'mv': 'Maldives', 'ml': 'Mali', 'mt': 'Malta', 'mx': 'Mexico', 'md': 'Moldova', 'mc': 'Monaco', 'mn': 'Mongolia', 'me': 'Montenegro', 'ma': 'Morocco',
  'mm': 'Myanmar', 'na': 'Namibia', 'np': 'Nepal', 'nl': 'Netherlands', 'nz': 'New Zealand', 'ni': 'Nicaragua', 'ne': 'Niger', 'ng': 'Nigeria', 'kp': 'North Korea',
  'no': 'Norway', 'om': 'Oman', 'pk': 'Pakistan', 'pw': 'Palau', 'pa': 'Panama', 'py': 'Paraguay', 'pe': 'Peru', 'ph': 'Philippines', 'pl': 'Poland', 'pt': 'Portugal', 'qa': 'Qatar',
  'ro': 'Romania', 'ru': 'Russia', 'rw': 'Rwanda', 'sa': 'Saudi Arabia', 'sn': 'Senegal', 'rs': 'Serbia', 'sc': 'Seychelles', 'sl': 'Sierra Leone', 'sg': 'Singapore',
  'sk': 'Slovakia', 'si': 'Slovenia', 'so': 'Somalia', 'za': 'South Africa', 'kr': 'South Korea', 'es': 'Spain', 'lk': 'Sri Lanka', 'sd': 'Sudan', 'sr': 'Suriname',
  'se': 'Sweden', 'ch': 'Switzerland', 'sy': 'Syria', 'tw': 'Taiwan', 'tj': 'Tajikistan', 'tz': 'Tanzania', 'th': 'Thailand', 'tg': 'Togo', 'to': 'Tonga', 'tn': 'Tunisia',
  'tr': 'Turkey', 'tm': 'Turkmenistan', 'ug': 'Uganda', 'ua': 'Ukraine', 'ae': 'United Arab Emirates', 'gb': 'United Kingdom', 'us': 'United States', 'uy': 'Uruguay',
  'uz': 'Uzbekistan', 'vu': 'Vanuatu', 've': 'Venezuela', 'vn': 'Vietnam', 'ye': 'Yemen', 'zm': 'Zambia', 'zw': 'Zimbabwe'
};

const Results = ({ onBack, initialSourceId }) => {
  const [viewMode, setViewMode] = useState('extracted');
  const [sources, setSources] = useState([]);
  const [currentSource, setCurrentSource] = useState(initialSourceId || null);
  const [data, setData] = useState([]);
  const [totalItems, setTotalItems] = useState(0);
  const [currentPage, setCurrentPage] = useState(1);
  const [pageSize] = useState(50);
  const [search, setSearch] = useState("");
  const [iocType, setIocType] = useState("");
  const [loading, setLoading] = useState(false);
  const [sourcesLoading, setSourcesLoading] = useState(true);
  const [fetchError, setFetchError] = useState(null);
  const [modalOpen, setModalOpen] = useState(false);
  const [selectedRecord, setSelectedRecord] = useState(null);
  const [activeTab, setActiveTab] = useState('overview');
  const [countryStats, setCountryStats] = useState([]);

  // Fetch sources list — does NOT depend on currentSource to avoid re-fetch loops
  const fetchSources = useCallback(async () => {
    setSourcesLoading(true);
    setFetchError(null);
    try {
      const api = viewMode === 'extracted' ? `${API_BASE}/api/extracted` : `${API_BASE}/api/enriched`;
      const res = await axios.get(`${api}/sources`);
      setSources(res.data);
      setCurrentSource(prev => {
        if (prev) return prev; // keep existing selection
        return res.data.length > 0 ? res.data[0].id : null;
      });
    } catch (err) {
      console.error("Failed to fetch sources:", err);
      setFetchError("Impossible de contacter le backend. Vérifiez que le serveur est démarré (port 8000).");
    } finally {
      setSourcesLoading(false);
    }
  }, [viewMode]);

  // Fetch data for current source
  const fetchData = useCallback(async () => {
    if (!currentSource) return;
    setLoading(true);
    try {
      const api = viewMode === 'extracted' ? `${API_BASE}/api/extracted` : `${API_BASE}/api/enriched`;
      const res = await axios.get(`${api}/data/${currentSource}`, {
        params: {
          page: currentPage,
          limit: pageSize,
          search: search,
          ioc_type: iocType
        }
      });
      setData(res.data.data);
      setTotalItems(res.data.total);
    } catch (err) {
      console.error("Failed to fetch data:", err);
    } finally {
      setLoading(false);
    }
  }, [currentSource, viewMode, currentPage, pageSize, search, iocType]);

  // Fetch country stats
  const fetchCountryStats = async () => {
    try {
      const res = await axios.get(`${API_BASE}/api/stats/countries`);
      setCountryStats(res.data);
    } catch (err) {
      console.error("Failed to fetch country stats:", err);
    }
  };

  useEffect(() => {
    fetchSources();
  }, [fetchSources]);

  useEffect(() => {
    fetchData();
  }, [fetchData]);

  useEffect(() => {
    fetchCountryStats();
  }, []);

  useEffect(() => {
    if (initialSourceId) {
      setCurrentSource(initialSourceId);
    }
  }, [initialSourceId]);

  const getSourceLogo = (name) => {
    if (!name) return null;
    const key = Object.keys(SOURCE_LOGOS).find(k => name.toLowerCase().includes(k.toLowerCase()));
    return key ? SOURCE_LOGOS[key] : null;
  };

  const formatSize = (bytes) => {
    if (!bytes) return '0 B';
    const k = 1024;
    const sizes = ['B', 'KB', 'MB', 'GB'];
    const i = Math.floor(Math.log(bytes) / Math.log(k));
    return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i];
  };

  const openDetails = (record) => {
    setSelectedRecord(record);
    setActiveTab('enrichment');
    setModalOpen(true);
  };

  const triggerEnrichment = async (stepName) => {
    if (!currentSource) return;
    const srcObj = sources.find(s => s.id === currentSource);
    if (!srcObj) return;

    try {
      await axios.post(`${API_BASE}/runs/targeted`, {
        source_name: srcObj.name,
        source_type: "manual_trigger"
      }, {
        params: { step_name: stepName }
      });
      alert(`${stepName} démarré avec succès.`);
    } catch (err) {
      alert(`Erreur : ${err.response?.data?.detail || err.message}`);
    }
  };

  const selectedSrcObj = sources.find(s => s.id === currentSource);

  return (
    <div className="min-h-screen bg-transparent relative overflow-hidden flex flex-col text-slate-200">
      <div className="fixed inset-0 hud-grid pointer-events-none opacity-20" />
      
      {/* ── Header ─────────────────────────────────────────────────── */}
      <header className="h-16 border-b border-white/5 bg-slate-900/40 backdrop-blur-xl flex items-center justify-between px-6 z-30">
        <div className="flex items-center gap-4">
          <button 
            onClick={onBack}
            className="p-2 hover:bg-white/5 rounded-lg transition-colors text-slate-400 hover:text-white"
          >
            <ChevronLeft size={20} />
          </button>
          <div className="flex items-center gap-2">
            <Database className="text-brand-400" size={20} />
            <h1 className="text-lg font-black tracking-tight uppercase">Intelligence Explorer</h1>
          </div>
        </div>

        <div className="flex items-center gap-3">
          <div className="flex p-1 bg-black/40 rounded-xl border border-white/5">
            <button 
              onClick={() => { setViewMode('extracted'); setCurrentPage(1); }}
              className={`px-4 py-1.5 rounded-lg text-xs font-bold transition-all ${viewMode === 'extracted' ? 'bg-brand-500/20 text-brand-400 border border-brand-500/30' : 'text-slate-500 hover:text-slate-300'}`}
            >
              Extracted
            </button>
            <button 
              onClick={() => { setViewMode('enriched'); setCurrentPage(1); }}
              className={`px-4 py-1.5 rounded-lg text-xs font-bold transition-all ${viewMode === 'enriched' ? 'bg-purple-500/20 text-purple-400 border border-purple-500/30' : 'text-slate-500 hover:text-slate-300'}`}
            >
              Enriched
            </button>
          </div>
          <button 
            onClick={() => fetchData()}
            className="p-2 hover:bg-white/5 rounded-lg transition-colors text-brand-400"
          >
            <RefreshCw size={18} className={loading ? "animate-spin" : ""} />
          </button>
        </div>
      </header>

      <div className="flex-1 flex overflow-hidden">
        {/* ── Sidebar: Sources ────────────────────────────────────────── */}
        <aside className="w-64 border-r border-white/5 bg-slate-900/20 flex flex-col z-20">
          <div className="p-4 border-b border-white/5 flex items-center justify-between">
            <span className="text-[10px] font-black uppercase tracking-widest text-slate-500">Data Sources</span>
            <span className="px-2 py-0.5 bg-slate-800 rounded text-[9px] font-bold text-slate-400">{sources.length}</span>
          </div>
          <div className="flex-1 overflow-y-auto p-2 space-y-1">
            {sourcesLoading ? (
              <div className="flex flex-col items-center justify-center py-10 gap-3">
                <Loader2 size={24} className="text-brand-500 animate-spin" />
                <span className="text-[10px] text-slate-500 font-mono">Chargement...</span>
              </div>
            ) : fetchError ? (
              <div className="p-3 space-y-3">
                <div className="p-3 bg-red-500/10 border border-red-500/20 rounded-xl text-[10px] text-red-400 font-mono leading-relaxed">
                  {fetchError}
                </div>
                <button
                  onClick={fetchSources}
                  className="w-full flex items-center justify-center gap-2 py-2 px-3 bg-brand-500/10 border border-brand-500/30 rounded-xl text-[10px] font-black uppercase tracking-widest text-brand-400 hover:bg-brand-500/20 transition-all"
                >
                  <RefreshCw size={12} />
                  Réessayer
                </button>
              </div>
            ) : sources.length === 0 ? (
              <div className="p-3 space-y-3">
                <div className="p-3 bg-slate-800/60 border border-white/5 rounded-xl text-[10px] text-slate-400 font-mono leading-relaxed">
                  Aucun fichier extrait trouvé.<br /><br />
                  Lancez d'abord le pipeline <span className="text-brand-400 font-bold">Collecte → Extraction</span> depuis le Monitor.
                </div>
                <button
                  onClick={fetchSources}
                  className="w-full flex items-center justify-center gap-2 py-2 px-3 bg-slate-800 border border-white/10 rounded-xl text-[10px] font-black uppercase tracking-widest text-slate-400 hover:text-brand-400 transition-all"
                >
                  <RefreshCw size={12} />
                  Actualiser
                </button>
              </div>
            ) : sources.map(src => {
              const logo = getSourceLogo(src.name);
              return (
                <button
                  key={src.id}
                  onClick={() => setCurrentSource(src.id)}
                  className={`w-full flex items-center gap-3 p-3 rounded-xl transition-all border ${currentSource === src.id ? 'bg-brand-500/10 border-brand-500/30 text-white shadow-[0_0_15px_rgba(14,165,233,0.1)]' : 'border-transparent text-slate-400 hover:bg-white/5'}`}
                >
                  <div className="w-8 h-8 rounded-lg bg-slate-800 flex items-center justify-center overflow-hidden border border-white/5 flex-shrink-0">
                    {logo ? (
                      <img
                        src={logo}
                        alt=""
                        className="w-5 h-5 object-contain"
                        onError={e => { e.target.style.display = 'none'; e.target.nextSibling.style.display = 'block'; }}
                      />
                    ) : null}
                    <Shield size={16} style={{ display: logo ? 'none' : 'block' }} />
                  </div>
                  <div className="flex flex-col items-start min-w-0">
                    <span className="text-xs font-bold truncate w-full">{src.name}</span>
                    <span className="text-[9px] opacity-50 uppercase tracking-tighter">{formatSize(src.size)}</span>
                  </div>
                </button>
              );
            })}
          </div>
        </aside>

        {/* ── Main Content Area ───────────────────────────────────────── */}
        <main className="flex-1 overflow-y-auto relative p-6">
          {/* No-source splash */}
          {!currentSource && !sourcesLoading && (
            <div className="flex flex-col items-center justify-center h-full gap-6 text-center py-24">
              <div className="w-20 h-20 rounded-3xl bg-brand-500/10 border border-brand-500/20 flex items-center justify-center">
                <Database size={36} className="text-brand-500/60" />
              </div>
              <div>
                <h2 className="text-2xl font-black text-white uppercase tracking-tight mb-2">
                  {sources.length === 0 ? "Pipeline non exécuté" : "Sélectionnez une source"}
                </h2>
                <p className="text-sm text-slate-500 max-w-sm mx-auto">
                  {sources.length === 0
                    ? "Lancez le pipeline Collecte + Extraction depuis le Monitor pour générer des données."
                    : "Cliquez sur une source dans la barre latérale pour explorer ses données."}
                </p>
              </div>
              {sources.length === 0 && (
                <button
                  onClick={onBack}
                  className="flex items-center gap-2 px-6 py-3 bg-brand-500 hover:bg-brand-400 text-white text-sm font-black rounded-xl transition-all active:scale-95 shadow-lg shadow-brand-500/20"
                >
                  <PlayCircle size={16} />
                  Aller au Monitor
                </button>
              )}
            </div>
          )}

          {currentSource && (
          <div className="max-w-6xl mx-auto space-y-6">

            {/* View Header */}
            <div className="flex flex-col md:flex-row md:items-end justify-between gap-4">
              <div>
                <div className="flex items-center gap-2 mb-1">
                  <div className="w-1.5 h-1.5 bg-brand-500 rounded-full shadow-[0_0_8px_#0ea5e9]" />
                  <span className="text-[10px] font-black uppercase tracking-[0.2em] text-brand-500">Live Workspace</span>
                </div>
                <h2 className="text-3xl font-black text-white uppercase tracking-tight">{selectedSrcObj?.name || "Select Source"}</h2>
                <p className="text-sm text-slate-500 mt-1">Exploring {viewMode} data stream for {selectedSrcObj?.name}</p>
              </div>

              <div className="flex items-center gap-4 bg-slate-900/60 p-2 rounded-2xl border border-white/5 backdrop-blur-md">
                 <div className="flex items-center gap-2 px-3">
                    <Search size={16} className="text-slate-500" />
                    <input 
                      type="text" 
                      placeholder="Search indicators..."
                      className="bg-transparent border-none outline-none text-xs text-white placeholder:text-slate-600 w-48"
                      value={search}
                      onChange={(e) => setSearch(e.target.value)}
                    />
                 </div>
                 <div className="w-px h-6 bg-slate-800" />
                 <select 
                    className="bg-transparent border-none outline-none text-xs text-slate-400 pr-4"
                    value={iocType}
                    onChange={(e) => setIocType(e.target.value)}
                  >
                    <option value="">All Types</option>
                    <option value="ip">IP</option>
                    <option value="domain">Domain</option>
                    <option value="url">URL</option>
                    <option value="hash">Hashes</option>
                    <option value="cve">CVE</option>
                 </select>
              </div>
            </div>

            {/* Stats Cards */}
            <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
               <div className="glass-panel p-4 rounded-2xl relative overflow-hidden group">
                  <div className="scan-beam" />
                  <div className="flex items-center gap-3">
                    <div className="w-10 h-10 rounded-xl bg-blue-500/10 flex items-center justify-center text-blue-400 border border-blue-500/20">
                      <Shield size={20} />
                    </div>
                    <div>
                      <div className="text-[10px] font-black text-slate-500 uppercase tracking-widest">Total Records</div>
                      <div className="text-2xl font-black text-white">{totalItems}</div>
                    </div>
                  </div>
                  <div className="absolute top-2 right-2 p-1 opacity-10 group-hover:opacity-20 transition-opacity">
                     <Database size={48} />
                  </div>
               </div>
               <div className="glass-panel p-4 rounded-2xl relative overflow-hidden group">
                  <div className="scan-beam" style={{ animationDelay: '1s' }} />
                  <div className="flex items-center gap-3">
                    <div className="w-10 h-10 rounded-xl bg-purple-500/10 flex items-center justify-center text-purple-400 border border-purple-500/20">
                      <Zap size={20} />
                    </div>
                    <div>
                      <div className="text-[10px] font-black text-slate-500 uppercase tracking-widest">Page View</div>
                      <div className="text-2xl font-black text-white">{data.length} / {pageSize}</div>
                    </div>
                  </div>
                  <div className="absolute top-2 right-2 p-1 opacity-10 group-hover:opacity-20 transition-opacity">
                     <Monitor size={48} />
                  </div>
               </div>
               <div className="glass-panel p-4 rounded-2xl relative overflow-hidden group">
                  <div className="scan-beam" style={{ animationDelay: '2s' }} />
                  <div className="flex items-center gap-3">
                    <div className="w-10 h-10 rounded-xl bg-amber-500/10 flex items-center justify-center text-amber-400 border border-amber-500/20">
                      <Clock size={20} />
                    </div>
                    <div>
                      <div className="text-[10px] font-black text-slate-500 uppercase tracking-widest">Source Modification</div>
                      <div className="text-lg font-black text-white truncate w-40">
                        {selectedSrcObj ? new Date(selectedSrcObj.last_modified * 1000).toLocaleDateString() : "—"}
                      </div>
                    </div>
                  </div>
                  <div className="absolute top-2 right-2 p-1 opacity-10 group-hover:opacity-20 transition-opacity">
                     <FileText size={48} />
                  </div>
               </div>
            </div>

            {/* Main Data Table */}
            <div className="glass-panel rounded-3xl overflow-hidden border border-white/5">
              <div className="px-6 py-4 border-b border-white/5 flex items-center justify-between bg-white/5">
                <h3 className="text-sm font-black uppercase tracking-widest text-white">Extraction Stream</h3>
                <div className="flex items-center gap-4">
                  <div className="flex items-center gap-2 text-[11px] font-mono text-slate-500">
                    <button 
                      onClick={() => setCurrentPage(prev => Math.max(1, prev - 1))}
                      disabled={currentPage === 1}
                      className="p-1 hover:text-brand-400 disabled:opacity-30"
                    >
                      <ChevronLeft size={16} />
                    </button>
                    <span>Page {currentPage} / {Math.ceil(totalItems / pageSize) || 1}</span>
                    <button 
                      onClick={() => setCurrentPage(prev => prev + 1)}
                      disabled={currentPage >= Math.ceil(totalItems / pageSize)}
                      className="p-1 hover:text-brand-400 disabled:opacity-30"
                    >
                      <ChevronRight size={16} />
                    </button>
                  </div>
                </div>
              </div>

              <div className="overflow-x-auto">
                <table className="w-full text-left">
                  <thead className="bg-black/20 text-[10px] font-black uppercase tracking-widest text-slate-500">
                    <tr>
                      <th className="px-6 py-4">ID</th>
                      <th className="px-6 py-4">Type</th>
                      <th className="px-6 py-4">Indicator</th>
                      <th className="px-6 py-4">Tags</th>
                      <th className="px-6 py-4">Date</th>
                      <th className="px-6 py-4">Status</th>
                      <th className="px-6 py-4"></th>
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-white/5">
                    {loading ? (
                      Array(5).fill(0).map((_, i) => (
                        <tr key={i} className="animate-pulse">
                          <td colSpan={7} className="px-6 py-4 h-12 bg-white/5" />
                        </tr>
                      ))
                    ) : data.length === 0 ? (
                      <tr>
                        <td colSpan={7} className="px-6 py-12 text-center text-slate-500 text-sm italic font-mono">
                          No intelligence records found for this criteria.
                        </td>
                      </tr>
                    ) : data.map(item => {
                      const ioc = item.iocs?.[0];
                      const cve = item.cves?.[0];
                      const mainVal = ioc ? ioc.value : (cve ? cve.id : item.record_id);
                      const type = ioc ? ioc.type : (cve ? 'cve' : 'unknown');
                      const logo = getSourceLogo(item.source);
                      
                      const hasUrlScan = (item.iocs || []).some(i => i.ioc_enrichment?.passer_par_urlscan === 1);
                      const hasFallback = (item.iocs || []).some(i => i.ioc_enrichment?.passer_par_fallback === 1);

                      return (
                        <tr key={item.id} className="hover:bg-white/[0.02] transition-colors group">
                          <td className="px-6 py-4 font-mono text-[10px] text-slate-600">
                            {item.record_id.substring(0, 8)}...
                          </td>
                          <td className="px-6 py-4">
                            <span className={`px-2 py-0.5 rounded text-[10px] font-bold uppercase ${
                              type === 'ip' ? 'bg-blue-500/10 text-blue-400 border border-blue-500/20' :
                              type === 'domain' ? 'bg-emerald-500/10 text-emerald-400 border border-emerald-500/20' :
                              type === 'cve' ? 'bg-purple-500/10 text-purple-400 border border-purple-500/20' :
                              'bg-slate-500/10 text-slate-400 border border-slate-500/20'
                            }`}>
                              {type}
                            </span>
                          </td>
                          <td className="px-6 py-4">
                            <div className="flex items-center gap-3">
                              <div className="w-6 h-6 rounded bg-slate-800 flex items-center justify-center overflow-hidden border border-white/5">
                                {logo ? (
                                  <img
                                    src={logo}
                                    alt=""
                                    className="w-3.5 h-3.5 object-contain"
                                    onError={e => { e.target.style.display = 'none'; e.target.nextSibling.style.display = 'block'; }}
                                  />
                                ) : null}
                                <Shield size={10} style={{ display: logo ? 'none' : 'block' }} />
                              </div>
                              <span className="text-xs font-bold text-slate-200 group-hover:text-white transition-colors truncate max-w-[200px]">
                                {mainVal}
                              </span>
                            </div>
                          </td>
                          <td className="px-6 py-4">
                             <div className="flex gap-1">
                                {(item.tags || []).slice(0, 2).map(t => (
                                  <span key={t} className="text-[9px] px-1.5 py-0.5 bg-slate-800 text-slate-500 rounded border border-white/5">
                                    {t}
                                  </span>
                                ))}
                                {(item.tags || []).length > 2 && <span className="text-[9px] text-slate-600">...</span>}
                             </div>
                          </td>
                          <td className="px-6 py-4 text-[10px] text-slate-500 font-mono">
                            {item.collected_at ? new Date(item.collected_at).toLocaleDateString() : "—"}
                          </td>
                          <td className="px-6 py-4">
                             <div className="flex gap-2">
                                {hasUrlScan && <div className="w-2 h-2 rounded-full bg-pink-500 shadow-[0_0_5px_#ec4899]" title="URLScan OK" />}
                                {hasFallback && <div className="w-2 h-2 rounded-full bg-orange-500 shadow-[0_0_5px_#f97316]" title="Fallback OK" />}
                                {!hasUrlScan && !hasFallback && <div className="w-2 h-2 rounded-full bg-slate-700" />}
                             </div>
                          </td>
                          <td className="px-6 py-4 text-right">
                            <button 
                              onClick={() => openDetails(item)}
                              className="px-3 py-1 bg-white/5 hover:bg-brand-500/20 border border-white/10 hover:border-brand-500/30 rounded text-[10px] font-black uppercase tracking-widest text-slate-400 hover:text-brand-400 transition-all active:scale-95"
                            >
                              Details
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
          )} {/* end currentSource conditional */}
        </main>
      </div>

      {/* ── Details Modal ───────────────────────────────────────────── */}
      {modalOpen && selectedRecord && (
        <div className="fixed inset-0 z-50 flex items-center justify-center p-4 md:p-12">
          <div 
            className="absolute inset-0 bg-black/80 backdrop-blur-md" 
            onClick={() => setModalOpen(false)}
          />
          <div className="glass-panel w-full max-w-5xl h-full max-h-[80vh] rounded-[2rem] relative z-10 flex flex-col overflow-hidden animate-in zoom-in-95 duration-200">
            <div className="hud-corner hud-corner-tl" />
            <div className="hud-corner hud-corner-tr" />
            <div className="hud-corner hud-corner-bl" />
            <div className="hud-corner hud-corner-br" />

            {/* Modal Header */}
            <header className="p-6 border-b border-white/5 flex items-center justify-between">
              <div className="flex items-center gap-4">
                <div className="w-12 h-12 rounded-2xl bg-brand-500/10 flex items-center justify-center border border-brand-500/20 text-brand-400">
                  <Shield size={24} />
                </div>
                <div>
                  <h3 className="text-xl font-black text-white uppercase tracking-tight">Intelligence Report</h3>
                  <p className="text-xs text-slate-500 font-mono">Record ID: {selectedRecord.record_id}</p>
                </div>
              </div>
              <button 
                onClick={() => setModalOpen(false)}
                className="p-2 hover:bg-white/10 rounded-full transition-colors text-slate-400 hover:text-white"
              >
                <X size={20} />
              </button>
            </header>

            {/* Enrichment Content */}
            <div className="flex-1 overflow-y-auto p-5 bg-slate-900/40 space-y-4">

              {/* ── Score Banner ── */}
              <div className="flex flex-wrap items-center gap-3 p-3 glass-panel rounded-2xl border border-white/5">
                {selectedRecord.priority_score && (
                  <span className={`px-3 py-1.5 rounded-lg text-[10px] font-black uppercase tracking-wider ${
                    selectedRecord.priority_score === 'CRITICAL' ? 'bg-red-500/20 text-red-400 border border-red-500/30' :
                    selectedRecord.priority_score === 'HIGH'     ? 'bg-orange-500/20 text-orange-400 border border-orange-500/30' :
                    selectedRecord.priority_score === 'MEDIUM'   ? 'bg-yellow-500/20 text-yellow-400 border border-yellow-500/30' :
                                                                   'bg-emerald-500/20 text-emerald-400 border border-emerald-500/30'
                  }`}>{selectedRecord.priority_score}</span>
                )}
                {selectedRecord.risk_score_additive != null && (
                  <div className="flex items-center gap-2 flex-1 min-w-[160px]">
                    <span className="text-[9px] text-slate-500 uppercase font-black whitespace-nowrap">Score CTI</span>
                    <div className="flex-1 h-1.5 bg-white/5 rounded-full overflow-hidden">
                      <div
                        className={`h-full rounded-full ${
                          selectedRecord.risk_score_additive >= 75 ? 'bg-red-500' :
                          selectedRecord.risk_score_additive >= 50 ? 'bg-orange-400' :
                          selectedRecord.risk_score_additive >= 25 ? 'bg-yellow-400' : 'bg-emerald-500'
                        }`}
                        style={{ width: `${selectedRecord.risk_score_additive}%` }}
                      />
                    </div>
                    <span className={`text-sm font-black ${
                      selectedRecord.risk_score_additive >= 75 ? 'text-red-400' :
                      selectedRecord.risk_score_additive >= 50 ? 'text-orange-400' :
                      selectedRecord.risk_score_additive >= 25 ? 'text-yellow-400' : 'text-emerald-400'
                    }`}>{selectedRecord.risk_score_additive}<span className="text-[9px] text-slate-500 font-normal">/100</span></span>
                  </div>
                )}
                {selectedRecord.soc_action && (
                  <span className="text-[9px] font-black uppercase tracking-widest text-slate-400 border border-white/10 rounded-lg px-2 py-1">
                    {selectedRecord.soc_action.replace('_', ' ')}
                  </span>
                )}
                <div className="ml-auto flex flex-col items-end gap-0.5">
                  <span className="text-[9px] font-bold text-slate-300">{selectedRecord.source}</span>
                  <span className="text-[9px] font-mono text-slate-600">{new Date(selectedRecord.collected_at).toLocaleString('fr-FR')}</span>
                </div>
              </div>

              {/* ── Per-IOC Enrichment ── */}
              {(selectedRecord.iocs || []).map(ioc => {
                const e = ioc.ioc_enrichment || {};
                const hasGeo   = !!(e.country || e.country_name);
                const hasVT    = (e.vt_total_engines ?? 0) > 0;
                const hasAbuse = e.abuseConfidenceScore != null;
                if (!hasGeo && !hasVT && !hasAbuse) return null;

                const flagEmoji = (code) => {
                  if (!code || code.length !== 2) return '🌐';
                  return String.fromCodePoint(...[...code.toUpperCase()].map(c => 0x1F1E6 + c.charCodeAt(0) - 65));
                };

                const typeColors = {
                  ip:     'bg-blue-500/10 text-blue-400 border-blue-500/20',
                  domain: 'bg-emerald-500/10 text-emerald-400 border-emerald-500/20',
                  url:    'bg-purple-500/10 text-purple-400 border-purple-500/20',
                  hash:   'bg-amber-500/10 text-amber-400 border-amber-500/20',
                  sha256: 'bg-amber-500/10 text-amber-400 border-amber-500/20',
                  md5:    'bg-amber-500/10 text-amber-400 border-amber-500/20',
                  cve:    'bg-rose-500/10 text-rose-400 border-rose-500/20',
                };

                return (
                  <div key={ioc.value} className="glass-panel rounded-2xl border border-white/5 overflow-hidden">
                    {/* IOC identifier row */}
                    <div className="px-4 py-2.5 bg-white/5 border-b border-white/5 flex items-center justify-between gap-3">
                      <div className="flex items-center gap-2 min-w-0">
                        <span className={`flex-shrink-0 px-2 py-0.5 rounded text-[9px] font-black uppercase border ${typeColors[ioc.type] || 'bg-slate-500/10 text-slate-400 border-slate-500/20'}`}>
                          {ioc.type}
                        </span>
                        <span className="font-mono text-xs text-white truncate">{ioc.value}</span>
                      </div>
                      {ioc.risk_score != null && (
                        <div className="flex items-center gap-1.5 flex-shrink-0">
                          <span className="text-[9px] text-slate-500 uppercase">Risk</span>
                          <span className={`text-xs font-black ${
                            ioc.risk_score >= 70 ? 'text-red-400' :
                            ioc.risk_score >= 40 ? 'text-orange-400' : 'text-emerald-400'
                          }`}>{ioc.risk_score}</span>
                        </div>
                      )}
                    </div>

                    {/* Enrichment 3-column grid */}
                    <div className="p-3 grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-3">

                      {/* Géolocalisation */}
                      {hasGeo && (
                        <div className="bg-emerald-500/5 border border-emerald-500/15 rounded-xl p-3">
                          <div className="flex items-center gap-1.5 mb-2">
                            <Globe size={11} className="text-emerald-400" />
                            <span className="text-[9px] font-black uppercase tracking-widest text-emerald-400">Géolocalisation</span>
                          </div>
                          <div className="space-y-1.5">
                            {(e.country || e.country_name) && (
                              <div className="flex items-center justify-between gap-2">
                                <span className="text-[9px] text-slate-500 uppercase flex-shrink-0">Pays</span>
                                <span className="text-xs font-bold text-white text-right">
                                  {flagEmoji(e.country)} {e.country_name || e.country}
                                </span>
                              </div>
                            )}
                            {e.country && (
                              <div className="flex items-center justify-between">
                                <span className="text-[9px] text-slate-500 uppercase">Code</span>
                                <span className="text-[10px] font-mono text-slate-300">{e.country}</span>
                              </div>
                            )}
                          </div>
                        </div>
                      )}

                      {/* VirusTotal */}
                      {hasVT && (
                        <div className="bg-blue-500/5 border border-blue-500/15 rounded-xl p-3">
                          <div className="flex items-center gap-1.5 mb-2">
                            <img
                              src="https://www.google.com/s2/favicons?domain=virustotal.com&sz=16"
                              className="w-3 h-3"
                              alt=""
                              onError={ev => { ev.target.style.display = 'none'; }}
                            />
                            <span className="text-[9px] font-black uppercase tracking-widest text-blue-400">VirusTotal</span>
                          </div>
                          <div className="flex h-1.5 rounded-full overflow-hidden mb-2 bg-white/5">
                            {(e.vt_malicious_count ?? 0) > 0 && <div className="bg-red-500" style={{ width: `${(e.vt_malicious_count / e.vt_total_engines) * 100}%` }} />}
                            {(e.vt_suspicious_count ?? 0) > 0 && <div className="bg-orange-400" style={{ width: `${(e.vt_suspicious_count / e.vt_total_engines) * 100}%` }} />}
                            {(e.vt_harmless_count ?? 0) > 0 && <div className="bg-emerald-500" style={{ width: `${(e.vt_harmless_count / e.vt_total_engines) * 100}%` }} />}
                          </div>
                          <div className="space-y-1">
                            {(e.vt_malicious_count ?? 0) > 0 && (
                              <div className="flex justify-between">
                                <span className="text-[9px] text-red-400 font-bold">Malicious</span>
                                <span className="text-[9px] font-mono text-red-300">{e.vt_malicious_count} / {e.vt_total_engines}</span>
                              </div>
                            )}
                            {(e.vt_suspicious_count ?? 0) > 0 && (
                              <div className="flex justify-between">
                                <span className="text-[9px] text-orange-400 font-bold">Suspicious</span>
                                <span className="text-[9px] font-mono text-orange-300">{e.vt_suspicious_count} / {e.vt_total_engines}</span>
                              </div>
                            )}
                            {(e.vt_harmless_count ?? 0) > 0 && (
                              <div className="flex justify-between">
                                <span className="text-[9px] text-emerald-400">Harmless</span>
                                <span className="text-[9px] font-mono text-emerald-300">{e.vt_harmless_count} / {e.vt_total_engines}</span>
                              </div>
                            )}
                            {e.vt_reputation != null && (
                              <div className="flex justify-between border-t border-white/5 pt-1 mt-1">
                                <span className="text-[9px] text-slate-500">Réputation</span>
                                <span className={`text-[9px] font-black ${e.vt_reputation < 0 ? 'text-red-400' : 'text-emerald-400'}`}>{e.vt_reputation}</span>
                              </div>
                            )}
                          </div>
                        </div>
                      )}

                      {/* AbuseIPDB */}
                      {hasAbuse && (
                        <div className="bg-orange-500/5 border border-orange-500/15 rounded-xl p-3">
                          <div className="flex items-center gap-1.5 mb-2">
                            <img
                              src="https://www.google.com/s2/favicons?domain=abuseipdb.com&sz=16"
                              className="w-3 h-3"
                              alt=""
                              onError={ev => { ev.target.style.display = 'none'; }}
                            />
                            <span className="text-[9px] font-black uppercase tracking-widest text-orange-400">AbuseIPDB</span>
                          </div>
                          <div className="mb-2">
                            <div className="flex justify-between items-center mb-1">
                              <span className="text-[9px] text-slate-500">Confidence</span>
                              <span className={`text-sm font-black ${
                                e.abuseConfidenceScore >= 75 ? 'text-red-400' :
                                e.abuseConfidenceScore >= 50 ? 'text-orange-400' :
                                e.abuseConfidenceScore >= 25 ? 'text-yellow-400' : 'text-emerald-400'
                              }`}>{e.abuseConfidenceScore}%</span>
                            </div>
                            <div className="h-1.5 bg-white/5 rounded-full overflow-hidden">
                              <div
                                className={`h-full rounded-full ${
                                  e.abuseConfidenceScore >= 75 ? 'bg-red-500' :
                                  e.abuseConfidenceScore >= 50 ? 'bg-orange-400' :
                                  e.abuseConfidenceScore >= 25 ? 'bg-yellow-400' : 'bg-emerald-500'
                                }`}
                                style={{ width: `${e.abuseConfidenceScore}%` }}
                              />
                            </div>
                          </div>
                          <div className="space-y-1">
                            {e.totalReports != null && (
                              <div className="flex justify-between">
                                <span className="text-[9px] text-slate-500 uppercase">Reports</span>
                                <span className="text-[9px] font-mono text-slate-300">{e.totalReports}</span>
                              </div>
                            )}
                            {e.isp && (
                              <div className="flex justify-between gap-2">
                                <span className="text-[9px] text-slate-500 uppercase flex-shrink-0">ISP</span>
                                <span className="text-[9px] font-mono text-slate-300 truncate text-right">{e.isp}</span>
                              </div>
                            )}
                            {e.lastReportedAt && (
                              <div className="flex justify-between">
                                <span className="text-[9px] text-slate-500 uppercase">Signalé le</span>
                                <span className="text-[9px] font-mono text-slate-400">{new Date(e.lastReportedAt).toLocaleDateString('fr-FR')}</span>
                              </div>
                            )}
                          </div>
                        </div>
                      )}
                    </div>
                  </div>
                );
              })}

              {/* Tags */}
              {(selectedRecord.tags || []).length > 0 && (
                <div className="glass-panel p-4 rounded-2xl border border-white/5">
                  <div className="flex items-center gap-2 mb-3">
                    <Bug size={12} className="text-brand-400" />
                    <span className="text-[9px] font-black uppercase tracking-widest text-brand-400">Tags</span>
                  </div>
                  <div className="flex flex-wrap gap-2">
                    {selectedRecord.tags.map(t => (
                      <span key={t} className="px-2.5 py-1 bg-brand-500/10 text-brand-400 border border-brand-500/20 rounded-full text-[10px] font-bold">{t}</span>
                    ))}
                  </div>
                </div>
              )}

              {/* Raw JSON Toggle */}
              <div>
                <button
                  onClick={() => setActiveTab(activeTab === 'raw' ? 'enrichment' : 'raw')}
                  className="w-full flex items-center justify-center gap-2 py-2 px-4 bg-white/5 hover:bg-white/10 text-slate-500 hover:text-slate-300 text-[10px] font-black uppercase tracking-widest rounded-xl transition-all border border-white/5"
                >
                  <Code size={12} />
                  {activeTab === 'raw' ? 'MASQUER' : 'VOIR'} RAW JSON
                </button>
                {activeTab === 'raw' && (
                  <div className="mt-3 glass-panel p-5 rounded-2xl border border-white/5">
                    <pre className="text-[11px] font-mono text-slate-400 whitespace-pre-wrap leading-relaxed overflow-x-auto max-h-[35vh]">
                      {JSON.stringify(selectedRecord, null, 2)}
                    </pre>
                  </div>
                )}
              </div>
            </div>
            
            {/* Modal Footer */}
            <footer className="p-4 border-t border-white/5 bg-black/40 flex justify-end">
              <button 
                onClick={() => setModalOpen(false)}
                className="px-6 py-2 bg-white/5 hover:bg-white/10 text-white text-xs font-black rounded-xl transition-all"
              >
                CLOSE REPORT
              </button>
            </footer>
          </div>
        </div>
      )}
    </div>
  );
};

export default Results;
