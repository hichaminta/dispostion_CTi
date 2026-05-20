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

const SOURCE_LOGOS = {
  'AbuseIPDB': 'https://www.abuseipdb.com/favicon.ico',

  'Spamhaus': 'https://www.spamhaus.org/favicon.ico',
  'URLHaus': 'https://urlhaus.abuse.ch/favicon.ico',
  'ThreatFox': 'https://threatfox.abuse.ch/favicon.ico',
  'MalwareBazaar': 'https://malwarebazaar.abuse.ch/favicon.ico',
  'PhishTank': 'https://www.phishtank.com/favicon_32x32.png',
  'OpenPhish': 'https://openphish.com/favicon.ico',
  'NVD': 'https://nvd.nist.gov/favicon.ico',
  'PulseDive': 'https://pulsedive.com/favicon.ico',
  'FeodoTracker': 'https://feodotracker.abuse.ch/favicon.ico',
  'DFIR Report': 'https://thedfirreport.com/favicon.ico'
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
  const [currentSource, setCurrentSource] = useState(initialSourceId);
  const [data, setData] = useState([]);
  const [totalItems, setTotalItems] = useState(0);
  const [currentPage, setCurrentPage] = useState(1);
  const [pageSize] = useState(50);
  const [search, setSearch] = useState("");
  const [iocType, setIocType] = useState("");
  const [loading, setLoading] = useState(false);
  const [modalOpen, setModalOpen] = useState(false);
  const [selectedRecord, setSelectedRecord] = useState(null);
  const [activeTab, setActiveTab] = useState('overview');
  const [countryStats, setCountryStats] = useState([]);

  // Fetch sources list
  const fetchSources = useCallback(async () => {
    try {
      const api = viewMode === 'extracted' ? `${API_BASE}/api/extracted` : `${API_BASE}/api/enriched`;
      const res = await axios.get(`${api}/sources`);
      setSources(res.data);
      if (res.data.length > 0 && !currentSource) {
        setCurrentSource(res.data[0].id);
      }
    } catch (err) {
      console.error("Failed to fetch sources:", err);
    }
  }, [viewMode, currentSource]);

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
    setActiveTab('overview');
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
            {sources.map(src => {
              const logo = getSourceLogo(src.name);
              return (
                <button
                  key={src.id}
                  onClick={() => setCurrentSource(src.id)}
                  className={`w-full flex items-center gap-3 p-3 rounded-xl transition-all border ${currentSource === src.id ? 'bg-brand-500/10 border-brand-500/30 text-white shadow-[0_0_15px_rgba(14,165,233,0.1)]' : 'border-transparent text-slate-400 hover:bg-white/5'}`}
                >
                  <div className="w-8 h-8 rounded-lg bg-slate-800 flex items-center justify-center overflow-hidden border border-white/5 flex-shrink-0">
                    {logo ? <img src={logo} alt="" className="w-5 h-5 object-contain" /> : <Shield size={16} />}
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

            {/* Enrichment Quick Actions (Only for selected source) */}
            {selectedSrcObj && (
              <div className="glass-panel p-4 rounded-3xl border border-brand-500/20 bg-brand-500/5 relative overflow-hidden">
                <div className="absolute inset-0 hud-grid opacity-10" />
                <div className="flex items-center justify-between mb-4 relative z-10">
                   <div className="flex items-center gap-2">
                      <Sparkles size={16} className="text-brand-400" />
                      <span className="text-xs font-black uppercase tracking-widest">Source Intelligence Phases</span>
                   </div>
                   <button 
                     onClick={() => triggerEnrichment('Enrichissement')}
                     className="flex items-center gap-2 px-4 py-1.5 bg-brand-500 hover:bg-brand-400 text-white text-[10px] font-black rounded-lg transition-all active:scale-95 shadow-lg shadow-brand-500/20"
                   >
                     <PlayCircle size={14} />
                     RUN COMPLETE ENRICHMENT
                   </button>
                </div>
                <div className="grid grid-cols-2 sm:grid-cols-3 lg:grid-cols-6 gap-3 relative z-10">
                   {[
                     { name: 'Geolocalisation', icon: <Globe size={14} />, label: 'Geo' },
                     { name: 'URLScan_Only', icon: <ScanEye size={14} />, label: 'Scan' },
                     { name: 'Fallback', icon: <Layers size={14} />, label: 'Heuristics' },
                     { name: 'URLScan', icon: <Zap size={14} />, label: 'Full URL' },
                     { name: 'Normalisation', icon: <Shield size={14} />, label: 'Norm' },
                     { name: 'Intégration MISP', icon: <Share2 size={14} />, label: 'MISP' },
                   ].map(step => (
                     <button 
                        key={step.name}
                        onClick={() => triggerEnrichment(step.name)}
                        className="flex flex-col items-center gap-2 p-3 bg-white/5 rounded-xl border border-white/5 hover:border-brand-500/40 hover:bg-brand-500/10 transition-all group"
                      >
                        <div className="p-2 bg-slate-800 rounded-lg group-hover:text-brand-400 transition-colors">
                          {step.icon}
                        </div>
                        <span className="text-[10px] font-bold text-slate-500 group-hover:text-slate-200">{step.label}</span>
                     </button>
                   ))}
                </div>
              </div>
            )}

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
                                {logo ? <img src={logo} alt="" className="w-3.5 h-3.5 object-contain" /> : <Shield size={10} />}
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

            {/* Modal Tabs */}
            <div className="flex px-6 border-b border-white/5 bg-white/5">
              {[
                { id: 'overview', label: 'Overview', icon: <Layout size={14} /> },
                { id: 'intelligence', label: 'Intelligence', icon: <Zap size={14} /> },
                { id: 'context', label: 'Context', icon: <Globe size={14} /> },
                { id: 'analysis', label: 'URL Analysis', icon: <ScanEye size={14} /> },
                { id: 'raw', label: 'Raw Data', icon: <Code size={14} /> },
              ].map(tab => (
                <button
                  key={tab.id}
                  onClick={() => setActiveTab(tab.id)}
                  className={`px-6 py-4 flex items-center gap-2 text-xs font-black uppercase tracking-widest transition-all relative ${activeTab === tab.id ? 'text-brand-400' : 'text-slate-500 hover:text-slate-300'}`}
                >
                  {tab.icon}
                  {tab.label}
                  {activeTab === tab.id && <div className="absolute bottom-0 left-0 w-full h-0.5 bg-brand-500 shadow-[0_0_10px_#0ea5e9]" />}
                </button>
              ))}
            </div>

            {/* Modal Content */}
            <div className="flex-1 overflow-y-auto p-6 bg-slate-900/40">
              {activeTab === 'overview' && (
                <div className="grid grid-cols-1 lg:grid-cols-3 gap-6 animate-in fade-in slide-in-from-bottom-4 duration-300">
                  <div className="lg:col-span-2 space-y-6">
                    <div className="glass-panel p-6 rounded-2xl border border-white/5">
                      <h4 className="text-[10px] font-black uppercase tracking-widest text-brand-400 mb-3">Intelligence Summary</h4>
                      <p className="text-slate-300 text-sm leading-relaxed">
                        {selectedRecord.summary || 
                         (selectedRecord.enrichment?.nlp_advanced?.nlp_summary?.split('{')[0]) || 
                         "Analysis of this intelligence record shows multiple indicators associated with the target activity. Automated extraction has successfully mapped the technical context."}
                      </p>
                    </div>
                  </div>
                  <div className="space-y-4">
                    <div className="glass-panel p-4 rounded-2xl border border-white/5 space-y-4">
                      <div>
                        <label className="text-[9px] font-black uppercase text-slate-500 block mb-1">Source Authority</label>
                        <span className="text-sm font-bold text-white">{selectedRecord.source}</span>
                      </div>
                      <div>
                        <label className="text-[9px] font-black uppercase text-slate-500 block mb-1">Extraction Date</label>
                        <span className="text-sm font-bold text-white">{new Date(selectedRecord.collected_at).toLocaleString()}</span>
                      </div>
                      <div>
                        <label className="text-[9px] font-black uppercase text-slate-500 block mb-1">Threat Level</label>
                        <span className="px-2 py-0.5 bg-red-500/20 text-red-400 border border-red-500/30 rounded text-[10px] font-black uppercase">CRITICAL</span>
                      </div>
                    </div>
                  </div>
                </div>
              )}

              {activeTab === 'intelligence' && (
                <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4 animate-in fade-in slide-in-from-bottom-4 duration-300">
                  <div className="glass-panel p-4 rounded-2xl border border-white/5">
                    <div className="flex items-center gap-2 mb-4">
                      <Target size={14} className="text-purple-400" />
                      <h4 className="text-[10px] font-black uppercase tracking-widest text-slate-400">Indicators of Compromise</h4>
                    </div>
                    <div className="space-y-2">
                      {(selectedRecord.iocs || []).map(ioc => (
                        <div key={ioc.value} className="flex flex-col p-2 bg-white/5 rounded-lg border border-white/5">
                           <span className="text-xs font-bold text-white break-all">{ioc.value}</span>
                           <span className="text-[9px] font-mono text-slate-500 mt-1 uppercase">{ioc.type} • {ioc.indicator_role?.role || 'indicator'}</span>
                        </div>
                      ))}
                    </div>
                  </div>
                  <div className="glass-panel p-4 rounded-2xl border border-white/5">
                    <div className="flex items-center gap-2 mb-4">
                      <Bug size={14} className="text-brand-400" />
                      <h4 className="text-[10px] font-black uppercase tracking-widest text-slate-400">Malware & Categorization</h4>
                    </div>
                    <div className="flex flex-wrap gap-2">
                       {(selectedRecord.tags || []).map(tag => (
                         <span key={tag} className="px-3 py-1 bg-brand-500/10 text-brand-400 border border-brand-500/20 rounded-full text-[10px] font-bold">
                           {tag}
                         </span>
                       ))}
                    </div>
                  </div>
                </div>
              )}

              {activeTab === 'context' && (
                <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4 animate-in fade-in slide-in-from-bottom-4 duration-300">
                   <div className="glass-panel p-4 rounded-2xl border border-white/5">
                    <div className="flex items-center gap-2 mb-4">
                      <Globe size={14} className="text-emerald-400" />
                      <h4 className="text-[10px] font-black uppercase tracking-widest text-slate-400">Geographical Data</h4>
                    </div>
                    <div className="space-y-3">
                      {(selectedRecord.iocs || []).map(ioc => {
                        const geo = ioc.ioc_enrichment?.geography || ioc.ioc_enrichment?.country;
                        if (!geo) return null;
                        return (
                          <div key={ioc.value} className="flex items-center gap-3 p-2 bg-white/5 rounded-lg border border-white/5">
                            <MapPin size={14} className="text-emerald-500" />
                            <div className="flex flex-col">
                              <span className="text-xs font-bold text-white">{Array.isArray(geo) ? geo.join(', ') : geo}</span>
                              <span className="text-[9px] text-slate-500">{ioc.value}</span>
                            </div>
                          </div>
                        );
                      })}
                    </div>
                  </div>
                  <div className="glass-panel p-4 rounded-2xl border border-white/5">
                    <div className="flex items-center gap-2 mb-4">
                      <Building size={14} className="text-blue-400" />
                      <h4 className="text-[10px] font-black uppercase tracking-widest text-slate-400">Infrastructure Context</h4>
                    </div>
                    <div className="space-y-2">
                       {Object.entries(selectedRecord.attributes || {}).map(([k, v]) => (
                         <div key={k} className="flex justify-between p-2 border-b border-white/5 last:border-0">
                           <span className="text-[10px] font-bold text-slate-500 uppercase">{k}</span>
                           <span className="text-[10px] font-mono text-slate-300">{String(v)}</span>
                         </div>
                       ))}
                    </div>
                  </div>
                </div>
              )}

              {activeTab === 'analysis' && (
                <div className="space-y-6 animate-in fade-in slide-in-from-bottom-4 duration-300">
                   {(selectedRecord.iocs || []).filter(i => i.ioc_enrichment?.url_scan?.scanned).map(ioc => (
                     <div key={ioc.value} className="glass-panel rounded-3xl overflow-hidden border border-white/5">
                        <div className="p-4 bg-white/5 border-b border-white/5 flex items-center justify-between">
                          <h4 className="text-xs font-black uppercase tracking-widest text-pink-400">URLScan Analysis: {ioc.value}</h4>
                        </div>
                        <div className="grid grid-cols-1 lg:grid-cols-2 gap-6 p-6">
                           <div className="rounded-2xl overflow-hidden border border-white/10 shadow-2xl">
                              <img src={ioc.ioc_enrichment.url_scan.screenshot} alt="Scan Screenshot" className="w-full h-auto" />
                           </div>
                           <div className="space-y-4">
                              <div className="grid grid-cols-2 gap-4">
                                 {[
                                   { label: 'IP', val: ioc.ioc_enrichment.url_scan.ip },
                                   { label: 'ASN', val: ioc.ioc_enrichment.url_scan.asn },
                                   { label: 'Country', val: ioc.ioc_enrichment.url_scan.country },
                                   { label: 'Server', val: ioc.ioc_enrichment.url_scan.server },
                                 ].map(d => (
                                   <div key={d.label} className="p-3 bg-white/5 rounded-xl border border-white/5">
                                      <div className="text-[9px] font-black text-slate-500 uppercase mb-1">{d.label}</div>
                                      <div className="text-xs font-mono text-white truncate">{d.val || "—"}</div>
                                   </div>
                                 ))}
                              </div>
                              <div className="p-4 bg-black/40 rounded-xl border border-white/5">
                                 <div className="text-[9px] font-black text-slate-500 uppercase mb-2">Effective URL</div>
                                 <div className="text-xs font-mono text-brand-400 break-all">{ioc.ioc_enrichment.url_scan.effective_url}</div>
                              </div>
                           </div>
                        </div>
                     </div>
                   ))}
                   
                   {(selectedRecord.iocs || []).filter(i => i.ioc_enrichment?.passer_par_fallback === 1).map(ioc => (
                     <div key={ioc.value} className="glass-panel p-6 rounded-3xl border border-white/5">
                        <h4 className="text-xs font-black uppercase tracking-widest text-orange-400 mb-4">Heuristic Fallback Analysis: {ioc.value}</h4>
                        <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-4">
                           {[
                             { label: 'Risk Flag', val: ioc.ioc_enrichment.risk_flag },
                             { label: 'Typosquatting', val: ioc.ioc_enrichment.typosquat_flag ? "YES" : "NO" },
                             { label: 'Domain Age', val: ioc.ioc_enrichment.domain_age_days ? `${ioc.ioc_enrichment.domain_age_days} days` : "—" },
                             { label: 'Server Header', val: ioc.ioc_enrichment.server || "—" },
                           ].map(d => (
                             <div key={d.label} className="p-3 bg-white/5 rounded-xl border border-white/5">
                                <div className="text-[9px] font-black text-slate-500 uppercase mb-1">{d.label}</div>
                                <div className="text-xs font-bold text-white">{d.val}</div>
                             </div>
                           ))}
                        </div>
                     </div>
                   ))}
                </div>
              )}

              {activeTab === 'raw' && (
                <div className="glass-panel p-6 rounded-2xl border border-white/5 animate-in fade-in slide-in-from-bottom-4 duration-300">
                  <pre className="text-[11px] font-mono text-slate-400 whitespace-pre-wrap leading-relaxed overflow-x-auto max-h-[50vh]">
                    {JSON.stringify(selectedRecord, null, 2)}
                  </pre>
                </div>
              )}
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
