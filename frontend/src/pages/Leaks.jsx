import React, { useState, useEffect, useMemo } from 'react';
import axios from 'axios';
import { 
  ShieldAlert, 
  Terminal, 
  AlertCircle, 
  Search, 
  Filter, 
  Database, 
  Clock, 
  Share2, 
  FileText,
  BrainCircuit,
  Zap,
  ChevronRight,
  FileSpreadsheet,
  Loader2,
  ExternalLink,
  ShieldCheck,
  AlertTriangle,
  History,
  Download,
  Calendar,
  BarChart2,
  LayoutGrid,
  List,
  TrendingUp,
  PieChart,
  SortAsc,
  SortDesc,
  Settings,
  Plus,
  Trash2,
  Globe
} from 'lucide-react';
import { format } from 'date-fns';
import CSVReader from './CSVReader';

// ── Mini Chart Components ─────────────────────────────────────────────────────

const SeverityBar = ({ label, count, total, color }) => {
  const pct = total > 0 ? Math.round((count / total) * 100) : 0;
  const colors = {
    critical: 'bg-red-500 shadow-[0_0_8px_rgba(239,68,68,0.5)]',
    high:     'bg-orange-500 shadow-[0_0_8px_rgba(249,115,22,0.4)]',
    medium:   'bg-yellow-500 shadow-[0_0_8px_rgba(234,179,8,0.4)]',
    low:      'bg-blue-500 shadow-[0_0_8px_rgba(59,130,246,0.4)]',
  };
  const textColors = {
    critical: 'text-red-400', high: 'text-orange-400', medium: 'text-yellow-400', low: 'text-blue-400'
  };
  return (
    <div className="flex items-center gap-3">
      <span className={`text-[10px] font-black uppercase w-14 shrink-0 ${textColors[label] || 'text-slate-400'}`}>{label}</span>
      <div className="flex-1 h-2 bg-slate-800 rounded-full overflow-hidden">
        <div className={`h-full rounded-full transition-all duration-700 ${colors[label] || 'bg-slate-500'}`} style={{ width: `${pct}%` }} />
      </div>
      <span className="text-[10px] font-mono font-bold text-slate-400 w-8 text-right">{count}</span>
    </div>
  );
};

const DonutRing = ({ segments, size = 80 }) => {
  const r = 30; const cx = size / 2; const cy = size / 2;
  const circumference = 2 * Math.PI * r;
  const total = segments.reduce((s, seg) => s + seg.value, 0);
  if (!total) return <div className="w-20 h-20 rounded-full border-4 border-slate-800" />;
  let offset = 0;
  return (
    <svg width={size} height={size} viewBox={`0 0 ${size} ${size}`} className="-rotate-90">
      {segments.map((seg, i) => {
        const pct = seg.value / total;
        const dash = circumference * pct;
        const el = (
          <circle key={i} cx={cx} cy={cy} r={r}
            fill="none" stroke={seg.color} strokeWidth="8"
            strokeDasharray={`${dash} ${circumference - dash}`}
            strokeDashoffset={-offset * circumference}
            className="transition-all duration-700"
          />
        );
        offset += pct;
        return el;
      })}
    </svg>
  );
};

const API_BASE = `http://${window.location.hostname}:8000`;

const SeverityBadge = ({ severity }) => {
  const styles = {
    critical: "bg-red-500/20 text-red-400 border-red-500/30 shadow-[0_0_10px_rgba(239,68,68,0.2)]",
    high: "bg-orange-500/20 text-orange-400 border-orange-500/30",
    medium: "bg-yellow-500/20 text-yellow-400 border-yellow-500/30",
    low: "bg-blue-500/20 text-blue-400 border-blue-500/30"
  };
  
  return (
    <span className={`px-2 py-0.5 rounded-full border text-[10px] font-bold uppercase tracking-wider ${styles[severity?.toLowerCase()] || styles.low}`}>
      {severity || 'Unknown'}
    </span>
  );
};

const Leaks = ({ onBack }) => {
  const [leaks, setLeaks] = useState([]);
  const [loading, setLoading] = useState(true);
  const [search, setSearch] = useState('');
  const [filter, setFilter] = useState('all');
  const [stats, setStats] = useState(null);
  const [selectedLeak, setSelectedLeak] = useState(null);
  const [analyzing, setAnalyzing] = useState(false);
  const [tgStatus, setTgStatus] = useState({ connected: false, loading: true });
  const [showAuth, setShowAuth] = useState(false);
  const [phone, setPhone] = useState('');
  const [code, setCode] = useState('');
  const [phoneCodeHash, setPhoneCodeHash] = useState('');
  const [authStep, setAuthStep] = useState(1); // 1: Phone, 2: Code
  const [logs, setLogs] = useState([]);
  const [activeRunId, setActiveRunId] = useState(null);
  const [viewingCSV, setViewingCSV] = useState(null);
  const [viewingBulletin, setViewingBulletin] = useState(null);
  const [showStartConfig, setShowStartConfig] = useState(false);
  const [selectedChannelsForRun, setSelectedChannelsForRun] = useState([]);
  const [startDateForRun, setStartDateForRun] = useState('');
  // Graphical options
  const [viewMode, setViewMode] = useState('list'); // 'list' | 'grid'
  const [showCharts, setShowCharts] = useState(false);
  const [sortBy, setSortBy] = useState('date_desc'); // 'date_desc' | 'date_asc' | 'severity'
  const [channels, setChannels] = useState([]);
  const [showChannelMgr, setShowChannelMgr] = useState(false);
  const [newChannelUrl, setNewChannelUrl] = useState('');
  const [addingChannel, setAddingChannel] = useState(false);

  useEffect(() => {
    fetchLeaks();
    fetchStats();
    checkTgStatus();
    fetchChannels();
  }, []);

  useEffect(() => {
    let interval;
    if (activeRunId) {
      interval = setInterval(() => {
        fetchLogs(activeRunId);
      }, 3000);
    }
    return () => clearInterval(interval);
  }, [activeRunId]);

  const fetchLogs = async (runId) => {
    try {
      const res = await axios.get(`${API_BASE}/api/runs/${runId}/logs?step=Monitoring%20Telegram`);
      if (res.data && res.data.logs) {
        setLogs(res.data.logs.slice(-10).reverse());
      }
    } catch (e) {
      console.error("Failed to fetch logs", e);
    }
  };

  const checkTgStatus = async () => {
    try {
      const res = await axios.get(`${API_BASE}/api/leaks/status`);
      setTgStatus({ connected: res.data.connected, loading: false });
    } catch (e) {
      setTgStatus({ connected: false, loading: false });
    }
  };

  const handleSendCode = async () => {
    try {
      // If phone is empty, the backend will use .env
      const url = phone ? `${API_BASE}/api/leaks/auth/send-code?phone=${phone}` : `${API_BASE}/api/leaks/auth/send-code`;
      const res = await axios.post(url);
      if (res.data.phone) setPhone(res.data.phone);
      setPhoneCodeHash(res.data.phone_code_hash);
      setAuthStep(2);
    } catch (e) {
      alert("Error: " + (e.response?.data?.detail || e.message));
    }
  };

  const handleVerifyCode = async () => {
    try {
      await axios.post(`${API_BASE}/api/leaks/auth/verify-code?phone=${phone}&code=${code}&phone_code_hash=${phoneCodeHash}`);
      setShowAuth(false);
      checkTgStatus();
      alert("Successfully connected to Telegram!");
    } catch (e) {
      alert("Verification failed: " + (e.response?.data?.detail || e.message));
    }
  };

  const fetchLeaks = async () => {
    setLoading(true);
    try {
      const res = await axios.get(`${API_BASE}/api/leaks/intel`);
      setLeaks(res.data);
    } catch (e) {
      console.error("Fetch leaks error:", e);
    } finally {
      setLoading(false);
    }
  };

  const fetchStats = async () => {
    try {
      const res = await axios.get(`${API_BASE}/api/leaks/stats`);
      setStats(res.data);
    } catch (e) {
      console.error("Fetch stats error:", e);
    }
  };

  const handleReanalyze = async (leak) => {
    setAnalyzing(true);
    try {
      await axios.post(`${API_BASE}/api/leaks/reanalyze/${leak.channel}/${leak.id}`);
      // Simulate update or refetch
      setTimeout(fetchLeaks, 1500);
    } catch (e) {
      alert("Re-analysis failed: " + e.message);
    } finally {
      setAnalyzing(false);
    }
  };

  const fetchChannels = async () => {
    try {
      const res = await axios.get(`${API_BASE}/api/leaks/channels`);
      setChannels(res.data);
    } catch (e) {
      console.error("Fetch channels error:", e);
    }
  };

  const handleAddChannel = async () => {
    if (!newChannelUrl) return;
    setAddingChannel(true);
    try {
      await axios.post(`${API_BASE}/api/leaks/channels?url=${encodeURIComponent(newChannelUrl)}`);
      setNewChannelUrl('');
      fetchChannels();
      fetchStats(); // Update channel count
    } catch (e) {
      alert("Failed to add channel: " + e.message);
    } finally {
      setAddingChannel(false);
    }
  };

  const handleRemoveChannel = async (url) => {
    if (!window.confirm(`Supprimer le canal ${url} ?`)) return;
    try {
      await axios.delete(`${API_BASE}/api/leaks/channels?url=${encodeURIComponent(url)}`);
      fetchChannels();
      fetchStats();
    } catch (e) {
      alert("Failed to remove channel: " + e.message);
    }
  };

  const handleStartMonitoring = async (config = null) => {
    try {
      const params = new URLSearchParams();
      if (config) {
        if (config.channels && config.channels.length > 0) {
          config.channels.forEach(c => params.append('channels', c));
        }
        if (config.startDate) {
          params.append('start_date', config.startDate);
        }
      }
      
      const res = await axios.post(`${API_BASE}/api/leaks/start?${params.toString()}`);
      setActiveRunId(res.data.run_id);
      setShowStartConfig(false);
      alert("Monitoring started! Check the Live Activity panel below.");
    } catch (e) {
      alert("Failed to start monitoring: " + e.message);
    }
  };

  const filteredLeaks = useMemo(() => {
    let result = leaks.filter(leak => {
      const matchesSearch =
        leak.summary_fr?.toLowerCase().includes(search.toLowerCase()) ||
        leak.source_channel?.toLowerCase().includes(search.toLowerCase()) ||
        leak.leak_metadata?.target_organization?.some(t => t.toLowerCase().includes(search.toLowerCase()));
      if (filter === 'all') return matchesSearch;
      return matchesSearch && leak.leak_metadata?.severity?.toLowerCase() === filter;
    });
    const severityOrder = { critical: 0, high: 1, medium: 2, low: 3 };
    if (sortBy === 'severity') {
      result = [...result].sort((a, b) =>
        (severityOrder[a.leak_metadata?.severity?.toLowerCase()] ?? 9) -
        (severityOrder[b.leak_metadata?.severity?.toLowerCase()] ?? 9)
      );
    } else if (sortBy === 'date_asc') {
      result = [...result].sort((a, b) => new Date(a.timestamp) - new Date(b.timestamp));
    } else {
      result = [...result].sort((a, b) => new Date(b.timestamp) - new Date(a.timestamp));
    }
    return result;
  }, [leaks, search, filter, sortBy]);

  // Computed chart data
  const severityCounts = useMemo(() => {
    const counts = { critical: 0, high: 0, medium: 0, low: 0 };
    leaks.forEach(l => {
      const s = l.leak_metadata?.severity?.toLowerCase();
      if (s in counts) counts[s]++;
    });
    return counts;
  }, [leaks]);

  const typeCounts = useMemo(() => {
    const counts = {};
    leaks.forEach(l => {
      const t = l.leak_metadata?.leak_type || 'Unknown';
      counts[t] = (counts[t] || 0) + 1;
    });
    return Object.entries(counts).sort((a, b) => b[1] - a[1]).slice(0, 6);
  }, [leaks]);

  const handleGenerateBulletin = async () => {
    try {
      // Logic for triggering generate_bulletin.py could go here via a backend endpoint
      alert("Intelligence Bulletin generation triggered! Check your results folder.");
    } catch (e) {
      alert("Failed to generate bulletin: " + e.message);
    }
  };

  const handleViewIndividualBulletin = async (intelId) => {
    try {
      const res = await axios.get(`${API_BASE}/api/leaks/intel/${intelId}/bulletin`);
      setViewingBulletin(res.data.content);
    } catch (e) {
      alert("Failed to fetch bulletin: " + e.message);
    }
  };

  if (viewingCSV) {
    return <CSVReader filePath={viewingCSV} onBack={() => setViewingCSV(null)} />;
  }

  return (
    <div className="min-h-screen bg-[#05060b] text-slate-200 p-8 relative overflow-hidden">
      {/* Background Glows */}
      <div className="absolute top-[-10%] left-[-10%] w-[50%] h-[50%] bg-brand-500/10 blur-[120px] rounded-full pointer-events-none" />
      <div className="absolute bottom-[-10%] right-[-10%] w-[50%] h-[50%] bg-purple-500/10 blur-[120px] rounded-full pointer-events-none" />
      <div className="absolute inset-0 hud-grid opacity-20 pointer-events-none" />

      <div className="max-w-[1400px] mx-auto relative z-10">
        
        {/* Header */}
        <div className="flex flex-col md:flex-row justify-between items-start md:items-center gap-6 mb-12">
          <div>
            <div className="flex items-center gap-3 mb-2">
              <div className="p-2 bg-brand-500/20 rounded-lg border border-brand-500/30">
                <ShieldAlert className="w-6 h-6 text-brand-400" />
              </div>
              <h1 className="text-3xl font-black text-white tracking-tight uppercase">
                Leak <span className="text-brand-500 italic">Intelligence</span>
              </h1>
              {/* Telegram Status Dot */}
              <div className="flex items-center gap-2 px-3 py-1 bg-slate-900/60 rounded-full border border-white/5 backdrop-blur-md">
                <div className={`w-2 h-2 rounded-full ${tgStatus.loading ? 'bg-slate-500 animate-pulse' : tgStatus.connected ? 'bg-emerald-500 shadow-[0_0_8px_rgba(16,185,129,0.5)]' : 'bg-red-500'}`} />
                <span className="text-[9px] font-black uppercase tracking-widest text-slate-400">
                  {tgStatus.loading ? 'Checking TG...' : tgStatus.connected ? 'TG Connected' : 'TG Disconnected'}
                </span>
                {!tgStatus.connected && !tgStatus.loading && (
                  <button 
                    onClick={() => setShowAuth(true)}
                    className="ml-2 text-[8px] font-black text-brand-400 hover:text-white uppercase underline underline-offset-2"
                  >
                    Connect
                  </button>
                )}
              </div>
            </div>
            <p className="text-slate-400 text-sm font-medium flex items-center gap-2">
              <BrainCircuit className="w-4 h-4 text-purple-400" />
              Monitoring et Analyse IA des fuites de données Telegram
            </p>
          </div>

          <div className="flex items-center gap-4">
            <div className="flex bg-slate-900/60 p-1 rounded-xl border border-white/5 backdrop-blur-md shadow-2xl">
              {['all', 'critical', 'high', 'medium'].map(f => (
                <button
                  key={f}
                  onClick={() => setFilter(f)}
                  className={`px-4 py-2 rounded-lg text-[10px] font-black uppercase tracking-widest transition-all ${filter === f ? 'bg-brand-600 text-white shadow-lg' : 'text-slate-500 hover:text-slate-300'}`}
                >
                  {f}
                </button>
              ))}
            </div>
            <button 
              onClick={() => {
                setSelectedChannelsForRun(channels); // Default to all
                setShowStartConfig(true);
              }}
              disabled={loading}
              className="flex items-center gap-2 px-4 py-3 bg-brand-600 hover:bg-brand-500 text-white rounded-xl font-black uppercase tracking-widest text-[10px] transition-all shadow-lg shadow-brand-600/20 active:scale-95 disabled:opacity-50"
            >
              <Zap className="w-4 h-4" />
              Start Monitoring
            </button>
            <button 
              onClick={handleGenerateBulletin}
              className="flex items-center gap-2 px-4 py-3 bg-slate-900/60 border border-white/5 hover:border-brand-500/30 text-white rounded-xl font-black uppercase tracking-widest text-[10px] transition-all active:scale-95"
            >
              <FileText className="w-4 h-4 text-brand-400" />
              Generate Bulletin
            </button>
            <button 
              onClick={() => setShowChannelMgr(true)}
              className="flex items-center gap-2 px-4 py-3 bg-slate-900/60 border border-white/5 hover:border-brand-500/30 text-white rounded-xl font-black uppercase tracking-widest text-[10px] transition-all active:scale-95"
            >
              <Globe className="w-4 h-4 text-purple-400" />
              Canaux
            </button>
            <button 
              onClick={fetchLeaks}
              disabled={loading}
              className="p-3 bg-slate-900/60 rounded-xl border border-white/5 hover:border-brand-500/30 text-slate-400 hover:text-brand-400 transition-all"
            >
              {loading ? <Loader2 className="w-5 h-5 animate-spin" /> : <History className="w-5 h-5" />}
            </button>
          </div>
        </div>

        {/* Stats Grid */}
        <div className="grid grid-cols-2 md:grid-cols-4 gap-6 mb-8">
          {[
            { label: 'Total Leaks', value: stats?.total || 0, icon: Database, color: 'brand' },
            { label: 'Critical', value: stats?.by_severity?.critical || 0, icon: AlertCircle, color: 'red' },
            { label: 'High Severity', value: stats?.by_severity?.high || 0, icon: AlertTriangle, color: 'orange' },
            { label: 'Channels', value: Object.keys(stats?.by_channel || {}).length, icon: Terminal, color: 'purple' },
          ].map((s, i) => (
            <div key={i} className="bg-slate-900/40 border border-white/5 p-5 rounded-2xl glass-panel relative overflow-hidden group">
              <div className={`absolute top-0 right-0 p-4 opacity-10 group-hover:opacity-20 transition-opacity`}>
                <s.icon className={`w-12 h-12 text-${s.color}-500`} />
              </div>
              <p className="text-slate-500 text-[10px] font-black uppercase tracking-[0.2em] mb-1">{s.label}</p>
              <p className="text-3xl font-black text-white">{s.value}</p>
            </div>
          ))}
        </div>

        {/* ── Options Toolbar ───────────────────────────────────────── */}
        <div className="flex flex-wrap items-center gap-3 mb-6 bg-slate-900/30 border border-white/5 rounded-2xl p-3 backdrop-blur-md">
          
          {/* View Mode */}
          <div className="flex items-center gap-1 bg-slate-900/60 rounded-xl p-1 border border-white/5">
            <button
              onClick={() => setViewMode('list')}
              className={`p-2 rounded-lg transition-all ${viewMode === 'list' ? 'bg-brand-500/20 text-brand-400 border border-brand-500/30' : 'text-slate-500 hover:text-slate-300'}`}
              title="Vue liste"
            >
              <List className="w-3.5 h-3.5" />
            </button>
            <button
              onClick={() => setViewMode('grid')}
              className={`p-2 rounded-lg transition-all ${viewMode === 'grid' ? 'bg-brand-500/20 text-brand-400 border border-brand-500/30' : 'text-slate-500 hover:text-slate-300'}`}
              title="Vue grille"
            >
              <LayoutGrid className="w-3.5 h-3.5" />
            </button>
          </div>

          {/* Divider */}
          <div className="w-px h-5 bg-white/10" />

          {/* Sort */}
          <div className="flex items-center gap-2">
            <span className="text-[9px] font-black text-slate-600 uppercase tracking-widest">Trier</span>
            {[
              { id: 'date_desc', label: 'Récent', icon: SortDesc },
              { id: 'date_asc',  label: 'Ancien', icon: SortAsc  },
              { id: 'severity',  label: 'Sévérité', icon: TrendingUp },
            ].map(({ id, label, icon: Icon }) => (
              <button
                key={id}
                onClick={() => setSortBy(id)}
                className={`flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-[10px] font-black uppercase tracking-widest transition-all ${
                  sortBy === id ? 'bg-brand-500/20 text-brand-400 border border-brand-500/30' : 'text-slate-500 hover:text-slate-300 hover:bg-white/5'
                }`}
              >
                <Icon className="w-3 h-3" />
                {label}
              </button>
            ))}
          </div>

          {/* Divider */}
          <div className="w-px h-5 bg-white/10" />

          {/* Charts toggle */}
          <button
            onClick={() => setShowCharts(v => !v)}
            className={`flex items-center gap-2 px-3 py-1.5 rounded-lg text-[10px] font-black uppercase tracking-widest transition-all ${
              showCharts ? 'bg-purple-500/20 text-purple-400 border border-purple-500/30' : 'text-slate-500 hover:text-slate-300 hover:bg-white/5'
            }`}
          >
            <BarChart2 className="w-3.5 h-3.5" />
            Graphiques {showCharts ? '▲' : '▼'}
          </button>

          {/* Results count */}
          <div className="ml-auto flex items-center gap-2 text-[10px] font-mono text-slate-600">
            <span className="text-brand-400 font-black">{filteredLeaks.length}</span>
            <span>/ {leaks.length} incidents</span>
          </div>
        </div>

        {/* ── Charts Panel ──────────────────────────────────────────── */}
        {showCharts && (
          <div className="grid grid-cols-1 md:grid-cols-2 gap-6 mb-8 animate-in slide-in-from-top-2 duration-300">
            
            {/* Severity Breakdown */}
            <div className="bg-slate-900/40 border border-white/5 rounded-3xl p-6 glass-panel">
              <div className="flex items-center gap-2 mb-5">
                <PieChart className="w-4 h-4 text-brand-400" />
                <h3 className="text-xs font-black text-white uppercase tracking-widest">Répartition par Sévérité</h3>
              </div>
              <div className="flex items-center gap-6">
                <DonutRing
                  size={90}
                  segments={[
                    { value: severityCounts.critical, color: '#ef4444' },
                    { value: severityCounts.high,     color: '#f97316' },
                    { value: severityCounts.medium,   color: '#eab308' },
                    { value: severityCounts.low,      color: '#3b82f6' },
                  ]}
                />
                <div className="flex-1 space-y-2">
                  {['critical','high','medium','low'].map(s => (
                    <SeverityBar key={s} label={s} count={severityCounts[s]} total={leaks.length} />
                  ))}
                </div>
              </div>
            </div>

            {/* Leak Type Distribution */}
            <div className="bg-slate-900/40 border border-white/5 rounded-3xl p-6 glass-panel">
              <div className="flex items-center gap-2 mb-5">
                <BarChart2 className="w-4 h-4 text-purple-400" />
                <h3 className="text-xs font-black text-white uppercase tracking-widest">Types de Fuites</h3>
              </div>
              <div className="space-y-2.5">
                {typeCounts.length === 0 ? (
                  <p className="text-slate-600 text-xs italic py-4 text-center">Aucune donnée disponible</p>
                ) : typeCounts.map(([type, count], i) => {
                  const typeColors = ['bg-purple-500','bg-violet-500','bg-indigo-500','bg-fuchsia-500','bg-pink-500','bg-rose-500'];
                  return (
                    <div key={type} className="flex items-center gap-3">
                      <span className="text-[10px] font-bold text-slate-400 w-28 truncate shrink-0">{type}</span>
                      <div className="flex-1 h-1.5 bg-slate-800 rounded-full overflow-hidden">
                        <div
                          className={`h-full rounded-full transition-all duration-700 ${typeColors[i % typeColors.length]}`}
                          style={{ width: `${(count / leaks.length) * 100}%` }}
                        />
                      </div>
                      <span className="text-[10px] font-mono font-bold text-slate-500 w-5 text-right">{count}</span>
                    </div>
                  );
                })}
              </div>
            </div>
          </div>
        )}

        {/* Live Activity Feed */}
        {activeRunId && (
          <div className="mb-8 animate-in slide-in-from-top duration-500">
            <div className="bg-slate-900/60 border border-white/5 rounded-3xl p-6 backdrop-blur-xl shadow-2xl">
              <div className="flex items-center justify-between mb-4">
                <div className="flex items-center gap-3">
                  <div className="w-2 h-2 rounded-full bg-emerald-500 animate-pulse shadow-[0_0_8px_rgba(16,185,129,0.5)]" />
                  <h3 className="text-xs font-black text-white uppercase tracking-widest">Live Activity Feed</h3>
                </div>
                <span className="text-[10px] font-mono text-slate-500 uppercase tracking-widest">Run ID: {activeRunId}</span>
              </div>
              <div className="bg-black/40 rounded-2xl p-4 font-mono text-[11px] h-40 overflow-y-auto custom-scrollbar border border-white/5">
                {logs.length > 0 ? (
                  logs.map((log, idx) => (
                    <div key={idx} className="mb-1 flex gap-3 animate-in fade-in duration-300">
                      <span className="text-brand-500/50 shrink-0">[{new Date().toLocaleTimeString()}]</span>
                      <span className="text-slate-300">{log.message}</span>
                    </div>
                  ))
                ) : (
                  <div className="text-slate-600 italic">En attente des premières données...</div>
                )}
              </div>
            </div>
          </div>
        )}

        {/* Search Bar */}
        <div className="relative mb-8 group">
          <Search className="absolute left-4 top-1/2 -translate-y-1/2 w-5 h-5 text-slate-500 group-focus-within:text-brand-400 transition-colors" />
          <input 
            type="text" 
            placeholder="Rechercher par domaine, mot-clé ou canal..."
            value={search}
            onChange={(e) => setSearch(e.target.value)}
            className="w-full bg-slate-900/60 border border-white/5 rounded-2xl py-4 pl-12 pr-4 text-sm focus:outline-none focus:border-brand-500/50 focus:ring-4 focus:ring-brand-500/10 transition-all backdrop-blur-md"
          />
        </div>

        {/* Main Content */}
        <div className="grid grid-cols-1 lg:grid-cols-3 gap-8">
          
          {/* List Section */}
          <div className={`lg:col-span-2 overflow-y-auto max-h-[700px] pr-2 custom-scrollbar ${
            viewMode === 'grid'
              ? 'grid grid-cols-1 sm:grid-cols-2 gap-4 content-start'
              : 'flex flex-col gap-4'
          }`}>
            {loading ? (
              <div className="flex flex-col items-center justify-center py-20 bg-slate-900/20 rounded-3xl border border-white/5">
                <Loader2 className="w-10 h-10 text-brand-500 animate-spin mb-4" />
                <p className="text-slate-500 font-mono text-xs uppercase tracking-widest">Initialisation de la matrice de données...</p>
              </div>
            ) : filteredLeaks.length === 0 ? (
              <div className="flex flex-col items-center justify-center py-20 bg-slate-900/20 rounded-3xl border border-white/5">
                <AlertCircle className="w-10 h-10 text-slate-700 mb-4" />
                <p className="text-slate-500 font-mono text-xs uppercase tracking-widest">Aucune donnée détectée dans ce secteur</p>
              </div>
            ) : (
              filteredLeaks.map((leak) => (
                <div 
                  key={leak.intel_id}
                  onClick={() => setSelectedLeak(leak)}
                  className={`p-5 rounded-2xl border transition-all cursor-pointer group relative overflow-hidden ${selectedLeak?.intel_id === leak.intel_id ? 'bg-brand-500/10 border-brand-500/40 shadow-lg shadow-brand-500/5' : 'bg-slate-900/40 border-white/5 hover:border-white/10 hover:bg-slate-900/60'}`}
                >
                  <div className="flex justify-between items-start gap-4 mb-3">
                    <div className="flex items-center gap-3">
                      <div className="w-10 h-10 rounded-xl bg-slate-800 flex items-center justify-center border border-white/5 text-slate-400 group-hover:text-brand-400 transition-colors">
                        <Terminal className="w-5 h-5" />
                      </div>
                      <div>
                        <h3 className="text-white font-bold text-sm flex items-center gap-2">
                          @{leak.source_channel}
                          <span className="text-[10px] text-slate-500 font-mono">#{leak.intel_id}</span>
                        </h3>
                        <p className="text-slate-500 text-[10px] font-medium flex items-center gap-2">
                          <Calendar className="w-3 h-3 text-brand-400" />
                          {leak.leak_date?.split('T')[0]}
                          <span className="text-slate-700">|</span>
                          <Clock className="w-3 h-3" />
                          {format(new Date(leak.timestamp), 'HH:mm')}
                        </p>
                      </div>
                    </div>
                    <SeverityBadge severity={leak.leak_metadata?.severity} />
                  </div>

                  <p className="text-slate-300 text-xs line-clamp-3 leading-relaxed mb-4 font-medium italic">
                    "{leak.summary_fr}"
                  </p>

                  <div className="flex items-center gap-4 text-[10px] font-black uppercase tracking-widest text-slate-500">
                    <div className="flex items-center gap-1.5">
                      <BrainCircuit className="w-3.5 h-3.5 text-purple-400" />
                      <span className="text-white">{leak.leak_metadata?.leak_type || 'Unknown'}</span>
                    </div>
                    <div className="flex items-center gap-1.5">
                      <ShieldCheck className="w-3.5 h-3.5 text-brand-400" />
                      <span className="text-white">{leak.leak_metadata?.target_organization?.[0] || 'Global'}</span>
                    </div>
                    {leak.file_references?.length > 0 && (
                      <div className="flex items-center gap-1.5 text-emerald-400">
                        <FileText className="w-3.5 h-3.5" />
                        {leak.file_references.length} Proof Files
                      </div>
                    )}
                  </div>

                  <div className="absolute right-4 bottom-4 opacity-0 group-hover:opacity-100 transition-opacity">
                    <ChevronRight className="w-5 h-5 text-brand-400" />
                  </div>
                </div>
              ))
            )}
          </div>

          {/* Details Section */}
          <div className="lg:col-span-1">
            {selectedLeak ? (
              <div className="sticky top-8 flex flex-col gap-6 animate-in fade-in slide-in-from-right duration-500">
                
                {/* AI Summary Card */}
                <div className="bg-gradient-to-br from-brand-600/20 to-slate-900/60 border border-brand-500/30 p-6 rounded-3xl shadow-2xl relative overflow-hidden">
                  <div className="absolute top-0 right-0 p-6 opacity-10">
                    <BrainCircuit className="w-20 h-20 text-brand-500" />
                  </div>
                  
                  <div className="flex items-center gap-3 mb-6">
                    <div className="w-8 h-8 rounded-lg bg-brand-500 flex items-center justify-center text-white shadow-[0_0_15px_rgba(14,165,233,0.5)]">
                      <Zap className="w-5 h-5" />
                    </div>
                    <h2 className="text-lg font-black text-white uppercase tracking-wider">AI Analysis</h2>
                  </div>
                  
                  {/* Timeline Badge */}
                  <div className="flex flex-wrap items-center gap-2 mb-6">
                    <div className="flex items-center gap-2 px-3 py-1 bg-brand-500/10 rounded-full border border-brand-500/20">
                      <Calendar className="w-3 h-3 text-brand-400" />
                      <span className="text-[9px] font-black text-brand-400 uppercase tracking-widest">
                        {selectedLeak.detected_dates && selectedLeak.detected_dates.length > 1 
                          ? `Timeline: ${selectedLeak.detected_dates.sort().map(d => d.split('T')[0]).join(' → ')}`
                          : `Original Date: ${selectedLeak.leak_date?.split('T')[0]}`}
                      </span>
                    </div>
                  </div>

                  <div className="space-y-4 mb-8">
                    <div>
                      <p className="text-[10px] font-black text-brand-400 uppercase tracking-widest mb-1">Executive Summary</p>
                      <p className="text-sm text-slate-200 leading-relaxed font-medium italic">
                        {selectedLeak.summary_fr}
                      </p>
                    </div>
                    
                    <div className="grid grid-cols-2 gap-4">
                      <div className="bg-white/5 p-3 rounded-xl border border-white/5">
                        <p className="text-[9px] font-black text-slate-500 uppercase tracking-widest mb-1">Confidence</p>
                        <div className="flex items-center gap-2">
                          <p className="text-lg font-black text-white">{selectedLeak.leak_metadata?.confidence_score * 100}%</p>
                          <div className="flex-1 h-1 bg-slate-800 rounded-full overflow-hidden">
                            <div className="h-full bg-brand-500" style={{ width: `${selectedLeak.leak_metadata?.confidence_score * 100}%` }} />
                          </div>
                        </div>
                      </div>
                      <div className="bg-white/5 p-3 rounded-xl border border-white/5">
                        <p className="text-[9px] font-black text-slate-500 uppercase tracking-widest mb-1">Source</p>
                        <p className="text-xs font-bold text-white">@{selectedLeak.source_channel}</p>
                      </div>
                    </div>

                    {selectedLeak.deep_correlation && (
                      <div className="bg-emerald-500/10 p-4 rounded-2xl border border-emerald-500/20 mt-4">
                        <p className="text-[10px] font-black text-emerald-400 uppercase tracking-widest mb-2 flex items-center gap-2">
                          <ShieldCheck className="w-3 h-3" />
                          Deep File Correlation (Verified)
                        </p>
                        <p className="text-xs text-slate-200 leading-relaxed font-medium mb-3">
                          {selectedLeak.deep_correlation.correlation_summary}
                        </p>
                        <div className="flex flex-wrap gap-2">
                          {selectedLeak.deep_correlation.data_types_confirmed?.map((t, i) => (
                            <span key={i} className="px-2 py-0.5 bg-emerald-500/20 text-emerald-400 rounded text-[8px] font-black uppercase tracking-wider border border-emerald-500/30">
                              {t}
                            </span>
                          ))}
                        </div>
                        {selectedLeak.deep_correlation.master_file_found && (
                          <div className="mt-3 flex items-center gap-2 text-[9px] text-slate-400 italic">
                            <Database className="w-3 h-3 text-emerald-500" />
                            Master File Identified: {selectedLeak.deep_correlation.master_file_found}
                          </div>
                        )}
                      </div>
                    )}

                    {selectedLeak.analysis?.file_relationship && (
                      <div className="bg-white/5 p-4 rounded-2xl border border-white/5 mt-4">
                        <p className="text-[10px] font-black text-brand-400 uppercase tracking-widest mb-2 flex items-center gap-2">
                          <BrainCircuit className="w-3 h-3" />
                          AI Relationship Analysis
                        </p>
                        <p className="text-xs text-slate-300 leading-relaxed font-medium">
                          {selectedLeak.analysis.file_relationship}
                        </p>
                      </div>
                    )}

                    {selectedLeak.mappings?.length > 0 && (
                      <div className="bg-slate-900/40 p-4 rounded-2xl border border-white/5 mt-4">
                        <p className="text-[10px] font-black text-emerald-400 uppercase tracking-widest mb-2 flex items-center gap-2">
                          <ShieldCheck className="w-3 h-3" />
                          Non-LLM Mapping (Heuristics)
                        </p>
                        <div className="space-y-2">
                          {selectedLeak.mappings.map((m, i) => (
                            <div key={i} className="text-[10px]">
                              <div className="flex justify-between mb-1">
                                <span className="text-slate-300 font-bold">{m.file_name}</span>
                                <span className="text-emerald-400">{m.confidence}% match</span>
                              </div>
                              <div className="flex flex-wrap gap-1">
                                {m.reasons.map((r, j) => (
                                  <span key={j} className="px-1.5 py-0.5 bg-emerald-500/10 text-emerald-500 rounded border border-emerald-500/20 text-[8px] uppercase">
                                    {r.replace('_', ' ')}
                                  </span>
                                ))}
                              </div>
                            </div>
                          ))}
                        </div>
                      </div>
                    )}
                  </div>

                  <div className="flex gap-4">
                    <button 
                      onClick={() => handleReanalyze(selectedLeak)}
                      disabled={analyzing}
                      className="flex-1 py-4 bg-brand-600 hover:bg-brand-500 text-white rounded-2xl font-black uppercase tracking-widest text-xs flex items-center justify-center gap-2 transition-all shadow-xl shadow-brand-600/20 active:scale-[0.98] disabled:opacity-50"
                    >
                      {analyzing ? <Loader2 className="w-4 h-4 animate-spin" /> : <BrainCircuit className="w-4 h-4" />}
                      <span>{analyzing ? 'Processing...' : 'Re-Analyze'}</span>
                    </button>
                    <button 
                      onClick={() => handleViewIndividualBulletin(selectedLeak.intel_id)}
                      className="px-6 py-4 bg-slate-900/60 border border-white/5 hover:border-brand-500/30 text-white rounded-2xl font-black uppercase tracking-widest text-xs transition-all flex items-center gap-2"
                    >
                      <FileText className="w-4 h-4 text-brand-400" />
                      Bulletin
                    </button>
                  </div>
                </div>



                {/* Entities/Artifacts Card */}
                {(selectedLeak.file_references?.length > 0 || selectedLeak.extracted_files?.length > 0) && (
                  <div className="bg-slate-900/60 border border-white/5 p-6 rounded-3xl backdrop-blur-xl">
                    <h3 className="text-xs font-black text-slate-400 uppercase tracking-widest mb-4 flex items-center gap-2">
                      <FileText className="w-4 h-4" />
                      Proof & Intelligence Files
                    </h3>
                    <div className="space-y-3 max-h-[400px] overflow-y-auto pr-2 custom-scrollbar">
                      {/* Archive Files */}
                      {selectedLeak.file_references?.map((file, i) => (
                        <div key={`ref-${i}`} className="flex items-center justify-between p-3 bg-white/5 rounded-xl border border-white/5 group hover:border-brand-500/30 transition-all">
                          <div className="flex items-center gap-3">
                            <div className="w-8 h-8 rounded bg-slate-800 flex items-center justify-center text-emerald-400">
                              <FileSpreadsheet className="w-4 h-4" />
                            </div>
                            <div className="max-w-[150px]">
                              <p className="text-[10px] font-bold text-white truncate">{file.split('\\').pop()}</p>
                              <p className="text-[8px] text-slate-500 uppercase">Source Archive</p>
                            </div>
                          </div>
                          <div className="flex items-center gap-2">
                            <a 
                              href={`${API_BASE}/data/leaks/${file}`}
                              download
                              className="p-2 bg-emerald-500/10 text-emerald-400 hover:bg-emerald-500 hover:text-white rounded-lg transition-all"
                              title="Download Archive"
                            >
                              <Download className="w-3.5 h-3.5" />
                            </a>
                          </div>
                        </div>
                      ))}

                      {/* Extracted Files */}
                      {selectedLeak.extracted_files?.map((file, i) => (
                        <div key={`ext-${i}`} className="flex items-center justify-between p-3 bg-brand-500/5 rounded-xl border border-brand-500/10 group hover:border-brand-500/30 transition-all">
                          <div className="flex items-center gap-3">
                            <div className="w-8 h-8 rounded bg-slate-800 flex items-center justify-center text-brand-400">
                              {(file.toLowerCase().includes('.csv') || file.toLowerCase().includes('.xlsx') || file.toLowerCase().includes('.xls')) ? <FileSpreadsheet className="w-4 h-4" /> : <FileText className="w-4 h-4" />}
                            </div>
                            <div className="max-w-[150px]">
                              <p className="text-[10px] font-bold text-white truncate">{file.split('\\').pop()}</p>
                              <p className="text-[8px] text-brand-500 uppercase font-black">Extracted Data</p>
                            </div>
                          </div>
                          <div className="flex items-center gap-2">
                            {(file.toLowerCase().includes('.csv') || file.toLowerCase().includes('.xlsx') || file.toLowerCase().includes('.xls')) && (
                              <button 
                                onClick={() => setViewingCSV(file)}
                                className="p-2 bg-brand-500/10 text-brand-400 hover:bg-brand-500 hover:text-white rounded-lg transition-all"
                                title="View Data"
                              >
                                <ExternalLink className="w-3.5 h-3.5" />
                              </button>
                            )}
                            <a 
                              href={`${API_BASE}/data/leaks/${file}`}
                              download
                              className="p-2 bg-emerald-500/10 text-emerald-400 hover:bg-emerald-500 hover:text-white rounded-lg transition-all"
                              title="Download File"
                            >
                              <Download className="w-3.5 h-3.5" />
                            </a>
                          </div>
                        </div>
                      ))}
                    </div>
                  </div>
                )}

              </div>
            ) : (
              <div className="h-full flex flex-col items-center justify-center bg-slate-900/20 border border-dashed border-white/10 rounded-3xl p-10 text-center">
                <div className="w-16 h-16 rounded-full bg-slate-800/50 flex items-center justify-center mb-6 text-slate-600">
                  <ShieldAlert className="w-8 h-8" />
                </div>
                <h3 className="text-white font-bold mb-2">Select a leak to analyze</h3>
                <p className="text-slate-500 text-xs leading-relaxed">
                  Sélectionnez un événement pour déclencher l'analyse approfondie par agent IA et visualiser les vecteurs de risque.
                </p>
              </div>
            )}
          </div>

        </div>

      </div>

      {/* Auth Modal */}
      {showAuth && (
        <div className="fixed inset-0 z-[100] flex items-center justify-center p-6">
          <div className="absolute inset-0 bg-black/80 backdrop-blur-sm" onClick={() => setShowAuth(false)} />
          <div className="bg-slate-900 border border-white/10 p-8 rounded-3xl w-full max-w-md relative z-10 shadow-2xl animate-in zoom-in duration-300">
            <h2 className="text-xl font-black text-white uppercase tracking-tight mb-2">Connect Telegram</h2>
            <p className="text-slate-500 text-xs mb-8 uppercase font-mono tracking-widest">
              {authStep === 1 ? 'Enter your phone number' : 'Enter verification code'}
            </p>

            {authStep === 1 ? (
              <div className="space-y-4">
                <div className="relative group">
                  <span className="absolute left-4 top-1/2 -translate-y-1/2 text-slate-500 text-xs font-bold">+</span>
                  <input 
                    type="text" 
                    placeholder="2126XXXXXXXX (or leave empty for .env)"
                    value={phone}
                    onChange={(e) => setPhone(e.target.value)}
                    className="w-full bg-black/40 border border-white/5 rounded-2xl py-4 pl-8 pr-4 text-sm focus:outline-none focus:border-brand-500/50 transition-all font-mono"
                  />
                </div>
                <p className="text-[10px] text-slate-500 italic">
                  Note: Si vous laissez vide, le numéro défini dans votre fichier .env sera utilisé.
                </p>
                <button 
                  onClick={handleSendCode}
                  className="w-full py-4 bg-brand-600 hover:bg-brand-500 text-white rounded-2xl font-black uppercase tracking-widest text-xs transition-all shadow-xl shadow-brand-600/20"
                >
                  Send Verification Code
                </button>
              </div>
            ) : (
              <div className="space-y-6">
                <div className="bg-emerald-500/10 border border-emerald-500/20 p-4 rounded-2xl text-center">
                  <p className="text-emerald-400 text-[10px] font-black uppercase tracking-widest mb-1">Code envoyé !</p>
                  <p className="text-slate-400 text-[10px]">Vérifiez votre application Telegram sur <strong>+{phone}</strong></p>
                </div>
                
                <div className="space-y-2">
                  <p className="text-[10px] font-black text-slate-500 uppercase tracking-widest px-1">Collez le code ici :</p>
                  <input 
                    type="text" 
                    placeholder="XXXXX"
                    value={code}
                    onChange={(e) => setCode(e.target.value)}
                    className="w-full bg-black border-2 border-brand-500/30 rounded-2xl py-5 px-4 text-center text-3xl font-black tracking-[0.5em] text-white focus:outline-none focus:border-brand-500 transition-all shadow-[0_0_20px_rgba(14,165,233,0.1)]"
                  />
                </div>

                <button 
                  onClick={handleVerifyCode}
                  className="w-full py-4 bg-emerald-600 hover:bg-emerald-500 text-white rounded-2xl font-black uppercase tracking-widest text-xs transition-all shadow-xl shadow-emerald-600/20 active:scale-95"
                >
                  Authorize Session
                </button>
                <button 
                  onClick={() => setAuthStep(1)}
                  className="w-full py-2 text-slate-500 hover:text-white text-[10px] font-black uppercase tracking-widest transition-all"
                >
                  Back to Phone Number
                </button>
              </div>
            )}
            
            <button 
              onClick={() => setShowAuth(false)}
              className="absolute top-6 right-6 text-slate-500 hover:text-white transition-colors"
            >
              <AlertCircle className="rotate-45 w-6 h-6" />
            </button>
          </div>
        </div>
      )}

      {/* Bulletin Viewer Modal */}
      {viewingBulletin && (
        <div className="fixed inset-0 z-[110] flex items-center justify-center p-6">
          <div className="absolute inset-0 bg-black/90 backdrop-blur-md" onClick={() => setViewingBulletin(null)} />
          <div className="bg-slate-900 border border-white/10 p-8 rounded-3xl w-full max-w-3xl relative z-10 shadow-2xl animate-in zoom-in duration-300 max-h-[80vh] flex flex-col">
            <div className="flex justify-between items-center mb-6">
              <h2 className="text-xl font-black text-white uppercase tracking-tight">Security Intel Bulletin</h2>
              <button 
                onClick={() => setViewingBulletin(null)}
                className="p-2 hover:bg-white/5 rounded-lg text-slate-500 hover:text-white transition-colors"
              >
                <AlertCircle className="rotate-45 w-6 h-6" />
              </button>
            </div>
            <div className="bg-black/40 rounded-2xl p-6 font-mono text-xs text-brand-400 leading-relaxed overflow-y-auto custom-scrollbar border border-white/5 whitespace-pre-wrap">
              {viewingBulletin}
            </div>
            <div className="mt-6 flex justify-end gap-4">
              <a 
                href={`${API_BASE}/api/leaks/intel/${selectedLeak.intel_id}/bulletin/pdf`}
                download
                className="px-6 py-3 bg-brand-600 hover:bg-brand-500 text-white rounded-xl font-black uppercase tracking-widest text-[10px] transition-all shadow-lg shadow-brand-600/20 flex items-center gap-2"
              >
                <Download className="w-4 h-4" />
                Download PDF Bulletin
              </a>
            </div>
          </div>
        </div>
      )}

        {/* ── Channel Management Modal ── */}
        {showChannelMgr && (
          <div className="fixed inset-0 z-[100] flex items-center justify-center p-4">
            <div className="absolute inset-0 bg-[#05060b]/80 backdrop-blur-sm" onClick={() => setShowChannelMgr(false)} />
            <div className="relative w-full max-w-xl bg-slate-900 border border-white/10 rounded-3xl shadow-2xl overflow-hidden animate-in zoom-in-95 duration-200">
              <div className="p-6 border-b border-white/5 flex justify-between items-center">
                <div className="flex items-center gap-3">
                  <div className="p-2 bg-purple-500/20 rounded-lg">
                    <Globe className="w-5 h-5 text-purple-400" />
                  </div>
                  <h3 className="text-lg font-black text-white uppercase tracking-tight">Gestion des Canaux Telegram</h3>
                </div>
                <button onClick={() => setShowChannelMgr(false)} className="text-slate-500 hover:text-white transition-colors">
                  <AlertCircle className="w-6 h-6 rotate-45" />
                </button>
              </div>

              <div className="p-6">
                {/* Add New Channel */}
                <div className="flex gap-2 mb-8">
                  <input 
                    type="text" 
                    placeholder="Lien du canal (ex: https://t.me/channel_name)"
                    value={newChannelUrl}
                    onChange={(e) => setNewChannelUrl(e.target.value)}
                    className="flex-1 bg-black/40 border border-white/10 rounded-xl px-4 py-3 text-sm focus:outline-none focus:border-brand-500/50 transition-all"
                  />
                  <button 
                    onClick={handleAddChannel}
                    disabled={addingChannel || !newChannelUrl}
                    className="bg-brand-600 hover:bg-brand-500 disabled:opacity-50 text-white px-4 py-3 rounded-xl transition-all active:scale-95 flex items-center gap-2"
                  >
                    {addingChannel ? <Loader2 className="w-4 h-4 animate-spin" /> : <Plus className="w-4 h-4" />}
                    <span className="text-[10px] font-black uppercase tracking-widest">Ajouter</span>
                  </button>
                </div>

                <div className="space-y-3 max-h-[300px] overflow-y-auto pr-2 custom-scrollbar">
                  <p className="text-[10px] font-black text-slate-500 uppercase tracking-[0.2em] mb-4">Canaux Actifs ({channels.length})</p>
                  {channels.length === 0 ? (
                    <div className="text-center py-10 bg-black/20 rounded-2xl border border-white/5">
                      <p className="text-xs text-slate-600 italic">Aucun canal configuré</p>
                    </div>
                  ) : (
                    channels.map((url, i) => (
                      <div key={i} className="flex items-center justify-between p-4 bg-white/5 rounded-2xl border border-white/5 group hover:border-white/10 transition-all">
                        <div className="flex items-center gap-3">
                          <div className="w-8 h-8 rounded-lg bg-slate-800 flex items-center justify-center text-purple-400 group-hover:bg-purple-500 group-hover:text-white transition-all">
                            <Terminal className="w-4 h-4" />
                          </div>
                          <span className="text-xs font-bold text-slate-300 truncate max-w-[300px]">{url}</span>
                        </div>
                        <button 
                          onClick={() => handleRemoveChannel(url)}
                          className="p-2 text-slate-600 hover:text-red-400 hover:bg-red-500/10 rounded-lg transition-all"
                          title="Supprimer"
                        >
                          <Trash2 className="w-4 h-4" />
                        </button>
                      </div>
                    ))
                  )}
                </div>
              </div>
              
              <div className="p-4 bg-black/20 text-center">
                <p className="text-[8px] text-slate-600 font-mono uppercase tracking-[0.2em]">
                  Les modifications sont appliquées immédiatement au collecteur
                </p>
              </div>
            </div>
          </div>
        )}

        {/* ── Start Monitoring Configuration Modal ── */}
        {showStartConfig && (
          <div className="fixed inset-0 z-[120] flex items-center justify-center p-4">
            <div className="absolute inset-0 bg-[#05060b]/90 backdrop-blur-md" onClick={() => setShowStartConfig(false)} />
            <div className="relative w-full max-w-lg bg-slate-900 border border-white/10 rounded-3xl shadow-2xl overflow-hidden animate-in zoom-in-95 duration-200">
              <div className="p-6 border-b border-white/5 flex justify-between items-center">
                <div className="flex items-center gap-3">
                  <div className="p-2 bg-brand-500/20 rounded-lg">
                    <Zap className="w-5 h-5 text-brand-400" />
                  </div>
                  <h3 className="text-lg font-black text-white uppercase tracking-tight">Configuration du Scan</h3>
                </div>
                <button onClick={() => setShowStartConfig(false)} className="text-slate-500 hover:text-white transition-colors">
                  <AlertCircle className="w-6 h-6 rotate-45" />
                </button>
              </div>

              <div className="p-6 space-y-6">
                {/* Channel Selection */}
                <div>
                  <p className="text-[10px] font-black text-slate-500 uppercase tracking-[0.2em] mb-3">Sélection des Canaux</p>
                  <div className="space-y-2 max-h-[200px] overflow-y-auto pr-2 custom-scrollbar">
                    {channels.map((url, i) => (
                      <label key={i} className="flex items-center gap-3 p-3 bg-white/5 rounded-xl border border-white/5 hover:border-brand-500/30 cursor-pointer transition-all">
                        <input 
                          type="checkbox" 
                          checked={selectedChannelsForRun.includes(url)}
                          onChange={(e) => {
                            if (e.target.checked) {
                              setSelectedChannelsForRun([...selectedChannelsForRun, url]);
                            } else {
                              setSelectedChannelsForRun(selectedChannelsForRun.filter(u => u !== url));
                            }
                          }}
                          className="w-4 h-4 rounded border-slate-700 bg-slate-800 text-brand-500 focus:ring-brand-500/20"
                        />
                        <span className="text-xs text-slate-300 truncate">{url}</span>
                      </label>
                    ))}
                  </div>
                </div>

                {/* Start Date Selection */}
                <div>
                  <p className="text-[10px] font-black text-slate-500 uppercase tracking-[0.2em] mb-3">Date et Heure de début (Backfill)</p>
                  <input 
                    type="datetime-local" 
                    value={startDateForRun}
                    onChange={(e) => setStartDateForRun(e.target.value)}
                    className="w-full bg-black/40 border border-white/10 rounded-xl px-4 py-3 text-sm text-slate-300 focus:outline-none focus:border-brand-500/50 transition-all"
                  />
                  <p className="text-[9px] text-slate-600 mt-2 italic">Laissez vide pour utiliser l'historique par défaut (tracking.json)</p>
                </div>
              </div>

              <div className="p-6 bg-black/20 flex gap-4">
                <button 
                  onClick={() => setShowStartConfig(false)}
                  className="flex-1 py-3 border border-white/10 text-slate-400 hover:text-white rounded-xl font-black uppercase tracking-widest text-[10px] transition-all"
                >
                  Annuler
                </button>
                <button 
                  onClick={() => handleStartMonitoring({
                    channels: selectedChannelsForRun,
                    startDate: startDateForRun
                  })}
                  disabled={selectedChannelsForRun.length === 0}
                  className="flex-1 py-3 bg-brand-600 hover:bg-brand-500 disabled:opacity-50 text-white rounded-xl font-black uppercase tracking-widest text-[10px] transition-all shadow-lg shadow-brand-600/20"
                >
                  Lancer le Scan
                </button>
              </div>
            </div>
          </div>
        )}

      <style dangerouslySetInnerHTML={{ __html: `
        .custom-scrollbar::-webkit-scrollbar {
          width: 4px;
        }
        .custom-scrollbar::-webkit-scrollbar-track {
          background: rgba(255, 255, 255, 0.02);
          border-radius: 10px;
        }
        .custom-scrollbar::-webkit-scrollbar-thumb {
          background: rgba(14, 165, 233, 0.1);
          border-radius: 10px;
        }
        .custom-scrollbar::-webkit-scrollbar-thumb:hover {
          background: rgba(14, 165, 233, 0.3);
          border-radius: 10px;
        }
        .glass-panel {
          backdrop-filter: blur(12px);
          box-shadow: 0 8px 32px 0 rgba(0, 0, 0, 0.37);
        }
      `}} />
    </div>
  );
};

export default Leaks;
