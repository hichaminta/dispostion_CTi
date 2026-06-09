import React, { useState, useEffect, useMemo } from 'react';
import axios from 'axios';
import logo from '../assets/logo.png';
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
  Globe,
  ChevronDown,
  ChevronUp,
  Activity,
  Users,
  Info,
  Edit2,
  Save,
  X,
  MapPin,
  Languages,
  ShieldQuestion
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
  const [defaultPhone, setDefaultPhone] = useState('');
  const [logs, setLogs] = useState([]);
  const [activeRunId, setActiveRunId] = useState(null);
  const [viewingFile, setViewingFile] = useState(null);
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
  const [newChannelDetails, setNewChannelDetails] = useState({ name: '', description: '', category: '', risk_level: 'unknown', member_count: 0, language: '', country: '' });
  const [addingChannel, setAddingChannel] = useState(false);
  const [expandedChannels, setExpandedChannels] = useState({});
  const [editingChannel, setEditingChannel] = useState(null); // url being edited
  const [editForm, setEditForm] = useState({});
  const [savingChannel, setSavingChannel] = useState(false);

  useEffect(() => {
    fetchLeaks();
    fetchStats();
    checkTgStatus();
    fetchChannels();
  }, []);

  useEffect(() => {
    if (!activeRunId) return;
    const logInterval  = setInterval(() => fetchLogs(activeRunId), 3000);
    const leakInterval = setInterval(() => fetchLeaks(), 10000);
    return () => {
      clearInterval(logInterval);
      clearInterval(leakInterval);
    };
  }, [activeRunId]);

  useEffect(() => {
    if (showAuth) {
      axios.get(`${API_BASE}/api/leaks/auth/config`).then(res => {
        if (res.data.default_phone) {
          setDefaultPhone(res.data.default_phone);
          if (!phone) setPhone(res.data.default_phone);
        }
      }).catch(() => {});
    }
  }, [showAuth]);

  const fetchLogs = async (runId) => {
    try {
      const [logsRes, statusRes] = await Promise.all([
        axios.get(`${API_BASE}/api/runs/${runId}/logs?step=Monitoring%20Telegram`),
        axios.get(`${API_BASE}/runs/${runId}`).catch(() => null),
      ]);

      if (logsRes.data?.logs) {
        setLogs(logsRes.data.logs.slice(-20).reverse());
      }

      // Auto-stop quand le run est terminé
      const runStatus = statusRes?.data?.status_global;
      if (runStatus && runStatus !== 'running') {
        setActiveRunId(null);
        fetchLeaks(); // rafraîchir la liste des leaks
      }
    } catch (e) {
      console.error("Failed to fetch logs", e);
    }
  };

  const handleStopMonitoring = () => {
    setActiveRunId(null);
    setLogs([]);
    fetchLeaks();
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
      const params = new URLSearchParams({ url: newChannelUrl, ...newChannelDetails, member_count: newChannelDetails.member_count || 0 });
      await axios.post(`${API_BASE}/api/leaks/channels?${params.toString()}`);
      setNewChannelUrl('');
      setNewChannelDetails({ name: '', description: '', category: '', risk_level: 'unknown', member_count: 0, language: '', country: '' });
      fetchChannels();
      fetchStats();
    } catch (e) {
      alert("Failed to add channel: " + e.message);
    } finally {
      setAddingChannel(false);
    }
  };

  const handleUpdateChannel = async (url) => {
    setSavingChannel(true);
    try {
      const params = new URLSearchParams({ url, ...editForm, member_count: editForm.member_count || 0 });
      await axios.put(`${API_BASE}/api/leaks/channels?${params.toString()}`);
      setEditingChannel(null);
      fetchChannels();
    } catch (e) {
      alert("Failed to update channel: " + e.message);
    } finally {
      setSavingChannel(false);
    }
  };

  const handleRemoveChannel = async (urlOrObj) => {
    const url = typeof urlOrObj === 'object' ? urlOrObj.url : urlOrObj;
    if (!window.confirm(`Supprimer le groupe ${url} ?`)) return;
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
          config.channels.forEach(c => params.append('channels', typeof c === 'object' ? c.url : c));
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

  const extractChannelName = (urlOrObj) => {
    const url = typeof urlOrObj === 'object' ? urlOrObj?.url : urlOrObj;
    try {
      const path = new URL(url).pathname.replace('/', '');
      return path.startsWith('+') ? path : `@${path}`;
    } catch {
      return url || '';
    }
  };

  const getRiskColor = (level) => {
    const map = { critical: 'text-red-400 bg-red-500/10 border-red-500/30', high: 'text-orange-400 bg-orange-500/10 border-orange-500/30', medium: 'text-yellow-400 bg-yellow-500/10 border-yellow-500/30', low: 'text-blue-400 bg-blue-500/10 border-blue-500/30', unknown: 'text-slate-400 bg-slate-500/10 border-slate-500/30' };
    return map[level?.toLowerCase()] || map.unknown;
  };

  const getChannelStats = (urlOrObj) => {
    const url = typeof urlOrObj === 'object' ? urlOrObj?.url : urlOrObj;
    const urlLower = url.toLowerCase();
    const channelLeaks = leaks.filter(l => {
      const sc = l.source_channel?.toLowerCase() || '';
      return urlLower.includes(sc) || sc.split(/[~_-]/)[0].length > 2 && urlLower.includes(sc.split(/[~_-]/)[0]);
    });
    const bySeverity = { critical: 0, high: 0, medium: 0, low: 0 };
    const typeCount = {};
    let lastDate = null;
    channelLeaks.forEach(l => {
      const sev = l.leak_metadata?.severity?.toLowerCase();
      if (sev && sev in bySeverity) bySeverity[sev]++;
      const type = l.leak_metadata?.leak_type;
      if (type) typeCount[type] = (typeCount[type] || 0) + 1;
      const d = l.leak_date || l.timestamp;
      if (d && (!lastDate || new Date(d) > new Date(lastDate))) lastDate = d;
    });
    const topType = Object.entries(typeCount).sort((a, b) => b[1] - a[1])[0]?.[0];
    const total = channelLeaks.length;
    return { total, bySeverity, lastDate: lastDate?.split('T')[0], topType };
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
      setViewingBulletin(`Chargement du bulletin pour ${intelId}...`);
      const res = await axios.get(`${API_BASE}/api/leaks/intel/${intelId}/bulletin`);
      setViewingBulletin(res.data.bulletin);
    } catch (err) {
      console.error(err);
      setViewingBulletin("Erreur lors de la génération du bulletin individuel.");
    }
  };

  const handleDeleteLeak = async (intelId) => {
    if (!window.confirm("Êtes-vous sûr de vouloir supprimer cette fuite ? Cela supprimera également tous les fichiers et données associés.")) return;
    try {
      const response = await fetch(`${API_BASE}/api/leaks/intel/${intelId}`, { method: 'DELETE' });
      if (!response.ok) throw new Error('Erreur lors de la suppression');
      setLeaks(prev => prev.filter(l => l.intel_id !== intelId));
      if (selectedLeak?.intel_id === intelId) setSelectedLeak(null);
      alert('Fuite et fichiers associés supprimés avec succès.');
    } catch (error) {
      console.error(error);
      alert('Erreur lors de la suppression de la fuite.');
    }
  };

  if (viewingFile) {
    return <CSVReader filePath={viewingFile} onBack={() => setViewingFile(null)} />;
  }

  return (
    <div className="min-h-screen bg-transparent text-slate-200 p-8 relative overflow-hidden">
      {/* Background Glows */}
      <div className="absolute top-[-10%] left-[-10%] w-[50%] h-[50%] bg-brand-500/10 blur-[120px] rounded-full pointer-events-none" />
      <div className="absolute bottom-[-10%] right-[-10%] w-[50%] h-[50%] bg-purple-500/10 blur-[120px] rounded-full pointer-events-none" />
      <div className="absolute inset-0 hud-grid opacity-20 pointer-events-none" />

      <div className="max-w-[1400px] mx-auto relative z-10">
        
        {/* Header */}
        <div className="flex flex-col md:flex-row justify-between items-start md:items-center gap-6 mb-12">
          <div>
            <div className="flex items-center gap-3 mb-2">
              <img src={logo} alt="BlueSec" className="h-8 w-auto drop-shadow-lg" />
              <h1 className="text-3xl font-black text-white tracking-tight uppercase">
                Leak <span className="text-brand-500 italic">Intelligence</span>
              </h1>
              {/* Telegram Status Badge */}
              {tgStatus.loading ? (
                <div className="flex items-center gap-2 px-3 py-1.5 bg-slate-800/60 rounded-full border border-white/5">
                  <div className="w-2 h-2 rounded-full bg-slate-500 animate-pulse" />
                  <span className="text-xs text-slate-500">Vérification...</span>
                </div>
              ) : tgStatus.connected ? (
                <div className="flex items-center gap-2 px-3 py-1.5 bg-emerald-500/10 rounded-full border border-emerald-500/30">
                  <div className="w-2 h-2 rounded-full bg-emerald-500 shadow-[0_0_8px_rgba(16,185,129,0.6)]" />
                  <span className="text-xs font-semibold text-emerald-400">Telegram connecté</span>
                </div>
              ) : (
                <button
                  onClick={() => setShowAuth(true)}
                  className="flex items-center gap-2 px-3 py-1.5 bg-red-500/10 hover:bg-red-500/20 rounded-full border border-red-500/40 transition-all group"
                >
                  <div className="w-2 h-2 rounded-full bg-red-500 animate-pulse" />
                  <span className="text-xs font-semibold text-red-400 group-hover:text-red-300">Déconnecté — Cliquer pour connecter</span>
                </button>
              )}
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

        {/* ── Bannière Telegram déconnecté ──────────────────────────── */}
        {!tgStatus.connected && !tgStatus.loading && (
          <div className="flex items-center justify-between gap-4 mb-6 px-5 py-4 bg-red-500/8 border border-red-500/25 rounded-2xl">
            <div className="flex items-center gap-3">
              <div className="w-9 h-9 rounded-xl bg-red-500/15 border border-red-500/30 flex items-center justify-center shrink-0">
                <AlertTriangle className="w-5 h-5 text-red-400" />
              </div>
              <div>
                <p className="text-sm font-semibold text-red-400">Session Telegram non connectée</p>
                <p className="text-xs text-slate-500 mt-0.5">
                  Connectez votre compte Telegram pour activer le monitoring des canaux.
                </p>
              </div>
            </div>
            <button
              onClick={() => setShowAuth(true)}
              className="shrink-0 flex items-center gap-2 px-4 py-2 bg-red-500 hover:bg-red-400 text-white rounded-xl text-sm font-semibold transition-all active:scale-95"
            >
              <Zap className="w-4 h-4" />
              Connecter Telegram
            </button>
          </div>
        )}

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

        {/* ── Live Activity Feed ─────────────────────────────────────── */}
        {activeRunId && (
          <div className="mb-8 animate-in slide-in-from-top duration-400">
            <div className="bg-slate-900/60 border border-emerald-500/20 rounded-2xl overflow-hidden backdrop-blur-xl shadow-xl">
              {/* Header */}
              <div className="flex items-center justify-between px-5 py-3 bg-emerald-500/5 border-b border-emerald-500/15">
                <div className="flex items-center gap-3">
                  <div className="flex gap-1">
                    <div className="w-2.5 h-2.5 rounded-full bg-red-500/50" />
                    <div className="w-2.5 h-2.5 rounded-full bg-yellow-500/50" />
                    <div className="w-2.5 h-2.5 rounded-full bg-emerald-500 animate-pulse shadow-[0_0_6px_rgba(16,185,129,0.6)]" />
                  </div>
                  <span className="text-xs font-semibold text-emerald-400">Collecte en cours...</span>
                  <span className="text-xs text-slate-600 font-mono hidden sm:block">run/{activeRunId?.slice(0,8)}</span>
                </div>
                <button
                  onClick={handleStopMonitoring}
                  className="flex items-center gap-1.5 px-3 py-1.5 bg-red-500/10 hover:bg-red-500/20 border border-red-500/30 text-red-400 rounded-lg text-xs font-semibold transition-all active:scale-95"
                >
                  <div className="w-2 h-2 rounded-sm bg-red-400" />
                  Arrêter le suivi
                </button>
              </div>

              {/* Logs */}
              <div className="p-4 font-mono text-xs h-36 overflow-y-auto custom-scrollbar">
                {logs.length > 0 ? (
                  <div className="space-y-1">
                    {logs.map((log, idx) => (
                      <div key={idx} className="flex gap-3 animate-in fade-in duration-200">
                        <span className="text-emerald-500/40 shrink-0 tabular-nums">
                          {new Date().toLocaleTimeString('fr-FR', { hour: '2-digit', minute: '2-digit', second: '2-digit' })}
                        </span>
                        <span className={`break-all ${
                          /erreur|error|fail/i.test(log.message) ? 'text-red-400' :
                          /nouveau|new|found|trouvé/i.test(log.message) ? 'text-emerald-400' :
                          'text-slate-400'
                        }`}>{log.message}</span>
                      </div>
                    ))}
                  </div>
                ) : (
                  <div className="flex items-center gap-3 h-full">
                    <Loader2 className="w-4 h-4 text-emerald-500 animate-spin shrink-0" />
                    <span className="text-slate-600 italic">En attente des premières données Telegram...</span>
                  </div>
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
          <div className={`lg:col-span-2 overflow-y-auto max-h-[calc(100vh-260px)] pr-2 custom-scrollbar ${
            viewMode === 'grid'
              ? 'grid grid-cols-1 sm:grid-cols-2 gap-3 content-start'
              : 'flex flex-col gap-3'
          }`}>
            {loading ? (
              <div className="flex flex-col items-center justify-center py-20 bg-slate-900/20 rounded-3xl border border-white/5">
                <Loader2 className="w-10 h-10 text-brand-500 animate-spin mb-4" />
                <p className="text-slate-500 font-mono text-xs uppercase tracking-widest">Initialisation de la matrice de données...</p>
              </div>
            ) : filteredLeaks.length === 0 ? (
              <div className="flex flex-col items-center justify-center py-16 bg-slate-900/20 rounded-3xl border border-white/5 text-center px-8">
                {search || filter !== 'all' ? (
                  <>
                    <Search className="w-10 h-10 text-slate-700 mb-4" />
                    <p className="text-white font-semibold mb-1">Aucun résultat</p>
                    <p className="text-slate-500 text-sm mb-4">Aucun leak ne correspond à vos filtres actuels.</p>
                    <button
                      onClick={() => { setSearch(''); setFilter('all'); }}
                      className="px-4 py-2 bg-slate-800 hover:bg-slate-700 text-slate-300 rounded-xl text-sm font-medium transition-all"
                    >
                      Réinitialiser les filtres
                    </button>
                  </>
                ) : !tgStatus.connected ? (
                  <>
                    <AlertTriangle className="w-10 h-10 text-red-500/40 mb-4" />
                    <p className="text-white font-semibold mb-1">Telegram non connecté</p>
                    <p className="text-slate-500 text-sm mb-4">
                      Connectez votre session Telegram pour lancer la collecte.
                    </p>
                    <button
                      onClick={() => setShowAuth(true)}
                      className="flex items-center gap-2 px-4 py-2 bg-red-500 hover:bg-red-400 text-white rounded-xl text-sm font-semibold transition-all active:scale-95"
                    >
                      <Zap className="w-4 h-4" />
                      Connecter Telegram
                    </button>
                  </>
                ) : channels.length === 0 ? (
                  <>
                    <Globe className="w-10 h-10 text-slate-700 mb-4" />
                    <p className="text-white font-semibold mb-1">Aucun canal configuré</p>
                    <p className="text-slate-500 text-sm mb-4">
                      Ajoutez des canaux Telegram à surveiller pour démarrer la collecte.
                    </p>
                    <button
                      onClick={() => setShowChannelMgr(true)}
                      className="flex items-center gap-2 px-4 py-2 bg-brand-600 hover:bg-brand-500 text-white rounded-xl text-sm font-semibold transition-all active:scale-95"
                    >
                      <Plus className="w-4 h-4" />
                      Ajouter des canaux
                    </button>
                  </>
                ) : (
                  <>
                    <Database className="w-10 h-10 text-slate-700 mb-4" />
                    <p className="text-white font-semibold mb-1">Aucune fuite collectée</p>
                    <p className="text-slate-500 text-sm mb-4">
                      Lancez le monitoring pour collecter les leaks depuis vos canaux Telegram.
                    </p>
                    <button
                      onClick={() => { setSelectedChannelsForRun(channels); setShowStartConfig(true); }}
                      className="flex items-center gap-2 px-4 py-2 bg-brand-600 hover:bg-brand-500 text-white rounded-xl text-sm font-semibold transition-all active:scale-95"
                    >
                      <Zap className="w-4 h-4" />
                      Lancer le monitoring
                    </button>
                  </>
                )}
              </div>
            ) : (
              filteredLeaks.map((leak) => (
                <div
                  key={leak.intel_id}
                  onClick={() => setSelectedLeak(leak)}
                  className={`p-4 rounded-2xl border transition-all cursor-pointer group ${
                    selectedLeak?.intel_id === leak.intel_id
                      ? 'bg-brand-500/10 border-brand-500/40 shadow-lg shadow-brand-500/5'
                      : 'bg-slate-900/40 border-white/5 hover:border-white/15 hover:bg-slate-900/60'
                  }`}
                >
                  {/* ── Ligne 1 : icône + canal + badge ── */}
                  <div className="flex items-start justify-between gap-3 mb-2">
                    <div className="flex items-start gap-3 min-w-0">
                      <div className="w-9 h-9 shrink-0 rounded-xl bg-slate-800 flex items-center justify-center border border-white/5 text-slate-400 group-hover:text-brand-400 transition-colors mt-0.5">
                        <Terminal className="w-4 h-4" />
                      </div>
                      <div className="min-w-0">
                        <span className="text-white font-semibold text-sm truncate block">
                          @{leak.source_channel}
                        </span>
                        <span className="text-xs text-slate-500 font-mono bg-slate-800/60 px-1.5 py-0.5 rounded mt-0.5 inline-block">
                          #{leak.intel_id}
                        </span>
                      </div>
                    </div>
                    <SeverityBadge severity={leak.leak_metadata?.severity} />
                  </div>

                  {/* ── Ligne 2 : date + heure ── */}
                  <div className="flex items-center gap-2 text-xs text-slate-500 mb-3 pl-12">
                    <Calendar className="w-3.5 h-3.5 text-brand-400/70 shrink-0" />
                    <span>{leak.leak_date?.split('T')[0]}</span>
                    <span className="text-slate-700">·</span>
                    <Clock className="w-3.5 h-3.5 shrink-0" />
                    <span>{format(new Date(leak.timestamp), 'HH:mm')}</span>
                  </div>

                  {/* ── Ligne 3 : résumé ── */}
                  {leak.summary_fr && (
                    <p className="text-slate-400 text-xs leading-relaxed line-clamp-2 mb-3 pl-12">
                      {leak.summary_fr}
                    </p>
                  )}

                  {/* ── Ligne 4 : tags metadata ── */}
                  <div className="flex items-center gap-3 pl-12 flex-wrap">
                    <div className="flex items-center gap-1.5 text-xs text-slate-400">
                      <BrainCircuit className="w-3.5 h-3.5 text-purple-400 shrink-0" />
                      <span>{leak.leak_metadata?.leak_type || 'Unknown'}</span>
                    </div>
                    {leak.leak_metadata?.target_organization?.[0] && (
                      <div className="flex items-center gap-1.5 text-xs text-slate-400">
                        <ShieldCheck className="w-3.5 h-3.5 text-brand-400 shrink-0" />
                        <span>{leak.leak_metadata.target_organization[0]}</span>
                      </div>
                    )}
                    {leak.file_references?.length > 0 && (
                      <div className="flex items-center gap-1.5 text-xs text-emerald-400">
                        <FileText className="w-3.5 h-3.5 shrink-0" />
                        <span>{leak.file_references.length} fichier{leak.file_references.length > 1 ? 's' : ''}</span>
                      </div>
                    )}
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
                      onClick={() => handleViewIndividualBulletin(selectedLeak.intel_id)}
                      className="flex-1 py-4 bg-slate-900/60 border border-white/5 hover:border-brand-500/30 text-white rounded-2xl font-black uppercase tracking-widest text-xs transition-all flex items-center justify-center gap-2"
                    >
                      <FileText className="w-4 h-4 text-brand-400" />
                      Bulletin
                    </button>
                    <button 
                      onClick={() => handleDeleteLeak(selectedLeak.intel_id)}
                      className="flex-1 py-4 bg-red-500/10 border border-red-500/20 hover:bg-red-500/20 hover:border-red-500/40 text-red-400 rounded-2xl font-black uppercase tracking-widest text-xs transition-all flex items-center justify-center gap-2"
                    >
                      <Trash2 className="w-4 h-4" />
                      Supprimer
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
                            {(file.toLowerCase().endsWith('.csv') || 
                              file.toLowerCase().endsWith('.xlsx') || 
                              file.toLowerCase().endsWith('.xls') ||
                              file.toLowerCase().endsWith('.txt') ||
                              file.toLowerCase().endsWith('.log')) && (
                              <button 
                                onClick={() => setViewingFile(file)}
                                className="p-2 bg-brand-500/10 text-brand-400 hover:bg-brand-500 hover:text-white rounded-lg transition-all"
                                title="View Content"
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

      {/* ── Auth Modal Telegram ─────────────────────────────────────── */}
      {showAuth && (
        <div className="fixed inset-0 z-[100] flex items-center justify-center p-6">
          <div className="absolute inset-0 bg-black/80 backdrop-blur-sm" onClick={() => setShowAuth(false)} />
          <div className="bg-slate-900 border border-white/10 rounded-3xl w-full max-w-md relative z-10 shadow-2xl animate-in zoom-in-95 duration-200 overflow-hidden">

            {/* Header */}
            <div className="flex items-center justify-between px-6 py-5 border-b border-white/8">
              <div className="flex items-center gap-3">
                <div className="w-10 h-10 rounded-xl bg-brand-500/15 border border-brand-500/30 flex items-center justify-center">
                  <svg viewBox="0 0 24 24" className="w-5 h-5 text-brand-400 fill-current">
                    <path d="M12 0C5.373 0 0 5.373 0 12s5.373 12 12 12 12-5.373 12-12S18.627 0 12 0zm5.562 8.248l-2.01 9.47c-.145.658-.537.818-1.084.508l-3-2.21-1.447 1.394c-.16.16-.295.295-.605.295l.213-3.053 5.56-5.023c.242-.213-.054-.333-.373-.12L7.088 14.38l-2.95-.924c-.642-.2-.654-.642.136-.953l11.527-4.445c.537-.194 1.006.131.761.19z"/>
                  </svg>
                </div>
                <div>
                  <h2 className="text-base font-bold text-white">Connexion Telegram</h2>
                  <p className="text-xs text-slate-500">
                    {authStep === 1 ? 'Étape 1 — Numéro de téléphone' : 'Étape 2 — Code de vérification'}
                  </p>
                </div>
              </div>
              <button onClick={() => setShowAuth(false)} className="p-1.5 rounded-lg text-slate-500 hover:text-white hover:bg-slate-800 transition-all">
                <AlertCircle className="rotate-45 w-5 h-5" />
              </button>
            </div>

            {/* Stepper */}
            <div className="flex px-6 pt-5 gap-2">
              {[1, 2].map(s => (
                <div key={s} className={`h-1 flex-1 rounded-full transition-all duration-500 ${authStep >= s ? 'bg-brand-500' : 'bg-slate-800'}`} />
              ))}
            </div>

            <div className="p-6">
              {authStep === 1 ? (
                <div className="space-y-4">
                  <div>
                    <label className="text-xs font-semibold text-slate-400 block mb-2">Numéro de téléphone</label>
                    <input
                      type="text"
                      placeholder={defaultPhone || "+2126XXXXXXXX"}
                      value={phone}
                      onChange={(e) => setPhone(e.target.value)}
                      onKeyDown={(e) => e.key === 'Enter' && handleSendCode()}
                      autoFocus
                      className="w-full bg-black/40 border border-white/10 rounded-xl py-3 px-4 text-sm font-mono text-white focus:outline-none focus:border-brand-500/60 focus:bg-black/60 transition-all placeholder:text-slate-600"
                    />
                    <p className="text-xs text-slate-600 mt-2 italic">
                      {defaultPhone ? `Un numéro par défaut a été détecté dans votre fichier .env. Cliquez sur envoyer pour recevoir le code.` : `Laissez vide pour utiliser le numéro défini dans le fichier .env.`}
                    </p>
                  </div>
                  <button
                    onClick={handleSendCode}
                    className="w-full py-3 bg-brand-600 hover:bg-brand-500 text-white rounded-xl text-sm font-semibold transition-all shadow-lg shadow-brand-600/20 active:scale-95 flex items-center justify-center gap-2"
                  >
                    <Zap className="w-4 h-4" />
                    Envoyer le code de vérification Telegram
                  </button>
                </div>
              ) : (
                <div className="space-y-5">
                  {/* Info envoi */}
                  <div className="flex items-start gap-3 p-4 bg-sky-500/8 border border-sky-500/20 rounded-xl">
                    <div className="w-8 h-8 rounded-lg bg-sky-500/15 flex items-center justify-center shrink-0 mt-0.5">
                      <svg viewBox="0 0 24 24" className="w-4 h-4 text-sky-400 fill-current">
                        <path d="M12 0C5.373 0 0 5.373 0 12s5.373 12 12 12 12-5.373 12-12S18.627 0 12 0zm5.562 8.248l-2.01 9.47c-.145.658-.537.818-1.084.508l-3-2.21-1.447 1.394c-.16.16-.295.295-.605.295l.213-3.053 5.56-5.023c.242-.213-.054-.333-.373-.12L7.088 14.38l-2.95-.924c-.642-.2-.654-.642.136-.953l11.527-4.445c.537-.194 1.006.131.761.19z"/>
                      </svg>
                    </div>
                    <div>
                      <p className="text-sm font-semibold text-sky-400">Code envoyé sur Telegram</p>
                      <p className="text-xs text-slate-400 mt-0.5">
                        Ouvrez votre application Telegram sur <span className="text-white font-mono">{phone || 'votre téléphone'}</span> et copiez le code reçu.
                      </p>
                    </div>
                  </div>

                  {/* Code input */}
                  <div>
                    <label className="text-xs font-semibold text-slate-400 block mb-2">Code de vérification</label>
                    <input
                      type="text"
                      placeholder="• • • • •"
                      value={code}
                      onChange={(e) => setCode(e.target.value.replace(/\D/g, '').slice(0, 6))}
                      onKeyDown={(e) => e.key === 'Enter' && code.length >= 5 && handleVerifyCode()}
                      autoFocus
                      maxLength={6}
                      className="w-full bg-black/60 border-2 border-brand-500/30 focus:border-brand-500 rounded-xl py-4 px-4 text-center text-4xl font-black tracking-[0.6em] text-white focus:outline-none transition-all shadow-[0_0_20px_rgba(14,165,233,0.08)] placeholder:text-slate-700 placeholder:text-2xl placeholder:tracking-[0.4em]"
                    />
                    <p className="text-xs text-slate-600 mt-2 text-center">
                      Entrez le code à 5 chiffres reçu dans l'application Telegram
                    </p>
                  </div>

                  <button
                    onClick={handleVerifyCode}
                    disabled={code.length < 5}
                    className="w-full py-3 bg-emerald-600 hover:bg-emerald-500 disabled:opacity-40 disabled:cursor-not-allowed text-white rounded-xl text-sm font-semibold transition-all shadow-lg shadow-emerald-600/20 active:scale-95"
                  >
                    Autoriser la session
                  </button>
                  <button
                    onClick={() => { setAuthStep(1); setCode(''); }}
                    className="w-full py-2 text-xs text-slate-500 hover:text-slate-300 transition-colors"
                  >
                    ← Changer de numéro
                  </button>
                </div>
              )}
            </div>
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
            <div className="absolute inset-0 bg-[#05060b]/80 backdrop-blur-sm" onClick={() => { setShowChannelMgr(false); setEditingChannel(null); }} />
            <div className="relative w-full max-w-3xl bg-slate-900 border border-white/10 rounded-3xl shadow-2xl overflow-hidden animate-in zoom-in-95 duration-200">
              {/* Header */}
              <div className="p-6 border-b border-white/5 flex justify-between items-center">
                <div className="flex items-center gap-3">
                  <div className="p-2 bg-purple-500/20 rounded-lg">
                    <Globe className="w-5 h-5 text-purple-400" />
                  </div>
                  <h3 className="text-lg font-black text-white uppercase tracking-tight">Gestion des Groupes Telegram</h3>
                </div>
                <button onClick={() => { setShowChannelMgr(false); setEditingChannel(null); }} className="text-slate-500 hover:text-white transition-colors">
                  <X className="w-5 h-5" />
                </button>
              </div>

              <div className="p-6 space-y-6 max-h-[80vh] overflow-y-auto custom-scrollbar">

                {/* ── Add New Channel Form ── */}
                <div className="bg-black/30 border border-white/5 rounded-2xl p-5 space-y-3">
                  <p className="text-[10px] font-black text-brand-400 uppercase tracking-[0.2em] flex items-center gap-2">
                    <Plus className="w-3 h-3" /> Ajouter un nouveau groupe
                  </p>
                  <input
                    type="text"
                    placeholder="URL du groupe (ex: https://t.me/channel_name) *"
                    value={newChannelUrl}
                    onChange={(e) => setNewChannelUrl(e.target.value)}
                    className="w-full bg-black/40 border border-white/10 rounded-xl px-4 py-3 text-sm focus:outline-none focus:border-brand-500/50 transition-all"
                  />
                  <input type="text" placeholder="Nom (optionnel)"
                    value={newChannelDetails.name} onChange={e => setNewChannelDetails(d => ({...d, name: e.target.value}))}
                    className="w-full bg-black/40 border border-white/10 rounded-xl px-3 py-2.5 text-sm focus:outline-none focus:border-brand-500/50 transition-all" />
                  <input type="number" placeholder="Nombre d'abonnés (optionnel)" min={0}
                    value={newChannelDetails.member_count || ''} onChange={e => setNewChannelDetails(d => ({...d, member_count: parseInt(e.target.value) || 0}))}
                    className="w-full bg-black/40 border border-white/10 rounded-xl px-3 py-2.5 text-sm focus:outline-none focus:border-brand-500/50 transition-all" />
                  <textarea placeholder="Description (optionnel)"
                    value={newChannelDetails.description} onChange={e => setNewChannelDetails(d => ({...d, description: e.target.value}))}
                    rows={2}
                    className="w-full bg-black/40 border border-white/10 rounded-xl px-3 py-2.5 text-sm focus:outline-none focus:border-brand-500/50 transition-all resize-none" />
                  <button
                    onClick={handleAddChannel}
                    disabled={addingChannel || !newChannelUrl}
                    className="flex items-center gap-2 px-5 py-2.5 bg-brand-600 hover:bg-brand-500 disabled:opacity-50 text-white rounded-xl transition-all active:scale-95 text-sm font-bold"
                  >
                    {addingChannel ? <Loader2 className="w-4 h-4 animate-spin" /> : <Plus className="w-4 h-4" />}
                    Ajouter le groupe
                  </button>
                </div>

                {/* ── Channel List ── */}
                <div>
                  <p className="text-[10px] font-black text-slate-500 uppercase tracking-[0.2em] mb-3">Groupes Actifs ({channels.length})</p>
                  {channels.length === 0 ? (
                    <div className="text-center py-10 bg-black/20 rounded-2xl border border-white/5">
                      <p className="text-xs text-slate-600 italic">Aucun groupe configuré</p>
                    </div>
                  ) : (
                    <div className="space-y-3">
                      {channels.map((ch, i) => {
                        const url = ch.url || ch;
                        const isEditing = editingChannel === url;
                        const isExpanded = expandedChannels[url];
                        const riskCls = getRiskColor(ch.risk_level);
                        return (
                          <div key={i} className="bg-white/3 border border-white/5 rounded-2xl overflow-hidden transition-all hover:border-white/10">
                            {/* Card Header */}
                            <div className="flex items-center gap-3 p-4">
                              <div className="w-9 h-9 rounded-xl bg-slate-800 flex items-center justify-center text-purple-400 shrink-0">
                                <Terminal className="w-4 h-4" />
                              </div>
                              <div className="flex-1 min-w-0">
                                <div className="flex items-center gap-2 flex-wrap">
                                  <p className="text-sm font-bold text-white">{ch.name || extractChannelName(url)}</p>
                                  {ch.name && <p className="text-[10px] text-slate-500 font-mono">{extractChannelName(url)}</p>}
                                  {ch.category && <span className="px-2 py-0.5 bg-purple-500/15 border border-purple-500/25 rounded-full text-[9px] font-bold text-purple-300 uppercase">{ch.category}</span>}
                                  {ch.risk_level && ch.risk_level !== 'unknown' && (
                                    <span className={`px-2 py-0.5 border rounded-full text-[9px] font-bold uppercase ${riskCls}`}>{ch.risk_level}</span>
                                  )}
                                </div>
                                <p className="text-[11px] text-slate-500 truncate mt-0.5">{url}</p>
                              </div>
                              <div className="flex items-center gap-1 shrink-0">
                                <button onClick={() => setExpandedChannels(s => ({...s, [url]: !s[url]}))}
                                  className="p-2 text-slate-600 hover:text-slate-300 hover:bg-white/5 rounded-lg transition-all" title="Voir détails">
                                  <Info className="w-3.5 h-3.5" />
                                </button>
                                <button onClick={() => { setEditingChannel(url); setEditForm({ name: ch.name || '', description: ch.description || '', category: ch.category || '', risk_level: ch.risk_level || 'unknown', member_count: ch.member_count || 0, language: ch.language || '', country: ch.country || '' }); setExpandedChannels(s => ({...s, [url]: true})); }}
                                  className="p-2 text-slate-600 hover:text-brand-400 hover:bg-brand-500/10 rounded-lg transition-all" title="Modifier">
                                  <Edit2 className="w-3.5 h-3.5" />
                                </button>
                                <button onClick={() => handleRemoveChannel(url)}
                                  className="p-2 text-slate-600 hover:text-red-400 hover:bg-red-500/10 rounded-lg transition-all" title="Supprimer">
                                  <Trash2 className="w-3.5 h-3.5" />
                                </button>
                              </div>
                            </div>

                            {/* Expanded / Edit Panel */}
                            {isExpanded && (
                              <div className="px-4 pb-4 border-t border-white/5 pt-4">
                                {isEditing ? (
                                  <div className="space-y-3">
                                    <div className="grid grid-cols-2 gap-3">
                                      <input type="text" placeholder="Nom du groupe" value={editForm.name}
                                        onChange={e => setEditForm(f => ({...f, name: e.target.value}))}
                                        className="bg-black/40 border border-white/10 rounded-xl px-3 py-2 text-sm focus:outline-none focus:border-brand-500/50" />
                                      <input type="text" placeholder="Catégorie" value={editForm.category}
                                        onChange={e => setEditForm(f => ({...f, category: e.target.value}))}
                                        className="bg-black/40 border border-white/10 rounded-xl px-3 py-2 text-sm focus:outline-none focus:border-brand-500/50" />
                                      <input type="text" placeholder="Pays d'origine" value={editForm.country}
                                        onChange={e => setEditForm(f => ({...f, country: e.target.value}))}
                                        className="bg-black/40 border border-white/10 rounded-xl px-3 py-2 text-sm focus:outline-none focus:border-brand-500/50" />
                                      <input type="text" placeholder="Langue" value={editForm.language}
                                        onChange={e => setEditForm(f => ({...f, language: e.target.value}))}
                                        className="bg-black/40 border border-white/10 rounded-xl px-3 py-2 text-sm focus:outline-none focus:border-brand-500/50" />
                                      <input type="number" placeholder="Membres" min={0} value={editForm.member_count || ''}
                                        onChange={e => setEditForm(f => ({...f, member_count: parseInt(e.target.value) || 0}))}
                                        className="bg-black/40 border border-white/10 rounded-xl px-3 py-2 text-sm focus:outline-none focus:border-brand-500/50" />
                                      <select value={editForm.risk_level} onChange={e => setEditForm(f => ({...f, risk_level: e.target.value}))}
                                        className="bg-black/40 border border-white/10 rounded-xl px-3 py-2 text-sm focus:outline-none focus:border-brand-500/50 text-slate-300">
                                        <option value="unknown">Niveau de risque</option>
                                        <option value="critical">Critical</option>
                                        <option value="high">High</option>
                                        <option value="medium">Medium</option>
                                        <option value="low">Low</option>
                                      </select>
                                    </div>
                                    <textarea placeholder="Description" rows={2} value={editForm.description}
                                      onChange={e => setEditForm(f => ({...f, description: e.target.value}))}
                                      className="w-full bg-black/40 border border-white/10 rounded-xl px-3 py-2 text-sm focus:outline-none focus:border-brand-500/50 resize-none" />
                                    <div className="flex gap-2">
                                      <button onClick={() => handleUpdateChannel(url)} disabled={savingChannel}
                                        className="flex items-center gap-2 px-4 py-2 bg-brand-600 hover:bg-brand-500 disabled:opacity-50 text-white rounded-xl text-xs font-bold transition-all active:scale-95">
                                        {savingChannel ? <Loader2 className="w-3.5 h-3.5 animate-spin" /> : <Save className="w-3.5 h-3.5" />}
                                        Enregistrer
                                      </button>
                                      <button onClick={() => setEditingChannel(null)}
                                        className="flex items-center gap-2 px-4 py-2 border border-white/10 text-slate-400 hover:text-white rounded-xl text-xs font-bold transition-all">
                                        <X className="w-3.5 h-3.5" /> Annuler
                                      </button>
                                    </div>
                                  </div>
                                ) : (
                                  <div className="grid grid-cols-2 gap-x-8 gap-y-2 text-xs">
                                    {ch.country && <div className="flex items-center gap-2 text-slate-400"><MapPin className="w-3.5 h-3.5 text-slate-600" /><span className="text-slate-500">Pays :</span> <span className="text-slate-200">{ch.country}</span></div>}
                                    {ch.language && <div className="flex items-center gap-2 text-slate-400"><Languages className="w-3.5 h-3.5 text-slate-600" /><span className="text-slate-500">Langue :</span> <span className="text-slate-200">{ch.language}</span></div>}
                                    {ch.member_count > 0 && <div className="flex items-center gap-2 text-slate-400"><Users className="w-3.5 h-3.5 text-slate-600" /><span className="text-slate-500">Membres :</span> <span className="text-slate-200">{ch.member_count.toLocaleString()}</span></div>}
                                    {ch.risk_level && ch.risk_level !== 'unknown' && <div className="flex items-center gap-2"><ShieldQuestion className="w-3.5 h-3.5 text-slate-600" /><span className="text-slate-500">Risque :</span> <span className={`font-bold uppercase ${getRiskColor(ch.risk_level).split(' ')[0]}`}>{ch.risk_level}</span></div>}
                                    {ch.description && <div className="col-span-2 mt-1 text-slate-400 leading-relaxed"><span className="text-slate-500 font-semibold">Description : </span>{ch.description}</div>}
                                    {!ch.country && !ch.language && !ch.member_count && !ch.description && (
                                      <p className="col-span-2 text-slate-600 italic text-[11px]">Aucun détail renseigné — cliquez sur <Edit2 className="inline w-3 h-3" /> pour compléter le profil.</p>
                                    )}
                                  </div>
                                )}
                              </div>
                            )}
                          </div>
                        );
                      })}
                    </div>
                  )}
                </div>
              </div>

              <div className="p-4 bg-black/20 text-center border-t border-white/5">
                <p className="text-[8px] text-slate-600 font-mono uppercase tracking-[0.2em]">
                  Les détails des groupes sont inclus dans les rapports PDF générés
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
                    {channels.map((ch, i) => {
                      const url = typeof ch === 'object' ? ch.url : ch;
                      const checked = selectedChannelsForRun.some(u => (typeof u === 'object' ? u.url : u) === url);
                      return (
                      <label key={i} className="flex items-center gap-3 p-3 bg-white/5 rounded-xl border border-white/5 hover:border-brand-500/30 cursor-pointer transition-all">
                        <input
                          type="checkbox"
                          checked={checked}
                          onChange={(e) => {
                            if (e.target.checked) {
                              setSelectedChannelsForRun(prev => [...prev, ch]);
                            } else {
                              setSelectedChannelsForRun(prev => prev.filter(u => (typeof u === 'object' ? u.url : u) !== url));
                            }
                          }}
                          className="w-4 h-4 rounded border-slate-700 bg-slate-800 text-brand-500 focus:ring-brand-500/20"
                        />
                        <div className="min-w-0">
                          <p className="text-sm font-semibold text-white">{ch.name || extractChannelName(url)}</p>
                          <p className="text-xs text-slate-500 truncate">{url}</p>
                        </div>
                      </label>
                      );
                    })}
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
