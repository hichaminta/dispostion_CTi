import React, { useState } from 'react';
import Dashboard from './pages/Dashboard';
import RunDetail from './pages/RunDetail';
import Results from './pages/Results';
import Leaks from './pages/Leaks';
import CSVAnalyzer from './pages/CSVAnalyzer';
import CorrelatedEvents from './pages/CorrelatedEvents';
import Planifications from './pages/Planifications';
import Login from './pages/Login';
import SettingsModal from './components/SettingsModal';
import { Settings, Activity, MessageSquare, BarChart2, FileText, ChevronLeft, Shield, Clock } from 'lucide-react';
import logo from './assets/logo.png';

const NAV_ITEMS = [
  { id: 'monitor',      label: 'Monitor',  icon: Activity   },
  { id: 'events',       label: 'Events',   icon: Shield     },
  { id: 'leaks',        label: 'Leaks',    icon: MessageSquare },
  { id: 'planifications', label: 'Planif.', icon: Clock    },
  { id: 'results',      label: 'Results',  icon: BarChart2  },
  { id: 'csv_analyzer', label: 'CSV AI',   icon: FileText, accent: true },
];

function App() {
  const [isAuthenticated, setIsAuthenticated] = useState(false);
  const [selectedRunId, setSelectedRunId] = useState(null);
  const [view, setView] = useState('monitor');
  const [showSettings, setShowSettings] = useState(false);
  const [selectedSourceId, setSelectedSourceId] = useState(null);

  if (!isAuthenticated) {
    return <Login onLogin={() => setIsAuthenticated(true)} />;
  }

  return (
    <div className="min-h-screen bg-transparent text-slate-200 flex flex-col">

      {/* ── Top Navigation Bar ───────────────────────────────────────── */}
      <div className="fixed top-4 left-1/2 -translate-x-1/2 z-50 w-[95%] max-w-5xl">
        <header className="h-14 bg-slate-950/80 backdrop-blur-xl border border-white/10 rounded-2xl flex items-center px-4 gap-4 shadow-[0_8px_32px_rgba(0,0,0,0.5)] transition-all duration-300">

          {/* Logo + brand */}
          <div className="flex items-center gap-3 shrink-0 pl-2">
            <img src={logo} alt="BlueSec" className="h-6 w-auto drop-shadow-[0_0_8px_rgba(14,165,233,0.5)]" />
            <div className="w-px h-5 bg-slate-700/50" />
            <div className="flex items-center gap-2">
              <span className="w-1.5 h-1.5 bg-emerald-500 rounded-full animate-pulse shadow-[0_0_8px_rgba(16,185,129,0.8)]" />
              <span className="text-[11px] font-bold tracking-widest text-slate-300 uppercase">CTI Platform</span>
            </div>
          </div>

          <div className="flex-1 flex justify-center">
            {/* Nav links — replaced by back button when viewing a run detail */}
            {selectedRunId ? (
              <button
                onClick={() => setSelectedRunId(null)}
                className="flex items-center gap-2 text-sm font-medium text-slate-400 hover:text-white transition-all px-4 py-1.5 rounded-xl hover:bg-white/5 border border-transparent hover:border-white/10"
              >
                <ChevronLeft className="w-4 h-4" />
                Back to Monitor
              </button>
            ) : (
              <nav className="flex items-center gap-1 bg-black/20 p-1 rounded-xl border border-white/5">
                {NAV_ITEMS.map(({ id, label, icon: Icon, accent }) => (
                  <button
                    key={id}
                    onClick={() => {
                      setView(id);
                      if (id !== 'results') {
                        setSelectedSourceId(null);
                      }
                    }}
                    className={`flex items-center gap-2 px-4 py-1.5 rounded-lg text-sm font-medium transition-all duration-300 relative overflow-hidden group ${
                      view === id
                        ? 'text-white shadow-md'
                        : 'text-slate-400 hover:text-slate-200 hover:bg-white/5'
                    }`}
                  >
                    {view === id && (
                      <div className={`absolute inset-0 opacity-20 ${accent ? 'bg-purple-500' : 'bg-brand-500'}`} />
                    )}
                    {view === id && (
                      <div className={`absolute bottom-0 left-1/4 right-1/4 h-[2px] rounded-t-full shadow-[0_-2px_8px_rgba(255,255,255,0.8)] ${accent ? 'bg-purple-400' : 'bg-brand-400'}`} />
                    )}
                    <Icon className={`w-4 h-4 relative z-10 transition-transform duration-300 ${view === id ? 'scale-110' : 'group-hover:scale-110'}`} />
                    <span className="relative z-10 hidden sm:inline">{label}</span>
                  </button>
                ))}
              </nav>
            )}
          </div>

          {/* Settings */}
          <button
            onClick={() => setShowSettings(true)}
            className={`flex items-center gap-2 px-3 py-1.5 rounded-xl text-sm font-medium transition-all ${
              showSettings
                ? 'bg-brand-500/20 text-brand-300 border border-brand-500/30'
                : 'text-slate-400 hover:text-white hover:bg-white/5 border border-transparent hover:border-white/10'
            }`}
          >
            <Settings className="w-4 h-4" />
          </button>
        </header>
      </div>

      {showSettings && <SettingsModal onClose={() => setShowSettings(false)} />}

      {/* ── Page content (offset below fixed nav) ──────────────────── */}
      <div className="flex-1 pt-24">
        {selectedRunId ? (
          <RunDetail 
            runId={selectedRunId} 
            onBack={() => setSelectedRunId(null)} 
            onExploreSource={(sourceId) => {
              setSelectedRunId(null);
              setView('results');
              setSelectedSourceId(sourceId);
            }}
          />
        ) : view === 'monitor' ? (
          <Dashboard 
            onSelectRun={(id) => setSelectedRunId(id)} 
            onExploreSource={(sourceId) => {
              setView('results');
              setSelectedSourceId(sourceId);
            }}
          />
        ) : view === 'events' ? (
          <CorrelatedEvents onBack={() => setView('monitor')} />
        ) : view === 'leaks' ? (
          <Leaks onBack={() => setView('monitor')} />
        ) : view === 'planifications' ? (
          <Planifications onBack={() => setView('monitor')} />
        ) : view === 'csv_analyzer' ? (
          <CSVAnalyzer onBack={() => setView('monitor')} />
        ) : (
          <Results 
            onBack={() => setView('monitor')} 
            initialSourceId={selectedSourceId}
          />
        )}
      </div>
    </div>
  );
}

export default App;
