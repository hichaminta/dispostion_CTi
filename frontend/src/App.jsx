import React, { useState } from 'react';
import Dashboard from './pages/Dashboard';
import RunDetail from './pages/RunDetail';
import Results from './pages/Results';
import Leaks from './pages/Leaks';
import CSVAnalyzer from './pages/CSVAnalyzer';
import CorrelatedEvents from './pages/CorrelatedEvents';
import SettingsModal from './components/SettingsModal';
import { Settings, Activity, MessageSquare, BarChart2, FileText, ChevronLeft, Shield } from 'lucide-react';
import logo from './assets/logo.png';

const NAV_ITEMS = [
  { id: 'monitor',      label: 'Monitor',  icon: Activity   },
  { id: 'events',       label: 'Events',   icon: Shield     },
  { id: 'leaks',        label: 'Leaks',    icon: MessageSquare },
  { id: 'results',      label: 'Results',  icon: BarChart2  },
  { id: 'csv_analyzer', label: 'CSV AI',   icon: FileText, accent: true },
];

function App() {
  const [selectedRunId, setSelectedRunId] = useState(null);
  const [view, setView] = useState('monitor');
  const [showSettings, setShowSettings] = useState(false);

  return (
    <div className="min-h-screen bg-[#05060b] text-slate-200 flex flex-col">

      {/* ── Top Navigation Bar ───────────────────────────────────────── */}
      <header className="fixed top-0 left-0 right-0 z-50 h-14 bg-slate-950/95 backdrop-blur-xl border-b border-slate-800/80 flex items-center px-6 gap-6 shadow-lg shadow-black/30">

        {/* Logo + brand */}
        <div className="flex items-center gap-3 shrink-0">
          <img src={logo} alt="BlueSec" className="h-6 w-auto drop-shadow-sm" />
          <div className="w-px h-5 bg-slate-700" />
          <div className="flex items-center gap-2">
            <span className="w-1.5 h-1.5 bg-emerald-500 rounded-full animate-pulse" />
            <span className="text-xs font-semibold text-slate-400">CTI Platform</span>
          </div>
        </div>

        {/* Nav links — replaced by back button when viewing a run detail */}
        {selectedRunId ? (
          <button
            onClick={() => setSelectedRunId(null)}
            className="flex items-center gap-2 text-sm font-medium text-slate-400 hover:text-slate-200 transition-colors px-3 py-1.5 rounded-lg hover:bg-slate-800/60"
          >
            <ChevronLeft className="w-4 h-4" />
            Back to Monitor
          </button>
        ) : (
          <nav className="flex items-center gap-1">
            {NAV_ITEMS.map(({ id, label, icon: Icon, accent }) => (
              <button
                key={id}
                onClick={() => setView(id)}
                className={`flex items-center gap-2 px-4 py-2 rounded-lg text-sm font-medium transition-all ${
                  view === id
                    ? accent
                      ? 'bg-purple-500/15 text-purple-400 border border-purple-500/30'
                      : 'bg-sky-500/15 text-sky-400 border border-sky-500/30'
                    : 'text-slate-400 hover:text-slate-200 hover:bg-slate-800/60'
                }`}
              >
                <Icon className="w-4 h-4" />
                {label}
              </button>
            ))}
          </nav>
        )}

        {/* Settings */}
        <button
          onClick={() => setShowSettings(true)}
          className={`ml-auto flex items-center gap-2 px-3 py-2 rounded-lg text-sm font-medium transition-all ${
            showSettings
              ? 'bg-sky-500/15 text-sky-400 border border-sky-500/30'
              : 'text-slate-400 hover:text-slate-200 hover:bg-slate-800/60'
          }`}
        >
          <Settings className="w-4 h-4" />
          <span className="hidden sm:inline">Settings</span>
        </button>
      </header>

      {showSettings && <SettingsModal onClose={() => setShowSettings(false)} />}

      {/* ── Page content (offset below fixed nav) ──────────────────── */}
      <div className="flex-1 pt-14">
        {selectedRunId ? (
          <RunDetail runId={selectedRunId} onBack={() => setSelectedRunId(null)} />
        ) : view === 'monitor' ? (
          <Dashboard onSelectRun={(id) => setSelectedRunId(id)} />
        ) : view === 'events' ? (
          <CorrelatedEvents onBack={() => setView('monitor')} />
        ) : view === 'leaks' ? (
          <Leaks onBack={() => setView('monitor')} />
        ) : view === 'csv_analyzer' ? (
          <CSVAnalyzer onBack={() => setView('monitor')} />
        ) : (
          <Results onBack={() => setView('monitor')} />
        )}
      </div>
    </div>
  );
}

export default App;
