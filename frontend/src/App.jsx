import React, { useState } from 'react';
import Dashboard from './pages/Dashboard';
import RunDetail from './pages/RunDetail';
import Results from './pages/Results';
import Leaks from './pages/Leaks';
import CSVAnalyzer from './pages/CSVAnalyzer';
import SettingsModal from './components/SettingsModal';
import { Settings } from 'lucide-react';

function App() {
  const [selectedRunId, setSelectedRunId] = useState(null);
  const [view, setView] = useState('monitor'); // 'monitor', 'results', or 'leaks'
  const [showSettings, setShowSettings] = useState(false);

  // If a run is selected, show details regardless of current view
  if (selectedRunId) {
    return (
      <div className="min-h-screen bg-[#0f1021] text-slate-200">
        <RunDetail 
          runId={selectedRunId} 
          onBack={() => setSelectedRunId(null)} 
        />
      </div>
    );
  }

  return (
    <div className="min-h-screen bg-[#0f1021] text-slate-200 flex flex-col">
      {/* Floating Nav Bar */}
      <div className="fixed bottom-8 left-1/2 -translate-x-1/2 z-50 p-1 bg-slate-900/80 backdrop-blur-xl rounded-2xl border border-white/10 shadow-2xl flex items-center gap-1">
        <button 
          onClick={() => setView('monitor')}
          className={`px-6 py-2 rounded-xl text-xs font-black uppercase tracking-widest transition-all ${view === 'monitor' ? 'bg-brand-500 text-white shadow-lg shadow-brand-500/20' : 'text-slate-500 hover:text-slate-300'}`}
        >
          Monitor
        </button>
        <button 
          onClick={() => setView('leaks')}
          className={`px-6 py-2 rounded-xl text-xs font-black uppercase tracking-widest transition-all ${view === 'leaks' ? 'bg-brand-500 text-white shadow-lg shadow-brand-500/20' : 'text-slate-500 hover:text-slate-300'}`}
        >
          Leaks
        </button>
        <button 
          onClick={() => setView('results')}
          className={`px-6 py-2 rounded-xl text-xs font-black uppercase tracking-widest transition-all ${view === 'results' ? 'bg-brand-500 text-white shadow-lg shadow-brand-500/20' : 'text-slate-500 hover:text-slate-300'}`}
        >
          Results
        </button>
        <button 
          onClick={() => setView('csv_analyzer')}
          className={`px-6 py-2 rounded-xl text-xs font-black uppercase tracking-widest transition-all ${view === 'csv_analyzer' ? 'bg-purple-500 text-white shadow-lg shadow-purple-500/20' : 'text-slate-500 hover:text-slate-300'}`}
        >
          CSV AI
        </button>

        {/* Divider */}
        <div className="w-px h-5 bg-white/10 mx-1" />

        {/* Settings Button */}
        <button
          onClick={() => setShowSettings(true)}
          title="Paramètres AI"
          className={`p-2 rounded-xl transition-all ${showSettings ? 'bg-brand-500/20 text-brand-400 border border-brand-500/30' : 'text-slate-500 hover:text-slate-300 hover:bg-white/5'}`}
        >
          <Settings className="w-4 h-4" />
        </button>
      </div>

      {/* Settings Modal */}
      {showSettings && <SettingsModal onClose={() => setShowSettings(false)} />}

      {view === 'monitor' ? (
        <Dashboard 
          onSelectRun={(id) => setSelectedRunId(id)} 
        />
      ) : view === 'leaks' ? (
        <Leaks 
          onBack={() => setView('monitor')}
        />
      ) : view === 'csv_analyzer' ? (
        <CSVAnalyzer 
          onBack={() => setView('monitor')}
        />
      ) : (
        <Results 
          onBack={() => setView('monitor')}
        />
      )}
    </div>
  );
}

export default App;
