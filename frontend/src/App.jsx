import React, { useState } from 'react';
import Dashboard from './pages/Dashboard';
import RunDetail from './pages/RunDetail';
import Results from './pages/Results';

function App() {
  const [selectedRunId, setSelectedRunId] = useState(null);
  const [view, setView] = useState('monitor'); // 'monitor' or 'results'

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
      {/* View Switcher Overlay (Floating) */}
      <div className="fixed bottom-8 left-1/2 -translate-x-1/2 z-50 p-1 bg-slate-900/80 backdrop-blur-xl rounded-2xl border border-white/10 shadow-2xl flex items-center gap-1">
        <button 
          onClick={() => setView('monitor')}
          className={`px-6 py-2 rounded-xl text-xs font-black uppercase tracking-widest transition-all ${view === 'monitor' ? 'bg-brand-500 text-white shadow-lg shadow-brand-500/20' : 'text-slate-500 hover:text-slate-300'}`}
        >
          Monitor
        </button>
        <button 
          onClick={() => setView('results')}
          className={`px-6 py-2 rounded-xl text-xs font-black uppercase tracking-widest transition-all ${view === 'results' ? 'bg-brand-500 text-white shadow-lg shadow-brand-500/20' : 'text-slate-500 hover:text-slate-300'}`}
        >
          Results
        </button>
      </div>

      {view === 'monitor' ? (
        <Dashboard 
          onSelectRun={(id) => setSelectedRunId(id)} 
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
