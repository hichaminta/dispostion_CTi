import React, { useState } from 'react';
import Dashboard from './pages/Dashboard';
import RunDetail from './pages/RunDetail';

function App() {
  const [selectedRunId, setSelectedRunId] = useState(null);

  return (
    <div className="min-h-screen bg-[#0f1021] text-slate-200">
      {selectedRunId ? (
        <RunDetail 
          runId={selectedRunId} 
          onBack={() => setSelectedRunId(null)} 
        />
      ) : (
        <Dashboard 
          onSelectRun={(id) => setSelectedRunId(id)} 
        />
      )}
    </div>
  );
}

export default App;
