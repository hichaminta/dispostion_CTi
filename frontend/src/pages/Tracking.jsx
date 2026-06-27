import React, { useState, useEffect } from 'react';
import axios from 'axios';
import { Activity, Clock, Database, Search, RefreshCw, FileText } from 'lucide-react';
import { format } from 'date-fns';

const API_BASE = `http://${window.location.hostname}:8000`;

export default function Tracking() {
  const [trackingData, setTrackingData] = useState({});
  const [loading, setLoading] = useState(true);
  const [searchTerm, setSearchTerm] = useState('');

  const fetchTracking = async () => {
    try {
      setLoading(true);
      const res = await axios.get(`${API_BASE}/api/tracking`);
      setTrackingData(res.data);
    } catch (e) {
      console.error("Error fetching tracking data:", e);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchTracking();
  }, []);

  // Process data: group by source name
  const sourcesMap = {};
  Object.keys(trackingData).forEach(key => {
    const parts = key.split('_');
    const type = parts[0]; // collection, extraction, enrichment
    const sourceName = parts.slice(1).join('_');
    
    if (!sourcesMap[sourceName]) {
      sourcesMap[sourceName] = { name: sourceName, collection: null, extraction: null, enrichment: null };
    }
    
    sourcesMap[sourceName][type] = trackingData[key];
  });

  const sources = Object.values(sourcesMap).filter(s => 
    s.name.toLowerCase().includes(searchTerm.toLowerCase())
  );

  const formatDate = (dateString) => {
    if (!dateString) return '—';
    try {
      return format(new Date(dateString), 'dd/MM/yyyy HH:mm:ss');
    } catch (e) {
      return dateString; // fallback
    }
  };

  const renderStatusCard = (type, data) => {
    if (!data) return (
      <div className="bg-slate-900/30 border border-slate-800 rounded-xl p-4 text-center">
        <span className="text-slate-600 text-sm">Aucune donnée</span>
      </div>
    );

    return (
      <div className="bg-slate-800/40 border border-white/5 rounded-xl p-4 space-y-2">
        {Object.entries(data).map(([k, v]) => (
          <div key={k} className="flex justify-between items-center text-sm border-b border-white/5 pb-1 last:border-0 last:pb-0">
            <span className="text-slate-400 font-medium capitalize">{k.replace(/_/g, ' ')}</span>
            <span className="text-slate-200">{typeof v === 'string' && v.includes('T') ? formatDate(v) : JSON.stringify(v)}</span>
          </div>
        ))}
      </div>
    );
  };

  return (
    <div className="min-h-screen bg-transparent p-6 md:p-8 text-slate-200">
      <div className="max-w-7xl mx-auto space-y-6">
        
        {/* Header */}
        <div className="flex flex-col md:flex-row md:items-center justify-between bg-slate-900/60 p-6 rounded-2xl border border-white/5 backdrop-blur-md gap-4">
          <div>
            <h1 className="text-2xl font-black text-white flex items-center gap-3">
              <Database className="w-6 h-6 text-brand-400" />
              Tracking des Données
            </h1>
            <p className="text-sm text-slate-400 mt-1">Supervisez l'état des collectes, extractions et enrichissements en temps réel.</p>
          </div>
          
          <div className="flex items-center gap-3">
            <div className="relative">
              <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-slate-500" />
              <input 
                type="text" 
                placeholder="Rechercher une source..." 
                value={searchTerm}
                onChange={(e) => setSearchTerm(e.target.value)}
                className="bg-slate-950/50 border border-slate-800 text-white pl-9 pr-4 py-2 rounded-xl text-sm focus:outline-none focus:border-brand-500 transition-colors w-64"
              />
            </div>
            <button
              onClick={fetchTracking}
              className="flex items-center justify-center p-2.5 bg-slate-800 hover:bg-slate-700 text-white rounded-xl transition-all"
              title="Rafraîchir"
            >
              <RefreshCw className={`w-4 h-4 ${loading ? 'animate-spin' : ''}`} />
            </button>
          </div>
        </div>

        {/* Content */}
        {loading && sources.length === 0 ? (
          <div className="flex justify-center p-12">
            <RefreshCw className="w-8 h-8 animate-spin text-brand-500" />
          </div>
        ) : sources.length === 0 ? (
          <div className="bg-slate-900/40 p-12 rounded-2xl border border-white/5 text-center flex flex-col items-center">
            <FileText className="w-12 h-12 text-slate-600 mb-4" />
            <h3 className="text-lg font-bold text-slate-300">Aucune donnée de tracking</h3>
            <p className="text-slate-500 mt-2">Aucun fichier local_tracking.json n'a été trouvé ou il est vide.</p>
          </div>
        ) : (
          <div className="grid grid-cols-1 gap-6">
            {sources.map(source => (
              <div key={source.name} className="bg-slate-900/60 p-6 rounded-2xl border border-white/5 backdrop-blur-md">
                <h2 className="text-xl font-bold text-white mb-4 flex items-center gap-2">
                  <Activity className="w-5 h-5 text-brand-400" />
                  {source.name}
                </h2>
                
                <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
                  {/* Collection */}
                  <div>
                    <h3 className="text-sm font-bold text-slate-400 uppercase tracking-widest mb-3 flex items-center gap-2">
                      <Database className="w-4 h-4" /> Collecte
                    </h3>
                    {renderStatusCard('collection', source.collection)}
                  </div>
                  
                  {/* Extraction */}
                  <div>
                    <h3 className="text-sm font-bold text-slate-400 uppercase tracking-widest mb-3 flex items-center gap-2">
                      <FileText className="w-4 h-4" /> Extraction
                    </h3>
                    {renderStatusCard('extraction', source.extraction)}
                  </div>
                  
                  {/* Enrichment */}
                  <div>
                    <h3 className="text-sm font-bold text-slate-400 uppercase tracking-widest mb-3 flex items-center gap-2">
                      <Clock className="w-4 h-4" /> Enrichissement
                    </h3>
                    {renderStatusCard('enrichment', source.enrichment)}
                  </div>
                </div>
              </div>
            ))}
          </div>
        )}
      </div>
    </div>
  );
}
