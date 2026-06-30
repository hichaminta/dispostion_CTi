import React, { useState, useEffect } from 'react';
import axios from 'axios';
import { Activity, Clock, Database, Search, RefreshCw, FileText, Edit2, X, Save } from 'lucide-react';
import { format } from 'date-fns';

const API_BASE = ``;

export default function Tracking() {
  const [trackingData, setTrackingData] = useState({});
  const [loading, setLoading] = useState(true);
  const [searchTerm, setSearchTerm] = useState('');
  
  const [activeTabs, setActiveTabs] = useState({});
  const [editingModal, setEditingModal] = useState(null);
  const [editingJson, setEditingJson] = useState("");
  const [saveError, setSaveError] = useState("");

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

  const handleSaveTracking = async () => {
    setSaveError("");
    try {
      const parsedData = JSON.parse(editingJson);
      const key = `${editingModal.type}_${editingModal.sourceName}`;
      const res = await axios.post(`${API_BASE}/api/tracking`, { key, data: parsedData });
      if (res.data.status === "error") {
        setSaveError(res.data.message);
        return;
      }
      setEditingModal(null);
      fetchTracking();
    } catch (e) {
      setSaveError("JSON invalide ou erreur réseau: " + e.message);
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
      sourcesMap[sourceName] = { name: sourceName, collection: null, extraction: null, enrichment: null, correlation: null, stix: null, misp: null };
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

  const renderStatusCard = (type, data, sourceName) => {
    if (!data) return (
      <div className="bg-slate-900/30 border border-slate-800 rounded-xl p-4 text-center">
        <span className="text-slate-600 text-sm">Aucune donnée</span>
      </div>
    );

    const isEditable = !['correlation', 'stix'].includes(type);

    return (
      <div className="bg-slate-800/40 border border-white/5 rounded-xl p-4 space-y-2 relative group">
        {isEditable && (
          <button 
            onClick={() => {
              setEditingModal({ type, sourceName, data });
              setEditingJson(JSON.stringify(data, null, 2));
              setSaveError("");
            }}
            className="absolute top-2 right-2 opacity-0 group-hover:opacity-100 p-1.5 bg-brand-500/20 text-brand-400 rounded-lg hover:bg-brand-500/40 transition-all z-10"
            title="Modifier le tracking"
          >
            <Edit2 className="w-3.5 h-3.5" />
          </button>
        )}
        {Object.entries(data).map(([k, v]) => (
          <div key={k} className="flex justify-between items-center text-sm border-b border-white/5 pb-1 last:border-0 last:pb-0">
            <span className="text-slate-400 font-medium capitalize truncate mr-2" title={k}>{k.replace(/_/g, ' ')}</span>
            <span className="text-slate-200 text-right truncate max-w-[140px]" title={String(v)}>
              {typeof v === 'string' && v.includes('T') ? formatDate(v) : JSON.stringify(v)}
            </span>
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
                
                <div className="mb-6 overflow-x-auto">
                  <div className="flex gap-2 border-b border-white/10 pb-4 min-w-max">
                    {[
                      { id: 'collection', label: 'Collecte', icon: Database },
                      { id: 'extraction', label: 'Extraction', icon: FileText },
                      { id: 'enrichment', label: 'Enrichissement', icon: Clock },
                      { id: 'correlation', label: 'Corrélation', icon: Activity },
                      { id: 'stix', label: 'STIX Export', icon: FileText },
                      { id: 'misp', label: 'MISP Sync', icon: Database }
                    ].map(tab => {
                      const isActive = (activeTabs[source.name] || 'collection') === tab.id;
                      const Icon = tab.icon;
                      return (
                        <button
                          key={tab.id}
                          onClick={() => setActiveTabs(prev => ({...prev, [source.name]: tab.id}))}
                          className={`flex items-center gap-2 px-5 py-2.5 rounded-xl text-sm font-bold transition-all ${
                            isActive 
                              ? 'bg-brand-500 text-white shadow-lg shadow-brand-500/25' 
                              : 'bg-slate-800/50 text-slate-400 hover:text-slate-200 hover:bg-slate-800'
                          }`}
                        >
                          <Icon className="w-4 h-4" />
                          {tab.label}
                        </button>
                      );
                    })}
                  </div>
                </div>

                <div className="min-h-[250px] bg-slate-950/50 p-6 rounded-xl border border-white/5">
                  {[
                    { id: 'collection', label: 'Collecte', icon: Database },
                    { id: 'extraction', label: 'Extraction', icon: FileText },
                    { id: 'enrichment', label: 'Enrichissement', icon: Clock },
                    { id: 'correlation', label: 'Corrélation', icon: Activity },
                    { id: 'stix', label: 'STIX Export', icon: FileText },
                    { id: 'misp', label: 'MISP Sync', icon: Database }
                  ].map(tab => {
                    const isActive = (activeTabs[source.name] || 'collection') === tab.id;
                    if (!isActive) return null;
                    const Icon = tab.icon;
                    
                    return (
                      <div key={tab.id} className="animate-in fade-in slide-in-from-bottom-4 duration-500">
                        <h3 className="text-base font-bold text-slate-300 uppercase tracking-widest mb-6 flex items-center gap-2 border-b border-white/5 pb-3">
                          <Icon className="w-5 h-5 text-brand-400" /> {tab.label}
                        </h3>
                        {renderStatusCard(tab.id, source[tab.id], source.name)}
                      </div>
                    );
                  })}
                </div>
              </div>
            ))}
          </div>
        )}
      </div>
      
      {/* Editing Modal */}
      {editingModal && (
        <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/60 backdrop-blur-sm">
          <div className="bg-slate-900 border border-slate-700 rounded-2xl shadow-2xl w-full max-w-lg overflow-hidden flex flex-col">
            <div className="flex items-center justify-between p-4 border-b border-slate-800 bg-slate-900/50">
              <h3 className="text-lg font-bold text-white flex items-center gap-2">
                <Edit2 className="w-5 h-5 text-brand-400" />
                Modifier le tracking
              </h3>
              <button onClick={() => setEditingModal(null)} className="p-1 text-slate-400 hover:text-white rounded-lg hover:bg-slate-800 transition-colors">
                <X className="w-5 h-5" />
              </button>
            </div>
            <div className="p-4 space-y-4">
              <div className="flex gap-2 mb-2">
                <span className="px-2 py-1 bg-brand-500/10 text-brand-400 rounded-md text-xs font-bold uppercase tracking-wider border border-brand-500/20">{editingModal.type}</span>
                <span className="px-2 py-1 bg-slate-800 text-slate-300 rounded-md text-xs font-medium border border-slate-700">{editingModal.sourceName}</span>
              </div>
              
              {saveError && (
                <div className="p-3 bg-red-500/10 border border-red-500/30 text-red-400 text-sm rounded-xl">
                  {saveError}
                </div>
              )}
              
              <textarea
                value={editingJson}
                onChange={(e) => setEditingJson(e.target.value)}
                className="w-full h-64 bg-slate-950 border border-slate-800 rounded-xl p-4 text-sm font-mono text-emerald-400 focus:outline-none focus:border-brand-500 transition-colors resize-none"
                spellCheck={false}
              />
            </div>
            <div className="flex items-center justify-end gap-3 p-4 border-t border-slate-800 bg-slate-900/50">
              <button 
                onClick={() => setEditingModal(null)}
                className="px-4 py-2 text-sm font-medium text-slate-300 hover:text-white transition-colors"
              >
                Annuler
              </button>
              <button 
                onClick={handleSaveTracking}
                className="flex items-center gap-2 px-4 py-2 bg-brand-600 hover:bg-brand-500 text-white text-sm font-medium rounded-xl transition-colors shadow-lg shadow-brand-500/20"
              >
                <Save className="w-4 h-4" />
                Sauvegarder
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
