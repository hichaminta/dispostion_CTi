import React, { useState, useEffect } from 'react';
import axios from 'axios';
import { Clock, Plus, Trash2, Play, Square, Loader2, RefreshCw } from 'lucide-react';
import { format } from 'date-fns';

const API_BASE = ``;

const SOURCES = [
  { id: 'unified',      name: 'Pipeline Complet', label: 'Toutes les sources (Unified)' },
  { id: 'alienvault',   name: 'AlienVault OTX',     label: 'AlienVault OTX' },
  { id: 'cins_army',    name: 'CINS Army',          label: 'CINS Army' },
  { id: 'feodotracker', name: 'FeodoTracker',       label: 'FeodoTracker' },
  { id: 'malwarebazaar',name: 'MalwareBazaar',      label: 'MalwareBazaar' },
  { id: 'nvd',          name: 'NVD',                label: 'NVD' },
  { id: 'openphish',    name: 'OpenPhish',          label: 'OpenPhish' },
  { id: 'phishtank',    name: 'PhishTank',          label: 'PhishTank' },
  { id: 'pulsedive',    name: 'PulseDive',          label: 'PulseDive' },
  { id: 'spamhaus',     name: 'Spamhaus',           label: 'Spamhaus' },
  { id: 'threatfox',    name: 'ThreatFox',          label: 'ThreatFox' },
  { id: 'urlhaus',      name: 'URLhaus',            label: 'URLhaus' },
  { id: 'dfir_report',  name: 'DFIR Report',        label: 'DFIR Report' },
];

const STEPS = [
  { id: 'pipeline',     name: 'Pipeline Complet' },
  { id: 'collecte',     name: 'Collecte' },
  { id: 'extraction',   name: 'Extraction CVE / IOC' },
  { id: 'enrichissement', name: 'Enrichissement' }
];

export default function Planifications() {
  const [schedules, setSchedules] = useState([]);
  const [loading, setLoading] = useState(true);
  const [showModal, setShowModal] = useState(false);
  
  // New Schedule form state
  const [newSource, setNewSource] = useState('Pipeline Complet');
  const [newStep, setNewStep] = useState('Pipeline Complet');
  const [newInterval, setNewInterval] = useState(60);
  const [isCreating, setIsCreating] = useState(false);

  const fetchSchedules = async () => {
    try {
      const res = await axios.get(`${API_BASE}/api/schedules`);
      setSchedules(res.data);
    } catch (e) {
      console.error("Error fetching schedules:", e);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchSchedules();
    const interval = setInterval(fetchSchedules, 5000);
    return () => clearInterval(interval);
  }, []);

  const handleCreate = async () => {
    setIsCreating(true);
    try {
      const resp = await axios.post(`${API_BASE}/api/schedules`, {
        source_name: newSource,
        step_name: newStep,
        interval_minutes: Number(newInterval)
      });
      console.log("Create response:", resp.data);
      setShowModal(false);
      fetchSchedules();
    } catch (e) {
      console.error("Error creating schedule:", e);
      alert(`Erreur lors de la création de la planification: ${e.message}`);
    } finally {
      setIsCreating(false);
    }
  };

  const handleToggle = async (id, currentActive) => {
    try {
      await axios.put(`${API_BASE}/api/schedules/${id}`, {
        action: currentActive ? 'stop' : 'start'
      });
      fetchSchedules();
    } catch (e) {
      console.error("Error toggling schedule:", e);
    }
  };

  const handleDelete = async (id) => {
    if (!window.confirm("Voulez-vous vraiment supprimer cette planification ?")) return;
    try {
      await axios.delete(`${API_BASE}/api/schedules/${id}`);
      fetchSchedules();
    } catch (e) {
      console.error("Error deleting schedule:", e);
    }
  };

  return (
    <div className="min-h-screen bg-transparent p-6 md:p-8 text-slate-200">
      <div className="max-w-6xl mx-auto space-y-6">
        
        <div className="flex justify-between items-center bg-slate-900/60 p-6 rounded-2xl border border-white/5 backdrop-blur-md">
          <div>
            <h1 className="text-2xl font-black text-white flex items-center gap-3">
              <Clock className="w-6 h-6 text-brand-400" />
              Gestion des Planifications
            </h1>
            <p className="text-sm text-slate-400 mt-1">Automatisez l'exécution des collectes et enrichissements.</p>
          </div>
          <button
            onClick={() => setShowModal(true)}
            className="flex items-center gap-2 px-4 py-2 bg-brand-600 hover:bg-brand-500 text-white rounded-xl shadow-lg transition-all font-bold"
          >
            <Plus className="w-4 h-4" />
            Nouvelle Planification
          </button>
        </div>

        {loading ? (
          <div className="flex justify-center p-12">
            <Loader2 className="w-8 h-8 animate-spin text-brand-500" />
          </div>
        ) : (
          <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
            {schedules.length === 0 ? (
              <div className="col-span-full bg-slate-900/40 p-12 rounded-2xl border border-white/5 text-center flex flex-col items-center">
                <Clock className="w-12 h-12 text-slate-600 mb-4" />
                <h3 className="text-lg font-bold text-slate-300">Aucune planification active</h3>
                <p className="text-slate-500 mt-2">Cliquez sur le bouton pour créer votre première tâche automatisée.</p>
              </div>
            ) : (
              schedules.map(sched => (
                <div key={sched.id} className="bg-slate-900/60 p-5 rounded-2xl border border-white/5 backdrop-blur-md flex flex-col justify-between group hover:border-brand-500/30 transition-all">
                  <div>
                    <div className="flex justify-between items-start mb-4">
                      <div className="flex items-center gap-2">
                        <span className={`w-2.5 h-2.5 rounded-full ${sched.active ? 'bg-emerald-500 shadow-[0_0_8px_rgba(16,185,129,0.8)] animate-pulse' : 'bg-slate-600'}`} />
                        <span className={`text-xs font-bold uppercase tracking-widest ${sched.active ? 'text-emerald-400' : 'text-slate-500'}`}>
                          {sched.active ? 'Actif' : 'En Pause'}
                        </span>
                      </div>
                      <button onClick={() => handleDelete(sched.id)} className="text-slate-500 hover:text-red-400 transition-colors">
                        <Trash2 className="w-4 h-4" />
                      </button>
                    </div>
                    
                    <h3 className="text-lg font-bold text-white mb-1">{sched.source_name}</h3>
                    <div className="text-brand-400 text-sm font-semibold mb-4 bg-brand-500/10 inline-block px-2 py-1 rounded-md">
                      {sched.step_name}
                    </div>

                    <div className="space-y-2 text-sm">
                      <div className="flex justify-between">
                        <span className="text-slate-500">Fréquence :</span>
                        <span className="text-slate-300 font-medium">Toutes les {sched.interval_minutes} min</span>
                      </div>
                      <div className="flex justify-between">
                        <span className="text-slate-500">Prochaine exécution :</span>
                        <span className="text-slate-300 font-medium">
                          {sched.next_run ? format(new Date(sched.next_run), 'dd/MM HH:mm:ss') : '—'}
                        </span>
                      </div>
                    </div>
                  </div>

                  <div className="mt-6 pt-4 border-t border-white/5">
                    <button
                      onClick={() => handleToggle(sched.id, sched.active)}
                      className={`w-full flex items-center justify-center gap-2 py-2 rounded-xl font-bold transition-all ${
                        sched.active 
                          ? 'bg-amber-500/10 text-amber-500 hover:bg-amber-500/20' 
                          : 'bg-emerald-500/10 text-emerald-500 hover:bg-emerald-500/20'
                      }`}
                    >
                      {sched.active ? <Square className="w-4 h-4 fill-current" /> : <Play className="w-4 h-4 fill-current" />}
                      {sched.active ? 'Mettre en pause' : 'Reprendre'}
                    </button>
                  </div>
                </div>
              ))
            )}
          </div>
        )}

        {/* Create Modal */}
        {showModal && (
          <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/60 backdrop-blur-sm">
            <div className="bg-slate-900 border border-slate-700 rounded-2xl p-6 w-full max-w-md shadow-2xl relative">
              <button onClick={() => setShowModal(false)} className="absolute top-4 right-4 text-slate-500 hover:text-white">
                X
              </button>
              
              <h2 className="text-xl font-black text-white mb-6 flex items-center gap-2">
                <Plus className="w-5 h-5 text-brand-400" />
                Nouvelle Planification
              </h2>
              
              <div className="space-y-4 mb-8">
                <div>
                  <label className="block text-xs font-bold text-slate-500 uppercase tracking-widest mb-2">Source / Cible</label>
                  <select 
                    value={newSource} 
                    onChange={(e) => setNewSource(e.target.value)}
                    className="w-full bg-slate-800 border border-slate-700 text-white rounded-xl px-4 py-3 text-sm focus:outline-none focus:border-brand-500"
                  >
                    {SOURCES.map(s => <option key={s.name} value={s.name}>{s.label}</option>)}
                  </select>
                </div>

                <div>
                  <label className="block text-xs font-bold text-slate-500 uppercase tracking-widest mb-2">Étape du Pipeline</label>
                  <select 
                    value={newStep} 
                    onChange={(e) => setNewStep(e.target.value)}
                    className="w-full bg-slate-800 border border-slate-700 text-white rounded-xl px-4 py-3 text-sm focus:outline-none focus:border-brand-500"
                  >
                    {STEPS.map(s => <option key={s.name} value={s.name}>{s.name}</option>)}
                  </select>
                </div>
                
                <div>
                  <label className="block text-xs font-bold text-slate-500 uppercase tracking-widest mb-2">Intervalle (minutes)</label>
                  <select 
                    value={newInterval} 
                    onChange={(e) => setNewInterval(Number(e.target.value))}
                    className="w-full bg-slate-800 border border-slate-700 text-white rounded-xl px-4 py-3 text-sm focus:outline-none focus:border-brand-500"
                  >
                    <option value={5}>Toutes les 5 minutes (Test)</option>
                    <option value={10}>Toutes les 10 minutes</option>
                    <option value={30}>Toutes les 30 minutes</option>
                    <option value={60}>Toutes les heures (1h)</option>
                    <option value={360}>Toutes les 6 heures (6h)</option>
                    <option value={720}>Toutes les 12 heures (12h)</option>
                    <option value={1440}>Tous les jours (24h)</option>
                  </select>
                </div>
              </div>
              
              <div className="flex gap-3">
                <button 
                  onClick={() => setShowModal(false)}
                  className="flex-1 py-3 bg-slate-800 hover:bg-slate-700 text-slate-300 font-bold rounded-xl transition-colors"
                >
                  Annuler
                </button>
                <button 
                  onClick={handleCreate}
                  disabled={isCreating}
                  className="flex-1 py-3 bg-brand-600 hover:bg-brand-500 text-white font-bold rounded-xl shadow-lg transition-colors flex items-center justify-center gap-2 disabled:opacity-50"
                >
                  {isCreating ? <Loader2 className="w-5 h-5 animate-spin" /> : "Créer"}
                </button>
              </div>
            </div>
          </div>
        )}
      </div>
    </div>
  );
}
