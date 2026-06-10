import React, { useState } from 'react';
import axios from 'axios';
import { Upload, FileText, Cpu, AlertCircle, Loader2, CheckCircle, ShieldAlert, TableProperties } from 'lucide-react';
import CSVReader from './CSVReader';

const API_BASE = `http://${window.location.hostname}:8000`;

const CSVAnalyzer = ({ onBack }) => {
  const [file, setFile] = useState(null);
  const [uploading, setUploading] = useState(false);
  const [analyzing, setAnalyzing] = useState(false);
  const [error, setError] = useState(null);
  const [uploadedPath, setUploadedPath] = useState(null);
  const [report, setReport] = useState(null);
  const [showReader, setShowReader] = useState(false);

  const handleFileChange = (e) => {
    if (e.target.files && e.target.files[0]) {
      setFile(e.target.files[0]);
      setError(null);
      setUploadedPath(null);
      setReport(null);
    }
  };

  const handleUpload = async () => {
    if (!file) return;
    setUploading(true);
    setError(null);
    
    const formData = new FormData();
    formData.append("file", file);

    try {
      const res = await axios.post(`${API_BASE}/api/leaks/csv/upload`, formData, {
        headers: { "Content-Type": "multipart/form-data" }
      });
      setUploadedPath(res.data.path);
    } catch (e) {
      setError(e.response?.data?.detail || "Erreur lors de l'upload du fichier");
    } finally {
      setUploading(false);
    }
  };

  const handleAnalyze = async () => {
    if (!uploadedPath) return;
    setAnalyzing(true);
    setError(null);
    
    try {
      const res = await axios.post(`${API_BASE}/api/leaks/csv/analyze?path=${encodeURIComponent(uploadedPath)}`);
      setReport(res.data.analysis);
    } catch (e) {
      setError(e.response?.data?.detail || "Erreur lors de l'analyse IA");
    } finally {
      setAnalyzing(false);
    }
  };

  const renderSeverity = (severity) => {
    const colors = {
      low: "bg-blue-500/20 text-blue-400 border-blue-500/50",
      medium: "bg-yellow-500/20 text-yellow-400 border-yellow-500/50",
      high: "bg-orange-500/20 text-orange-400 border-orange-500/50",
      critical: "bg-red-500/20 text-red-400 border-red-500/50"
    };
    const c = colors[severity?.toLowerCase()] || colors.low;
    return (
      <span className={`px-3 py-1 rounded-full text-xs font-black uppercase tracking-wider border ${c}`}>
        {severity || "Inconnu"}
      </span>
    );
  };

  if (showReader && uploadedPath) {
    return (
      <CSVReader 
        filePath={uploadedPath} 
        onBack={() => setShowReader(false)} 
      />
    );
  }

  return (
    <div className="min-h-screen bg-transparent text-slate-200 p-8 relative overflow-hidden">
      {/* Background Glows */}
      <div className="absolute top-0 left-1/4 w-[500px] h-[500px] bg-brand-500/10 blur-[150px] rounded-full pointer-events-none" />
      <div className="absolute bottom-0 right-1/4 w-[500px] h-[500px] bg-purple-500/10 blur-[150px] rounded-full pointer-events-none" />
      
      <div className="max-w-4xl mx-auto relative z-10">
        
        {/* Header */}
        <div className="flex items-center gap-4 mb-8">
          {onBack && (
            <button
              onClick={onBack}
              className="p-2 hover:bg-white/5 rounded-xl text-slate-400 hover:text-white transition-all border border-white/5"
            >
              ← Retour
            </button>
          )}
          <div>
            <h1 className="text-3xl font-black text-white flex items-center gap-3">
              <FileText className="w-8 h-8 text-brand-400" />
              Analyse de Fichiers CSV
            </h1>
            <p className="text-slate-500 text-sm mt-1">Uploadez un fichier et laissez l'IA générer un rapport de gravité.</p>
          </div>
        </div>

        {error && (
          <div className="mb-6 p-4 bg-red-500/10 border border-red-500/50 rounded-2xl flex items-center gap-3 text-red-400">
            <AlertCircle className="w-5 h-5 flex-shrink-0" />
            <p className="text-sm">{error}</p>
          </div>
        )}

        <div className="grid grid-cols-1 md:grid-cols-2 gap-8">
          {/* Upload Section */}
          <div className="bg-slate-900/60 border border-white/10 rounded-3xl p-8 backdrop-blur-xl shadow-2xl flex flex-col items-center justify-center text-center">
            <div className="w-20 h-20 rounded-full bg-brand-500/20 flex items-center justify-center mb-6">
              <Upload className="w-10 h-10 text-brand-400" />
            </div>
            
            <h2 className="text-xl font-bold text-white mb-2">Uploader un CSV</h2>
            <p className="text-slate-500 text-xs mb-6 max-w-xs">Sélectionnez un fichier .csv ou .txt contenant des données suspectes.</p>

            <label className="cursor-pointer px-6 py-3 bg-slate-800 hover:bg-slate-700 border border-white/10 rounded-xl text-sm font-bold transition-all w-full max-w-xs block">
              Choisir un fichier
              <input type="file" accept=".csv,.txt" className="hidden" onChange={handleFileChange} />
            </label>

            {file && (
              <div className="mt-4 w-full max-w-xs text-left p-4 bg-black/40 rounded-xl border border-white/5">
                <p className="text-sm text-brand-300 font-mono truncate">{file.name}</p>
                <p className="text-xs text-slate-500 mt-1">{(file.size / 1024).toFixed(1)} KB</p>
              </div>
            )}

            <button
              onClick={handleUpload}
              disabled={!file || uploading || uploadedPath}
              className="mt-6 px-6 py-3 w-full max-w-xs bg-brand-600 hover:bg-brand-500 disabled:bg-slate-800 disabled:text-slate-500 text-white rounded-xl text-xs font-black uppercase tracking-wider transition-all shadow-lg flex items-center justify-center gap-2"
            >
              {uploading ? <Loader2 className="w-4 h-4 animate-spin" /> : uploadedPath ? <CheckCircle className="w-4 h-4" /> : <Upload className="w-4 h-4" />}
              {uploading ? "Upload en cours..." : uploadedPath ? "Fichier Uploadé" : "Uploader"}
            </button>

            {uploadedPath && (
              <button
                onClick={() => setShowReader(true)}
                className="mt-3 px-6 py-3 w-full max-w-xs bg-slate-800 hover:bg-slate-700 text-brand-300 rounded-xl text-xs font-black uppercase tracking-wider transition-all border border-brand-500/20 flex items-center justify-center gap-2"
              >
                <TableProperties className="w-4 h-4" />
                Voir les données (Séparateurs)
              </button>
            )}
          </div>

          {/* Analysis Section */}
          <div className="bg-slate-900/60 border border-white/10 rounded-3xl p-8 backdrop-blur-xl shadow-2xl flex flex-col items-center justify-center text-center">
            <div className="w-20 h-20 rounded-full bg-purple-500/20 flex items-center justify-center mb-6">
              <Cpu className="w-10 h-10 text-purple-400" />
            </div>
            
            <h2 className="text-xl font-bold text-white mb-2">Analyser avec l'IA</h2>
            <p className="text-slate-500 text-xs mb-6 max-w-xs">L'IA va scanner un échantillon pour détecter les fuites et évaluer la gravité.</p>

            <button
              onClick={handleAnalyze}
              disabled={!uploadedPath || analyzing}
              className="px-6 py-4 w-full max-w-xs bg-purple-600 hover:bg-purple-500 disabled:bg-slate-800 disabled:text-slate-500 text-white rounded-2xl text-sm font-black uppercase tracking-wider transition-all shadow-[0_0_20px_rgba(168,85,247,0.4)] disabled:shadow-none flex items-center justify-center gap-3"
            >
              {analyzing ? <Loader2 className="w-5 h-5 animate-spin" /> : <Cpu className="w-5 h-5" />}
              {analyzing ? "Analyse en cours..." : "Analyser AI"}
            </button>
          </div>
        </div>

        {/* Report Section */}
        {report && (
          <div className="mt-8 bg-slate-900/80 border border-purple-500/30 rounded-3xl p-8 backdrop-blur-xl shadow-[0_0_30px_rgba(168,85,247,0.15)] animate-in slide-in-from-bottom-4">
            <div className="flex flex-col md:flex-row md:items-start justify-between gap-6 mb-8 border-b border-white/10 pb-6">
              <div>
                <h3 className="text-2xl font-black text-white mb-2">
                  Rapport d'Intelligence
                </h3>
                <p className="text-slate-400 font-mono text-sm">{file?.name}</p>
              </div>
              <div className="flex flex-col items-end gap-2">
                <span className="text-slate-500 text-xs uppercase tracking-widest font-black">Niveau de Gravité</span>
                {renderSeverity(report.severity)}
              </div>
            </div>

            <div className="grid grid-cols-1 md:grid-cols-2 gap-8">
              <div>
                <h4 className="text-slate-500 text-xs uppercase tracking-widest font-black mb-3">Résumé de l'IA</h4>
                <p className="text-slate-300 leading-relaxed text-sm bg-black/40 p-5 rounded-2xl border border-white/5 shadow-inner">
                  {report.summary || "Aucun résumé généré."}
                </p>
              </div>

              <div className="space-y-6">
                <div>
                  <h4 className="text-slate-500 text-xs uppercase tracking-widest font-black mb-3">Détails Techniques</h4>
                  <div className="bg-black/40 p-5 rounded-2xl border border-white/5 space-y-3">
                    <div className="flex justify-between items-center">
                      <span className="text-slate-400 text-xs">Type de fuite</span>
                      <span className="text-brand-300 font-mono text-sm">{report.leak_type || "N/A"}</span>
                    </div>
                    <div className="w-full h-px bg-white/5" />
                    <div className="flex justify-between items-center">
                      <span className="text-slate-400 text-xs">Confiance IA</span>
                      <span className="text-purple-300 font-mono text-sm">{report.confidence ? `${report.confidence}%` : "N/A"}</span>
                    </div>
                    <div className="w-full h-px bg-white/5" />
                    <div className="flex justify-between items-center">
                      <span className="text-slate-400 text-xs">Fuite confirmée</span>
                      <span className={report.is_leak ? "text-red-400 font-bold" : "text-emerald-400 font-bold"}>
                        {report.is_leak ? "OUI" : "NON"}
                      </span>
                    </div>
                  </div>
                </div>

                {report.targets && report.targets.length > 0 && (
                  <div>
                    <h4 className="text-slate-500 text-xs uppercase tracking-widest font-black mb-3">Cibles Identifiées</h4>
                    <div className="flex flex-wrap gap-2">
                      {report.targets.map((target, idx) => (
                         <span key={idx} className="px-3 py-1 bg-red-500/10 border border-red-500/30 text-red-400 rounded-lg text-xs font-mono">
                           {target}
                         </span>
                      ))}
                    </div>
                  </div>
                )}
              </div>
            </div>
          </div>
        )}
      </div>
    </div>
  );
};

export default CSVAnalyzer;
