import React, { useState, useEffect } from 'react';
import axios from 'axios';
import { 
  Shield, Search, Filter, Calendar, Tag, ChevronDown, ChevronUp, 
  AlertTriangle, CheckCircle, Info, ExternalLink, Globe, Hash, Server, 
  MapPin, Activity, Zap, Share2, Box, Code, Layers, Database, FileText
} from 'lucide-react';

const API_BASE = `http://${window.location.hostname}:8000`;

const PRIORITY_COLORS = {
  CRITICAL: 'bg-red-500/20 text-red-400 border-red-500/40',
  HIGH:     'bg-orange-500/20 text-orange-400 border-orange-500/40',
  MEDIUM:   'bg-yellow-500/20 text-yellow-400 border-yellow-500/40',
  LOW:      'bg-blue-500/20 text-blue-400 border-blue-500/40',
};

const ATTRIBUTE_ICONS = {
  ip:     Server,
  domain: Globe,
  url:    Globe,
  md5:    Hash,
  sha1:   Hash,
  sha256: Hash,
  cve:    AlertTriangle,
};

function CorrelatedEvents() {
  const [events, setEvents] = useState([]);
  const [loading, setLoading] = useState(true);
  const [search, setSearch] = useState('');
  const [priority, setPriority] = useState('');
  const [expandedEvent, setExpandedEvent] = useState(null);
  const [viewMode, setViewMode] = useState('events'); // 'events' or 'stix'
  const [stixData, setStixData] = useState({ objects: [] });
  const [stixLoading, setStixLoading] = useState(false);
  const [bulletinLoading, setBulletinLoading] = useState(false);

  useEffect(() => {
    fetchEvents();
  }, [priority]);

  useEffect(() => {
    if (viewMode === 'stix') {
      fetchStix();
    }
  }, [viewMode]);

  const fetchStix = async () => {
    setStixLoading(true);
    try {
      const res = await axios.get(`${API_BASE}/api/stix/data`);
      setStixData(res.data);
    } catch (err) {
      console.error("Failed to fetch STIX data", err);
    } finally {
      // Small delay to ensure smooth transition
      setTimeout(() => setStixLoading(false), 500);
    }
  };

  const generateBulletin = async () => {
    setBulletinLoading(true);
    try {
      const res = await axios.post(`${API_BASE}/api/generate-stix-bulletin`);
      if (res.data.status === "success") {
        window.open(`${API_BASE}${res.data.url}`, '_blank');
      } else {
        alert("Erreur: " + res.data.message);
      }
    } catch (e) {
      console.error("Bulletin error:", e);
      alert("Erreur lors de la génération du bulletin");
    } finally {
      setBulletinLoading(false);
    }
  };

  const fetchEvents = async () => {
    setLoading(true);
    try {
      let url = `${API_BASE}/api/correlated/data?limit=100`;
      const params = {};
      if (priority) params.priority = priority;
      if (search) params.search = search;
      
      const res = await axios.get(url, { params });
      setEvents(res.data.data || []);
    } catch (err) {
      console.error("Failed to fetch correlated events", err);
    } finally {
      setLoading(false);
    }
  };

  const toggleEvent = (id) => {
    setExpandedEvent(expandedEvent === id ? null : id);
  };

  return (
    <div className="p-6 max-w-[1600px] mx-auto animate-in fade-in duration-500">
      
      {/* Header */}
      <div className="flex flex-col md:flex-row md:items-center justify-between gap-4 mb-8">
        <div>
          <h1 className="text-3xl font-bold text-white flex items-center gap-3">
            <div className="p-2 bg-indigo-500/20 rounded-xl border border-indigo-500/30">
              <Shield className="w-8 h-8 text-indigo-400" />
            </div>
            Correlated Events
          </h1>
          <p className="text-slate-400 mt-1 ml-14">MISP-ready intelligence grouped by threat campaign and infrastructure</p>
        </div>

        <div className="flex items-center gap-3">
          <div className="flex p-1 bg-slate-900/60 rounded-xl border border-slate-800 mr-4">
             <button 
               onClick={() => setViewMode('events')}
               className={`px-4 py-2 rounded-lg text-xs font-bold transition-all flex items-center gap-2 ${viewMode === 'events' ? 'bg-indigo-600 text-white shadow-lg' : 'text-slate-500 hover:text-slate-300'}`}
             >
               <Layers className="w-3.5 h-3.5" />
               Events
             </button>
             <button 
               onClick={() => setViewMode('stix')}
               className={`px-4 py-2 rounded-lg text-xs font-bold transition-all flex items-center gap-2 ${viewMode === 'stix' ? 'bg-blue-600 text-white shadow-lg' : 'text-slate-500 hover:text-slate-300'}`}
             >
               <Share2 className="w-3.5 h-3.5" />
               STIX Bundle
             </button>
          </div>

          <div className="relative group">
            <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-slate-500 group-focus-within:text-indigo-400 transition-colors" />
            <input 
              type="text" 
              placeholder="Search events, tags, IOCs..." 
              value={search}
              onChange={(e) => setSearch(e.target.value)}
              onKeyDown={(e) => e.key === 'Enter' && fetchEvents()}
              className="bg-slate-900/50 border border-slate-800 rounded-xl pl-10 pr-4 py-2.5 text-sm w-64 focus:outline-none focus:border-indigo-500/50 focus:ring-4 focus:ring-indigo-500/10 transition-all"
            />
          </div>

          <select 
            value={priority}
            onChange={(e) => setPriority(e.target.value)}
            className="bg-slate-900/50 border border-slate-800 rounded-xl px-4 py-2.5 text-sm focus:outline-none focus:border-indigo-500/50 transition-all cursor-pointer"
          >
            <option value="">All Priorities</option>
            <option value="CRITICAL">Critical Only</option>
            <option value="HIGH">High Priority</option>
            <option value="MEDIUM">Medium</option>
            <option value="LOW">Low</option>
          </select>

          <button 
            onClick={fetchEvents}
            title="Refresh Data"
            className="p-2.5 bg-indigo-600/20 hover:bg-indigo-600/40 text-indigo-400 border border-indigo-500/30 rounded-xl transition-all"
          >
            <Activity className="w-5 h-5" />
          </button>

          <button 
            onClick={generateBulletin}
            disabled={bulletinLoading}
            title="Générer Bulletin PDF"
            className={`flex items-center gap-2 px-4 py-2.5 rounded-xl font-bold transition-all shadow-lg active:scale-95 ${
              bulletinLoading 
                ? 'bg-slate-800 text-slate-500 cursor-not-allowed' 
                : 'bg-gradient-to-r from-red-600 to-rose-600 hover:from-red-500 hover:to-rose-500 text-white shadow-red-500/20'
            }`}
          >
            {bulletinLoading ? <Zap className="w-4 h-4 animate-spin" /> : <FileText className="w-4 h-4" />}
            <span>Bulletin</span>
          </button>
        </div>
      </div>

      {/* Events List / STIX View */}
      {viewMode === 'events' ? (
        <div className="space-y-4">
          {loading ? (
            <div className="flex flex-col items-center justify-center py-20 gap-4">
              <div className="w-12 h-12 border-4 border-indigo-500/30 border-t-indigo-500 rounded-full animate-spin" />
              <span className="text-slate-400 font-medium animate-pulse">Correlating Intelligence...</span>
            </div>
          ) : events.length === 0 ? (
            <div className="text-center py-20 bg-slate-900/30 border border-slate-800 rounded-3xl">
              <Info className="w-12 h-12 text-slate-600 mx-auto mb-4" />
              <h3 className="text-xl font-semibold text-slate-300">No correlated events found</h3>
              <p className="text-slate-500 mt-2">Try running the correlation pipeline or adjusting your filters.</p>
            </div>
          ) : (
            events.map(event => (
              <div 
                key={event.group_id}
                className={`bg-slate-950 border border-slate-800/80 rounded-2xl overflow-hidden transition-all duration-300 ${
                  expandedEvent === event.group_id ? 'ring-2 ring-indigo-500/20 shadow-2xl shadow-black' : 'hover:border-slate-700'
                }`}
              >
                {/* Event Header Row */}
                <div 
                  onClick={() => toggleEvent(event.group_id)}
                  className="flex items-center gap-4 p-4 cursor-pointer select-none"
                >
                  <div className={`px-3 py-1 rounded-full text-[10px] font-bold border ${PRIORITY_COLORS[event.priority_score] || PRIORITY_COLORS.LOW}`}>
                    {event.priority_score}
                  </div>

                  <div className="flex-1 min-w-0">
                    <h3 className="text-sm font-bold text-slate-100 truncate flex items-center gap-2">
                      {event.event_name}
                      <span className="text-[10px] font-normal text-slate-500 bg-slate-900 px-2 py-0.5 rounded border border-slate-800 uppercase tracking-wider">
                        {event.attack_type || event.event_type}
                      </span>
                    </h3>
                    <div className="flex items-center gap-4 mt-1">
                      <span className="text-xs text-slate-500 flex items-center gap-1">
                        <Hash className="w-3 h-3" /> {event.group_id}
                      </span>
                      <span className="text-xs text-slate-500 flex items-center gap-1">
                        <Calendar className="w-3 h-3" /> {new Date(event.last_seen).toLocaleString()}
                      </span>
                      <span className="text-xs text-slate-500 flex items-center gap-1">
                        <Zap className="w-3 h-3 text-amber-500" /> Score: {event.risk_score}/100
                      </span>
                    </div>
                  </div>

                  {/* Sources & Tags Summary */}
                  <div className="hidden lg:flex items-center gap-2 max-w-[400px] overflow-hidden">
                    {event.source_list?.slice(0, 3).map(src => (
                      <span key={src} className="text-[10px] text-slate-400 bg-slate-900 px-2 py-1 rounded border border-slate-800 whitespace-nowrap">
                        {src}
                      </span>
                    ))}
                    {event.tags?.slice(0, 2).map(tag => (
                      <span key={tag} className="text-[10px] text-emerald-400 bg-emerald-500/10 px-2 py-1 rounded border border-emerald-500/20 whitespace-nowrap">
                        {tag}
                      </span>
                    ))}
                  </div>

                  <div className="flex items-center gap-4 ml-4">
                    <div className="text-right">
                      <div className="text-xs font-bold text-slate-300">{event.iocs?.length || 0} Attributes</div>
                      <div className="text-[10px] text-slate-500">{event.relations?.length || 0} Relations</div>
                    </div>
                    {expandedEvent === event.group_id ? <ChevronUp className="w-5 h-5 text-slate-500" /> : <ChevronDown className="w-5 h-5 text-slate-500" />}
                  </div>
                </div>

                {/* Expanded Content */}
                {expandedEvent === event.group_id && (
                  <div className="border-t border-slate-800/80 bg-slate-900/20 p-6 animate-in slide-in-from-top duration-300">
                    
                    <div className="grid grid-cols-1 xl:grid-cols-3 gap-8">
                      
                      {/* Left: Metadata & Context */}
                      <div className="space-y-6">
                        <section>
                          <h4 className="text-xs font-bold text-slate-500 uppercase tracking-widest mb-3 flex items-center gap-2">
                            <Info className="w-3 h-3" /> Event Details
                          </h4>
                          <div className="bg-slate-900/50 rounded-xl p-4 border border-slate-800 space-y-3">
                            <DetailRow label="Threat Type" value={event.threat_type} />
                            <DetailRow label="Attack Type" value={event.attack_type} />
                            <DetailRow label="SOC Action" value={event.soc_action} highlight />
                            <DetailRow label="Confidence" value={`${event.confidence_score}%`} />
                            <DetailRow label="Correlation" value={`${event.correlation_strength} connections`} />
                          </div>
                        </section>

                        <section>
                          <h4 className="text-xs font-bold text-slate-500 uppercase tracking-widest mb-3 flex items-center gap-2">
                            <Tag className="w-3 h-3" /> Classification Tags
                          </h4>
                          <div className="flex flex-wrap gap-2">
                            {event.tags?.map(tag => (
                              <span key={tag} className="text-xs text-indigo-300 bg-indigo-500/10 px-3 py-1.5 rounded-lg border border-indigo-500/20">
                                {tag}
                              </span>
                            ))}
                          </div>
                        </section>

                        {event.mitre_techniques?.length > 0 && (
                          <section>
                            <h4 className="text-xs font-bold text-slate-500 uppercase tracking-widest mb-3 flex items-center gap-2">
                              <Activity className="w-3 h-3" /> MITRE ATT&CK
                            </h4>
                            <div className="flex flex-wrap gap-2">
                              {event.mitre_techniques.map(tech => (
                                <span key={tech} className="text-xs text-amber-400 bg-amber-500/10 px-3 py-1.5 rounded-lg border border-amber-500/20 font-mono">
                                  {tech}
                                </span>
                              ))}
                            </div>
                          </section>
                        )}
                      </div>

                      {/* Middle & Right: Attributes (IOCs) */}
                      <div className="xl:col-span-2">
                        <h4 className="text-xs font-bold text-slate-500 uppercase tracking-widest mb-3 flex items-center gap-2">
                          <Shield className="w-3 h-3" /> Attributes (IOCs)
                        </h4>
                        <div className="bg-slate-950 border border-slate-800 rounded-xl overflow-hidden">
                          <table className="w-full text-left border-collapse">
                            <thead>
                              <tr className="bg-slate-900/80 text-[10px] font-bold text-slate-500 uppercase">
                                <th className="px-4 py-3">Type</th>
                                <th className="px-4 py-3">Value</th>
                                <th className="px-4 py-3">Risk</th>
                                <th className="px-4 py-3 text-right">Action</th>
                              </tr>
                            </thead>
                            <tbody className="divide-y divide-slate-800/50">
                              {event.iocs?.map((ioc, idx) => {
                                const Icon = ATTRIBUTE_ICONS[ioc.type] || Info;
                                return (
                                  <tr key={idx} className="hover:bg-slate-900/30 transition-colors group">
                                    <td className="px-4 py-3">
                                      <div className="flex items-center gap-2 text-xs text-slate-400">
                                        <Icon className="w-3 h-3 text-slate-500" />
                                        {ioc.type.toUpperCase()}
                                      </div>
                                    </td>
                                    <td className="px-4 py-3">
                                      <div className="text-xs font-mono text-slate-200 break-all max-w-[400px]">
                                        {ioc.value}
                                      </div>
                                    </td>
                                    <td className="px-4 py-3">
                                      <div className={`inline-flex items-center px-2 py-0.5 rounded text-[10px] font-bold ${
                                        ioc.risk_score > 70 ? 'bg-red-500/10 text-red-400' :
                                        ioc.risk_score > 40 ? 'bg-orange-500/10 text-orange-400' :
                                        'bg-blue-500/10 text-blue-400'
                                      }`}>
                                        {ioc.risk_score}
                                      </div>
                                    </td>
                                    <td className="px-4 py-3 text-right">
                                      <button className="p-1.5 opacity-0 group-hover:opacity-100 transition-opacity hover:bg-indigo-500/20 rounded-lg text-indigo-400">
                                        <ExternalLink className="w-3.5 h-3.5" />
                                      </button>
                                    </td>
                                  </tr>
                                );
                              })}
                            </tbody>
                          </table>
                        </div>
                        
                        {/* Relations Footer */}
                        {event.relations?.length > 0 && (
                          <div className="mt-4 p-4 bg-slate-900/30 rounded-xl border border-dashed border-slate-800">
                             <div className="text-[10px] font-bold text-slate-500 uppercase mb-2">Internal Relationships Graph</div>
                             <div className="flex flex-wrap gap-x-6 gap-y-2">
                               {event.relations.map((rel, idx) => (
                                 <div key={idx} className="text-[10px] flex items-center gap-2">
                                   <span className="text-slate-400 truncate max-w-[100px]">{rel.source}</span>
                                   <span className="text-indigo-500 font-bold px-1.5 py-0.5 bg-indigo-500/10 rounded">→ {rel.type} →</span>
                                   <span className="text-slate-400 truncate max-w-[100px]">{rel.target}</span>
                                 </div>
                               ))}
                             </div>
                          </div>
                        )}
                      </div>

                    </div>
                  </div>
                )}
              </div>
            ))
          )}
        </div>
      ) : (
        <div className="space-y-10 animate-in slide-in-from-right duration-500 pb-20">
          {/* STIX Bundle Header Cards */}
          <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
             <div className="bg-slate-900/40 border border-blue-500/20 rounded-2xl p-4">
                <div className="text-[10px] font-black text-blue-400 uppercase tracking-widest mb-1">Bundle Type</div>
                <div className="text-lg font-bold text-white uppercase">{stixData.type || 'N/A'}</div>
             </div>
             <div className="bg-slate-900/40 border border-purple-500/20 rounded-2xl p-4">
                <div className="text-[10px] font-black text-purple-400 uppercase tracking-widest mb-1">STIX Version</div>
                <div className="text-lg font-bold text-white uppercase">{stixData.spec_version || '2.1'}</div>
             </div>
             <div className="bg-slate-900/40 border border-emerald-500/20 rounded-2xl p-4">
                <div className="text-[10px] font-black text-emerald-400 uppercase tracking-widest mb-1">Total Objects</div>
                <div className="text-lg font-bold text-white uppercase">{stixData.objects?.length || 0}</div>
             </div>
             <div className="bg-slate-900/40 border border-amber-500/20 rounded-2xl p-4">
                <div className="text-[10px] font-black text-amber-400 uppercase tracking-widest mb-1">Producer</div>
                <div className="text-lg font-bold text-white uppercase">CTI Pipeline</div>
             </div>
          </div>

          {/* Grouped by MISP-like Events (STIX Reports) */}
          <div className="space-y-8">
            {stixLoading ? (
               <div className="flex flex-col items-center justify-center py-20 gap-4">
                 <div className="w-12 h-12 border-4 border-blue-500/30 border-t-blue-500 rounded-full animate-spin" />
                 <span className="text-slate-400 font-medium">Parsing STIX Bundle...</span>
               </div>
            ) : stixData.objects?.filter(o => o.type === 'report').length === 0 ? (
               <div className="text-center py-20 bg-slate-900/30 border border-slate-800 rounded-3xl">
                  <Box className="w-12 h-12 text-slate-700 mx-auto mb-4" />
                  <p className="text-slate-500">No reports found in this bundle. Run the exporter first.</p>
               </div>
            ) : (
              stixData.objects.filter(o => o.type === 'report').map(report => {
                // Find all objects referenced by this report
                const relatedObjects = stixData.objects.filter(obj => 
                   report.object_refs?.includes(obj.id) && obj.type !== 'report'
                );

                return (
                  <div key={report.id} className="bg-slate-950 border border-slate-800 rounded-3xl overflow-hidden shadow-2xl">
                    {/* MISP Event Header Style */}
                    <div className="p-6 bg-slate-900/60 border-b border-slate-800">
                      <div className="flex items-start justify-between">
                        <div className="space-y-2">
                          <div className="flex items-center gap-3">
                             <div className="p-2 bg-blue-500/20 rounded-lg border border-blue-500/30">
                               <Database className="w-5 h-5 text-blue-400" />
                             </div>
                             <h3 className="text-xl font-bold text-white">
                                {report.name}
                             </h3>
                          </div>
                          <div className="flex items-center gap-4 text-xs text-slate-500">
                             <span className="flex items-center gap-1"><Calendar className="w-3.5 h-3.5" /> Published: {new Date(report.published).toLocaleString()}</span>
                             <span className="flex items-center gap-1"><Hash className="w-3.5 h-3.5" /> UUID: {report.id}</span>
                          </div>
                        </div>
                        <div className="flex flex-wrap gap-2 justify-end max-w-[400px]">
                          {report.labels?.map(label => (
                            <span key={label} className="px-2.5 py-1 rounded-md text-[10px] font-bold bg-indigo-500/10 text-indigo-400 border border-indigo-500/20 uppercase tracking-tighter">
                              {label}
                            </span>
                          ))}
                        </div>
                      </div>
                      
                      {report.description && (
                         <div className="mt-4 p-3 bg-slate-900/40 rounded-xl border border-slate-800/50 text-[11px] text-slate-400 font-mono leading-relaxed whitespace-pre-wrap">
                            {report.description}
                         </div>
                      )}
                    </div>

                    {/* Attributes Table (MISP Style) */}
                    <div className="overflow-x-auto">
                      <table className="w-full text-left">
                        <thead className="bg-slate-900/30 text-[10px] font-black uppercase tracking-widest text-slate-500 border-b border-slate-800">
                          <tr>
                            <th className="px-6 py-4">Category / Type</th>
                            <th className="px-6 py-4">Value / Pattern</th>
                            <th className="px-6 py-4">Relationship / Details</th>
                            <th className="px-6 py-4 text-right">Raw</th>
                          </tr>
                        </thead>
                        <tbody className="divide-y divide-slate-800/50">
                          {relatedObjects.map(obj => (
                            <tr key={obj.id} className="hover:bg-white/[0.02] transition-colors group">
                              <td className="px-6 py-4">
                                <div className="flex flex-col gap-1">
                                  <span className={`w-fit px-2 py-0.5 rounded text-[9px] font-black uppercase ${
                                    obj.type === 'malware' ? 'bg-pink-500/10 text-pink-400' :
                                    obj.type === 'indicator' ? 'bg-blue-500/10 text-blue-400' :
                                    obj.type === 'relationship' ? 'bg-amber-500/10 text-amber-400' :
                                    obj.type === 'attack-pattern' ? 'bg-emerald-500/10 text-emerald-400' :
                                    'bg-slate-500/10 text-slate-400'
                                  }`}>
                                    {obj.type}
                                  </span>
                                  <span className="text-[10px] text-slate-500 font-mono">
                                     {obj.indicator_types?.[0] || obj.malware_types?.[0] || 'attribute'}
                                  </span>
                                </div>
                              </td>
                              <td className="px-6 py-4">
                                <div className="text-xs font-bold text-slate-200">
                                  {obj.name || obj.pattern || obj.relationship_type || obj.external_references?.[0]?.external_id}
                                </div>
                                <div className="text-[9px] font-mono text-slate-600 mt-0.5 truncate max-w-[250px]">
                                  {obj.id}
                                </div>
                              </td>
                              <td className="px-6 py-4">
                                <div className="text-[10px] text-slate-500 leading-relaxed max-w-[400px]">
                                  {obj.description ? (
                                    <div className="line-clamp-2 hover:line-clamp-none transition-all">
                                       {obj.description}
                                    </div>
                                  ) : (
                                    <span className="italic opacity-50">No additional details</span>
                                  )}
                                </div>
                                {obj.external_references?.length > 0 && (
                                   <div className="flex gap-2 mt-1">
                                      {obj.external_references.slice(0,2).map((ref, i) => (
                                         <span key={i} className="text-[9px] text-emerald-500/70 border border-emerald-500/20 px-1 rounded">
                                            {ref.source_name}: {ref.external_id || 'link'}
                                         </span>
                                      ))}
                                   </div>
                                )}
                              </td>
                              <td className="px-6 py-4 text-right">
                                <button className="p-1.5 hover:bg-slate-800 rounded-lg text-slate-500 hover:text-white transition-colors">
                                  <Code className="w-3.5 h-3.5" />
                                </button>
                              </td>
                            </tr>
                          ))}
                        </tbody>
                      </table>
                    </div>
                  </div>
                );
              })
            )}
          </div>
        </div>
      )}
    </div>
  );
}

function DetailRow({ label, value, highlight }) {
  return (
    <div className="flex items-center justify-between text-xs">
      <span className="text-slate-500">{label}</span>
      <span className={`font-semibold ${highlight ? 'text-indigo-400' : 'text-slate-300'}`}>
        {value || 'N/A'}
      </span>
    </div>
  );
}

export default CorrelatedEvents;
