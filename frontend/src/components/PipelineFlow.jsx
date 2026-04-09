import React from 'react';
import { CheckCircle2, Circle, Loader2, XCircle } from 'lucide-react';

const steps = [
  "Source détectée",
  "Collecte en cours",
  "Collecte terminée",
  "Extraction IOC",
  "Extraction CVE",
  "Validation",
  "Stockage des résultats",
  "Étape terminée / prête pour la suite"
];

const StatusIcon = ({ status }) => {
  switch (status) {
    case 'success':
      return <CheckCircle2 className="w-6 h-6 text-green-500" />;
    case 'failed':
      return <XCircle className="w-6 h-6 text-red-500" />;
    case 'running':
      return <Loader2 className="w-6 h-6 text-blue-500 animate-spin" />;
    default:
      return <Circle className="w-6 h-6 text-slate-400" />;
  }
};

const PipelineFlow = ({ currentSteps = [] }) => {
  return (
    <div className="flex flex-col space-y-4 w-full max-w-2xl mx-auto p-6 bg-slate-900/50 rounded-xl border border-slate-800 backdrop-blur-sm">
      <h2 className="text-xl font-bold text-white mb-4">Pipeline Status</h2>
      <div className="relative">
        {/* Progress Line */}
        <div className="absolute left-3 top-0 bottom-0 w-0.5 bg-slate-800" />
        
        <div className="space-y-6">
          {steps.map((stepName, index) => {
            const stepData = currentSteps.find(s => s.step_name === stepName) || { status: 'pending' };
            return (
              <div key={index} className="flex items-start space-x-4 relative z-10 group">
                <div className="bg-slate-900 rounded-full p-1">
                  <StatusIcon status={stepData.status} />
                </div>
                <div className="flex-1 pt-1">
                  <div className="flex justify-between items-center">
                    <h3 className={`font-medium ${stepData.status !== 'pending' ? 'text-white' : 'text-slate-500'}`}>
                      {stepName}
                    </h3>
                    {stepData.status === 'success' && (
                      <span className="text-xs text-slate-400">
                        {stepData.duration ? `${stepData.duration}s` : ''}
                      </span>
                    )}
                  </div>
                  {stepData.status === 'running' && (
                    <div className="mt-2 w-full bg-slate-800 h-1 rounded-full overflow-hidden">
                      <div className="bg-blue-500 h-full animate-pulse" style={{ width: '60%' }} />
                    </div>
                  )}
                  {(stepData.ioc_count > 0 || stepData.cve_count > 0) && (
                    <div className="mt-1 flex space-x-3 text-xs">
                      {stepData.ioc_count > 0 && (
                        <span className="px-2 py-0.5 bg-blue-500/10 text-blue-400 rounded-full border border-blue-500/20">
                          {stepData.ioc_count} IOCs
                        </span>
                      )}
                      {stepData.cve_count > 0 && (
                        <span className="px-2 py-0.5 bg-purple-500/10 text-purple-400 rounded-full border border-purple-500/20">
                          {stepData.cve_count} CVEs
                        </span>
                      )}
                    </div>
                  )}
                  {stepData.error_message && (
                    <p className="mt-1 text-xs text-red-400 bg-red-400/10 p-2 rounded border border-red-400/20">
                      {stepData.error_message}
                    </p>
                  )}
                </div>
              </div>
            );
          })}
        </div>
      </div>
    </div>
  );
};

export default PipelineFlow;
