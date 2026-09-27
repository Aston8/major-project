import React, { useState } from 'react';
import { X, Globe, Eye, FileText, Layers, ShieldAlert, CheckCircle2, AlertTriangle, HelpCircle } from 'lucide-react';
import ThreatBadge from './ThreatBadge';
import ThreatScore from './ThreatScore';
import SandboxBrowser from './SandboxBrowser';

export const InvestigationDetailModal = ({ investigation, onClose }) => {
  if (!investigation) return null;

  const [activeTab, setActiveTab] = useState('overview');

  const hasSandbox = Boolean(investigation.sandboxData && (investigation.sandboxData.url || investigation.type === 'url' || investigation.type === 'sandbox'));

  const tabs = [
    { id: 'overview', label: 'Verdict & Summary', icon: Eye },
    { id: 'evidence', label: 'Evidence Findings', icon: FileText },
    ...(hasSandbox ? [{ id: 'sandbox', label: 'Sandbox Telemetry', icon: Globe }] : [])
  ];

  return (
    <div className="fixed inset-0 z-50 bg-black/60 backdrop-blur-xs flex items-center justify-center p-4 md:p-8 overflow-y-auto">
      <div 
        className="w-full max-w-4xl bg-white border border-[#E5E5E5] rounded-2xl shadow-2xl overflow-hidden my-auto max-h-[90vh] flex flex-col font-sans"
        onClick={(e) => e.stopPropagation()}
      >
        {/* Modal Header */}
        <div className="p-6 bg-[#111111] text-white border-b border-[#262626] flex items-center justify-between shrink-0 font-mono">
          <div className="flex items-center gap-4">
            <div className="w-10 h-10 rounded-xl bg-white/10 text-white font-bold flex items-center justify-center text-sm border border-white/20">
              ◈
            </div>
            <div>
              <div className="flex items-center gap-3">
                <span className="text-[#8E8E8E] text-xs font-bold">{investigation.id}</span>
                <ThreatBadge level={investigation.threatLevel} />
                <span className="text-[10px] text-gray-300 uppercase tracking-widest bg-white/10 px-2 py-0.5 rounded">
                  {investigation.vector}
                </span>
              </div>
              <h2 className="text-lg font-bold text-white tracking-tight mt-0.5">
                {investigation.category || investigation.title}
              </h2>
            </div>
          </div>

          <button 
            onClick={onClose}
            className="p-2 text-gray-400 hover:text-white rounded-xl bg-white/5 hover:bg-white/10 transition-colors cursor-pointer"
          >
            <X className="w-5 h-5" />
          </button>
        </div>

        {/* Modal Navigation Tab Bar */}
        <div className="bg-[#F7F7F5] border-b border-[#E5E5E5] px-6 py-2 flex items-center gap-2 overflow-x-auto shrink-0 font-mono text-xs">
          {tabs.map((tab) => {
            const Icon = tab.icon;
            const isActive = activeTab === tab.id;
            return (
              <button
                key={tab.id}
                onClick={() => setActiveTab(tab.id)}
                className={`
                  flex items-center gap-2 px-3.5 py-2 rounded-xl transition-all font-semibold shrink-0 cursor-pointer
                  ${isActive 
                    ? 'bg-[#111111] text-white shadow-sm' 
                    : 'text-[#6B6B6B] hover:text-[#111111] hover:bg-white'
                  }
                `}
              >
                <Icon className="w-4 h-4" />
                <span>{tab.label}</span>
              </button>
            );
          })}
        </div>

        {/* Modal Main Body Scroll Area */}
        <div className="p-6 overflow-y-auto space-y-6 flex-1 bg-[#F7F7F5]">
          {activeTab === 'overview' && (
            <div className="space-y-6 font-mono">
              <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
                {/* Left: Summary & Metadata */}
                <div className="shield-card p-6 md:col-span-2 space-y-4">
                  <div className="text-[10px] font-bold text-[#6B6B6B] uppercase tracking-widest">
                    EXECUTIVE VERDICT EXPLANATION
                  </div>
                  <p className="text-sm text-[#111111] leading-relaxed font-sans">
                    {investigation.explanation || investigation.summary || "Investigation completed."}
                  </p>

                  <div className="pt-4 border-t border-[#E5E5E5] grid grid-cols-2 gap-4 text-xs">
                    <div>
                      <span className="text-[#6B6B6B] block">Timestamp:</span>
                      <strong className="text-[#111111]">{investigation.timestamp}</strong>
                    </div>
                    <div>
                      <span className="text-[#6B6B6B] block">Category:</span>
                      <strong className="text-[#111111]">{investigation.category || investigation.title}</strong>
                    </div>
                  </div>
                </div>

                {/* Right: Score */}
                <div className="shield-card p-6 flex flex-col items-center justify-center text-center space-y-2">
                  <div className="text-[10px] font-bold text-[#6B6B6B] uppercase tracking-widest">
                    RISK SCORE
                  </div>
                  {investigation.score !== null ? (
                    <ThreatScore score={investigation.score} level={investigation.threatLevel} size="lg" />
                  ) : (
                    <div className="py-6 text-[#6B6B6B] font-bold text-lg">
                      INCONCLUSIVE
                    </div>
                  )}
                  <div className="mt-2">
                    <ThreatBadge level={investigation.threatLevel} />
                  </div>
                </div>
              </div>

              {/* Recommended Actions */}
              {Array.isArray(investigation.recommendations) && investigation.recommendations.length > 0 && (
                <div className="shield-card p-6 space-y-3">
                  <div className="text-[10px] font-bold text-[#6B6B6B] uppercase tracking-widest">
                    RECOMMENDED DEFENSIVE ACTIONS
                  </div>
                  <div className="space-y-2 font-sans text-xs">
                    {investigation.recommendations.map((rec, idx) => (
                      <div key={idx} className="flex items-start gap-2.5 p-3 rounded-xl bg-[#F7F7F5] border border-[#E5E5E5]">
                        <span className="w-5 h-5 rounded-full bg-[#111111] text-white flex items-center justify-center text-[10px] font-bold shrink-0 font-mono">
                          {idx + 1}
                        </span>
                        <span className="text-[#111111] font-medium leading-relaxed">{rec}</span>
                      </div>
                    ))}
                  </div>
                </div>
              )}

              {/* Original Target Payload */}
              <div className="shield-card p-6 space-y-3">
                <div className="text-[10px] font-bold text-[#6B6B6B] uppercase tracking-widest">
                  INVESTIGATED TARGET / PAYLOAD
                </div>
                {investigation.originalContent?.text && (
                  <div className="p-4 rounded-xl bg-[#111111] text-gray-200 text-xs font-mono border border-[#262626] whitespace-pre-wrap">
                    {investigation.originalContent.text}
                  </div>
                )}
                {investigation.originalContent?.url && (
                  <div className="text-xs text-[#111111]">
                    URL Analyzed: <strong className="underline">{investigation.originalContent.url}</strong>
                  </div>
                )}
                {investigation.filename && (
                  <div className="text-xs text-[#111111]">
                    File Analyzed: <strong>{investigation.filename}</strong>
                  </div>
                )}
              </div>
            </div>
          )}

          {activeTab === 'evidence' && (
            <div className="space-y-4 font-mono">
              <div className="shield-card p-6 space-y-4">
                <div className="text-[10px] font-bold text-[#6B6B6B] uppercase tracking-widest">
                  BEHAVIORAL EVIDENCE &amp; SIGNALS
                </div>

                {investigation.tacticBreakdown ? (
                  <div className="space-y-3">
                    {Object.entries(investigation.tacticBreakdown).map(([key, val]) => (
                      <div key={key} className="space-y-1">
                        <div className="flex justify-between text-xs">
                          <span className="uppercase text-[#6B6B6B] font-bold">{key.replace(/([A-Z])/g, ' $1')}</span>
                          <span className="font-bold text-[#111111]">{val}%</span>
                        </div>
                        <div className="h-2 bg-[#E5E5E5] rounded-full overflow-hidden">
                          <div
                            className="h-full bg-[#111111] rounded-full transition-all"
                            style={{ width: `${Math.min(100, Math.max(0, val))}%` }}
                          />
                        </div>
                      </div>
                    ))}
                  </div>
                ) : (
                  <p className="text-xs text-[#6B6B6B]">
                    No granular tactic metrics recorded for this scan.
                  </p>
                )}
              </div>

              {Array.isArray(investigation.highlights) && investigation.highlights.length > 0 && (
                <div className="shield-card p-6 space-y-3">
                  <div className="text-[10px] font-bold text-[#6B6B6B] uppercase tracking-widest">
                    DETECTED THREAT HIGHLIGHTS
                  </div>
                  <div className="space-y-2">
                    {investigation.highlights.map((h, i) => (
                      <div key={i} className="p-3 bg-red-50/60 border border-red-200 rounded-xl text-xs text-red-900 font-sans">
                        {typeof h === 'string' ? h : h.text || JSON.stringify(h)}
                      </div>
                    ))}
                  </div>
                </div>
              )}
            </div>
          )}

          {activeTab === 'sandbox' && hasSandbox && (
            <div className="space-y-4 font-mono">
              <SandboxBrowser sandboxData={investigation.sandboxData} />
            </div>
          )}
        </div>

        {/* Modal Footer */}
        <div className="p-4 bg-white border-t border-[#E5E5E5] flex items-center justify-between font-mono text-xs text-[#6B6B6B] shrink-0">
          <span>Dossier ID: <strong>{investigation.id}</strong> | Permanent Intelligence Archive</span>
          <button 
            onClick={onClose}
            className="px-4 py-2 bg-[#111111] text-white rounded-xl font-bold hover:bg-black transition-colors cursor-pointer"
          >
            Close Dossier
          </button>
        </div>
      </div>
    </div>
  );
};

export default InvestigationDetailModal;
