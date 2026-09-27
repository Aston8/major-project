import React, { useState } from 'react';
import { Globe, Lock, ShieldAlert, ArrowRight, Server, FileCode, AlertTriangle, Layers, Terminal, CheckCircle2, ShieldCheck, Copy } from 'lucide-react';
import ThreatBadge from './ThreatBadge';

export const SandboxBrowser = ({ sandboxData = {} }) => {
  const [activeTab, setActiveTab] = useState('summary');

  const url = sandboxData.url || 'Analyzed Target URL';
  const redirects = sandboxData.redirects || sandboxData.redirect_chain?.length || 0;
  const redirectList = sandboxData.redirect_chain || [];
  const networkRequests = sandboxData.networkRequests || sandboxData.network_requests?.length || 0;
  const networkList = sandboxData.network_requests || [];
  const formsDetected = sandboxData.formsDetected ?? sandboxData.detected_forms?.length ?? (sandboxData.forms_count || 0);
  const formsList = sandboxData.detected_forms || [];
  const scriptsExecuted = sandboxData.scriptsExecuted ?? (sandboxData.scripts_count || 0);
  const suspiciousActions = sandboxData.suspiciousActions ?? sandboxData.behavior_findings?.length ?? 0;
  const findings = sandboxData.behavior_findings || sandboxData.behaviorFindings || [];
  const status = sandboxData.status || sandboxData.sandbox_verdict || (suspiciousActions > 0 ? "SUSPICIOUS" : "CLEARED");

  return (
    <div className="shield-card p-6 space-y-6 font-mono">
      {/* Workstation Header */}
      <div className="flex flex-col md:flex-row md:items-center justify-between border-b border-[#E5E5E5] pb-4 gap-4">
        <div>
          <div className="text-[10px] font-mono font-bold tracking-widest text-[#6B6B6B] uppercase flex items-center gap-2">
            <span className="w-2 h-2 rounded-full bg-emerald-500 animate-pulse"></span>
            ISOLATED SANDBOX TELEMETRY
          </div>
          <h2 className="text-xl font-bold tracking-tight text-[#111111] mt-0.5">
            Website Sandbox Telemetry Report
          </h2>
        </div>
        <div className="flex items-center gap-3">
          <span className="text-xs text-[#6B6B6B] bg-[#F7F7F5] px-3 py-1.5 rounded-lg border border-[#E5E5E5] truncate max-w-xs">
            Target: <strong className="text-[#111111]">{url}</strong>
          </span>
          <ThreatBadge level={status === 'CONTAINED' || status === 'SUSPICIOUS' || suspiciousActions > 0 ? 'CRITICAL' : 'SAFE'} />
        </div>
      </div>

      {/* Metric Cards */}
      <div className="grid grid-cols-2 sm:grid-cols-3 md:grid-cols-5 gap-3">
        <div className="p-3.5 rounded-xl bg-[#F7F7F5] border border-[#E5E5E5]">
          <div className="text-[10px] text-[#6B6B6B] uppercase font-bold">Redirects</div>
          <div className="text-2xl font-bold text-[#111111]">{redirects}</div>
        </div>
        <div className="p-3.5 rounded-xl bg-[#F7F7F5] border border-[#E5E5E5]">
          <div className="text-[10px] text-[#6B6B6B] uppercase font-bold">Network Events</div>
          <div className="text-2xl font-bold text-[#111111]">{networkRequests}</div>
        </div>
        <div className="p-3.5 rounded-xl bg-[#F7F7F5] border border-[#E5E5E5]">
          <div className="text-[10px] text-[#6B6B6B] uppercase font-bold">Forms Detected</div>
          <div className={`text-2xl font-bold ${formsDetected > 0 ? 'text-red-600' : 'text-[#111111]'}`}>{formsDetected}</div>
        </div>
        <div className="p-3.5 rounded-xl bg-[#F7F7F5] border border-[#E5E5E5]">
          <div className="text-[10px] text-[#6B6B6B] uppercase font-bold">Scripts Executed</div>
          <div className="text-2xl font-bold text-[#111111]">{scriptsExecuted}</div>
        </div>
        <div className="p-3.5 rounded-xl bg-[#F7F7F5] border border-[#E5E5E5]">
          <div className="text-[10px] text-[#6B6B6B] uppercase font-bold">Risk Findings</div>
          <div className={`text-2xl font-bold ${suspiciousActions > 0 ? 'text-amber-600' : 'text-emerald-600'}`}>{suspiciousActions}</div>
        </div>
      </div>

      {/* Inspector Tabs */}
      <div className="border-t border-[#E5E5E5] pt-4 space-y-3">
        <div className="flex items-center gap-2 text-xs overflow-x-auto pb-1">
          {['summary', 'findings', 'redirects', 'forms'].map((tab) => (
            <button
              key={tab}
              onClick={() => setActiveTab(tab)}
              className={`
                px-4 py-2 rounded-xl uppercase tracking-wider font-semibold transition-all shrink-0 cursor-pointer
                ${activeTab === tab 
                  ? 'bg-[#111111] text-white shadow-sm' 
                  : 'bg-[#F7F7F5] text-[#6B6B6B] hover:text-[#111111] border border-[#E5E5E5]'
                }
              `}
            >
              {tab}
            </button>
          ))}
        </div>

        {/* Tab Content Display */}
        <div className="p-4 rounded-xl bg-[#F7F7F5] border border-[#E5E5E5] text-xs">
          {activeTab === 'summary' && (
            <div className="space-y-2">
              <div className="font-bold text-[#111111]">Sandbox Execution Summary:</div>
              <p className="text-[#6B6B6B]">
                Target URL <span className="font-mono font-bold text-[#111111]">{url}</span> was executed in an isolated browser environment.
                Observed {formsDetected} input forms, {redirects} redirects, and {networkRequests} network events.
              </p>
            </div>
          )}

          {activeTab === 'findings' && (
            <div className="space-y-2">
              {findings.length > 0 ? (
                findings.map((f, idx) => (
                  <div key={idx} className="p-2.5 bg-red-50 border border-red-200 rounded-lg text-red-800">
                    {typeof f === 'string' ? f : JSON.stringify(f)}
                  </div>
                ))
              ) : (
                <div className="text-emerald-700 font-semibold flex items-center gap-2">
                  <CheckCircle2 className="w-4 h-4" />
                  <span>No malicious DOM behavior anomalies recorded during execution.</span>
                </div>
              )}
            </div>
          )}

          {activeTab === 'redirects' && (
            <div className="space-y-1">
              {redirectList.length > 0 ? (
                redirectList.map((r, idx) => (
                  <div key={idx} className="text-[#111111] font-mono">
                    {idx + 1}. {typeof r === 'string' ? r : r.url || JSON.stringify(r)}
                  </div>
                ))
              ) : (
                <div className="text-[#6B6B6B]">No intermediate redirect chain detected (direct navigation).</div>
              )}
            </div>
          )}

          {activeTab === 'forms' && (
            <div className="space-y-1">
              {formsList.length > 0 ? (
                formsList.map((fm, idx) => (
                  <div key={idx} className="p-2.5 bg-white border border-[#E5E5E5] rounded-lg text-red-700 font-bold">
                    [FORM {idx + 1}] {typeof fm === 'string' ? fm : JSON.stringify(fm)}
                  </div>
                ))
              ) : (
                <div className="text-[#6B6B6B]">
                  {formsDetected > 0 
                    ? `${formsDetected} input forms detected during page rendering.`
                    : 'No credential or identity harvesting forms detected on target page.'}
                </div>
              )}
            </div>
          )}
        </div>
      </div>
    </div>
  );
};

export default SandboxBrowser;
