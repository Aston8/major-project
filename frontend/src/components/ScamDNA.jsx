import React from 'react';
import { Dna, ShieldAlert, GitBranch, Sparkles } from 'lucide-react';

export const ScamDNA = ({ dnaSignals, familyMatches }) => {
  const defaultSignals = {
    phishing: 92,
    impersonation: 81,
    urgency: 88,
    otpFraud: 76,
    financial: 73
  };

  const signals = dnaSignals ? {
    phishing: dnaSignals.phishing ?? 50,
    impersonation: dnaSignals.impersonation ?? 50,
    urgency: dnaSignals.urgency ?? 50,
    otpFraud: dnaSignals.otpFraud ?? dnaSignals.credentialHarvest ?? 50,
    financial: dnaSignals.financial ?? dnaSignals.financialIntent ?? 50
  } : defaultSignals;

  const matches = familyMatches || [
    { name: "Bank Phishing (Family #BF-09)", similarity: Math.min(99, signals.phishing + 1) },
    { name: "OTP Fraud (Family #OF-21)", similarity: Math.min(99, signals.otpFraud + 2) },
    { name: "Account Takeover (Family #AT-04)", similarity: Math.min(99, signals.impersonation - 3) }
  ];

  return (
    <div className="shield-card p-6 space-y-8 font-sans">
      {/* Header */}
      <div className="flex items-center justify-between border-b border-[#E5E5E5] pb-4">
        <div>
          <div className="text-[10px] font-mono font-medium tracking-widest text-[#6B6B6B] uppercase">
            BEHAVIORAL FINGERPRINT
          </div>
          <h2 className="text-2xl font-bold tracking-tight text-[#111111] mt-0.5">
            SCAM DNA
          </h2>
          <p className="text-xs text-[#6B6B6B] mt-0.5 font-mono">
            The unique signal vector fingerprint of this threat actor.
          </p>
        </div>
        <div className="p-3 bg-[#111111] text-white rounded-xl shadow-md flex items-center gap-2 font-mono">
          <Dna className="w-5 h-5 text-blue-400 animate-pulse" />
          <span className="text-xs font-bold">DNA-VEC-9941</span>
        </div>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-2 gap-8 items-center">
        {/* Unique Dark Constellation Visual Fingerprint */}
        <div className="shield-dark-panel p-6 rounded-2xl relative overflow-hidden flex flex-col items-center justify-center min-h-[300px]">
          <div className="absolute inset-0 dark-grid-pattern opacity-30"></div>
          
          <div className="text-[10px] font-mono tracking-widest text-gray-400 uppercase mb-4 z-10">
            SIGNAL MATRIX CONSTELLATION
          </div>

          {/* Node Fingerprint Graphic */}
          <div className="relative w-64 h-64 flex items-center justify-center z-10 font-mono">
            {/* Background Orbit Ring */}
            <div className="absolute w-56 h-56 rounded-full border border-white/10 animate-spin-slow"></div>
            <div className="absolute w-36 h-36 rounded-full border border-blue-500/20"></div>

            {/* Central DNA Core Node */}
            <div className="w-12 h-12 rounded-full bg-blue-600 text-white flex items-center justify-center font-bold text-xs shadow-lg shadow-blue-500/30 border border-blue-400 z-20">
              DNA
            </div>

            {/* Impersonation Node (Top) */}
            <div className="absolute top-2 flex flex-col items-center">
              <div className="w-4 h-4 rounded-full bg-red-500 border border-white shadow-md animate-ping"></div>
              <span className="text-[9px] font-mono text-red-400 font-bold uppercase mt-1">IMPERSONATION ({signals.impersonation}%)</span>
            </div>

            {/* Urgency Node (Top-Left) */}
            <div className="absolute top-16 left-2 flex flex-col items-center">
              <div className="w-3.5 h-3.5 rounded-full bg-amber-500 border border-white shadow-md"></div>
              <span className="text-[9px] font-mono text-amber-400 font-bold uppercase mt-1">URGENCY ({signals.urgency}%)</span>
            </div>

            {/* OTP Node (Top-Right) */}
            <div className="absolute top-16 right-2 flex flex-col items-center">
              <div className="w-3.5 h-3.5 rounded-full bg-orange-500 border border-white shadow-md"></div>
              <span className="text-[9px] font-mono text-orange-400 font-bold uppercase mt-1">OTP ({signals.otpFraud}%)</span>
            </div>

            {/* Payment Node (Bottom-Left) */}
            <div className="absolute bottom-12 left-4 flex flex-col items-center">
              <div className="w-3.5 h-3.5 rounded-full bg-emerald-500 border border-white shadow-md"></div>
              <span className="text-[9px] font-mono text-emerald-400 font-bold uppercase mt-1">PAYMENT ({signals.financial}%)</span>
            </div>

            {/* Phishing Node (Bottom-Right) */}
            <div className="absolute bottom-12 right-4 flex flex-col items-center">
              <div className="w-4 h-4 rounded-full bg-red-600 border border-white shadow-md"></div>
              <span className="text-[9px] font-mono text-red-400 font-bold uppercase mt-1">PHISHING ({signals.phishing}%)</span>
            </div>
          </div>
        </div>

        {/* DNA Signal Spectrum Breakdown */}
        <div className="space-y-4">
          <h3 className="text-xs font-mono font-semibold uppercase tracking-widest text-[#6B6B6B]">
            SIGNAL SPECTRUM INTENSITY
          </h3>

          <div className="space-y-3 font-mono">
            {Object.entries(signals).map(([key, val]) => (
              <div key={key} className="space-y-1">
                <div className="flex justify-between text-xs font-bold text-[#111111] uppercase">
                  <span>{key.replace(/([A-Z])/g, ' $1')}</span>
                  <span>{val}%</span>
                </div>
                <div className="w-full h-2.5 bg-[#F0F0EE] rounded-full overflow-hidden border border-[#E5E5E5]">
                  <div 
                    className="h-full bg-[#111111] rounded-full transition-all duration-700"
                    style={{ width: `${val}%` }}
                  />
                </div>
              </div>
            ))}
          </div>

          {/* Closest Scam Families Section */}
          <div className="pt-4 border-t border-[#E5E5E5] space-y-3 font-mono">
            <h4 className="text-xs font-mono font-semibold uppercase tracking-widest text-[#6B6B6B] flex items-center gap-2">
              <GitBranch className="w-3.5 h-3.5 text-[#111111]" />
              Closest Scam Families
            </h4>

            <div className="space-y-2">
              {matches.map((item, idx) => (
                <div key={idx} className="flex items-center justify-between p-3 rounded-xl bg-[#F7F7F5] border border-[#E5E5E5] text-xs">
                  <span className="font-semibold text-[#111111]">{item.name}</span>
                  <span className="px-2 py-0.5 rounded-md bg-[#111111] text-white font-bold">
                    {item.similarity}%
                  </span>
                </div>
              ))}
            </div>
          </div>
        </div>
      </div>
    </div>
  );
};

export default ScamDNA;
