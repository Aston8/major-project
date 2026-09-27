import React, { useState } from 'react';
import { AlertTriangle, Info, ShieldAlert, CheckCircle2 } from 'lucide-react';
import ThreatBadge from './ThreatBadge';

export const RevealScamPanel = ({ originalText = '', highlights = [] }) => {
  const [selectedTactic, setSelectedTactic] = useState(null);

  const textToRender = originalText || "";

  if (!textToRender.trim()) {
    return (
      <div className="shield-card p-6 font-mono text-center space-y-2">
        <div className="text-xs font-bold text-[#6B6B6B] uppercase">Forensic Highlight Mode</div>
        <p className="text-xs text-[#8E8E8E]">No text or transcription payload available for tactic highlighting in this investigation.</p>
      </div>
    );
  }

  // Generate dynamic highlights if none were passed
  let activeHighlights = highlights;
  if (!activeHighlights || activeHighlights.length === 0) {
    activeHighlights = [];
    
    // Check for URLs
    const urlMatch = textToRender.match(/(https?:\/\/[^\s]+|www\.[^\s]+)/i);
    if (urlMatch) {
      activeHighlights.push({
        phrase: urlMatch[0],
        tactic: "PHISHING URL / CREDENTIAL HARVEST",
        description: `Unverified destination link "${urlMatch[0]}" designed to exfiltrate credentials.`,
        severity: "CRITICAL"
      });
    }

    // Check for urgency phrases
    const urgencyMatch = textToRender.match(/(urgent|immediately|within \d+ hours|restricted|suspended|lock|restricted due to|action required|do not ignore|failed login)/i);
    if (urgencyMatch) {
      activeHighlights.push({
        phrase: urgencyMatch[0],
        tactic: "URGENCY & COERCION",
        description: `High-pressure psychological trigger "${urgencyMatch[0]}" forcing victim into rapid action.`,
        severity: "HIGH"
      });
    }

    // Check for brand impersonation
    const brandMatch = textToRender.match(/(chase|bank|paypal|apple|fedex|irs|metamask|coinbase|amazon|microsoft|wells fargo|citi)/i);
    if (brandMatch) {
      activeHighlights.push({
        phrase: brandMatch[0],
        tactic: "AUTHORITY IMPERSONATION",
        description: `Spoofed identity keyword "${brandMatch[0]}" used to exploit consumer brand trust.`,
        severity: "CRITICAL"
      });
    }

    // Check for credential/OTP requests
    const credMatch = textToRender.match(/(otp|verification code|password|ssn|seed phrase|login|verify|credentials)/i);
    if (credMatch) {
      activeHighlights.push({
        phrase: credMatch[0],
        tactic: "CREDENTIAL HARVESTING",
        description: `Explicit request for sensitive authentication token or credential "${credMatch[0]}".`,
        severity: "CRITICAL"
      });
    }
  }

  // Render text with dynamic highlighted spans
  const renderHighlightedText = () => {
    if (!activeHighlights || activeHighlights.length === 0) {
      return <span>{textToRender}</span>;
    }

    const phraseMap = new Map();
    activeHighlights.forEach((h) => {
      if (h.phrase) {
        phraseMap.set(h.phrase.toLowerCase(), h);
      }
    });

    const escapedPhrases = activeHighlights
      .map(h => h.phrase ? h.phrase.replace(/[-\/\\^$*+?.()|[\]{}]/g, '\\$&') : null)
      .filter(Boolean);

    if (escapedPhrases.length === 0) return <span>{textToRender}</span>;

    const regex = new RegExp(`(${escapedPhrases.join('|')})`, 'gi');
    const parts = textToRender.split(regex);

    return parts.map((part, index) => {
      const matchedHighlight = phraseMap.get(part.toLowerCase());
      if (matchedHighlight) {
        const isCritical = matchedHighlight.severity === 'CRITICAL';
        return (
          <span
            key={index}
            onClick={() => setSelectedTactic(matchedHighlight)}
            className={`cursor-pointer font-bold px-1 rounded border-b-2 transition-colors inline-block my-0.5 ${
              isCritical
                ? 'bg-red-500/20 text-red-900 border-red-500 hover:bg-red-500/30'
                : 'bg-amber-500/20 text-amber-900 border-amber-500 hover:bg-amber-500/30'
            }`}
          >
            {part}
          </span>
        );
      }
      return <span key={index}>{part}</span>;
    });
  };

  return (
    <div className="shield-card p-6 space-y-6 font-mono">
      <div className="flex items-center justify-between border-b border-[#E5E5E5] pb-4">
        <div>
          <div className="text-[10px] font-mono font-medium tracking-widest text-[#6B6B6B] uppercase">
            FORENSIC HIGHLIGHT MODE
          </div>
          <h3 className="text-xl font-bold tracking-tight text-[#111111] mt-0.5">
            Reveal the Scam
          </h3>
        </div>
        <div className="text-xs font-mono text-[#6B6B6B] flex items-center gap-2">
          <Info className="w-4 h-4 text-blue-600" />
          Click highlighted text to inspect scam tactic
        </div>
      </div>

      {/* Content Container */}
      <div className="p-6 rounded-2xl bg-[#F7F7F5] border border-[#E5E5E5] text-sm leading-relaxed text-[#111111]">
        <span className="block text-[10px] uppercase font-bold tracking-widest text-[#6B6B6B] mb-3">
          ORIGINAL SUSPECT PAYLOAD
        </span>
        
        <div className="space-x-0.5">
          {renderHighlightedText()}
        </div>
      </div>

      {/* Selected Tactic Inspector */}
      {selectedTactic ? (
        <div className="p-5 rounded-2xl bg-[#111111] text-white border border-[#262626] font-mono space-y-3 animate-in fade-in duration-200">
          <div className="flex items-center justify-between border-b border-white/10 pb-3">
            <div className="flex items-center gap-2">
              <ShieldAlert className="w-5 h-5 text-red-400" />
              <div>
                <div className="text-[10px] text-gray-400 uppercase tracking-widest">TACTIC DETECTED</div>
                <div className="text-base font-bold text-white tracking-wider">{selectedTactic.tactic}</div>
              </div>
            </div>
            <ThreatBadge level={selectedTactic.severity || "CRITICAL"} />
          </div>

          <p className="text-xs text-gray-300 leading-normal">
            {selectedTactic.description}
          </p>

          <div className="flex items-center justify-between pt-2 text-[10px] text-gray-400 border-t border-white/10">
            <span>TARGET PHRASE: <strong className="text-amber-400">"{selectedTactic.phrase}"</strong></span>
            <button 
              onClick={() => setSelectedTactic(null)}
              className="text-white underline hover:text-gray-300 cursor-pointer"
            >
              Close Inspector
            </button>
          </div>
        </div>
      ) : (
        <div className="p-4 rounded-xl bg-white border border-dashed border-[#E5E5E5] text-center text-xs font-mono text-[#6B6B6B]">
          👉 Select any highlighted text span above to view deep psychological tactic analysis.
        </div>
      )}
    </div>
  );
};

export default RevealScamPanel;
