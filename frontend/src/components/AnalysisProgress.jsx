import React, { useEffect, useState } from 'react';
import { Check, Loader2, Circle } from 'lucide-react';

export const AnalysisProgress = ({ mode = 'text', onComplete }) => {
  const stepsByMode = {
    sandbox: [
      "Auditing recorded interactive navigation & DOM events",
      "Analyzing form actions & credential harvesting vectors",
      "Correlating external domain redirects & network telemetry",
      "Querying global threat intelligence & domain reputation",
      "Computing behavioral fusion risk metrics",
      "Generating Scam DNA fingerprint",
      "Finalizing comprehensive sandbox investigation verdict"
    ],
    multimodal: [
      "Image processed & visual signals extracted",
      "Text extracted & NLP entity parsed",
      "Voice transcribed & tone tactics extracted",
      "URL analyzed in isolated sandbox",
      "Correlating cross-modal signals",
      "Generating Scam DNA fingerprint",
      "Finalizing threat assessment"
    ],
    default: [
      "Extracting content & cleaning payload",
      "Detecting entities & brand trademarks",
      "Analyzing behavioral signals & tactics",
      "Correlating threat signatures",
      "Generating Scam DNA fingerprint",
      "Searching related scam families",
      "Finalizing threat assessment"
    ]
  };

  const steps = stepsByMode[mode] || stepsByMode.default;
  const [currentStepIndex, setCurrentStepIndex] = useState(0);

  useEffect(() => {
    if (currentStepIndex < steps.length) {
      const timer = setTimeout(() => {
        setCurrentStepIndex((prev) => prev + 1);
      }, 180);
      return () => clearTimeout(timer);
    } else if (onComplete) {
      const timer = setTimeout(() => {
        onComplete();
      }, 100);
      return () => clearTimeout(timer);
    }
  }, [currentStepIndex, steps.length, onComplete]);

  return (
    <div className="w-full bg-[#111111] text-white p-6 rounded-2xl border border-[#262626] font-mono shadow-2xl space-y-4">
      <div className="flex items-center justify-between border-b border-[#262626] pb-3">
        <div className="flex items-center gap-2 text-xs text-blue-400 font-bold uppercase tracking-widest">
          <Loader2 className="w-4 h-4 animate-spin" />
          <span>ANALYZING THREAT PAYLOAD</span>
        </div>
        <span className="text-[10px] text-gray-400">
          STEP {Math.min(currentStepIndex + 1, steps.length)} OF {steps.length}
        </span>
      </div>

      <div className="space-y-2.5">
        {steps.map((stepText, idx) => {
          const isDone = idx < currentStepIndex;
          const isCurrent = idx === currentStepIndex;
          const isPending = idx > currentStepIndex;

          return (
            <div key={idx} className="flex items-center gap-3 text-xs">
              {isDone && (
                <div className="w-5 h-5 rounded-full bg-emerald-500/20 text-emerald-400 flex items-center justify-center border border-emerald-500/40">
                  <Check className="w-3 h-3" />
                </div>
              )}
              {isCurrent && (
                <div className="w-5 h-5 rounded-full bg-blue-500/20 text-blue-400 flex items-center justify-center border border-blue-500/40 animate-pulse">
                  <span className="text-[10px]">◉</span>
                </div>
              )}
              {isPending && (
                <div className="w-5 h-5 rounded-full bg-white/5 text-gray-600 flex items-center justify-center border border-white/10">
                  <Circle className="w-2.5 h-2.5" />
                </div>
              )}

              <span className={`
                ${isDone ? 'text-gray-300' : ''}
                ${isCurrent ? 'text-white font-semibold text-sm' : ''}
                ${isPending ? 'text-gray-600' : ''}
              `}>
                {stepText}
              </span>
            </div>
          );
        })}
      </div>
    </div>
  );
};

export default AnalysisProgress;
