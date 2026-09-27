import React from 'react';

export const ThreatScore = ({ score = 0, level = 'SAFE', size = 'md' }) => {
  const getScoreColor = () => {
    if (score >= 90) return 'text-red-600 border-red-500 bg-red-500/5';
    if (score >= 70) return 'text-orange-600 border-orange-500 bg-orange-500/5';
    if (score >= 40) return 'text-amber-600 border-amber-500 bg-amber-500/5';
    return 'text-emerald-600 border-emerald-500 bg-emerald-500/5';
  };

  const getBarColor = () => {
    if (score >= 90) return 'bg-red-500';
    if (score >= 70) return 'bg-orange-500';
    if (score >= 40) return 'bg-amber-500';
    return 'bg-emerald-500';
  };

  return (
    <div className="flex flex-col items-center justify-center font-mono">
      <div className={`relative flex items-center justify-center rounded-2xl border-2 p-4 ${getScoreColor()} ${size === 'lg' ? 'w-32 h-32' : 'w-24 h-24'}`}>
        <div className="text-center">
          <span className={`font-mono font-bold tracking-tight ${size === 'lg' ? 'text-4xl' : 'text-2xl'}`}>
            {score}
          </span>
          <span className="block text-[10px] font-mono uppercase tracking-widest text-[#6B6B6B] mt-0.5">
            / 100
          </span>
        </div>
      </div>
      <div className="w-full mt-3 bg-[#E5E5E5] h-1.5 rounded-full overflow-hidden">
        <div 
          className={`h-full transition-all duration-700 ease-out ${getBarColor()}`}
          style={{ width: `${Math.min(100, Math.max(0, score))}%` }}
        />
      </div>
    </div>
  );
};

export default ThreatScore;
