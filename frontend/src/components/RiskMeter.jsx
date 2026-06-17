import React, { useEffect, useState } from 'react';

export const RiskMeter = ({ score = 0, category = 'Safe' }) => {
  const [animatedScore, setAnimatedScore] = useState(0);

  useEffect(() => {
    // Smooth initial count animation
    const duration = 1000;
    const steps = 30;
    const stepVal = score / steps;
    let current = 0;
    
    const interval = setInterval(() => {
      current += stepVal;
      if (current >= score) {
        setAnimatedScore(score);
        clearInterval(interval);
      } else {
        setAnimatedScore(Math.round(current));
      }
    }, duration / steps);

    return () => clearInterval(interval);
  }, [score]);

  // Determine colors based on status
  let glowClass = "glow-success";
  let textClass = "text-cyber-success";
  let borderClass = "border-cyber-success/30";
  let bgGradient = "from-emerald-500/10 to-transparent";

  if (score > 60) {
    glowClass = "glow-danger";
    textClass = "text-cyber-danger";
    borderClass = "border-cyber-danger/30";
    bgGradient = "from-red-500/10 to-transparent";
  } else if (score > 30) {
    glowClass = "glow-warning";
    textClass = "text-cyber-warning";
    borderClass = "border-cyber-warning/30";
    bgGradient = "from-amber-500/10 to-transparent";
  }

  // Radial calculation (stroke offset)
  const radius = 60;
  const circumference = 2 * Math.PI * radius;
  const strokeDashoffset = circumference - (animatedScore / 100) * circumference;

  return (
    <div className={`glass-card p-6 rounded-2xl flex flex-col items-center justify-center border text-center transition ${glowClass} ${borderClass} bg-gradient-to-b ${bgGradient}`}>
      <span className="text-xs font-semibold text-gray-400 uppercase tracking-widest mb-4">Threat Index Rating</span>
      
      <div className="relative w-40 h-40 flex items-center justify-center">
        {/* SVG Circular Progress */}
        <svg className="w-full h-full transform -rotate-90" viewBox="0 0 140 140">
          {/* Background circle */}
          <circle
            cx="70"
            cy="70"
            r={radius}
            className="stroke-gray-800"
            strokeWidth="8"
            fill="transparent"
          />
          {/* Active progress track */}
          <circle
            cx="70"
            cy="70"
            r={radius}
            className={`transition-all duration-300 ease-out ${
              score > 60 ? 'stroke-red-500' : score > 30 ? 'stroke-amber-500' : 'stroke-emerald-500'
            }`}
            strokeWidth="10"
            strokeDasharray={circumference}
            strokeDashoffset={strokeDashoffset}
            strokeLinecap="round"
            fill="transparent"
          />
        </svg>
        
        {/* Absolute center scores */}
        <div className="absolute flex flex-col items-center justify-center">
          <span className="text-4xl font-extrabold tracking-tight text-white">{animatedScore}</span>
          <span className="text-3xs uppercase tracking-widest text-gray-500">of 100</span>
        </div>
      </div>

      <div className="mt-4">
        <span className={`text-lg font-bold uppercase tracking-wider ${textClass}`}>
          {category}
        </span>
      </div>
    </div>
  );
};
