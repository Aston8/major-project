import React from 'react';

export const ThreatBadge = ({ level, className = "" }) => {
  const normalizedLevel = (level || 'SAFE').toUpperCase();

  const getStyle = () => {
    switch (normalizedLevel) {
      case 'SAFE':
        return 'badge-safe text-emerald-700 bg-emerald-500/10 border-emerald-500/30';
      case 'SUSPICIOUS':
        return 'badge-suspicious text-amber-700 bg-amber-500/10 border-amber-500/30';
      case 'HIGH':
        return 'badge-high text-orange-700 bg-orange-500/10 border-orange-500/30';
      case 'CRITICAL':
        return 'badge-critical text-red-700 bg-red-500/10 border-red-500/30';
      case 'PROCESSING':
        return 'badge-processing text-blue-700 bg-blue-500/10 border-blue-500/30 animate-pulse';
      default:
        return 'bg-gray-100 text-gray-700 border-gray-200';
    }
  };

  const getDotColor = () => {
    switch (normalizedLevel) {
      case 'SAFE':
        return 'bg-emerald-500';
      case 'SUSPICIOUS':
        return 'bg-amber-500';
      case 'HIGH':
        return 'bg-orange-500';
      case 'CRITICAL':
        return 'bg-red-500';
      case 'PROCESSING':
        return 'bg-blue-500 animate-ping';
      default:
        return 'bg-gray-400';
    }
  };

  return (
    <span className={`inline-flex items-center px-2.5 py-1 rounded-full text-xs font-mono font-semibold tracking-wider border ${getStyle()} ${className}`}>
      <span className={`w-1.5 h-1.5 rounded-full mr-1.5 ${getDotColor()}`}></span>
      {normalizedLevel}
    </span>
  );
};

export default ThreatBadge;
