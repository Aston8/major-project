import React from 'react';

export const ProtectionBadge = ({ category = 'Safe' }) => {
  const cleanCat = category.trim().toLowerCase();
  
  let styles = {
    bg: 'bg-emerald-500/10',
    text: 'text-cyber-success',
    border: 'border-cyber-success/20',
    icon: (
      <svg className="w-3.5 h-3.5" fill="none" stroke="currentColor" strokeWidth="2.5" viewBox="0 0 24 24">
        <path strokeLinecap="round" strokeLinejoin="round" d="M9 12.75L11.25 15 15 9.75M21 12c0 1.268-.63 2.39-1.593 3.068a3.745 3.745 0 01-1.043 3.296 3.745 3.745 0 01-3.296 1.043A3.745 3.745 0 0112 21c-1.268 0-2.39-.63-3.068-1.593a3.746 3.746 0 01-3.296-1.043 3.745 3.745 0 01-1.043-3.296A3.745 3.745 0 013 12c0-1.268.63-2.39 1.593-3.068a3.745 3.745 0 011.043-3.296 3.746 3.746 0 013.296-1.043A3.746 3.746 0 0112 3c1.268 0 2.39.63 3.068 1.593a3.746 3.746 0 013.296 1.043 3.746 3.746 0 011.043 3.296A3.745 3.745 0 0121 12z"></path>
      </svg>
    )
  };

  if (cleanCat === 'dangerous' || cleanCat === 'malicious' || cleanCat === 'scam') {
    styles = {
      bg: 'bg-red-500/10',
      text: 'text-cyber-danger',
      border: 'border-cyber-danger/20',
      icon: (
        <svg className="w-3.5 h-3.5" fill="none" stroke="currentColor" strokeWidth="2.5" viewBox="0 0 24 24">
          <path strokeLinecap="round" strokeLinejoin="round" d="M12 9v3.75m-9.303 3.376c-.866 1.5.217 3.374 1.948 3.374h14.71c1.73 0 2.813-1.874 1.948-3.374L13.949 3.378c-.866-1.5-3.032-1.5-3.898 0L2.697 16.126zM12 15.75h.007v.008H12v-.008z"></path>
        </svg>
      )
    };
  } else if (cleanCat === 'suspicious' || cleanCat === 'warning') {
    styles = {
      bg: 'bg-amber-500/10',
      text: 'text-cyber-warning',
      border: 'border-cyber-warning/20',
      icon: (
        <svg className="w-3.5 h-3.5" fill="none" stroke="currentColor" strokeWidth="2.5" viewBox="0 0 24 24">
          <path strokeLinecap="round" strokeLinejoin="round" d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-3L13.732 4c-.77-1.333-2.694-1.333-3.464 0L3.34 16c-.77 1.333.192 3 1.732 3z"></path>
        </svg>
      )
    };
  }

  const displayLabel = (cleanCat === 'dangerous' || cleanCat === 'suspicious' || cleanCat === 'scam') ? 'SCAM' : 'NOT SCAM';
  
  return (
    <span className={`inline-flex items-center gap-1.5 px-2.5 py-1 rounded-md text-xs font-semibold border ${styles.bg} ${styles.text} ${styles.border}`}>
      {styles.icon}
      <span>{displayLabel}</span>
    </span>
  );
};
