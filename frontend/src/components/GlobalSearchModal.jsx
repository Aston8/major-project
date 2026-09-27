import React, { useState, useEffect } from 'react';
import { Search, X, Shield, ArrowRight } from 'lucide-react';
import ThreatBadge from './ThreatBadge';

export const GlobalSearchModal = ({ isOpen, onClose, investigations = [], onSelectInvestigation }) => {
  const [query, setQuery] = useState('');

  useEffect(() => {
    const handleKeyDown = (e) => {
      if ((e.metaKey || e.ctrlKey) && e.key === 'k') {
        e.preventDefault();
        onClose();
      }
      if (e.key === 'Escape' && isOpen) {
        onClose();
      }
    };
    window.addEventListener('keydown', handleKeyDown);
    return () => window.removeEventListener('keydown', handleKeyDown);
  }, [isOpen, onClose]);

  if (!isOpen) return null;

  const filtered = (investigations || []).filter((inv) => {
    const q = query.toLowerCase().trim();
    if (!q) return true;
    return (
      inv.id?.toLowerCase().includes(q) ||
      inv.title?.toLowerCase().includes(q) ||
      inv.category?.toLowerCase().includes(q) ||
      inv.vector?.toLowerCase().includes(q) ||
      inv.target?.toLowerCase().includes(q) ||
      (inv.originalContent?.url && inv.originalContent.url.toLowerCase().includes(q)) ||
      (inv.originalContent?.text && inv.originalContent.text.toLowerCase().includes(q))
    );
  });

  return (
    <div className="fixed inset-0 z-50 bg-black/50 backdrop-blur-xs flex items-start justify-center pt-16 px-4 font-sans">
      <div 
        className="w-full max-w-2xl bg-white border border-[#E5E5E5] rounded-2xl shadow-2xl overflow-hidden animate-in fade-in zoom-in-95 duration-150"
        onClick={(e) => e.stopPropagation()}
      >
        {/* Search Input Bar */}
        <div className="p-4 border-b border-[#E5E5E5] flex items-center gap-3 bg-[#FAFAFA] font-mono">
          <Search className="w-5 h-5 text-[#6B6B6B]" />
          <input
            type="text"
            placeholder="Search investigation ID, target, category, or evidence text..."
            value={query}
            onChange={(e) => setQuery(e.target.value)}
            autoFocus
            className="w-full bg-transparent border-none outline-none text-sm font-mono text-[#111111] placeholder-[#8E8E8E]"
          />
          {query && (
            <button onClick={() => setQuery('')} className="p-1 text-[#6B6B6B] hover:text-[#111111] cursor-pointer">
              <X className="w-4 h-4" />
            </button>
          )}
          <button onClick={onClose} className="p-1 text-[#6B6B6B] hover:text-[#111111] text-xs font-mono border border-[#E5E5E5] rounded-md px-2 py-0.5 cursor-pointer">
            ESC
          </button>
        </div>

        {/* Results Body */}
        <div className="max-h-[60vh] overflow-y-auto p-4 space-y-2 font-mono">
          {filtered.length === 0 ? (
            <div className="text-center py-10 text-[#6B6B6B] font-mono text-xs">
              {query ? `No matching investigations found for "${query}"` : 'No stored investigations in database.'}
            </div>
          ) : (
            filtered.map((inv) => (
              <div
                key={inv.rawId || inv.id}
                onClick={() => {
                  onSelectInvestigation(inv);
                  onClose();
                }}
                className="p-3.5 rounded-xl border border-[#E5E5E5] hover:border-[#111111] bg-white hover:bg-[#F7F7F5] transition-all cursor-pointer group flex items-center justify-between"
              >
                <div className="space-y-1">
                  <div className="flex items-center gap-2">
                    <span className="font-mono text-xs font-bold text-[#111111]">{inv.id}</span>
                    <ThreatBadge level={inv.threatLevel} />
                    <span className="text-[10px] font-mono text-[#6B6B6B] uppercase">{inv.vector}</span>
                  </div>
                  <div className="text-sm font-semibold text-[#111111] group-hover:text-blue-600 transition-colors">
                    {inv.category || inv.title}
                  </div>
                  <div className="text-xs text-[#6B6B6B] line-clamp-1">
                    Target: {inv.target || inv.originalContent?.url || 'Evidence Payload'}
                  </div>
                </div>

                <div className="flex items-center gap-2 text-xs font-mono text-[#6B6B6B] group-hover:text-[#111111]">
                  <span>View</span>
                  <ArrowRight className="w-4 h-4 group-hover:translate-x-1 transition-transform" />
                </div>
              </div>
            ))
          )}
        </div>

        {/* Footer */}
        <div className="p-3 bg-[#F7F7F5] border-t border-[#E5E5E5] text-[10px] font-mono text-[#6B6B6B] flex items-center justify-between px-4">
          <span>Search records by dossier ID, target URL, or threat category</span>
          <span>SHIELD AI Intelligence</span>
        </div>
      </div>
    </div>
  );
};

export default GlobalSearchModal;
