import React, { useState, useEffect } from 'react';
import { Search, RefreshCw, ArrowRight, Shield, Globe, FileText, Image as ImageIcon, Mic, Layers, AlertTriangle, CheckCircle2, HelpCircle } from 'lucide-react';
import ThreatBadge from '../components/ThreatBadge';
import { historyService } from '../services/historyService';
import { formatScanDocument } from '../services/formatters';

export const HistoryPage = ({ onSelectInvestigation }) => {
  const [investigations, setInvestigations] = useState([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);
  const [searchQuery, setSearchQuery] = useState('');
  const [activeFilter, setActiveFilter] = useState('ALL');

  const fetchHistory = async () => {
    try {
      setLoading(true);
      setError(null);
      const data = await historyService.getScanHistory(50);
      const rawScans = data?.results || [];
      const formatted = rawScans.map(formatScanDocument).filter(Boolean);
      setInvestigations(formatted);
    } catch (err) {
      console.error('Failed to load scan history:', err);
      setError('Unable to load stored investigation history from backend.');
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchHistory();
  }, []);

  const filterOptions = [
    'ALL', 'TEXT', 'IMAGE', 'VOICE', 'WEBSITE SANDBOX', 'MULTIMODAL', 'CRITICAL', 'SUSPICIOUS', 'SAFE', 'INCONCLUSIVE'
  ];

  const filtered = investigations.filter((inv) => {
    const q = searchQuery.toLowerCase().trim();
    const matchesSearch = !q || (
      inv.id?.toLowerCase().includes(q) ||
      inv.title?.toLowerCase().includes(q) ||
      inv.category?.toLowerCase().includes(q) ||
      inv.target?.toLowerCase().includes(q) ||
      inv.vector?.toLowerCase().includes(q)
    );

    if (!matchesSearch) return false;

    if (activeFilter === 'ALL') return true;
    if (activeFilter === 'TEXT') return inv.vector === 'TEXT';
    if (activeFilter === 'IMAGE') return inv.vector === 'IMAGE';
    if (activeFilter === 'VOICE') return inv.vector === 'VOICE';
    if (activeFilter === 'WEBSITE SANDBOX') return inv.vector === 'WEBSITE SANDBOX' || inv.type === 'url' || inv.type === 'sandbox';
    if (activeFilter === 'MULTIMODAL') return inv.vector === 'MULTIMODAL';
    if (activeFilter === 'CRITICAL') return inv.threatLevel === 'CRITICAL' || inv.threatLevel === 'HIGH';
    if (activeFilter === 'SUSPICIOUS') return inv.threatLevel === 'SUSPICIOUS';
    if (activeFilter === 'SAFE') return inv.threatLevel === 'SAFE';
    if (activeFilter === 'INCONCLUSIVE') return inv.threatLevel === 'INCONCLUSIVE';

    return true;
  });

  const getVectorIcon = (vector) => {
    switch (vector) {
      case 'IMAGE':
        return <ImageIcon className="w-3.5 h-3.5" />;
      case 'VOICE':
        return <Mic className="w-3.5 h-3.5" />;
      case 'WEBSITE SANDBOX':
        return <Globe className="w-3.5 h-3.5" />;
      case 'MULTIMODAL':
        return <Layers className="w-3.5 h-3.5" />;
      default:
        return <FileText className="w-3.5 h-3.5" />;
    }
  };

  return (
    <div className="space-y-6 font-sans">
      {/* Header */}
      <div className="border-b border-[#E5E5E5] pb-6 flex flex-col md:flex-row md:items-center md:justify-between gap-4">
        <div>
          <div className="text-[10px] font-mono font-bold tracking-widest text-[#6B6B6B] uppercase">
            SHIELD AI // PERMANENT AUDIT ARCHIVE
          </div>
          <h1 className="text-3xl lg:text-4xl font-bold tracking-tight text-[#111111] mt-0.5">
            Investigation History
          </h1>
          <p className="text-xs text-[#6B6B6B] mt-1 font-mono">
            Stored investigation records and evidence dossiers retrieved directly from the backend database.
          </p>
        </div>

        <button
          onClick={fetchHistory}
          disabled={loading}
          className="flex items-center gap-2 px-3.5 py-2 bg-white border border-[#E5E5E5] hover:border-[#111111] rounded-xl text-xs font-mono font-bold text-[#111111] transition-all self-start md:self-auto cursor-pointer shadow-2xs"
        >
          <RefreshCw className={`w-3.5 h-3.5 ${loading ? 'animate-spin' : ''}`} />
          <span>Refresh Records</span>
        </button>
      </div>

      {/* Search & Filter Controls */}
      <div className="shield-card p-4 space-y-4 font-mono">
        <div className="flex items-center gap-3 bg-[#F7F7F5] border border-[#E5E5E5] rounded-xl px-3.5 py-2.5">
          <Search className="w-4 h-4 text-[#6B6B6B]" />
          <input
            type="text"
            placeholder="Search investigations by ID, target file/URL, or category..."
            value={searchQuery}
            onChange={(e) => setSearchQuery(e.target.value)}
            className="w-full bg-transparent border-none outline-none text-xs text-[#111111] placeholder-[#8E8E8E]"
          />
        </div>

        {/* Filter Chips */}
        <div className="flex items-center gap-2 overflow-x-auto pb-1 text-xs">
          <span className="text-[10px] text-[#6B6B6B] font-bold uppercase mr-1">Filter:</span>
          {filterOptions.map((f) => (
            <button
              key={f}
              onClick={() => setActiveFilter(f)}
              className={`
                px-3 py-1.5 rounded-lg uppercase tracking-wider font-semibold transition-all shrink-0 text-[11px] cursor-pointer
                ${activeFilter === f 
                  ? 'bg-[#111111] text-white shadow-sm' 
                  : 'bg-[#F7F7F5] text-[#6B6B6B] hover:text-[#111111] border border-[#E5E5E5]'
                }
              `}
            >
              {f}
            </button>
          ))}
        </div>
      </div>

      {/* Loading & Error States */}
      {loading && (
        <div className="shield-card p-12 text-center font-mono">
          <RefreshCw className="w-6 h-6 animate-spin mx-auto text-[#111111] mb-3" />
          <p className="text-xs text-[#6B6B6B] font-bold uppercase tracking-wider">
            Loading investigation records from database...
          </p>
        </div>
      )}

      {error && !loading && (
        <div className="shield-card p-6 border-red-200 bg-red-50/50 font-mono text-xs text-red-700 flex items-center justify-between">
          <span>{error}</span>
          <button onClick={fetchHistory} className="underline font-bold cursor-pointer">Retry</button>
        </div>
      )}

      {/* Investigations Table / Structured Record View */}
      {!loading && !error && filtered.length === 0 && (
        <div className="shield-card p-12 text-center font-mono space-y-3">
          <Shield className="w-8 h-8 text-[#8E8E8E] mx-auto stroke-1" />
          <h3 className="text-sm font-bold text-[#111111] uppercase tracking-wide">
            No Investigations Found
          </h3>
          <p className="text-xs text-[#6B6B6B] max-w-md mx-auto">
            {searchQuery || activeFilter !== 'ALL'
              ? 'No stored records match your search criteria. Try resetting the filters.'
              : 'No investigations have been saved in the database yet. Run an analysis in the Investigate tab to record evidence.'}
          </p>
        </div>
      )}

      {!loading && !error && filtered.length > 0 && (
        <div className="shield-card overflow-hidden font-mono text-xs">
          {/* Table Header (Desktop) */}
          <div className="hidden lg:grid grid-cols-12 gap-4 px-6 py-3.5 bg-[#F7F7F5] border-b border-[#E5E5E5] text-[10px] font-bold uppercase text-[#6B6B6B] tracking-wider">
            <div className="col-span-2">Date / Time</div>
            <div className="col-span-2">Investigation Type</div>
            <div className="col-span-3">Target / File</div>
            <div className="col-span-2">Risk Score</div>
            <div className="col-span-1">Verdict</div>
            <div className="col-span-2 text-right">Category</div>
          </div>

          {/* List Rows */}
          <div className="divide-y divide-[#E5E5E5]">
            {filtered.map((inv) => (
              <div
                key={inv.rawId || inv.id}
                onClick={() => onSelectInvestigation(inv)}
                className="p-4 lg:px-6 lg:py-4 hover:bg-[#F7F7F5] transition-colors cursor-pointer group flex flex-col lg:grid lg:grid-cols-12 gap-3 lg:gap-4 items-start lg:items-center"
              >
                {/* Date / Time */}
                <div className="lg:col-span-2">
                  <div className="font-bold text-[#111111]">{inv.timestamp}</div>
                  <div className="text-[10px] text-[#8E8E8E]">{inv.id}</div>
                </div>

                {/* Investigation Type */}
                <div className="lg:col-span-2 flex items-center gap-1.5">
                  <span className="p-1.5 rounded-lg bg-[#EAEAEA] text-[#111111]">
                    {getVectorIcon(inv.vector)}
                  </span>
                  <span className="font-bold text-[#111111] text-[11px] uppercase tracking-wide">
                    {inv.vector}
                  </span>
                </div>

                {/* Target / File */}
                <div className="lg:col-span-3 w-full truncate">
                  <span className="text-[#111111] font-semibold block truncate" title={inv.target}>
                    {inv.target || 'Payload Evidence'}
                  </span>
                </div>

                {/* Risk Score */}
                <div className="lg:col-span-2">
                  {inv.score !== null ? (
                    <span className="font-bold text-sm text-[#111111]">
                      {inv.score} <span className="text-[10px] text-[#6B6B6B]">/ 100</span>
                    </span>
                  ) : (
                    <span className="text-[#8E8E8E] font-medium">—</span>
                  )}
                </div>

                {/* Verdict Badge */}
                <div className="lg:col-span-1">
                  <ThreatBadge level={inv.threatLevel} />
                </div>

                {/* Category */}
                <div className="lg:col-span-2 w-full flex items-center justify-between lg:justify-end gap-2 text-right">
                  <span className="font-bold text-[#111111] truncate" title={inv.category}>
                    {inv.category}
                  </span>
                  <ArrowRight className="w-4 h-4 text-[#8E8E8E] group-hover:text-[#111111] group-hover:translate-x-1 transition-all shrink-0" />
                </div>
              </div>
            ))}
          </div>
        </div>
      )}
    </div>
  );
};

export default HistoryPage;
