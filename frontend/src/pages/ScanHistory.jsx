import React, { useState, useEffect } from 'react';
import axios from 'axios';
import { ProtectionBadge } from '../components/ProtectionBadge';

export const ScanHistory = () => {
  const [scans, setScans] = useState([]);
  const [loading, setLoading] = useState(true);
  
  // Filtering & Pagination
  const [searchTerm, setSearchTerm] = useState('');
  const [scanType, setScanType] = useState('');
  const [category, setCategory] = useState('');
  const [skip, setSkip] = useState(0);
  const [limit] = useState(10);
  const [total, setTotal] = useState(0);

  const fetchHistory = async () => {
    setLoading(true);
    try {
      const res = await axios.get('/api/scans/history', {
        params: {
          skip,
          limit,
          scan_type: scanType || undefined,
          category: category || undefined,
          q: searchTerm || undefined
        }
      });
      setScans(res.data.results);
      setTotal(res.data.total);
    } catch (err) {
      console.error("Failed to load history:", err);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchHistory();
  }, [skip, scanType, category]);

  const handleSearchSubmit = (e) => {
    e.preventDefault();
    setSkip(0);
    fetchHistory();
  };

  const downloadReport = async (scanId) => {
    try {
      const response = await axios.get(`/api/scans/report/${scanId}`, {
        responseType: 'blob'
      });
      const file = new Blob([response.data], { type: 'application/pdf' });
      const fileURL = URL.createObjectURL(file);
      const link = document.createElement('a');
      link.href = fileURL;
      link.setAttribute('download', `SmartShield_Report_${scanId}.pdf`);
      document.body.appendChild(link);
      link.click();
      link.remove();
    } catch (err) {
      alert("Failed to download PDF report.");
    }
  };

  return (
    <div className="p-6 flex flex-col gap-6">
      <div>
        <h1 className="text-2xl font-extrabold text-white tracking-tight">Diagnostics Audit Logs</h1>
        <p className="text-xs text-gray-400 mt-1">Review, filter, and compile reports for past security scans</p>
      </div>

      {/* Filter and search bar */}
      <form onSubmit={handleSearchSubmit} className="glass-card p-4 rounded-xl border border-white/5 flex flex-col md:flex-row gap-4 items-end justify-between">
        <div className="grid grid-cols-1 sm:grid-cols-3 gap-4 flex-1 w-full">
          <div className="flex flex-col gap-1.5">
            <label className="text-2xs font-bold uppercase tracking-wider text-gray-400">Search Keyword</label>
            <input
              type="text"
              value={searchTerm}
              onChange={(e) => setSearchTerm(e.target.value)}
              placeholder="Search by keywords, URLs..."
              className="w-full px-4 py-2.5 rounded-lg bg-cyber-bg border border-gray-800 text-xs text-gray-200 focus:outline-none focus:border-indigo-500/50 transition"
            />
          </div>

          <div className="flex flex-col gap-1.5">
            <label className="text-2xs font-bold uppercase tracking-wider text-gray-400">Scan Channel</label>
            <select
              value={scanType}
              onChange={(e) => {
                setScanType(e.target.value);
                setSkip(0);
              }}
              className="w-full px-4 py-2.5 rounded-lg bg-cyber-bg border border-gray-800 text-xs text-gray-200 focus:outline-none focus:border-indigo-500/50 transition"
            >
              <option value="">All Channels</option>
              <option value="text">Text / SMS</option>
              <option value="url">URL Sandbox</option>
              <option value="image">Screenshot OCR</option>
              <option value="voice">Voice Call Whisper</option>
              <option value="email">Email Integrity</option>
            </select>
          </div>

          <div className="flex flex-col gap-1.5">
            <label className="text-2xs font-bold uppercase tracking-wider text-gray-400">Verdict State</label>
            <select
              value={category}
              onChange={(e) => {
                setCategory(e.target.value);
                setSkip(0);
              }}
              className="w-full px-4 py-2.5 rounded-lg bg-cyber-bg border border-gray-800 text-xs text-gray-200 focus:outline-none focus:border-indigo-500/50 transition"
            >
              <option value="">All Categories</option>
              <option value="Safe">Safe</option>
              <option value="Suspicious">Suspicious</option>
              <option value="Dangerous">Dangerous</option>
            </select>
          </div>
        </div>

        <button
          type="submit"
          className="px-5 py-2.5 rounded-lg bg-indigo-600 hover:bg-indigo-500 text-white font-semibold text-xs tracking-wide transition w-full md:w-auto shrink-0 flex items-center justify-center gap-1.5"
        >
          <svg className="w-4 h-4" fill="none" stroke="currentColor" strokeWidth="2" viewBox="0 0 24 24">
            <path strokeLinecap="round" strokeLinejoin="round" d="M21 21l-5.197-5.197m0 0A7.5 7.5 0 105.196 5.196a7.5 7.5 0 0010.637 10.637z"></path>
          </svg>
          <span>Search Logs</span>
        </button>
      </form>

      {/* History table */}
      <div className="glass-card p-6 rounded-2xl border border-white/5 flex flex-col gap-4">
        {loading ? (
          <div className="py-12 flex justify-center">
            <span className="w-8 h-8 border-4 border-indigo-500/20 border-t-indigo-400 rounded-full animate-spin"></span>
          </div>
        ) : scans.length > 0 ? (
          <>
            <div className="overflow-x-auto">
              <table className="w-full text-left border-collapse">
                <thead>
                  <tr className="border-b border-gray-800 text-2xs uppercase tracking-widest text-gray-400">
                    <th className="pb-3 font-semibold">Channel</th>
                    <th className="pb-3 font-semibold">Input Details</th>
                    <th className="pb-3 font-semibold">Verdict</th>
                    <th className="pb-3 font-semibold">Risk Score</th>
                    <th className="pb-3 font-semibold">Audit Timestamp</th>
                    <th className="pb-3 font-semibold text-right">Actions</th>
                  </tr>
                </thead>
                <tbody>
                  {scans.map((scan) => {
                    const inputVal = scan.input_data.content || scan.input_data.url || scan.input_data.filename;
                    return (
                      <tr key={scan._id} className="border-b border-gray-900/60 hover:bg-gray-800/10 text-xs text-gray-300">
                        <td className="py-4 capitalize font-semibold text-gray-400">{scan.type}</td>
                        <td className="py-4 font-mono truncate max-w-[200px]" title={inputVal}>{inputVal}</td>
                        <td className="py-4">
                          <ProtectionBadge category={scan.fusion_result?.category} />
                        </td>
                        <td className="py-4 font-bold">{scan.fusion_result?.final_score} / 100</td>
                        <td className="py-4 text-2xs text-gray-500">
                          {new Date(scan.created_at).toLocaleString()}
                        </td>
                        <td className="py-4 text-right">
                          <button
                            onClick={() => downloadReport(scan._id)}
                            className="inline-flex items-center gap-1 text-2xs font-semibold text-indigo-400 hover:text-indigo-300 transition"
                          >
                            <svg className="w-3.5 h-3.5" fill="none" stroke="currentColor" strokeWidth="2" viewBox="0 0 24 24">
                              <path strokeLinecap="round" strokeLinejoin="round" d="M3 16.5v2.25A2.25 2.25 0 005.25 21h13.5A2.25 2.25 0 0021 18.75V16.5M16.5 12L12 16.5m0 0L7.5 12m4.5 4.5V3"></path>
                            </svg>
                            <span>Compile PDF</span>
                          </button>
                        </td>
                      </tr>
                    );
                  })}
                </tbody>
              </table>
            </div>

            {/* Pagination Controls */}
            {total > limit && (
              <div className="flex items-center justify-between mt-4 pt-4 border-t border-gray-800/60 text-xs text-gray-400">
                <span>Showing {skip + 1} - {Math.min(skip + limit, total)} of {total} records</span>
                <div className="flex gap-2">
                  <button
                    disabled={skip === 0}
                    onClick={() => setSkip(Math.max(0, skip - limit))}
                    className="px-3 py-1.5 rounded bg-cyber-bg border border-gray-800 hover:border-gray-700 disabled:opacity-30 transition font-semibold"
                  >
                    Previous
                  </button>
                  <button
                    disabled={skip + limit >= total}
                    onClick={() => setSkip(skip + limit)}
                    className="px-3 py-1.5 rounded bg-cyber-bg border border-gray-800 hover:border-gray-700 disabled:opacity-30 transition font-semibold"
                  >
                    Next
                  </button>
                </div>
              </div>
            )}
          </>
        ) : (
          <div className="text-center py-12 text-gray-500 text-xs font-light">
            No diagnostic events match current filter conditions.
          </div>
        )}
      </div>
    </div>
  );
};
