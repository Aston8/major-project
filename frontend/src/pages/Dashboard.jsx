import React, { useState, useEffect } from 'react';
import axios from 'axios';
import { useAuth } from '../context/AuthContext';
import { StatsChart } from '../components/StatsChart';
import { ProtectionBadge } from '../components/ProtectionBadge';
import { Link } from 'react-router-dom';

export const Dashboard = () => {
  const { user, isAdmin } = useAuth();
  const [stats, setStats] = useState({
    total_scans: 0,
    scams_count: 0,
    safe_count: 0,
    by_type: { text: 0, url: 0, image: 0, voice: 0, email: 0 },
    by_category: { Safe: 0, Suspicious: 0, Dangerous: 0 }
  });
  const [recentScans, setRecentScans] = useState([]);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    const fetchDashboardData = async () => {
      setLoading(true);
      try {
        if (user?.role === 'admin') {
          // Admin gets full system stats
          const res = await axios.get('/api/admin/stats');
          const data = res.data;
          setStats({
            total_scans: data.total_scans,
            scams_count: data.scans_by_category["Dangerous"] || 0,
            safe_count: data.scans_by_category["Safe"] || 0,
            by_type: data.scans_by_type,
            by_category: data.scans_by_category
          });
        } else {
          // Standard user aggregates their own history
          const res = await axios.get('/api/scans/history?limit=100');
          const scans = res.data.results;
          
          const by_type = { text: 0, url: 0, image: 0, voice: 0, email: 0 };
          const by_category = { Safe: 0, Suspicious: 0, Dangerous: 0 };
          
          scans.forEach(s => {
            by_type[s.type] = (by_type[s.type] || 0) + 1;
            const cat = s.fusion_result?.category || 'Safe';
            by_category[cat] = (by_category[cat] || 0) + 1;
          });
          
          const total = scans.length;
          setStats({
            total_scans: total,
            scams_count: by_category["Dangerous"] || 0,
            safe_count: by_category["Safe"] || 0,
            by_type,
            by_category
          });
        }
        
        // Fetch recent scans (up to 5)
        const histRes = await axios.get('/api/scans/history?limit=5');
        setRecentScans(histRes.data.results);
      } catch (err) {
        console.error("Dashboard data load failed:", err);
      } finally {
        setLoading(false);
      }
    };

    if (user) {
      fetchDashboardData();
    }
  }, [user]);

  if (loading) {
    return (
      <div className="flex items-center justify-center min-h-[calc(100vh-200px)]">
        <span className="w-10 h-10 border-4 border-indigo-500/20 border-t-indigo-400 rounded-full animate-spin"></span>
      </div>
    );
  }

  return (
    <div className="p-6 flex flex-col gap-6">
      <div>
        <h1 className="text-2xl font-extrabold text-white tracking-tight">Security Control Dashboard</h1>
        <p className="text-xs text-gray-400 mt-1">Real-time scam diagnostics and multi-engine verification stats</p>
      </div>

      {/* Metrics Cards */}
      <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
        <div className="glass-card p-6 rounded-2xl border border-white/5 bg-gradient-to-b from-indigo-500/5 to-transparent flex items-center justify-between">
          <div>
            <p className="text-2xs font-bold uppercase tracking-wider text-gray-400">Total Diagnostics Runs</p>
            <p className="text-3xl font-extrabold text-white mt-2">{stats.total_scans}</p>
          </div>
          <div className="p-3 bg-indigo-500/10 rounded-xl border border-indigo-500/20 text-indigo-400">
            <svg className="w-6 h-6" fill="none" stroke="currentColor" strokeWidth="2" viewBox="0 0 24 24">
              <path strokeLinecap="round" strokeLinejoin="round" d="M9 12.75L11.25 15 15 9.75M21 12c0 1.268-.63 2.39-1.593 3.068a3.745 3.745 0 01-1.043 3.296 3.745 3.745 0 01-3.296 1.043A3.745 3.745 0 0112 21c-1.268 0-2.39-.63-3.068-1.593a3.746 3.746 0 01-3.296-1.043 3.745 3.745 0 01-1.043-3.296A3.745 3.745 0 013 12c0-1.268.63-2.39 1.593-3.068a3.745 3.745 0 011.043-3.296 3.746 3.746 0 013.296-1.043A3.746 3.746 0 0112 3c1.268 0 2.39.63 3.068 1.593a3.746 3.746 0 013.296 1.043 3.746 3.746 0 011.043 3.296A3.745 3.745 0 0121 12z"></path>
            </svg>
          </div>
        </div>

        <div className="glass-card p-6 rounded-2xl border border-white/5 bg-gradient-to-b from-rose-500/5 to-transparent flex items-center justify-between">
          <div>
            <p className="text-2xs font-bold uppercase tracking-wider text-gray-400">Scams Blocked (Dangerous)</p>
            <p className="text-3xl font-extrabold text-rose-400 mt-2">{stats.scams_count}</p>
          </div>
          <div className="p-3 bg-rose-500/10 rounded-xl border border-rose-500/20 text-rose-400 glow-danger border-rose-500/40">
            <svg className="w-6 h-6" fill="none" stroke="currentColor" strokeWidth="2" viewBox="0 0 24 24">
              <path strokeLinecap="round" strokeLinejoin="round" d="M12 9v3.75m-9.303 3.376c-.866 1.5.217 3.374 1.948 3.374h14.71c1.73 0 2.813-1.874 1.948-3.374L13.949 3.378c-.866-1.5-3.032-1.5-3.898 0L2.697 16.126zM12 15.75h.007v.008H12v-.008z"></path>
            </svg>
          </div>
        </div>

        <div className="glass-card p-6 rounded-2xl border border-white/5 bg-gradient-to-b from-emerald-500/5 to-transparent flex items-center justify-between">
          <div>
            <p className="text-2xs font-bold uppercase tracking-wider text-gray-400">Safe / Legitimate Audits</p>
            <p className="text-3xl font-extrabold text-emerald-400 mt-2">{stats.safe_count}</p>
          </div>
          <div className="p-3 bg-emerald-500/10 rounded-xl border border-emerald-500/20 text-emerald-400">
            <svg className="w-6 h-6" fill="none" stroke="currentColor" strokeWidth="2" viewBox="0 0 24 24">
              <path strokeLinecap="round" strokeLinejoin="round" d="M9 12.75L11.25 15 15 9.75M21 12c0 1.268-.63 2.39-1.593 3.068a3.745 3.745 0 01-1.043 3.296 3.745 3.745 0 01-3.296 1.043A3.745 3.745 0 0112 21c-1.268 0-2.39-.63-3.068-1.593a3.746 3.746 0 01-3.296-1.043 3.745 3.745 0 01-1.043-3.296A3.745 3.745 0 013 12c0-1.268.63-2.39 1.593-3.068a3.745 3.745 0 011.043-3.296 3.746 3.746 0 013.296-1.043A3.746 3.746 0 0112 3c1.268 0 2.39.63 3.068 1.593a3.746 3.746 0 013.296 1.043 3.746 3.746 0 011.043 3.296A3.745 3.745 0 0121 12z"></path>
            </svg>
          </div>
        </div>
      </div>

      {/* Analytics Charts */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        <div className="glass-card p-6 rounded-2xl border border-white/5 flex flex-col">
          <h3 className="font-extrabold text-sm text-gray-200 mb-6 uppercase tracking-wider">Risk Category Distribution</h3>
          <div className="flex-1 min-h-[260px] flex items-center justify-center">
            {stats.total_scans > 0 ? (
              <StatsChart type="pie" data={stats.by_category} />
            ) : (
              <p className="text-xs text-gray-500">No scan diagnostics history to plot.</p>
            )}
          </div>
        </div>

        <div className="glass-card p-6 rounded-2xl border border-white/5 flex flex-col">
          <h3 className="font-extrabold text-sm text-gray-200 mb-6 uppercase tracking-wider">Modality Activity Runs</h3>
          <div className="flex-1 min-h-[260px] flex items-center justify-center">
            {stats.total_scans > 0 ? (
              <StatsChart type="bar" data={stats.by_type} />
            ) : (
              <p className="text-xs text-gray-500">No active scans across channels.</p>
            )}
          </div>
        </div>
      </div>

      {/* Recent activity logs */}
      <div className="glass-card p-6 rounded-2xl border border-white/5">
        <div className="flex justify-between items-center mb-6">
          <h3 className="font-extrabold text-sm text-gray-200 uppercase tracking-wider">Recent Diagnostic Events</h3>
          <Link to="/history" className="text-xs text-indigo-400 hover:text-indigo-300 transition">View History →</Link>
        </div>

        {recentScans.length > 0 ? (
          <div className="overflow-x-auto">
            <table className="w-full text-left border-collapse">
              <thead>
                <tr className="border-b border-gray-800 text-2xs uppercase tracking-widest text-gray-400">
                  <th className="pb-3 font-semibold">Channel</th>
                  <th className="pb-3 font-semibold">Analyzed Input</th>
                  <th className="pb-3 font-semibold">Verdict</th>
                  <th className="pb-3 font-semibold">Threat Score</th>
                  <th className="pb-3 font-semibold">Diagnostic Date</th>
                </tr>
              </thead>
              <tbody>
                {recentScans.map((scan) => {
                  const inputVal = scan.input_data.content || scan.input_data.url || scan.input_data.filename;
                  return (
                    <tr key={scan._id} className="border-b border-gray-900/60 hover:bg-gray-800/10 text-xs text-gray-300">
                      <td className="py-4 capitalize font-medium text-gray-400">{scan.type}</td>
                      <td className="py-4 font-mono truncate max-w-xs">{inputVal}</td>
                      <td className="py-4">
                        <ProtectionBadge category={scan.fusion_result?.category} />
                      </td>
                      <td className="py-4 font-bold">{scan.fusion_result?.final_score} / 100</td>
                      <td className="py-4 text-2xs text-gray-500">
                        {new Date(scan.created_at).toLocaleString()}
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>
        ) : (
          <div className="text-center py-8">
            <p className="text-xs text-gray-500">No threats analyzed yet. Launch a scanner to check.</p>
            <Link to="/scanner" className="inline-block mt-4 text-xs font-semibold bg-indigo-600 hover:bg-indigo-500 text-white px-4 py-2 rounded-xl transition">
              Launch Diagnostic Scanner
            </Link>
          </div>
        )}
      </div>
    </div>
  );
};
