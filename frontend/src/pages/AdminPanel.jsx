import React, { useState, useEffect } from 'react';
import axios from 'axios';

export const AdminPanel = () => {
  const [stats, setStats] = useState(null);
  const [blacklist, setBlacklist] = useState([]);
  const [auditLogs, setAuditLogs] = useState([]);
  const [loading, setLoading] = useState(true);

  // Blacklist form inputs
  const [blackValue, setBlackValue] = useState('');
  const [blackType, setBlackType] = useState('domain');
  const [blackNotes, setBlackNotes] = useState('');
  
  const [actionLoading, setActionLoading] = useState(false);

  const fetchAdminData = async () => {
    setLoading(true);
    try {
      const statsRes = await axios.get('/api/admin/stats');
      setStats(statsRes.data);
      
      const blackRes = await axios.get('/api/admin/blacklist');
      setBlacklist(blackRes.data);
      
      const logsRes = await axios.get('/api/admin/audit-logs?limit=30');
      setAuditLogs(logsRes.data);
    } catch (err) {
      console.error("Admin dashboard loading failed:", err);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchAdminData();
  }, []);

  const handleAddBlacklist = async (e) => {
    e.preventDefault();
    setActionLoading(true);
    try {
      await axios.post('/api/admin/blacklist', {
        value: blackValue,
        type: blackType,
        notes: blackNotes
      });
      setBlackValue('');
      setBlackNotes('');
      fetchAdminData();
    } catch (err) {
      alert(err.response?.data?.detail || "Could not add blacklist item.");
    } finally {
      setActionLoading(false);
    }
  };

  const handleRemoveBlacklist = async (itemId) => {
    if (!confirm("Are you sure you want to remove this blacklist entry?")) return;
    try {
      await axios.delete(`/api/admin/blacklist/${itemId}`);
      fetchAdminData();
    } catch (err) {
      alert("Could not remove blacklist item.");
    }
  };

  if (loading && !stats) {
    return (
      <div className="flex items-center justify-center min-h-[calc(100vh-200px)]">
        <span className="w-10 h-10 border-4 border-indigo-500/20 border-t-indigo-400 rounded-full animate-spin"></span>
      </div>
    );
  }

  return (
    <div className="p-6 flex flex-col gap-6">
      <div>
        <h1 className="text-2xl font-extrabold text-white tracking-tight">Admin System Settings</h1>
        <p className="text-xs text-gray-400 mt-1">Configure global blacklists, audit logs, and monitor sandbox states</p>
      </div>

      {/* System connections info */}
      <div className="grid grid-cols-1 md:grid-cols-4 gap-6">
        <div className="glass-card p-5 rounded-2xl border border-white/5 flex flex-col gap-1.5">
          <span className="text-2xs font-semibold text-gray-400 uppercase tracking-widest">MongoDB Status</span>
          <div className="flex items-center gap-2 mt-1">
            <span className="w-2.5 h-2.5 rounded-full bg-emerald-500 shadow-sm animate-pulse"></span>
            <span className="text-sm font-bold text-gray-200">Connected</span>
          </div>
        </div>

        <div className="glass-card p-5 rounded-2xl border border-white/5 flex flex-col gap-1.5">
          <span className="text-2xs font-semibold text-gray-400 uppercase tracking-widest">Redis Status</span>
          <div className="flex items-center gap-2 mt-1">
            {stats?.redis_connected ? (
              <>
                <span className="w-2.5 h-2.5 rounded-full bg-emerald-500 shadow-sm animate-pulse"></span>
                <span className="text-sm font-bold text-gray-200">Connected Cache</span>
              </>
            ) : (
              <>
                <span className="w-2.5 h-2.5 rounded-full bg-amber-500 shadow-sm"></span>
                <span className="text-sm font-bold text-gray-300">In-Memory Fallback</span>
              </>
            )}
          </div>
        </div>

        <div className="glass-card p-5 rounded-2xl border border-white/5 flex flex-col gap-1.5">
          <span className="text-2xs font-semibold text-gray-400 uppercase tracking-widest">Docker sandbox agents</span>
          <div className="flex items-center gap-2 mt-1">
            <span className="w-2.5 h-2.5 rounded-full bg-indigo-500 shadow-sm"></span>
            <span className="text-sm font-bold text-gray-200">{stats?.active_sandbox_containers || 0} Containers Active</span>
          </div>
        </div>

        <div className="glass-card p-5 rounded-2xl border border-white/5 flex flex-col gap-1.5">
          <span className="text-2xs font-semibold text-gray-400 uppercase tracking-widest">Total Registered Users</span>
          <div className="flex items-center gap-2 mt-1">
            <span className="w-2.5 h-2.5 rounded-full bg-sky-500 shadow-sm"></span>
            <span className="text-sm font-bold text-gray-200">{stats?.total_users || 0} Registered</span>
          </div>
        </div>
      </div>

      {/* Blacklist and Logs panels */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6 items-start">
        {/* Blacklist configurations */}
        <div className="lg:col-span-1 flex flex-col gap-6">
          <div className="glass-card p-6 rounded-2xl border border-white/5 flex flex-col gap-4">
            <h3 className="font-extrabold text-sm text-gray-200 uppercase tracking-wider">Configure Custom Blacklist</h3>
            <form onSubmit={handleAddBlacklist} className="flex flex-col gap-4">
              <div className="flex flex-col gap-1.5">
                <label className="text-2xs font-bold uppercase tracking-wider text-gray-400">Blacklist Value</label>
                <input
                  type="text"
                  value={blackValue}
                  onChange={(e) => setBlackValue(e.target.value)}
                  required
                  placeholder="e.g. malwaredomain.com, OTP, 192.168.1.1"
                  className="w-full px-4 py-2.5 rounded-lg bg-cyber-bg border border-gray-800 text-xs text-gray-200 focus:outline-none focus:border-indigo-500/50 transition"
                />
              </div>

              <div className="flex flex-col gap-1.5">
                <label className="text-2xs font-bold uppercase tracking-wider text-gray-400">Match Type</label>
                <select
                  value={blackType}
                  onChange={(e) => setBlackType(e.target.value)}
                  className="w-full px-4 py-2.5 rounded-lg bg-cyber-bg border border-gray-800 text-xs text-gray-200 focus:outline-none focus:border-indigo-500/50 transition"
                >
                  <option value="domain">Domain / URL Host</option>
                  <option value="keyword">Keyword Text</option>
                  <option value="ip">IP Address</option>
                </select>
              </div>

              <div className="flex flex-col gap-1.5">
                <label className="text-2xs font-bold uppercase tracking-wider text-gray-400">Rule Notes (Description)</label>
                <input
                  type="text"
                  value={blackNotes}
                  onChange={(e) => setBlackNotes(e.target.value)}
                  placeholder="e.g. Known Phishing site for Paypal clone"
                  className="w-full px-4 py-2.5 rounded-lg bg-cyber-bg border border-gray-800 text-xs text-gray-200 focus:outline-none focus:border-indigo-500/50 transition"
                />
              </div>

              <button
                type="submit"
                disabled={actionLoading}
                className="w-full py-2.5 rounded-lg bg-rose-600 hover:bg-rose-500 text-white font-semibold text-xs tracking-wide transition flex items-center justify-center gap-1.5 disabled:opacity-50"
              >
                <span>Add Security Rule</span>
              </button>
            </form>
          </div>

          <div className="glass-card p-6 rounded-2xl border border-white/5 flex flex-col gap-4">
            <h3 className="font-extrabold text-sm text-gray-200 uppercase tracking-wider">Active Blacklist Rules</h3>
            <div className="flex flex-col gap-2 max-h-72 overflow-y-auto pr-1">
              {blacklist.length > 0 ? (
                blacklist.map((item) => (
                  <div key={item._id} className="p-3 bg-gray-900/30 border border-gray-800 rounded-lg flex items-center justify-between text-2xs">
                    <div className="flex flex-col gap-1 truncate pr-2">
                      <span className="font-mono text-gray-200 font-bold truncate">{item.value}</span>
                      <span className="text-gray-500 font-light truncate">{item.notes || 'No notes specified'}</span>
                      <span className="text-indigo-400 font-semibold uppercase">{item.type}</span>
                    </div>
                    <button
                      onClick={() => handleRemoveBlacklist(item._id)}
                      className="text-red-400 hover:text-red-300 font-semibold"
                    >
                      Delete
                    </button>
                  </div>
                ))
              ) : (
                <span className="text-2xs text-gray-500 text-center py-4">No custom rules active.</span>
              )}
            </div>
          </div>
        </div>

        {/* Audit logging */}
        <div className="lg:col-span-2 glass-card p-6 rounded-2xl border border-white/5">
          <h3 className="font-extrabold text-sm text-gray-200 uppercase tracking-wider mb-6">Security Audit Logs</h3>
          <div className="overflow-x-auto">
            <table className="w-full text-left border-collapse">
              <thead>
                <tr className="border-b border-gray-800 text-2xs uppercase tracking-widest text-gray-400">
                  <th className="pb-3 font-semibold">Admin / User</th>
                  <th className="pb-3 font-semibold">Action Trigger</th>
                  <th className="pb-3 font-semibold">Audit Details</th>
                  <th className="pb-3 font-semibold">Log Timestamp</th>
                </tr>
              </thead>
              <tbody>
                {auditLogs.map((log) => (
                  <tr key={log._id} className="border-b border-gray-900/60 hover:bg-gray-800/10 text-2xs text-gray-300">
                    <td className="py-3.5 font-medium text-gray-400 truncate max-w-[120px]" title={log.user_email}>{log.user_email}</td>
                    <td className="py-3.5">
                      <span className="px-2 py-0.5 rounded bg-indigo-500/10 text-indigo-400 border border-indigo-500/20 text-3xs font-semibold uppercase">
                        {log.action}
                      </span>
                    </td>
                    <td className="py-3.5 font-light text-gray-400 max-w-xs truncate" title={log.details}>{log.details}</td>
                    <td className="py-3.5 text-gray-500">{new Date(log.created_at).toLocaleString()}</td>
                  </tr>
                ))}
              </tbody>
            </table>
            {auditLogs.length === 0 && (
              <p className="text-xs text-gray-500 py-8 text-center">No system events logged.</p>
            )}
          </div>
        </div>
      </div>
    </div>
  );
};
