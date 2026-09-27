import api from './api';

export const historyService = {
  async getScanHistory({ skip = 0, limit = 50, scan_type = null, category = null, q = null } = {}) {
    const params = new URLSearchParams();
    params.append('skip', skip);
    params.append('limit', limit);
    if (scan_type && scan_type !== 'ALL') params.append('scan_type', scan_type.toLowerCase());
    if (category && category !== 'ALL') params.append('category', category);
    if (q) params.append('q', q);

    const res = await api.get(`/api/scans/history?${params.toString()}`);
    return res.data;
  },

  async getScanReport(scanId) {
    const res = await api.get(`/api/scans/report/${scanId}`);
    return res.data;
  }
};

export default historyService;
