import api from './api';

export const investigationService = {
  // 1. Text scan
  async scanText(content, sourceType = 'SMS') {
    const res = await api.post('/api/scans/text', {
      content,
      source_type: sourceType
    });
    return res.data;
  },

  // 2. Image scan
  async scanImage(file) {
    const formData = new FormData();
    formData.append('file', file);
    const res = await api.post('/api/scans/image', formData);
    return res.data;
  },

  // 3. Voice scan
  async scanVoice(file) {
    const formData = new FormData();
    formData.append('file', file);
    const res = await api.post('/api/scans/voice', formData);
    return res.data;
  },

  // 4. Multimodal / Unified scan
  async scanUnified({ text, image, audio }) {
    const formData = new FormData();
    if (text) formData.append('text', text);
    if (image) formData.append('image', image);
    if (audio) formData.append('audio', audio);

    const res = await api.post('/api/scans/unified', formData);
    return res.data;
  },

  // 5. Website Sandbox interactive session audit
  async auditSandboxSession({ url, events = [], page_text = '', page_title = '' }) {
    const res = await api.post('/api/scans/sandbox/audit-session', {
      url,
      events,
      page_text,
      page_title
    });
    return res.data;
  }
};

export default investigationService;
