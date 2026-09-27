import api from './api';

export const authService = {
  async login(email, password) {
    const params = new URLSearchParams();
    params.append('username', email);
    params.append('password', password);

    const res = await api.post('/api/auth/login', params, {
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' }
    });
    if (res.data && res.data.access_token) {
      localStorage.setItem('token', res.data.access_token);
    }
    return res.data;
  },

  async register(email, password) {
    const res = await api.post('/api/auth/register', { email, password });
    return res.data;
  },

  async getMe() {
    const res = await api.get('/api/auth/me');
    return res.data;
  },

  logout() {
    localStorage.removeItem('token');
  }
};

export default authService;
