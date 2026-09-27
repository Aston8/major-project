import axios from 'axios';

const api = axios.create({
  baseURL: '',
  headers: {
    'Accept': 'application/json'
  }
});

// Request interceptor to attach JWT token
api.interceptors.request.use(
  (config) => {
    const token = localStorage.getItem('token');
    if (token) {
      config.headers['Authorization'] = `Bearer ${token}`;
    }
    return config;
  },
  (error) => Promise.reject(error)
);

// Response interceptor to handle 401 unauthenticated
api.interceptors.response.use(
  (response) => response,
  (error) => {
    if (error.response && error.response.status === 401) {
      // Auto-clear invalid token
      localStorage.removeItem('token');
    }
    return Promise.reject(error);
  }
);

export default api;
