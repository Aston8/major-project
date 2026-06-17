import React, { createContext, useState, useEffect, useContext } from 'react';
import axios from 'axios';

const AuthContext = createContext(null);

export const AuthProvider = ({ children }) => {
  const [user, setUser] = useState(null);
  const [token, setToken] = useState(localStorage.getItem('token'));
  const [loading, setLoading] = useState(true);

  // Configure Axios defaults when token updates
  useEffect(() => {
    if (token) {
      axios.defaults.headers.common['Authorization'] = `Bearer ${token}`;
      localStorage.setItem('token', token);
      
      // Query profile
      axios.get('/api/auth/me')
        .then(res => {
          setUser(res.data);
          setLoading(false);
        })
        .catch(err => {
          console.error("Session restoration failed:", err);
          logout();
          setLoading(false);
        });
    } else {
      delete axios.defaults.headers.common['Authorization'];
      localStorage.removeItem('token');
      setUser(null);
      setLoading(false);
    }
  }, [token]);

  const parseValidationError = (err, defaultMsg) => {
    const detail = err.response?.data?.detail;
    if (!detail) return defaultMsg;
    if (typeof detail === 'string') return detail;
    if (Array.isArray(detail) && detail.length > 0) {
      return detail.map(d => {
        const field = d.loc && d.loc.length > 0 ? d.loc[d.loc.length - 1] : '';
        return `${field ? field + ': ' : ''}${d.msg}`;
      }).join(', ');
    }
    return JSON.stringify(detail);
  };

  const login = async (email, password) => {
    setLoading(true);
    try {
      const params = new URLSearchParams();
      params.append('username', email);
      params.append('password', password);
      
      const res = await axios.post('/api/auth/login', params, {
        headers: { 'Content-Type': 'application/x-www-form-urlencoded' }
      });
      
      setToken(res.data.access_token);
      return { success: true, role: res.data.role };
    } catch (err) {
      console.error("Login request failed:", err);
      const errorMsg = parseValidationError(err, "Invalid credentials. Try again.");
      setLoading(false);
      return { success: false, error: errorMsg };
    }
  };

  const register = async (email, password) => {
    setLoading(true);
    try {
      await axios.post('/api/auth/register', { email, password });
      setLoading(false);
      return { success: true };
    } catch (err) {
      console.error("Registration failed:", err);
      const errorMsg = parseValidationError(err, "Could not register account.");
      setLoading(false);
      return { success: false, error: errorMsg };
    }
  };

  const logout = () => {
    setToken(null);
    setUser(null);
    localStorage.removeItem('token');
  };

  const value = {
    user,
    token,
    loading,
    login,
    register,
    logout,
    isAdmin: user?.role === 'admin'
  };

  return <AuthContext.Provider value={value}>{children}</AuthContext.Provider>;
};

export const useAuth = () => useContext(AuthContext);
