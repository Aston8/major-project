import React from 'react';
import { BrowserRouter, Routes, Route, Navigate } from 'react-router-dom';
import { AuthProvider, useAuth } from './context/AuthContext';
import { Navbar } from './components/Navbar';
import { Sidebar } from './components/Sidebar';
import { Login } from './pages/Login';
import { Register } from './pages/Register';
import { Dashboard } from './pages/Dashboard';
import { Scanner } from './pages/Scanner';
import { ScanHistory } from './pages/ScanHistory';
import { AdminPanel } from './pages/AdminPanel';

// Protected Route Guard
const ProtectedRoute = ({ children }) => {
  const { token, loading } = useAuth();
  
  if (loading) {
    return (
      <div className="min-h-screen flex items-center justify-center bg-cyber-bg text-gray-400">
        <span className="w-8 h-8 border-4 border-indigo-500/20 border-t-indigo-400 rounded-full animate-spin"></span>
      </div>
    );
  }
  
  if (!token) {
    return <Navigate to="/login" replace />;
  }
  
  return children;
};

// Admin Route Guard
const AdminRoute = ({ children }) => {
  const { token, user, loading } = useAuth();
  
  if (loading) {
    return (
      <div className="min-h-screen flex items-center justify-center bg-cyber-bg text-gray-400">
        <span className="w-8 h-8 border-4 border-indigo-500/20 border-t-indigo-400 rounded-full animate-spin"></span>
      </div>
    );
  }
  
  if (!token || user?.role !== 'admin') {
    return <Navigate to="/" replace />;
  }
  
  return children;
};

// Application shell layout
const AppLayout = () => {
  return (
    <div className="flex flex-col min-h-screen bg-cyber-bg">
      <Navbar />
      <div className="flex flex-1">
        <Sidebar />
        <main className="flex-1 bg-cyber-bg overflow-y-auto">
          <Routes>
            <Route path="/" element={<Dashboard />} />
            <Route path="/scanner" element={<Scanner />} />
            <Route path="/history" element={<ScanHistory />} />
            <Route path="/admin" element={<AdminRoute><AdminPanel /></AdminRoute>} />
            <Route path="*" element={<Navigate to="/" replace />} />
          </Routes>
        </main>
      </div>
    </div>
  );
};

function App() {
  return (
    <BrowserRouter>
      <AuthProvider>
        <Routes>
          <Route path="/login" element={<Login />} />
          <Route path="/register" element={<Register />} />
          <Route path="/*" element={<ProtectedRoute><AppLayout /></ProtectedRoute>} />
        </Routes>
      </AuthProvider>
    </BrowserRouter>
  );
}

export default App;
