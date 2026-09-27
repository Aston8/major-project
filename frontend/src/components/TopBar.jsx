import React, { useState } from 'react';
import { Search, Menu, Bell, Command, ChevronDown, LogOut } from 'lucide-react';
import { useAuth } from '../context/AuthContext';

export const TopBar = ({ onOpenSearch, onToggleSidebar, activeTab }) => {
  const [showProfileMenu, setShowProfileMenu] = useState(false);
  const { user, logout } = useAuth();

  const userInitials = user?.email 
    ? user.email.slice(0, 2).toUpperCase() 
    : 'AM';

  const handleSignOut = () => {
    setShowProfileMenu(false);
    logout();
  };

  return (
    <header className="h-16 bg-[#FFFFFF] border-b border-[#E5E5E5] px-4 md:px-8 flex items-center justify-between sticky top-0 z-30 font-sans">
      {/* Mobile Toggle & Search */}
      <div className="flex items-center gap-3 flex-1 max-w-xl">
        <button 
          onClick={onToggleSidebar}
          className="lg:hidden p-2 text-[#6B6B6B] hover:text-[#111111] hover:bg-[#F7F7F5] rounded-lg cursor-pointer"
        >
          <Menu className="w-5 h-5" />
        </button>

        {/* Global Search Input Trigger */}
        <button
          onClick={onOpenSearch}
          className="w-full flex items-center justify-between px-3.5 py-2 rounded-xl bg-[#F7F7F5] border border-[#E5E5E5] text-[#6B6B6B] hover:border-[#D4D4D4] hover:bg-[#F0F0EE] transition-all text-xs font-mono group cursor-pointer"
        >
          <div className="flex items-center gap-2.5">
            <Search className="w-4 h-4 text-[#6B6B6B] group-hover:text-[#111111] transition-colors" />
            <span className="hidden sm:inline">Search investigations, domains, IOCs...</span>
            <span className="sm:hidden">Search...</span>
          </div>
          <kbd className="hidden sm:inline-flex items-center gap-1 px-1.5 py-0.5 rounded border border-[#E5E5E5] bg-white text-[10px] font-mono text-[#6B6B6B] shadow-2xs">
            <Command className="w-3 h-3" /> K
          </kbd>
        </button>
      </div>

      {/* Right Controls */}
      <div className="flex items-center gap-4">
        {/* Operational Badge */}
        <div className="hidden sm:flex items-center gap-2 px-3 py-1.5 rounded-full bg-emerald-500/10 border border-emerald-500/25 text-emerald-700 text-xs font-mono font-medium">
          <span className="relative flex h-2 w-2">
            <span className="animate-ping absolute inline-flex h-full w-full rounded-full bg-emerald-400 opacity-75"></span>
            <span className="relative inline-flex rounded-full h-2 w-2 bg-emerald-500"></span>
          </span>
          SYSTEM OPERATIONAL
        </div>

        {/* Notification Bell */}
        <button className="relative p-2 text-[#6B6B6B] hover:text-[#111111] hover:bg-[#F7F7F5] rounded-xl transition-colors cursor-pointer">
          <Bell className="w-4 h-4" />
          <span className="absolute top-1.5 right-1.5 w-2 h-2 rounded-full bg-emerald-500"></span>
        </button>

        {/* Profile Avatar & Dropdown (ONLY Sign Out) */}
        <div className="relative">
          <button 
            onClick={() => setShowProfileMenu(!showProfileMenu)}
            className="flex items-center gap-2 p-1 rounded-xl hover:bg-[#F7F7F5] transition-colors cursor-pointer"
          >
            <div className="w-8 h-8 rounded-full bg-[#111111] text-white font-bold flex items-center justify-center text-xs shadow-2xs">
              {userInitials}
            </div>
            <ChevronDown className="w-3.5 h-3.5 text-[#6B6B6B]" />
          </button>

          {showProfileMenu && (
            <div 
              className="absolute right-0 mt-2 w-44 bg-white border border-[#E5E5E5] rounded-xl shadow-xl p-1.5 z-50 text-xs font-mono animate-in fade-in slide-in-from-top-1 duration-150"
              onMouseLeave={() => setShowProfileMenu(false)}
            >
              <button 
                onClick={handleSignOut}
                className="w-full flex items-center gap-2 px-3 py-2.5 hover:bg-red-50 text-red-600 rounded-lg font-bold text-left transition-colors cursor-pointer"
              >
                <LogOut className="w-4 h-4" />
                <span>Sign Out</span>
              </button>
            </div>
          )}
        </div>
      </div>
    </header>
  );
};

export default TopBar;
