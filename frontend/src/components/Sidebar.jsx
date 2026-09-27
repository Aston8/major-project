import React from 'react';
import { Search, History, X } from 'lucide-react';

export const Sidebar = ({ activeTab, setActiveTab, isOpen, setIsOpen }) => {
  const navItems = [
    { id: 'investigate', label: 'INVESTIGATE', icon: Search, badge: '5 MODES' },
    { id: 'history', label: 'HISTORY', icon: History }
  ];

  return (
    <>
      {/* Mobile Backdrop */}
      {isOpen && (
        <div 
          className="fixed inset-0 bg-black/40 backdrop-blur-sm z-40 lg:hidden"
          onClick={() => setIsOpen(false)}
        />
      )}

      {/* Sidebar Container */}
      <aside className={`
        fixed top-0 left-0 bottom-0 z-50 w-64 bg-[#FFFFFF] border-r border-[#E5E5E5] flex flex-col justify-between font-sans
        transition-transform duration-300 ease-in-out lg:translate-x-0
        ${isOpen ? 'translate-x-0' : '-translate-x-full'}
      `}>
        <div>
          {/* Brand Header */}
          <div className="h-16 px-6 flex items-center justify-between border-b border-[#E5E5E5]">
            <div 
              className="flex items-center gap-2.5 cursor-pointer group"
              onClick={() => { setActiveTab('investigate'); if (setIsOpen) setIsOpen(false); }}
            >
              <div className="w-8 h-8 rounded-lg bg-[#111111] text-white flex items-center justify-center font-bold text-lg shadow-sm group-hover:bg-black transition-colors">
                ◈
              </div>
              <div>
                <span className="font-bold text-sm tracking-wider text-[#111111] block leading-none font-mono">
                  SHIELD AI
                </span>
                <span className="text-[9px] font-mono tracking-widest text-[#6B6B6B] block mt-1 uppercase">
                  Threat Intelligence
                </span>
              </div>
            </div>
            {setIsOpen && (
              <button 
                className="lg:hidden text-[#6B6B6B] hover:text-[#111111] p-1 cursor-pointer"
                onClick={() => setIsOpen(false)}
              >
                <X className="w-5 h-5" />
              </button>
            )}
          </div>

          {/* Navigation Items */}
          <nav className="p-4 space-y-1">
            <div className="px-3 py-2 text-[10px] font-mono font-medium tracking-widest text-[#6B6B6B] uppercase">
              Investigation Platform
            </div>
            
            {navItems.map((item) => {
              const Icon = item.icon;
              const isActive = activeTab === item.id;
              
              return (
                <button
                  key={item.id}
                  onClick={() => {
                    if (setActiveTab) setActiveTab(item.id);
                    if (setIsOpen) setIsOpen(false);
                  }}
                  className={`
                    w-full flex items-center justify-between px-3 py-2.5 rounded-xl text-xs font-mono tracking-wider transition-all duration-150 cursor-pointer
                    ${isActive 
                      ? 'bg-[#111111] text-white font-medium shadow-sm' 
                      : 'text-[#6B6B6B] hover:text-[#111111] hover:bg-[#F7F7F5]'
                    }
                  `}
                >
                  <div className="flex items-center gap-3">
                    <Icon className={`w-4 h-4 ${isActive ? 'text-white' : 'text-[#6B6B6B]'}`} />
                    <span>{item.label}</span>
                  </div>
                  {item.badge && (
                    <span className={`text-[9px] px-1.5 py-0.5 rounded font-mono font-semibold ${
                      isActive ? 'bg-white/20 text-white' : 'bg-[#F0F0EE] text-[#111111]'
                    }`}>
                      {item.badge}
                    </span>
                  )}
                </button>
              );
            })}
          </nav>
        </div>
      </aside>
    </>
  );
};

export default Sidebar;
