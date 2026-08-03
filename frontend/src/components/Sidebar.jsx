import React from 'react';
import { NavLink } from 'react-router-dom';
import { useAuth } from '../context/AuthContext';

export const Sidebar = () => {
  const { user } = useAuth();
  
  const navItems = [
    {
      name: 'Security Scanners',
      path: '/',
      icon: (
        <svg className="w-5 h-5" fill="none" stroke="currentColor" strokeWidth="2" viewBox="0 0 24 24">
          <path strokeLinecap="round" strokeLinejoin="round" d="M21 21l-5.197-5.197m0 0A7.5 7.5 0 105.196 5.196a7.5 7.5 0 0010.637 10.637zM12 9.75v3.5m0 0H8.5m3.5 0h3.5"></path>
        </svg>
      )
    },
    {
      name: 'Scan History',
      path: '/history',
      icon: (
        <svg className="w-5 h-5" fill="none" stroke="currentColor" strokeWidth="2" viewBox="0 0 24 24">
          <path strokeLinecap="round" strokeLinejoin="round" d="M9 12h3.75M9 15h3.375M9 9h3.75M16.5 21.75V3.375c0-.621-.504-1.125-1.125-1.125H3.75c-.621 0-1.125.504-1.125 1.125v18.375c0 .621.504 1.125 1.125 1.125h11.625c.621 0 1.125-.504 1.125-1.125zM16.5 21.75V3.375c0-.621.504-1.125 1.125-1.125h2.25c.621 0 1.125.504 1.125 1.125V21.75c0 .621-.504 1.125-1.125 1.125h-2.25c-.621 0-1.125-.504-1.125-1.125z"></path>
        </svg>
      )
    }
  ];

  if (user?.role === 'admin') {
    navItems.push({
      name: 'Admin Panel',
      path: '/admin',
      icon: (
        <svg className="w-5 h-5" fill="none" stroke="currentColor" strokeWidth="2" viewBox="0 0 24 24">
          <path strokeLinecap="round" strokeLinejoin="round" d="M10.343 3.94c.09-.542.56-.94 1.11-.94h1.093c.557 0 1.02.398 1.11.94l.149.894c.07.424.384.764.78.93.398.164.855.142 1.205-.108l.737-.527a1.125 1.125 0 011.45.12l.773.774c.39.39.43 1.007.093 1.45l-.526.737c-.25.35-.272.806-.107 1.204.165.397.505.71.93.78l.893.15c.543.09.94.56.94 1.109v1.094c0 .557-.397 1.02-.94 1.11l-.893.149c-.425.07-.765.383-.93.78-.165.398-.143.854.107 1.204l.527.738c.337.443.297 1.06-.093 1.45l-.774.773a1.125 1.125 0 01-1.449.093l-.738-.527c-.35-.25-.806-.272-1.203-.107-.397.165-.71.505-.78.93l-.15.893c-.09.543-.56.94-1.11.94h-1.094c-.557 0-1.02-.397-1.11-.94l-.148-.893c-.07-.425-.383-.765-.78-.93-.398-.165-.854-.143-1.204.107l-.738.527c-.442.337-1.06.297-1.45-.093l-.773-.774a1.125 1.125 0 01-.093-1.449l.527-.738c.25-.35.272-.806.108-1.203-.165-.397-.505-.71-.93-.78l-.894-.15c-.542-.09-.94-.56-.94-1.11v-1.094c0-.557.398-1.02.94-1.11l.894-.149c.424-.07.765-.383.93-.78.165-.398.143-.854-.107-1.204l-.527-.738a1.125 1.125 0 01.093-1.45l.774-.773a1.125 1.125 0 011.449-.093l.738.527c.35.25.806.272 1.204.107.397-.165.71-.505.78-.93l.15-.894z"></path>
          <path strokeLinecap="round" strokeLinejoin="round" d="M15 12a3 3 0 11-6 0 3 3 0 016 0z"></path>
        </svg>
      )
    });
  }

  return (
    <aside className="w-64 glass-card min-h-[calc(100vh-73px)] p-4 flex flex-col gap-2">
      <div className="px-3 py-4 text-xs font-semibold text-gray-500 uppercase tracking-widest">
        Security Menu
      </div>
      
      {navItems.map((item, index) => (
        <NavLink
          key={index}
          to={item.path}
          className={({ isActive }) =>
            `flex items-center gap-3 px-4 py-3 rounded-xl text-sm font-medium transition ${
              isActive
                ? 'bg-indigo-500/10 text-indigo-400 border border-indigo-500/20 glow-primary'
                : 'text-gray-400 hover:text-gray-200 hover:bg-gray-800/30 border border-transparent'
            }`
          }
        >
          {item.icon}
          <span>{item.name}</span>
        </NavLink>
      ))}

      <div className="mt-auto p-4 bg-indigo-950/20 border border-indigo-900/30 rounded-2xl flex flex-col gap-2">
        <div className="flex items-center gap-2 text-indigo-400">
          <svg className="w-5 h-5 text-indigo-400 pulse-cyber" fill="none" stroke="currentColor" strokeWidth="2" viewBox="0 0 24 24">
            <path strokeLinecap="round" strokeLinejoin="round" d="M9 12.75L11.25 15 15 9.75m-3-7.036A11.959 11.959 0 013.598 6 11.99 11.99 0 003 9.749c0 5.592 3.824 10.29 9 11.622 5.176-1.332 9-6.03 9-11.622 0-1.31-.21-2.57-.598-3.75h-.152c-3.196 0-6.1-1.248-8.25-3.285z"></path>
          </svg>
          <span className="text-xs font-bold uppercase tracking-wider">Shield Status</span>
        </div>
        <p className="text-2xs text-gray-500 leading-normal">
          Multi-Model AI and Container Sandboxing active. Protection status online.
        </p>
      </div>
    </aside>
  );
};
