import React, { useState, useEffect } from 'react';
import LandingPage from './pages/LandingPage';
import Investigate from './pages/Investigate';
import HistoryPage from './pages/HistoryPage';
import Sidebar from './components/Sidebar';
import TopBar from './components/TopBar';
import GlobalSearchModal from './components/GlobalSearchModal';
import InvestigationDetailModal from './components/InvestigationDetailModal';
import { historyService } from './services/historyService';
import { formatScanDocument } from './services/formatters';

export function App() {
  const [viewMode, setViewMode] = useState('app'); // 'landing' or 'app'
  const [activeTab, setActiveTab] = useState('investigate'); // 'investigate' or 'history'
  const [isSidebarOpen, setIsSidebarOpen] = useState(false);
  const [isSearchOpen, setIsSearchOpen] = useState(false);
  const [selectedInvestigation, setSelectedInvestigation] = useState(null);
  const [investigations, setInvestigations] = useState([]);

  // Sync real database scan history for search modal
  useEffect(() => {
    historyService.getScanHistory(50)
      .then(res => {
        if (res && res.results && res.results.length > 0) {
          const formatted = res.results.map(formatScanDocument).filter(Boolean);
          setInvestigations(formatted);
        }
      })
      .catch(err => {
        console.log('Search index sync notice:', err);
      });
  }, [activeTab]);

  const handleSaveNewInvestigation = (newInv) => {
    const formatted = formatScanDocument(newInv) || newInv;
    setInvestigations(prev => [formatted, ...prev]);
  };

  if (viewMode === 'landing') {
    return <LandingPage onEnterApp={() => setViewMode('app')} />;
  }

  return (
    <div className="min-h-screen bg-[#F7F7F5] text-[#111111] font-sans antialiased flex selection:bg-[#111111] selection:text-white">
      {/* Persistent Left Sidebar: INVESTIGATE & HISTORY only */}
      <Sidebar
        activeTab={activeTab}
        setActiveTab={setActiveTab}
        isOpen={isSidebarOpen}
        setIsOpen={setIsSidebarOpen}
      />

      {/* Main Content Workspace */}
      <div className="flex-1 flex flex-col min-w-0 lg:pl-64">
        {/* Top Header Bar */}
        <TopBar
          onOpenSearch={() => setIsSearchOpen(true)}
          onToggleSidebar={() => setIsSidebarOpen(!isSidebarOpen)}
          activeTab={activeTab}
        />

        {/* Page Content Body */}
        <main className="flex-1 p-4 md:p-8 max-w-7xl w-full mx-auto space-y-8">
          {activeTab === 'investigate' && (
            <Investigate
              onSaveNewInvestigation={handleSaveNewInvestigation}
            />
          )}

          {activeTab === 'history' && (
            <HistoryPage
              onSelectInvestigation={(inv) => setSelectedInvestigation(inv)}
            />
          )}
        </main>
      </div>

      {/* Global Search Modal (Cmd + K) */}
      <GlobalSearchModal
        isOpen={isSearchOpen}
        onClose={() => setIsSearchOpen(false)}
        investigations={investigations}
        onSelectInvestigation={(inv) => setSelectedInvestigation(inv)}
      />

      {/* Investigation Detail Modal */}
      {selectedInvestigation && (
        <InvestigationDetailModal
          investigation={selectedInvestigation}
          onClose={() => setSelectedInvestigation(null)}
        />
      )}
    </div>
  );
}

export default App;
