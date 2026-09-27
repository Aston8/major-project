import React from 'react';
import { ArrowRight, ShieldCheck, Globe, Dna, GitBranch, Layers, Lock, Cpu, Sparkles } from 'lucide-react';

export const LandingPage = ({ onEnterApp }) => {
  return (
    <div className="min-h-screen bg-[#F7F7F5] text-[#111111] font-sans selection:bg-[#111111] selection:text-white">
      {/* Landing Navbar */}
      <header className="h-20 border-b border-[#E5E5E5] bg-white/80 backdrop-blur-md sticky top-0 z-40 px-6 lg:px-16 flex items-center justify-between">
        {/* Brand */}
        <div className="flex items-center gap-3 cursor-pointer" onClick={onEnterApp}>
          <div className="w-9 h-9 rounded-xl bg-[#111111] text-white flex items-center justify-center font-bold text-xl shadow-md">
            ◈
          </div>
          <span className="font-bold text-lg tracking-wider text-[#111111] font-mono">
            SHIELD AI
          </span>
        </div>

        {/* Navigation Links */}
        <nav className="hidden md:flex items-center gap-8 text-xs font-mono font-medium text-[#6B6B6B]">
          <a href="#platform" className="hover:text-[#111111] transition-colors">Platform</a>
          <a href="#intelligence" className="hover:text-[#111111] transition-colors">Intelligence</a>
          <a href="#sandbox" className="hover:text-[#111111] transition-colors">Sandbox</a>
          <a href="#about" className="hover:text-[#111111] transition-colors">About</a>
        </nav>

        {/* Right CTA */}
        <div className="flex items-center gap-4">
          <button 
            onClick={onEnterApp}
            className="text-xs font-mono font-semibold text-[#6B6B6B] hover:text-[#111111] px-3 py-2 transition-colors cursor-pointer"
          >
            Sign In
          </button>
          <button 
            onClick={onEnterApp}
            className="px-5 py-2.5 rounded-xl bg-[#111111] text-white font-mono text-xs font-bold hover:bg-black transition-all shadow-md flex items-center gap-2 group cursor-pointer"
          >
            <span>Get Started</span>
            <ArrowRight className="w-3.5 h-3.5 group-hover:translate-x-1 transition-transform" />
          </button>
        </div>
      </header>

      {/* HERO SECTION */}
      <section className="py-20 lg:py-28 px-6 lg:px-16 max-w-7xl mx-auto text-center space-y-8">
        <div className="inline-flex items-center gap-2 px-3.5 py-1.5 rounded-full bg-white border border-[#E5E5E5] text-xs font-mono font-semibold text-[#111111] shadow-2xs">
          <span className="w-2 h-2 rounded-full bg-blue-600 animate-pulse"></span>
          MULTIMODAL SCAM INTELLIGENCE PLATFORM v2.4
        </div>

        <h1 className="text-4xl md:text-6xl lg:text-7xl font-bold tracking-tight text-[#111111] max-w-4xl mx-auto leading-[1.08]">
          Understand the scam.<br />
          <span className="text-[#6B6B6B] font-light">Before it understands you.</span>
        </h1>

        <p className="text-base md:text-xl text-[#6B6B6B] max-w-2xl mx-auto font-sans leading-relaxed">
          Multimodal AI that analyzes messages, images, voice and live websites in an isolated sandbox to uncover the hidden signals behind digital scams.
        </p>

        <div className="flex flex-col sm:flex-row items-center justify-center gap-4 pt-4">
          <button 
            onClick={onEnterApp}
            className="w-full sm:w-auto px-8 py-4 rounded-2xl bg-[#111111] text-white font-mono font-bold text-sm hover:bg-black shadow-xl hover:shadow-2xl transition-all flex items-center justify-center gap-3 group cursor-pointer"
          >
            <span>Analyze a Threat</span>
            <ArrowRight className="w-4 h-4 group-hover:translate-x-1 transition-transform" />
          </button>
          <button 
            onClick={onEnterApp}
            className="w-full sm:w-auto px-8 py-4 rounded-2xl bg-white text-[#111111] font-mono font-bold text-sm border border-[#E5E5E5] hover:border-[#111111] shadow-sm transition-all cursor-pointer"
          >
            Explore Platform Workspace
          </button>
        </div>

        {/* Threat-Intelligence Network Diagram below Hero */}
        <div className="pt-16 max-w-4xl mx-auto">
          <div className="shield-dark-panel p-8 rounded-3xl relative overflow-hidden text-center shadow-2xl">
            <div className="absolute inset-0 dark-grid-pattern opacity-20"></div>
            
            <div className="text-[10px] font-mono font-bold tracking-widest text-gray-400 uppercase mb-8">
              THREAT INTELLIGENCE NEURAL ENGINE ARCHITECTURE
            </div>

            {/* Network Nodes Diagram */}
            <div className="relative z-10 font-mono text-xs font-bold">
              <div className="grid grid-cols-4 gap-4 max-w-2xl mx-auto text-white mb-8">
                <div className="p-3 rounded-xl bg-white/10 border border-white/10 flex items-center justify-center gap-2">
                  <span>TEXT</span>
                </div>
                <div className="p-3 rounded-xl bg-white/10 border border-white/10 flex items-center justify-center gap-2">
                  <span>IMAGE</span>
                </div>
                <div className="p-3 rounded-xl bg-white/10 border border-white/10 flex items-center justify-center gap-2">
                  <span>VOICE</span>
                </div>
                <div className="p-3 rounded-xl bg-white/10 border border-white/10 flex items-center justify-center gap-2">
                  <span>WEBSITE</span>
                </div>
              </div>

              {/* Animated Lines */}
              <div className="w-full h-12 flex items-center justify-center text-blue-400">
                <div className="w-64 h-[2px] bg-gradient-to-r from-blue-500/20 via-blue-500 to-blue-500/20 animate-pulse"></div>
              </div>

              {/* Central Threat Intelligence Hub */}
              <div className="inline-flex items-center gap-3 px-8 py-4 rounded-2xl bg-blue-600 text-white font-bold text-sm shadow-xl border border-blue-400">
                <Cpu className="w-5 h-5 animate-spin-slow" />
                <span>THREAT INTELLIGENCE FUSION CORE</span>
              </div>
            </div>
          </div>
        </div>
      </section>

      {/* FEATURE HIGHLIGHTS */}
      <section id="platform" className="py-20 px-6 lg:px-16 max-w-7xl mx-auto space-y-12">
        <div className="text-center space-y-3">
          <div className="text-[10px] font-mono font-bold tracking-widest text-[#6B6B6B] uppercase">
            ENTERPRISE THREAT INVESTIGATION
          </div>
          <h2 className="text-3xl lg:text-4xl font-bold tracking-tight text-[#111111]">
            Built like a modern SOC digital forensics suite.
          </h2>
        </div>

        <div className="grid grid-cols-1 md:grid-cols-3 gap-8">
          <div className="shield-card p-8 space-y-4">
            <div className="w-12 h-12 rounded-2xl bg-[#111111] text-white flex items-center justify-center font-bold text-xl">
              ✦
            </div>
            <h3 className="text-lg font-bold font-mono text-[#111111]">Multimodal Fusion</h3>
            <p className="text-xs text-[#6B6B6B] leading-relaxed font-sans">
              Combine screenshot image, SMS message text, voice call note, and suspicious domain URL into one unified correlated investigation.
            </p>
          </div>

          <div className="shield-card p-8 space-y-4">
            <div className="w-12 h-12 rounded-2xl bg-[#111111] text-white flex items-center justify-center font-bold text-xl">
              ◈
            </div>
            <h3 className="text-lg font-bold font-mono text-[#111111]">Isolated Website Sandbox</h3>
            <p className="text-xs text-[#6B6B6B] leading-relaxed font-sans">
              Safely render and analyze suspect URLs in a containerized workstation with DOM clone similarity detection and script inspection.
            </p>
          </div>

          <div className="shield-card p-8 space-y-4">
            <div className="w-12 h-12 rounded-2xl bg-[#111111] text-white flex items-center justify-center font-bold text-xl">
              🧬
            </div>
            <h3 className="text-lg font-bold font-mono text-[#111111]">Scam DNA Fingerprinting</h3>
            <p className="text-xs text-[#6B6B6B] leading-relaxed font-sans">
              Generate unique behavioral signal fingerprints for each threat actor and track how scam family variants mutate over time.
            </p>
          </div>
        </div>
      </section>

      {/* FOOTER */}
      <footer className="py-12 border-t border-[#E5E5E5] bg-white px-6 lg:px-16 text-center text-xs font-mono text-[#6B6B6B] space-y-4">
        <div className="flex items-center justify-center gap-2 font-bold text-[#111111]">
          <span>◈ SHIELD AI</span> — Multimodal Scam Intelligence Platform
        </div>
        <p>Enterprise SOC Command Center &amp; Threat Forensics. Production Quality Environment.</p>
      </footer>
    </div>
  );
};

export default LandingPage;
