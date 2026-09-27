import React from 'react';
import { FileText, Image as ImageIcon, Mic, Globe, Layers, ArrowRight } from 'lucide-react';

export const MODE_CONFIG = {
  text: {
    id: 'text',
    symbol: '◉',
    title: 'TEXT',
    subtitle: 'Analyze messages, SMS & emails',
    icon: FileText,
  },
  image: {
    id: 'image',
    symbol: '◇',
    title: 'IMAGE',
    subtitle: 'Analyze screenshots & logos',
    icon: ImageIcon,
  },
  voice: {
    id: 'voice',
    symbol: '◇',
    title: 'VOICE',
    subtitle: 'Analyze audio recordings & calls',
    icon: Mic,
  },
  sandbox: {
    id: 'sandbox',
    symbol: '◈',
    title: 'WEBSITE SANDBOX',
    subtitle: 'Analyze live URLs in sandbox',
    icon: Globe,
  },
  multimodal: {
    id: 'multimodal',
    symbol: '✦',
    title: 'MULTIMODAL',
    subtitle: 'Combine multiple evidence sources',
    icon: Layers,
  }
};

export const AnalysisModeCard = ({ modeKey, isSelected, onClick }) => {
  const mode = MODE_CONFIG[modeKey];
  if (!mode) return null;
  const Icon = mode.icon;

  return (
    <button
      onClick={onClick}
      className={`
        w-full text-left p-6 rounded-2xl border transition-all duration-200 flex flex-col justify-between h-48 relative overflow-hidden group cursor-pointer
        ${isSelected
          ? 'bg-[#111111] text-white border-[#111111] shadow-lg translate-y-[-2px]'
          : 'bg-white text-[#111111] border-[#E5E5E5] hover:border-[#111111] hover:shadow-md'
        }
      `}
    >
      {/* Top Header */}
      <div className="flex items-center justify-between w-full">
        <span className={`text-2xl font-mono ${isSelected ? 'text-white' : 'text-[#111111]'}`}>
          {mode.symbol}
        </span>
        <div className={`p-2 rounded-xl ${isSelected ? 'bg-white/10 text-white' : 'bg-[#F7F7F5] text-[#111111]'}`}>
          <Icon className="w-5 h-5" />
        </div>
      </div>

      {/* Middle Label & Subtitle */}
      <div>
        <div className={`text-xs font-mono font-semibold uppercase tracking-widest ${isSelected ? 'text-white/70' : 'text-[#6B6B6B]'}`}>
          INVESTIGATION MODE
        </div>
        <div className="text-lg font-bold tracking-tight font-mono mt-0.5">
          {mode.title}
        </div>
        <p className={`text-xs mt-1 ${isSelected ? 'text-white/80' : 'text-[#6B6B6B]'}`}>
          {mode.subtitle}
        </p>
      </div>

      {/* Bottom Action Footer */}
      <div className="flex items-center justify-between pt-2 border-t border-current/10 w-full text-xs font-mono">
        <span className="text-[10px] uppercase tracking-wider font-semibold">Select Mode</span>
        <ArrowRight className={`w-4 h-4 transition-transform group-hover:translate-x-1 ${isSelected ? 'text-white' : 'text-[#111111]'}`} />
      </div>
    </button>
  );
};

export default AnalysisModeCard;
