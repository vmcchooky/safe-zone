import { useState } from 'react';
import { Info } from 'lucide-react';
import type { ReactNode } from 'react';

export function InfoTooltip({ content, size = 18 }: { content: ReactNode, size?: number }) {
  const [isHovered, setIsHovered] = useState(false);

  return (
    <div 
      className="relative inline-flex items-center justify-center cursor-help"
      onMouseEnter={() => setIsHovered(true)}
      onMouseLeave={() => setIsHovered(false)}
      onFocus={() => setIsHovered(true)}
      onBlur={() => setIsHovered(false)}
    >
      <Info 
        size={size} 
        className={`text-slate-400 transition-colors duration-200 ${isHovered ? 'text-sky-500' : ''}`} 
      />
      
      {/* Tooltip content */}
      <div 
        className={`absolute bottom-full mb-2.5 left-1/2 -translate-x-1/2 w-max max-w-[280px] pointer-events-none transition-all duration-200 ease-out z-50 origin-bottom ${
          isHovered ? 'opacity-100 scale-100' : 'opacity-0 scale-95'
        }`}
      >
        <div className="bg-white/90 backdrop-blur-md text-slate-700 text-sm px-4 py-2.5 rounded-xl border border-sky-200 shadow-xl leading-relaxed font-medium text-center">
          {content}
        </div>
        {/* Arrow */}
        <div className="absolute top-full left-1/2 -translate-x-1/2 -mt-0.5 border-[6px] border-transparent border-t-sky-200" />
      </div>
    </div>
  );
}
