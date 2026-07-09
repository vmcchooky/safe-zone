import { Info } from 'lucide-react';
import type { ReactNode } from 'react';

export function InfoTooltip({ content, size = 18 }: { content: ReactNode, size?: number }) {
  return (
    <div className="relative group inline-flex items-center justify-center cursor-help">
      <Info size={size} className="text-slate-400 group-hover:text-sky-500 transition-colors duration-200" />
      
      {/* Tooltip content */}
      <div className="absolute bottom-full mb-2.5 left-1/2 -translate-x-1/2 w-max max-w-[280px] opacity-0 scale-95 pointer-events-none group-hover:opacity-100 group-hover:scale-100 transition-all duration-200 ease-out z-50 origin-bottom">
        <div className="bg-white/90 backdrop-blur-md text-slate-700 text-sm px-4 py-2.5 rounded-xl border border-sky-200 shadow-xl leading-relaxed font-medium text-center">
          {content}
        </div>
        {/* Arrow */}
        <div className="absolute top-full left-1/2 -translate-x-1/2 -mt-0.5 border-[6px] border-transparent border-t-sky-200" />
      </div>
    </div>
  );
}
