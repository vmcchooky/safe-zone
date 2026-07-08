import React, { useEffect, useState, useCallback, useRef, useMemo } from 'react';
import { ShieldCheck, AlertTriangle, ShieldAlert, Zap, Loader2, Activity, Database, ChevronDown, ChevronUp, Check, Calendar } from 'lucide-react';
import type { ValueType } from 'recharts/types/component/DefaultTooltipContent';
import {
  ResponsiveContainer,
  BarChart, Bar as RBar,
  PieChart, Pie, Cell, Sector,
  RadarChart, PolarGrid, PolarAngleAxis, Radar as RRadar,
  XAxis, YAxis, CartesianGrid, Tooltip, Area, AreaChart,
} from 'recharts';
import { motion } from 'framer-motion';

import './TelemetryPage.css';
interface TelemetryStats {
  total: number;
  safe: number;
  suspicious: number;
  malicious: number;
  cache_hits: number;
  period: string;
}

interface TelemetryEntry {
  id: number;
  domain: string;
  verdict: string;
  score: number;
  cache_hit: boolean;
  source?: string;
  analyzed_at: string;
}



interface CustomSelectProps {
  value: string;
  onChange: (val: string) => void;
  options: { value: string; label: string }[];
  placeholder?: string;
  minWidth?: string;
}

function CustomSelect({ value, onChange, options, placeholder = "Select...", minWidth = "120px" }: CustomSelectProps) {
  const [isOpen, setIsOpen] = useState(false);
  const ref = useRef<HTMLDivElement>(null);

  useEffect(() => {
    const handleClickOutside = (event: MouseEvent) => {
      if (ref.current && !ref.current.contains(event.target as Node)) {
        setIsOpen(false);
      }
    };
    document.addEventListener('mousedown', handleClickOutside);
    return () => document.removeEventListener('mousedown', handleClickOutside);
  }, []);

  const selectedLabel = options.find(o => o.value === value)?.label || placeholder;

  return (
    <div className="custom-select-container" ref={ref} style={{ minWidth }}>
      <button 
        type="button" 
        className={`custom-select-trigger ${isOpen ? 'open' : ''}`}
        onClick={() => setIsOpen(!isOpen)}
      >
        <span>{selectedLabel}</span>
        <ChevronDown size={16} className={`chevron ${isOpen ? 'open' : ''}`} />
      </button>
      <div className={`custom-select-menu ${isOpen ? 'open' : ''}`}>
        {options.map(opt => (
          <button 
            key={opt.value}
            type="button"
            className={`custom-select-option ${value === opt.value ? 'selected' : ''}`}
            onClick={() => {
              onChange(opt.value);
              setIsOpen(false);
            }}
          >
            {opt.label}
            {value === opt.value && <Check size={14} />}
          </button>
        ))}
      </div>
    </div>
  );
}

import { useNavigate } from 'react-router-dom';

const CustomCalendar = ({ selectedDate, onSelect, onClose: _onClose }: { selectedDate: string, onSelect: (d: string) => void, onClose: () => void }) => {
  const [currentDate, setCurrentDate] = useState(() => {
    if (selectedDate && selectedDate.includes('-')) {
      return new Date(selectedDate);
    }
    return new Date();
  });

  const getDaysInMonth = (year: number, month: number) => new Date(year, month + 1, 0).getDate();
  const getFirstDayOfMonth = (year: number, month: number) => new Date(year, month, 1).getDay();

  const handlePrevMonth = (e: React.MouseEvent) => {
    e.stopPropagation();
    setCurrentDate(new Date(currentDate.getFullYear(), currentDate.getMonth() - 1, 1));
  };
  
  const handleNextMonth = (e: React.MouseEvent) => {
    e.stopPropagation();
    setCurrentDate(new Date(currentDate.getFullYear(), currentDate.getMonth() + 1, 1));
  };

  const year = currentDate.getFullYear();
  const month = currentDate.getMonth();
  const daysInMonth = getDaysInMonth(year, month);
  const firstDay = getFirstDayOfMonth(year, month); // 0 = Sunday

  const days = [];
  for (let i = 0; i < firstDay; i++) {
    days.push(<div key={`empty-${i}`} className="cal-day empty"></div>);
  }
  
  for (let d = 1; d <= daysInMonth; d++) {
    const dateString = `${year}-${String(month + 1).padStart(2, '0')}-${String(d).padStart(2, '0')}`;
    const isSelected = selectedDate === dateString;
    const isToday = new Date().toDateString() === new Date(year, month, d).toDateString();
    
    days.push(
      <button 
        key={d} 
        className={`cal-day ${isSelected ? 'selected' : ''} ${isToday && !isSelected ? 'today' : ''}`}
        onClick={(e) => {
          e.stopPropagation();
          onSelect(dateString);
        }}
      >
        {d}
      </button>
    );
  }

  const monthNames = ["January", "February", "March", "April", "May", "June", "July", "August", "September", "October", "November", "December"];

  return (
    <div className="custom-calendar-popup" onClick={(e) => e.stopPropagation()}>
      <div className="cal-header">
        <button onClick={handlePrevMonth} className="cal-nav"><ChevronUp size={16} style={{transform: 'rotate(-90deg)'}} /></button>
        <div className="cal-title">{monthNames[month]} {year}</div>
        <button onClick={handleNextMonth} className="cal-nav"><ChevronUp size={16} style={{transform: 'rotate(90deg)'}} /></button>
      </div>
      <div className="cal-weekdays">
        {['Su', 'Mo', 'Tu', 'We', 'Th', 'Fr', 'Sa'].map(w => <div key={w} className="cal-weekday">{w}</div>)}
      </div>
      <div className="cal-grid">
        {days}
      </div>
    </div>
  );
};

const MaskedDateInput = ({ value, onChange, onKeyDown, inputRef }: { value: string, onChange: (v: string) => void, onKeyDown?: (e: React.KeyboardEvent<HTMLInputElement>) => void, inputRef?: React.RefObject<HTMLInputElement | null> }) => {
  const [showCalendar, setShowCalendar] = useState(false);
  const wrapperRef = useRef<HTMLDivElement>(null);

  const formatForDisplay = (val: string) => {
    if (!val) return '';
    if (val.includes('-')) {
      const [y, m, d] = val.split('-');
      if (y && m && d) return `${d}/${m}/${y}`;
    }
    return val;
  };

  const [displayValue, setDisplayValue] = useState(formatForDisplay(value));

  useEffect(() => {
    setDisplayValue(formatForDisplay(value));
  }, [value]);

  useEffect(() => {
    function handleClickOutside(event: MouseEvent) {
      if (wrapperRef.current && !wrapperRef.current.contains(event.target as Node)) {
        setShowCalendar(false);
      }
    }
    if (showCalendar) {
      document.addEventListener("mousedown", handleClickOutside);
    }
    return () => document.removeEventListener("mousedown", handleClickOutside);
  }, [showCalendar]);

  const handleChange = (e: React.ChangeEvent<HTMLInputElement>) => {
    const inputType = (e.nativeEvent as any).inputType;
    const isDeleting = inputType === 'deleteContentBackward' || inputType === 'deleteContentForward';
    
    const val = e.target.value.replace(/[^0-9]/g, '');
    let formatted = '';
    
    if (val.length > 0) formatted += val.substring(0, 2);
    if (val.length >= 2 && !isDeleting) formatted += '/';
    
    if (val.length > 2) formatted += val.substring(2, 4);
    if (val.length >= 4 && !isDeleting) formatted += '/';
    
    if (val.length > 4) formatted += val.substring(4, 8);
    
    if (isDeleting && formatted.endsWith('/')) {
      formatted = formatted.slice(0, -1);
    }
    
    setDisplayValue(formatted);

    if (val.length === 8) {
      const d = parseInt(val.substring(0, 2), 10);
      const m = parseInt(val.substring(2, 4), 10);
      const y = parseInt(val.substring(4, 8), 10);
      
      const dateObj = new Date(y, m - 1, d);
      if (dateObj.getFullYear() === y && dateObj.getMonth() === m - 1 && dateObj.getDate() === d) {
        onChange(`${y}-${String(m).padStart(2, '0')}-${String(d).padStart(2, '0')}`);
      } else {
        onChange('INVALID');
      }
    } else {
      onChange('');
    }
  };

  const handleIconClick = () => {
    setShowCalendar(!showCalendar);
  };

  return (
    <div ref={wrapperRef} style={{ position: 'relative', display: 'flex', alignItems: 'center' }}>
      <input 
        ref={inputRef}
        type="text" 
        value={displayValue} 
        onChange={handleChange} 
        onKeyDown={onKeyDown}
        placeholder="DD/MM/YYYY"
        maxLength={10}
        style={{ paddingRight: '32px' }}
      />
      <div 
        onClick={handleIconClick}
        style={{ position: 'absolute', right: '10px', cursor: 'pointer', color: 'rgba(255,255,255,0.6)', display: 'flex', alignItems: 'center' }}
      >
        <Calendar size={16} />
      </div>
      {showCalendar && (
        <CustomCalendar 
           selectedDate={value} 
           onSelect={(d) => {
             onChange(d);
             setDisplayValue(formatForDisplay(d));
             setShowCalendar(false);
           }}
           onClose={() => setShowCalendar(false)}
        />
      )}
    </div>
  );
};

const CustomCursor = (props: any) => {
  const { points } = props;
  if (!points || points.length < 2) return null;
  const x = points[0].x;
  return (
    <motion.line
      initial={{ x1: x, x2: x, opacity: 0 }}
      animate={{ x1: x, x2: x, opacity: 1 }}
      transition={{ type: 'spring', stiffness: 400, damping: 30 }}
      y1={points[0].y}
      y2={points[1].y}
      stroke="rgba(255, 255, 255, 0.4)"
      strokeWidth={1}
      strokeDasharray="4 4"
    />
  );
};

const CustomActiveDot = (props: any) => {
  const { cx, cy, fill } = props;
  if (cx == null || cy == null) return null;
  
  // Recharts passes the Area's stroke to the activeDot's fill if we specified activeDot={{fill: color}}
  // We'll use the passed `fill` which we defined in the `<Area>` component.
  return (
    <motion.circle
      initial={{ cx, cy, r: 0, opacity: 0 }}
      animate={{ cx, cy, r: 5, opacity: 1 }}
      transition={{ type: 'spring', stiffness: 400, damping: 30 }}
      fill={fill}
      stroke="#fff"
      strokeWidth={2}
      style={{ filter: `drop-shadow(0 0 6px ${fill})` }}
    />
  );
};

export function TelemetryPage() {
  const navigate = useNavigate();
  const [stats, setStats] = useState<TelemetryStats | null>(null);
  const [recent, setRecent] = useState<TelemetryEntry[]>([]);
  const [loading, setLoading] = useState(true);
  const [_isFetchingStats, setIsFetchingStats] = useState(false);
  const [isFetchingRows, setIsFetchingRows] = useState(false);
  const [dataRefreshKey, setDataRefreshKey] = useState(0);

  // Filters and Pagination
  const [period, setPeriod] = useState('24h');
  const [showDatePicker, setShowDatePicker] = useState(false);
  const [customStartDate, setCustomStartDate] = useState('');
  const [customEndDate, setCustomEndDate] = useState('');
  const [activeCustomLabel, setActiveCustomLabel] = useState('');
  const [dateError, setDateError] = useState('');
  const datePickerRef = useRef<HTMLDivElement>(null);
  const fromInputRef = useRef<HTMLInputElement>(null);
  const toInputRef = useRef<HTMLInputElement>(null);

  useEffect(() => {
    function handleClickOutside(event: MouseEvent) {
      if (datePickerRef.current && !datePickerRef.current.contains(event.target as Node)) {
        setShowDatePicker(false);
      }
    }
    document.addEventListener("mousedown", handleClickOutside);
    return () => {
      document.removeEventListener("mousedown", handleClickOutside);
    };
  }, []);

  const [domainFilter, setDomainFilter] = useState('');
  const [debouncedDomainFilter, setDebouncedDomainFilter] = useState('');
  const [verdictFilter, setVerdictFilter] = useState('');
  const [sourceFilter, setSourceFilter] = useState('');
  const [page, setPage] = useState(1);
  const limit = 20;



  useEffect(() => {
    const timer = setTimeout(() => {
      setDebouncedDomainFilter(domainFilter);
    }, 300);
    return () => clearTimeout(timer);
  }, [domainFilter]);

  const loadData = useCallback(async () => {
    setIsFetchingRows(true);
    await new Promise(resolve => setTimeout(resolve, 300)); // Artificial delay for CSS outro animation
    try {
      // MOCK DATA for demonstration purposes
      let multiplier = 1;
      if (period === '24h') multiplier = 1;
      else if (period === '7d') multiplier = 7;
      else if (period === '30d') multiplier = 30;
      else if (period === 'custom') {
        if (customStartDate && customEndDate) {
           const d1 = new Date(customStartDate);
           const d2 = new Date(customEndDate);
           const days = Math.max(1, Math.round((d2.getTime() - d1.getTime()) / (1000 * 3600 * 24)));
           multiplier = days;
        } else {
           multiplier = 14;
        }
      }
      const baseTotal = 1254300 * multiplier;
      
      const mockStats: TelemetryStats = {
        total: baseTotal,
        safe: Math.floor(baseTotal * 0.85),
        suspicious: Math.floor(baseTotal * 0.10),
        malicious: Math.floor(baseTotal * 0.05),
        cache_hits: Math.floor(baseTotal * 0.92),
        period: period
      };

      const mockRecent: TelemetryEntry[] = Array(20).fill(null).map((_, i) => {
        const verdicts = ['SAFE', 'SUSPICIOUS', 'MALICIOUS'];
        const v = verdicts[Math.floor(Math.random() * 3)] as any;
        const score = v === 'SAFE' ? Math.floor(Math.random() * 20) : v === 'SUSPICIOUS' ? Math.floor(Math.random() * 40) + 40 : Math.floor(Math.random() * 20) + 80;
        return {
          id: i,
          domain: `example-domain-${Math.floor(Math.random() * 1000)}.com`,
          analyzed_at: new Date(Date.now() - Math.floor(Math.random() * 10000000)).toISOString(),
          verdict: v,
          score,
          cache_hit: Math.random() > 0.5,
          source: Math.random() > 0.5 ? 'cache' : 'lexical'
        };
      });

      setStats(mockStats);
      setRecent(mockRecent);
      
    } catch (e) {
      console.error('Failed to load telemetry data', e);
    } finally {
      setLoading(false);
      setIsFetchingRows(false);
      setIsFetchingStats(false);
      setDataRefreshKey(k => k + 1);
    }
  }, [period, page, limit, debouncedDomainFilter, verdictFilter, sourceFilter]);

  useEffect(() => {
    loadData();
    const interval = setInterval(loadData, 15000); // 15s refresh
    return () => clearInterval(interval);
  }, [loadData]);



  const clearFilters = () => {
    setDomainFilter('');
    setVerdictFilter('');
    setSourceFilter('');
    setPage(1);
  };

  const radarData = useMemo(() => {
    const categories = ['DDoS', 'SQL Injection', 'XSS', 'Malware', 'Botnet'];
    return categories.map(cat => ({
      subject: cat,
      current: Math.floor(Math.random() * 40) + 10,
      average: Math.floor(Math.random() * 50) + 10,
      fullMark: 100,
    }));
  // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [dataRefreshKey]);

  if (loading && !stats) {
    return (
      <div className="loader-container">
        <Loader2 size={32} className="animate-spin" />
        <span>Syncing with Core API...</span>
      </div>
    );
  }

  // Chart configs
  const safeVal = stats?.safe || 0;
  const suspVal = stats?.suspicious || 0;
  const malVal = stats?.malicious || 0;

  const formatValue = (v: ValueType | undefined): string => {
    const n = Number(v) || 0;
    if (n >= 1_000_000) return (n / 1_000_000).toFixed(1).replace(/\.0$/, '') + 'M';
    if (n >= 1_000) return (n / 1_000).toFixed(1).replace(/\.0$/, '') + 'K';
    return String(n);
  };

  const tooltipStyle = {
    contentStyle: { background: 'rgba(15, 23, 42, 0.92)', border: '1px solid rgba(255,255,255,0.1)', borderRadius: 8, color: '#fff', fontSize: 13 },
    itemStyle: { },
    labelStyle: { color: 'rgba(255,255,255,0.5)' },
  };

  const trafficLabels = period === '7d'
    ? ['-7d', '-6d', '-5d', '-4d', '-3d', '-2d', 'Now']
    : period === '30d'
    ? ['-30d', '-25d', '-20d', '-15d', '-10d', '-5d', 'Now']
    : period === 'custom'
    ? [customStartDate || 'Start', '', '', '', '', '', customEndDate || 'End']
    : ['-24h', '-20h', '-16h', '-12h', '-8h', '-4h', 'Now'];

  const trafficData = trafficLabels.map((label, i) => {
    const safeMultipliers = [0.2, 0.3, 0.25, 0.6, 0.8, 0.7, 1];
    const suspMultipliers = [0.1, 0.2, 0.15, 0.4, 0.5, 0.6, 1];
    const malMultipliers  = [0.3, 0.1, 0.5, 0.8, 0.9, 0.85, 1];
    return {
      name: label,
      Safe: Math.round(safeVal * safeMultipliers[i]),
      Suspicious: Math.round(suspVal * suspMultipliers[i]),
      Malicious: Math.round(malVal * malMultipliers[i]),
    };
  });


  const score = stats?.total ? Math.round(100 - ((stats.suspicious + stats.malicious) / stats.total) * 100) : 100;
  const gaugeColor = score > 80 ? '#14b8a6' : score > 50 ? '#fbbf24' : '#f87171';
  const gaugeData = [
    { name: 'Safe', value: score, fill: gaugeColor },
    { name: 'Risk', value: 100 - score, fill: 'rgba(255,255,255,0.05)' },
  ];

  const threatData = [
    { name: 'Safe', value: stats?.safe || 0, fill: '#14b8a6' },
    { name: 'Suspicious', value: stats?.suspicious || 0, fill: '#fbbf24' },
    { name: 'Malicious', value: stats?.malicious || 0, fill: '#f87171' },
  ];

  const scoreData = [
    { range: '0-20 (Safe)',       domains: stats?.total ? Math.round(stats.total * 0.6)  : 0, fill: 'rgba(20, 184, 166, 0.8)' },
    { range: '21-40',             domains: stats?.total ? Math.round(stats.total * 0.2)  : 0, fill: 'url(#patternSuspiciousLight)' },
    { range: '41-60',             domains: stats?.total ? Math.round(stats.total * 0.1)  : 0, fill: 'url(#patternSuspiciousDark)' },
    { range: '61-80',             domains: stats?.total ? Math.round(stats.total * 0.05) : 0, fill: 'url(#patternMaliciousLight)' },
    { range: '81-100 (Malicious)',domains: stats?.total ? Math.round(stats.total * 0.05) : 0, fill: 'url(#patternMaliciousDark)' },
  ];

  const hitRatio = stats?.total && stats.total > 0 ? Math.round((stats.cache_hits / stats.total) * 100) : 0;

  return (
    <div className="telemetry-container">
      {/* Global SVG Definitions for WCAG Accessibility (Patterns for Color Blindness) */}
      <svg width="0" height="0" style={{ position: 'absolute' }}>
        <defs>
          {/* Subtle Diagonal Stripes for Malicious (Pie Chart) */}
          <pattern id="patternMalicious" width="8" height="8" patternUnits="userSpaceOnUse" patternTransform="rotate(45)">
            <rect width="8" height="8" fill="#f87171" />
            <rect width="4" height="8" fill="#b91c1c" fillOpacity="0.25" />
          </pattern>
          
          {/* Subtle Polka Dots for Suspicious (Pie Chart) */}
          <pattern id="patternSuspicious" width="10" height="10" patternUnits="userSpaceOnUse">
            <rect width="10" height="10" fill="#fbbf24" />
            <circle cx="2" cy="2" r="1.5" fill="#b45309" fillOpacity="0.4" />
            <circle cx="7" cy="7" r="1.5" fill="#b45309" fillOpacity="0.4" />
          </pattern>

          {/* Semi-transparent Stripes for AreaChart overlay */}
          <pattern id="patternMaliciousArea" width="8" height="8" patternUnits="userSpaceOnUse" patternTransform="rotate(45)">
            <rect width="8" height="8" fill="#f87171" fillOpacity="0.2" />
            <rect width="4" height="8" fill="#b91c1c" fillOpacity="0.3" />
          </pattern>
          
          {/* Semi-transparent Dots for AreaChart overlay */}
          <pattern id="patternSuspiciousArea" width="10" height="10" patternUnits="userSpaceOnUse">
            <rect width="10" height="10" fill="#fbbf24" fillOpacity="0.2" />
            <circle cx="2" cy="2" r="1.5" fill="#b45309" fillOpacity="0.3" />
            <circle cx="7" cy="7" r="1.5" fill="#b45309" fillOpacity="0.3" />
          </pattern>

          {/* BarChart Patterns */}
          <pattern id="patternSuspiciousLight" width="10" height="10" patternUnits="userSpaceOnUse">
            <rect width="10" height="10" fill="rgba(251, 191, 36, 0.4)" />
            <circle cx="2" cy="2" r="1.5" fill="#b45309" fillOpacity="0.4" />
            <circle cx="7" cy="7" r="1.5" fill="#b45309" fillOpacity="0.4" />
          </pattern>
          <pattern id="patternSuspiciousDark" width="10" height="10" patternUnits="userSpaceOnUse">
            <rect width="10" height="10" fill="rgba(251, 191, 36, 0.8)" />
            <circle cx="2" cy="2" r="1.5" fill="#b45309" fillOpacity="0.6" />
            <circle cx="7" cy="7" r="1.5" fill="#b45309" fillOpacity="0.6" />
          </pattern>
          <pattern id="patternMaliciousLight" width="8" height="8" patternUnits="userSpaceOnUse" patternTransform="rotate(45)">
            <rect width="8" height="8" fill="rgba(248, 113, 113, 0.4)" />
            <rect width="4" height="8" fill="#b91c1c" fillOpacity="0.25" />
          </pattern>
          <pattern id="patternMaliciousDark" width="8" height="8" patternUnits="userSpaceOnUse" patternTransform="rotate(45)">
            <rect width="8" height="8" fill="rgba(248, 113, 113, 0.8)" />
            <rect width="4" height="8" fill="#b91c1c" fillOpacity="0.4" />
          </pattern>
        </defs>
      </svg>
      {/* Top Header with Period Switcher */}
      <div style={{display:'flex', justifyContent:'space-between', alignItems:'center'}}>
        <h2 style={{margin:0, fontSize:20}}>Overview</h2>
        <div style={{display:'flex', alignItems:'center', gap: '16px'}}>
          <div className="period-bar">
            <button className={`period-btn ${period === '24h' ? 'active' : ''}`} onClick={() => { setPeriod('24h'); setCustomStartDate(''); setCustomEndDate(''); }}>24h</button>
            <button className={`period-btn ${period === '7d' ? 'active' : ''}`} onClick={() => { setPeriod('7d'); setCustomStartDate(''); setCustomEndDate(''); }}>7d</button>
            <button className={`period-btn ${period === '30d' ? 'active' : ''}`} onClick={() => { setPeriod('30d'); setCustomStartDate(''); setCustomEndDate(''); }}>30d</button>
          </div>
          
          <div className="date-picker-wrapper" ref={datePickerRef}>
            <button 
              className={`btn-secondary ${period === 'custom' ? 'active' : ''}`} 
              onClick={() => setShowDatePicker(!showDatePicker)}
              style={{ display: 'flex', alignItems: 'center', gap: '8px', background: period === 'custom' ? 'rgba(14, 165, 233, 0.1)' : '', borderColor: period === 'custom' ? 'rgba(14, 165, 233, 0.3)' : '', color: period === 'custom' ? '#0ea5e9' : '' }}
            >
              <Calendar size={16} />
              {period === 'custom' && activeCustomLabel ? activeCustomLabel : 'Custom'}
            </button>
            
            <div className={`date-picker-popover ${showDatePicker ? 'visible' : ''}`}>
              <div className="date-inputs">
                <div className="date-input-group">
                  <label>From</label>
                  <MaskedDateInput 
                    inputRef={fromInputRef}
                    value={customStartDate} 
                    onChange={(v) => { setCustomStartDate(v); setDateError(''); }} 
                    onKeyDown={(e) => {
                      if (e.key === 'Enter') {
                        toInputRef.current?.focus();
                      }
                    }}
                  />
                </div>
                <div className="date-input-group">
                  <label>To</label>
                  <MaskedDateInput 
                    inputRef={toInputRef}
                    value={customEndDate} 
                    onChange={(v) => { setCustomEndDate(v); setDateError(''); }} 
                    onKeyDown={(e) => {
                      if (e.key === 'Enter') {
                        toInputRef.current?.blur();
                      }
                    }}
                  />
                </div>
              </div>
              {dateError && <div style={{ color: '#ef4444', fontSize: '13px', marginBottom: '16px', textAlign: 'center', background: 'rgba(239, 68, 68, 0.1)', padding: '8px', borderRadius: '6px' }}>{dateError}</div>}
              <div className="date-picker-actions">
                <button className="btn-secondary" onClick={() => { setShowDatePicker(false); setDateError(''); }}>Cancel</button>
                <button className="btn-primary" onClick={() => {
                  let finalStart = customStartDate;
                  let finalEnd = customEndDate;

                  if (!finalStart && !finalEnd) {
                    setDateError('Please enter at least one date.');
                    return;
                  }
                  if (finalStart === 'INVALID' || finalEnd === 'INVALID') {
                    setDateError('Please enter a valid date (DD/MM/YYYY).');
                    return;
                  }

                  const formatToYYYYMMDD = (d: Date) => {
                    const year = d.getFullYear();
                    const month = String(d.getMonth() + 1).padStart(2, '0');
                    const day = String(d.getDate()).padStart(2, '0');
                    return `${year}-${month}-${day}`;
                  };

                  if (finalStart && !finalEnd) {
                    finalEnd = formatToYYYYMMDD(new Date());
                    setCustomEndDate(finalEnd);
                  } else if (!finalStart && finalEnd) {
                    const endDateObj = new Date(finalEnd);
                    endDateObj.setDate(endDateObj.getDate() - 30);
                    finalStart = formatToYYYYMMDD(endDateObj);
                    setCustomStartDate(finalStart);
                  }

                  if (new Date(finalStart) > new Date(finalEnd)) {
                    setDateError('From date cannot be after To date.');
                    return;
                  }
                  
                  setPeriod('custom');
                  setActiveCustomLabel(`${finalStart} - ${finalEnd}`);
                  setShowDatePicker(false);
                  setDateError('');
                }}>Apply</button>
              </div>
            </div>
          </div>
        </div>
      </div>

      {/* KPIs */}
      <div className="telemetry-stats-grid" key={dataRefreshKey}>
        <div className="stat-card">
          <div className="stat-card-header">
            <h4 className="stat-title">Total ({period})</h4>
            <div className="stat-icon blue"><Activity size={20} /></div>
          </div>
          <p className="stat-value animated" key={stats ? `${stats.total}-t` : 't'}>{(stats?.total || 0).toLocaleString()}</p>
        </div>
        <div className="stat-card">
          <div className="stat-card-header">
            <h4 className="stat-title">Safe</h4>
            <div className="stat-icon green"><ShieldCheck size={20} /></div>
          </div>
          <p className="stat-value animated" key={stats ? `${stats.total}-sf` : 'sf'}>{(stats?.safe || 0).toLocaleString()}</p>
        </div>
        <div className="stat-card">
          <div className="stat-card-header">
            <h4 className="stat-title">Suspicious</h4>
            <div className="stat-icon yellow"><Zap size={20} /></div>
          </div>
          <p className="stat-value animated" key={stats ? `${stats.total}-sp` : 'sp'}>{(stats?.suspicious || 0).toLocaleString()}</p>
        </div>
        <div className="stat-card">
          <div className="stat-card-header">
            <h4 className="stat-title">Malicious</h4>
            <div className="stat-icon red"><ShieldAlert size={20} /></div>
          </div>
          <p className="stat-value animated" key={stats ? `${stats.total}-m` : 'm'}>{(stats?.malicious || 0).toLocaleString()}</p>
        </div>
        <div className="stat-card">
          <div className="stat-card-header">
            <h4 className="stat-title">Cache Hits</h4>
            <div className="stat-icon blue"><Database size={20} /></div>
          </div>
          <p className="stat-value animated" key={stats ? `${stats.total}-c` : 'c'}>{(stats?.cache_hits || 0).toLocaleString()}</p>
        </div>
      </div>

      {/* Cache Efficiency Bar */}
      <div className="efficiency-container">
        <div className="efficiency-header">
          <span>Cache Efficiency</span>
          <span>{hitRatio}%</span>
        </div>
        <div className="efficiency-bar">
          <div className="efficiency-fill" style={{ width: `${hitRatio}%` }}></div>
        </div>
      </div>

      {/* Charts */}
      <div className="telemetry-charts-grid">
        <div className="chart-card">
          <h3>Traffic Overview</h3>
          <div className="chart-container">
            <ResponsiveContainer width="100%" height="100%">
              <AreaChart data={trafficData} margin={{ top: 10, right: 10, left: 0, bottom: 0 }}>
                <defs>
                  <linearGradient id="gradSafe" x1="0" y1="0" x2="0" y2="1">
                    <stop offset="5%" stopColor="#14b8a6" stopOpacity={0.2} />
                    <stop offset="95%" stopColor="#14b8a6" stopOpacity={0} />
                  </linearGradient>
                  <linearGradient id="gradSusp" x1="0" y1="0" x2="0" y2="1">
                    <stop offset="5%" stopColor="#fbbf24" stopOpacity={0.2} />
                    <stop offset="95%" stopColor="#fbbf24" stopOpacity={0} />
                  </linearGradient>
                  <linearGradient id="gradMal" x1="0" y1="0" x2="0" y2="1">
                    <stop offset="5%" stopColor="#f87171" stopOpacity={0.2} />
                    <stop offset="95%" stopColor="#f87171" stopOpacity={0} />
                  </linearGradient>
                </defs>
                <CartesianGrid strokeDasharray="5 5" stroke="rgba(255,255,255,0.05)" vertical={false} />
                <XAxis dataKey="name" tick={{ fill: 'rgba(255,255,255,0.3)', fontSize: 12 }} axisLine={false} tickLine={false} />
                <YAxis tick={{ fill: 'rgba(255,255,255,0.3)', fontSize: 12 }} axisLine={false} tickLine={false} tickFormatter={(v) => formatValue(v)} width={60} />
                <Tooltip {...tooltipStyle} formatter={((value: ValueType) => formatValue(value)) as any} cursor={<CustomCursor />} />
                {/* Single stacked layer for correct tooltips and rendering */}
                <Area type="monotone" dataKey="Malicious" stackId="1" stroke="#f87171" fillOpacity={1} fill="url(#patternMaliciousArea)" strokeWidth={2} dot={false} activeDot={<CustomActiveDot fill="#f87171" />} />
                <Area type="monotone" dataKey="Suspicious" stackId="1" stroke="#fbbf24" fillOpacity={1} fill="url(#patternSuspiciousArea)" strokeWidth={2} dot={false} activeDot={<CustomActiveDot fill="#fbbf24" />} />
                <Area type="monotone" dataKey="Safe" stackId="1" stroke="#14b8a6" fillOpacity={1} fill="url(#gradSafe)" strokeWidth={2} dot={false} activeDot={<CustomActiveDot fill="#14b8a6" />} />
              </AreaChart>
            </ResponsiveContainer>
          </div>
          <div className="mix-section" style={{ marginTop: '24px' }}>
            <div className="mix-card">
              <div className="mix-header">
                <span>Risk Mix</span>
                <span>{stats?.total ? Math.round(((stats.suspicious + stats.malicious) / stats.total) * 100) : 0}% risk</span>
              </div>
              <div className="mix-bar">
                <div className="mix-segment safe" style={{width: `${stats?.total ? Math.round((stats.safe / stats.total) * 100) : 100}%`}}></div>
                <div className="mix-segment risk" style={{width: `${stats?.total ? Math.round(((stats.suspicious + stats.malicious) / stats.total) * 100) : 0}%`}}></div>
              </div>
            </div>
          </div>
        </div>
        <div className="chart-card">
          <h3>Traffic Distribution</h3>
          {(stats?.safe === 0 && stats?.suspicious === 0 && stats?.malicious === 0) ? (
            <div className="chart-container">
              <div className="chart-empty-state">
                <span>No Data</span>
              </div>
            </div>
          ) : (
            <>
              <div className="chart-container">
                <ResponsiveContainer width="100%" height="100%">
                  <PieChart>
                    <Pie
                      data={threatData}
                      dataKey="value"
                      nameKey="name"
                      cx="50%"
                      cy="50%"
                      startAngle={90}
                      endAngle={-270}
                      innerRadius="55%"
                      outerRadius="80%"
                      paddingAngle={2}
                      strokeWidth={0}
                      animationDuration={1500}
                      animationEasing="ease-out"
                      activeShape={(props: any) => {
                        const { cx, cy, innerRadius, outerRadius, startAngle, endAngle, fill } = props;
                        return (
                          <Sector
                            cx={cx}
                            cy={cy}
                            innerRadius={innerRadius}
                            outerRadius={outerRadius + 15}
                            startAngle={startAngle}
                            endAngle={endAngle}
                            fill={fill}
                          />
                        );
                      }}
                    >
                      {threatData.map((entry, index) => (
                        <Cell 
                          key={`cell-${index}`} 
                          fill={entry.name === 'Malicious' ? 'url(#patternMalicious)' : entry.name === 'Suspicious' ? 'url(#patternSuspicious)' : entry.fill} 
                        />
                      ))}
                    </Pie>
                    <Tooltip {...tooltipStyle} formatter={((value: ValueType) => formatValue(value)) as any} />
                  </PieChart>
                </ResponsiveContainer>
              </div>
              <div style={{ textAlign: 'center', fontSize: '13px', marginTop: 24, fontWeight: 500, fontFamily: 'monospace' }}>
                <span style={{color: '#14b8a6'}}>Safe {stats?.total ? Math.round((stats.safe / stats.total) * 100) : 0}%</span>
                <span style={{color: 'rgba(255,255,255,0.3)', margin: '0 12px'}}>/</span>
                <span style={{color: '#fbbf24'}}>Suspicious {stats?.total ? Math.round((stats.suspicious / stats.total) * 100) : 0}%</span>
                <span style={{color: 'rgba(255,255,255,0.3)', margin: '0 12px'}}>/</span>
                <span style={{color: '#f87171'}}>Malicious {stats?.total ? Math.round((stats.malicious / stats.total) * 100) : 0}%</span>
              </div>
            </>
          )}
        </div>
      </div>
      
      {/* Deep Risk Analysis - Tạm ẩn chờ thu thập dữ liệu thật */}
      {false && (
        <>
          <h2 style={{ fontSize: '18px', fontWeight: 600, marginTop: '32px', marginBottom: '16px', color: '#fff', display: 'flex', alignItems: 'center', gap: '8px' }}>
            <Zap size={20} color="#f87171" /> Deep Risk Analysis
          </h2>
          <div className="telemetry-charts-grid">
            <div className="chart-card">
              <h3>Threat Vector Radar</h3>
              <div className="chart-container" style={{ position: 'relative', height: '300px', marginTop: '16px' }}>
                <ResponsiveContainer width="100%" height="100%">
                  <RadarChart data={radarData} cx="50%" cy="50%" outerRadius="70%">
                    <PolarGrid stroke="rgba(255,255,255,0.1)" />
                    <PolarAngleAxis dataKey="subject" tick={{ fill: 'rgba(255,255,255,0.6)', fontSize: 11, fontFamily: 'monospace' }} />
                    <RRadar name="Current Attack Intensity" dataKey="current" stroke="#f87171" fill="rgba(248, 113, 113, 0.2)" fillOpacity={0.6} strokeWidth={2} />
                    <RRadar name="7-Day Average" dataKey="average" stroke="#0ea5e9" fill="rgba(14, 165, 233, 0.1)" fillOpacity={0.4} strokeWidth={1} strokeDasharray="5 5" />
                    <Tooltip {...tooltipStyle} />
                  </RadarChart>
                </ResponsiveContainer>
              </div>
            </div>
            <div className="chart-card" style={{ display: 'flex', flexDirection: 'column' }}>
              <h3>Cluster Threat Level</h3>
              <div className="chart-container" style={{ position: 'relative', height: '240px', display: 'flex', justifyContent: 'center', alignItems: 'flex-end', marginTop: 'auto', marginBottom: 'auto' }}>
                <div style={{ position: 'absolute', width: '100%', height: '100%', top: '20px', left: 0 }}>
                  <ResponsiveContainer width="100%" height="100%">
                    <PieChart>
                      <Pie
                        data={gaugeData}
                        dataKey="value"
                        startAngle={180}
                        endAngle={0}
                        innerRadius="75%"
                        outerRadius="95%"
                        strokeWidth={0}
                        animationDuration={1200}
                      >
                        {gaugeData.map((entry, index) => (
                          <Cell key={`gauge-${index}`} fill={entry.fill} />
                        ))}
                      </Pie>
                    </PieChart>
                  </ResponsiveContainer>
                </div>
                <div style={{ position: 'absolute', bottom: '30px', display: 'flex', flexDirection: 'column', alignItems: 'center' }}>
                  <span style={{ fontSize: '56px', fontWeight: 700, color: score > 80 ? '#14b8a6' : score > 50 ? '#fbbf24' : '#f87171', lineHeight: 1 }}>{score}</span>
                  <span style={{ fontSize: '14px', color: 'rgba(255,255,255,0.5)', textTransform: 'uppercase', letterSpacing: '2px', marginTop: '8px' }}>Security Score</span>
                </div>
              </div>
            </div>
          </div>
        </>
      )}
      
      {/* Score Distribution Chart */}
      <div className="telemetry-score-grid">
        <div className="chart-card">
          <h3>Score Distribution Histogram</h3>
          <div className="chart-container">
            <ResponsiveContainer width="100%" height="100%">
              <BarChart data={scoreData} margin={{ top: 10, right: 10, left: 0, bottom: 0 }}>
                <CartesianGrid strokeDasharray="5 5" stroke="rgba(255,255,255,0.05)" vertical={false} />
                <XAxis dataKey="range" tick={{ fill: 'rgba(255,255,255,0.3)', fontSize: 11 }} axisLine={false} tickLine={false} />
                <YAxis tick={{ fill: 'rgba(255,255,255,0.3)', fontSize: 12 }} axisLine={false} tickLine={false} tickFormatter={(v) => formatValue(v)} width={60} />
                <Tooltip 
                  {...tooltipStyle} 
                  cursor={{ fill: 'rgba(255, 255, 255, 0.05)', rx: 4, ry: 4 }} 
                  itemStyle={{ color: '#fff' }} 
                  formatter={((value: ValueType) => formatValue(value)) as any} 
                />
                <RBar 
                  dataKey="domains" 
                  radius={[4, 4, 0, 0]} 
                  barSize={40} 
                  animationDuration={1200}
                  activeBar={{ filter: 'brightness(1.3)' }}
                >
                  {scoreData.map((entry, index) => (
                    <Cell key={`score-${index}`} fill={entry.fill} />
                  ))}
                </RBar>
              </BarChart>
            </ResponsiveContainer>
          </div>
        </div>
      </div>

      {/* Recent Activity Table */}
      <div className="recent-table-card">
        <div style={{display:'flex', justifyContent:'space-between', alignItems:'center', marginBottom: '24px'}}>
          <h3 style={{margin:0}}>Recent Network Activity</h3>
          {isFetchingRows && <Loader2 size={16} className="animate-spin text-blue" />}
        </div>
        
        <table className="t-table">
          <thead>
            <tr>
              <th>Domain</th>
              <th>Verdict</th>
              <th>Source</th>
              <th>Score</th>
              <th>Timestamp</th>
              <th>Actions</th>
            </tr>
            <tr className="filter-row">
              <th>
                <input 
                  type="text" 
                  className="t-input inline-filter" 
                  placeholder="e.g. example.com" 
                  value={domainFilter} 
                  onChange={e => {setDomainFilter(e.target.value); setPage(1);}} 
                />
              </th>
              <th>
                <CustomSelect 
                  minWidth="130px"
                  value={verdictFilter} 
                  onChange={v => {setVerdictFilter(v); setPage(1);}} 
                  options={[
                    { value: '', label: 'All' },
                    { value: 'SAFE', label: 'Safe' },
                    { value: 'SUSPICIOUS', label: 'Suspicious' },
                    { value: 'MALICIOUS', label: 'Malicious' },
                    { value: 'INVALID', label: 'Invalid' }
                  ]} 
                />
              </th>
              <th>
                <CustomSelect 
                  value={sourceFilter} 
                  onChange={v => {setSourceFilter(v); setPage(1);}} 
                  options={[
                    { value: '', label: 'All' },
                    { value: 'cache', label: 'Cache' },
                    { value: 'lexical', label: 'Lexical' },
                    { value: 'ai', label: 'AI' }
                  ]} 
                />
              </th>
              <th></th>
              <th></th>
              <th>
                <button 
                  className="t-btn-clear" 
                  onClick={clearFilters}
                  style={{
                    visibility: (domainFilter || verdictFilter || sourceFilter) ? 'visible' : 'hidden'
                  }}
                >
                  Clear
                </button>
              </th>
            </tr>
          </thead>
          <tbody key={dataRefreshKey} className={isFetchingRows ? 'fetching' : ''}>
            {recent.map((item, idx) => (
              <tr key={`${item.id}-${idx}`} className="animated-row" style={{ animationDelay: `${idx * 0.03}s` }}>
                <td style={{fontFamily: 'monospace', fontWeight: 600, fontSize: '16px', color: '#fff'}}>{item.domain}</td>
                <td>
                  <span className={`verdict-pill ${item.verdict.toLowerCase()}`}>
                    {item.verdict === 'MALICIOUS' && <AlertTriangle size={12} style={{marginRight:4}} />}
                    {item.verdict === 'SUSPICIOUS' && <Zap size={12} style={{marginRight:4}} />}
                    {item.verdict === 'SAFE' && <ShieldCheck size={12} style={{marginRight:4}} />}
                    {item.verdict}
                  </span>
                </td>
                <td>
                  <span className="source-pill">
                    {item.source ? item.source : (item.cache_hit ? 'Cache' : 'Engine')}
                  </span>
                </td>
                <td>{item.score}/100</td>
                <td style={{color: 'rgba(255,255,255,0.5)', fontSize: 13}}>{new Date(item.analyzed_at).toLocaleString()}</td>
                <td>
                  <button className="action-btn review-btn" onClick={() => navigate(`/analysis?domain=${item.domain}`)}>
                    Review
                  </button>
                </td>
              </tr>
            ))}
            {recent.length === 0 && !isFetchingRows && (
              <tr>
                <td colSpan={6} style={{textAlign: 'center', padding: '48px', color: 'rgba(255,255,255,0.4)'}}>
                  No recent activity matches your filters.
                </td>
              </tr>
            )}
          </tbody>
        </table>

        <div className="pagination">
          <button 
            className="t-btn-page" 
            disabled={page === 1} 
            onClick={() => setPage(p => p - 1)}>
            Prev
          </button>
          <span className="page-indicator">Page {page}</span>
          <button 
            className="t-btn-page" 
            disabled={recent.length < limit} 
            onClick={() => setPage(p => p + 1)}>
            Next
          </button>
        </div>
      </div>


    </div>
  );
}
