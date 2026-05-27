import React, { useState, useEffect, useRef } from 'react';

// ================= HỆ THỐNG ICON SVG TỰ THIẾT KẾ ĐỂ ĐẢM BẢO HOẠT ĐỘNG KHÔNG LỖI =================
const Icons = {
  Dashboard: () => (
    <svg className="w-5 h-5" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}>
      <path strokeLinecap="round" strokeLinejoin="round" d="M4 6a2 2 0 012-2h2a2 2 0 012 2v4a2 2 0 01-2 2H6a2 2 0 01-2-2V6zM14 6a2 2 0 012-2h2a2 2 0 012 2v4a2 2 0 01-2 2h-2a2 2 0 01-2-2V6zM4 16a2 2 0 012-2h2a2 2 0 012 2v4a2 2 0 01-2 2H6a2 2 0 01-2-2v-4zM14 16a2 2 0 012-2h2a2 2 0 012 2v4a2 2 0 01-2 2h-2a2 2 0 01-2-2v-4z" />
    </svg>
  ),
  Nodes: () => (
    <svg className="w-5 h-5" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}>
      <path strokeLinecap="round" strokeLinejoin="round" d="M19.428 15.428a2 2 0 00-1.022-.547l-2.387-.477a6 6 0 00-3.86.517l-.318.158a6 6 0 01-3.86.517L6.05 15.21a2 2 0 00-1.806.547M8 4h8l-1 1v5.172a2 2 0 00.586 1.414l5 5c1.26 1.26.367 3.414-1.415 3.414H4.828c-1.782 0-2.674-2.154-1.414-3.414l5-5A2 2 0 009 10.172V5L8 4z" />
    </svg>
  ),
  Firewall: () => (
    <svg className="w-5 h-5" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}>
      <path strokeLinecap="round" strokeLinejoin="round" d="M9 12l2 2 4-4m5.618-4.016A11.955 11.955 0 0112 2.944a11.955 11.955 0 01-8.618 3.04A12.02 12.02 0 003 9c0 5.591 3.824 10.29 9 11.622 5.176-1.332 9-6.03 9-11.622 0-1.042-.133-2.052-.382-3.016z" />
    </svg>
  ),
  Automation: () => (
    <svg className="w-5 h-5" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}>
      <path strokeLinecap="round" strokeLinejoin="round" d="M8 9l3 3-3 3m5 0h3M5 20h14a2 2 0 002-2V6a2 2 0 00-2-2H5a2 2 0 00-2 2v12a2 2 0 002 2z" />
    </svg>
  ),
  Settings: () => (
    <svg className="w-5 h-5" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}>
      <path strokeLinecap="round" strokeLinejoin="round" d="M10.325 4.317c.426-1.756 2.924-1.756 3.35 0a1.724 1.724 0 002.573 1.066c1.543-.94 3.31.826 2.37 2.37a1.724 1.724 0 001.065 2.572c1.756.426 1.756 2.924 0 3.35a1.724 1.724 0 00-1.066 2.573c.94 1.543-.826 3.31-2.37 2.37a1.724 1.724 0 00-2.572 1.065c-.426 1.756-2.924 1.756-3.35 0a1.724 1.724 0 00-2.573-1.066c-1.543.94-3.31-.826-2.37-2.37a1.724 1.724 0 00-1.065-2.572c-1.756-.426-1.756-2.924 0-3.35a1.724 1.724 0 001.066-2.573c-.94-1.543.826-3.31 2.37-2.37.996.608 2.296.07 2.572-1.065z" />
      <path strokeLinecap="round" strokeLinejoin="round" d="M15 12a3 3 0 11-6 0 3 3 0 016 0z" />
    </svg>
  ),
  ArrowLeft: () => (
    <svg className="w-4 h-4" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2.5}>
      <path strokeLinecap="round" strokeLinejoin="round" d="M15 19l-7-7 7-7" />
    </svg>
  ),
  ArrowRight: () => (
    <svg className="w-4 h-4" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2.5}>
      <path strokeLinecap="round" strokeLinejoin="round" d="M9 5l7 7-7 7" />
    </svg>
  ),
  Refresh: () => (
    <svg className="w-4 h-4 animate-spin" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}>
      <path strokeLinecap="round" strokeLinejoin="round" d="M4 4v5h.582m15.356 2A8.001 8.001 0 1121.21 15H15" />
    </svg>
  ),
  Check: () => (
    <svg className="w-5 h-5 text-emerald-500" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2.5}>
      <path strokeLinecap="round" strokeLinejoin="round" d="M5 13l4 4L19 7" />
    </svg>
  )
};

// ================= SUB-COMPONENT: SIDEBAR MENU ITEM =================
const SidebarItem = ({ icon: Icon, label, isOpen, isActive, onClick }) => {
  return (
    <button
      onClick={onClick}
      className={`w-full flex items-center p-3 rounded-xl transition-all duration-300 group relative font-medium text-sm
        ${isActive 
          ? 'bg-blue-600 text-white shadow-lg shadow-blue-500/25' 
          : 'text-slate-400 hover:bg-slate-800/60 hover:text-slate-100'
        }`}
    >
      {/* Icon cố định khung kích thước không đổi */}
      <div className="flex-shrink-0 flex items-center justify-center w-6 h-6">
        <Icon />
      </div>

      {/* Chuyển động co giãn text và opacity đồng bộ cực mượt */}
      <span
        className={`whitespace-nowrap transition-all duration-300 ease-in-out overflow-hidden
          ${isOpen ? 'max-w-xs opacity-100 ml-3' : 'max-w-0 opacity-0 ml-0'}`}
      >
        {label}
      </span>

      {/* Tooltip thông minh hiển thị khi Sidebar bị thu gọn */}
      {!isOpen && (
        <div className="absolute left-full rounded-lg px-3 py-1.5 ml-4 bg-slate-900 text-slate-100 text-xs border border-slate-800
          invisible opacity-0 -translate-x-2 transition-all duration-200 group-hover:visible group-hover:opacity-100 group-hover:translate-x-0 whitespace-nowrap z-50 shadow-2xl">
          {label}
        </div>
      )}
    </button>
  );
};

// ================= MAIN COMPONENT APP =================
export default function App() {
  const [isOpen, setIsOpen] = useState(true);
  const [activeTab, setActiveTab] = useState('dashboard');
  const [toast, setToast] = useState(null);

  // --- STATE CHO CÁC PHÂN HỆ SỬ DỤNG ---
  // Node Cluster State
  const [nodes, setNodes] = useState([
    { id: 'node-1', name: 'VN-Edge-Router-01', ip: '10.120.1.1', status: 'Active', cpu: 22, ram: 45, region: 'Hanoi' },
    { id: 'node-2', name: 'VN-Core-Switch-02', ip: '10.120.1.254', status: 'Active', cpu: 14, ram: 38, region: 'HCMC' },
    { id: 'node-3', name: 'SGP-Cloud-Gateway', ip: '172.16.50.12', status: 'Active', cpu: 41, ram: 62, region: 'Singapore' },
    { id: 'node-4', name: 'US-East-Tunnel', ip: '192.168.100.5', status: 'Offline', cpu: 0, ram: 0, region: 'Virginia' },
  ]);

  // Firewall State
  const [firewallLogs, setFirewallLogs] = useState([
    { id: 1, time: '22:50:11', ip: '198.51.100.42', action: 'BLOCKED', reason: 'DDoS TCP Flood', risk: 'High' },
    { id: 2, time: '22:50:35', ip: '203.0.113.88', action: 'BLOCKED', reason: 'SSH Brute Force', risk: 'Medium' },
    { id: 3, time: '22:51:02', ip: '185.220.101.5', action: 'BLOCKED', reason: 'Tor Exit Node Scan', risk: 'Low' },
  ]);

  // Terminal Script Automation State
  const [selectedScript, setSelectedScript] = useState('golang'); // golang | typescript
  const [isScriptRunning, setIsScriptRunning] = useState(false);
  const [terminalLogs, setTerminalLogs] = useState([
    'Nexus terminal initialized v2.5.4...',
    'Awaiting target execution script selection.'
  ]);
  const terminalEndRef = useRef(null);

  // Hiển thị thông báo Toast
  const showToast = (message, type = 'success') => {
    setToast({ message, type });
    setTimeout(() => setToast(null), 3000);
  };

  // Cuộn dòng Terminal xuống cuối khi chạy script
  useEffect(() => {
    if (terminalEndRef.current) {
      terminalEndRef.current.scrollIntoView({ behavior: 'smooth' });
    }
  }, [terminalLogs]);

  // Giả lập traffic thời gian thực tăng giảm CPU cho Dashboard sinh động
  useEffect(() => {
    const interval = setInterval(() => {
      setNodes(prev => prev.map(node => {
        if (node.status === 'Active') {
          const deltaCpu = Math.floor(Math.random() * 9) - 4; // -4% đến +4%
          const deltaRam = Math.floor(Math.random() * 5) - 2; // -2% đến +2%
          return {
            ...node,
            cpu: Math.min(Math.max(node.cpu + deltaCpu, 5), 95),
            ram: Math.min(Math.max(node.ram + deltaRam, 10), 90)
          };
        }
        return node;
      }));

      // Thỉnh thoảng đẩy thêm log firewall mới
      if (Math.random() > 0.7) {
        const mockIps = ['182.21.90.10', '93.184.216.34', '142.250.190.46', '8.8.8.8'];
        const mockReasons = ['SQL Injection attempt', 'Port Scanning', 'Unusual API Burst', 'XSS Signature'];
        const mockRisks = ['High', 'Medium', 'Low'];
        const now = new Date();
        const timeStr = `${String(now.getHours()).padStart(2, '0')}:${String(now.getMinutes()).padStart(2, '0')}:${String(now.getSeconds()).padStart(2, '0')}`;
        
        setFirewallLogs(prev => [
          {
            id: Date.now(),
            time: timeStr,
            ip: mockIps[Math.floor(Math.random() * mockIps.length)],
            action: 'BLOCKED',
            reason: mockReasons[Math.floor(Math.random() * mockReasons.length)],
            risk: mockRisks[Math.floor(Math.random() * mockRisks.length)]
          },
          ...prev.slice(0, 7) // Giữ lại tối đa 8 logs gần nhất
        ]);
      }
    }, 3000);

    return () => clearInterval(interval);
  }, []);

  // Hàm kích hoạt/Vô hiệu hóa Node mạng
  const toggleNodeStatus = (id, name) => {
    setNodes(prev => prev.map(node => {
      if (node.id === id) {
        const nextStatus = node.status === 'Active' ? 'Offline' : 'Active';
        showToast(`${nextStatus === 'Active' ? 'Đã bật' : 'Đã ngắt'} kết nối ${name}`, nextStatus === 'Active' ? 'success' : 'info');
        return {
          ...node,
          status: nextStatus,
          cpu: nextStatus === 'Active' ? 15 : 0,
          ram: nextStatus === 'Active' ? 30 : 0
        };
      }
      return node;
    }));
  };

  // Giả lập chạy script tự động hóa mạng bằng Golang / TypeScript
  const runAutomationScript = () => {
    if (isScriptRunning) return;
    setIsScriptRunning(true);
    setTerminalLogs([]);

    const scriptSteps = selectedScript === 'golang' ? [
      '[GO] Initializing Nexus Automation Engine inside Go Runtime...',
      '[GO] Building binary packet generator dependencies...',
      '[GO] Connecting to local cluster endpoint (10.120.1.254)... [OK]',
      '[GO] Fetching current network routing table...',
      '[GO] Syncing 14 global routes dynamically over BGP peering...',
      '[GO] Verifying cryptographic signatures of packets...',
      '[GO] SUCCESS: Automation script pipeline completed in 24.5ms!'
    ] : [
      '[TS] Executing system deployment pipeline via Bun/TypeScript...',
      '[TS] Reading configurations from network-env.config.ts...',
      '[TS] Establishing secure WebSocket connection to US-East Gateway...',
      '[TS] Triggering auto-scale deployment rules...',
      '[TS] Provisioning a secure Virtual Tunnel on US-East-Tunnel...',
      '[TS] Testing end-to-end ping payload (size=64, count=5)... 0.4ms average latency',
      '[TS] SUCCESS: Route table automation initialized and secured.'
    ];

    let currentStep = 0;
    const executeStep = () => {
      if (currentStep < scriptSteps.length) {
        setTerminalLogs(prev => [...prev, scriptSteps[currentStep]]);
        currentStep++;
        setTimeout(executeStep, 800);
      } else {
        setIsScriptRunning(false);
        showToast('Kịch bản tự động hóa mạng hoàn tất!', 'success');
        
        // Tự động bật Node US East Tunnel lên nếu đang chạy script TS thành công
        if (selectedScript === 'typescript') {
          setNodes(prev => prev.map(node => {
            if (node.id === 'node-4') {
              return { ...node, status: 'Active', cpu: 18, ram: 28 };
            }
            return node;
          }));
        }
      }
    };

    setTimeout(executeStep, 200);
  };

  return (
    <div className="flex h-screen w-full bg-slate-950 text-slate-100 overflow-hidden font-sans">
      
      {/* Toast Notification */}
      {toast && (
        <div className="fixed top-5 right-5 z-50 flex items-center gap-3 px-4 py-3 rounded-xl border border-slate-800 bg-slate-900 shadow-2xl animate-bounce">
          <div className={`w-2 h-2 rounded-full ${toast.type === 'success' ? 'bg-emerald-500 shadow-lg shadow-emerald-500/50' : 'bg-blue-500 shadow-lg shadow-blue-500/50'}`} />
          <span className="text-sm font-medium">{toast.message}</span>
        </div>
      )}

      {/* ================= SIDEBAR COMPONENT ================= */}
      <aside
        className={`h-full bg-slate-900/40 backdrop-blur-md border-r border-slate-800/80 flex flex-col justify-between p-4 relative transition-all duration-300 ease-in-out select-none
          ${isOpen ? 'w-64' : 'w-20'}`}
      >
        <div>
          {/* Header: Logo & Toggle Button */}
          <div className="flex items-center justify-between mb-8 h-10 px-1 relative">
            <div className="flex items-center gap-3 overflow-hidden">
              <div className="p-2 bg-blue-600/10 text-blue-500 rounded-xl flex-shrink-0 border border-blue-500/20">
                <svg className="w-5 h-5 animate-pulse" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2.5}>
                  <path strokeLinecap="round" strokeLinejoin="round" d="M13 10V3L4 14h7v7l9-11h-7z" />
                </svg>
              </div>
              <span className={`font-bold text-base tracking-wider bg-gradient-to-r from-blue-400 to-indigo-400 bg-clip-text text-transparent transition-opacity duration-300 whitespace-nowrap ${isOpen ? 'opacity-100' : 'opacity-0'}`}>
                NEXUS OPS
              </span>
            </div>
            
            {/* Nút Toggle dạng tròn cực chất đè lên viền phải */}
            <button
              onClick={() => setIsOpen(!isOpen)}
              className="absolute -right-7 top-2 bg-slate-900 hover:bg-slate-800 text-slate-400 hover:text-slate-100 border border-slate-800 p-1.5 rounded-full transition-all duration-200 shadow-xl z-20"
            >
              {isOpen ? <Icons.ArrowLeft /> : <Icons.ArrowRight />}
            </button>
          </div>

          {/* Body: Danh sách các thẻ điều hướng Menu chính */}
          <nav className="space-y-1.5">
            <SidebarItem
              icon={Icons.Dashboard}
              label="Bảng Giám Sát"
              isOpen={isOpen}
              isActive={activeTab === 'dashboard'}
              onClick={() => setActiveTab('dashboard')}
            />
            <SidebarItem
              icon={Icons.Nodes}
              label="Cụm Thiết Bị Mạng"
              isOpen={isOpen}
              isActive={activeTab === 'nodes'}
              onClick={() => setActiveTab('nodes')}
            />
            <SidebarItem
              icon={Icons.Firewall}
              label="Tường Lửa Bảo Mật"
              isOpen={isOpen}
              isActive={activeTab === 'firewall'}
              onClick={() => setActiveTab('firewall')}
            />
            <SidebarItem
              icon={Icons.Automation}
              label="Tự Động Hóa Script"
              isOpen={isOpen}
              isActive={activeTab === 'automation'}
              onClick={() => setActiveTab('automation')}
            />
          </nav>
        </div>

        {/* Footer Sidebar: Cấu hình hệ thống */}
        <div className="border-t border-slate-800/80 pt-4">
          <SidebarItem 
            icon={Icons.Settings} 
            label="Thiết Lập Hệ Thống" 
            isOpen={isOpen} 
            isActive={activeTab === 'settings'}
            onClick={() => setActiveTab('settings')}
          />
        </div>
      </aside>

      {/* ================= PHẦN HIỂN THỊ NỘI DUNG CHÍNH (MAIN CONTENT) ================= */}
      <main className="flex-1 p-8 overflow-y-auto bg-slate-950 flex flex-col">
        <div className="max-w-6xl w-full mx-auto flex-1 flex flex-col">
          
          {/* Header Khu Vực Nội Dung */}
          <div className="border-b border-slate-800/80 pb-5 mb-8 flex flex-col md:flex-row md:items-center md:justify-between gap-4">
            <div>
              <h1 className="text-2xl font-bold tracking-tight text-white flex items-center gap-2">
                {activeTab === 'dashboard' && 'Bảng Giám Sát Hệ Thống'}
                {activeTab === 'nodes' && 'Quản Lý Cụm Thiết Bị Mạng'}
                {activeTab === 'firewall' && 'Nhật Ký Tường Lửa Real-time'}
                {activeTab === 'automation' && 'Tự Động Hóa Cấu Hình Mạng (Network Automation)'}
                {activeTab === 'settings' && 'Cài Đặt Hệ Thống'}
              </h1>
              <p className="text-slate-400 text-sm mt-1">
                {activeTab === 'dashboard' && 'Giám sát độ trễ, lưu lượng băng thông quốc tế và hoạt động hạ tầng.'}
                {activeTab === 'nodes' && 'Theo dõi trạng thái vật lý và ảo hóa của các Core-Switch, Edge-Router.'}
                {activeTab === 'firewall' && 'Cập nhật trực tiếp các gói tin bất thường được hệ thống IDS/IPS ngăn chặn.'}
                {activeTab === 'automation' && 'Sử dụng Golang hoặc TypeScript để tự động phân luồng VLAN và tối ưu định tuyến.'}
                {activeTab === 'settings' && 'Quản lý các Token phân quyền, thông số hạ tầng mạng đám mây Nexus.'}
              </p>
            </div>
            
            {/* Live Indicator giả lập */}
            <div className="flex items-center gap-2 bg-slate-900 border border-slate-800 px-3.5 py-1.5 rounded-full self-start md:self-auto">
              <span className="relative flex h-2 w-2">
                <span className="animate-ping absolute inline-flex h-full w-full rounded-full bg-emerald-400 opacity-75"></span>
                <span className="relative inline-flex rounded-full h-2 w-2 bg-emerald-500"></span>
              </span>
              <span className="text-xs font-semibold text-emerald-400 uppercase tracking-wider">Hệ Thống Trực Tuyến</span>
            </div>
          </div>

          {/* ================= TAB 1: BẢNG GIÁM SÁT (DASHBOARD) ================= */}
          {activeTab === 'dashboard' && (
            <div className="space-y-6 animate-fadeIn">
              {/* Grid 4 Chỉ Số Cơ Bản */}
              <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
                <div className="bg-slate-900/40 border border-slate-800 p-5 rounded-2xl flex flex-col justify-between">
                  <span className="text-xs font-semibold text-blue-400 uppercase tracking-wider">Ping Quốc Tế Trung Bình</span>
                  <div className="flex items-baseline gap-2 mt-3">
                    <span className="text-2xl font-bold tracking-tight">14.2 ms</span>
                    <span className="text-xs text-emerald-400">▼ 1.2ms</span>
                  </div>
                </div>
                <div className="bg-slate-900/40 border border-slate-800 p-5 rounded-2xl flex flex-col justify-between">
                  <span className="text-xs font-semibold text-emerald-400 uppercase tracking-wider">Tổng Băng Thông WAN</span>
                  <div className="flex items-baseline gap-2 mt-3">
                    <span className="text-2xl font-bold tracking-tight">8.42 Gbps</span>
                    <span className="text-xs text-emerald-400">▲ 14%</span>
                  </div>
                </div>
                <div className="bg-slate-900/40 border border-slate-800 p-5 rounded-2xl flex flex-col justify-between">
                  <span className="text-xs font-semibold text-amber-400 uppercase tracking-wider">CPU Trung Bình</span>
                  <div className="flex items-baseline gap-2 mt-3">
                    <span className="text-2xl font-bold tracking-tight">
                      {Math.floor(nodes.reduce((acc, node) => acc + node.cpu, 0) / nodes.length)}%
                    </span>
                    <span className="text-xs text-slate-400">Tối ưu</span>
                  </div>
                </div>
                <div className="bg-slate-900/40 border border-slate-800 p-5 rounded-2xl flex flex-col justify-between">
                  <span className="text-xs font-semibold text-purple-400 uppercase tracking-wider">Tỉ Lệ Uptime (SLA)</span>
                  <div className="flex items-baseline gap-2 mt-3">
                    <span className="text-2xl font-bold tracking-tight">99.98%</span>
                    <span className="text-xs text-emerald-400">Đạt chuẩn</span>
                  </div>
                </div>
              </div>

              {/* Biểu Đồ Lưu Lượng Mạng Giả Lập Bằng SVG */}
              <div className="bg-slate-900/30 border border-slate-800 rounded-2xl p-6">
                <div className="flex items-center justify-between mb-6">
                  <div>
                    <h3 className="font-semibold text-white">Lưu Lượng Truyền Tải (Băng thông WAN)</h3>
                    <p className="text-xs text-slate-400 mt-0.5">Biểu đồ giám sát 12 giờ qua</p>
                  </div>
                  <div className="flex gap-4 text-xs font-medium">
                    <span className="flex items-center gap-1.5"><span className="w-2.5 h-2.5 rounded-full bg-blue-500 inline-block"></span>Trong Nước</span>
                    <span className="flex items-center gap-1.5"><span className="w-2.5 h-2.5 rounded-full bg-indigo-500 inline-block"></span>Quốc Tế</span>
                  </div>
                </div>
                
                {/* SVG Chart */}
                <div className="w-full h-48 bg-slate-950/50 rounded-xl relative overflow-hidden border border-slate-900 flex items-end">
                  <svg className="absolute inset-0 w-full h-full" preserveAspectRatio="none">
                    <defs>
                      <linearGradient id="blueGrad" x1="0" y1="0" x2="0" y2="1">
                        <stop offset="0%" stopColor="#3b82f6" stopOpacity="0.2"/>
                        <stop offset="100%" stopColor="#3b82f6" stopOpacity="0"/>
                      </linearGradient>
                      <linearGradient id="indigoGrad" x1="0" y1="0" x2="0" y2="1">
                        <stop offset="0%" stopColor="#6366f1" stopOpacity="0.15"/>
                        <stop offset="100%" stopColor="#6366f1" stopOpacity="0"/>
                      </linearGradient>
                    </defs>
                    {/* Grid Lines */}
                    <line x1="0" y1="25%" x2="100%" y2="25%" stroke="#1e293b" strokeDasharray="4 4" />
                    <line x1="0" y1="50%" x2="100%" y2="50%" stroke="#1e293b" strokeDasharray="4 4" />
                    <line x1="0" y1="75%" x2="100%" y2="75%" stroke="#1e293b" strokeDasharray="4 4" />
                    
                    {/* SVG Line 1 (Trong nước) */}
                    <path d="M 0 120 Q 80 140 160 100 T 320 80 T 480 110 T 640 50 T 800 90 T 960 70 L 1200 60 L 1200 192 L 0 192 Z" fill="url(#blueGrad)" />
                    <path d="M 0 120 Q 80 140 160 100 T 320 80 T 480 110 T 640 50 T 800 90 T 960 70 L 1200 60" fill="none" stroke="#3b82f6" strokeWidth="2" />
                    
                    {/* SVG Line 2 (Quốc tế) */}
                    <path d="M 0 150 Q 80 130 160 150 T 320 120 T 480 130 T 640 90 T 800 130 T 960 110 L 1200 100 L 1200 192 L 0 192 Z" fill="url(#indigoGrad)" />
                    <path d="M 0 150 Q 80 130 160 150 T 320 120 T 480 130 T 640 90 T 800 130 T 960 110 L 1200 100" fill="none" stroke="#6366f1" strokeWidth="1.5" />
                  </svg>
                  <div className="absolute bottom-2 left-4 text-[10px] text-slate-500 font-mono">00:00</div>
                  <div className="absolute bottom-2 left-1/2 -translate-x-1/2 text-[10px] text-slate-500 font-mono">06:00</div>
                  <div className="absolute bottom-2 right-4 text-[10px] text-slate-500 font-mono">Now</div>
                </div>
              </div>
            </div>
          )}

          {/* ================= TAB 2: CỤM THIẾT BỊ MẠNG (NODES) ================= */}
          {activeTab === 'nodes' && (
            <div className="space-y-6 animate-fadeIn">
              <div className="flex items-center justify-between">
                <span className="text-sm text-slate-400">Tổng cộng {nodes.length} thực thể hạ tầng cơ sở</span>
                <button 
                  onClick={() => {
                    showToast('Đang quét làm mới mạng lưới thiết bị...', 'info');
                  }} 
                  className="flex items-center gap-2 text-xs bg-slate-900 border border-slate-800 hover:bg-slate-800 px-3 py-2 rounded-lg text-slate-200 transition-all font-medium"
                >
                  <Icons.Refresh /> Làm mới
                </button>
              </div>

              {/* Grid Nodes */}
              <div className="grid grid-cols-1 md:grid-cols-2 gap-5">
                {nodes.map(node => (
                  <div key={node.id} className="bg-slate-900/30 border border-slate-800/80 rounded-2xl p-5 hover:border-slate-700/80 transition-all duration-300">
                    <div className="flex items-center justify-between mb-4">
                      <div className="flex items-center gap-3">
                        {/* Biểu tượng trạng thái Node */}
                        <div className={`w-3 h-3 rounded-full ${node.status === 'Active' ? 'bg-emerald-500 shadow-md shadow-emerald-500/30' : 'bg-slate-600'}`} />
                        <div>
                          <h4 className="font-semibold text-white">{node.name}</h4>
                          <span className="text-xs text-slate-400 font-mono">{node.ip}</span>
                        </div>
                      </div>
                      
                      {/* Toggle Switch */}
                      <button
                        onClick={() => toggleNodeStatus(node.id, node.name)}
                        className={`w-11 h-6 rounded-full p-1 transition-all duration-300 focus:outline-none ${node.status === 'Active' ? 'bg-blue-600' : 'bg-slate-800'}`}
                      >
                        <div className={`bg-white w-4 h-4 rounded-full shadow-md transform transition-transform duration-300 ${node.status === 'Active' ? 'translate-x-5' : 'translate-x-0'}`} />
                      </button>
                    </div>

                    {/* Chỉ số CPU & RAM */}
                    {node.status === 'Active' ? (
                      <div className="space-y-3 mt-4">
                        {/* CPU Bar */}
                        <div>
                          <div className="flex justify-between text-xs font-semibold mb-1">
                            <span className="text-slate-400">Sử dụng CPU</span>
                            <span className="text-blue-400">{node.cpu}%</span>
                          </div>
                          <div className="h-1.5 w-full bg-slate-800 rounded-full overflow-hidden">
                            <div className="h-full bg-blue-500 transition-all duration-300" style={{ width: `${node.cpu}%` }} />
                          </div>
                        </div>
                        {/* RAM Bar */}
                        <div>
                          <div className="flex justify-between text-xs font-semibold mb-1">
                            <span className="text-slate-400">Sử dụng RAM</span>
                            <span className="text-indigo-400">{node.ram}%</span>
                          </div>
                          <div className="h-1.5 w-full bg-slate-800 rounded-full overflow-hidden">
                            <div className="h-full bg-indigo-500 transition-all duration-300" style={{ width: `${node.ram}%` }} />
                          </div>
                        </div>
                        <div className="pt-2 text-[11px] text-slate-500 flex justify-between font-medium">
                          <span>Vị trí: {node.region}</span>
                          <span>Ping kiểm tra: OK</span>
                        </div>
                      </div>
                    ) : (
                      <div className="h-24 flex items-center justify-center border border-dashed border-slate-800 rounded-xl mt-4">
                        <span className="text-xs text-slate-500 italic">Thiết bị hiện đang tắt hoặc mất kết nối WAN</span>
                      </div>
                    )}
                  </div>
                ))}
              </div>
            </div>
          )}

          {/* ================= TAB 3: TƯỜNG LỬA BẢO MẬT (FIREWALL) ================= */}
          {activeTab === 'firewall' && (
            <div className="space-y-6 animate-fadeIn flex-1 flex flex-col">
              <div className="bg-slate-900/30 border border-slate-800 rounded-2xl p-5 flex-1 flex flex-col">
                <div className="flex items-center justify-between mb-4 border-b border-slate-800 pb-4">
                  <h3 className="font-semibold text-white">Live IPS/IDS Packet Block-logs</h3>
                  <span className="text-xs bg-red-500/10 text-red-400 px-2 py-1 border border-red-500/20 rounded-md font-medium">Auto-filtering Active</span>
                </div>
                
                {/* Table Logs */}
                <div className="overflow-x-auto flex-1">
                  <table className="w-full text-left border-collapse">
                    <thead>
                      <tr className="border-b border-slate-800 text-slate-400 text-xs uppercase tracking-wider font-semibold">
                        <th className="py-3 px-4">Thời Gian</th>
                        <th className="py-3 px-4">IP Nguồn</th>
                        <th className="py-3 px-4">Hành Động</th>
                        <th className="py-3 px-4">Nguyên Nhân Chặn</th>
                        <th className="py-3 px-4 text-right">Rủi Ro</th>
                      </tr>
                    </thead>
                    <tbody className="text-sm font-medium">
                      {firewallLogs.map(log => (
                        <tr key={log.id} className="border-b border-slate-800/40 hover:bg-slate-900/10 transition-colors">
                          <td className="py-3 px-4 text-slate-500 font-mono">{log.time}</td>
                          <td className="py-3 px-4 text-slate-200 font-mono">{log.ip}</td>
                          <td className="py-3 px-4">
                            <span className="px-2 py-0.5 rounded text-[11px] font-bold bg-rose-500/10 text-rose-500 border border-rose-500/20">
                              {log.action}
                            </span>
                          </td>
                          <td className="py-3 px-4 text-slate-300">{log.reason}</td>
                          <td className="py-3 px-4 text-right">
                            <span className={`text-xs ${
                              log.risk === 'High' ? 'text-red-400 font-bold' :
                              log.risk === 'Medium' ? 'text-amber-400' : 'text-blue-400'
                            }`}>
                              {log.risk}
                            </span>
                          </td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              </div>
            </div>
          )}

          {/* ================= TAB 4: TỰ ĐỘNG HÓA SCRIPT (AUTOMATION) ================= */}
          {activeTab === 'automation' && (
            <div className="space-y-6 animate-fadeIn flex-1 flex flex-col">
              <div className="grid grid-cols-1 lg:grid-cols-3 gap-6 flex-1">
                
                {/* Script Panel Selection */}
                <div className="bg-slate-900/30 border border-slate-800 rounded-2xl p-5 space-y-4">
                  <h3 className="font-semibold text-white">Lựa Chọn Kịch Bản</h3>
                  
                  {/* Option 1: Golang Script */}
                  <button 
                    onClick={() => setSelectedScript('golang')}
                    disabled={isScriptRunning}
                    className={`w-full p-4 rounded-xl text-left border transition-all duration-200 ${
                      selectedScript === 'golang' 
                        ? 'bg-blue-600/10 border-blue-500 text-white' 
                        : 'bg-slate-900/40 border-slate-800/80 text-slate-400 hover:border-slate-700'
                    }`}
                  >
                    <div className="flex items-center justify-between">
                      <h4 className="font-bold text-sm">Deploy_BGP_VLAN.go</h4>
                      <span className="text-[10px] bg-slate-800 text-slate-300 px-1.5 py-0.5 rounded font-mono font-semibold">Golang</span>
                    </div>
                    <p className="text-xs text-slate-400 mt-2">Đồng bộ hóa 14 định tuyến ảo, định hình VLAN nhanh và bảo mật.</p>
                  </button>

                  {/* Option 2: TypeScript Script */}
                  <button 
                    onClick={() => setSelectedScript('typescript')}
                    disabled={isScriptRunning}
                    className={`w-full p-4 rounded-xl text-left border transition-all duration-200 ${
                      selectedScript === 'typescript' 
                        ? 'bg-blue-600/10 border-blue-500 text-white' 
                        : 'bg-slate-900/40 border-slate-800/80 text-slate-400 hover:border-slate-700'
                    }`}
                  >
                    <div className="flex items-center justify-between">
                      <h4 className="font-bold text-sm">GatewayTunnelSync.ts</h4>
                      <span className="text-[10px] bg-slate-800 text-slate-300 px-1.5 py-0.5 rounded font-mono font-semibold">TypeScript</span>
                    </div>
                    <p className="text-xs text-slate-400 mt-2">Kiểm tra kết nối và cấu hình tự động Tunnel bảo mật cho cụm Virginia US-East.</p>
                  </button>

                  {/* Run Button */}
                  <button
                    onClick={runAutomationScript}
                    disabled={isScriptRunning}
                    className={`w-full py-3.5 rounded-xl text-center font-semibold text-sm transition-all duration-300 flex items-center justify-center gap-2
                      ${isScriptRunning 
                        ? 'bg-slate-800 text-slate-500 cursor-not-allowed border border-slate-700/50' 
                        : 'bg-blue-600 hover:bg-blue-500 text-white shadow-lg shadow-blue-500/20'
                      }`}
                  >
                    {isScriptRunning ? (
                      <>
                        <svg className="animate-spin h-5 w-5 text-slate-500" xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24">
                          <circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4"></circle>
                          <path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4zm2 5.291A7.962 7.962 0 014 12H0c0 3.042 1.135 5.824 3 7.938l3-2.647z"></path>
                        </svg>
                        Đang Biên Dịch & Chạy...
                      </>
                    ) : (
                      <>
                        <svg className="w-5 h-5" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2.5}>
                          <path strokeLinecap="round" strokeLinejoin="round" d="M14.752 11.168l-3.197-2.132A1 1 0 0010 9.87v4.263a1 1 0 001.555.832l3.197-2.132a1 1 0 000-1.664z" />
                          <path strokeLinecap="round" strokeLinejoin="round" d="M21 12a9 9 0 11-18 0 9 9 0 0118 0z" />
                        </svg>
                        Khởi Chạy Script Ngay
                      </>
                    )}
                  </button>
                </div>

                {/* Terminal Console */}
                <div className="lg:col-span-2 bg-slate-950 border border-slate-800 rounded-2xl flex flex-col p-4 font-mono text-sm relative shadow-inner">
                  <div className="flex items-center justify-between border-b border-slate-900 pb-3 mb-4">
                    <span className="text-xs text-slate-500">NEXUS SCRIPT TERMINAL</span>
                    <div className="flex gap-1.5">
                      <span className="w-2.5 h-2.5 rounded-full bg-slate-800"></span>
                      <span className="w-2.5 h-2.5 rounded-full bg-slate-800"></span>
                      <span className="w-2.5 h-2.5 rounded-full bg-slate-800"></span>
                    </div>
                  </div>
                  
                  {/* Console Logs Area */}
                  <div className="flex-1 overflow-y-auto space-y-2.5 max-h-[280px] text-xs leading-relaxed">
                    {terminalLogs.map((log, index) => (
                      <div key={index} className={`${
                        log.includes('SUCCESS') ? 'text-emerald-400 font-bold' : 
                        log.includes('[GO]') ? 'text-cyan-400' :
                        log.includes('[TS]') ? 'text-indigo-400' : 'text-slate-400'
                      }`}>
                        {log}
                      </div>
                    ))}
                    {/* Thụt dòng khi đang chạy script */}
                    {isScriptRunning && (
                      <div className="text-slate-500 animate-pulse">Running step configuration...</div>
                    )}
                    <div ref={terminalEndRef} />
                  </div>
                </div>

              </div>
            </div>
          )}

          {/* ================= TAB 5: CÀI ĐẶT HỆ THỐNG (SETTINGS) ================= */}
          {activeTab === 'settings' && (
            <div className="space-y-6 animate-fadeIn">
              <div className="bg-slate-900/30 border border-slate-800 rounded-2xl p-6 space-y-6">
                <div>
                  <h3 className="font-semibold text-white mb-4">API Token & Xác Thực Bảo Mật</h3>
                  <div className="space-y-3">
                    <div className="flex flex-col gap-1.5">
                      <label className="text-xs text-slate-400 font-semibold">NEXUS PRIVATE ACCESS KEY</label>
                      <div className="flex gap-2">
                        <input 
                          type="password" 
                          readOnly 
                          value="••••••••••••••••••••••••••••••••••••••••" 
                          className="flex-1 bg-slate-950 border border-slate-800 rounded-xl px-4 py-2.5 text-xs text-slate-300 font-mono"
                        />
                        <button 
                          onClick={() => showToast('Đã sao chép khóa truy cập API!', 'success')}
                          className="bg-slate-800 hover:bg-slate-700 text-xs px-4 py-2.5 rounded-xl border border-slate-700/50 font-semibold text-slate-200 transition-colors"
                        >
                          Sao Chép
                        </button>
                      </div>
                    </div>
                  </div>
                </div>

                <div className="border-t border-slate-800/80 pt-6">
                  <h3 className="font-semibold text-white mb-4">Phương Thức Định Tuyến Ưu Tiên</h3>
                  <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
                    <div className="bg-slate-950/60 p-4 rounded-xl border border-blue-500/20 relative">
                      <span className="text-xs font-bold text-blue-400">Dynamic BGP Routing</span>
                      <p className="text-xs text-slate-400 mt-1">Định tuyến động thích ứng tối đa 14 node, tự động phục hồi kết nối bị đứt gãy.</p>
                      <div className="absolute top-4 right-4"><Icons.Check /></div>
                    </div>
                    <div className="bg-slate-950/30 p-4 rounded-xl border border-slate-800 opacity-50 hover:opacity-80 transition-all cursor-pointer">
                      <span className="text-xs font-bold text-slate-400">Static Routing Mode</span>
                      <p className="text-xs text-slate-500 mt-1">Sử dụng bảng định tuyến cố định, an toàn nhưng không tự động mở rộng.</p>
                    </div>
                  </div>
                </div>
              </div>
            </div>
          )}

        </div>
      </main>

    </div>
  );
}