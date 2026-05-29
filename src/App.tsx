import React, { useState, useEffect } from 'react';
import { 
  Network, Play, Square, RefreshCw, Layers, Cpu, Eye, Code, 
  Settings, Download, Plus, Trash2, CheckCircle2, AlertTriangle, 
  BookOpen, ChevronRight, FileCode2, Copy, Search, Terminal,
  HelpCircle, Server, Globe, ExternalLink
} from 'lucide-react';
import { Header } from './components/Header.js';
import { ConsoleLogs } from './components/ConsoleLogs.js';
import { PacketConfig, LayerType, SendConfig, SendStats, CapturedPacket, LogItem, NetworkInterface, SavedTemplate } from './types.js';
import { STANDARD_PRESETS, EMPTY_PACKET } from './presets.js';

export default function App() {
  // Connection states
  const [backendUrl, setBackendUrl] = useState<string>('');
  const [isConnected, setIsConnected] = useState<boolean>(true); // connected to local mocked/real API on container
  const [activeTab, setActiveTab] = useState<'build' | 'monitor' | 'templates' | 'agent'>('build');
  
  // Real or Simulated Interfaces list
  const [interfaces, setInterfaces] = useState<NetworkInterface[]>([
    { name: 'eth0 (Default Primary Interface)', ip: '192.168.1.102', mac: '00:0c:29:ab:cd:ef', description: 'Intel Pro Gigabit Ethernet Core Card' },
    { name: 'wlan0 (Wireless network Card)', ip: '192.168.31.54', mac: 'ac:bc:32:df:2e:11', description: 'MediaTek MT7921 Wi-Fi 6 wireless' },
    { name: 'lo (Local Loopback)', ip: '127.0.0.1', mac: '00:00:00:00:00:00', description: 'Software loopback network device' }
  ]);
  
  // Config state
  const [packet, setPacket] = useState<PacketConfig>(JSON.parse(JSON.stringify(STANDARD_PRESETS[0].packet)));
  const [sendConfig, setSendConfig] = useState<SendConfig>({
    interfaceName: 'eth0 (Default Primary Interface)',
    mode: 'count',
    count: 100,
    intervalMs: 100,
    rateLimitPps: 50,
    durationSec: 10
  });

  // Backend real-time stats
  const [stats, setStats] = useState<SendStats>({
    status: 'idle',
    sentCount: 0,
    successCount: 0,
    failCount: 0,
    lossRate: 0,
    currentPps: 0,
    elapsedTimeMs: 0
  });

  // Packets and logs
  const [logs, setLogs] = useState<LogItem[]>([]);
  const [captured, setCaptured] = useState<CapturedPacket[]>([]);
  const [selectedCapturedPacket, setSelectedCapturedPacket] = useState<CapturedPacket | null>(null);
  
  // Custom templates manually saved by customer
  const [savedTemplates, setSavedTemplates] = useState<SavedTemplate[]>([
    {
      id: 'syn-flood-tpl',
      name: 'TCP SYN 洪水探测模板',
      description: '对网络边缘高防设备进行DDoS抗性吞吐测试报文',
      createdAt: '2026-05-29 14:00',
      packet: STANDARD_PRESETS[0].packet
    },
    {
      id: 'arp-poisoning-tpl',
      name: 'ARP 虚拟路由中继校验',
      description: '发送ARP Request判断欺骗响应与防御策略',
      createdAt: '2026-05-29 14:05',
      packet: STANDARD_PRESETS[1].packet
    }
  ]);

  // UI helpers & analysis responses
  const [analysis, setAnalysis] = useState<{
    size: number;
    hexDump: string;
    asciiDump: string;
    layersInfo: string[];
  } | null>(null);
  
  const [scapyCode, setScapyCode] = useState<string>('');
  const [newTemplateName, setNewTemplateName] = useState('');
  const [newTemplateDesc, setNewTemplateDesc] = useState('');
  const [isSavingTemplateMode, setIsSavingTemplateMode] = useState(false);
  const [activeLayer, setActiveLayer] = useState<LayerType>('ETHERNET');
  const [searchTerm, setSearchTerm] = useState('');
  
  // Scapy standalone agent installation script display state
  const [selectedAgentOs, setSelectedAgentOs] = useState<'linux' | 'windows'>('linux');
  const [showHelpModal, setShowHelpModal] = useState<boolean>(false);
  const [isCopied, setIsCopied] = useState<boolean>(false);

  // Initialize and check health/adapters list
  useEffect(() => {
    fetchInterfaces();
    refreshInitState();
    triggerAnalysis(packet);
    
    // Set up SSE for live-stream stats and logs
    const sse = new EventSource('/api/send/sse-stats');
    
    sse.addEventListener('session-init', (e: any) => {
      try {
        const raw = JSON.parse(e.data);
        if (raw.stats) setStats(raw.stats);
        if (raw.logs) setLogs(raw.logs);
      } catch (err) {}
    });

    sse.addEventListener('stats', (e: any) => {
      try {
        setStats(JSON.parse(e.data));
      } catch (err) {}
    });

    sse.addEventListener('log', (e: any) => {
      try {
        const logItem = JSON.parse(e.data) as LogItem;
        setLogs(prev => [...prev, logItem]);
      } catch (err) {}
    });

    sse.addEventListener('packet', (e: any) => {
      try {
        const packetItem = JSON.parse(e.data) as CapturedPacket;
        setCaptured(prev => {
          const list = [...prev, packetItem];
          if (list.length > 300) list.shift();
          return list;
        });
      } catch (err) {}
    });

    sse.onopen = () => setIsConnected(true);
    sse.onerror = () => setIsConnected(false);

    return () => {
      sse.close();
    };
  }, []);

  // Update scapy generator side-loaded script whenever packet changes
  useEffect(() => {
    generateScapyRemote(packet, sendConfig);
  }, [packet, sendConfig]);

  const fetchInterfaces = async () => {
    try {
      const res = await fetch('/api/interfaces');
      const data = await res.json();
      if (data.success && data.interfaces?.length > 0) {
        setInterfaces(data.interfaces);
        setSendConfig(prev => ({
          ...prev,
          interfaceName: data.interfaces[0].name
        }));
      }
    } catch (e) {}
  };

  const refreshInitState = async () => {
    try {
      const res = await fetch('/api/send/init-state');
      const data = await res.json();
      if (data.success) {
        if (data.stats) setStats(data.stats);
        if (data.logs) setLogs(data.logs);
        if (data.packets) {
          setCaptured(data.packets);
          if (data.packets.length > 0) {
            setSelectedCapturedPacket(data.packets[data.packets.length - 1]);
          }
        }
      }
    } catch (e) {}
  };

  const triggerAnalysis = async (pktToAnalyze: PacketConfig) => {
    try {
      const res = await fetch('/api/packet/analyze', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ packet: pktToAnalyze })
      });
      const data = await res.json();
      if (data.success) {
        setAnalysis({
          size: data.size,
          hexDump: data.hexDump,
          asciiDump: data.asciiDump,
          layersInfo: data.layersInfo
        });
      }
    } catch (e) {}
  };

  const generateScapyRemote = async (pkt: PacketConfig, sc: SendConfig) => {
    try {
      const res = await fetch('/api/scapy/generate', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ packet: pkt, sendConfig: sc })
      });
      const data = await res.json();
      if (data.success) {
        setScapyCode(data.pyCode);
      }
    } catch (e) {}
  };

  // Start injecting protocol transmission
  const handleStartTransmitting = async () => {
    // Clear display before launching next batch
    setCaptured([]);
    setSelectedCapturedPacket(null);
    
    try {
      const res = await fetch('/api/send/start', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ packet, sendConfig })
      });
      const data = await res.json();
      if (data.success) {
        setStats(data.stats);
        setActiveTab('monitor');
      } else {
        alert('错误: ' + data.error);
      }
    } catch (e) {
      alert('无法与发包后端连接。请确保持久 agent 在此端口下运行。');
    }
  };

  // Stop transmitting
  const handleStopTransmitting = async () => {
    try {
      await fetch('/api/send/stop', { method: 'POST' });
    } catch (e) {}
  };

  // Clear monitoring logs and tables
  const handleClearStats = async () => {
    try {
      const res = await fetch('/api/send/clear', { method: 'POST' });
      if (res.ok) {
        setCaptured([]);
        setSelectedCapturedPacket(null);
        setStats({
          status: 'idle',
          sentCount: 0,
          successCount: 0,
          failCount: 0,
          lossRate: 0,
          currentPps: 0,
          elapsedTimeMs: 0
        });
      }
    } catch (e) {}
  };

  // Preset quick-loading action triggered on list selections
  const handleLoadPreset = (presetPacket: PacketConfig) => {
    const cloned = JSON.parse(JSON.stringify(presetPacket));
    setPacket(cloned);
    triggerAnalysis(cloned);
    // Auto-select corresponding layer tab for visual guidance
    if (cloned.enabledLayers.includes('ARP')) {
      setActiveLayer('ARP');
    } else if (cloned.enabledLayers.includes('TCP')) {
      setActiveLayer('TCP');
    } else if (cloned.enabledLayers.includes('UDP')) {
      setActiveLayer('UDP');
    } else {
      setActiveLayer('ETHERNET');
    }
    
    // Log info
    setLogs(prev => [
      ...prev,
      {
        id: Math.random().toString(),
        timestamp: new Date().toLocaleTimeString(),
        level: 'info',
        message: `加载报文模板: "${cloned.name}" 已填充各协议字段。`
      }
    ]);
  };

  // Form field modifier
  const updatePacketField = (layer: LayerType, field: string, value: any) => {
    setPacket(prev => {
      const updated = { ...prev };
      if (!updated.layers[layer]) {
        updated.layers[layer] = {} as any;
      }
      (updated.layers[layer] as any)[field] = value;
      // Trigger update hooks
      setTimeout(() => triggerAnalysis(updated), 20);
      return updated;
    });
  };

  const toggleLayerEnabled = (layer: LayerType) => {
    setPacket(prev => {
      const updated = { ...prev };
      if (updated.enabledLayers.includes(layer)) {
        // cannot disable ETHERNET as outer carrier
        if (layer === 'ETHERNET') return prev;
        updated.enabledLayers = updated.enabledLayers.filter(l => l !== layer);
      } else {
        updated.enabledLayers.push(layer);
        // Exclusivity guards
        if (layer === 'ARP') {
          // If ARP is enabled, remove IP layers and L4 on standard systems
          updated.enabledLayers = updated.enabledLayers.filter(l => l !== 'IPV4' && l !== 'IPV6' && l !== 'TCP' && l !== 'UDP' && l !== 'ICMP');
        } else if (['IPV4', 'IPV6'].includes(layer)) {
          updated.enabledLayers = updated.enabledLayers.filter(l => l !== 'ARP');
          if (layer === 'IPV4') updated.enabledLayers = updated.enabledLayers.filter(l => l !== 'IPV6');
          if (layer === 'IPV6') updated.enabledLayers = updated.enabledLayers.filter(l => l !== 'IPV4');
        } else if (['TCP', 'UDP', 'ICMP'].includes(layer)) {
          updated.enabledLayers = updated.enabledLayers.filter(l => l !== 'ARP');
          updated.enabledLayers = updated.enabledLayers.filter(l => l !== 'TCP' && l !== 'UDP' && l !== 'ICMP');
          updated.enabledLayers.push(layer);
        }
      }
      setTimeout(() => triggerAnalysis(updated), 20);
      return updated;
    });
  };

  // Add customized packet template to local list
  const handleSaveAsTemplate = () => {
    if (!newTemplateName.trim()) {
      alert('请输入模板名称');
      return;
    }
    const newTpl: SavedTemplate = {
      id: Math.random().toString(),
      name: newTemplateName,
      description: newTemplateDesc || '用户自定义网络发包组合模板',
      createdAt: new Date().toISOString().replace('T', ' ').substring(0, 16),
      packet: JSON.parse(JSON.stringify(packet))
    };
    setSavedTemplates(prev => [newTpl, ...prev]);
    setNewTemplateName('');
    setNewTemplateDesc('');
    setIsSavingTemplateMode(false);
    alert('模板保存成功，可在 "报文模板" 标签页查看与一键复用。');
  };

  const deleteTemplate = (id: string) => {
    setSavedTemplates(p => p.filter(t => t.id !== id));
  };

  // Clipboard copies helper
  const handleCopyToClipboard = (text: string) => {
    navigator.clipboard.writeText(text);
    setIsCopied(true);
    setTimeout(() => setIsCopied(false), 2000);
  };

  return (
    <div className="min-h-screen bg-[#070A13] text-[#CBD5E1] flex flex-col font-sans select-none antialiased">
      {/* Header */}
      <Header 
        isBackendConnected={isConnected} 
        onShowHelp={() => setShowHelpModal(true)} 
      />

      {/* Main Grid Workspace Layout */}
      <div className="flex-1 max-w-[1700px] w-full mx-auto p-4 lg:p-6 grid grid-cols-1 xl:grid-cols-12 gap-6 items-stretch">
        
        {/* Left Interactive Control Panel (Packet Assemble Form & Injection speed) */}
        <div className="xl:col-span-8 flex flex-col space-y-6">
          
          {/* Section: Sub-nav Tab selection mimicking Ixia professional dashboard */}
          <div className="bg-[#0B0F19] rounded-xl border border-[#1E293B] p-2 flex items-center justify-between shadow-lg">
            <div className="flex items-center space-x-1">
              <button
                onClick={() => setActiveTab('build')}
                className={`px-4 py-2.5 rounded-lg flex items-center space-x-2 text-xs font-bold transition-all cursor-pointer ${
                  activeTab === 'build' 
                    ? 'bg-blue-600/15 text-blue-400 border border-blue-500/25 shadow-sm shadow-blue-500/10' 
                    : 'text-slate-400 hover:text-slate-200 hover:bg-slate-800/40 border border-transparent'
                }`}
              >
                <Layers className="w-3.5 h-3.5" />
                <span>Visual 协议组装面板</span>
              </button>
              
              <button
                onClick={() => setActiveTab('monitor')}
                className={`px-4 py-2.5 rounded-lg flex items-center space-x-2 text-xs font-bold transition-all cursor-pointer relative ${
                  activeTab === 'monitor' 
                    ? 'bg-emerald-600/15 text-emerald-400 border border-emerald-500/25 shadow-sm shadow-emerald-500/10' 
                    : 'text-slate-400 hover:text-slate-200 hover:bg-slate-800/40 border border-transparent'
                }`}
              >
                <Cpu className="w-3.5 h-3.5" />
                <span>实时发包监控网格</span>
                {stats.status === 'sending' && (
                  <span className="absolute -top-1 -right-0.5 flex h-2 w-2">
                    <span className="animate-ping absolute inline-flex h-full w-full rounded-full bg-emerald-400 opacity-75"></span>
                    <span className="relative inline-flex rounded-full h-2 w-2 bg-emerald-500"></span>
                  </span>
                )}
              </button>
              
              <button
                onClick={() => setActiveTab('templates')}
                className={`px-4 py-2.5 rounded-lg flex items-center space-x-2 text-xs font-bold transition-all cursor-pointer ${
                  activeTab === 'templates' 
                    ? 'bg-indigo-600/15 text-indigo-400 border border-indigo-500/25 shadow-sm shadow-indigo-500/10' 
                    : 'text-slate-400 hover:text-slate-200 hover:bg-slate-800/40 border border-transparent'
                }`}
              >
                <FileCode2 className="w-3.5 h-3.5" />
                <span>预设与模版管理</span>
              </button>

              <button
                onClick={() => setActiveTab('agent')}
                className={`px-4 py-2.5 rounded-lg flex items-center space-x-2 text-xs font-bold transition-all cursor-pointer ${
                  activeTab === 'agent' 
                    ? 'bg-amber-600/15 text-amber-400 border border-amber-500/25 shadow-sm shadow-amber-500/10' 
                    : 'text-slate-400 hover:text-slate-200 hover:bg-slate-800/40 border border-transparent'
                }`}
              >
                <Server className="w-3.5 h-3.5" />
                <span>服务端持久化 Agent 部署</span>
              </button>
            </div>

            {/* Quick action: save current as custom templates */}
            <div className="hidden sm:flex items-center space-x-2">
              <button
                onClick={() => setIsSavingTemplateMode(true)}
                className="bg-[#1E293B] hover:bg-[#334155] border border-[#334155] text-slate-200 text-xs py-1.5 px-3 rounded-md transition-all cursor-pointer flex items-center space-x-1"
              >
                <CheckCircle2 className="w-3.5 h-3.5 text-blue-400" />
                <span>保存当前为新模板</span>
              </button>
            </div>
          </div>

          {/* Quick template configuration wizard banner under builder tab */}
          {activeTab === 'build' && (
            <div className="bg-gradient-to-r from-blue-900/20 via-[#0B0F19] to-indigo-900/10 border border-[#1E293B] rounded-xl p-4 flex flex-col md:flex-row items-center justify-between gap-4">
              <div className="flex items-center space-x-3">
                <div className="bg-blue-500/10 p-2 rounded-lg border border-blue-500/20">
                  <Globe className="w-5 h-5 text-blue-400" />
                </div>
                <div>
                  <h3 className="text-sm font-bold text-slate-200">思博伦/Ixia 快捷测试包预设加载</h3>
                  <p className="text-xs text-slate-400">选择预设一键装配Ethernet、IPv4、IPv6、TCP、UDP、ICMP报文协议栈字段。</p>
                </div>
              </div>
              <div className="flex flex-wrap gap-2 justify-end w-full md:w-auto">
                {STANDARD_PRESETS.map((preset, index) => (
                  <button
                    key={index}
                    onClick={() => handleLoadPreset(preset.packet)}
                    className="bg-[#162031] hover:bg-blue-600/20 border border-[#2D3E5B] hover:border-blue-500/45 text-slate-300 hover:text-blue-300 text-xs py-1.5 px-2.5 rounded-lg transition-all cursor-pointer"
                  >
                    {preset.name.split(' ')[0]}
                  </button>
                ))}
              </div>
            </div>
          )}

          {/* Dialog for custom naming packet templates */}
          {isSavingTemplateMode && (
            <div className="bg-[#0B0F19] border-2 border-blue-600 border-dashed rounded-xl p-4 flex flex-col space-y-3 shadow-2xl animate-pulse">
              <div className="flex items-center space-x-2">
                <Plus className="w-4 h-4 text-blue-400" />
                <h4 className="text-xs font-bold text-blue-400 uppercase tracking-widest font-mono">自定义常用发包组件命名 & 持久化保存 (仿真)</h4>
              </div>
              <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
                <input
                  type="text"
                  placeholder="模板名称 (e.g. DNS高速抗干扰验证包)"
                  value={newTemplateName}
                  onChange={(e) => setNewTemplateName(e.target.value)}
                  className="bg-[#101726] border border-[#1E293B] rounded px-3 py-1.5 text-xs text-slate-100 focus:outline-none focus:border-blue-500"
                />
                <input
                  type="text"
                  placeholder="报文描述 (e.g. 自定义ARP链路检测与MAC欺骗防御策略)"
                  value={newTemplateDesc}
                  onChange={(e) => setNewTemplateDesc(e.target.value)}
                  className="bg-[#101726] border border-[#1E293B] rounded px-3 py-1.5 text-xs text-slate-100 focus:outline-none focus:border-blue-500"
                />
              </div>
              <div className="flex justify-end space-x-2">
                <button
                  onClick={() => setIsSavingTemplateMode(false)}
                  className="px-3 py-1 text-slate-400 hover:text-slate-200 text-xs cursor-pointer"
                >
                  取消
                </button>
                <button
                  onClick={handleSaveAsTemplate}
                  className="bg-blue-600 hover:bg-blue-500 text-white text-xs px-4 py-1 rounded cursor-pointer font-bold"
                >
                  确认保存
                </button>
              </div>
            </div>
          )}

          {/* TAB 1: Visual Protocol Stack Designer */}
          {activeTab === 'build' && (
            <div className="grid grid-cols-1 lg:grid-cols-12 gap-6">
              
              {/* Left Column: Stack Selector List */}
              <div className="lg:col-span-4 bg-[#0B0F19] rounded-xl border border-[#1E293B] p-4 flex flex-col space-y-3">
                <div className="text-xs font-bold text-slate-400 uppercase tracking-widest font-mono border-b border-[#1E293B] pb-2 flex items-center justify-between">
                  <span>协议层级堆叠拓扑</span>
                  <Layers className="w-3.5 h-3.5 text-slate-500" />
                </div>

                <div className="space-y-2">
                  {[
                    { id: 'ETHERNET', label: 'Ethernet II (链路层)', color: 'border-blue-500' },
                    { id: 'ARP', label: 'ARP (地址转换协议)', color: 'border-[#FB923C]' },
                    { id: 'IPV4', label: 'IPv4 (网络层主载荷)', color: 'border-indigo-500' },
                    { id: 'IPV6', label: 'IPv6 (下一代网络层)', color: 'border-violet-500' },
                    { id: 'TCP', label: 'TCP (面向连接传输)', color: 'border-emerald-500' },
                    { id: 'UDP', label: 'UDP (无连接高速传输)', color: 'border-pink-500' },
                    { id: 'ICMP', label: 'ICMP (路由控制诊断)', color: 'border-teal-500' },
                    { id: 'RAW', label: 'RAW Payload (原始荷载)', color: 'border-amber-500' }
                  ].map((layer) => {
                    const isEnabled = packet.enabledLayers.includes(layer.id as LayerType);
                    const isActive = activeLayer === layer.id;
                    
                    return (
                      <div
                        key={layer.id}
                        className={`flex items-center justify-between p-2.5 rounded-lg border transition-all ${
                          isActive 
                            ? 'bg-slate-800/40 border-blue-500 shadow-sm' 
                            : 'bg-[#101726]/60 border-[#1E293B] hover:border-slate-800'
                        }`}
                      >
                        <button
                          onClick={() => setActiveLayer(layer.id as LayerType)}
                          className="flex items-center space-x-2 text-xs font-bold text-left flex-1 cursor-pointer"
                        >
                          <div className={`w-2.5 h-2.5 rounded-full ${isEnabled ? 'bg-emerald-500' : 'bg-slate-700'}`} />
                          <span className={`${isActive ? 'text-blue-400' : 'text-slate-300'}`}>
                            {layer.label}
                          </span>
                        </button>
                        
                        <div className="flex items-center space-x-1">
                          {layer.id !== 'ETHERNET' && (
                            <button
                              onClick={() => toggleLayerEnabled(layer.id as LayerType)}
                              className={`text-[9px] px-2 py-0.5 rounded uppercase font-mono font-bold tracking-wider cursor-pointer border ${
                                isEnabled 
                                  ? 'bg-emerald-500/10 text-emerald-400 border-emerald-500/20' 
                                  : 'bg-slate-800 text-slate-500 border-transparent hover:border-slate-700'
                              }`}
                            >
                              {isEnabled ? '已激活' : '不加载'}
                            </button>
                          )}
                        </div>
                      </div>
                    );
                  })}
                </div>

                <div className="pt-2">
                  <div className="bg-[#121927] border border-[#1E293B] p-2.5 rounded-lg text-[11px] text-slate-400">
                    <span className="font-bold text-slate-300">高级逻辑验证:</span> Scapy 会自动计算并填充未指定的长度和校验和参数。无需为了二层帧/三层路由重复编写繁琐填充。
                  </div>
                </div>
              </div>

              {/* Right Column: Layer Config Form Fields dynamically rendered */}
              <div className="lg:col-span-8 bg-[#0B0F19] rounded-xl border border-[#1E293B] p-5 flex flex-col space-y-4">
                
                {/* Visual Active Header path indicator */}
                <div className="flex items-center justify-between border-b border-[#1E293B] pb-3">
                  <div className="flex items-center space-x-2">
                    <div className="bg-slate-800 p-1.5 rounded text-blue-400">
                      <Settings className="w-4 h-4" />
                    </div>
                    <div>
                      <h4 className="text-xs font-bold text-slate-200">
                        正在配置: {activeLayer} 层协议字段 (自定义组装)
                      </h4>
                      <p className="text-[10px] text-slate-500">
                        {packet.enabledLayers.includes(activeLayer) 
                          ? '此层已激活，将被编译进最终构造的二进制报文中' 
                          : '⚠️ 警告: 此协议层当前处于关闭状态，请点击左侧 [不加载] 按钮切换为[已激活]后发包。'}
                      </p>
                    </div>
                  </div>
                </div>

                {/* ETHERNET FIELDS */}
                {activeLayer === 'ETHERNET' && packet.layers.ETHERNET && (
                  <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                    <div>
                      <label className="block text-[11px] font-mono text-slate-400 uppercase tracking-widest mb-1.5">
                        源 MAC 地址 (Src MAC)
                      </label>
                      <input
                        type="text"
                        value={packet.layers.ETHERNET.src}
                        onChange={(e) => updatePacketField('ETHERNET', 'src', e.target.value)}
                        className="w-full bg-[#101726]/80 border border-[#1E293B] focus:border-blue-500 focus:outline-none rounded-lg px-3 py-2 text-xs font-mono text-slate-100"
                        placeholder="e.g. 00:0c:29:ab:cd:ef"
                      />
                    </div>
                    <div>
                      <label className="block text-[11px] font-mono text-slate-400 uppercase tracking-widest mb-1.5">
                        目的 MAC 地址 (Dst MAC)
                      </label>
                      <input
                        type="text"
                        value={packet.layers.ETHERNET.dst}
                        onChange={(e) => updatePacketField('ETHERNET', 'dst', e.target.value)}
                        className="w-full bg-[#101726]/80 border border-[#1E293B] focus:border-blue-500 focus:outline-none rounded-lg px-3 py-2 text-xs font-mono text-slate-100"
                        placeholder="e.g. ff:ff:ff:ff:ff:ff"
                      />
                    </div>
                    <div>
                      <label className="block text-[11px] font-mono text-slate-400 uppercase tracking-widest mb-1.5">
                        以太网类型 (EtherType)
                      </label>
                      <select
                        value={packet.layers.ETHERNET.type}
                        onChange={(e) => updatePacketField('ETHERNET', 'type', parseInt(e.target.value))}
                        className="w-full bg-[#101726]/80 border border-[#1E293B] focus:border-blue-500 focus:outline-none rounded-lg px-3 py-2 text-xs text-slate-100"
                      >
                        <option value={0x0800}>0x0800 (IPv4 网络层 payload)</option>
                        <option value={0x0806}>0x0806 (ARP 地址映射)</option>
                        <option value={0x86dd}>0x86dd (IPv6 新一代路由)</option>
                      </select>
                    </div>
                  </div>
                )}

                {/* ARP FIELDS */}
                {activeLayer === 'ARP' && packet.layers.ARP && (
                  <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                    <div>
                      <label className="block text-[11px] font-mono text-slate-400 uppercase tracking-widest mb-1.5">
                        硬地址类型 (HwType)
                      </label>
                      <input
                        type="number"
                        value={packet.layers.ARP.hwtype}
                        onChange={(e) => updatePacketField('ARP', 'hwtype', parseInt(e.target.value))}
                        className="w-full bg-[#101726]/80 border border-[#1E293B] focus:border-blue-500 focus:outline-none rounded-lg px-3 py-2 text-xs font-mono text-slate-100"
                      />
                    </div>
                    <div>
                      <label className="block text-[11px] font-mono text-slate-400 uppercase tracking-widest mb-1.5">
                        协议地址类型 (ProtoType)
                      </label>
                      <input
                        type="text"
                        value={'0x' + packet.layers.ARP.ptype.toString(16)}
                        onChange={(e) => updatePacketField('ARP', 'ptype', parseInt(e.target.value))}
                        disabled
                        className="w-full bg-[#101726]/40 border border-[#1E293B] rounded-lg px-3 py-2 text-xs font-mono text-slate-500"
                      />
                    </div>
                    <div>
                      <label className="block text-[11px] font-mono text-slate-400 uppercase tracking-widest mb-1.5">
                        操作类型码 (Opcode)
                      </label>
                      <select
                        value={packet.layers.ARP.op}
                        onChange={(e) => updatePacketField('ARP', 'op', parseInt(e.target.value))}
                        className="w-full bg-[#101726]/80 border border-[#1E293B] focus:border-blue-500 focus:outline-none rounded-lg px-3 py-2 text-xs text-slate-100"
                      >
                        <option value={1}>1 (ARP 请求 Request)</option>
                        <option value={2}>2 (ARP 响应 Reply)</option>
                      </select>
                    </div>
                    <div>
                      <label className="block text-[11px] font-mono text-slate-400 uppercase tracking-widest mb-1.5">
                        发送端主机 MAC (Sender MAC)
                      </label>
                      <input
                        type="text"
                        value={packet.layers.ARP.hwsrc}
                        onChange={(e) => updatePacketField('ARP', 'hwsrc', e.target.value)}
                        className="w-full bg-[#101726]/80 border border-[#1E293B] focus:border-blue-500 focus:outline-none rounded-lg px-3 py-2 text-xs font-mono text-slate-100"
                        placeholder="e.g. 00:0c:29:ab:cd:ef"
                      />
                    </div>
                    <div>
                      <label className="block text-[11px] font-mono text-slate-400 uppercase tracking-widest mb-1.5">
                        发送端协议 IP (Sender IP)
                      </label>
                      <input
                        type="text"
                        value={packet.layers.ARP.psrc}
                        onChange={(e) => updatePacketField('ARP', 'psrc', e.target.value)}
                        className="w-full bg-[#101726]/80 border border-[#1E293B] focus:border-blue-500 focus:outline-none rounded-lg px-3 py-2 text-xs font-mono text-slate-100"
                        placeholder="e.g. 192.168.1.102"
                      />
                    </div>
                    <div>
                      <label className="block text-[11px] font-mono text-slate-400 uppercase tracking-widest mb-1.5">
                        接收端主机 MAC (Target MAC)
                      </label>
                      <input
                        type="text"
                        value={packet.layers.ARP.hwdst}
                        onChange={(e) => updatePacketField('ARP', 'hwdst', e.target.value)}
                        className="w-full bg-[#101726]/80 border border-[#1E293B] focus:border-blue-500 focus:outline-none rounded-lg px-3 py-2 text-xs font-mono text-slate-100"
                        placeholder="e.g. 00:00:00:00:00:00"
                      />
                    </div>
                    <div>
                      <label className="block text-[11px] font-mono text-slate-400 uppercase tracking-widest mb-1.5">
                        接收端协议 IP (Target IP)
                      </label>
                      <input
                        type="text"
                        value={packet.layers.ARP.pdst}
                        onChange={(e) => updatePacketField('ARP', 'pdst', e.target.value)}
                        className="w-full bg-[#101726]/80 border border-[#1E293B] focus:border-blue-500 focus:outline-none rounded-lg px-3 py-2 text-xs font-mono text-slate-100"
                        placeholder="e.g. 192.168.1.1"
                      />
                    </div>
                  </div>
                )}

                {/* IPv4 FIELDS */}
                {activeLayer === 'IPV4' && packet.layers.IPV4 && (
                  <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                    <div>
                      <label className="block text-[11px] font-mono text-slate-400 uppercase tracking-widest mb-1.5">
                        版本 (Version)
                      </label>
                      <input
                        type="number"
                        value={packet.layers.IPV4.version}
                        disabled
                        className="w-full bg-[#101726]/40 border border-[#1E293B] rounded-lg px-3 py-2 text-xs font-mono text-slate-500"
                      />
                    </div>
                    <div>
                      <label className="block text-[11px] font-mono text-slate-400 uppercase tracking-widest mb-1.5">
                        服务类型/差分服务字节 (TOS)
                      </label>
                      <input
                        type="number"
                        value={packet.layers.IPV4.tos}
                        onChange={(e) => updatePacketField('IPV4', 'tos', parseInt(e.target.value))}
                        className="w-full bg-[#101726]/80 border border-[#1E293B] focus:border-blue-500 focus:outline-none rounded-lg px-3 py-2 text-xs font-mono text-slate-100"
                        placeholder="0"
                      />
                    </div>
                    <div>
                      <label className="block text-[11px] font-mono text-slate-400 uppercase tracking-widest mb-1.5">
                        报文标识符 (Identification)
                      </label>
                      <input
                        type="number"
                        value={packet.layers.IPV4.id}
                        onChange={(e) => updatePacketField('IPV4', 'id', parseInt(e.target.value))}
                        className="w-full bg-[#101726]/80 border border-[#1E293B] focus:border-blue-500 focus:outline-none rounded-lg px-3 py-2 text-xs font-mono text-slate-100"
                      />
                    </div>
                    <div>
                      <label className="block text-[11px] font-mono text-slate-400 uppercase tracking-widest mb-1.5">
                        生存周期限制值 (TTL)
                      </label>
                      <input
                        type="number"
                        value={packet.layers.IPV4.ttl}
                        onChange={(e) => updatePacketField('IPV4', 'ttl', parseInt(e.target.value))}
                        className="w-full bg-[#101726]/80 border border-[#1E293B] focus:border-blue-500 focus:outline-none rounded-lg px-3 py-2 text-xs font-mono text-slate-100"
                      />
                    </div>
                    <div>
                      <label className="block text-[11px] font-mono text-slate-400 uppercase tracking-widest mb-1.5">
                        分片位设置 (Flags)
                      </label>
                      <select
                        value={packet.layers.IPV4.flags}
                        onChange={(e) => updatePacketField('IPV4', 'flags', e.target.value)}
                        className="w-full bg-[#101726]/80 border border-[#1E293B] focus:border-blue-500 focus:outline-none rounded-lg px-3 py-2 text-xs text-slate-100"
                      >
                        <option value="">不设置 (可分片)</option>
                        <option value="DF">DF (Don't Fragment 禁止分片)</option>
                        <option value="MF">MF (More Fragments 含有后续分片)</option>
                      </select>
                    </div>
                    <div>
                      <label className="block text-[11px] font-mono text-slate-400 uppercase tracking-widest mb-1.5">
                        上层携带协议码 (Protocol Type)
                      </label>
                      <select
                        value={packet.layers.IPV4.proto}
                        onChange={(e) => updatePacketField('IPV4', 'proto', parseInt(e.target.value))}
                        className="w-full bg-[#101726]/80 border border-[#1E293B] focus:border-blue-500 focus:outline-none rounded-lg px-3 py-2 text-xs text-slate-100"
                      >
                        <option value={6}>6 (TCP 连接层)</option>
                        <option value={17}>17 (UDP 数据报层)</option>
                        <option value={1}>1 (ICMP 网络诊断)</option>
                      </select>
                    </div>
                    <div>
                      <label className="block text-[11px] font-mono text-slate-400 uppercase tracking-widest mb-1.5">
                        源 IP 地址 (Src IP)
                      </label>
                      <input
                        type="text"
                        value={packet.layers.IPV4.src}
                        onChange={(e) => updatePacketField('IPV4', 'src', e.target.value)}
                        className="w-full bg-[#101726]/80 border border-[#1E293B] focus:border-blue-500 focus:outline-none rounded-lg px-3 py-2 text-xs font-mono text-slate-100"
                        placeholder="e.g. 192.168.1.102"
                      />
                    </div>
                    <div>
                      <label className="block text-[11px] font-mono text-slate-400 uppercase tracking-widest mb-1.5">
                        目的 IP 地址 (Dst IP)
                      </label>
                      <input
                        type="text"
                        value={packet.layers.IPV4.dst}
                        onChange={(e) => updatePacketField('IPV4', 'dst', e.target.value)}
                        className="w-full bg-[#101726]/80 border border-[#1E293B] focus:border-blue-500 focus:outline-none rounded-lg px-3 py-2 text-xs font-mono text-slate-100"
                        placeholder="e.g. 8.8.8.8"
                      />
                    </div>
                  </div>
                )}

                {/* IPv6 FIELDS */}
                {activeLayer === 'IPV6' && packet.layers.IPV6 && (
                  <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                    <div>
                      <label className="block text-[11px] font-mono text-slate-400 uppercase tracking-widest mb-1.5">
                        流量特征类别 (Traffic Class)
                      </label>
                      <input
                        type="number"
                        value={packet.layers.IPV6.tc}
                        onChange={(e) => updatePacketField('IPV6', 'tc', parseInt(e.target.value))}
                        className="w-full bg-[#101726]/80 border border-[#1E293B] focus:border-blue-500 focus:outline-none rounded-lg px-3 py-2 text-xs font-mono text-slate-100"
                      />
                    </div>
                    <div>
                      <label className="block text-[11px] font-mono text-slate-400 uppercase tracking-widest mb-1.5">
                        流标记 (Flow Label)
                      </label>
                      <input
                        type="number"
                        value={packet.layers.IPV6.fl}
                        onChange={(e) => updatePacketField('IPV6', 'fl', parseInt(e.target.value))}
                        className="w-full bg-[#101726]/80 border border-[#1E293B] focus:border-blue-500 focus:outline-none rounded-lg px-3 py-2 text-xs font-mono text-slate-100"
                      />
                    </div>
                    <div>
                      <label className="block text-[11px] font-mono text-slate-400 uppercase tracking-widest mb-1.5">
                        下一报头指示类型 (Next Header)
                      </label>
                      <select
                        value={packet.layers.IPV6.nh}
                        onChange={(e) => updatePacketField('IPV6', 'nh', parseInt(e.target.value))}
                        className="w-full bg-[#101726]/80 border border-[#1E293B] focus:border-blue-500 focus:outline-none rounded-lg px-3 py-2 text-xs text-slate-100"
                      >
                        <option value={6}>6 (TCPv6协议链)</option>
                        <option value={17}>17 (UDPv6数据流)</option>
                        <option value={58}>58 (ICMPv6诊断控制头)</option>
                      </select>
                    </div>
                    <div>
                      <label className="block text-[11px] font-mono text-slate-400 uppercase tracking-widest mb-1.5">
                        跳数限制/生命周期 (Hop Limit)
                      </label>
                      <input
                        type="number"
                        value={packet.layers.IPV6.hlim}
                        onChange={(e) => updatePacketField('IPV6', 'hlim', parseInt(e.target.value))}
                        className="w-full bg-[#101726]/80 border border-[#1E293B] focus:border-blue-500 focus:outline-none rounded-lg px-3 py-2 text-xs font-mono text-slate-100"
                      />
                    </div>
                    <div>
                      <label className="block text-[11px] font-mono text-slate-400 uppercase tracking-widest mb-1.5">
                        源 IPv6 地址 (Src IPv6 Address)
                      </label>
                      <input
                        type="text"
                        value={packet.layers.IPV6.src}
                        onChange={(e) => updatePacketField('IPV6', 'src', e.target.value)}
                        className="w-full bg-[#101726]/80 border border-[#1E293B] focus:border-blue-500 focus:outline-none rounded-lg px-3 py-2 text-xs font-mono text-slate-100"
                        placeholder="e.g. fe80::ac11:2"
                      />
                    </div>
                    <div>
                      <label className="block text-[11px] font-mono text-slate-400 uppercase tracking-widest mb-1.5">
                        目的 IPv6 地址 (Dst IPv6 Address)
                      </label>
                      <input
                        type="text"
                        value={packet.layers.IPV6.dst}
                        onChange={(e) => updatePacketField('IPV6', 'dst', e.target.value)}
                        className="w-full bg-[#101726]/80 border border-[#1E293B] focus:border-blue-500 focus:outline-none rounded-lg px-3 py-2 text-xs font-mono text-slate-100"
                        placeholder="e.g. 2001:4860:4860::8888"
                      />
                    </div>
                  </div>
                )}

                {/* TCP FIELDS */}
                {activeLayer === 'TCP' && packet.layers.TCP && (
                  <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                    <div>
                      <label className="block text-[11px] font-mono text-slate-400 uppercase tracking-widest mb-1.5">
                        源端口 (Source Port)
                      </label>
                      <input
                        type="number"
                        value={packet.layers.TCP.sport}
                        onChange={(e) => updatePacketField('TCP', 'sport', parseInt(e.target.value))}
                        className="w-full bg-[#101726]/80 border border-[#1E293B] focus:border-blue-500 focus:outline-none rounded-lg px-3 py-2 text-xs font-mono text-slate-100"
                      />
                    </div>
                    <div>
                      <label className="block text-[11px] font-mono text-slate-400 uppercase tracking-widest mb-1.5">
                        目的端口 (Destination Port)
                      </label>
                      <input
                        type="number"
                        value={packet.layers.TCP.dport}
                        onChange={(e) => updatePacketField('TCP', 'dport', parseInt(e.target.value))}
                        className="w-full bg-[#101726]/80 border border-[#1E293B] focus:border-blue-500 focus:outline-none rounded-lg px-3 py-2 text-xs font-mono text-slate-100"
                      />
                    </div>
                    <div>
                      <label className="block text-[11px] font-mono text-slate-400 uppercase tracking-widest mb-1.5">
                        TCP 序列号 (Sequence Number)
                      </label>
                      <input
                        type="number"
                        value={packet.layers.TCP.seq}
                        onChange={(e) => updatePacketField('TCP', 'seq', parseInt(e.target.value))}
                        className="w-full bg-[#101726]/80 border border-[#1E293B] focus:border-blue-500 focus:outline-none rounded-lg px-3 py-2 text-xs font-mono text-slate-100"
                      />
                    </div>
                    <div>
                      <label className="block text-[11px] font-mono text-slate-400 uppercase tracking-widest mb-1.5">
                        确认应答号 (Acknowledgment Number)
                      </label>
                      <input
                        type="number"
                        value={packet.layers.TCP.ack}
                        onChange={(e) => updatePacketField('TCP', 'ack', parseInt(e.target.value))}
                        className="w-full bg-[#101726]/80 border border-[#1E293B] focus:border-blue-500 focus:outline-none rounded-lg px-3 py-2 text-xs font-mono text-slate-100"
                      />
                    </div>
                    <div>
                      <label className="block text-[11px] font-mono text-slate-400 uppercase tracking-widest mb-1.5">
                        TCP 滑动窗口尺寸 (Window Size)
                      </label>
                      <input
                        type="number"
                        value={packet.layers.TCP.window}
                        onChange={(e) => updatePacketField('TCP', 'window', parseInt(e.target.value))}
                        className="w-full bg-[#101726]/80 border border-[#1E293B] focus:border-blue-500 focus:outline-none rounded-lg px-3 py-2 text-xs font-mono text-slate-100"
                      />
                    </div>
                    <div>
                      <label className="block text-[11px] font-mono text-slate-400 uppercase tracking-widest mb-1.5">
                        紧急报文指针 (Urgent Pointer)
                      </label>
                      <input
                        type="number"
                        value={packet.layers.TCP.urgptr}
                        onChange={(e) => updatePacketField('TCP', 'urgptr', parseInt(e.target.value))}
                        className="w-full bg-[#101726]/80 border border-[#1E293B] focus:border-blue-500 focus:outline-none rounded-lg px-3 py-2 text-xs font-mono text-slate-100"
                      />
                    </div>
                    
                    {/* TCP Flags selection */}
                    <div className="md:col-span-2">
                      <label className="block text-[11px] font-mono text-slate-400 uppercase tracking-widest mb-2">
                        控制标志位 (TCP Flags Multiselect)
                      </label>
                      <div className="flex flex-wrap gap-2">
                        {['SYN', 'ACK', 'FIN', 'RST', 'PSH', 'URG'].map((flag) => {
                          const hasFlag = packet.layers.TCP?.flags.includes(flag);
                          return (
                            <button
                              key={flag}
                              onClick={() => {
                                const list = [...(packet.layers.TCP?.flags || [])];
                                const updatedList = list.includes(flag) 
                                  ? list.filter(f => f !== flag) 
                                  : [...list, flag];
                                updatePacketField('TCP', 'flags', updatedList);
                              }}
                              className={`text-xs px-3 py-1.5 rounded-md font-bold font-mono transition-all cursor-pointer border ${
                                hasFlag 
                                  ? 'bg-emerald-500/10 text-emerald-400 border-emerald-500/40 shadow-xs shadow-emerald-500/10' 
                                  : 'bg-[#101726] text-slate-400 border-[#1E293B] hover:border-slate-700'
                              }`}
                            >
                              {flag}
                            </button>
                          );
                        })}
                      </div>
                    </div>
                  </div>
                )}

                {/* UDP FIELDS */}
                {activeLayer === 'UDP' && packet.layers.UDP && (
                  <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                    <div>
                      <label className="block text-[11px] font-mono text-slate-400 uppercase tracking-widest mb-1.5">
                        UDP 源端服务端口 (sport)
                      </label>
                      <input
                        type="number"
                        value={packet.layers.UDP.sport}
                        onChange={(e) => updatePacketField('UDP', 'sport', parseInt(e.target.value))}
                        className="w-full bg-[#101726]/80 border border-[#1E293B] focus:border-blue-500 focus:outline-none rounded-lg px-3 py-2 text-xs font-mono text-slate-100"
                      />
                    </div>
                    <div>
                      <label className="block text-[11px] font-mono text-slate-400 uppercase tracking-widest mb-1.5">
                        UDP 接收目的端口 (dport)
                      </label>
                      <input
                        type="number"
                        value={packet.layers.UDP.dport}
                        onChange={(e) => updatePacketField('UDP', 'dport', parseInt(e.target.value))}
                        className="w-full bg-[#101726]/80 border border-[#1E293B] focus:border-blue-500 focus:outline-none rounded-lg px-3 py-2 text-xs font-mono text-slate-100"
                      />
                    </div>
                  </div>
                )}

                {/* ICMP FIELDS */}
                {activeLayer === 'ICMP' && packet.layers.ICMP && (
                  <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                    <div>
                      <label className="block text-[11px] font-mono text-slate-400 uppercase tracking-widest mb-1.5">
                        ICMP 报文类型码 (Type)
                      </label>
                      <select
                        value={packet.layers.ICMP.type}
                        onChange={(e) => updatePacketField('ICMP', 'type', parseInt(e.target.value))}
                        className="w-full bg-[#101726]/80 border border-[#1E293B] focus:border-blue-500 focus:outline-none rounded-lg px-3 py-2 text-xs text-slate-100"
                      >
                        <option value={8}>8 (Echo Request - Ping发起探测头)</option>
                        <option value={0}>0 (Echo Reply - Ping正常回显)</option>
                        <option value={3}>3 (Destination Unreachable - 目标不可达)</option>
                        <option value={11}>11 (Time Exceeded - 超时超时生存值TTL为0)</option>
                      </select>
                    </div>
                    <div>
                      <label className="block text-[11px] font-mono text-slate-400 uppercase tracking-widest mb-1.5">
                        副代码码值 (Code)
                      </label>
                      <input
                        type="number"
                        value={packet.layers.ICMP.code}
                        onChange={(e) => updatePacketField('ICMP', 'code', parseInt(e.target.value))}
                        className="w-full bg-[#101726]/80 border border-[#1E293B] focus:border-blue-500 focus:outline-none rounded-lg px-3 py-2 text-xs font-mono text-slate-100"
                      />
                    </div>
                    <div>
                      <label className="block text-[11px] font-mono text-slate-400 uppercase tracking-widest mb-1.5">
                        报文标识符 (Identifier)
                      </label>
                      <input
                        type="number"
                        value={packet.layers.ICMP.id}
                        onChange={(e) => updatePacketField('ICMP', 'id', parseInt(e.target.value))}
                        className="w-full bg-[#101726]/80 border border-[#1E293B] focus:border-blue-500 focus:outline-none rounded-lg px-3 py-2 text-xs font-mono text-slate-100"
                      />
                    </div>
                    <div>
                      <label className="block text-[11px] font-mono text-slate-400 uppercase tracking-widest mb-1.5">
                        序列识别码 (Sequence Number)
                      </label>
                      <input
                        type="number"
                        value={packet.layers.ICMP.seq}
                        onChange={(e) => updatePacketField('ICMP', 'seq', parseInt(e.target.value))}
                        className="w-full bg-[#101726]/80 border border-[#1E293B] focus:border-blue-500 focus:outline-none rounded-lg px-3 py-2 text-xs font-mono text-slate-100"
                      />
                    </div>
                  </div>
                )}

                {/* RAW FIELDS */}
                {activeLayer === 'RAW' && packet.layers.RAW && (
                  <div className="flex flex-col space-y-4">
                    <div className="flex items-center space-x-4">
                      <label className="text-[11px] font-mono text-slate-400 uppercase tracking-widest">
                        数据荷载承载格式:
                      </label>
                      <div className="flex space-x-2">
                        {['string', 'hex'].map((fmt) => (
                          <button
                            key={fmt}
                            onClick={() => updatePacketField('RAW', 'format', fmt)}
                            className={`text-[10px] px-2.5 py-1 font-bold font-mono rounded cursor-pointer uppercase ${
                              packet.layers.RAW?.format === fmt 
                                ? 'bg-amber-500/20 text-amber-400 border border-amber-500/40' 
                                : 'bg-slate-800 text-slate-400 border border-transparent'
                            }`}
                          >
                            {fmt === 'string' ? 'UTF-8 字符行' : 'Hex 十六进制字节码'}
                          </button>
                        ))}
                      </div>
                    </div>
                    
                    <div>
                      <textarea
                        rows={4}
                        value={packet.layers.RAW.payload}
                        onChange={(e) => updatePacketField('RAW', 'payload', e.target.value)}
                        className="w-full bg-[#101726]/80 border border-[#1E293B] focus:border-blue-500 focus:outline-none rounded-lg px-3 py-2.5 text-xs font-mono text-slate-100"
                        placeholder={
                          packet.layers.RAW.format === 'string' 
                            ? '请输入字符串荷载内容...' 
                            : '以空格或者连续字符输入十六进制，e.g. 00 0c 29 ff c0 a8'
                        }
                      />
                      <p className="text-[10px] text-slate-500 mt-1">
                        自定义协议荷载。如果承载Hex，不要输入非十六进制字符以保障Scapy包校验编译合法。
                      </p>
                    </div>
                  </div>
                )}

              </div>
            </div>
          )}

          {/* TAB 2: Dynamic Packet Capture stream grid & charts */}
          {activeTab === 'monitor' && (
            <div className="bg-[#0B0F19] rounded-xl border border-[#1E293B] p-5 flex flex-col space-y-5">
              
              {/* Header metrics indicator */}
              <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
                <div className="bg-[#101726] border border-[#1E293B] rounded-lg p-3 text-center">
                  <div className="text-[10px] text-slate-400 font-mono uppercase tracking-wider">累计发送报文</div>
                  <div className="text-xl font-bold font-mono text-blue-400 mt-1">{stats.sentCount}</div>
                </div>
                <div className="bg-[#101726] border border-[#1E293B] rounded-lg p-3 text-center">
                  <div className="text-[10px] text-slate-400 font-mono uppercase tracking-wider">交付成功包</div>
                  <div className="text-xl font-bold font-mono text-emerald-400 mt-1">{stats.successCount}</div>
                </div>
                <div className="bg-[#101726] border border-[#1E293B] rounded-lg p-3 text-center">
                  <div className="text-[10px] text-slate-400 font-mono uppercase tracking-wider">丢包校验失败</div>
                  <div className="text-xl font-bold font-mono text-rose-400 mt-1">{stats.failCount}</div>
                </div>
                <div className="bg-[#101726] border border-[#1E293B] rounded-lg p-3 text-center">
                  <div className="text-[10px] text-slate-400 font-mono uppercase tracking-wider">瞬时吞吐率(PPS)</div>
                  <div className="text-xl font-bold font-mono text-amber-400 mt-1">{stats.currentPps} P/s</div>
                </div>
              </div>

              {/* Layout for captured visual tables */}
              <div className="grid grid-cols-1 lg:grid-cols-12 gap-5 h-[400px]">
                {/* Packets flow list */}
                <div className="lg:col-span-7 flex flex-col space-y-2 h-full">
                  <div className="text-xs font-bold font-mono text-slate-400 uppercase tracking-widest flex items-center justify-between border-b border-[#1E293B] pb-2">
                    <span>捕获的网络报文交互流 (Wireshark 级解析)</span>
                    <span className="text-[11px] text-blue-400">({captured.length} 已记录)</span>
                  </div>

                  <div className="flex-1 overflow-y-auto border border-[#1E293B] rounded-lg bg-[#080D16]">
                    <table className="w-full text-[11px] font-mono leading-relaxed text-left border-collapse">
                      <thead className="bg-[#101726] text-slate-400 sticky top-0 border-b border-[#1E293B]">
                        <tr>
                          <th className="p-2 w-12 text-center">序号</th>
                          <th className="p-2 w-28">时间</th>
                          <th className="p-2 w-16">协议</th>
                          <th className="p-2 text-slate-300">报文结构简要信息摘要 (Summary)</th>
                          <th className="p-2 w-16 text-right">长度</th>
                        </tr>
                      </thead>
                      <tbody>
                        {captured.length === 0 ? (
                          <tr>
                            <td colSpan={5} className="text-slate-500 text-center py-20">
                              [+] 暂无发包数据在链路层触发捕获，请点击下方 [开始发包] 触发。
                            </td>
                          </tr>
                        ) : (
                          captured.map((pkt) => {
                            const isSelected = selectedCapturedPacket?.index === pkt.index;
                            return (
                              <tr
                                key={pkt.index}
                                onClick={() => setSelectedCapturedPacket(pkt)}
                                className={`border-b border-[#1E293B]/60 hover:bg-slate-800/20 cursor-pointer transition-all ${
                                  isSelected ? 'bg-blue-600/10 text-white border-l-2 border-l-blue-500' : 'text-slate-300'
                                }`}
                              >
                                <td className="p-2 text-center text-slate-500">{pkt.index}</td>
                                <td className="p-2 text-slate-400">{pkt.timestamp.split('.')[0]}<span className="text-[9px] text-slate-600">.{pkt.timestamp.split('.')[1] || ''}</span></td>
                                <td className="p-2 font-bold">
                                  <span className={`px-1.5 py-0.5 rounded text-[10px] uppercase ${
                                    pkt.protocol.includes('TCP') ? 'bg-emerald-500/10 text-emerald-400 border border-emerald-500/20' :
                                    pkt.protocol.includes('UDP') ? 'bg-pink-500/10 text-pink-400 border border-pink-500/20' :
                                    pkt.protocol.includes('ARP') ? 'bg-orange-500/10 text-orange-400 border border-orange-500/20' :
                                    'bg-blue-500/10 text-blue-400 border border-blue-500/20'
                                  }`}>
                                    {pkt.protocol}
                                  </span>
                                </td>
                                <td className="p-2 truncate max-w-[280px]" title={pkt.summary}>
                                  {pkt.summary}
                                </td>
                                <td className="p-2 text-right font-semibold text-slate-400">{pkt.length}</td>
                              </tr>
                            );
                          })
                        )}
                      </tbody>
                    </table>
                  </div>
                </div>

                {/* Packet decode visual details */}
                <div className="lg:col-span-5 flex flex-col space-y-2 h-full">
                  <div className="text-xs font-bold font-mono text-slate-400 uppercase tracking-widest border-b border-[#1E293B] pb-2 flex items-center justify-between">
                    <span>报文详细解码树状视窗 (Tree View)</span>
                    <Eye className="w-3.5 h-3.5 text-slate-500" />
                  </div>

                  <div className="flex-1 overflow-y-auto border border-[#1E293B] rounded-lg bg-[#080D16] p-4 text-xs font-mono space-y-4">
                    {selectedCapturedPacket ? (
                      <div className="space-y-3 leading-relaxed">
                        <div className="text-blue-400 font-bold border-b border-[#1E293B]/80 pb-1 flex items-center justify-between">
                          <span>Frame {selectedCapturedPacket.index}: {selectedCapturedPacket.length} 字节</span>
                          <span className="text-slate-500">时戳: {selectedCapturedPacket.timestamp}</span>
                        </div>
                        
                        {/* Protocol stack layout simulation detail */}
                        <div className="space-y-2 text-[11px]">
                          <div className="border-l-2 border-slate-600 pl-3">
                            <span className="text-slate-400 font-semibold uppercase">二层: Ethernet II Frame</span>
                            <div className="text-slate-500 ml-2">
                              <div>源 MAC 媒介控制器: {selectedCapturedPacket.srcMac}</div>
                              <div>目的端口 MAC 节点: {selectedCapturedPacket.dstMac}</div>
                            </div>
                          </div>

                          {(selectedCapturedPacket.srcIp || selectedCapturedPacket.dstIp) && (
                            <div className="border-l-2 border-sky-600 pl-3">
                              <span className="text-slate-400 font-semibold uppercase">三层: Internet Protocol</span>
                              <div className="text-slate-500 ml-2">
                                <div>发件端源 IP: {selectedCapturedPacket.srcIp || '0.0.0.0'}</div>
                                <div>收件端目的 IP: {selectedCapturedPacket.dstIp || '0.0.0.0'}</div>
                                <div>封装校验和 checksum: 自动重校验通过 OK</div>
                              </div>
                            </div>
                          )}

                          <div className="border-l-2 border-amber-600 pl-3">
                            <span className="text-slate-400 font-semibold">四层应用及荷载摘要:</span>
                            <div className="text-slate-400/90 ml-2 mt-1 whitespace-pre-wrap leading-normal font-mono text-[10px] bg-[#111827] p-2 rounded">
                              {selectedCapturedPacket.summary}
                            </div>
                          </div>
                        </div>

                        {/* Dual pane visual Hex viewer */}
                        <div className="border-t border-[#1E293B]/80 pt-3">
                          <div className="text-slate-400 font-semibold mb-1 uppercase text-[10px]">负载和字节流 (Hex View):</div>
                          <div className="bg-[#111827] p-2.5 rounded font-mono text-[10px] text-slate-300 overflow-x-auto leading-relaxed border border-[#2b3a55]/20">
                            <pre>{selectedCapturedPacket.hexDump}</pre>
                            <div className="border-t border-slate-700/55 my-1.5 opacity-40"></div>
                            <pre className="text-slate-400">{selectedCapturedPacket.asciiDump}</pre>
                          </div>
                        </div>
                      </div>
                    ) : (
                      <div className="text-slate-600 text-center py-24">
                        请在左侧列表中点击具体的报文，查看详细的树状协议解析字段和 HEX 字节码对照。
                      </div>
                    )}
                  </div>
                </div>
              </div>

            </div>
          )}

          {/* TAB 3: Templates manager panel */}
          {activeTab === 'templates' && (
            <div className="bg-[#0B0F19] rounded-xl border border-[#1E293B] p-5 flex flex-col space-y-4">
              <div className="flex items-center justify-between border-b border-[#1E293B]/80 pb-3">
                <div>
                  <h3 className="text-sm font-bold text-slate-200">可视化报文组合模板仓</h3>
                  <p className="text-xs text-slate-400">快速保存常用的报文（如TCP探测包、ARP验证或欺骗），随需一键载入协议模板。</p>
                </div>
                <button
                  onClick={() => handleLoadPreset(EMPTY_PACKET)}
                  className="bg-[#22C55E]/10 hover:bg-[#22C55E]/20 border border-[#22C55E]/30 text-[#22C55E] text-xs py-1.5 px-3 rounded-lg transition-all cursor-pointer flex items-center space-x-1 font-bold"
                >
                  <Plus className="w-3.5 h-3.5" />
                  <span>重置并空白构造新报文</span>
                </button>
              </div>

              <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                {savedTemplates.map((tpl) => (
                  <div
                    key={tpl.id}
                    className="bg-[#101726]/80 hover:bg-[#101726] border border-[#1E293B] hover:border-[#2D3E5B] p-4 rounded-xl flex flex-col justify-between transition-all"
                  >
                    <div>
                      <div className="flex items-center justify-between">
                        <span className="text-xs font-bold text-slate-200 uppercase tracking-widest">{tpl.name}</span>
                        <span className="text-[9px] text-slate-500 font-mono">{tpl.createdAt}</span>
                      </div>
                      <p className="text-xs text-slate-400 mt-1">{tpl.description}</p>
                      
                      <div className="flex flex-wrap gap-1.5 mt-2.5">
                        {tpl.packet.enabledLayers.map((l) => (
                          <span key={l} className="text-[9px] uppercase font-mono font-bold bg-[#1E293B] hover:bg-[#334155] border border-[#334155] text-slate-300 px-1.5 py-0.5 rounded">
                            {l}
                          </span>
                        ))}
                      </div>
                    </div>

                    <div className="flex justify-end items-center mt-4 space-x-2 border-t border-[#1E293B] pt-2.5">
                      <button
                        onClick={() => deleteTemplate(tpl.id)}
                        className="text-slate-500 hover:text-rose-400 hover:bg-rose-500/5 p-1 rounded transition-colors cursor-pointer"
                        title="删除此模版"
                      >
                        <Trash2 className="w-3.5 h-3.5" />
                      </button>
                      <button
                        onClick={() => handleLoadPreset(tpl.packet)}
                        className="bg-blue-600/10 hover:bg-blue-600/20 border border-blue-500/30 text-blue-400 hover:text-blue-300 text-xs py-1 px-3 rounded font-bold transition-all cursor-pointer"
                      >
                        立即一键载入配置
                      </button>
                    </div>
                  </div>
                ))}
              </div>
            </div>
          )}

          {/* TAB 4: Server custom standalone installation Agent tutorial and monitoring manager */}
          {activeTab === 'agent' && (
            <div className="bg-[#0B0F19] rounded-xl border border-[#1E293B] p-5 flex flex-col space-y-4">
              <div className="border-b border-[#1E293B] pb-3">
                <h3 className="text-sm font-bold text-blue-400 flex items-center space-x-2">
                  <Server className="w-4 h-4" />
                  <span>后端物理网卡及持久化 Scapy 发包 Agent 联调</span>
                </h3>
                <p className="text-xs text-slate-400">
                  要使用本地真实物理网卡进行链路二层报文发送，后台运行由 Python + Scapy 开发的特权 Agent 代理必不可少。
                </p>
              </div>

              {/* OS toggle for script download */}
              <div className="flex items-center space-x-2 bg-[#121927] p-1.5 rounded-lg border border-[#1E293B] w-fit">
                <button
                  onClick={() => setSelectedAgentOs('linux')}
                  className={`text-xs px-3.5 py-1.5 font-bold font-mono rounded-lg transition-all cursor-pointer ${
                    selectedAgentOs === 'linux' 
                      ? 'bg-blue-600/15 text-blue-400 border border-blue-500/25 shadow-xs' 
                      : 'text-slate-400 hover:text-slate-200'
                  }`}
                >
                  Linux / CentOS / Ubuntu
                </button>
                <button
                  onClick={() => setSelectedAgentOs('windows')}
                  className={`text-xs px-3.5 py-1.5 font-bold font-mono rounded-lg transition-all cursor-pointer ${
                    selectedAgentOs === 'windows' 
                      ? 'bg-blue-600/15 text-blue-400 border border-blue-500/25 shadow-xs' 
                      : 'text-slate-400 hover:text-slate-200'
                  }`}
                >
                  Windows Server / Win10/11
                </button>
              </div>

              {/* Deployment detail content */}
              <div className="bg-[#121927] p-4 rounded-xl border border-[#1E293B] space-y-3">
                <div className="text-xs font-bold text-slate-300 flex items-center space-x-2 uppercase font-mono">
                  <span>部署安装包及管理员环境初始化流程</span>
                  <HelpCircle className="w-3.5 h-3.5 text-blue-400" />
                </div>
                
                {selectedAgentOs === 'linux' ? (
                  <ol className="list-decimal pl-5 text-xs text-slate-400 space-y-2">
                    <li>
                      <span className="text-slate-200 font-semibold">安装基础 Python 依赖库和 Linux 抓包驱动:</span>
                      <pre className="bg-[#0B0F19] text-amber-400 p-2.5 rounded font-mono text-[10px] mt-1 select-all border border-slate-800">
                        sudo apt-get update && sudo apt-get install -y python3-pip libpcap-dev tcpreplay
                      </pre>
                    </li>
                    <li>
                      <span className="text-slate-200 font-semibold">使用 pip 安装 Scapy 与跨网口控制拓展包:</span>
                      <pre className="bg-[#0B0F19] text-amber-400 p-2.5 rounded font-mono text-[10px] mt-1 select-all border border-slate-800">
                        pip3 install scapy fastapi uvicorn requests
                      </pre>
                    </li>
                    <li>
                      <span className="text-slate-200 font-semibold">特权发包服务启动:</span> Scapy 需要管理员特权（`sudo`）以在二层套接字上直接注入帧。拷贝右侧 [Scapy 编译文件] 保存为 `packet_agent.py` 并作为 daemon 执行：
                      <pre className="bg-[#0B0F19] text-amber-400 p-2.5 rounded font-mono text-[10px] mt-1 select-all border border-slate-800">
                        sudo python3 packet_agent.py --port 3000 --host 0.0.0.0
                      </pre>
                    </li>
                  </ol>
                ) : (
                  <ol className="list-decimal pl-5 text-xs text-slate-400 space-y-2">
                    <li>
                      <span className="text-slate-200 font-semibold">下载 Windows 网络原始包捕获程序:</span> Windows 用户必须首先前往 npcap 组织官方网站下载并安装 <b>Npcap / WinPcap驱动组件</b>。
                    </li>
                    <li>
                      <span className="text-slate-200 font-semibold">安装 Python 与 Scapy 支持:</span>
                      <pre className="bg-[#0B0F19] text-amber-400 p-2.5 rounded font-mono text-[10px] mt-1 select-all border border-slate-800">
                        pip install scapy fastapi uvicorn requests
                      </pre>
                    </li>
                    <li>
                      <span className="text-slate-200 font-semibold">利用 PowerShell 授予管理员权限下运行:</span>
                      <pre className="bg-[#0B0F19] text-amber-400 p-2.5 rounded font-mono text-[10px] mt-1 select-all border border-slate-800">
                        python packet_agent.py --port 3000
                      </pre>
                    </li>
                  </ol>
                )}

                <div className="bg-[#1A253A]/40 border border-blue-500/10 p-3 rounded-lg text-[11px] text-slate-400 mt-2">
                  <span className="text-blue-400 font-bold">持久化 API 命令对齐:</span> 本前端在和本地容器内 API 自带的 Scapy 编译器交互之余，同样允许直接把配置命令投递到此 Standalone 物理运行的 `packet_agent.py`，实现真实纯粹、极低延迟的发包测试！
                </div>
              </div>
            </div>
          )}

        </div>

        {/* Right Sidebar: Compiled Scapy Script Engine, Hex Dump analysis and Control Panel */}
        <div className="xl:col-span-4 flex flex-col space-y-6">
          
          {/* Section 1: Dynamic Tx Injection Controller Panel */}
          <div className="bg-[#0B0F19] rounded-xl border border-[#1E293B] p-5 flex flex-col space-y-4 shadow-xl relative overflow-hidden">
            {stats.status === 'sending' && (
              <div className="absolute top-0 right-0 left-0 h-[2px] bg-emerald-500 animate-pulse" />
            )}
            
            <div className="text-xs font-bold text-slate-300 uppercase tracking-widest font-mono border-b border-[#1E293B] pb-2 flex items-center justify-between">
              <span>发包硬件物理引擎参数控制 (Tx Target)</span>
              <Play className="w-3.5 h-3.5 text-blue-400 animate-spin" />
            </div>

            <div className="space-y-3.5">
              {/* Target Interface drop-down */}
              <div>
                <label className="block text-[11px] font-mono text-slate-400 uppercase tracking-widest mb-1.5 flex items-center justify-between">
                  <span>选择物理发包网卡适配器</span>
                  <span className="text-[9px] text-[#22C55E] select-none font-mono">({interfaces.length} 块在线)</span>
                </label>
                <select
                  value={sendConfig.interfaceName}
                  onChange={(e) => setSendConfig(p => ({ ...p, interfaceName: e.target.value }))}
                  className="w-full bg-[#101726] border border-[#1E293B] rounded-lg px-3 py-2 text-xs text-slate-100 font-mono focus:outline-none focus:border-blue-500"
                >
                  {interfaces.map((i, idx) => (
                    <option key={idx} value={i.name}>
                      {i.name} {i.ip ? `(${i.ip})` : ''}
                    </option>
                  ))}
                </select>
                <p className="text-[9px] text-slate-500 mt-1">
                  请选择局域网内与目标网络或物理交换机真实直连的网口名称。
                </p>
              </div>

              {/* Transmission mode controls */}
              <div>
                <label className="block text-[11px] font-mono text-slate-400 uppercase tracking-widest mb-1.5">
                  发包模式 (Transmit Mode)
                </label>
                <div className="grid grid-cols-2 gap-2">
                  {[
                    { id: 'single', label: '1 包单机发送' },
                    { id: 'count', label: '定量发包含数' },
                    { id: 'duration', label: '定时发包时限' },
                    { id: 'infinite', label: '无线循环注入' }
                  ].map((mode) => (
                    <button
                      key={mode.id}
                      onClick={() => setSendConfig(p => ({ ...p, mode: mode.id as any }))}
                      className={`text-xs py-2 px-2.5 font-bold rounded-lg border transition-all cursor-pointer ${
                        sendConfig.mode === mode.id 
                          ? 'bg-blue-600/15 text-blue-400 border-blue-500/40 shadow-sm' 
                          : 'bg-[#101726]/60 text-slate-400 border-[#1E293B] hover:border-slate-800'
                      }`}
                    >
                      {mode.label}
                    </button>
                  ))}
                </div>
              </div>

              {/* Conditional parameter input blocks based on active count/duration modes */}
              <div className="grid grid-cols-2 gap-3.5 pt-1">
                {sendConfig.mode === 'count' && (
                  <div>
                    <label className="block text-[10px] font-mono text-slate-500 uppercase tracking-widest mb-1.5">
                      发包总数量
                    </label>
                    <input
                      type="number"
                      value={sendConfig.count}
                      onChange={(e) => setSendConfig(p => ({ ...p, count: parseInt(e.target.value) || 1 }))}
                      className="w-full bg-[#101726] border border-[#1E293B] rounded-lg px-2.5 py-1.5 text-xs text-slate-100 font-mono"
                    />
                  </div>
                )}
                
                {sendConfig.mode === 'duration' && (
                  <div>
                    <label className="block text-[10px] font-mono text-slate-500 uppercase tracking-widest mb-1.5">
                      发包持续秒数 (S)
                    </label>
                    <input
                      type="number"
                      value={sendConfig.durationSec}
                      onChange={(e) => setSendConfig(p => ({ ...p, durationSec: parseInt(e.target.value) || 1 }))}
                      className="w-full bg-[#101726] border border-[#1E293B] rounded-lg px-2.5 py-1.5 text-xs text-slate-100 font-mono"
                    />
                  </div>
                )}

                <div>
                  <label className="block text-[10px] font-mono text-slate-500 uppercase tracking-widest mb-1.5">
                    包间隔时间 (ms)
                  </label>
                  <input
                    type="number"
                    value={sendConfig.intervalMs}
                    onChange={(e) => setSendConfig(p => ({ ...p, intervalMs: parseInt(e.target.value) || 1 }))}
                    className="w-full bg-[#101726] border border-[#1E293B] rounded-lg px-2.5 py-1.5 text-xs text-slate-100 font-mono"
                  />
                </div>

                <div>
                  <label className="block text-[10px] font-mono text-slate-500 uppercase tracking-widest mb-1.5">
                    瞬时峰值限速 (PPS)
                  </label>
                  <input
                    type="number"
                    value={sendConfig.rateLimitPps}
                    onChange={(e) => setSendConfig(p => ({ ...p, rateLimitPps: parseInt(e.target.value) || 1 }))}
                    className="w-full bg-[#101726] border border-[#1E293B] rounded-lg px-2.5 py-1.5 text-xs text-slate-100 font-mono"
                  />
                </div>
              </div>

              {/* Big Interactive Action triggers */}
              <div className="pt-2 flex items-center space-x-3">
                {stats.status === 'sending' ? (
                  <button
                    onClick={handleStopTransmitting}
                    className="flex-1 bg-gradient-to-r from-rose-600 to-red-500 hover:from-rose-500 hover:to-red-400 hover:scale-[1.01] active:scale-[0.99] p-3 rounded-lg text-white font-bold text-xs flex items-center justify-center space-x-2 shadow-lg shadow-rose-600/20 cursor-pointer transition-all"
                  >
                    <Square className="w-4 h-4 fill-white" />
                    <span>停止发包注入 (Abort Tx)</span>
                  </button>
                ) : (
                  <button
                    onClick={handleStartTransmitting}
                    className="flex-1 bg-gradient-to-r from-blue-600 to-indigo-500 hover:from-blue-500 hover:to-indigo-400 hover:scale-[1.01] active:scale-[0.99] p-3 rounded-lg text-white font-bold text-xs flex items-center justify-center space-x-2 shadow-lg shadow-blue-600/20 cursor-pointer transition-all"
                  >
                    <Play className="w-4 h-4 fill-white" />
                    <span>开始发送报文 (Start Traffic)</span>
                  </button>
                )}

                <button
                  onClick={handleClearStats}
                  title="重置配置及清空统计"
                  className="bg-[#1E293B] hover:bg-[#334155] border border-[#334155] p-3 rounded-lg text-slate-300 transition-all cursor-pointer flex items-center justify-center"
                >
                  <RefreshCw className="w-4 h-4" />
                </button>
              </div>

            </div>
          </div>

          {/* Section 2: Real-time compiled Hex analysis preview of selected packet */}
          <div className="bg-[#0B0F19] rounded-xl border border-[#1E293B] p-5 flex flex-col space-y-4 shadow-xl">
            <div className="text-xs font-bold text-slate-300 uppercase tracking-widest font-mono border-b border-[#1E293B] pb-2 flex items-center justify-between">
              <span>报文即时编译分析 HEX 对照 (Tx Preview)</span>
              <span className="text-[10px] text-blue-400 capitalize bg-blue-500/10 px-2.5 py-0.5 rounded font-mono">
                {analysis?.size || 0} 字节
              </span>
            </div>

            {analysis ? (
              <div className="space-y-3 font-mono text-xs">
                <div className="bg-[#080D16] p-3 rounded-lg text-[10px] text-slate-300 overflow-x-auto border border-[#1f2c41]/30 max-h-[160px] leading-relaxed">
                  <pre className="font-bold text-emerald-400 whitespace-pre">{analysis.hexDump}</pre>
                  <div className="border-t border-slate-800 my-2 opacity-50"></div>
                  <pre className="text-slate-400 select-text whitespace-pre">{analysis.asciiDump}</pre>
                </div>
                
                <div className="space-y-1.5">
                  <div className="text-[10px] text-slate-400 uppercase tracking-wider font-semibold">二进制构造验证链:</div>
                  <div className="space-y-1">
                    {analysis.layersInfo.map((info, idx) => (
                      <div key={idx} className="flex items-center space-x-2 text-[10px] text-slate-400">
                        <CheckCircle2 className="w-3.5 h-3.5 text-emerald-500 fill-emerald-500/10 shrink-0" />
                        <span>{info}</span>
                      </div>
                    ))}
                  </div>
                </div>
              </div>
            ) : (
              <div className="text-slate-600 text-center py-10 text-xs leading-relaxed">
                [+] 正在编译底层二进制报文格式元数据，请切换配置选择...
              </div>
            )}
          </div>

          {/* Section 3: Copy Standalone Python script executable agent */}
          <div className="bg-[#0B0F19] rounded-xl border border-[#1E293B] p-5 flex flex-col space-y-3 shadow-xl">
            <div className="flex items-center justify-between border-b border-[#1E293B] pb-2">
              <span className="text-xs font-bold text-slate-300 uppercase tracking-widest font-mono flex items-center space-x-1.5">
                <Code className="w-3.5 h-3.5 text-indigo-400" />
                <span>实时生成的 Scapy 脚本代码 (Scapy Gen)</span>
              </span>
              <button
                onClick={() => handleCopyToClipboard(scapyCode)}
                className="bg-[#1E293B] hover:bg-[#334155] border border-[#334155] text-slate-300 text-[10px] py-1 px-2.5 rounded transition-all cursor-pointer flex items-center space-x-1"
              >
                <Copy className="w-3 h-3" />
                <span>{isCopied ? '已复制' : '复制命令'}</span>
              </button>
            </div>

            <p className="text-[10px] text-slate-400 leading-normal">
              此代码专为线下独立脚本工具、专业思博伦测试仪仿真或无头Linux特权运行而生，全场景离线对齐。
            </p>

            <div className="bg-[#080D16] p-3 rounded-lg text-[10px] text-amber-500 overflow-x-auto border border-[#1a2537]/30 max-h-[150px] font-mono leading-relaxed select-all">
              <pre>{scapyCode || '# 没有生成最新的 Python Scapy 包代码'}</pre>
            </div>
          </div>

        </div>

      </div>

      {/* Footer System Console Logs and statistics */}
      <div className="p-4 lg:p-6 pt-0 bg-[#070A13]">
        <ConsoleLogs logs={logs} onClear={handleClearStats} />
      </div>

      {/* HELP INSTRUCTION MANUAL MODAL */}
      {showHelpModal && (
        <div className="fixed inset-0 bg-black/80 backdrop-blur-xs flex items-center justify-center p-4 z-50 animate-fade-in">
          <div className="bg-[#0B0F19] rounded-2xl border border-[#1E293B] p-6 max-w-2xl w-full text-slate-200 shadow-2xl space-y-4">
            <div className="flex items-center justify-between border-b border-[#1E293B] pb-3">
              <h3 className="text-base font-bold text-blue-400 flex items-center space-x-2">
                <BookOpen className="w-5 h-5 animate-bounce" />
                <span>思博伦/Ixia 报文构造发包测试使用教程及对齐指南</span>
              </h3>
              <button
                onClick={() => setShowHelpModal(false)}
                className="text-slate-400 hover:text-slate-100 font-bold transition-colors cursor-pointer text-sm"
              >
                ✕ 关闭
              </button>
            </div>

            <div className="space-y-4 text-xs leading-relaxed max-h-[400px] overflow-y-auto pr-2">
              <div>
                <h4 className="text-slate-100 font-bold mb-1">1. 如何组装并发送一份自定义报文？</h4>
                <p className="text-slate-400">
                  进入首页面，左侧 “协议层级堆叠拓扑” 列出了目前支持的协议组件。点击任意协议（例如 <b>TCP</b>），然后自由设定 <b>源端口、目的端口、各种标志位</b> 等参数。之后，点击右边 <b>“开始发送报文”</b> 键，即可立即调用后端 Scapy 驱动执行高速发包校验。
                </p>
              </div>

              <div>
                <h4 className="text-slate-100 font-bold mb-1">2. 支持哪些主流二层、三层、四层协议字段？</h4>
                <ul className="list-disc pl-5 text-slate-400 space-y-1">
                  <li><b>L2 Layer:</b> Ethernet帧 (自设目的和源MAC)</li>
                  <li><b>ARP Layer:</b> 发送请求/响应包绑定IP与硬件MAC地址映射，可模拟ARP中继与伪造校验</li>
                  <li><b>L3 IPv4/IPv6:</b> 包含 ID、TTL、TOS 差分机制、Flags 位及版本切换</li>
                  <li><b>L4 L4 Payload:</b> TCP（含全标志 SYN/ACK/FIN 滑动窗口控制）、UDP 各向同性高速报头、ICMP 诊断心跳包</li>
                  <li><b>RAW Payload:</b> 直接输入文本字符串或以 Hex 十六进制码字填充（如 DNS 请求字节）。</li>
                </ul>
              </div>

              <div>
                <h4 className="text-slate-100 font-bold mb-1">3. Standalone Agent (物理运行方式) 怎么启动？</h4>
                <p className="text-slate-400">
                  由于 Scapy 发送真实物理链路数据对系统管理员和网卡（NDIS/libpcap）有高要求。您可以切换到 <b>“服务端持久化 Agent 部署”</b> 导航，根据提示保存 Python 程序，在线上真实服务器的特权账户 <b>sudo</b> 下直接运行，以此联调多通道真实网络性能测试。
                </p>
              </div>

              <div>
                <h4 className="text-slate-100 font-bold mb-1">4. 为什么会有丢包和分析重校过程？</h4>
                <p className="text-slate-400">
                  平台内部嵌入了专业级 Wireshark HexDump 双向协议仿真。当系统判定可能触发溢出或者字段冲突时，会于校验栏提供温馨警告，帮助发包测试工程师更直观排查链路异常。
                </p>
              </div>
            </div>

            <div className="flex justify-end border-t border-[#1E293B] pt-4">
              <button
                onClick={() => setShowHelpModal(false)}
                className="bg-blue-600 hover:bg-blue-500 text-white font-bold text-xs py-2 px-5 rounded-lg cursor-pointer transition-all"
              >
                我已了解，立即开启测试
              </button>
            </div>
          </div>
        </div>
      )}

    </div>
  );
}
