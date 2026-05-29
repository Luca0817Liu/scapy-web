import React from 'react';
import { ShieldCheck, Network, Cpu, Wifi, WifiOff, HelpCircle } from 'lucide-react';

interface HeaderProps {
  isBackendConnected: boolean;
  onShowHelp: () => void;
}

export const Header: React.FC<HeaderProps> = ({ isBackendConnected, onShowHelp }) => {
  return (
    <header className="bg-[#0B0F19] border-b border-[#1E293B] px-6 py-4 flex items-center justify-between shadow-2xl">
      <div className="flex items-center space-x-3">
        <div className="bg-gradient-to-tr from-blue-600 to-indigo-500 p-2.5 rounded-lg shadow-lg shadow-blue-500/20 flex items-center justify-center">
          <ShieldCheck className="w-6 h-6 text-white" />
        </div>
        <div>
          <h1 className="text-lg font-bold text-slate-100 tracking-tight flex items-center space-x-2">
            <span>Visual Packet Studio</span>
            <span className="text-[10px] font-mono bg-blue-500/10 text-blue-400 border border-blue-500/20 px-2 py-0.5 rounded uppercase tracking-widest hidden md:inline">
              V1.2 PEER-TO-PEER
            </span>
          </h1>
          <p className="text-xs text-slate-400 font-medium hidden sm:block">
            全协议栈可视化网络报文构造与发包测试平台 (媲美思博伦/Ixia专业测试仪)
          </p>
        </div>
      </div>

      <div className="flex items-center space-x-4">
        {/* Connection Status indicator */}
        <div className="flex items-center space-x-2 bg-[#161F30] px-3.5 py-1.5 rounded-full border border-[#2e405e]/30">
          <div className="relative flex h-2.5 w-2.5">
            {isBackendConnected ? (
              <>
                <span className="animate-ping absolute inline-flex h-full w-full rounded-full bg-emerald-400 opacity-75"></span>
                <span className="relative inline-flex rounded-full h-2.5 w-2.5 bg-emerald-500"></span>
              </>
            ) : (
              <span className="relative inline-flex rounded-full h-2.5 w-2.5 bg-rose-500"></span>
            )}
          </div>
          <span className="text-xs font-mono font-medium text-slate-300">
            {isBackendConnected ? '后端引擎: 已连接 (API/SSE)' : '后端引擎: 离线模式'}
          </span>
        </div>

        {/* Action icons / Help */}
        <button
          onClick={onShowHelp}
          className="text-slate-400 hover:text-slate-200 transition-all p-2 rounded-lg bg-[#161F30]/50 hover:bg-[#161F30] border border-[#1E293B] cursor-pointer flex items-center space-x-1"
        >
          <HelpCircle className="w-4 h-4" />
          <span className="text-xs font-medium pr-1">教程文档</span>
        </button>
      </div>
    </header>
  );
};
