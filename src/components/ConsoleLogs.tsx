import React, { useEffect, useRef } from 'react';
import { Terminal, Trash2 } from 'lucide-react';
import { LogItem } from '../types.js';

interface ConsoleLogsProps {
  logs: LogItem[];
  onClear: () => void;
}

export const ConsoleLogs: React.FC<ConsoleLogsProps> = ({ logs, onClear }) => {
  const containerRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    if (containerRef.current) {
      containerRef.current.scrollTop = containerRef.current.scrollHeight;
    }
  }, [logs]);

  const getLogLevelStyle = (level: string) => {
    switch (level) {
      case 'success':
        return 'text-emerald-400 border-l-2 border-emerald-500 bg-emerald-500/5';
      case 'warn':
        return 'text-amber-400 border-l-2 border-amber-500 bg-amber-500/5';
      case 'error':
        return 'text-rose-400 border-l-2 border-rose-500 bg-rose-500/5';
      default:
        return 'text-slate-300 border-l-2 border-blue-500 bg-blue-500/5';
    }
  };

  return (
    <div className="bg-[#0B0F19] rounded-xl border border-[#1E293B] shadow-lg flex flex-col h-[200px]">
      <div className="flex items-center justify-between border-b border-[#1E293B] px-4 py-2 bg-[#101726]/80 rounded-t-xl">
        <div className="flex items-center space-x-2 text-slate-300">
          <Terminal className="w-4 h-4 text-blue-400" />
          <span className="text-xs font-bold uppercase tracking-wider font-mono">系统发包监控日志</span>
          <span className="text-[10px] font-mono opacity-60">({logs.length}/200)</span>
        </div>
        <button
          onClick={onClear}
          title="清空日志"
          className="text-slate-400 hover:text-slate-200 transition-colors cursor-pointer"
        >
          <Trash2 className="w-3.5 h-3.5" />
        </button>
      </div>

      <div
        ref={containerRef}
        className="flex-1 overflow-y-auto px-4 py-3 font-mono text-[11px] leading-relaxed space-y-2 bg-[#090D16]"
      >
        {logs.length === 0 ? (
          <div className="text-slate-500 text-center py-8">
            [+] 暂无最新网络发包日志，请构造报文并启动发包测试...
          </div>
        ) : (
          logs.map((log) => (
            <div
              key={log.id}
              className={`px-3 py-1.5 rounded transition-colors ${getLogLevelStyle(log.level)}`}
            >
              <span className="text-slate-500 select-none mr-2">[{log.timestamp}]</span>
              <span className="font-semibold select-all">{log.message}</span>
            </div>
          ))
        )}
      </div>
    </div>
  );
};
