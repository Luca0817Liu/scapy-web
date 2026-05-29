import express from 'express';
import path from 'path';
import os from 'os';
import { createServer as createViteServer } from 'vite';
import { PacketConfig, SendConfig, SendStats, CapturedPacket, LogItem, NetworkInterface } from './src/types.js';
import { buildPacket, generateHexAndAsciiDump, generateScapyScript } from './src/packetBuilder.js';

// Global server state for the packet injection simulation
let isSending = false;
let sendTimer: NodeJS.Timeout | null = null;
let currentStats: SendStats = {
  status: 'idle',
  sentCount: 0,
  successCount: 0,
  failCount: 0,
  lossRate: 0,
  currentPps: 0,
  elapsedTimeMs: 0
};
let activePacketConfig: PacketConfig | null = null;
let activeSendConfig: SendConfig | null = null;
let totalToPacketCount = 0;
let sendingStartTime = 0;
let lastPpsCount = 0;
let lastPpsTime = 0;

// Logs and Captured packets storage for active session
let sessionLogs: LogItem[] = [];
let capturedPackets: CapturedPacket[] = [];

// SSE client connections list for real-time updates
const sseClients: express.Response[] = [];

function broadcastSSE(type: string, data: any) {
  const message = `event: ${type}\ndata: ${JSON.stringify(data)}\n\n`;
  sseClients.forEach(client => client.write(message));
}

// Log message generator
function addLog(level: 'info' | 'warn' | 'error' | 'success', message: string) {
  const item: LogItem = {
    id: Math.random().toString(36).substring(7),
    timestamp: new Date().toLocaleTimeString(),
    level,
    message
  };
  sessionLogs.push(item);
  // limit storage size
  if (sessionLogs.length > 200) sessionLogs.shift();
  broadcastSSE('log', item);
  return item;
}

// Generate random mock capture records matching the user packet configuration
function addMockCapturedPacket(config: PacketConfig) {
  const isLoss = Math.random() < 0.02; // 2% mock loss rate
  if (isLoss) {
    currentStats.failCount++;
    addLog('warn', `Packet Drop Simulated: Layer checksum mismatch or router dropped packet.`);
    currentStats.lossRate = parseFloat(((currentStats.failCount / currentStats.sentCount) * 100).toFixed(1));
    return;
  }

  currentStats.successCount++;
  
  // Create beautiful raw bytes from the packet config
  const { buffer } = buildPacket(config);
  const { hexDump, asciiDump } = generateHexAndAsciiDump(buffer);
  
  // Format summaries
  let proto = 'RAW';
  let src = 'N/A';
  let dst = 'N/A';
  let sumStr = '';
  
  if (config.isStacked && config.stackedHeaders && config.stackedHeaders.length > 0) {
    const list = config.stackedHeaders.map(h => h.type);
    proto = list.join('/');
    const ips = config.stackedHeaders.filter(h => h.type === 'IPV4' || h.type === 'IPV6');
    if (ips.length > 0) {
      src = ips[0].fields.src || '192.168.1.100';
      dst = ips[0].fields.dst || '8.8.8.8';
    }
    const flowNode = config.stackedHeaders.find(h => h.type === 'TCP' || h.type === 'UDP' || h.type === 'VXLAN');
    let extra = '';
    if (flowNode) {
      if (flowNode.type === 'TCP' || flowNode.type === 'UDP') {
        extra = ` Ports:${flowNode.fields.sport}->${flowNode.fields.dport}`;
      } else if (flowNode.type === 'VXLAN') {
        extra = ` VNI:${flowNode.fields.vni || '5001'}`;
      }
    }
    sumStr = `Stacked Encap: ${list.join(' / ')}${extra}` + (config.payloadLength ? ` | Len: ${config.payloadLength}` : '');
  } else if (config.enabledLayers.includes('ARP') && config.layers.ARP) {
    proto = 'ARP';
    src = config.layers.ARP.psrc;
    dst = config.layers.ARP.pdst;
    sumStr = `ARP ${config.layers.ARP.op === 1 ? 'Request' : 'Reply'}: ${src} asks MAC of ${dst}`;
  } else if (config.enabledLayers.includes('IPV4') && config.layers.IPV4) {
    proto = 'IPv4';
    src = config.layers.IPV4.src;
    dst = config.layers.IPV4.dst;
    if (config.enabledLayers.includes('TCP') && config.layers.TCP) {
      proto = 'TCP';
      const tcp = config.layers.TCP;
      sumStr = `TCP ${src}:${tcp.sport} -> ${dst}:${tcp.dport} [${tcp.flags.join(',')}] Seq=${tcp.seq} Ack=${tcp.ack}`;
    } else if (config.enabledLayers.includes('UDP') && config.layers.UDP) {
      proto = 'UDP';
      const udp = config.layers.UDP;
      sumStr = `UDP ${src}:${udp.sport} -> ${dst}:${udp.dport} Length=${buffer.length - 34}`;
    } else if (config.enabledLayers.includes('ICMP') && config.layers.ICMP) {
      proto = 'ICMP';
      const icmp = config.layers.ICMP;
      sumStr = `ICMP (Type=${icmp.type}, Code=${icmp.code}) Seq=${icmp.seq} ID=${icmp.id}`;
    } else {
      sumStr = `IPv4 ${src} -> ${dst} Proto=${config.layers.IPV4.proto}`;
    }
  } else if (config.enabledLayers.includes('IPV6') && config.layers.IPV6) {
    proto = 'IPv6';
    src = config.layers.IPV6.src;
    dst = config.layers.IPV6.dst;
    if (config.enabledLayers.includes('TCP') && config.layers.TCP) {
      proto = 'TCP6';
      const tcp = config.layers.TCP;
      sumStr = `TCPv6 ${src}:${tcp.sport} -> ${dst}:${tcp.dport} [${tcp.flags.join(',')}]`;
    } else if (config.enabledLayers.includes('UDP') && config.layers.UDP) {
      proto = 'UDP6';
      const udp = config.layers.UDP;
      sumStr = `UDPv6 ${src}:${udp.sport} -> ${dst}:${udp.dport}`;
    } else {
      sumStr = `IPv6 ${src} -> ${dst} NH=${config.layers.IPV6.nh}`;
    }
  } else if (config.enabledLayers.includes('ETHERNET') && config.layers.ETHERNET) {
    proto = 'Ethernet';
    src = config.layers.ETHERNET.src;
    dst = config.layers.ETHERNET.dst;
    sumStr = `Ethernet Frames (Type=${config.layers.ETHERNET.type})`;
  } else {
    sumStr = `RAW Byte frame, Payload size: ${buffer.length} bytes`;
  }

  const pkg: CapturedPacket = {
    index: capturedPackets.length + 1,
    timestamp: new Date().toLocaleTimeString() + '.' + String(Date.now() % 1000).padStart(3, '0'),
    srcMac: config.layers.ETHERNET?.src || '00:00:00:00:00:00',
    dstMac: config.layers.ETHERNET?.dst || '00:00:00:00:00:00',
    srcIp: src !== 'N/A' ? src : undefined,
    dstIp: dst !== 'N/A' ? dst : undefined,
    protocol: proto,
    length: buffer.length,
    summary: sumStr,
    hexDump,
    asciiDump
  };

  capturedPackets.push(pkg);
  if (capturedPackets.length > 500) capturedPackets.shift();
  
  broadcastSSE('packet', pkg);
}

// Tick updater: process periodic statistics calculation and loop sending
function onSendTick() {
  if (!isSending || !activePacketConfig || !activeSendConfig) return;
  
  const elapsed = Date.now() - sendingStartTime;
  currentStats.elapsedTimeMs = elapsed;
  
  // Calculate current PPS and handle pacing
  // We want to send a batch of packages to match the PPS configuration
  const targetPps = activeSendConfig.rateLimitPps || 100;
  const tickDurationMs = activeSendConfig.intervalMs || 100;
  
  // calculate how many packages we need to deliver in this tick
  let toSendThisTick = Math.ceil((targetPps * tickDurationMs) / 1000);
  if (toSendThisTick < 1) toSendThisTick = 1;
  
  for (let i = 0; i < toSendThisTick; i++) {
    if (activeSendConfig.mode === 'count' && currentStats.sentCount >= totalToPacketCount) {
      finishSending('finished');
      return;
    }
    if (activeSendConfig.mode === 'duration' && elapsed >= activeSendConfig.durationSec * 1000) {
      finishSending('finished');
      return;
    }
    
    currentStats.sentCount++;
    lastPpsCount++;
    
    // Create capturing record
    addMockCapturedPacket(activePacketConfig);
  }

  // PPS reporting
  const now = Date.now();
  if (now - lastPpsTime >= 1000) {
    const elapsedSec = (now - lastPpsTime) / 1000;
    currentStats.currentPps = Math.round(lastPpsCount / elapsedSec);
    lastPpsCount = 0;
    lastPpsTime = now;
  }
  
  broadcastSSE('stats', currentStats);
}

function finishSending(status: 'finished' | 'stopped' | 'error' = 'finished') {
  if (sendTimer) {
    clearInterval(sendTimer);
    sendTimer = null;
  }
  isSending = false;
  currentStats.status = status;
  currentStats.currentPps = 0;
  broadcastSSE('stats', currentStats);
  
  if (status === 'finished') {
    addLog('success', `发包任务全部完成！共发送了 ${currentStats.sentCount} 个数据包，丢包率 ${currentStats.lossRate}%。`);
  } else if (status === 'stopped') {
    addLog('warn', `发包任务被用户手动停止，累计已发送 ${currentStats.sentCount} 个数据包。`);
  }
}

async function startServer() {
  const app = express();
  const PORT = 3000;

  app.use(express.json());

  // API routing declarations
  
  // 1. Get host network adapters
  app.get('/api/interfaces', (req, res) => {
    const interfaces = os.networkInterfaces();
    const list: NetworkInterface[] = [];
    
    // Inject mock and real ones combined for physical experience
    list.push({
      name: 'eth0 (Default Primary Interface)',
      ip: '192.168.1.102',
      mac: '00:0c:29:ab:cd:ef',
      description: 'Physical Gigabit Intel Pro Ethernet Connection'
    });
    
    list.push({
      name: 'wlan0 (Wireless network Card)',
      ip: '192.168.31.54',
      mac: 'ac:bc:32:df:2e:11',
      description: 'MediaTek MT7921 Wi-Fi 6 Wireless Connection'
    });

    list.push({
      name: 'lo (Loopback Adapter)',
      ip: '127.0.0.1',
      mac: '00:00:00:00:00:00',
      description: 'Software Local Loopback Connection'
    });

    // Extract genuine container interfaces
    Object.keys(interfaces).forEach(name => {
      const info = interfaces[name];
      if (info) {
        const ipv4 = info.find(i => i.family === 'IPv4');
        if (ipv4) {
          list.push({
            name: `${name} (Container Real OS)`,
            ip: ipv4.address,
            mac: ipv4.mac !== '00:00:00:00:00:00' ? ipv4.mac : undefined,
            description: `Docker/Cloud Container virtual tap adapter`
          });
        }
      }
    });

    res.json({ success: true, interfaces: list });
  });

  // 2. Clear current statistics, logs and packets table
  app.post('/api/send/clear', (req, res) => {
    capturedPackets = [];
    sessionLogs = [];
    currentStats = {
      status: 'idle',
      sentCount: 0,
      successCount: 0,
      failCount: 0,
      lossRate: 0,
      currentPps: 0,
      elapsedTimeMs: 0
    };
    addLog('info', '发包统计及抓包缓存已成功重置。');
    broadcastSSE('stats', currentStats);
    res.json({ success: true });
  });

  // 3. Assemble and analyze custom packet
  app.post('/api/packet/analyze', (req, res) => {
    const { packet } = req.body;
    if (!packet) {
       res.status(400).json({ success: false, error: 'Packet configuration is null' });
       return;
    }
    
    try {
      const { buffer, layersInfo } = buildPacket(packet);
      const { hexDump, asciiDump } = generateHexAndAsciiDump(buffer);
      
      res.json({
        success: true,
        size: buffer.length,
        hexDump,
        asciiDump,
        layersInfo
      });
    } catch (e: any) {
      res.status(500).json({ success: false, error: e.message || 'Error occurred during packet assembly' });
    }
  });

  // 4. Generate Python standalone packet script
  app.post('/api/scapy/generate', (req, res) => {
    const { packet, sendConfig } = req.body;
    if (!packet || !sendConfig) {
       res.status(400).json({ success: false, error: 'Packet configuration or Send configuration is missing' });
       return;
    }
    
    try {
      const pyCode = generateScapyScript(packet, sendConfig);
      res.json({ success: true, pyCode });
    } catch (e: any) {
      res.status(500).json({ success: false, error: e.message });
    }
  });

  // 5. Start sending packet injection
  app.post('/api/send/start', (req, res) => {
    const { packet, sendConfig } = req.body;
    if (!packet || !sendConfig) {
       res.status(400).json({ success: false, error: 'Invalid configuration' });
       return;
    }
    
    if (isSending) {
       res.status(400).json({ success: false, error: 'Another发包 task is currently running' });
       return;
    }
    
    isSending = true;
    activePacketConfig = packet;
    activeSendConfig = sendConfig;
    
    // Set parameters
    totalToPacketCount = sendConfig.mode === 'count' ? sendConfig.count : Infinity;
    sendingStartTime = Date.now();
    lastPpsCount = 0;
    lastPpsTime = Date.now();
    
    currentStats = {
      status: 'sending',
      sentCount: 0,
      successCount: 0,
      failCount: 0,
      lossRate: 0,
      currentPps: 0,
      elapsedTimeMs: 0
    };
    
    addLog('info', `发包任务启动! 网卡: ${sendConfig.interfaceName} | 模式: ${sendConfig.mode} | PPS限制: ${sendConfig.rateLimitPps}/s`);
    
    // Trigger tick based on intervals configured by standard Ixia limits
    const tickInterval = sendConfig.intervalMs || 100;
    sendTimer = setInterval(onSendTick, tickInterval);
    
    res.json({ success: true, stats: currentStats });
  });

  // 6. Stop sending injection
  app.post('/api/send/stop', (req, res) => {
    if (!isSending) {
       res.json({ success: true, message: 'Already stopped' });
       return;
    }
    finishSending('stopped');
    res.json({ success: true });
  });

  // 7. Get historical stats/logs for startup
  app.get('/api/send/init-state', (req, res) => {
    res.json({
      success: true,
      stats: currentStats,
      logs: sessionLogs,
      packets: capturedPackets
    });
  });

  // Server-Sent Events (SSE) Route
  app.get('/api/send/sse-stats', (req, res) => {
    res.writeHead(200, {
      'Content-Type': 'text/event-stream',
      'Cache-Control': 'no-cache',
      'Connection': 'keep-alive',
    });
    
    sseClients.push(res);
    
    // Send current status immediately
    res.write(`event: session-init\ndata: ${JSON.stringify({ stats: currentStats, logs: sessionLogs })}\n\n`);
    
    req.on('close', () => {
      const idx = sseClients.indexOf(res);
      if (idx !== -1) {
        sseClients.splice(idx, 1);
      }
    });
  });

  // --- Serve UI files ---
  if (process.env.NODE_ENV !== "production") {
    // Vite Dev Middleware
    const vite = await createViteServer({
      server: { middlewareMode: true },
      appType: 'spa'
    });
    app.use(vite.middlewares);
  } else {
    // Production Static Files
    const distPath = path.join(process.cwd(), 'dist');
    app.use(express.static(distPath));
    app.get('*', (req, res) => {
      res.sendFile(path.join(distPath, 'index.html'));
    });
  }

  // Run server
  app.listen(PORT, '0.0.0.0', () => {
    console.log(`Server launched on http://0.0.0.0:${PORT}`);
  });
}

startServer();
