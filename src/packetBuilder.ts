import { PacketConfig, LayerType, HeaderConfig } from './types.js';

// Helper: Convert MAC address (e.g., "00:11:22:33:44:55") to Buffer
export function macToBytes(mac: string): Buffer {
  const clean = mac.replace(/[:-]/g, '');
  if (clean.length !== 12) return Buffer.alloc(6);
  return Buffer.from(clean, 'hex');
}

// Helper: Convert IPv4 string to Buffer
export function ipv4ToBytes(ip: string): Buffer {
  const parts = ip.split('.').map(Number);
  if (parts.length !== 4 || parts.some(isNaN)) return Buffer.alloc(4);
  return Buffer.from(parts);
}

// Helper: Convert IPv6 string to Buffer
export function ipv6ToBytes(ip: string): Buffer {
  // Simple IPv6 parser (supports full and basic compressed formatting)
  const expanded = expandIpv6(ip);
  if (!expanded) return Buffer.alloc(16);
  return Buffer.from(expanded.replace(/[:]/g, ''), 'hex');
}

function expandIpv6(ip: string): string | null {
  try {
    let address = ip.trim();
    if (address === '::') {
      return Array(8).fill('0000').join(':');
    }
    const parts = address.split('::');
    if (parts.length > 2) return null; // Invalid IPv6
    
    let left = parts[0] ? parts[0].split(':') : [];
    let right = parts[1] ? parts[1].split(':') : [];
    
    if (parts.length === 2) {
      const missingLength = 8 - (left.length + right.length);
      const middle = Array(missingLength).fill('0000');
      left = left.concat(middle).concat(right);
    }
    
    if (left.length !== 8) return null;
    
    return left.map(part => part.padStart(4, '0')).join(':');
  } catch (e) {
    return null;
  }
}

// RFC 1071 Internet Checksum
export function computeChecksum(buf: Buffer): number {
  let sum = 0;
  for (let i = 0; i < buf.length; i += 2) {
    if (i + 1 < buf.length) {
      sum += buf.readUInt16BE(i);
    } else {
      sum += buf[i] << 8;
    }
  }
  while (sum >> 16) {
    sum = (sum & 0xffff) + (sum >> 16);
  }
  return (~sum) & 0xffff;
}

// Generate dual pane hex + ASCII view of any buffer
export function generateHexAndAsciiDump(buf: Buffer): { hexDump: string; asciiDump: string } {
  const hexLines: string[] = [];
  const asciiLines: string[] = [];
  
  for (let i = 0; i < buf.length; i += 16) {
    const chunk = buf.subarray(i, i + 16);
    const hexSlice: string[] = [];
    const asciiSlice: string[] = [];
    
    for (let j = 0; j < 16; j++) {
      if (j < chunk.length) {
        const val = chunk[j];
        hexSlice.push(val.toString(16).padStart(2, '0'));
        // ASCII representation
        if (val >= 32 && val <= 126) {
          asciiSlice.push(String.fromCharCode(val));
        } else {
          asciiSlice.push('.');
        }
      } else {
        hexSlice.push('  ');
        asciiSlice.push(' ');
      }
    }
    
    // Line prefix 0000, 0010, 0020...
    const addr = i.toString(16).padStart(4, '0');
    hexLines.push(`${addr}  ${hexSlice.slice(0, 8).join(' ')}  ${hexSlice.slice(8, 16).join(' ')}`);
    asciiLines.push(asciiSlice.join(''));
  }
  
  return {
    hexDump: hexLines.join('\n'),
    asciiDump: asciiLines.join('\n')
  };
}

// Build a real binary packet buffer from user config
export function buildPacket(config: PacketConfig): {
  buffer: Buffer;
  layersInfo: string[];
} {
  if (config.isStacked) {
    return buildStackedPacket(config);
  }
  const layersInfo: string[] = [];
  let buffer = Buffer.alloc(0);
  
  // 1. Ethernet
  let hasEther = config.enabledLayers.includes('ETHERNET') && config.layers.ETHERNET;
  let protoType = 0x0800; // default IPv4
  
  if (config.enabledLayers.includes('ARP')) protoType = 0x0806;
  else if (config.enabledLayers.includes('IPV6')) protoType = 0x86dd;
  
  let ethBuf = Buffer.alloc(0);
  if (hasEther) {
    const eth = config.layers.ETHERNET!;
    ethBuf = Buffer.alloc(14);
    macToBytes(eth.dst).copy(ethBuf, 0);
    macToBytes(eth.src).copy(ethBuf, 6);
    ethBuf.writeUInt16BE(eth.type || protoType, 12);
    layersInfo.push('Ethernet II Layer assembled');
  }

  // 2. ARP
  if (config.enabledLayers.includes('ARP') && config.layers.ARP) {
    const arp = config.layers.ARP!;
    const arpBuf = Buffer.alloc(28);
    arpBuf.writeUInt16BE(arp.hwtype, 0);
    arpBuf.writeUInt16BE(arp.ptype, 2);
    arpBuf.writeUInt8(arp.hwlen, 4);
    arpBuf.writeUInt8(arp.plen, 5);
    arpBuf.writeUInt16BE(arp.op, 6);
    macToBytes(arp.hwsrc).copy(arpBuf, 8);
    ipv4ToBytes(arp.psrc).copy(arpBuf, 14);
    macToBytes(arp.hwdst).copy(arpBuf, 18);
    ipv4ToBytes(arp.pdst).copy(arpBuf, 24);
    
    buffer = Buffer.concat([ethBuf, arpBuf]);
    layersInfo.push('ARP Request/Reply Layer assembled');
    return { buffer, layersInfo }; // ARP is L2 payload, stop here usually
  }

  // Determine Layer 3 payload
  let l3Buf = Buffer.alloc(0);
  let l4Buf = Buffer.alloc(0);
  
  // Prepare payload first to compute lengths
  let rawPayload = Buffer.alloc(0);
  if (config.enabledLayers.includes('RAW') && config.layers.RAW) {
    const raw = config.layers.RAW!;
    if (raw.format === 'hex') {
      const cleanHex = raw.payload.replace(/\s+/g, '');
      rawPayload = Buffer.from(cleanHex, 'hex');
    } else {
      rawPayload = Buffer.from(raw.payload, 'utf8');
    }
  }

  // Build L4
  let l4Proto = 6; // TCP
  if (config.enabledLayers.includes('UDP')) l4Proto = 17;
  else if (config.enabledLayers.includes('ICMP')) l4Proto = 1; // ICMPv4
  
  if (config.enabledLayers.includes('TCP') && config.layers.TCP) {
    const tcp = config.layers.TCP!;
    const tcpBuf = Buffer.alloc(20);
    
    tcpBuf.writeUInt16BE(tcp.sport, 0);
    tcpBuf.writeUInt16BE(tcp.dport, 2);
    tcpBuf.writeUInt32BE(tcp.seq, 4);
    tcpBuf.writeUInt32BE(tcp.ack, 8);
    
    // Data offset = 5 (20 bytes), RSV = 0
    let flagVal = 0;
    if (tcp.flags.includes('FIN')) flagVal |= 0x01;
    if (tcp.flags.includes('SYN')) flagVal |= 0x02;
    if (tcp.flags.includes('RST')) flagVal |= 0x04;
    if (tcp.flags.includes('PSH')) flagVal |= 0x08;
    if (tcp.flags.includes('ACK')) flagVal |= 0x10;
    if (tcp.flags.includes('URG')) flagVal |= 0x20;
    
    tcpBuf.writeUInt16BE((5 << 12) | flagVal, 12);
    tcpBuf.writeUInt16BE(tcp.window, 14);
    tcpBuf.writeUInt16BE(0, 16); // Checksum temp 0
    tcpBuf.writeUInt16BE(tcp.urgptr, 18);
    
    l4Buf = Buffer.concat([tcpBuf, rawPayload]);
    
    // Checksum with pseudo-header
    let pseudo = Buffer.alloc(12);
    if (config.enabledLayers.includes('IPV4') && config.layers.IPV4) {
      ipv4ToBytes(config.layers.IPV4.src).copy(pseudo, 0);
      ipv4ToBytes(config.layers.IPV4.dst).copy(pseudo, 4);
      pseudo.writeUInt8(0, 8);
      pseudo.writeUInt8(6, 9); // TCP proto
      pseudo.writeUInt16BE(l4Buf.length, 10);
      
      const combined = Buffer.concat([pseudo, l4Buf]);
      const chksumVal = computeChecksum(combined);
      l4Buf.writeUInt16BE(chksumVal, 16);
    }
    layersInfo.push('TCP Layer assembled (Checksum dynamically calculated)');
  } 
  else if (config.enabledLayers.includes('UDP') && config.layers.UDP) {
    const udp = config.layers.UDP!;
    const udpBuf = Buffer.alloc(8);
    
    const udpLen = 8 + rawPayload.length;
    udpBuf.writeUInt16BE(udp.sport, 0);
    udpBuf.writeUInt16BE(udp.dport, 2);
    udpBuf.writeUInt16BE(udpLen, 4);
    udpBuf.writeUInt16BE(0, 6); // Checksum temp 
    
    l4Buf = Buffer.concat([udpBuf, rawPayload]);
    
    // Checksum with pseudo-header
    let pseudo = Buffer.alloc(12);
    if (config.enabledLayers.includes('IPV4') && config.layers.IPV4) {
      ipv4ToBytes(config.layers.IPV4.src).copy(pseudo, 0);
      ipv4ToBytes(config.layers.IPV4.dst).copy(pseudo, 4);
      pseudo.writeUInt8(0, 8);
      pseudo.writeUInt8(17, 9); // UDP proto
      pseudo.writeUInt16BE(l4Buf.length, 10);
      
      const combined = Buffer.concat([pseudo, l4Buf]);
      const chksumVal = computeChecksum(combined);
      l4Buf.writeUInt16BE(chksumVal, 6);
    }
    layersInfo.push('UDP Layer assembled (Length ' + udpLen + ' bytes)');
  } 
  else if (config.enabledLayers.includes('ICMP') && config.layers.ICMP) {
    const icmp = config.layers.ICMP!;
    const icmpBuf = Buffer.alloc(8);
    icmpBuf.writeUInt8(icmp.type, 0);
    icmpBuf.writeUInt8(icmp.code, 1);
    icmpBuf.writeUInt16BE(0, 2); // Checksum temp
    icmpBuf.writeUInt16BE(icmp.id, 4);
    icmpBuf.writeUInt16BE(icmp.seq, 6);
    
    l4Buf = Buffer.concat([icmpBuf, rawPayload]);
    const chksumVal = computeChecksum(l4Buf);
    l4Buf.writeUInt16BE(chksumVal, 2);
    layersInfo.push('ICMP Layer assembled (Type ' + icmp.type + ', Checksum calculated)');
  } else {
    // Just payload
    l4Buf = rawPayload;
    if (l4Buf.length > 0) {
      layersInfo.push('RAW Payload appended (' + l4Buf.length + ' bytes)');
    }
  }

  // Build L3
  if (config.enabledLayers.includes('IPV4') && config.layers.IPV4) {
    const ip = config.layers.IPV4!;
    const ipBuf = Buffer.alloc(20);
    const ipLen = 20 + l4Buf.length;
    
    ipBuf.writeUInt8(0x45, 0); // Version 4, IHL 5
    ipBuf.writeUInt8(ip.tos, 1);
    ipBuf.writeUInt16BE(ipLen, 2);
    ipBuf.writeUInt16BE(ip.id, 4);
    
    let flagVal = 0;
    if (ip.flags.includes('DF')) flagVal |= 0x4000;
    if (ip.flags.includes('MF')) flagVal |= 0x2000;
    flagVal |= (ip.frag & 0x1fff);
    ipBuf.writeUInt16BE(flagVal, 6);
    
    ipBuf.writeUInt8(ip.ttl, 8);
    ipBuf.writeUInt8(ip.proto || l4Proto, 9);
    ipBuf.writeUInt16BE(0, 10); // Checksum temp
    ipv4ToBytes(ip.src).copy(ipBuf, 12);
    ipv4ToBytes(ip.dst).copy(ipBuf, 16);
    
    const chksumVal = computeChecksum(ipBuf);
    ipBuf.writeUInt16BE(chksumVal, 10);
    
    l3Buf = Buffer.concat([ipBuf, l4Buf]);
    layersInfo.push('IPv4 Layer assembled (IP Total Length ' + ipLen + ' bytes, IPv4 Header Checksum calculated)');
  } 
  else if (config.enabledLayers.includes('IPV6') && config.layers.IPV6) {
    const ip6 = config.layers.IPV6!;
    const ipBuf = Buffer.alloc(40);
    
    // Traffic class 8 bits, flow label 20 bits
    const vTcF = (0x60000000 | (ip6.tc << 20) | (ip6.fl & 0xfffff)) >>> 0;
    ipBuf.writeUInt32BE(vTcF, 0);
    ipBuf.writeUInt16BE(l4Buf.length, 4); // Payload Length
    ipBuf.writeUInt8(ip6.nh || l4Proto, 6);
    ipBuf.writeUInt8(ip6.hlim, 7);
    ipv6ToBytes(ip6.src).copy(ipBuf, 8);
    ipv6ToBytes(ip6.dst).copy(ipBuf, 24);
    
    l3Buf = Buffer.concat([ipBuf, l4Buf]);
    layersInfo.push('IPv6 Layer assembled (Flow Label: ' + ip6.fl + ', Next Header: ' + ip6.nh + ')');
  } else {
    // No L3 layer, layer 4 sits directly on link or raw
    l3Buf = l4Buf;
  }

  // Combine Ethereum
  buffer = Buffer.concat([ethBuf, l3Buf]);
  return { buffer, layersInfo };
}

// Generate the fully functional offline Python + Scapy standalone code
export function generateScapyScript(config: PacketConfig, sendConf: any): string {
  if (config.isStacked) {
    return generateScapyStackedScript(config, sendConf);
  }
  let scapyLines: string[] = ['#!/usr/bin/env python3', 'import time', 'import sys', 'from scapy.all import *', ''];
  let pktLayers: string[] = [];
  
  // 1. Ethernet Layer
  if (config.enabledLayers.includes('ETHERNET') && config.layers.ETHERNET) {
    const eth = config.layers.ETHERNET!;
    let ethType = '';
    if (config.enabledLayers.includes('ARP')) ethType = ', type=0x0806';
    else if (config.enabledLayers.includes('IPV6')) ethType = ', type=0x86dd';
    else if (config.enabledLayers.includes('IPV4')) ethType = ', type=0x0800';
    pktLayers.push(`Ether(dst="${eth.dst}", src="${eth.src}"${ethType})`);
  }
  
  // 2. ARP Layer
  if (config.enabledLayers.includes('ARP') && config.layers.ARP) {
    const arp = config.layers.ARP!;
    pktLayers.push(`ARP(hwtype=${arp.hwtype}, ptype=0x${arp.ptype.toString(16)}, op=${arp.op}, hwsrc="${arp.hwsrc}", psrc="${arp.psrc}", hwdst="${arp.hwdst}", pdst="${arp.pdst}")`);
  }
  
  // 3. IP Layers
  if (config.enabledLayers.includes('IPV4') && config.layers.IPV4) {
    const ip = config.layers.IPV4!;
    let flagsStr = ip.flags === 'DF' ? 'DF' : ip.flags === 'MF' ? 'MF' : '';
    let protoMapStr = '';
    if (config.enabledLayers.includes('TCP')) protoMapStr = ', proto=6';
    else if (config.enabledLayers.includes('UDP')) protoMapStr = ', proto=17';
    else if (config.enabledLayers.includes('ICMP')) protoMapStr = ', proto=1';
    
    pktLayers.push(`IP(tos=${ip.tos}, id=${ip.id}, flags="${flagsStr}", frag=${ip.frag}, ttl=${ip.ttl}${protoMapStr}, src="${ip.src}", dst="${ip.dst}")`);
  } else if (config.enabledLayers.includes('IPV6') && config.layers.IPV6) {
    const ip6 = config.layers.IPV6!;
    pktLayers.push(`IPv6(tc=${ip6.tc}, fl=${ip6.fl}, hlim=${ip6.hlim}, src="${ip6.src}", dst="${ip6.dst}")`);
  }
  
  // 4. L4 Layers
  if (config.enabledLayers.includes('TCP') && config.layers.TCP) {
    const tcp = config.layers.TCP!;
    const flagsList = tcp.flags.map(f => f[0]).join(''); // 'S', 'A', etc.
    pktLayers.push(`TCP(sport=${tcp.sport}, dport=${tcp.dport}, seq=${tcp.seq}, ack=${tcp.ack}, flags="${flagsList}", window=${tcp.window}, urgptr=${tcp.urgptr})`);
  } else if (config.enabledLayers.includes('UDP') && config.layers.UDP) {
    const udp = config.layers.UDP!;
    pktLayers.push(`UDP(sport=${udp.sport}, dport=${udp.dport})`);
  } else if (config.enabledLayers.includes('ICMP') && config.layers.ICMP) {
    const icmp = config.layers.ICMP!;
    pktLayers.push(`ICMP(type=${icmp.type}, code=${icmp.code}, id=${icmp.id}, seq=${icmp.seq})`);
  }
  
  // 5. Payload
  if (config.enabledLayers.includes('RAW') && config.layers.RAW) {
    const raw = config.layers.RAW!;
    if (raw.format === 'hex') {
      const hexLiteral = raw.payload.replace(/\s+/g, '');
      pktLayers.push(`Raw(load=bytes.fromhex("${hexLiteral}"))`);
    } else {
      // Escape payload quotes
      const escaped = raw.payload.replace(/"/g, '\\"').replace(/\n/g, '\\n');
      pktLayers.push(`Raw(load="${escaped}")`);
    }
  }

  // Build the packet
  scapyLines.push('# 1. 构造网络层/物理层自定义报文');
  scapyLines.push(`pkt = ${pktLayers.join(' / ')}`);
  scapyLines.push('');
  scapyLines.push('print("=" * 60)');
  scapyLines.push('print(" Visual Packet Studio - Standalone Packet Injector")');
  scapyLines.push('print("=" * 60)');
  scapyLines.push('print("[*] 组装报文格式如下:")');
  scapyLines.push('pkt.show()');
  scapyLines.push('print("-" * 60)');
  
  // Sending setup
  const ifaceParam = sendConf.interfaceName && sendConf.interfaceName !== 'Any' ? `, iface="${sendConf.interfaceName}"` : '';
  const intervalS = sendConf.intervalMs / 1000;
  
  scapyLines.push('# 2. 初始化发包控制');
  scapyLines.push(`interval = ${intervalS}`);
  scapyLines.push(`mode = "${sendConf.mode}"`);
  
  if (sendConf.mode === 'single') {
    scapyLines.push('print("[*] 正在发送 1 个自定义报文...")');
    if (config.enabledLayers.includes('ETHERNET')) {
      scapyLines.push(`sendp(pkt${ifaceParam}, verbose=True)`);
    } else {
      scapyLines.push(`send(pkt${ifaceParam}, verbose=True)`);
    }
  } else if (sendConf.mode === 'count') {
    scapyLines.push(`count = ${sendConf.count}`);
    scapyLines.push('print(f"[*] 准备发送 {count} 个自定义报文, 间隔: {interval} 秒...")');
    scapyLines.push('sent = 0');
    scapyLines.push('try:');
    scapyLines.push('    for i in range(count):');
    if (config.enabledLayers.includes('ETHERNET')) {
      scapyLines.push(`        sendp(pkt${ifaceParam}, verbose=False)`);
    } else {
      scapyLines.push(`        send(pkt${ifaceParam}, verbose=False)`);
    }
    scapyLines.push('        sent += 1');
    scapyLines.push('        print(f"\\r[+] 成功发送: {sent}/{count} 个报文 [{sent*100//count}%]", end="", flush=True)');
    scapyLines.push('        if i < count - 1:');
    scapyLines.push('            time.sleep(interval)');
    scapyLines.push('    print("\\n[+] 发送完成！")');
    scapyLines.push('except KeyboardInterrupt:');
    scapyLines.push('    print("\\n[-] 用户手动中断发包！")');
  } else if (sendConf.mode === 'duration') {
    scapyLines.push(`duration = ${sendConf.durationSec}`);
    scapyLines.push('print(f"[*] 准备发包, 持续时间: {duration} 秒, 间隔: {interval} 秒...")');
    scapyLines.push('start_time = time.time()');
    scapyLines.push('sent = 0');
    scapyLines.push('try:');
    scapyLines.push('    while (time.time() - start_time) < duration:');
    if (config.enabledLayers.includes('ETHERNET')) {
      scapyLines.push(`        sendp(pkt${ifaceParam}, verbose=False)`);
    } else {
      scapyLines.push(`        send(pkt${ifaceParam}, verbose=False)`);
    }
    scapyLines.push('        sent += 1');
    scapyLines.push('        elapsed = round(time.time() - start_time, 1)');
    scapyLines.push('        print(f"\\r[+] 已耗时: {elapsed}s / {duration}s | 累计已发送: {sent} 个报文", end="", flush=True)');
    scapyLines.push('        time.sleep(interval)');
    scapyLines.push('    print("\\n[+] 定时发包完成！")');
    scapyLines.push('except KeyboardInterrupt:');
    scapyLines.push('    print("\\n[-] 用户手动中断发包！")');
  } else {
    // infinite
    scapyLines.push('print("[-] 正在循环发包中... 按 Ctrl+C 停止。")');
    scapyLines.push('sent = 0');
    scapyLines.push('try:');
    scapyLines.push('    while True:');
    if (config.enabledLayers.includes('ETHERNET')) {
      scapyLines.push(`        sendp(pkt${ifaceParam}, verbose=False)`);
    } else {
      scapyLines.push(`        send(pkt${ifaceParam}, verbose=False)`);
    }
    scapyLines.push('        sent += 1');
    scapyLines.push('        print(f"\\r[+] 累计已发送: {sent} 个报文", end="", flush=True)');
    scapyLines.push('        time.sleep(interval)');
    scapyLines.push('except KeyboardInterrupt:');
    scapyLines.push('    print("\\n[-] 用户停止发包。")');
  }
  
  return scapyLines.join('\n');
}

export function buildStackedPacket(config: PacketConfig): {
  buffer: Buffer;
  layersInfo: string[];
} {
  const layersInfo: string[] = [];
  const buffers: Buffer[] = [];
  
  if (!config.stackedHeaders || config.stackedHeaders.length === 0) {
    const payload = getPayloadBuffer(config);
    return { buffer: payload, layersInfo: ['Only RAW Payload present'] };
  }

  for (let i = 0; i < config.stackedHeaders.length; i++) {
    const hdr = config.stackedHeaders[i];
    const fields = hdr.fields;
    
    if (hdr.type === 'ETHERNET') {
      const buf = Buffer.alloc(14);
      const dstEth = fields.dst || 'ff:ff:ff:ff:ff:ff';
      macToBytes(dstEth).copy(buf, 0);
      const srcEth = fields.src || '00:11:22:33:44:55';
      macToBytes(srcEth).copy(buf, 6);
      let ethType = parseInt(fields.type || '0x0800');
      if (isNaN(ethType)) ethType = 0x0800;
      buf.writeUInt16BE(ethType, 12);
      
      buffers.push(buf);
      layersInfo.push(`Ethernet Header: Src ${srcEth} -> Dst ${dstEth} (Type: 0x${ethType.toString(16).padStart(4, '0')})`);
    }
    else if (hdr.type === 'ARP') {
      const buf = Buffer.alloc(28);
      let hwtype = parseInt(fields.hwtype || '1');
      buf.writeUInt16BE(isNaN(hwtype) ? 1 : hwtype, 0);
      let ptype = parseInt(fields.ptype || '0x0800');
      buf.writeUInt16BE(isNaN(ptype) ? 0x0800 : ptype, 2);
      let hwlen = parseInt(fields.hwlen || '6');
      buf.writeUInt8(isNaN(hwlen) ? 6 : hwlen, 4);
      let plen = parseInt(fields.plen || '4');
      buf.writeUInt8(isNaN(plen) ? 4 : plen, 5);
      let op = parseInt(fields.op || '1');
      buf.writeUInt16BE(isNaN(op) ? 1 : op, 6);
      const hwsrc = fields.hwsrc || '00:11:22:33:44:55';
      macToBytes(hwsrc).copy(buf, 8);
      const psrc = fields.psrc || '192.168.1.1';
      ipv4ToBytes(psrc).copy(buf, 14);
      const hwdst = fields.hwdst || '00:00:00:00:00:00';
      macToBytes(hwdst).copy(buf, 18);
      const pdst = fields.pdst || '192.168.1.254';
      ipv4ToBytes(pdst).copy(buf, 24);
      
      buffers.push(buf);
      layersInfo.push(`ARP Header: Opcode ${op} (Sender: ${psrc}, Target: ${pdst})`);
    }
    else if (hdr.type === 'IPV4') {
      const buf = Buffer.alloc(20);
      let version = parseInt(fields.version || '4');
      let ihl = parseInt(fields.ihl || '5');
      buf.writeUInt8(((version & 0x0f) << 4) | (ihl & 0x0f), 0);
      
      let tos = parseInt(fields.tos || '0');
      buf.writeUInt8(isNaN(tos) ? 0 : tos, 1);
      
      let len = parseInt(fields.len || '0');
      buf.writeUInt16BE(isNaN(len) ? 0 : len, 2);
      
      let id = parseInt(fields.id || '12345');
      buf.writeUInt16BE(isNaN(id) ? 12345 : id, 4);
      
      let frag = parseInt(fields.frag || '0');
      let flagsVal = 0;
      const flagsStr = fields.flags || '';
      if (flagsStr.includes('DF')) flagsVal |= 0x4000;
      if (flagsStr.includes('MF')) flagsVal |= 0x2000;
      flagsVal |= (frag & 0x1fff);
      buf.writeUInt16BE(flagsVal, 6);
      
      let ttl = parseInt(fields.ttl || '64');
      buf.writeUInt8(isNaN(ttl) ? 64 : ttl, 8);
      
      let proto = parseInt(fields.proto || '17');
      buf.writeUInt8(isNaN(proto) ? 17 : proto, 9);
      
      buf.writeUInt16BE(0, 10);
      
      const src = fields.src || '192.168.1.100';
      const dst = fields.dst || '8.8.8.8';
      ipv4ToBytes(src).copy(buf, 12);
      ipv4ToBytes(dst).copy(buf, 16);
      
      const chk = computeChecksum(buf);
      buf.writeUInt16BE(chk, 10);
      
      buffers.push(buf);
      layersInfo.push(`IPv4 Header: Src ${src} -> Dst ${dst} (Proto: ${proto}, TTL: ${ttl})`);
    }
    else if (hdr.type === 'IPV6') {
      const buf = Buffer.alloc(40);
      let tc = parseInt(fields.tc || '0');
      let fl = parseInt(fields.fl || '0');
      
      const vTcF = (0x60000000 | ((tc & 0xff) << 20) | (fl & 0xfffff)) >>> 0;
      buf.writeUInt32BE(vTcF, 0);
      
      let plen = parseInt(fields.plen || '0');
      buf.writeUInt16BE(isNaN(plen) ? 0 : plen, 4);
      
      let nh = parseInt(fields.nh || '17');
      buf.writeUInt8(isNaN(nh) ? 17 : nh, 6);
      
      let hlim = parseInt(fields.hlim || '64');
      buf.writeUInt8(isNaN(hlim) ? 64 : hlim, 7);
      
      const src = fields.src || 'fe80::1';
      const dst = fields.dst || '2001:4860:4860::8888';
      ipv6ToBytes(src).copy(buf, 8);
      ipv6ToBytes(dst).copy(buf, 24);
      
      buffers.push(buf);
      layersInfo.push(`IPv6 Header: Src ${src} -> Dst ${dst} (NextHdr: ${nh})`);
    }
    else if (hdr.type === 'TCP') {
      const buf = Buffer.alloc(20);
      let sport = parseInt(fields.sport || '12345');
      let dport = parseInt(fields.dport || '80');
      buf.writeUInt16BE(isNaN(sport) ? 12345 : sport, 0);
      buf.writeUInt16BE(isNaN(dport) ? 80 : dport, 2);
      
      let seq = parseInt(fields.seq || '1000');
      buf.writeUInt32BE(isNaN(seq) ? 1000 : seq, 4);
      
      let ack = parseInt(fields.ack || '0');
      buf.writeUInt32BE(isNaN(ack) ? 0 : ack, 8);
      
      let offset = parseInt(fields.offset || '5');
      let flagVal = 0;
      const flagsStr = fields.flags || 'SYN';
      if (flagsStr.includes('FIN')) flagVal |= 0x01;
      if (flagsStr.includes('SYN')) flagVal |= 0x02;
      if (flagsStr.includes('RST')) flagVal |= 0x04;
      if (flagsStr.includes('PSH')) flagVal |= 0x08;
      if (flagsStr.includes('ACK')) flagVal |= 0x10;
      if (flagsStr.includes('URG')) flagVal |= 0x20;
      
      buf.writeUInt16BE(((offset & 0x0f) << 12) | flagVal, 12);
      
      let window = parseInt(fields.window || '8192');
      buf.writeUInt16BE(isNaN(window) ? 8192 : window, 14);
      
      buf.writeUInt16BE(0, 16);
      
      let urgptr = parseInt(fields.urgptr || '0');
      buf.writeUInt16BE(isNaN(urgptr) ? 0 : urgptr, 18);
      
      const chk = computeChecksum(buf);
      buf.writeUInt16BE(chk, 16);
      
      buffers.push(buf);
      layersInfo.push(`TCP Header: Sport ${sport} -> Dport ${dport} (Flags: ${flagsStr}, Seq: ${seq})`);
    }
    else if (hdr.type === 'UDP') {
      const buf = Buffer.alloc(8);
      let sport = parseInt(fields.sport || '12345');
      let dport = parseInt(fields.dport || '4789');
      buf.writeUInt16BE(isNaN(sport) ? 12345 : sport, 0);
      buf.writeUInt16BE(isNaN(dport) ? 4789 : dport, 2);
      
      let len = parseInt(fields.len || '0');
      buf.writeUInt16BE(isNaN(len) ? 8 : len, 4);
      
      buf.writeUInt16BE(0, 6);
      
      buffers.push(buf);
      layersInfo.push(`UDP Header: Sport ${sport} -> Dport ${dport}`);
    }
    else if (hdr.type === 'ICMP') {
      const buf = Buffer.alloc(8);
      let type = parseInt(fields.type || '8');
      let code = parseInt(fields.code || '0');
      buf.writeUInt8(isNaN(type) ? 8 : type, 0);
      buf.writeUInt8(isNaN(code) ? 0 : code, 1);
      buf.writeUInt16BE(0, 2);
      
      let id = parseInt(fields.id || '1234');
      buf.writeUInt16BE(isNaN(id) ? 1234 : id, 4);
      
      let seq = parseInt(fields.seq || '1');
      buf.writeUInt16BE(isNaN(seq) ? 1 : seq, 6);
      
      const chk = computeChecksum(buf);
      buf.writeUInt16BE(chk, 2);
      
      buffers.push(buf);
      layersInfo.push(`ICMP Header: Type ${type}, Code ${code}`);
    }
    else if (hdr.type === 'VXLAN') {
      const buf = Buffer.alloc(8);
      let flags = parseInt(fields.flags || '0x08');
      if (isNaN(flags)) flags = 0x08;
      buf.writeUInt8(flags, 0);
      
      let rsvd1 = parseInt(fields.rsvd1 || '0');
      if (isNaN(rsvd1)) rsvd1 = 0;
      buf.writeUInt8((rsvd1 >> 16) & 0xff, 1);
      buf.writeUInt8((rsvd1 >> 8) & 0xff, 2);
      buf.writeUInt8(rsvd1 & 0xff, 3);
      
      let vni = parseInt(fields.vni || '5001');
      if (isNaN(vni)) vni = 5001;
      buf.writeUInt8((vni >> 16) & 0xff, 4);
      buf.writeUInt8((vni >> 8) & 0xff, 5);
      buf.writeUInt8(vni & 0xff, 6);
      
      let rsvd2 = parseInt(fields.rsvd2 || '0');
      buf.writeUInt8(isNaN(rsvd2) ? 0 : rsvd2, 7);
      
      buffers.push(buf);
      layersInfo.push(`VXLAN Header: VNI ${vni}`);
    }
  }

  const payloadBuf = getPayloadBuffer(config);
  if (payloadBuf.length > 0) {
    buffers.push(payloadBuf);
    layersInfo.push(`User Custom Payload: ${payloadBuf.length} bytes`);
  }

  const finalBuf = Buffer.concat(buffers);

  let currentOffset = 0;
  for (let i = 0; i < config.stackedHeaders.length; i++) {
    const hdr = config.stackedHeaders[i];
    const headerLen = getHeaderLength(hdr.type);
    
    if (hdr.type === 'IPV4' && (hdr.fields.len === '0' || !hdr.fields.len)) {
      const totalLen = finalBuf.length - currentOffset;
      if (currentOffset + 4 <= finalBuf.length) {
        finalBuf.writeUInt16BE(totalLen, currentOffset + 2);
        const ipHeaderSlice = finalBuf.subarray(currentOffset, currentOffset + 20);
        ipHeaderSlice.writeUInt16BE(0, 10);
        const chk = computeChecksum(ipHeaderSlice);
        ipHeaderSlice.writeUInt16BE(chk, 10);
      }
    }
    else if (hdr.type === 'UDP' && (hdr.fields.len === '0' || !hdr.fields.len)) {
      const totalLen = finalBuf.length - currentOffset;
      if (currentOffset + 6 <= finalBuf.length) {
        finalBuf.writeUInt16BE(totalLen, currentOffset + 4);
      }
    }
    currentOffset += headerLen;
  }

  return { buffer: finalBuf, layersInfo };
}

function getHeaderLength(type: string): number {
  switch (type) {
    case 'ETHERNET': return 14;
    case 'ARP': return 28;
    case 'IPV4': return 20;
    case 'IPV6': return 40;
    case 'TCP': return 20;
    case 'UDP': return 8;
    case 'ICMP': return 8;
    case 'VXLAN': return 8;
    default: return 0;
  }
}

function getPayloadBuffer(config: PacketConfig): Buffer {
  const format = config.payloadFormat || 'string';
  const val = config.payloadValue || '';
  const length = config.payloadLength || 0;
  
  let baseBuf = Buffer.alloc(0);
  if (format === 'hex') {
    const clean = val.replace(/\s+/g, '');
    try {
      baseBuf = Buffer.from(clean, 'hex');
    } catch {
      baseBuf = Buffer.alloc(0);
    }
  } else {
    baseBuf = Buffer.from(val, 'utf8');
  }

  if (length > baseBuf.length) {
    const padded = Buffer.alloc(length);
    baseBuf.copy(padded, 0);
    return padded;
  }
  return baseBuf;
}

export function generateScapyStackedScript(config: PacketConfig, sendConf: any): string {
  let scapyLines: string[] = ['#!/usr/bin/env python3', 'import time', 'import sys', 'from scapy.all import *', ''];
  let pktLayers: string[] = [];
  
  if (config.stackedHeaders && config.stackedHeaders.length > 0) {
    for (const hdr of config.stackedHeaders) {
      const fields = hdr.fields;
      if (hdr.type === 'ETHERNET') {
        const dst = fields.dst || 'ff:ff:ff:ff:ff:ff';
        const src = fields.src || '00:11:22:33:44:55';
        let t = fields.type || '0x0800';
        pktLayers.push(`Ether(dst="${dst}", src="${src}", type=${t})`);
      }
      else if (hdr.type === 'ARP') {
        const hwtype = fields.hwtype || '1';
        const ptype = fields.ptype || '0x0800';
        const hwlen = fields.hwlen || '6';
        const plen = fields.plen || '4';
        const op = fields.op || '1';
        const hwsrc = fields.hwsrc || '00:11:22:33:44:55';
        const psrc = fields.psrc || '192.168.1.1';
        const hwdst = fields.hwdst || '00:00:00:00:00:00';
        const pdst = fields.pdst || '192.168.1.254';
        pktLayers.push(`ARP(hwtype=${hwtype}, ptype=${ptype}, hwlen=${hwlen}, plen=${plen}, op=${op}, hwsrc="${hwsrc}", psrc="${psrc}", hwdst="${hwdst}", pdst="${pdst}")`);
      }
      else if (hdr.type === 'IPV4') {
        const version = fields.version || '4';
        const ihl = fields.ihl || '5';
        const tos = fields.tos || '0';
        const id = fields.id || '12345';
        const flags = fields.flags || 'DF';
        const frag = fields.frag || '0';
        const ttl = fields.ttl || '64';
        const proto = fields.proto || '17';
        const src = fields.src || '192.168.1.100';
        const dst = fields.dst || '8.8.8.8';
        let flagsStr = flags === 'DF' ? 'DF' : flags === 'MF' ? 'MF' : '';
        pktLayers.push(`IP(version=${version}, ihl=${ihl}, tos=${tos}, id=${id}, flags="${flagsStr}", frag=${frag}, ttl=${ttl}, proto=${proto}, src="${src}", dst="${dst}")`);
      }
      else if (hdr.type === 'IPV6') {
        const version = fields.version || '6';
        const tc = fields.tc || '0';
        const fl = fields.fl || '0';
        const nh = fields.nh || '17';
        const hlim = fields.hlim || '64';
        const src = fields.src || 'fe80::1';
        const dst = fields.dst || '2001:4860:4860::8888';
        pktLayers.push(`IPv6(version=${version}, tc=${tc}, fl=${fl}, nh=${nh}, hlim=${hlim}, src="${src}", dst="${dst}")`);
      }
      else if (hdr.type === 'TCP') {
        const sport = fields.sport || '12345';
        const dport = fields.dport || '80';
        const seq = fields.seq || '1000';
        const ack = fields.ack || '0';
        const flags = fields.flags || 'SYN';
        const window = fields.window || '8192';
        const urgptr = fields.urgptr || '0';
        const flagsList = flags.split(',').map((f: string) => f.trim()[0]).join('');
        pktLayers.push(`TCP(sport=${sport}, dport=${dport}, seq=${seq}, ack=${ack}, flags="${flagsList}", window=${window}, urgptr=${urgptr})`);
      }
      else if (hdr.type === 'UDP') {
        const sport = fields.sport || '12345';
        const dport = fields.dport || '4789';
        pktLayers.push(`UDP(sport=${sport}, dport=${dport})`);
      }
      else if (hdr.type === 'ICMP') {
        const type = fields.type || '8';
        const code = fields.code || '0';
        const id = fields.id || '1234';
        const seq = fields.seq || '1';
        pktLayers.push(`ICMP(type=${type}, code=${code}, id=${id}, seq=${seq})`);
      }
      else if (hdr.type === 'VXLAN') {
        const vni = fields.vni || '5001';
        const flags = fields.flags || '0x08';
        pktLayers.push(`VXLAN(vni=${vni}, flags=${flags})`);
      }
    }
  }

  const format = config.payloadFormat || 'string';
  const val = config.payloadValue || '';
  const length = config.payloadLength || 0;
  if (val || length > 0) {
    if (format === 'hex') {
      const hexLiteral = val.replace(/\s+/g, '');
      pktLayers.push(`Raw(load=bytes.fromhex("${hexLiteral}"))`);
    } else {
      const escaped = val.replace(/"/g, '\\"').replace(/\n/g, '\\n');
      const padLen = Math.max(0, length - val.length);
      pktLayers.push(`Raw(load="${escaped}" + "\\x00" * ${padLen})`);
    }
  }

  scapyLines.push('# 1. 构造多层/VXLAN堆叠 自定义报文');
  scapyLines.push(`pkt = ${pktLayers.join(' / ')}`);
  scapyLines.push('');
  scapyLines.push('print("=" * 60)');
  scapyLines.push('print(" Visual Packet Studio - Stacked Standalone Packet Injector")');
  scapyLines.push('print("=" * 60)');
  scapyLines.push('print("[*] 组装的多层报文格式如下:")');
  scapyLines.push('pkt.show()');
  scapyLines.push('print("-" * 60)');
  
  const ifaceParam = sendConf.interfaceName && sendConf.interfaceName !== 'Any' ? `, iface="${sendConf.interfaceName}"` : '';
  const intervalS = sendConf.intervalMs / 1000;
  
  scapyLines.push('# 2. 初始化发包控制');
  scapyLines.push(`interval = ${intervalS}`);
  scapyLines.push(`mode = "${sendConf.mode}"`);
  
  const hasEth = config.stackedHeaders && config.stackedHeaders.some(h => h.type === 'ETHERNET');
  const sendCmd = hasEth ? 'sendp' : 'send';

  if (sendConf.mode === 'single') {
    scapyLines.push('print("[*] 正在发送 1 个自定义堆叠报文...")');
    scapyLines.push(`${sendCmd}(pkt${ifaceParam}, verbose=True)`);
  } else if (sendConf.mode === 'count') {
    scapyLines.push(`count = ${sendConf.count}`);
    scapyLines.push('print(f"[*] 准备发送 {count} 个自定义堆叠报文, 间隔: {interval} 秒...")');
    scapyLines.push('sent = 0');
    scapyLines.push('try:');
    scapyLines.push('    for i in range(count):');
    scapyLines.push(`        ${sendCmd}(pkt${ifaceParam}, verbose=False)`);
    scapyLines.push('        sent += 1');
    scapyLines.push('        print(f"\\r[+] 成功发送: {sent}/{count} 个报文 [{sent*100//count}%]", end="", flush=True)');
    scapyLines.push('        if i < count - 1:');
    scapyLines.push('            time.sleep(interval)');
    scapyLines.push('    print("\\n[+] 发送完成！")');
    scapyLines.push('except KeyboardInterrupt:');
    scapyLines.push('    print("\\n[-] 用户手动中断发包！")');
  } else if (sendConf.mode === 'duration') {
    scapyLines.push(`duration = ${sendConf.durationSec}`);
    scapyLines.push('print(f"[*] 准备发包, 持续时间: {duration} 秒, 间隔: {interval} 秒...")');
    scapyLines.push('start_time = time.time()');
    scapyLines.push('sent = 0');
    scapyLines.push('try:');
    scapyLines.push('    while (time.time() - start_time) < duration:');
    scapyLines.push(`        ${sendCmd}(pkt${ifaceParam}, verbose=False)`);
    scapyLines.push('        sent += 1');
    scapyLines.push('        elapsed = round(time.time() - start_time, 1)');
    scapyLines.push('        print(f"\\r[+] 已耗时: {elapsed}s / {duration}s | 累计已发送: {sent} 个报文", end="", flush=True)');
    scapyLines.push('        time.sleep(interval)');
    scapyLines.push('    print("\\n[+] 定时发包完成！")');
    scapyLines.push('except KeyboardInterrupt:');
    scapyLines.push('    print("\\n[-] 用户手动中断发包！")');
  } else {
    scapyLines.push('print("[-] 正在循环发包中... 按 Ctrl+C 停止。")');
    scapyLines.push('sent = 0');
    scapyLines.push('try:');
    scapyLines.push('    while True:');
    scapyLines.push(`        ${sendCmd}(pkt${ifaceParam}, verbose=False)`);
    scapyLines.push('        sent += 1');
    scapyLines.push('        print(f"\\r[+] 累计已发送: {sent} 个报文", end="", flush=True)');
    scapyLines.push('        time.sleep(interval)');
    scapyLines.push('except KeyboardInterrupt:');
    scapyLines.push('    print("\\n[-] 用户停止发包。")');
  }
  
  return scapyLines.join('\n');
}
