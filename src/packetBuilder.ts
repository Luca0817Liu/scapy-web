import { PacketConfig, LayerType } from './types.js';

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
