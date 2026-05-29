/**
 * @license
 * SPDX-License-Identifier: Apache-2.0
 */

// Protocol Layer Type
export type LayerType = 'ETHERNET' | 'ARP' | 'IPV4' | 'IPV6' | 'TCP' | 'UDP' | 'ICMP' | 'RAW';

// Ethernet Layer Fields
export interface EthernetFields {
  dst: string; // Destination MAC
  src: string; // Source MAC
  type: number; // EtherType (e.g. 0x0800 for IPv4, 0x0806 for ARP, 0x86dd for IPv6)
}

// ARP Layer Fields
export interface ArpFields {
  hwtype: number; // Hardware type (1 for Ethernet)
  ptype: number;  // Protocol type (0x0800 for IPv4)
  hwlen: number;  // Hardware address length (6)
  plen: number;   // Protocol address length (4)
  op: number;     // Opcode (1 for request, 2 for reply)
  hwsrc: string;  // Sender MAC
  psrc: string;   // Sender IP
  hwdst: string;  // Target MAC
  pdst: string;   // Target IP
}

// IPv4 Layer Fields
export interface Ipv4Fields {
  version: number; // Version (4)
  tos: number;     // Type of Service / DSCP
  id: number;      // Identification
  flags: string;   // Flags (DF, MF)
  frag: number;    // Fragment offset
  ttl: number;     // Time to Live
  proto: number;   // Protocol (6 for TCP, 17 for UDP, 1 for ICMP)
  src: string;     // Source IP
  dst: string;     // Destination IP
}

// IPv6 Layer Fields
export interface Ipv6Fields {
  version: number;  // Version (6)
  tc: number;       // Traffic Class
  fl: number;       // Flow Label
  nh: number;       // Next Header (6 for TCP, 17 for UDP, 58 for ICMPv6)
  hlim: number;     // Hop Limit (TTL)
  src: string;      // Source IP
  dst: string;      // Destination IP
}

// TCP Layer Fields
export interface TcpFields {
  sport: number;    // Source Port
  dport: number;    // Destination Port
  seq: number;      // Sequence Number
  ack: number;      // Acknowledgment Number
  flags: string[];  // Flags (SYN, ACK, FIN, RST, PSH, URG)
  window: number;   // Window Size
  urgptr: number;   // Urgent Pointer
}

// UDP Layer Fields
export interface UdpFields {
  sport: number;    // Source Port
  dport: number;    // Destination Port
}

// ICMP Layer Fields
export interface IcmpFields {
  type: number;     // ICMP Type (e.g. 8 for Echo Request, 0 for Echo Reply)
  code: number;     // ICMP Code
  id: number;       // Identifier
  seq: number;      // Sequence Number
}

// RAW Payload Layer Fields
export interface RawFields {
  format: 'string' | 'hex';
  payload: string;
}

// Full packet layout configuration
export interface PacketConfig {
  id: string;
  name: string;
  layers: {
    ETHERNET?: EthernetFields;
    ARP?: ArpFields;
    IPV4?: Ipv4Fields;
    IPV6?: Ipv6Fields;
    TCP?: TcpFields;
    UDP?: UdpFields;
    ICMP?: IcmpFields;
    RAW?: RawFields;
  };
  enabledLayers: LayerType[];
  isStacked?: boolean;
  stackedHeaders?: HeaderConfig[];
  payloadValue?: string;
  payloadLength?: number;
  payloadFormat?: 'string' | 'hex';
}

// Configuration for individual stacked headers
export interface HeaderConfig {
  id: string;
  type: 'ETHERNET' | 'ARP' | 'IPV4' | 'IPV6' | 'TCP' | 'UDP' | 'ICMP' | 'VXLAN';
  fields: {
    [key: string]: string; // Arbitrary field values (keeps user input simple and supports valid/invalid types)
  };
}

// Network interface
export interface NetworkInterface {
  name: string;
  ip?: string;
  mac?: string;
  description?: string;
}

// Sending configuration Page
export type SendMode = 'single' | 'count' | 'duration' | 'infinite';

export interface SendConfig {
  interfaceName: string;
  mode: SendMode;
  count: number;        // Total packet count
  intervalMs: number;   // Packet sending interval
  rateLimitPps: number; // PPS limit
  durationSec: number;  // Sending duration when mode is 'duration'
}

// Sending real-time statistics
export interface SendStats {
  status: 'idle' | 'sending' | 'stopped' | 'finished' | 'error';
  sentCount: number;
  successCount: number;
  failCount: number;
  lossRate: number; // %
  currentPps: number; // Packets per second
  elapsedTimeMs: number;
}

// Packet Capture detail representation
export interface CapturedPacket {
  index: number;
  timestamp: string;
  srcMac: string;
  dstMac: string;
  srcIp?: string;
  dstIp?: string;
  protocol: string;
  length: number;
  summary: string;
  hexDump: string; // Space separated hex
  asciiDump: string; // ASCII visual text representation
}

// Saved templates
export interface SavedTemplate {
  id: string;
  name: string;
  description: string;
  packet: PacketConfig;
  createdAt: string;
}

// Log messages
export interface LogItem {
  id: string;
  timestamp: string;
  level: 'info' | 'warn' | 'error' | 'success';
  message: string;
}
