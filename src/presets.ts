import { PacketConfig } from './types.js';

export const STANDARD_PRESETS: { name: string; description: string; packet: PacketConfig }[] = [
  {
    name: 'TCP SYN Flood 攻击探测',
    description: '标准TCP握手首包，用于测试防火墙抗DDoS能力或开放端口扫描',
    packet: {
      id: 'tcp-syn-flood',
      name: 'TCP SYN Flood 攻击探测',
      enabledLayers: ['ETHERNET', 'IPV4', 'TCP'],
      layers: {
        ETHERNET: {
          dst: 'ff:ff:ff:ff:ff:ff',
          src: '00:0c:29:ab:cd:ef',
          type: 0x0800
        },
        IPV4: {
          version: 4,
          tos: 0,
          id: 1042,
          flags: 'DF',
          frag: 0,
          ttl: 64,
          proto: 6, // TCP
          src: '192.168.1.102',
          dst: '8.8.8.8'
        },
        TCP: {
          sport: 50431,
          dport: 80,
          seq: 19842031,
          ack: 0,
          flags: ['SYN'],
          window: 8192,
          urgptr: 0
        },
        RAW: {
          format: 'string',
          payload: ''
        }
      }
    }
  },
  {
    name: 'ARP 漏洞扫描探测 (IP欺骗)',
    description: '欺骗局域网网关，声称自己拥有目标IP，用于嗅探流量或ARP欺骗测试',
    packet: {
      id: 'arp-poisoning',
      name: 'ARP 漏洞扫描探测 (IP欺骗)',
      enabledLayers: ['ETHERNET', 'ARP'],
      layers: {
        ETHERNET: {
          dst: 'ff:ff:ff:ff:ff:ff',
          src: '00:0c:29:ab:cd:ef',
          type: 0x0806 // ARP
        },
        ARP: {
          hwtype: 1,
          ptype: 0x0800,
          hwlen: 6,
          plen: 4,
          op: 1, // Request
          hwsrc: '00:0c:29:ab:cd:ef',
          psrc: '192.168.1.1', // Gateway IP
          hwdst: '00:00:00:00:00:00',
          pdst: '192.168.1.150'
        }
      }
    }
  },
  {
    name: 'UDP DNS 域名解析请求',
    description: '标准的DNS（53端口）域名解析UDP帧，附带自定义解析请求原始荷载',
    packet: {
      id: 'dns-query',
      name: 'UDP DNS 域名解析请求',
      enabledLayers: ['ETHERNET', 'IPV4', 'UDP', 'RAW'],
      layers: {
        ETHERNET: {
          dst: '3c:a6:2f:11:22:33',
          src: 'ac:bc:32:df:2e:11',
          type: 0x0800
        },
        IPV4: {
          version: 4,
          tos: 0,
          id: 54311,
          flags: 'DF',
          frag: 0,
          ttl: 128,
          proto: 17, // UDP
          src: '192.168.31.54',
          dst: '114.114.114.114'
        },
        UDP: {
          sport: 59312,
          dport: 53
        },
        RAW: {
          format: 'hex',
          payload: '00 01 01 00 00 01 00 00 00 00 00 00 03 77 77 77 05 62 61 69 64 75 03 63 6f 6d 00 00 01 00 01' // baidu.com IN A
        }
      }
    }
  },
  {
    name: 'ICMP Echo Ping 请求包',
    description: '标准ICMP网络诊断Ping请求包，用于测试防火墙响应与存活判断',
    packet: {
      id: 'icmp-ping',
      name: 'ICMP Echo Ping 请求包',
      enabledLayers: ['ETHERNET', 'IPV4', 'ICMP', 'RAW'],
      layers: {
        ETHERNET: {
          dst: '00:0c:29:11:22:33',
          src: '00:0c:29:ab:cd:ef',
          type: 0x0800
        },
        IPV4: {
          version: 4,
          tos: 0,
          id: 9942,
          flags: '',
          frag: 0,
          ttl: 64,
          proto: 1, // ICMP
          src: '192.168.1.102',
          dst: '192.168.1.1'
        },
        ICMP: {
          type: 8, // Echo Request
          code: 0,
          id: 1122,
          seq: 1
        },
        RAW: {
          format: 'string',
          payload: 'abcdefghijklmnopqrstuvwabcdefghi' // ICMP payload padding
        }
      }
    }
  }
];

export const EMPTY_PACKET: PacketConfig = {
  id: 'new-packet',
  name: '未命名自定义报文',
  enabledLayers: ['ETHERNET', 'IPV4', 'TCP'],
  layers: {
    ETHERNET: {
      dst: 'ff:ff:ff:ff:ff:ff',
      src: '00:0c:29:ab:cd:ef',
      type: 0x0800
    },
    IPV4: {
      version: 4,
      tos: 0,
      id: 1,
      flags: 'DF',
      frag: 0,
      ttl: 64,
      proto: 6,
      src: '192.168.1.102',
      dst: '192.168.1.1'
    },
    TCP: {
      sport: 8080,
      dport: 80,
      seq: 0,
      ack: 0,
      flags: ['SYN'],
      window: 8192,
      urgptr: 0
    },
    UDP: {
      sport: 8080,
      dport: 80
    },
    ARP: {
      hwtype: 1,
      ptype: 0x0800,
      hwlen: 6,
      plen: 4,
      op: 1,
      hwsrc: '00:0c:29:ab:cd:ef',
      psrc: '192.168.1.102',
      hwdst: '00:00:00:00:00:00',
      pdst: '192.168.1.1'
    },
    ICMP: {
      type: 8,
      code: 0,
      id: 1,
      seq: 1
    },
    RAW: {
      format: 'string',
      payload: 'Hello Packet'
    }
  }
};
