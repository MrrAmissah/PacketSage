function writeU16LE(target: Uint8Array, offset: number, value: number): void {
  new DataView(target.buffer).setUint16(offset, value, true);
}

function writeU32LE(target: Uint8Array, offset: number, value: number): void {
  new DataView(target.buffer).setUint32(offset, value, true);
}

function concat(...parts: Uint8Array[]): Uint8Array {
  const result = new Uint8Array(parts.reduce((size, part) => size + part.length, 0));
  let offset = 0;
  parts.forEach(part => {
    result.set(part, offset);
    offset += part.length;
  });
  return result;
}

export function dnsEthernetPacket(): Uint8Array {
  const query = new Uint8Array([
    0x12, 0x34, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x07, ...new TextEncoder().encode('example'),
    0x03, ...new TextEncoder().encode('com'),
    0x00, 0x00, 0x01, 0x00, 0x01,
  ]);
  const packet = new Uint8Array(14 + 20 + 8 + query.length);
  packet.set([0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 0x08, 0x00], 0);
  const ip = 14;
  packet[ip] = 0x45;
  packet[ip + 2] = ((20 + 8 + query.length) >> 8) & 0xff;
  packet[ip + 3] = (20 + 8 + query.length) & 0xff;
  packet[ip + 8] = 64;
  packet[ip + 9] = 17;
  packet.set([10, 0, 0, 15], ip + 12);
  packet.set([8, 8, 8, 8], ip + 16);
  const udp = ip + 20;
  packet[udp] = 0xcf;
  packet[udp + 1] = 0x08;
  packet[udp + 2] = 0x00;
  packet[udp + 3] = 0x35;
  packet[udp + 4] = ((8 + query.length) >> 8) & 0xff;
  packet[udp + 5] = (8 + query.length) & 0xff;
  packet.set(query, udp + 8);
  return packet;
}

export function validPcap(): ArrayBuffer {
  const packet = dnsEthernetPacket();
  const header = new Uint8Array(24);
  header.set([0xd4, 0xc3, 0xb2, 0xa1]);
  writeU16LE(header, 4, 2);
  writeU16LE(header, 6, 4);
  writeU32LE(header, 16, 65_535);
  writeU32LE(header, 20, 1);
  const record = new Uint8Array(16);
  writeU32LE(record, 0, 1_716_285_600);
  writeU32LE(record, 4, 123_456);
  writeU32LE(record, 8, packet.length);
  writeU32LE(record, 12, packet.length);
  return concat(header, record, packet).buffer;
}

export function rawIpv4Pcap(
  protocol: number,
  transport: Uint8Array,
  fragmentOffset = 0,
): ArrayBuffer {
  const packet = new Uint8Array(20 + transport.length);
  packet[0] = 0x45;
  packet[2] = (packet.length >> 8) & 0xff;
  packet[3] = packet.length & 0xff;
  packet[6] = (fragmentOffset >> 8) & 0x1f;
  packet[7] = fragmentOffset & 0xff;
  packet[8] = 64;
  packet[9] = protocol;
  packet.set([10, 0, 0, 15], 12);
  packet.set([203, 0, 113, 80], 16);
  packet.set(transport, 20);

  const header = new Uint8Array(24);
  header.set([0xd4, 0xc3, 0xb2, 0xa1]);
  writeU16LE(header, 4, 2);
  writeU16LE(header, 6, 4);
  writeU32LE(header, 16, 65_535);
  writeU32LE(header, 20, 101);
  const record = new Uint8Array(16);
  writeU32LE(record, 0, 1_716_285_600);
  writeU32LE(record, 8, packet.length);
  writeU32LE(record, 12, packet.length);
  return concat(header, record, packet).buffer;
}

export function nativeTcpPcap(sourcePort: number, destinationPort: number): ArrayBuffer {
  const tcp = new Uint8Array(20);
  tcp[0] = (sourcePort >> 8) & 0xff;
  tcp[1] = sourcePort & 0xff;
  tcp[2] = (destinationPort >> 8) & 0xff;
  tcp[3] = destinationPort & 0xff;
  tcp[12] = 0x50;
  tcp[13] = 0x02;
  return rawIpv4Pcap(6, tcp);
}

export function nativeUdpPcap(sourcePort: number, destinationPort: number): ArrayBuffer {
  const udp = new Uint8Array(8);
  udp[0] = (sourcePort >> 8) & 0xff;
  udp[1] = sourcePort & 0xff;
  udp[2] = (destinationPort >> 8) & 0xff;
  udp[3] = destinationPort & 0xff;
  udp[5] = 8;
  return rawIpv4Pcap(17, udp);
}

export function ipv6Pcap(source: readonly number[], destination: readonly number[]): ArrayBuffer {
  if (source.length !== 8 || destination.length !== 8) throw new Error('IPv6 fixtures require eight hextets.');

  const packet = new Uint8Array(40 + 20);
  packet[0] = 0x60;
  packet[4] = 0;
  packet[5] = 20;
  packet[6] = 6;
  packet[7] = 64;
  [...source, ...destination].forEach((hextet, index) => {
    const offset = 8 + index * 2;
    packet[offset] = (hextet >> 8) & 0xff;
    packet[offset + 1] = hextet & 0xff;
  });
  packet[40] = 0xc3;
  packet[41] = 0x50;
  packet[42] = 0x01;
  packet[43] = 0xbb;
  packet[52] = 0x50;
  packet[53] = 0x02;

  const header = new Uint8Array(24);
  header.set([0xd4, 0xc3, 0xb2, 0xa1]);
  writeU16LE(header, 4, 2);
  writeU16LE(header, 6, 4);
  writeU32LE(header, 16, 65_535);
  writeU32LE(header, 20, 101);
  const record = new Uint8Array(16);
  writeU32LE(record, 0, 1_716_285_600);
  writeU32LE(record, 4, 123_456);
  writeU32LE(record, 8, packet.length);
  writeU32LE(record, 12, packet.length);
  return concat(header, record, packet).buffer;
}

export function validPcapng(): ArrayBuffer {
  const packet = dnsEthernetPacket();
  const section = new Uint8Array(28);
  writeU32LE(section, 0, 0x0a0d0d0a);
  writeU32LE(section, 4, 28);
  writeU32LE(section, 8, 0x1a2b3c4d);
  writeU16LE(section, 12, 1);
  section.fill(0xff, 16, 24);
  writeU32LE(section, 24, 28);

  const iface = new Uint8Array(20);
  writeU32LE(iface, 0, 1);
  writeU32LE(iface, 4, 20);
  writeU16LE(iface, 8, 1);
  writeU32LE(iface, 12, 65_535);
  writeU32LE(iface, 16, 20);

  const paddedLength = Math.ceil(packet.length / 4) * 4;
  const enhanced = new Uint8Array(32 + paddedLength);
  writeU32LE(enhanced, 0, 6);
  writeU32LE(enhanced, 4, enhanced.length);
  const timestamp = 1_716_285_600_123_456n;
  writeU32LE(enhanced, 12, Number(timestamp >> 32n));
  writeU32LE(enhanced, 16, Number(timestamp & 0xffffffffn));
  writeU32LE(enhanced, 20, packet.length);
  writeU32LE(enhanced, 24, packet.length);
  enhanced.set(packet, 28);
  writeU32LE(enhanced, enhanced.length - 4, enhanced.length);
  return concat(section, iface, enhanced).buffer;
}
