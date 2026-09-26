"""
TCP Stream Reconstructor for PCAP Analysis

Reconstructs TCP streams from packet captures by grouping packets by
the 4-tuple (src IP, src port, dst IP, dst port) and reordering by sequence number.

This is a scoped v1 implementation focused on well-formed SMTP/IMAP/POP3 captures.
"""

from typing import List, Dict, Tuple, Optional
from collections import defaultdict
import struct


class TcpPacket:
    """Represents a TCP packet with essential fields."""
    def __init__(self, src_ip: str, src_port: int, dst_ip: str, dst_port: int,
                 seq: int, ack: int, payload: bytes, timestamp: float):
        self.src_ip = src_ip
        self.src_port = src_port
        self.dst_ip = dst_ip
        self.dst_port = dst_port
        self.seq = seq
        self.ack = ack
        self.payload = payload
        self.timestamp = timestamp

    def get_stream_key(self) -> str:
        """Get unique key for this stream (bidirectional)."""
        # Normalize key so direction doesn't matter
        endpoints = sorted([
            (self.src_ip, self.src_port),
            (self.dst_ip, self.dst_port)
        ])
        return f"{endpoints[0][0]}:{endpoints[0][1]}-{endpoints[1][0]}:{endpoints[1][1]}"


class TcpStream:
    """Represents a reconstructed TCP stream."""
    def __init__(self, stream_id: int):
        self.stream_id = stream_id
        self.packets: List[TcpPacket] = []
        self.client_ip: Optional[str] = None
        self.client_port: Optional[int] = None
        self.server_ip: Optional[str] = None
        self.server_port: Optional[int] = None
        self.reassembled_payload: bytes = b''
        self.packet_count: int = 0
        self.client_bytes: int = 0
        self.server_bytes: int = 0

    def add_packet(self, packet: TcpPacket):
        """Add a packet to this stream."""
        self.packets.append(packet)
        self.packet_count += 1
        
        # Track bytes by direction
        if packet.src_port == self.client_port:
            self.client_bytes += len(packet.payload)
        else:
            self.server_bytes += len(packet.payload)

    def reassemble(self):
        """Reassemble the stream payload in order."""
        # Sort by sequence number
        self.packets.sort(key=lambda p: p.seq)
        
        # Simple reassembly (doesn't handle gaps or retransmissions - scoped v1)
        payload_parts = []
        for packet in self.packets:
            if packet.payload:
                payload_parts.append(packet.payload)
        
        self.reassembled_payload = b''.join(payload_parts)


def reconstruct_tcp_streams(packets: List[TcpPacket]) -> List[TcpStream]:
    """
    Reconstruct TCP streams from a list of TCP packets.
    
    Args:
        packets: List of TcpPacket objects
    
    Returns:
        List of TcpStream objects with reassembled payloads
    """
    # Group packets by stream key
    stream_groups: Dict[str, List[TcpPacket]] = defaultdict(list)
    
    for packet in packets:
        key = packet.get_stream_key()
        stream_groups[key].append(packet)
    
    # Create stream objects
    streams = []
    for stream_id, (key, packet_list) in enumerate(stream_groups.items()):
        stream = TcpStream(stream_id)
        
        # Determine client/server (assuming lower port is server for common protocols)
        ports = [p.src_port for p in packet_list] + [p.dst_port for p in packet_list]
        min_port = min(ports)
        max_port = max(ports)
        
        # First packet in stream is likely client (initiator)
        if packet_list:
            first_packet = min(packet_list, key=lambda p: p.timestamp)
            stream.client_ip = first_packet.src_ip
            stream.client_port = first_packet.src_port
            stream.server_ip = first_packet.dst_ip
            stream.server_port = first_packet.dst_port
        
        # Add all packets
        for packet in packet_list:
            stream.add_packet(packet)
        
        # Reassemble payload
        stream.reassemble()
        streams.append(stream)
    
    return streams


def parse_pcap_simple(pcap_data: bytes) -> List[TcpPacket]:
    """
    Simple PCAP parser for well-formed captures.
    
    This is a scoped v1 implementation that handles basic PCAP format.
    For production use, consider using scapy's rdpcap() function.
    
    Args:
        pcap_data: Raw PCAP file bytes
    
    Returns:
        List of TcpPacket objects
    """
    # For v1, we'll use scapy if available, otherwise return empty
    try:
        from scapy.all import rdpcap, TCP, IP
        
        # Use scapy to parse
        packets = rdpcap(pcap_data)
        tcp_packets = []
        
        for packet in packets:
            if packet.haslayer(TCP) and packet.haslayer(IP):
                ip = packet[IP]
                tcp = packet[TCP]
                
                tcp_packet = TcpPacket(
                    src_ip=ip.src,
                    src_port=tcp.sport,
                    dst_ip=ip.dst,
                    dst_port=tcp.dport,
                    seq=tcp.seq,
                    ack=tcp.ack if tcp.ack else 0,
                    payload=bytes(tcp.payload),
                    timestamp=float(packet.time)
                )
                tcp_packets.append(tcp_packet)
        
        return tcp_packets
        
    except ImportError:
        # Scapy not available
        return []
    except Exception as e:
        # Parsing error
        print(f"PCAP parsing error: {e}")
        return []
