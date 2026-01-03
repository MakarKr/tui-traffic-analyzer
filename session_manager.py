#!/usr/bin/env python3

import sqlite3
import threading
import time
import json
from enum import Enum

class PacketType(Enum):
    HTTP_REQUEST = "HTTP_REQUEST"
    HTTP_RESPONSE = "HTTP_RESPONSE"
    HTTPS_SESSION = "HTTPS_SESSION"
    DNS_QUERY = "DNS_QUERY"
    DNS_RESPONSE = "DNS_RESPONSE"
    TCP_CONNECTION = "TCP_CONNECTION"
    UDP_SESSION = "UDP_SESSION"

class Packet:
    def __init__(self, timestamp, src_ip, dst_ip, src_port, dst_port, protocol, packet_type, size, data, raw=None, session_id=None):
        self.timestamp = timestamp
        self.src_ip = src_ip
        self.dst_ip = dst_ip
        self.src_port = src_port
        self.dst_port = dst_port
        self.protocol = protocol
        self.packet_type = packet_type
        self.size = size
        self.data = data
        self.raw = raw
        self.session_id = session_id

class Session:
    def __init__(self, session_id, start_time, end_time=None, client_ip="", server_ip="", client_port=0, server_port=0, protocol=""):
        self.session_id = session_id
        self.start_time = start_time
        self.end_time = end_time
        self.client_ip = client_ip
        self.server_ip = server_ip
        self.client_port = client_port
        self.server_port = server_port
        self.protocol = protocol
        self.packets = []
        self.total_bytes = 0

    def add_packet(self, pkt):
        self.packets.append(pkt)
        self.total_bytes += pkt.size
        if self.end_time is None or pkt.timestamp > self.end_time:
            self.end_time = pkt.timestamp

    def get_duration(self):
        if self.end_time:
            return self.end_time - self.start_time
        return time.time() - self.start_time

class SessionManager:
    def __init__(self, db="sessions.db"):
        self.db = db
        self.sessions = {}
        self.packets = []
        self.lock = threading.Lock()
        self._init_db()

    def _init_db(self):
        with sqlite3.connect(self.db) as conn:
            c = conn.cursor()
            c.execute('''
                CREATE TABLE IF NOT EXISTS sessions (
                    session_id TEXT PRIMARY KEY,
                    start_time REAL,
                    end_time REAL,
                    client_ip TEXT,
                    server_ip TEXT,
                    client_port INTEGER,
                    server_port INTEGER,
                    protocol TEXT,
                    total_bytes INTEGER
                )
            ''')
            c.execute('''
                CREATE TABLE IF NOT EXISTS packets (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    session_id TEXT,
                    timestamp REAL,
                    src_ip TEXT,
                    dst_ip TEXT,
                    src_port INTEGER,
                    dst_port INTEGER,
                    protocol TEXT,
                    packet_type TEXT,
                    size INTEGER,
                    data TEXT
                )
            ''')
            conn.commit()

    def add_packet(self, pkt):
        with self.lock:
            self.packets.append(pkt)

            if pkt.session_id:
                if pkt.session_id not in self.sessions:
                    self.sessions[pkt.session_id] = Session(
                        session_id=pkt.session_id,
                        start_time=pkt.timestamp,
                        client_ip=pkt.src_ip,
                        server_ip=pkt.dst_ip,
                        client_port=pkt.src_port,
                        server_port=pkt.dst_port,
                        protocol=pkt.protocol
                    )

                self.sessions[pkt.session_id].add_packet(pkt)

            # Save to DB in background
            threading.Thread(target=self._save, args=(pkt,), daemon=True).start()

    def _save(self, pkt):
        try:
            with sqlite3.connect(self.db) as conn:
                c = conn.cursor()
                c.execute('''
                    INSERT INTO packets (session_id, timestamp, src_ip, dst_ip, src_port, dst_port, protocol, packet_type, size, data)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ''', (
                    pkt.session_id,
                    pkt.timestamp,
                    pkt.src_ip,
                    pkt.dst_ip,
                    pkt.src_port,
                    pkt.dst_port,
                    pkt.protocol,
                    pkt.packet_type.value,
                    pkt.size,
                    json.dumps(pkt.data)
                ))

                if pkt.session_id:
                    s = self.sessions[pkt.session_id]
                    c.execute('''
                        INSERT OR REPLACE INTO sessions VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                    ''', (
                        s.session_id,
                        s.start_time,
                        s.end_time,
                        s.client_ip,
                        s.server_ip,
                        s.client_port,
                        s.server_port,
                        s.protocol,
                        s.total_bytes
                    ))

                conn.commit()
        except Exception as e:
            print(f"DB error: {e}")

    def get_sessions(self, limit=100):
        with self.lock:
            sess = list(self.sessions.values())
            sess.sort(key=lambda x: x.start_time, reverse=True)
            return sess[:limit]

    def get_packets(self, session_id=None, limit=1000):
        with self.lock:
            if session_id:
                if session_id in self.sessions:
                    return self.sessions[session_id].packets[:limit]
                return []
            return self.packets[-limit:]

    def get_statistics(self):
        with self.lock:
            stats = {
                "total_sessions": len(self.sessions),
                "total_packets": len(self.packets),
                "total_bytes": sum(p.size for p in self.packets),
                "http_requests": len([p for p in self.packets if p.packet_type == PacketType.HTTP_REQUEST]),
                "http_responses": len([p for p in self.packets if p.packet_type == PacketType.HTTP_RESPONSE]),
                "https_sessions": len([p for p in self.packets if p.packet_type == PacketType.HTTPS_SESSION]),
            }

            # Protocols
            proto = {}
            for p in self.packets:
                proto[p.protocol] = proto.get(p.protocol, 0) + 1
            stats["protocols"] = proto

            return stats

    def clear_all(self):
        with self.lock:
            self.sessions.clear()
            self.packets.clear()

        with sqlite3.connect(self.db) as conn:
            c = conn.cursor()
            c.execute("DELETE FROM packets")
            c.execute("DELETE FROM sessions")
            conn.commit()

    def export(self, fname):
        """Export to JSON"""
        with self.lock:
            data = {
                "sessions": [],
                "stats": self.get_statistics()
            }

            for s in self.sessions.values():
                sess_data = {
                    "id": s.session_id,
                    "start": s.start_time,
                    "end": s.end_time,
                    "client": f"{s.client_ip}:{s.client_port}",
                    "server": f"{s.server_ip}:{s.server_port}",
                    "protocol": s.protocol,
                    "bytes": s.total_bytes,
                    "packets": len(s.packets)
                }
                data["sessions"].append(sess_data)

            with open(fname, 'w') as f:
                json.dump(data, f, indent=2)
