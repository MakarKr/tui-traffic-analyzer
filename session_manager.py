#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import sqlite3
import threading
import time
import json
from datetime import datetime
from typing import Dict, List, Any, Optional
from dataclasses import dataclass, asdict
from enum import Enum


class PacketType(Enum):
    HTTP_REQUEST = "HTTP_REQUEST"
    HTTP_RESPONSE = "HTTP_RESPONSE"
    HTTPS_SESSION = "HTTPS_SESSION"
    DNS_QUERY = "DNS_QUERY"
    DNS_RESPONSE = "DNS_RESPONSE"
    TCP_CONNECTION = "TCP_CONNECTION"
    UDP_SESSION = "UDP_SESSION"


@dataclass
class Packet:
    timestamp: float
    src_ip: str
    dst_ip: str
    src_port: int
    dst_port: int
    protocol: str
    packet_type: PacketType
    size: int
    data: Dict[str, Any]
    raw_data: Optional[bytes] = None
    session_id: Optional[str] = None


@dataclass
class Session:
    session_id: str
    start_time: float
    end_time: Optional[float] = None
    client_ip: str = ""
    server_ip: str = ""
    client_port: int = 0
    server_port: int = 0
    protocol: str = ""
    packets: List[Packet] = None
    total_bytes: int = 0

    def __post_init__(self):
        if self.packets is None:
            self.packets = []

    def add_packet(self, packet: Packet):
        self.packets.append(packet)
        self.total_bytes += packet.size
        if self.end_time is None or packet.timestamp > self.end_time:
            self.end_time = packet.timestamp

    def get_duration(self) -> float:
        if self.end_time:
            return self.end_time - self.start_time
        return time.time() - self.start_time


class SessionManager:
    def __init__(self, db_path: str = "sessions.db"):
        self.db_path = db_path
        self.sessions: Dict[str, Session] = {}
        self.packets: List[Packet] = []
        self.lock = threading.Lock()
        self.init_database()

    def init_database(self):
        """Инициализировать базу данных"""
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()

            # Таблица сессий
            cursor.execute('''
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

            # Таблица пакетов
            cursor.execute('''
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
                    data TEXT,
                    FOREIGN KEY (session_id) REFERENCES sessions (session_id)
                )
            ''')

            # Индексы для быстрого поиска
            cursor.execute('CREATE INDEX IF NOT EXISTS idx_sessions_time ON sessions(start_time)')
            cursor.execute('CREATE INDEX IF NOT EXISTS idx_packets_session ON packets(session_id)')
            cursor.execute('CREATE INDEX IF NOT EXISTS idx_packets_time ON packets(timestamp)')

            conn.commit()

    def add_packet(self, packet: Packet):
        """Добавить пакет в менеджер сессий"""
        with self.lock:
            self.packets.append(packet)

            # Создаем или обновляем сессию
            if packet.session_id:
                if packet.session_id not in self.sessions:
                    self.sessions[packet.session_id] = Session(
                        session_id=packet.session_id,
                        start_time=packet.timestamp,
                        client_ip=packet.src_ip,
                        server_ip=packet.dst_ip,
                        client_port=packet.src_port,
                        server_port=packet.dst_port,
                        protocol=packet.protocol
                    )

                self.sessions[packet.session_id].add_packet(packet)

            # Сохраняем в базу данных (в фоне)
            threading.Thread(target=self._save_to_db, args=(packet,), daemon=True).start()

    def _save_to_db(self, packet: Packet):
        """Сохранить пакет в базу данных"""
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()

                # Сохраняем данные пакета
                cursor.execute('''
                    INSERT INTO packets 
                    (session_id, timestamp, src_ip, dst_ip, src_port, dst_port, protocol, packet_type, size, data)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ''', (
                    packet.session_id,
                    packet.timestamp,
                    packet.src_ip,
                    packet.dst_ip,
                    packet.src_port,
                    packet.dst_port,
                    packet.protocol,
                    packet.packet_type.value,
                    packet.size,
                    json.dumps(packet.data)
                ))

                # Обновляем или создаем сессию
                if packet.session_id:
                    cursor.execute('''
                        INSERT OR REPLACE INTO sessions 
                        (session_id, start_time, end_time, client_ip, server_ip, client_port, server_port, protocol, total_bytes)
                        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                    ''', (
                        packet.session_id,
                        self.sessions[packet.session_id].start_time,
                        self.sessions[packet.session_id].end_time,
                        self.sessions[packet.session_id].client_ip,
                        self.sessions[packet.session_id].server_ip,
                        self.sessions[packet.session_id].client_port,
                        self.sessions[packet.session_id].server_port,
                        self.sessions[packet.session_id].protocol,
                        self.sessions[packet.session_id].total_bytes
                    ))

                conn.commit()
        except Exception as e:
            print(f"[!] Ошибка сохранения в БД: {e}")

    def get_sessions(self, limit: int = 100) -> List[Session]:
        """Получить список сессий"""
        with self.lock:
            sessions = list(self.sessions.values())
            sessions.sort(key=lambda s: s.start_time, reverse=True)
            return sessions[:limit]

    def get_packets(self, session_id: Optional[str] = None, limit: int = 1000) -> List[Packet]:
        """Получить список пакетов"""
        with self.lock:
            if session_id:
                if session_id in self.sessions:
                    return self.sessions[session_id].packets[:limit]
                return []

            return self.packets[-limit:]

    def get_statistics(self) -> Dict[str, Any]:
        """Получить статистику"""
        with self.lock:
            stats = {
                "total_sessions": len(self.sessions),
                "total_packets": len(self.packets),
                "total_bytes": sum(p.size for p in self.packets),
                "http_requests": len([p for p in self.packets if p.packet_type == PacketType.HTTP_REQUEST]),
                "http_responses": len([p for p in self.packets if p.packet_type == PacketType.HTTP_RESPONSE]),
                "https_sessions": len([p for p in self.packets if p.packet_type == PacketType.HTTPS_SESSION]),
            }

            # Добавляем информацию по протоколам
            protocols = {}
            for packet in self.packets:
                protocols[packet.protocol] = protocols.get(packet.protocol, 0) + 1

            stats["protocols"] = protocols
            return stats

    def clear_all(self):
        """Очистить все данные"""
        with self.lock:
            self.sessions.clear()
            self.packets.clear()

        # Очистить базу данных
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            cursor.execute("DELETE FROM packets")
            cursor.execute("DELETE FROM sessions")
            conn.commit()

    def export_to_json(self, filename: str):
        """Экспортировать данные в JSON"""
        with self.lock:
            data = {
                "sessions": [asdict(session) for session in self.sessions.values()],
                "statistics": self.get_statistics(),
                "export_time": datetime.now().isoformat()
            }

            # Преобразовать объекты Packet в словари
            for session_data in data["sessions"]:
                session_data["packets"] = [asdict(packet) for packet in session_data["packets"]]

            with open(filename, 'w') as f:
                json.dump(data, f, indent=2, default=str)

    def import_from_json(self, filename: str):
        """Импортировать данные из JSON"""
        try:
            with open(filename, 'r') as f:
                data = json.load(f)

            with self.lock:
                self.clear_all()

                # Импорт сессий
                for session_data in data.get("sessions", []):
                    session = Session(
                        session_id=session_data["session_id"],
                        start_time=session_data["start_time"],
                        end_time=session_data.get("end_time"),
                        client_ip=session_data["client_ip"],
                        server_ip=session_data["server_ip"],
                        client_port=session_data["client_port"],
                        server_port=session_data["server_port"],
                        protocol=session_data["protocol"],
                        total_bytes=session_data["total_bytes"]
                    )

                    # Импорт пакетов
                    for packet_data in session_data.get("packets", []):
                        packet = Packet(
                            timestamp=packet_data["timestamp"],
                            src_ip=packet_data["src_ip"],
                            dst_ip=packet_data["dst_ip"],
                            src_port=packet_data["src_port"],
                            dst_port=packet_data["dst_port"],
                            protocol=packet_data["protocol"],
                            packet_type=PacketType(packet_data["packet_type"]),
                            size=packet_data["size"],
                            data=packet_data["data"],
                            session_id=packet_data.get("session_id")
                        )
                        session.add_packet(packet)
                        self.packets.append(packet)

                    self.sessions[session.session_id] = session

        except Exception as e:
            print(f"[!] Ошибка импорта: {e}")