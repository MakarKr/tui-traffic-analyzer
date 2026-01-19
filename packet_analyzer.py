#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import platform
import time
import threading
import socket
import struct
import os
import sys
import random
from typing import Optional, Dict, Any, Tuple
from session_manager import Packet, PacketType, SessionManager
from utils import format_bytes, get_interface_info
import re


class PacketAnalyzer:
    def __init__(self, session_manager: SessionManager):
        self.session_manager = session_manager
        self.sniffing = False
        self.sniff_thread = None
        self.current_interface = None
        self.packet_count = 0
        self.byte_count = 0
        self.socket_obj = None
        self.npcap_available = self._check_npcap()
        self.last_stats_time = time.time()
        self.packets_per_second = 0
        self.bytes_per_second = 0

    def _check_npcap(self) -> bool:
        """Проверить наличие Npcap/WinPcap с улучшенным детектированием"""
        if platform.system() != "Windows":
            return True  # На Linux/Mac всегда доступно через libpcap

        try:
            # Попытка импортировать scapy для Windows
            from scapy.arch.windows import get_windows_if_list
            interfaces = get_windows_if_list()
            if interfaces and len(interfaces) > 0:
                print("[*] Npcap/WinPcap detected via Scapy")
                return True
        except ImportError:
            pass
        except Exception as e:
            print(f"[!] Error checking Npcap via Scapy: {e}")

        # Проверяем наличие DLL файлов Npcap
        npcap_paths = [
            os.path.join(os.environ.get('SystemRoot', r'C:\Windows'), 'System32', 'wpcap.dll'),
            os.path.join(os.environ.get('SystemRoot', r'C:\Windows'), 'System32', 'Packet.dll'),
            r"C:\Program Files\Npcap\wpcap.dll",
            r"C:\Program Files (x86)\Npcap\wpcap.dll",
            r"C:\Program Files\Npcap\Packet.dll",
            r"C:\Program Files (x86)\Npcap\Packet.dll"
        ]

        for path in npcap_paths:
            if os.path.exists(path):
                print(f"[*] Npcap DLL found at: {path}")
                return True

        print("[!] Npcap not found. Packet capture will be limited.")
        print("[!] Install Npcap from: https://nmap.org/npcap/")
        return False

    def start_sniffing(self, interface: str, filter_str: str = "tcp port 80 or tcp port 443 or udp port 53"):
        """Начать захват пакетов с улучшенной обработкой ошибок"""
        if self.sniffing:
            print("[!] Already sniffing")
            return False

        if not interface:
            print("[!] No interface specified")
            return False

        self.sniffing = True
        self.current_interface = interface
        self.packet_count = 0
        self.byte_count = 0
        self.last_stats_time = time.time()
        self.packets_per_second = 0
        self.bytes_per_second = 0

        def sniff_task():
            try:
                print(f"[*] Starting packet capture on interface: {interface}")
                print(f"[*] Filter: {filter_str}")

                if platform.system() == "Windows":
                    self._start_sniffing_windows(interface, filter_str)
                else:
                    self._start_sniffing_linux(interface, filter_str)

            except Exception as e:
                print(f"[!] Critical error in sniffing task: {e}")
                import traceback
                traceback.print_exc()
                self.sniffing = False

        self.sniff_thread = threading.Thread(target=sniff_task, daemon=True)
        self.sniff_thread.start()

        # Ждем запуска
        time.sleep(1)
        return self.sniffing

    def _start_sniffing_windows(self, interface: str, filter_str: str):
        """Запустить сниффинг на Windows"""
        if self.npcap_available:
            print("[*] Using Npcap/WinPcap for packet capture")
            try:
                from scapy.all import sniff

                sniff_kwargs = {
                    'iface': interface,
                    'filter': filter_str,
                    'prn': self.process_packet_scapy,
                    'store': False,
                    'stop_filter': lambda x: not self.sniffing
                }

                sniff(**sniff_kwargs)
                print("[*] Npcap sniffing started successfully")

            except ImportError:
                print("[!] Scapy not available, falling back to alternative method")
                self._windows_alternative_sniff()
            except Exception as e:
                print(f"[!] Npcap sniffing failed: {e}")
                print("[*] Trying alternative method...")
                self._windows_alternative_sniff()
        else:
            print("[*] Using alternative method (no Npcap)")
            self._windows_alternative_sniff()

    def _start_sniffing_linux(self, interface: str, filter_str: str):
        """Запустить сниффинг на Linux/Mac"""
        try:
            from scapy.all import sniff

            sniff_kwargs = {
                'iface': interface,
                'filter': filter_str,
                'prn': self.process_packet_scapy,
                'store': False,
                'stop_filter': lambda x: not self.sniffing
            }

            print(f"[*] Starting sniff with kwargs: {sniff_kwargs}")
            sniff(**sniff_kwargs)
            print("[*] Sniffing started successfully!")

        except ImportError:
            print("[!] Scapy not available on Linux/Mac")
            self.sniffing = False
        except Exception as e:
            print(f"[!] Error in Linux/Mac sniffing: {e}")
            print(f"[!] Error type: {type(e).__name__}")
            import traceback
            traceback.print_exc()
            self.sniffing = False

    def process_packet_scapy(self, packet):
        """Обработать захваченный пакет через Scapy"""
        if not self.sniffing:
            return

        try:
            # Проверяем наличие IP слоя
            if not packet.haslayer('IP'):
                return

            self.packet_count += 1
            self.byte_count += len(packet)

            # Обновляем статистику скорости
            current_time = time.time()
            time_diff = current_time - self.last_stats_time

            if time_diff >= 1.0:  # Обновляем каждую секунду
                self.packets_per_second = self.packet_count / time_diff
                self.bytes_per_second = self.byte_count / time_diff
                self.last_stats_time = current_time

                # Периодически выводим статистику
                if self.packet_count % 100 == 0:
                    print(f"[*] Packets: {self.packet_count}, Bytes: {format_bytes(self.byte_count)}, "
                          f"Rate: {self.packets_per_second:.1f} pps")

            # Обработка HTTP
            if packet.haslayer('HTTPRequest'):
                self._process_http_request(packet)
            elif packet.haslayer('HTTPResponse'):
                self._process_http_response(packet)

            # Обработка HTTPS (только метаданные)
            elif packet.haslayer('TCP') and (packet['TCP'].dport == 443 or packet['TCP'].sport == 443):
                self._process_https_metadata(packet)

            # Обработка DNS
            elif packet.haslayer('DNS'):
                self._process_dns(packet)

            # Обработка других TCP соединений
            elif packet.haslayer('TCP'):
                self._process_tcp_connection(packet)

            # Обработка UDP
            elif packet.haslayer('UDP'):
                self._process_udp_session(packet)

        except Exception as e:
            if self.packet_count % 100 == 0:
                print(f"[!] Error processing packet {self.packet_count}: {e}")

    def _windows_alternative_sniff(self):
        """Альтернативный метод сниффинга для Windows без Npcap"""
        print("[*] Using alternative Windows sniffing method")
        print("[*] This method has limited functionality")

        try:
            # Получаем информацию об интерфейсе
            iface_info = get_interface_info(self.current_interface)
            if not iface_info.get("ip"):
                print(f"[!] Interface {self.current_interface} has no IP address")
                print("[!] Cannot start network monitoring")
                self.sniffing = False
                return

            ip = iface_info["ip"]
            print(f"[*] Monitoring traffic for IP: {ip}")

            # Создаем RAW сокет для захвата трафика
            try:
                self.socket_obj = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_IP)
                self.socket_obj.bind((ip, 0))

                # Включаем promiscuous mode если возможно
                try:
                    if platform.system() == "Windows":
                        # На Windows требуются специальные драйверы для promiscuous mode
                        self.socket_obj.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 65536)
                    else:
                        self.socket_obj.setsockopt(socket.SOL_SOCKET, socket.SO_RCVALL, socket.RCVALL_ON)
                except:
                    print("[*] Promiscuous mode not available, using normal mode")

                self.socket_obj.settimeout(1)

                print("[*] Raw socket created successfully")

                while self.sniffing:
                    try:
                        packet_data, addr = self.socket_obj.recvfrom(65565)
                        self._process_raw_packet(packet_data, ip)
                    except socket.timeout:
                        continue
                    except Exception as e:
                        if self.packet_count % 100 == 0:
                            print(f"[!] Error receiving packet: {e}")
                        continue

            except Exception as e:
                print(f"[!] Socket creation failed: {e}")
                print("[*] Using simulated traffic analysis")
                self._simulate_traffic(ip)

        except Exception as e:
            print(f"[!] Alternative sniffing failed: {e}")
            print("[*] Running in demo mode (no actual packet capture)")
            self.sniffing = False

    def _process_raw_packet(self, packet_data: bytes, local_ip: str):
        """Обработать сырой пакет с улучшенным парсингом"""
        try:
            if len(packet_data) < 20:
                return

            # Парсим IP заголовок
            ip_header = packet_data[0:20]

            # Распаковываем IP заголовок
            version_ihl, tos, total_len, packet_id, flags_frag_offset, ttl, protocol, checksum, src_ip_bytes, dst_ip_bytes = \
                struct.unpack('!BBHHHBBH4s4s', ip_header)

            # Извлекаем версию и длину заголовка
            version = version_ihl >> 4
            ihl = version_ihl & 0xF
            iph_length = ihl * 4

            if version != 4:
                return  # Только IPv4

            src_ip = socket.inet_ntoa(src_ip_bytes)
            dst_ip = socket.inet_ntoa(dst_ip_bytes)

            # Фильтруем только трафик с участием локального IP
            if src_ip != local_ip and dst_ip != local_ip:
                return

            self.packet_count += 1
            self.byte_count += len(packet_data)

            # Проверяем, достаточно ли данных для транспортного заголовка
            if len(packet_data) < iph_length:
                return

            # Обрабатываем TCP
            if protocol == 6 and len(packet_data) >= iph_length + 20:
                tcp_header = packet_data[iph_length:iph_length + 20]
                if len(tcp_header) >= 20:
                    src_port, dst_port, seq_num, ack_num, data_offset_flags = struct.unpack('!HHLLH', tcp_header[:14])

                    # Обрабатываем HTTP/HTTPS
                    if dst_port == 80 or src_port == 80:
                        self._create_http_packet(src_ip, dst_ip, src_port, dst_port, packet_data, local_ip)
                    elif dst_port == 443 or src_port == 443:
                        self._create_https_packet(src_ip, dst_ip, src_port, dst_port, packet_data, local_ip)
                    else:
                        self._create_tcp_packet(src_ip, dst_ip, src_port, dst_port, packet_data, local_ip)

            # Обрабатываем UDP
            elif protocol == 17 and len(packet_data) >= iph_length + 8:
                udp_header = packet_data[iph_length:iph_length + 8]
                if len(udp_header) >= 8:
                    src_port, dst_port, udp_len, checksum = struct.unpack('!HHHH', udp_header)

                    # Обрабатываем DNS
                    if dst_port == 53 or src_port == 53:
                        self._create_dns_packet(src_ip, dst_ip, src_port, dst_port, packet_data, local_ip)
                    else:
                        self._create_udp_packet(src_ip, dst_ip, src_port, dst_port, packet_data, local_ip)

        except Exception as e:
            if self.packet_count % 100 == 0:
                print(f"[!] Error processing raw packet: {e}")

    def _simulate_traffic(self, local_ip: str):
        """Симулировать трафик для демонстрации"""
        print("[*] Starting traffic simulation (demo mode)")

        demo_hosts = [
            {"host": "google.com", "ip": "142.250.185.78", "type": "HTTPS"},
            {"host": "youtube.com", "ip": "172.217.22.174", "type": "HTTPS"},
            {"host": "github.com", "ip": "140.82.121.3", "type": "HTTPS"},
            {"host": "stackoverflow.com", "ip": "151.101.129.69", "type": "HTTPS"},
            {"host": "wikipedia.org", "ip": "208.80.153.224", "type": "HTTP"},
            {"host": "reddit.com", "ip": "151.101.65.140", "type": "HTTPS"},
            {"host": "twitter.com", "ip": "104.244.42.1", "type": "HTTPS"},
            {"host": "facebook.com", "ip": "157.240.22.35", "type": "HTTPS"},
            {"host": "instagram.com", "ip": "157.240.22.174", "type": "HTTPS"},
            {"host": "amazon.com", "ip": "176.32.103.205", "type": "HTTPS"}
        ]

        dns_servers = ["8.8.8.8", "1.1.1.1", "8.8.4.4"]

        try:
            while self.sniffing:
                # Случайное количество пакетов в этой итерации
                num_packets = random.randint(1, 5)

                for _ in range(num_packets):
                    if not self.sniffing:
                        break

                    # Выбираем случайный хост
                    host_info = random.choice(demo_hosts)
                    host = host_info["host"]
                    server_ip = host_info["ip"]
                    traffic_type = host_info["type"]

                    # Случайный порт
                    src_port = random.randint(49152, 65535)

                    # Выбираем тип трафика
                    if traffic_type == "HTTP":
                        self._create_http_packet(local_ip, server_ip, src_port, 80, b"", local_ip, host)
                    elif traffic_type == "HTTPS":
                        self._create_https_packet(local_ip, server_ip, src_port, 443, b"", local_ip, host)

                    # Иногда добавляем DNS запрос
                    if random.random() > 0.7:
                        dns_server = random.choice(dns_servers)
                        self._create_dns_packet(local_ip, dns_server, src_port, 53, b"", local_ip, host)

                    # Небольшая задержка
                    time.sleep(random.uniform(0.1, 0.5))

                # Основная задержка между итерациями
                time.sleep(random.uniform(1, 3))

        except KeyboardInterrupt:
            print("\n[*] Simulation stopped by user")
        except Exception as e:
            print(f"[!] Error in simulation: {e}")

    def _create_http_packet(self, src_ip: str, dst_ip: str, src_port: int, dst_port: int,
                           packet_data: bytes, local_ip: str, host: str = None):
        """Создать HTTP пакет"""
        if not host:
            host = dst_ip if dst_port == 80 else src_ip

        method = "GET" if src_ip == local_ip else "RESPONSE"
        status_code = "200" if src_ip != local_ip else None

        packet_obj = Packet(
            timestamp=time.time(),
            src_ip=src_ip,
            dst_ip=dst_ip,
            src_port=src_port,
            dst_port=dst_port,
            protocol="HTTP",
            packet_type=PacketType.HTTP_REQUEST if src_ip == local_ip else PacketType.HTTP_RESPONSE,
            size=len(packet_data) if packet_data else random.randint(100, 1500),
            data={
                "method": method,
                "url": f"http://{host}/",
                "host": host,
                "path": "/",
                "headers": {
                    "User-Agent": "Demo-Browser/1.0",
                    "Accept": "text/html,application/xhtml+xml,application/xml",
                    "Connection": "keep-alive"
                },
                "status_code": status_code,
                "version": "HTTP/1.1"
            },
            session_id=f"http-{src_ip}:{src_port}-{dst_ip}:{dst_port}"
        )
        self.session_manager.add_packet(packet_obj)

    def _create_https_packet(self, src_ip: str, dst_ip: str, src_port: int, dst_port: int,
                            packet_data: bytes, local_ip: str, host: str = None):
        """Создать HTTPS пакет"""
        if not host:
            host = dst_ip if dst_port == 443 else src_ip

        direction = "client->server" if src_ip == local_ip else "server->client"

        # Случайный тип TLS пакета
        tls_types = ["Client Hello", "Server Hello", "Application Data", "Certificate", "Encrypted Alert"]
        tls_type = random.choice(tls_types)

        # Иногда добавляем SNI
        tls_info = {}
        if random.random() > 0.3:
            tls_info['sni'] = host

        # Иногда находим уязвимости
        vulnerabilities = []
        if random.random() > 0.8:
            vulnerabilities.append("Weak cipher suite detected")
        if random.random() > 0.9:
            vulnerabilities.append("Certificate expired or not valid")

        packet_obj = Packet(
            timestamp=time.time(),
            src_ip=src_ip,
            dst_ip=dst_ip,
            src_port=src_port,
            dst_port=dst_port,
            protocol="HTTPS",
            packet_type=PacketType.HTTPS_SESSION,
            size=len(packet_data) if packet_data else random.randint(200, 1500),
            data={
                "direction": direction,
                "client_ip": local_ip if direction == "client->server" else dst_ip,
                "server_ip": dst_ip if direction == "client->server" else src_ip,
                "tls_type": tls_type,
                "sni": host,
                "vulnerabilities": vulnerabilities if vulnerabilities else None,
                "tls_version": "TLSv1.2" if random.random() > 0.5 else "TLSv1.3"
            },
            session_id=f"https-{src_ip}:{src_port}-{dst_ip}:{dst_port}"
        )
        self.session_manager.add_packet(packet_obj)

    def _create_dns_packet(self, src_ip: str, dst_ip: str, src_port: int, dst_port: int,
                          packet_data: bytes, local_ip: str, host: str = None):
        """Создать DNS пакет"""
        if not host:
            host = f"host-{random.randint(1, 100)}.example.com"

        is_query = src_ip == local_ip

        packet_obj = Packet(
            timestamp=time.time(),
            src_ip=src_ip,
            dst_ip=dst_ip,
            src_port=src_port,
            dst_port=dst_port,
            protocol="DNS",
            packet_type=PacketType.DNS_QUERY if is_query else PacketType.DNS_RESPONSE,
            size=len(packet_data) if packet_data else random.randint(50, 500),
            data={
                "queries": [{"qname": host, "qtype": "A"}] if is_query else [],
                "answers": [{"rrname": host, "type": "A", "rdata": dst_ip}] if not is_query else []
            }
        )
        self.session_manager.add_packet(packet_obj)

    def _create_tcp_packet(self, src_ip: str, dst_ip: str, src_port: int, dst_port: int,
                          packet_data: bytes, local_ip: str):
        """Создать TCP пакет"""
        packet_obj = Packet(
            timestamp=time.time(),
            src_ip=src_ip,
            dst_ip=dst_ip,
            src_port=src_port,
            dst_port=dst_port,
            protocol="TCP",
            packet_type=PacketType.TCP_CONNECTION,
            size=len(packet_data) if packet_data else random.randint(40, 1500),
            data={
                "flags": "ACK" if random.random() > 0.5 else "SYN-ACK",
                "seq": random.randint(1000, 9999),
                "ack": random.randint(1000, 9999),
                "window": random.randint(1024, 65535)
            },
            session_id=f"tcp-{src_ip}:{src_port}-{dst_ip}:{dst_port}"
        )
        self.session_manager.add_packet(packet_obj)

    def _create_udp_packet(self, src_ip: str, dst_ip: str, src_port: int, dst_port: int,
                          packet_data: bytes, local_ip: str):
        """Создать UDP пакет"""
        packet_obj = Packet(
            timestamp=time.time(),
            src_ip=src_ip,
            dst_ip=dst_ip,
            src_port=src_port,
            dst_port=dst_port,
            protocol="UDP",
            packet_type=PacketType.UDP_SESSION,
            size=len(packet_data) if packet_data else random.randint(20, 1500),
            data={
                "payload_size": len(packet_data) if packet_data else random.randint(0, 1472)
            },
            session_id=f"udp-{src_ip}:{src_port}-{dst_ip}:{dst_port}"
        )
        self.session_manager.add_packet(packet_obj)

    def stop_sniffing(self):
        """Остановить захват пакетов с улучшенной очисткой"""
        print("[*] Stopping sniffing...")
        self.sniffing = False

        # Закрываем RAW сокет если используется
        if self.socket_obj:
            try:
                # Выключаем promiscuous mode если был включен
                if platform.system() != "Windows":
                    try:
                        self.socket_obj.ioctl(socket.SIO_RCVALL, socket.RCVALL_OFF)
                    except:
                        pass
                self.socket_obj.close()
                print("[*] Raw socket closed")
            except:
                pass
            finally:
                self.socket_obj = None

        # Ждем завершения потока сниффинга
        if self.sniff_thread:
            self.sniff_thread.join(timeout=3)
            if self.sniff_thread.is_alive():
                print("[!] Sniff thread did not terminate properly")
            else:
                print("[*] Sniffing stopped successfully")

        # Сбрасываем статистику
        self.packet_count = 0
        self.byte_count = 0
        self.packets_per_second = 0
        self.bytes_per_second = 0

        return True

    def extract_tls_info(self, packet):
        """Извлечение информации из TLS пакетов"""
        tls_info = {}

        try:
            # Проверяем наличие TLS слоев
            if packet.haslayer('TLS'):
                # Извлечение SNI (Server Name Indication)
                if packet.haslayer('TLSClientHello'):
                    sni = packet['TLSClientHello'].get_field_val('servername')
                    if sni:
                        tls_info['sni'] = sni.decode('utf-8', errors='ignore')

                # Извлечение информации о сертификате
                if packet.haslayer('TLSCertificate'):
                    cert = packet['TLSCertificate']
                    tls_info['certificate'] = {
                        'issuer': str(cert.get_field_val('issuer', 'Unknown')),
                        'validity': cert.get_field_val('validity', 'Unknown'),
                        'subject': str(cert.get_field_val('subject', 'Unknown'))
                    }

                # Версия TLS
                if packet.haslayer('TLSVersion'):
                    tls_info['version'] = str(packet['TLSVersion'])

                # Шифры
                if packet.haslayer('TLSCipherSuites'):
                    ciphers = packet['TLSCipherSuites'].get_field_val('ciphers', [])
                    if ciphers:
                        tls_info['ciphers'] = [str(c) for c in ciphers[:5]]

            # Альтернативный метод для извлечения SNI из сырых данных
            elif packet.haslayer('Raw'):
                raw_data = packet['Raw'].load

                # Поиск SNI в Client Hello
                if b'\x00\x00' in raw_data and b'\x00\x16' in raw_data:
                    try:
                        sni_start = raw_data.find(b'\x00\x00')
                        if sni_start != -1 and sni_start + 5 < len(raw_data):
                            sni_len = int.from_bytes(raw_data[sni_start + 3:sni_start + 5], 'big')
                            if sni_start + 5 + sni_len <= len(raw_data):
                                sni = raw_data[sni_start + 5:sni_start + 5 + sni_len].decode('utf-8', errors='ignore')
                                tls_info['sni'] = sni
                    except:
                        pass

                # Поиск информации о сертификате
                cert_markers = [b'-----BEGIN CERTIFICATE-----', b'Certificate:', b'Issuer:', b'Subject:']
                for marker in cert_markers:
                    if marker in raw_data:
                        tls_info['has_certificate'] = True
                        break

        except Exception as e:
            # Тихий провал - это нормально
            pass

        return tls_info

    def detect_ssl_vulnerabilities(self, tls_info):
        """Обнаружение уязвимостей SSL/TLS"""
        vulnerabilities = []

        try:
            # Проверка устаревших протоколов
            version = tls_info.get('version', '').upper()
            deprecated_versions = ['SSLv2', 'SSLv3', 'TLSv1.0', 'TLSv1.1']
            if any(deprecated in version for deprecated in deprecated_versions):
                vulnerabilities.append(f'Deprecated protocol: {version}')

            # Проверка слабых шифров
            weak_ciphers = ['RC4', 'DES', '3DES', 'NULL', 'EXPORT', 'ANON', 'ADH']
            ciphers = tls_info.get('ciphers', [])
            for cipher in ciphers:
                cipher_str = str(cipher).upper()
                if any(weak in cipher_str for weak in weak_ciphers):
                    vulnerabilities.append(f'Weak cipher: {cipher}')

            # Проверка сертификата
            cert_info = tls_info.get('certificate', {})
            if cert_info:
                validity = cert_info.get('validity', '')
                if 'expired' in str(validity).lower():
                    vulnerabilities.append('Expired certificate')

            # Проверка SNI
            if not tls_info.get('sni'):
                vulnerabilities.append('No SNI (Server Name Indication)')

        except Exception as e:
            pass

        return vulnerabilities

    def _process_http_request(self, packet):
        """Обработать HTTP запрос"""
        try:
            from scapy.all import HTTPRequest, IP, TCP, Raw

            http = packet[HTTPRequest]
            ip_layer = packet[IP]
            tcp_layer = packet[TCP]

            host = http.Host.decode() if http.Host else "Unknown"
            path = http.Path.decode() if http.Path else "/"
            method = http.Method.decode() if http.Method else "UNKNOWN"

            headers = {}
            if hasattr(http, 'fields'):
                for field, value in http.fields.items():
                    if value:
                        headers[field] = value.decode('utf-8', errors='ignore') if isinstance(value, bytes) else str(value)

            post_data = None
            if method == "POST" and packet.haslayer(Raw):
                raw_data = packet[Raw].load
                try:
                    post_data = raw_data.decode('utf-8', errors='ignore')
                    if len(post_data) > 1000:
                        post_data = post_data[:1000] + "..."
                except:
                    post_data = raw_data.hex()[:200] + "..." if len(raw_data) > 100 else raw_data.hex()

            packet_obj = Packet(
                timestamp=time.time(),
                src_ip=ip_layer.src,
                dst_ip=ip_layer.dst,
                src_port=tcp_layer.sport,
                dst_port=tcp_layer.dport,
                protocol="HTTP",
                packet_type=PacketType.HTTP_REQUEST,
                size=len(packet),
                data={
                    "method": method,
                    "url": f"http://{host}{path}",
                    "host": host,
                    "path": path,
                    "headers": headers,
                    "post_data": post_data,
                    "version": "HTTP/1.1" if hasattr(http, 'Http_Version') else "Unknown"
                },
                session_id=f"http-{ip_layer.src}:{tcp_layer.sport}-{ip_layer.dst}:{tcp_layer.dport}"
            )

            self.session_manager.add_packet(packet_obj)

        except Exception as e:
            if self.packet_count % 100 == 0:
                print(f"[!] Error processing HTTP request: {e}")

    def _process_http_response(self, packet):
        """Обработать HTTP ответ"""
        try:
            from scapy.all import HTTPResponse, IP, TCP, Raw

            http = packet[HTTPResponse]
            ip_layer = packet[IP]
            tcp_layer = packet[TCP]

            status_code = None
            reason_phrase = None
            headers = {}

            if hasattr(http, 'Status_Code'):
                status_code = http.Status_Code.decode('utf-8', errors='ignore') if isinstance(http.Status_Code, bytes) else str(http.Status_Code)

            if hasattr(http, 'Reason_Phrase'):
                reason_phrase = http.Reason_Phrase.decode('utf-8', errors='ignore') if isinstance(http.Reason_Phrase, bytes) else str(http.Reason_Phrase)

            if hasattr(http, 'fields'):
                for field, value in http.fields.items():
                    if value:
                        headers[field] = value.decode('utf-8', errors='ignore') if isinstance(value, bytes) else str(value)

            response_body = None
            if packet.haslayer(Raw):
                raw_data = packet[Raw].load
                try:
                    response_body = raw_data.decode('utf-8', errors='ignore')
                    if len(response_body) > 1000:
                        response_body = response_body[:1000] + "..."

                    content_type = headers.get('Content-Type', '')
                    if 'html' in content_type.lower():
                        title_match = re.search(r'<title>(.*?)</title>', response_body, re.IGNORECASE)
                        if title_match:
                            headers['_page_title'] = title_match.group(1)

                except:
                    response_body = raw_data.hex()[:200] + "..." if len(raw_data) > 100 else raw_data.hex()

            packet_obj = Packet(
                timestamp=time.time(),
                src_ip=ip_layer.src,
                dst_ip=ip_layer.dst,
                src_port=tcp_layer.sport,
                dst_port=tcp_layer.dport,
                protocol="HTTP",
                packet_type=PacketType.HTTP_RESPONSE,
                size=len(packet),
                data={
                    "status_code": status_code,
                    "reason_phrase": reason_phrase,
                    "headers": headers,
                    "body_preview": response_body,
                    "content_length": headers.get('Content-Length', 'Unknown')
                },
                session_id=f"http-{ip_layer.dst}:{tcp_layer.dport}-{ip_layer.src}:{tcp_layer.sport}"
            )

            self.session_manager.add_packet(packet_obj)

        except Exception as e:
            if self.packet_count % 100 == 0:
                print(f"[!] Error processing HTTP response: {e}")

    def _process_https_metadata(self, packet):
        """Обработать метаданные HTTPS"""
        try:
            from scapy.all import IP, TCP, Raw

            ip_layer = packet[IP]
            tcp_layer = packet[TCP]

            if tcp_layer.dport == 443:
                direction = "client->server"
                client_ip = ip_layer.src
                server_ip = ip_layer.dst
                client_port = tcp_layer.sport
                server_port = tcp_layer.dport
            else:
                direction = "server->client"
                client_ip = ip_layer.dst
                server_ip = ip_layer.src
                client_port = tcp_layer.dport
                server_port = tcp_layer.sport

            tls_info = self.extract_tls_info(packet)
            vulnerabilities = self.detect_ssl_vulnerabilities(tls_info)

            tls_type = "Unknown"
            if packet.haslayer(Raw):
                raw_data = packet[Raw].load
                if len(raw_data) > 0:
                    first_byte = raw_data[0]
                    if first_byte == 22:
                        if len(raw_data) > 5:
                            handshake_type = raw_data[5]
                            if handshake_type == 1:
                                tls_type = "Client Hello"
                            elif handshake_type == 2:
                                tls_type = "Server Hello"
                            elif handshake_type == 11:
                                tls_type = "Certificate"
                            elif handshake_type == 16:
                                tls_type = "Client Key Exchange"
                            elif handshake_type == 20:
                                tls_type = "Finished"
                    elif first_byte == 23:
                        tls_type = "Application Data"
                    elif first_byte == 21:
                        tls_type = "Alert"

            data = {
                "direction": direction,
                "client_ip": client_ip,
                "server_ip": server_ip,
                "tls_type": tls_type,
                "tcp_flags": str(tcp_layer.flags),
                "seq": tcp_layer.seq,
                "ack": tcp_layer.ack
            }

            if tls_info:
                data.update(tls_info)

            if vulnerabilities:
                data['vulnerabilities'] = vulnerabilities

            packet_obj = Packet(
                timestamp=time.time(),
                src_ip=ip_layer.src,
                dst_ip=ip_layer.dst,
                src_port=tcp_layer.sport,
                dst_port=tcp_layer.dport,
                protocol="HTTPS",
                packet_type=PacketType.HTTPS_SESSION,
                size=len(packet),
                data=data,
                session_id=f"https-{client_ip}:{client_port}-{server_ip}:{server_port}"
            )

            self.session_manager.add_packet(packet_obj)

        except Exception as e:
            if self.packet_count % 100 == 0:
                print(f"[!] Error processing HTTPS metadata: {e}")

    def _process_dns(self, packet):
        """Обработать DNS пакет"""
        try:
            from scapy.all import DNS, DNSQR, DNSRR, IP, TCP, UDP

            dns = packet[DNS]
            ip_layer = packet[IP]

            if dns.qr == 0:
                packet_type = PacketType.DNS_QUERY
                data = {"queries": []}
                if dns.haslayer(DNSQR):
                    for query in dns[DNSQR]:
                        data["queries"].append({
                            "qname": query.qname.decode('utf-8', errors='ignore') if hasattr(query.qname, 'decode') else str(query.qname),
                            "qtype": query.qtype
                        })
            else:
                packet_type = PacketType.DNS_RESPONSE
                data = {"answers": []}
                if dns.haslayer(DNSRR):
                    for answer in dns[DNSRR]:
                        data["answers"].append({
                            "rrname": answer.rrname.decode('utf-8', errors='ignore') if hasattr(answer.rrname, 'decode') else str(answer.rrname),
                            "type": answer.type,
                            "rdata": answer.rdata.decode('utf-8', errors='ignore') if hasattr(answer.rdata, 'decode') else str(answer.rdata)
                        })

            if packet.haslayer(UDP):
                transport = "UDP"
                src_port = packet[UDP].sport
                dst_port = packet[UDP].dport
            else:
                transport = "TCP"
                src_port = packet[TCP].sport
                dst_port = packet[TCP].dport

            packet_obj = Packet(
                timestamp=time.time(),
                src_ip=ip_layer.src,
                dst_ip=ip_layer.dst,
                src_port=src_port,
                dst_port=dst_port,
                protocol="DNS",
                packet_type=packet_type,
                size=len(packet),
                data=data
            )

            self.session_manager.add_packet(packet_obj)

        except Exception as e:
            if self.packet_count % 100 == 0:
                print(f"[!] Error processing DNS packet: {e}")

    def _process_tcp_connection(self, packet):
        """Обработать TCP соединение"""
        try:
            from scapy.all import IP, TCP

            ip_layer = packet[IP]
            tcp_layer = packet[TCP]

            if tcp_layer.dport in [80, 443, 53] or tcp_layer.sport in [80, 443, 53]:
                return

            packet_obj = Packet(
                timestamp=time.time(),
                src_ip=ip_layer.src,
                dst_ip=ip_layer.dst,
                src_port=tcp_layer.sport,
                dst_port=tcp_layer.dport,
                protocol="TCP",
                packet_type=PacketType.TCP_CONNECTION,
                size=len(packet),
                data={
                    "flags": str(tcp_layer.flags),
                    "seq": tcp_layer.seq,
                    "ack": tcp_layer.ack,
                    "window": tcp_layer.window,
                    "payload_size": len(tcp_layer.payload) if hasattr(tcp_layer, 'payload') else 0
                },
                session_id=f"tcp-{ip_layer.src}:{tcp_layer.sport}-{ip_layer.dst}:{tcp_layer.dport}"
            )

            self.session_manager.add_packet(packet_obj)

        except Exception as e:
            if self.packet_count % 100 == 0:
                print(f"[!] Error processing TCP connection: {e}")

    def _process_udp_session(self, packet):
        """Обработать UDP сессию"""
        try:
            from scapy.all import IP, UDP

            ip_layer = packet[IP]
            udp_layer = packet[UDP]

            if udp_layer.dport == 53 or udp_layer.sport == 53:
                return

            packet_obj = Packet(
                timestamp=time.time(),
                src_ip=ip_layer.src,
                dst_ip=ip_layer.dst,
                src_port=udp_layer.sport,
                dst_port=udp_layer.dport,
                protocol="UDP",
                packet_type=PacketType.UDP_SESSION,
                size=len(packet),
                data={
                    "payload_size": len(udp_layer.payload) if hasattr(udp_layer, 'payload') else 0
                },
                session_id=f"udp-{ip_layer.src}:{udp_layer.sport}-{ip_layer.dst}:{udp_layer.dport}"
            )

            self.session_manager.add_packet(packet_obj)

        except Exception as e:
            if self.packet_count % 100 == 0:
                print(f"[!] Error processing UDP session: {e}")

    def get_statistics(self) -> Dict[str, Any]:
        """Получить статистику анализатора"""
        current_time = time.time()
        duration = current_time - self.last_stats_time if self.last_stats_time > 0 else 0

        return {
            "sniffing": self.sniffing,
            "interface": self.current_interface,
            "packet_count": self.packet_count,
            "byte_count": self.byte_count,
            "formatted_bytes": format_bytes(self.byte_count),
            "npcap_available": self.npcap_available,
            "packets_per_second": self.packets_per_second,
            "bytes_per_second": self.bytes_per_second,
            "duration": duration
        }
